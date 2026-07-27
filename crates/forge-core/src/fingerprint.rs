//! Canonical, side-effect-free dependency fingerprints for evidence invalidation.
//!
//! Known dependencies return a [`Digest`] wrapped in an explicit [`DependencyValue`]. Explicit
//! command environment values are part of the hashed preimage because they affect execution, but
//! this module never returns or formats that preimage. Callers must still use a cryptographic
//! [`Hasher`] implementation and must not log command specifications merely to explain a digest.

use std::ffi::OsStr;
use std::fmt;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use forge_schema::{Digest, PathEncoding, WirePath};

use crate::control::OPERATION_CONTROL_PROTOCOL_VERSION;
use crate::domain::{
    CommandEnforcement, CommandSource, CommandSpec, Confidence, CoverageDimension, Intent,
    Mutability, NetworkIntent, ProjectUnit, Provenance, SuccessPredicate, ToolchainInfo,
    validate_provenance,
};
use crate::evidence::{
    BaseTaskDependency, DependencyValue, ExecutionDependencyFingerprint,
    RECEIPT_VALIDITY_PROTOCOL_VERSION, SUCCESS_NORMALIZATION_PROTOCOL_VERSION,
};
use crate::git::GitObjectFormat;
use crate::ports::Hasher;
use crate::scope::ScopeHead;

/// Internal protocol version for only the command and toolchain projections in this module.
pub const COMMAND_TOOLCHAIN_FINGERPRINT_PROTOCOL_VERSION: &str =
    "forge.command-toolchain-fingerprint-protocol/v1";

/// Ordered aggregation of per-command command, toolchain, and environment dependencies.
pub const ORDERED_EXECUTION_DEPENDENCY_PROTOCOL_VERSION: &str =
    "forge.ordered-execution-dependencies/v1";

/// Command-set confidence binding layered over the ordered command dependency.
pub const COMMAND_SET_DEPENDENCY_PROTOCOL_VERSION: &str = "forge.command-set-dependency/v1";

/// Marker protocol for process failures that cannot provide stream observations.
pub const PROCESS_OUTPUT_UNAVAILABLE_PROTOCOL_VERSION: &str = "forge.process-output-unavailable/v1";

/// Complete local-evidence behavior composition frozen by ADR-0020.
pub const EVIDENCE_BEHAVIOR_PROTOCOL_VERSION: &str = "forge.evidence-behavior/v6";

// Existing behavior identifiers are repeated here as composition inputs because their defining
// modules deliberately keep implementation domains private. A change to any implementation must
// bump its identifier here and at its source in the same reviewed change.
const WORKTREE_COMPARISON_PROTOCOL_VERSION: &str = "forge.worktree-comparison/v1";
const SCOPE_ACQUISITION_PROTOCOL_VERSION: &str = "forge.scope-acquisition/v1";
const SCOPE_DIGEST_INPUT_VERSION: &str = "forge.scope-digest-input/v1";
const SCOPE_DIGEST_DOMAIN: &[u8] = b"forge.scope-digest/v1";
pub const ENVIRONMENT_FINGERPRINT_PROTOCOL_VERSION: &str = "forge.environment-fingerprint/v1";
const EFFECTIVE_POLICY_DIGEST_DOMAIN: &[u8] = b"forge.effective-policy-digest/v1";
const PROCESS_OUTPUT_DIGEST_DOMAIN: &[u8] = b"forge.process-output/v1\0";
const PROCESS_OUTPUT_UNAVAILABLE_DIGEST_DOMAIN: &[u8] = b"forge.process-output-unavailable/v1\0";
const COVERAGE_AGGREGATION_PROTOCOL_VERSION: &str = "forge.coverage-aggregation/v2";
const RECEIPT_CANONICAL_SERIALIZATION_PROTOCOL_VERSION: &str = "forge.receipt-canonical-json/v3";
const EVIDENCE_CANONICAL_SERIALIZATION_PROTOCOL_VERSION: &str = "forge.evidence-canonical-json/v3";

const COMMAND_DIGEST_DOMAIN: &[u8] = b"forge.command-digest/v1";
const TOOLCHAIN_DIGEST_DOMAIN: &[u8] = b"forge.toolchain-digest/v1";
const ORDERED_COMMAND_DEPENDENCY_DOMAIN: &[u8] = b"forge.ordered-command-dependency/v1";
const ORDERED_TOOLCHAIN_DEPENDENCY_DOMAIN: &[u8] = b"forge.ordered-toolchain-dependency/v1";
const ORDERED_ENVIRONMENT_DEPENDENCY_DOMAIN: &[u8] = b"forge.ordered-environment-dependency/v1";
const COMMAND_SET_DEPENDENCY_DOMAIN: &[u8] = b"forge.command-set-dependency/v1";
const EVIDENCE_BEHAVIOR_DIGEST_DOMAIN: &[u8] = b"forge.evidence-behavior-digest/v1";
const WORKTREE_BASE_TASK_DEPENDENCY_DOMAIN: &[u8] = b"forge.worktree-base-task-dependency/v1";

/// A content-safe reason why a dependency cannot be fingerprinted safely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintError {
    /// The explicit environment contains a name conventionally used for secrets.
    SecretLikeEnvironment,
    /// The command argv contains a literal conventionally used to carry credentials.
    SecretLikeArgument,
    /// A native environment name cannot be classified with the frozen ASCII rule set.
    UnclassifiableEnvironmentName,
    /// A source path explicitly reports an unknown encoding.
    UnknownPathEncoding,
    /// A future source-path encoding is unsupported by this fingerprint protocol.
    UnsupportedPathEncoding,
    /// A source-path representation is internally inconsistent or incomplete.
    InvalidPathEncoding,
    /// Derivation evidence violates the shared project-model provenance contract.
    InvalidProvenance,
}

impl fmt::Display for FingerprintError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SecretLikeEnvironment => formatter.write_str(
                "command environment contains secret-like data that cannot enter a fingerprint",
            ),
            Self::SecretLikeArgument => formatter.write_str(
                "command arguments contain secret-like data that cannot enter a fingerprint",
            ),
            Self::UnclassifiableEnvironmentName => formatter
                .write_str("command environment contains a name that cannot be classified safely"),
            Self::UnknownPathEncoding => {
                formatter.write_str("fingerprint source path has an unknown encoding")
            }
            Self::UnsupportedPathEncoding => {
                formatter.write_str("fingerprint source path uses an unsupported encoding")
            }
            Self::InvalidPathEncoding => {
                formatter.write_str("fingerprint source path encoding is incomplete or invalid")
            }
            Self::InvalidProvenance => {
                formatter.write_str("fingerprint provenance is incomplete or invalid")
            }
        }
    }
}

impl std::error::Error for FingerprintError {}

/// Digests every command fact that can change execution, interpretation, or derivation.
///
/// Argument order is significant. Environment map, coverage, and provenance order are
/// canonicalized. Native program, argument, environment, and path values are encoded losslessly.
/// Missing or explicitly unknown authoritative facts return [`DependencyValue::Unknown`] without
/// invoking the hasher. Unsafe environment or provenance inputs return [`FingerprintError`].
pub fn command_dependency_digest<H: Hasher + ?Sized>(
    hasher: &H,
    command: &CommandSpec,
    provenance: &[Provenance],
) -> Result<DependencyValue<Digest>, FingerprintError> {
    let CommandSpec {
        id,
        intent,
        program,
        args,
        cwd,
        env,
        timeout,
        mutability,
        network,
        enforcement,
        success,
        source,
        confidence,
        coverage,
    } = command;
    validate_command_privacy(command)?;
    if program.is_empty()
        || *mutability == Mutability::Unknown
        || *network == NetworkIntent::Unknown
        || *confidence == Confidence::Unknown
        || coverage.is_empty()
        || provenance.is_empty()
        || !success_is_authoritative(success)
    {
        return Ok(DependencyValue::Unknown);
    }
    validate_provenance("command dependency fingerprint", provenance)
        .map_err(|_| FingerprintError::InvalidProvenance)?;
    let mut encoder = CanonicalEncoder::new("command");
    encoder.text(
        "protocol-version",
        COMMAND_TOOLCHAIN_FINGERPRINT_PROTOCOL_VERSION,
    );
    encoder.text("id", id.as_str());
    encoder.text("intent", intent_name(*intent));
    encoder.bytes("program", &canonical_native_os_bytes(program));
    encoder.sequence("args", args.iter(), |argument| {
        canonical_native_os_bytes(argument)
    });
    encoder.bytes("cwd", &canonical_native_path_bytes(cwd.as_path()));

    let mut environment: Vec<_> = env
        .iter()
        .map(|(name, value)| {
            let mut entry = CanonicalEncoder::new("environment-entry");
            entry.bytes("name", &canonical_native_os_bytes(name));
            entry.bytes("value", &canonical_native_os_bytes(value));
            entry.finish()
        })
        .collect();
    environment.sort();
    encoder.sequence("environment", environment, |entry| entry);

    encoder.u64("timeout-seconds", timeout.as_secs());
    encoder.u32("timeout-nanoseconds", timeout.subsec_nanos());
    encoder.text("mutability", mutability_name(*mutability));
    encoder.text("network", network_name(*network));
    encoder.text("enforcement", enforcement_name(*enforcement));
    encoder.bytes("success", &encode_success(success));
    encoder.bytes("source", &encode_command_source(source));
    encoder.text("confidence", confidence_name(*confidence));

    let mut encoded_coverage: Vec<_> = coverage.iter().map(encode_coverage).collect();
    encoded_coverage.sort();
    encoder.sequence("coverage", encoded_coverage, |dimension| dimension);
    encoder.bytes("provenance", &encode_provenance_set(provenance)?);
    Ok(DependencyValue::Known(
        hasher.digest(&[COMMAND_DIGEST_DOMAIN, &encoder.finish()]),
    ))
}

/// Digests one unit's observed toolchain values and their derivation evidence.
///
/// Project-unit identity is deliberately excluded: equal toolchain observations can be compared
/// across units, while the caller retains the unit identity as a separate dependency. Missing or
/// explicitly unknown authoritative facts return [`DependencyValue::Unknown`] without invoking the
/// hasher.
pub fn toolchain_dependency_digest<H: Hasher + ?Sized>(
    hasher: &H,
    unit: &ProjectUnit,
) -> Result<DependencyValue<Digest>, FingerprintError> {
    toolchain_info_dependency_digest(hasher, &unit.toolchain)
}

/// Digests authoritative toolchain facts independent of a project-unit container.
///
/// This is used by the execution boundary after it probes the exact command/toolchain binaries.
/// Project-unit detection continues to call [`toolchain_dependency_digest`], which delegates here
/// and therefore shares the same protocol and fail-closed rules.
pub fn toolchain_info_dependency_digest<H: Hasher + ?Sized>(
    hasher: &H,
    toolchain: &ToolchainInfo,
) -> Result<DependencyValue<Digest>, FingerprintError> {
    let ToolchainInfo {
        values,
        provenance,
        confidence,
    } = toolchain;
    if *confidence == Confidence::Unknown
        || values.is_empty()
        || values
            .iter()
            .any(|(name, value)| name.is_empty() || value.is_empty())
        || provenance.is_empty()
    {
        return Ok(DependencyValue::Unknown);
    }
    validate_provenance("toolchain dependency fingerprint", provenance)
        .map_err(|_| FingerprintError::InvalidProvenance)?;
    let mut encoder = CanonicalEncoder::new("toolchain");
    encoder.text(
        "protocol-version",
        COMMAND_TOOLCHAIN_FINGERPRINT_PROTOCOL_VERSION,
    );
    let mut encoded_values: Vec<_> = values
        .iter()
        .map(|(name, value)| {
            let mut entry = CanonicalEncoder::new("toolchain-entry");
            entry.text("name", name);
            entry.text("value", value);
            entry.finish()
        })
        .collect();
    encoded_values.sort();
    encoder.sequence("values", encoded_values, |entry| entry);
    encoder.text("confidence", confidence_name(*confidence));
    encoder.bytes("provenance", &encode_provenance_set(provenance)?);
    Ok(DependencyValue::Known(
        hasher.digest(&[TOOLCHAIN_DIGEST_DOMAIN, &encoder.finish()]),
    ))
}

/// Digests the exact sanitized environment supplied to one project command.
///
/// The caller must pass the post-allowlist, post-override map actually used by the process
/// boundary. Native names and values are encoded losslessly and never returned. Secret-like or
/// unclassifiable names fail closed so a low-entropy credential cannot leak through a reusable
/// Receipt digest. A known empty environment remains a valid, distinct dependency.
pub fn environment_dependency_digest<H: Hasher + ?Sized>(
    hasher: &H,
    environment: &std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString>,
) -> Result<DependencyValue<Digest>, FingerprintError> {
    validate_environment_privacy(environment)?;
    let mut encoder = CanonicalEncoder::new("environment");
    encoder.text("protocol-version", ENVIRONMENT_FINGERPRINT_PROTOCOL_VERSION);
    let entries: Vec<_> = environment
        .iter()
        .map(|(name, value)| {
            let mut entry = CanonicalEncoder::new("environment-entry");
            entry.bytes("name", &canonical_native_os_bytes(name));
            entry.bytes("value", &canonical_native_os_bytes(value));
            entry.finish()
        })
        .collect();
    encoder.sequence("entries", entries, |entry| entry);
    Ok(DependencyValue::Known(hasher.digest(&[
        b"forge.environment-digest/v1",
        &encoder.finish(),
    ])))
}

/// Aggregates the three execution dependency dimensions in command execution order.
///
/// Order and duplicate entries are significant. Each dimension fails closed independently: an
/// empty sequence, an unknown member, or an empty known digest makes only that aggregate unknown
/// and does not invoke the hasher for that dimension. Raw environment data is outside this API.
#[must_use]
pub fn aggregate_ordered_execution_dependencies<H: Hasher + ?Sized>(
    hasher: &H,
    commands: &[ExecutionDependencyFingerprint],
) -> ExecutionDependencyFingerprint {
    ExecutionDependencyFingerprint::new(
        aggregate_digest_axis(
            hasher,
            "command",
            ORDERED_COMMAND_DEPENDENCY_DOMAIN,
            commands.iter().map(ExecutionDependencyFingerprint::command),
        ),
        aggregate_digest_axis(
            hasher,
            "toolchain",
            ORDERED_TOOLCHAIN_DEPENDENCY_DOMAIN,
            commands
                .iter()
                .map(ExecutionDependencyFingerprint::toolchain),
        ),
        aggregate_digest_axis(
            hasher,
            "environment",
            ORDERED_ENVIRONMENT_DEPENDENCY_DOMAIN,
            commands
                .iter()
                .map(ExecutionDependencyFingerprint::environment),
        ),
    )
}

/// Returns non-output sentinels for a process boundary that produced no complete stream facts.
///
/// These digests deliberately do not claim that either stream was empty. Stream identity is part
/// of the preimage, and the separate domain prevents collision with normal process-output digests.
#[must_use]
pub fn process_output_unavailable_digests<H: Hasher + ?Sized>(hasher: &H) -> (Digest, Digest) {
    (
        hasher.digest(&[PROCESS_OUTPUT_UNAVAILABLE_DIGEST_DOMAIN, b"stdout"]),
        hasher.digest(&[PROCESS_OUTPUT_UNAVAILABLE_DIGEST_DOMAIN, b"stderr"]),
    )
}

/// Binds command-set resolution and coverage confidence to an ordered execution dependency.
///
/// `High` and `Medium` are explicit, comparable evidence inputs and produce distinct digests.
/// `Low` and `Unknown` are useful discovery observations but cannot support reusable local
/// evidence, so only the command axis becomes unknown. Toolchain and environment axes are
/// preserved to retain accurate stale diagnostics without upgrading the command decision.
#[must_use]
pub fn bind_command_set_confidence<H: Hasher + ?Sized>(
    hasher: &H,
    execution: &ExecutionDependencyFingerprint,
    resolution_confidence: Confidence,
    coverage_confidence: Confidence,
) -> ExecutionDependencyFingerprint {
    let command = match (
        execution.command(),
        resolution_confidence,
        coverage_confidence,
    ) {
        (
            DependencyValue::Known(command),
            Confidence::Medium | Confidence::High,
            Confidence::Medium | Confidence::High,
        ) if !command.as_str().is_empty() => {
            let mut encoder = CanonicalEncoder::new("command-set-dependency");
            encoder.text("protocol-version", COMMAND_SET_DEPENDENCY_PROTOCOL_VERSION);
            encoder.text("ordered-command-digest", command.as_str());
            encoder.text(
                "resolution-confidence",
                confidence_name(resolution_confidence),
            );
            encoder.text("coverage-confidence", confidence_name(coverage_confidence));
            DependencyValue::Known(
                hasher.digest(&[COMMAND_SET_DEPENDENCY_DOMAIN, &encoder.finish()]),
            )
        }
        _ => DependencyValue::Unknown,
    };
    ExecutionDependencyFingerprint::new(
        command,
        execution.toolchain().clone(),
        execution.environment().clone(),
    )
}

/// Derives the v0 comparison/base-task dependency from the canonical starting `HEAD`.
///
/// A normal repository has an applicable baseline even though v0 task acceptance itself is not
/// applicable. Only an unborn repository has neither input and therefore returns
/// [`BaseTaskDependency::NotApplicable`]. Policy-base identity is deliberately excluded because it
/// is recorded and compared on the independent policy dependency axis.
#[must_use]
pub fn worktree_base_task_dependency<H: Hasher + ?Sized>(
    hasher: &H,
    head: &ScopeHead,
) -> BaseTaskDependency {
    let ScopeHead::Commit(object_id) = head else {
        return BaseTaskDependency::NotApplicable;
    };
    let mut encoder = CanonicalEncoder::new("worktree-base-task-dependency");
    encoder.text("comparison-protocol", WORKTREE_COMPARISON_PROTOCOL_VERSION);
    encoder.text("baseline", "head");
    encoder.text(
        "object-format",
        match object_id.object_format() {
            GitObjectFormat::Sha1 => "sha1",
            GitObjectFormat::Sha256 => "sha256",
        },
    );
    encoder.bytes("object-id", object_id.lowercase_hex());
    encoder.text("task-acceptance", "not-applicable");
    BaseTaskDependency::Known(
        hasher.digest(&[WORKTREE_BASE_TASK_DEPENDENCY_DOMAIN, &encoder.finish()]),
    )
}

fn aggregate_digest_axis<'a, H: Hasher + ?Sized>(
    hasher: &H,
    axis: &str,
    digest_domain: &[u8],
    values: impl Iterator<Item = &'a DependencyValue<Digest>>,
) -> DependencyValue<Digest> {
    let mut known = Vec::new();
    for value in values {
        match value {
            DependencyValue::Known(digest) if !digest.as_str().is_empty() => known.push(digest),
            DependencyValue::Known(_) | DependencyValue::Unknown => {
                return DependencyValue::Unknown;
            }
        }
    }
    if known.is_empty() {
        return DependencyValue::Unknown;
    }

    let mut encoder = CanonicalEncoder::new("ordered-execution-dependency");
    encoder.text(
        "protocol-version",
        ORDERED_EXECUTION_DEPENDENCY_PROTOCOL_VERSION,
    );
    encoder.text("axis", axis);
    encoder.sequence("digests", known, |digest| {
        digest.as_str().as_bytes().to_vec()
    });
    DependencyValue::Known(hasher.digest(&[digest_domain, &encoder.finish()]))
}

/// Digests the complete Forge behavior composition required by ADR-0020.
///
/// This function binds protocol identifiers and digest domains only; it does not claim that a
/// caller successfully acquired any corresponding dependency. The authoritative receipt builder
/// must still return an explicit unknown when acquisition for any applicable dependency is
/// incomplete.
#[must_use]
pub fn evidence_behavior_digest<H: Hasher + ?Sized>(hasher: &H) -> Digest {
    let mut encoder = CanonicalEncoder::new("evidence-behavior");
    encoder.text("protocol-version", EVIDENCE_BEHAVIOR_PROTOCOL_VERSION);
    encoder.sequence(
        "components",
        [
            behavior_component(
                "comparison",
                WORKTREE_COMPARISON_PROTOCOL_VERSION.as_bytes(),
            ),
            behavior_component(
                "operation-control",
                OPERATION_CONTROL_PROTOCOL_VERSION.as_bytes(),
            ),
            behavior_component(
                "worktree-base-task-dependency-domain",
                WORKTREE_BASE_TASK_DEPENDENCY_DOMAIN,
            ),
            behavior_component(
                "scope-acquisition",
                SCOPE_ACQUISITION_PROTOCOL_VERSION.as_bytes(),
            ),
            behavior_component("scope-input", SCOPE_DIGEST_INPUT_VERSION.as_bytes()),
            behavior_component("scope-digest-domain", SCOPE_DIGEST_DOMAIN),
            behavior_component(
                "command-toolchain-fingerprint",
                COMMAND_TOOLCHAIN_FINGERPRINT_PROTOCOL_VERSION.as_bytes(),
            ),
            behavior_component("command-digest-domain", COMMAND_DIGEST_DOMAIN),
            behavior_component("toolchain-digest-domain", TOOLCHAIN_DIGEST_DOMAIN),
            behavior_component(
                "ordered-execution-dependencies",
                ORDERED_EXECUTION_DEPENDENCY_PROTOCOL_VERSION.as_bytes(),
            ),
            behavior_component(
                "command-set-dependency",
                COMMAND_SET_DEPENDENCY_PROTOCOL_VERSION.as_bytes(),
            ),
            behavior_component(
                "command-set-dependency-domain",
                COMMAND_SET_DEPENDENCY_DOMAIN,
            ),
            behavior_component(
                "ordered-command-dependency-domain",
                ORDERED_COMMAND_DEPENDENCY_DOMAIN,
            ),
            behavior_component(
                "ordered-toolchain-dependency-domain",
                ORDERED_TOOLCHAIN_DEPENDENCY_DOMAIN,
            ),
            behavior_component(
                "ordered-environment-dependency-domain",
                ORDERED_ENVIRONMENT_DEPENDENCY_DOMAIN,
            ),
            behavior_component(
                "environment-fingerprint",
                ENVIRONMENT_FINGERPRINT_PROTOCOL_VERSION.as_bytes(),
            ),
            behavior_component("policy-digest-domain", EFFECTIVE_POLICY_DIGEST_DOMAIN),
            behavior_component("process-output-digest-domain", PROCESS_OUTPUT_DIGEST_DOMAIN),
            behavior_component(
                "process-output-unavailable",
                PROCESS_OUTPUT_UNAVAILABLE_PROTOCOL_VERSION.as_bytes(),
            ),
            behavior_component(
                "process-output-unavailable-digest-domain",
                PROCESS_OUTPUT_UNAVAILABLE_DIGEST_DOMAIN,
            ),
            behavior_component(
                "success-normalization",
                SUCCESS_NORMALIZATION_PROTOCOL_VERSION.as_bytes(),
            ),
            behavior_component(
                "receipt-validity",
                RECEIPT_VALIDITY_PROTOCOL_VERSION.as_bytes(),
            ),
            behavior_component(
                "coverage-aggregation",
                COVERAGE_AGGREGATION_PROTOCOL_VERSION.as_bytes(),
            ),
            behavior_component(
                "receipt-canonical-serialization",
                RECEIPT_CANONICAL_SERIALIZATION_PROTOCOL_VERSION.as_bytes(),
            ),
            behavior_component(
                "evidence-canonical-serialization",
                EVIDENCE_CANONICAL_SERIALIZATION_PROTOCOL_VERSION.as_bytes(),
            ),
        ],
        |component| component,
    );
    hasher.digest(&[EVIDENCE_BEHAVIOR_DIGEST_DOMAIN, &encoder.finish()])
}

fn behavior_component(name: &str, version: &[u8]) -> Vec<u8> {
    let mut encoder = CanonicalEncoder::new("evidence-behavior-component");
    encoder.text("name", name);
    encoder.bytes("version", version);
    encoder.finish()
}

/// Digests only the command/toolchain fingerprint protocol frozen in this module.
///
/// This is not the complete Forge evidence behavior dependency from ADR-0016. Scope, process,
/// validity, and other algorithms must be frozen and composed separately before such a digest can
/// be claimed.
#[must_use]
#[allow(
    dead_code,
    reason = "the authoritative receipt builder will compose this protocol digest"
)]
pub(crate) fn command_toolchain_fingerprint_protocol_digest<H: Hasher + ?Sized>(
    hasher: &H,
) -> Digest {
    const DIGEST_DOMAIN: &[u8] = b"forge.command-toolchain-fingerprint-protocol-digest/v1";

    let mut encoder = CanonicalEncoder::new("command-toolchain-fingerprint-protocol");
    encoder.text(
        "protocol-version",
        COMMAND_TOOLCHAIN_FINGERPRINT_PROTOCOL_VERSION,
    );
    encoder.bytes("command-domain", COMMAND_DIGEST_DOMAIN);
    encoder.bytes("toolchain-domain", TOOLCHAIN_DIGEST_DOMAIN);
    hasher.digest(&[DIGEST_DOMAIN, &encoder.finish()])
}

/// Rejects explicit command environment names that cannot safely enter previews, Receipts, or
/// dependency fingerprints.
///
/// The error deliberately carries no offending name or value. Callers must run this check before
/// projecting or displaying a command because the wire contract preserves environment names.
pub fn validate_command_environment_privacy(command: &CommandSpec) -> Result<(), FingerprintError> {
    validate_environment_privacy(&command.env)
}

/// Returns whether a portable name conventionally denotes secret-bearing data.
///
/// This one classifier is shared by fingerprints and every generated command surface so their
/// privacy decisions cannot drift. The conservative substring and cloud-prefix rules are the
/// minimum accepted-design boundary; false positives fail closed instead of allowing a value that
/// may be a credential to enter a Receipt, preview, or persisted runner.
#[must_use]
pub fn is_secret_like_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    if ["TOKEN", "SECRET", "PASSWORD", "PRIVATE", "KEY"]
        .iter()
        .any(|pattern| upper.contains(pattern))
        || ["AWS_", "GOOGLE_", "AZURE_"]
            .iter()
            .any(|prefix| upper.starts_with(prefix))
    {
        return true;
    }

    let tokens = secret_name_tokens(name);
    if tokens.iter().any(|token| {
        matches!(
            token.as_str(),
            "TOKEN"
                | "TOKENS"
                | "SECRET"
                | "SECRETS"
                | "PASSWORD"
                | "PASSWD"
                | "CREDENTIAL"
                | "CREDENTIALS"
                | "AUTH"
                | "OAUTH"
                | "AUTHN"
                | "AUTHZ"
                | "AUTHORIZATION"
                | "AUTHENTICATION"
                | "COOKIE"
                | "COOKIES"
                | "SESSION"
        )
    }) {
        return true;
    }
    false
}

fn secret_name_tokens(name: &str) -> Vec<String> {
    let characters = name.chars().collect::<Vec<_>>();
    let mut tokens = Vec::new();
    let mut current = String::new();
    for &character in &characters {
        if character.is_ascii_alphanumeric() {
            current.push(character.to_ascii_uppercase());
        } else if !current.is_empty() {
            tokens.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        tokens.push(std::mem::take(&mut current));
    }
    for (index, &character) in characters.iter().enumerate() {
        if !character.is_ascii_alphanumeric() {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            continue;
        }
        let previous = index.checked_sub(1).and_then(|index| characters.get(index));
        let next = characters.get(index + 1);
        let starts_word = !current.is_empty()
            && character.is_ascii_uppercase()
            && (previous.is_some_and(char::is_ascii_lowercase)
                || previous.is_some_and(char::is_ascii_uppercase)
                    && next.is_some_and(char::is_ascii_lowercase));
        if starts_word {
            tokens.push(std::mem::take(&mut current));
        }
        current.push(character.to_ascii_uppercase());
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// Rejects credential-like literals before a complete command can be fingerprinted or persisted.
pub fn validate_command_privacy(command: &CommandSpec) -> Result<(), FingerprintError> {
    validate_command_environment_privacy(command)?;
    validate_argv_privacy(std::iter::once(&command.program).chain(command.args.iter()))
}

/// Rejects obvious credential literals in one native argv sequence without formatting its values.
///
/// Ordinary short options are intentionally opaque. A secret-like long option is rejected only
/// when it contains an inline value or is followed by an obvious non-option value.
pub fn validate_argv_privacy<I, S>(argv: I) -> Result<(), FingerprintError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut secret_long_option_awaiting_value = false;
    for argument in argv {
        let bytes = argument.as_ref().as_encoded_bytes();
        if secret_long_option_awaiting_value && is_obvious_following_value(bytes) {
            return Err(FingerprintError::SecretLikeArgument);
        }
        secret_long_option_awaiting_value = false;

        if has_authorization_header_literal(bytes)
            || has_uri_userinfo(bytes)
            || has_secret_like_assignment(bytes)
        {
            return Err(FingerprintError::SecretLikeArgument);
        }
        match secret_like_long_option(bytes) {
            SecretLongOption::None => {}
            SecretLongOption::AwaitingValue => secret_long_option_awaiting_value = true,
            SecretLongOption::InlineLiteral => {
                return Err(FingerprintError::SecretLikeArgument);
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecretLongOption {
    None,
    AwaitingValue,
    InlineLiteral,
}

fn secret_like_long_option(argument: &[u8]) -> SecretLongOption {
    let Some(body) = argument.strip_prefix(b"--") else {
        return SecretLongOption::None;
    };
    if body.is_empty() {
        return SecretLongOption::None;
    }
    let (name, value) = body
        .iter()
        .position(|byte| matches!(byte, b'=' | b':'))
        .map_or((body, None), |separator| {
            (&body[..separator], Some(&body[separator + 1..]))
        });
    let Some(name) = std::str::from_utf8(name).ok() else {
        return SecretLongOption::None;
    };
    if !is_secret_like_name(name) {
        return SecretLongOption::None;
    }
    match value {
        Some(value) if !value.is_empty() => SecretLongOption::InlineLiteral,
        Some(_) => SecretLongOption::None,
        None => SecretLongOption::AwaitingValue,
    }
}

fn is_obvious_following_value(argument: &[u8]) -> bool {
    !(argument.is_empty() || argument.len() > 1 && argument.starts_with(b"-"))
}

fn has_secret_like_assignment(argument: &[u8]) -> bool {
    let Some(separator) = argument.iter().position(|byte| *byte == b'=') else {
        return false;
    };
    if separator == 0 || separator + 1 == argument.len() {
        return false;
    }
    std::str::from_utf8(&argument[..separator]).is_ok_and(is_secret_like_name)
}

fn has_authorization_header_literal(argument: &[u8]) -> bool {
    let argument = trim_ascii(argument);
    let candidate = if argument.len() > 2 && argument[..2].eq_ignore_ascii_case(b"-h") {
        &argument[2..]
    } else if let Some(separator) = argument.iter().position(|byte| *byte == b'=') {
        &argument[separator + 1..]
    } else {
        argument
    };
    let candidate = trim_ascii(candidate);
    let header = b"authorization";
    candidate.len() > header.len()
        && candidate[..header.len()].eq_ignore_ascii_case(header)
        && candidate[header.len()] == b':'
        && !trim_ascii(&candidate[header.len() + 1..]).is_empty()
}

fn has_uri_userinfo(argument: &[u8]) -> bool {
    let Some(scheme_end) = argument.windows(3).position(|window| window == b"://") else {
        return false;
    };
    let authority = &argument[scheme_end + 3..];
    let authority_end = authority
        .iter()
        .position(|byte| matches!(byte, b'/' | b'?' | b'#'))
        .unwrap_or(authority.len());
    let authority = &authority[..authority_end];
    let Some(at) = authority.iter().rposition(|byte| *byte == b'@') else {
        return false;
    };
    at > 0
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

fn validate_environment_privacy(
    environment: &std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString>,
) -> Result<(), FingerprintError> {
    for name in environment.keys() {
        let name = name
            .to_str()
            .ok_or(FingerprintError::UnclassifiableEnvironmentName)?;
        if is_secret_like_name(name) {
            return Err(FingerprintError::SecretLikeEnvironment);
        }
    }
    Ok(())
}

/// Lossless canonical encoding of a native OS string for reuse by later scope fingerprints.
///
/// The returned bytes include an explicit platform encoding tag and length-delimited native data;
/// they never contain a display or lossy conversion.
#[must_use]
pub(crate) fn canonical_native_os_bytes(value: &OsStr) -> Vec<u8> {
    let mut encoder = CanonicalEncoder::new("native-os-string");
    if let Some(utf8) = value.to_str() {
        encoder.text("encoding", "utf8");
        encoder.bytes("native", utf8.as_bytes());
        return encoder.finish();
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;

        encoder.text("encoding", "unix-bytes");
        encoder.bytes("native", value.as_bytes());
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt as _;

        encoder.text("encoding", "windows-wide-le");
        let native: Vec<u8> = value.encode_wide().flat_map(u16::to_le_bytes).collect();
        encoder.bytes("native", &native);
    }
    #[cfg(not(any(unix, windows)))]
    {
        encoder.text("encoding", "rust-encoded-bytes");
        encoder.bytes("native", value.as_encoded_bytes());
    }
    encoder.finish()
}

/// Lossless canonical native path encoding built on [`canonical_native_os_bytes`].
#[must_use]
pub(crate) fn canonical_native_path_bytes(value: &Path) -> Vec<u8> {
    canonical_native_os_bytes(value.as_os_str())
}

#[derive(Debug)]
struct CanonicalEncoder {
    bytes: Vec<u8>,
}

impl CanonicalEncoder {
    fn new(record_type: &str) -> Self {
        let mut encoder = Self { bytes: Vec::new() };
        encoder.text("record-type", record_type);
        encoder
    }

    fn text(&mut self, field: &str, value: &str) {
        self.bytes(field, value.as_bytes());
    }

    fn u32(&mut self, field: &str, value: u32) {
        self.bytes(field, &value.to_be_bytes());
    }

    fn u64(&mut self, field: &str, value: u64) {
        self.bytes(field, &value.to_be_bytes());
    }

    fn bytes(&mut self, field: &str, value: &[u8]) {
        self.bytes.push(1);
        append_length_prefixed(&mut self.bytes, field.as_bytes());
        append_length_prefixed(&mut self.bytes, value);
    }

    fn sequence<T>(
        &mut self,
        field: &str,
        values: impl IntoIterator<Item = T>,
        encode: impl Fn(T) -> Vec<u8>,
    ) {
        let values: Vec<Vec<u8>> = values.into_iter().map(encode).collect();
        let mut sequence = Vec::new();
        sequence.extend_from_slice(&(values.len() as u128).to_be_bytes());
        for value in values {
            append_length_prefixed(&mut sequence, &value);
        }
        self.bytes(field, &sequence);
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

fn append_length_prefixed(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u128).to_be_bytes());
    output.extend_from_slice(value);
}

fn encode_success(success: &SuccessPredicate) -> Vec<u8> {
    let mut encoder = CanonicalEncoder::new("success-predicate");
    match success {
        SuccessPredicate::ExitZero => encoder.text("variant", "exit-zero"),
        SuccessPredicate::ExitZeroAndStdoutEmpty => {
            encoder.text("variant", "exit-zero-and-stdout-empty");
        }
        SuccessPredicate::JsonHasNoErrors => encoder.text("variant", "json-has-no-errors"),
        SuccessPredicate::All(predicates) => {
            encoder.text("variant", "all");
            encoder.sequence("predicates", predicates, encode_success);
        }
    }
    encoder.finish()
}

fn success_is_authoritative(success: &SuccessPredicate) -> bool {
    match success {
        SuccessPredicate::ExitZero
        | SuccessPredicate::ExitZeroAndStdoutEmpty
        | SuccessPredicate::JsonHasNoErrors => true,
        SuccessPredicate::All(predicates) => {
            !predicates.is_empty() && predicates.iter().all(success_is_authoritative)
        }
    }
}

fn encode_command_source(source: &CommandSource) -> Vec<u8> {
    let mut encoder = CanonicalEncoder::new("command-source");
    match source {
        CommandSource::ExplicitConfig => encoder.text("variant", "explicit-config"),
        CommandSource::ExistingProjectTarget { path, target } => {
            encoder.text("variant", "existing-project-target");
            encoder.bytes("path", &canonical_native_path_bytes(path.as_path()));
            encoder.text("target", target);
        }
        CommandSource::LanguageDefault { provider, rule } => {
            encoder.text("variant", "language-default");
            encoder.text("provider", provider);
            encoder.text("rule", rule);
        }
    }
    encoder.finish()
}

fn encode_coverage(coverage: &CoverageDimension) -> Vec<u8> {
    let mut encoder = CanonicalEncoder::new("coverage-dimension");
    match coverage {
        CoverageDimension::Format => encoder.text("variant", "format"),
        CoverageDimension::Compile => encoder.text("variant", "compile"),
        CoverageDimension::Lint => encoder.text("variant", "lint"),
        CoverageDimension::UnitTest => encoder.text("variant", "unit-test"),
        CoverageDimension::IntegrationTest => encoder.text("variant", "integration-test"),
        CoverageDimension::Build => encoder.text("variant", "build"),
        CoverageDimension::Security => encoder.text("variant", "security"),
        CoverageDimension::Custom(value) => {
            encoder.text("variant", "custom");
            encoder.text("value", value);
        }
    }
    encoder.finish()
}

fn encode_provenance_set(provenance: &[Provenance]) -> Result<Vec<u8>, FingerprintError> {
    let mut entries = provenance
        .iter()
        .map(encode_provenance)
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort();
    entries.dedup();
    let mut encoder = CanonicalEncoder::new("provenance-set");
    encoder.sequence("entries", entries, |entry| entry);
    Ok(encoder.finish())
}

fn encode_provenance(provenance: &Provenance) -> Result<Vec<u8>, FingerprintError> {
    let mut encoder = CanonicalEncoder::new("provenance");
    encoder.text("rule-id", &provenance.rule_id);
    match &provenance.source_path {
        Some(path) => {
            encoder.text("source-path-presence", "some");
            encoder.bytes("source-path", &encode_wire_path(path)?);
        }
        None => encoder.text("source-path-presence", "none"),
    }
    match provenance.source_range {
        Some(range) => {
            encoder.text("source-range-presence", "some");
            encoder.u64("source-range-start", range.start_byte());
            encoder.u64("source-range-end", range.end_byte());
        }
        None => encoder.text("source-range-presence", "none"),
    }
    encoder.text("detail", &provenance.detail);
    Ok(encoder.finish())
}

fn encode_wire_path(path: &WirePath) -> Result<Vec<u8>, FingerprintError> {
    let mut encoder = CanonicalEncoder::new("wire-path");
    match path.encoding {
        PathEncoding::Utf8 => {
            if path.raw_base64.is_some() || path.display.as_bytes().contains(&0) {
                return Err(FingerprintError::InvalidPathEncoding);
            }
            encoder.text("encoding", "utf8");
            encoder.text("utf8", &path.display);
        }
        PathEncoding::UnixBytes => {
            let raw = decode_wire_path_bytes(
                path.raw_base64
                    .as_deref()
                    .ok_or(FingerprintError::InvalidPathEncoding)?,
            )?;
            if raw.contains(&0) || std::str::from_utf8(&raw).is_ok() {
                return Err(FingerprintError::InvalidPathEncoding);
            }
            encoder.text("encoding", "unix-bytes");
            encoder.bytes("raw", &raw);
        }
        PathEncoding::WindowsWide => {
            let raw = decode_wire_path_bytes(
                path.raw_base64
                    .as_deref()
                    .ok_or(FingerprintError::InvalidPathEncoding)?,
            )?;
            if raw.len() % 2 != 0 {
                return Err(FingerprintError::InvalidPathEncoding);
            }
            let wide: Vec<u16> = raw
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect();
            if wide.contains(&0) || String::from_utf16(&wide).is_ok() {
                return Err(FingerprintError::InvalidPathEncoding);
            }
            encoder.text("encoding", "windows-wide");
            encoder.bytes("raw", &raw);
        }
        PathEncoding::Unknown => return Err(FingerprintError::UnknownPathEncoding),
        _ => return Err(FingerprintError::UnsupportedPathEncoding),
    }
    Ok(encoder.finish())
}

fn decode_wire_path_bytes(raw_base64: &str) -> Result<Vec<u8>, FingerprintError> {
    STANDARD
        .decode(raw_base64)
        .map_err(|_| FingerprintError::InvalidPathEncoding)
}

const fn intent_name(intent: Intent) -> &'static str {
    match intent {
        Intent::Setup => "setup",
        Intent::FormatCheck => "format-check",
        Intent::Format => "format",
        Intent::Check => "check",
        Intent::Fix => "fix",
        Intent::Test => "test",
        Intent::Verify => "verify",
        Intent::Build => "build",
    }
}

const fn mutability_name(mutability: Mutability) -> &'static str {
    match mutability {
        Mutability::ReadOnly => "read-only",
        Mutability::WorkingTreeWrite => "working-tree-write",
        Mutability::ExternalSideEffect => "external-side-effect",
        Mutability::Unknown => "unknown",
    }
}

const fn network_name(network: NetworkIntent) -> &'static str {
    match network {
        NetworkIntent::Inherit => "inherit",
        NetworkIntent::OfflineRequested => "offline-requested",
        NetworkIntent::Required => "required",
        NetworkIntent::Unknown => "unknown",
    }
}

const fn enforcement_name(enforcement: CommandEnforcement) -> &'static str {
    match enforcement {
        CommandEnforcement::Required => "required",
        CommandEnforcement::Advisory => "advisory",
    }
}

const fn confidence_name(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Unknown => "unknown",
        Confidence::Low => "low",
        Confidence::Medium => "medium",
        Confidence::High => "high",
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::{BTreeMap, BTreeSet};
    use std::error::Error;
    use std::ffi::OsString;
    use std::io;
    use std::path::Path;
    use std::time::Duration;

    use forge_schema::{CommandId, LanguageId, UnitId};

    use super::*;
    use crate::domain::{ProjectKind, ToolchainInfo};
    use crate::path::RepoRelativePath;

    struct FixtureHasher;

    impl Hasher for FixtureHasher {
        fn digest(&self, chunks: &[&[u8]]) -> Digest {
            let mut state = 0xcbf2_9ce4_8422_2325_u64;
            for chunk in chunks {
                for byte in (chunk.len() as u128).to_be_bytes() {
                    state ^= u64::from(byte);
                    state = state.wrapping_mul(0x0000_0100_0000_01b3);
                }
                for byte in *chunk {
                    state ^= u64::from(*byte);
                    state = state.wrapping_mul(0x0000_0100_0000_01b3);
                }
            }
            Digest::new(format!("fixture:{state:016x}"))
        }
    }

    #[derive(Debug, Default)]
    struct SpyHasher {
        calls: Cell<usize>,
    }

    impl Hasher for SpyHasher {
        fn digest(&self, _chunks: &[&[u8]]) -> Digest {
            self.calls.set(self.calls.get() + 1);
            Digest::new("spy:called")
        }
    }

    fn provenance(rule: &str) -> Provenance {
        Provenance {
            rule_id: rule.to_owned(),
            source_path: Some(WirePath::from_path(Path::new("Cargo.toml"))),
            source_range: None,
            detail: format!("source for {rule}"),
        }
    }

    fn command() -> Result<CommandSpec, crate::path::RelativePathError> {
        let mut command = CommandSpec::new(
            CommandId::from("rust.check"),
            Intent::Check,
            "cargo",
            RepoRelativePath::new("crates/core")?,
            CommandSource::LanguageDefault {
                provider: String::from("rust"),
                rule: String::from("cargo-check"),
            },
        )
        .with_args(["check", "--workspace"]);
        command.env = BTreeMap::from([
            (OsString::from("CARGO_NET_OFFLINE"), OsString::from("true")),
            (OsString::from("RUSTUP_AUTO_INSTALL"), OsString::from("0")),
        ]);
        command.timeout = Duration::from_millis(12_345);
        command.mutability = Mutability::ReadOnly;
        command.network = NetworkIntent::OfflineRequested;
        command.enforcement = CommandEnforcement::Required;
        command.success = SuccessPredicate::All(vec![
            SuccessPredicate::ExitZero,
            SuccessPredicate::JsonHasNoErrors,
        ]);
        command.confidence = Confidence::High;
        command.coverage = BTreeSet::from([CoverageDimension::Compile, CoverageDimension::Lint]);
        Ok(command)
    }

    fn project_unit() -> Result<ProjectUnit, crate::path::RelativePathError> {
        Ok(ProjectUnit {
            id: UnitId::from("unit/core"),
            display_name: String::from("core"),
            language: LanguageId::from("rust"),
            kind: ProjectKind::RustPackage,
            root: RepoRelativePath::new("crates/core")?,
            manifest: RepoRelativePath::new("crates/core/Cargo.toml")?,
            workspace_root: Some(RepoRelativePath::root()),
            members: Vec::new(),
            dependencies: Vec::new(),
            toolchain: ToolchainInfo::new(
                BTreeMap::from([
                    (String::from("cargo"), String::from("1.85.0")),
                    (String::from("rustc"), String::from("1.85.0")),
                ]),
                vec![provenance("toolchain/cargo"), provenance("toolchain/rustc")],
                Confidence::High,
            ),
            provenance: vec![provenance("unit")],
            confidence: Confidence::High,
        })
    }

    fn digest(command: &CommandSpec, provenance: &[Provenance]) -> Result<Digest, Box<dyn Error>> {
        match command_dependency_digest(&FixtureHasher, command, provenance)? {
            DependencyValue::Known(digest) => Ok(digest),
            DependencyValue::Unknown => {
                Err(io::Error::other("authoritative fixture command was unknown").into())
            }
        }
    }

    fn known_toolchain_digest(unit: &ProjectUnit) -> Result<Digest, Box<dyn Error>> {
        match toolchain_dependency_digest(&FixtureHasher, unit)? {
            DependencyValue::Known(digest) => Ok(digest),
            DependencyValue::Unknown => {
                Err(io::Error::other("authoritative fixture toolchain was unknown").into())
            }
        }
    }

    fn execution_dependencies(
        command: &str,
        toolchain: &str,
        environment: &str,
    ) -> ExecutionDependencyFingerprint {
        ExecutionDependencyFingerprint::new(
            DependencyValue::Known(Digest::from(command)),
            DependencyValue::Known(Digest::from(toolchain)),
            DependencyValue::Known(Digest::from(environment)),
        )
    }

    #[test]
    fn fixture_hasher_frames_top_level_chunks() {
        let hasher = FixtureHasher;
        assert_ne!(hasher.digest(&[b"ab", b"c"]), hasher.digest(&[b"a", b"bc"]));
    }

    #[test]
    fn every_command_dependency_field_changes_the_digest() -> Result<(), Box<dyn Error>> {
        let base = command()?;
        let evidence = vec![provenance("command/base")];
        let expected = digest(&base, &evidence)?;
        let mut variants = Vec::new();

        let mut changed = base.clone();
        changed.id = CommandId::from("rust.check.changed");
        variants.push(changed);
        let mut changed = base.clone();
        changed.intent = Intent::Test;
        variants.push(changed);
        let mut changed = base.clone();
        changed.program = OsString::from("cargo-nextest");
        variants.push(changed);
        let mut changed = base.clone();
        changed.args[0] = OsString::from("clippy");
        variants.push(changed);
        let mut changed = base.clone();
        changed.args.reverse();
        variants.push(changed);
        let mut changed = base.clone();
        changed.cwd = RepoRelativePath::new("crates/other")?;
        variants.push(changed);
        let mut changed = base.clone();
        changed
            .env
            .insert(OsString::from("NEW"), OsString::from("1"));
        variants.push(changed);
        let mut changed = base.clone();
        changed
            .env
            .insert(OsString::from("CARGO_NET_OFFLINE"), OsString::from("false"));
        variants.push(changed);
        let mut changed = base.clone();
        changed.timeout += Duration::from_nanos(1);
        variants.push(changed);
        let mut changed = base.clone();
        changed.mutability = Mutability::WorkingTreeWrite;
        variants.push(changed);
        let mut changed = base.clone();
        changed.network = NetworkIntent::Required;
        variants.push(changed);
        let mut changed = base.clone();
        changed.enforcement = CommandEnforcement::Advisory;
        variants.push(changed);
        let mut changed = base.clone();
        changed.success = SuccessPredicate::ExitZero;
        variants.push(changed);
        let mut changed = base.clone();
        changed.source = CommandSource::ExplicitConfig;
        variants.push(changed);
        let mut changed = base.clone();
        changed.confidence = Confidence::Medium;
        variants.push(changed);
        let mut changed = base.clone();
        changed.coverage.insert(CoverageDimension::Security);
        variants.push(changed);

        for (index, variant) in variants.iter().enumerate() {
            assert_ne!(digest(variant, &evidence)?, expected, "mutation {index}");
        }
        assert_ne!(digest(&base, &[provenance("command/changed")])?, expected);
        Ok(())
    }

    #[test]
    fn unordered_sets_maps_and_provenance_are_canonical() -> Result<(), Box<dyn Error>> {
        let first = command()?;
        let mut second = first.clone();
        second.env = BTreeMap::new();
        second
            .env
            .insert(OsString::from("RUSTUP_AUTO_INSTALL"), OsString::from("0"));
        second
            .env
            .insert(OsString::from("CARGO_NET_OFFLINE"), OsString::from("true"));
        second.coverage = BTreeSet::new();
        second.coverage.insert(CoverageDimension::Lint);
        second.coverage.insert(CoverageDimension::Compile);
        let left = [provenance("b"), provenance("a")];
        let right = [provenance("a"), provenance("b")];
        assert_eq!(digest(&first, &left)?, digest(&second, &right)?);
        Ok(())
    }

    #[test]
    fn incomplete_command_facts_are_unknown_without_hashing() -> Result<(), Box<dyn Error>> {
        let base = command()?;
        let evidence = [provenance("command/base")];
        let mut variants = Vec::new();

        let mut changed = base.clone();
        changed.program = OsString::new();
        variants.push(("empty program", changed));
        let mut changed = base.clone();
        changed.mutability = Mutability::Unknown;
        variants.push(("unknown mutability", changed));
        let mut changed = base.clone();
        changed.network = NetworkIntent::Unknown;
        variants.push(("unknown network intent", changed));
        let mut changed = base.clone();
        changed.confidence = Confidence::Unknown;
        variants.push(("unknown confidence", changed));
        let mut changed = base.clone();
        changed.coverage.clear();
        variants.push(("empty coverage", changed));
        let mut changed = base.clone();
        changed.success = SuccessPredicate::All(Vec::new());
        variants.push(("empty success conjunction", changed));

        for (reason, command) in variants {
            let hasher = SpyHasher::default();
            let dependency = command_dependency_digest(&hasher, &command, &evidence)?;
            assert_eq!(dependency, DependencyValue::Unknown, "{reason}");
            assert_eq!(hasher.calls.get(), 0, "{reason}");
        }

        let hasher = SpyHasher::default();
        let dependency = command_dependency_digest(&hasher, &base, &[])?;
        assert_eq!(dependency, DependencyValue::Unknown, "empty provenance");
        assert_eq!(hasher.calls.get(), 0, "empty provenance");
        Ok(())
    }

    #[test]
    fn incomplete_toolchain_facts_are_unknown_without_hashing() -> Result<(), Box<dyn Error>> {
        let base = project_unit()?;
        let mut variants = Vec::new();

        let mut changed = base.clone();
        changed.toolchain.confidence = Confidence::Unknown;
        variants.push(("unknown confidence", changed));
        let mut changed = base.clone();
        changed.toolchain.values.clear();
        variants.push(("empty values", changed));
        let mut changed = base.clone();
        changed
            .toolchain
            .values
            .insert(String::new(), String::from("1.0"));
        variants.push(("empty value name", changed));
        let mut changed = base.clone();
        changed
            .toolchain
            .values
            .insert(String::from("empty"), String::new());
        variants.push(("empty value", changed));
        let mut changed = base;
        changed.toolchain.provenance.clear();
        variants.push(("empty provenance", changed));

        for (reason, unit) in variants {
            let hasher = SpyHasher::default();
            let dependency = toolchain_dependency_digest(&hasher, &unit)?;
            assert_eq!(dependency, DependencyValue::Unknown, "{reason}");
            assert_eq!(hasher.calls.get(), 0, "{reason}");
        }
        Ok(())
    }

    #[test]
    fn length_frames_separate_argument_boundaries() -> Result<(), Box<dyn Error>> {
        let mut first = command()?;
        first.args = vec![OsString::from("ab"), OsString::from("c")];
        let mut second = first.clone();
        second.args = vec![OsString::from("a"), OsString::from("bc")];
        let evidence = [provenance("command/base")];
        assert_ne!(digest(&first, &evidence)?, digest(&second, &evidence)?);
        Ok(())
    }

    #[test]
    fn unknown_and_invalid_provenance_paths_fail_closed_before_hashing()
    -> Result<(), Box<dyn Error>> {
        let command = command()?;
        let cases = [
            (
                PathEncoding::Unknown,
                None,
                FingerprintError::UnknownPathEncoding,
            ),
            (
                PathEncoding::Utf8,
                Some(String::from("unexpected")),
                FingerprintError::InvalidPathEncoding,
            ),
            (
                PathEncoding::UnixBytes,
                None,
                FingerprintError::InvalidPathEncoding,
            ),
            (
                PathEncoding::UnixBytes,
                Some(String::from("not base64")),
                FingerprintError::InvalidPathEncoding,
            ),
            (
                PathEncoding::UnixBytes,
                Some(String::from("YQ==")),
                FingerprintError::InvalidPathEncoding,
            ),
            (
                PathEncoding::WindowsWide,
                Some(String::from("YQ==")),
                FingerprintError::InvalidPathEncoding,
            ),
            (
                PathEncoding::WindowsWide,
                Some(String::from("YQA=")),
                FingerprintError::InvalidPathEncoding,
            ),
        ];

        for (encoding, raw_base64, expected) in cases {
            let evidence = [Provenance {
                rule_id: String::from("command/path"),
                source_path: Some(WirePath {
                    display: String::from("source"),
                    encoding,
                    raw_base64,
                }),
                source_range: None,
                detail: String::from("path encoding fixture"),
            }];
            let hasher = SpyHasher::default();
            let error = match command_dependency_digest(&hasher, &command, &evidence) {
                Err(error) => error,
                Ok(_) => {
                    return Err(io::Error::other("invalid source path was accepted").into());
                }
            };
            assert_eq!(error, expected);
            assert_eq!(hasher.calls.get(), 0);
        }
        assert_ne!(
            FingerprintError::UnknownPathEncoding,
            FingerprintError::UnsupportedPathEncoding
        );
        Ok(())
    }

    #[test]
    fn raw_provenance_paths_use_lossless_bytes_not_display_text() -> Result<(), Box<dyn Error>> {
        let command = command()?;
        let provenance_with = |display: &str, raw_base64: &str| Provenance {
            rule_id: String::from("command/path"),
            source_path: Some(WirePath {
                display: display.to_owned(),
                encoding: PathEncoding::UnixBytes,
                raw_base64: Some(raw_base64.to_owned()),
            }),
            source_range: None,
            detail: String::from("native path fixture"),
        };

        let first = digest(&command, &[provenance_with("first display", "/w==")])?;
        let same_native = digest(&command, &[provenance_with("other display", "/w==")])?;
        let first_entry = provenance_with("first display", "/w==");
        let alias_entry = provenance_with("other display", "/w==");
        let aliases = digest(&command, &[first_entry, alias_entry])?;
        let other_native = digest(&command, &[provenance_with("first display", "/g==")])?;
        let windows_unpaired_surrogate = Provenance {
            rule_id: String::from("command/path"),
            source_path: Some(WirePath {
                display: String::from("replacement display"),
                encoding: PathEncoding::WindowsWide,
                raw_base64: Some(String::from("ANg=")),
            }),
            source_range: None,
            detail: String::from("native path fixture"),
        };

        assert_eq!(first, same_native);
        assert_eq!(first, aliases);
        assert_ne!(first, other_native);
        assert!(matches!(
            command_dependency_digest(&FixtureHasher, &command, &[windows_unpaired_surrogate])?,
            DependencyValue::Known(_)
        ));
        Ok(())
    }

    #[test]
    fn invalid_provenance_fails_before_hashing() -> Result<(), Box<dyn Error>> {
        let command = command()?;
        let invalid = [
            Provenance {
                rule_id: String::new(),
                source_path: None,
                source_range: None,
                detail: String::from("detail"),
            },
            Provenance {
                rule_id: String::from("rule"),
                source_path: None,
                source_range: None,
                detail: String::from("  "),
            },
            Provenance {
                rule_id: String::from("rule"),
                source_path: None,
                source_range: Some(crate::domain::TextRange::new(0, 1)?),
                detail: String::from("detail"),
            },
        ];

        for provenance in invalid {
            let hasher = SpyHasher::default();
            let error = match command_dependency_digest(&hasher, &command, &[provenance]) {
                Err(error) => error,
                Ok(_) => {
                    return Err(io::Error::other("invalid command provenance was accepted").into());
                }
            };
            assert_eq!(error, FingerprintError::InvalidProvenance);
            assert_eq!(hasher.calls.get(), 0);
        }

        let mut unit = project_unit()?;
        unit.toolchain.provenance = vec![Provenance {
            rule_id: String::from("rule"),
            source_path: None,
            source_range: None,
            detail: String::new(),
        }];
        let hasher = SpyHasher::default();
        let error = match toolchain_dependency_digest(&hasher, &unit) {
            Err(error) => error,
            Ok(_) => {
                return Err(io::Error::other("invalid toolchain provenance was accepted").into());
            }
        };
        assert_eq!(error, FingerprintError::InvalidProvenance);
        assert_eq!(hasher.calls.get(), 0);
        Ok(())
    }

    #[test]
    fn secret_like_environment_names_fail_before_hashing_without_content_leakage()
    -> Result<(), Box<dyn Error>> {
        for name in [
            "api_token",
            "ClientSecret",
            "db_PaSsWoRd",
            "legacy_passwd",
            "service_credential",
            "oauth_client",
            "browser_cookie",
            "user_session",
            "signing_private_key",
            "cloud_access_key",
            "access-key",
            "aws_access_key_id",
            "GoOgLe_Client_Secret",
            "azure_auth_token",
            "github_token",
        ] {
            let mut command = command()?;
            command.env = BTreeMap::from([(
                OsString::from(name),
                OsString::from("SENSITIVE_SAMPLE_VALUE"),
            )]);
            assert_eq!(
                validate_command_environment_privacy(&command),
                Err(FingerprintError::SecretLikeEnvironment)
            );
            let hasher = SpyHasher::default();
            let error = match command_dependency_digest(&hasher, &command, &[]) {
                Err(error) => error,
                Ok(_) => {
                    return Err(io::Error::other("secret-like environment was accepted").into());
                }
            };
            assert_eq!(error, FingerprintError::SecretLikeEnvironment);
            assert_eq!(hasher.calls.get(), 0);
            let display = error.to_string();
            let debug = format!("{error:?}");
            for rendered in [&display, &debug] {
                assert!(!rendered.contains(name));
                assert!(!rendered.contains("SENSITIVE_SAMPLE_VALUE"));
            }
        }
        Ok(())
    }

    #[test]
    fn shared_secret_name_classifier_has_one_conservative_vocabulary() {
        for name in [
            "API_TOKEN",
            "clientSecret",
            "DB_PASSWORD",
            "legacy_passwd",
            "service_credential",
            "oauth_client",
            "browser_cookie",
            "user_session",
            "signing_private_key",
            "PRIVATE_MATERIAL",
            "cloud_access_key",
            "access-key",
            "AWS_ACCESS_KEY_ID",
            "AWS_REGION",
            "google_client_secret",
            "GOOGLE_PROJECT",
            "Azure_Auth_Token",
            "AZURE_TENANT",
            "SSH_AUTH_SOCK",
            "OAuthToken",
            "Authorization",
            "MONKEY",
        ] {
            assert!(
                is_secret_like_name(name),
                "expected `{name}` to be secret-like"
            );
        }
        for name in [
            "PATH",
            "PROFILE",
            "AUTHOR",
            "GIT_AUTHOR_NAME",
            "GIT_AUTHOR_DATE",
            "CARGO_HOME",
            "RUSTUP_HOME",
            "GOMODCACHE",
        ] {
            assert!(
                !is_secret_like_name(name),
                "expected `{name}` to remain ordinary"
            );
        }
    }

    #[test]
    fn credential_literals_in_argv_fail_before_hashing_without_content_leakage()
    -> Result<(), Box<dyn Error>> {
        for (args, literal) in [
            (vec!["--api-token=literal-inline"], "literal-inline"),
            (vec!["--cookie:literal-colon"], "literal-colon"),
            (vec!["--password", "literal-following"], "literal-following"),
            (
                vec!["-H", "Authorization: Bearer literal-header"],
                "literal-header",
            ),
            (
                vec!["https://user:literal-uri@example.invalid/path"],
                "literal-uri",
            ),
            (
                vec!["https://literal-userinfo@example.invalid/path"],
                "literal-userinfo",
            ),
            (vec!["SESSION_ID=literal-assignment"], "literal-assignment"),
        ] {
            let mut command = command()?;
            command.args = args.iter().map(OsString::from).collect();
            assert_eq!(
                validate_command_privacy(&command),
                Err(FingerprintError::SecretLikeArgument)
            );
            let hasher = SpyHasher::default();
            let error = match command_dependency_digest(&hasher, &command, &[]) {
                Err(error) => error,
                Ok(_) => {
                    return Err(io::Error::other("credential-like argv was accepted").into());
                }
            };
            assert_eq!(error, FingerprintError::SecretLikeArgument);
            assert_eq!(hasher.calls.get(), 0);
            assert!(!error.to_string().contains(literal));
            assert!(!format!("{error:?}").contains(literal));
        }
        Ok(())
    }

    #[test]
    fn ordinary_short_options_remain_allowed() {
        for argv in [
            vec!["tool", "-p", "ordinary-value"],
            vec!["tool", "--verbose", "ordinary-value"],
            vec!["tool", "--token", "--verbose"],
        ] {
            assert_eq!(validate_argv_privacy(argv), Ok(()));
        }
    }

    #[test]
    fn effective_environment_digest_is_known_empty_and_sensitive_to_names_and_values()
    -> Result<(), Box<dyn Error>> {
        let empty = environment_dependency_digest(&FixtureHasher, &BTreeMap::new())?;
        let first = environment_dependency_digest(
            &FixtureHasher,
            &BTreeMap::from([(OsString::from("PATH"), OsString::from("/one"))]),
        )?;
        let second = environment_dependency_digest(
            &FixtureHasher,
            &BTreeMap::from([(OsString::from("PATH"), OsString::from("/two"))]),
        )?;
        let renamed = environment_dependency_digest(
            &FixtureHasher,
            &BTreeMap::from([(OsString::from("HOME"), OsString::from("/one"))]),
        )?;

        assert!(matches!(empty, DependencyValue::Known(_)));
        assert_ne!(empty, first);
        assert_ne!(first, second);
        assert_ne!(first, renamed);
        Ok(())
    }

    #[test]
    fn effective_environment_digest_rejects_secret_like_names_before_hashing() {
        let hasher = SpyHasher::default();
        let environment = BTreeMap::from([(
            OsString::from("API_TOKEN"),
            OsString::from("must-not-be-digested"),
        )]);

        assert_eq!(
            environment_dependency_digest(&hasher, &environment),
            Err(FingerprintError::SecretLikeEnvironment)
        );
        assert_eq!(hasher.calls.get(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_environment_name_fails_before_hashing() -> Result<(), Box<dyn Error>> {
        use std::os::unix::ffi::OsStringExt as _;

        let mut command = command()?;
        command.env = BTreeMap::from([(
            OsString::from_vec(vec![b'N', 0xff]),
            OsString::from("SENSITIVE_SAMPLE_VALUE"),
        )]);
        let hasher = SpyHasher::default();
        let error = match command_dependency_digest(&hasher, &command, &[]) {
            Err(error) => error,
            Ok(_) => {
                return Err(io::Error::other("unclassifiable environment was accepted").into());
            }
        };
        assert_eq!(error, FingerprintError::UnclassifiableEnvironmentName);
        assert_eq!(hasher.calls.get(), 0);
        assert!(!error.to_string().contains("SENSITIVE_SAMPLE_VALUE"));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn native_values_are_lossless_even_when_display_text_would_collide()
    -> Result<(), Box<dyn Error>> {
        use std::os::unix::ffi::OsStringExt as _;

        let first_native = OsString::from_vec(vec![b'x', 0xff]);
        let second_native = OsString::from_vec(vec![b'x', 0xfe]);
        assert_eq!(
            first_native.to_string_lossy(),
            second_native.to_string_lossy()
        );
        assert_ne!(
            canonical_native_os_bytes(&first_native),
            canonical_native_os_bytes(&second_native)
        );

        let mut first = command()?;
        first.program = first_native.clone();
        first.args = vec![first_native.clone()];
        first.cwd = RepoRelativePath::new(OsString::from_vec(vec![b'd', 0xff]))?;
        first.env.clear();
        let mut second = first.clone();
        second.program = second_native.clone();
        second.args = vec![second_native.clone()];
        second.cwd = RepoRelativePath::new(OsString::from_vec(vec![b'd', 0xfe]))?;
        second.env.clear();
        let evidence = [provenance("command/base")];
        assert_ne!(digest(&first, &evidence)?, digest(&second, &evidence)?);
        Ok(())
    }

    #[test]
    fn toolchain_digest_is_order_stable_and_sensitive_to_each_fact() -> Result<(), Box<dyn Error>> {
        let first = project_unit()?;
        let expected = known_toolchain_digest(&first)?;
        let mut reordered = first.clone();
        reordered.toolchain = ToolchainInfo::new(
            [
                (String::from("rustc"), String::from("1.85.0")),
                (String::from("cargo"), String::from("1.85.0")),
            ]
            .into_iter()
            .collect(),
            vec![provenance("toolchain/rustc"), provenance("toolchain/cargo")],
            Confidence::High,
        );
        assert_eq!(known_toolchain_digest(&reordered)?, expected);

        let mut changed_value = first.clone();
        changed_value
            .toolchain
            .values
            .insert(String::from("rustc"), String::from("1.86.0"));
        assert_ne!(known_toolchain_digest(&changed_value)?, expected);
        let mut changed_source = first.clone();
        changed_source.toolchain.provenance = vec![provenance("toolchain/changed")];
        assert_ne!(known_toolchain_digest(&changed_source)?, expected);
        let mut changed_confidence = first;
        changed_confidence.toolchain.confidence = Confidence::Medium;
        assert_ne!(known_toolchain_digest(&changed_confidence)?, expected);
        Ok(())
    }

    #[test]
    fn ordered_execution_aggregation_preserves_order_duplicates_and_axes() {
        let first = execution_dependencies("command:a", "toolchain:a", "environment:a");
        let second = execution_dependencies("command:b", "toolchain:b", "environment:b");

        let forward = aggregate_ordered_execution_dependencies(
            &FixtureHasher,
            &[first.clone(), second.clone()],
        );
        let reverse = aggregate_ordered_execution_dependencies(
            &FixtureHasher,
            &[second.clone(), first.clone()],
        );
        let duplicated =
            aggregate_ordered_execution_dependencies(&FixtureHasher, &[first.clone(), first]);
        let single = aggregate_ordered_execution_dependencies(&FixtureHasher, &[second]);

        assert_ne!(forward.command(), reverse.command());
        assert_ne!(forward.toolchain(), reverse.toolchain());
        assert_ne!(forward.environment(), reverse.environment());
        assert_ne!(duplicated.command(), single.command());
        assert_ne!(forward.command(), forward.toolchain());
        assert_ne!(forward.toolchain(), forward.environment());
        assert_eq!(
            forward.command(),
            &DependencyValue::Known(Digest::from("fixture:67afb7e658ed6553"))
        );
        assert_eq!(
            forward.toolchain(),
            &DependencyValue::Known(Digest::from("fixture:018e6333e82ea759"))
        );
        assert_eq!(
            forward.environment(),
            &DependencyValue::Known(Digest::from("fixture:b2968def73b65637"))
        );
    }

    #[test]
    fn ordered_execution_aggregation_fails_each_incomplete_axis_closed() {
        let complete = execution_dependencies("command:a", "toolchain:a", "environment:a");
        let incomplete = ExecutionDependencyFingerprint::new(
            DependencyValue::Unknown,
            DependencyValue::Known(Digest::from("toolchain:b")),
            DependencyValue::Known(Digest::from("")),
        );
        let hasher = SpyHasher::default();

        let aggregate = aggregate_ordered_execution_dependencies(&hasher, &[complete, incomplete]);

        assert_eq!(aggregate.command(), &DependencyValue::Unknown);
        assert!(matches!(aggregate.toolchain(), DependencyValue::Known(_)));
        assert_eq!(aggregate.environment(), &DependencyValue::Unknown);
        assert_eq!(hasher.calls.get(), 1);

        let empty_hasher = SpyHasher::default();
        let empty = aggregate_ordered_execution_dependencies(&empty_hasher, &[]);
        assert_eq!(empty.command(), &DependencyValue::Unknown);
        assert_eq!(empty.toolchain(), &DependencyValue::Unknown);
        assert_eq!(empty.environment(), &DependencyValue::Unknown);
        assert_eq!(empty_hasher.calls.get(), 0);
    }

    #[test]
    fn command_set_confidence_is_bound_and_low_confidence_fails_only_command_closed() {
        let execution = execution_dependencies("command:a", "toolchain:a", "environment:a");
        let high = bind_command_set_confidence(
            &FixtureHasher,
            &execution,
            Confidence::High,
            Confidence::High,
        );
        let medium_resolution = bind_command_set_confidence(
            &FixtureHasher,
            &execution,
            Confidence::Medium,
            Confidence::High,
        );
        let medium_coverage = bind_command_set_confidence(
            &FixtureHasher,
            &execution,
            Confidence::High,
            Confidence::Medium,
        );
        assert!(matches!(high.command(), DependencyValue::Known(_)));
        assert_ne!(high.command(), medium_resolution.command());
        assert_ne!(high.command(), medium_coverage.command());
        assert_ne!(medium_resolution.command(), medium_coverage.command());

        for confidence in [Confidence::Low, Confidence::Unknown] {
            let bound = bind_command_set_confidence(
                &FixtureHasher,
                &execution,
                confidence,
                Confidence::High,
            );
            assert_eq!(bound.command(), &DependencyValue::Unknown);
            assert_eq!(bound.toolchain(), execution.toolchain());
            assert_eq!(bound.environment(), execution.environment());
        }
    }

    #[test]
    fn command_set_confidence_does_not_hash_an_unknown_ordered_command() {
        let hasher = SpyHasher::default();
        let execution = ExecutionDependencyFingerprint::new(
            DependencyValue::Unknown,
            DependencyValue::Known(Digest::from("toolchain:a")),
            DependencyValue::Known(Digest::from("environment:a")),
        );
        let bound =
            bind_command_set_confidence(&hasher, &execution, Confidence::High, Confidence::High);
        assert_eq!(bound.command(), &DependencyValue::Unknown);
        assert_eq!(hasher.calls.get(), 0);
    }

    #[test]
    fn worktree_base_task_dependency_is_known_for_head_and_not_applicable_when_unborn()
    -> Result<(), Box<dyn Error>> {
        let first = ScopeHead::Commit(crate::scope::ScopeObjectId::new(
            GitObjectFormat::Sha1,
            b"1111111111111111111111111111111111111111",
        )?);
        let second = ScopeHead::Commit(crate::scope::ScopeObjectId::new(
            GitObjectFormat::Sha1,
            b"2222222222222222222222222222222222222222",
        )?);

        let first_dependency = worktree_base_task_dependency(&FixtureHasher, &first);
        assert!(matches!(first_dependency, BaseTaskDependency::Known(_)));
        assert_ne!(
            first_dependency,
            worktree_base_task_dependency(&FixtureHasher, &second)
        );

        let hasher = SpyHasher::default();
        assert_eq!(
            worktree_base_task_dependency(&hasher, &ScopeHead::Unborn(GitObjectFormat::Sha256)),
            BaseTaskDependency::NotApplicable
        );
        assert_eq!(hasher.calls.get(), 0);
        Ok(())
    }

    #[test]
    fn process_output_unavailable_markers_are_stream_separated_fixed_vectors() {
        let (stdout, stderr) = process_output_unavailable_digests(&FixtureHasher);
        assert_eq!(stdout.as_str(), "fixture:38e9dcd2487583e9");
        assert_eq!(stderr.as_str(), "fixture:02b8f6d229228cda");
        assert_ne!(stdout, stderr);
    }

    #[test]
    fn evidence_behavior_digest_is_pinned_to_operation_control_and_coverage_v2() {
        assert_eq!(
            EVIDENCE_BEHAVIOR_PROTOCOL_VERSION,
            "forge.evidence-behavior/v6"
        );
        assert_eq!(
            OPERATION_CONTROL_PROTOCOL_VERSION,
            "forge.operation-control/v1"
        );
        assert_eq!(
            COVERAGE_AGGREGATION_PROTOCOL_VERSION,
            "forge.coverage-aggregation/v2"
        );
        assert_eq!(
            evidence_behavior_digest(&FixtureHasher).as_str(),
            "fixture:2ff6f5d16b92507f"
        );
    }

    #[test]
    fn fixed_vectors_pin_command_toolchain_protocol_and_dependency_domains()
    -> Result<(), Box<dyn Error>> {
        let command = command()?;
        let unit = project_unit()?;
        assert_eq!(
            command_toolchain_fingerprint_protocol_digest(&FixtureHasher).as_str(),
            "fixture:38dc4d1f6c58e179"
        );
        assert_eq!(
            digest(&command, &[provenance("command/base")])?.as_str(),
            "fixture:07667a0350b767cf"
        );
        assert_eq!(
            known_toolchain_digest(&unit)?.as_str(),
            "fixture:88466b243e61f739"
        );
        Ok(())
    }
}
