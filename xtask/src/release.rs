//! Deterministic, candidate-controlled assembly of reviewable release assets.
//!
//! These tasks deliberately stop before provenance, signing, upload, or release authorization.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component as PathComponent, Path, PathBuf};
use std::time::Duration;

use forge_core::ports::{
    EnvPolicy, ExecSpec, OutputPolicy, ProcessObservation, ProcessPort, StdinPolicy,
};
use forge_core::{Mutability, NetworkIntent, RepoRelativePath};
use forge_runtime::fs::RepositoryWriter;
use forge_runtime::git::{HARDENED_GIT_ENV, HARDENED_GIT_GLOBAL_ARGS};
use forge_runtime::process::SynchronousProcessRunner;
use forge_schema::{
    ReleaseArtifactData, ReleaseArtifactKindData, ReleaseAuthorityStatusData,
    ReleaseCandidateStatusData, ReleaseChannelData, ReleaseDescriptorData, ReleaseDistributionData,
    ReleaseManifestData, ReleasePredicateTypeData, ReleaseProvenanceData,
    ReleaseProvenanceStatusData, ReleaseRollbackData, ReleaseRollbackStatusData, ReleaseSha256Data,
    ReleaseSigningData, ReleaseSubjectSetData, SchemaKind,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

const RELEASE_VERSION: &str = env!("CARGO_PKG_VERSION");
const MANIFEST_FILE: &str = "release-manifest.json";
const CHECKSUMS_FILE: &str = "SHA256SUMS";
const MAX_BINARY_BYTES: u64 = 256 * 1024 * 1024;
const MAX_METADATA_BYTES: usize = 32 * 1024 * 1024;
const MAX_DIAGNOSTIC_BYTES: usize = 16 * 1024;
const MAX_BUILD_STREAM_BYTES: usize = 4 * 1024 * 1024;
const FINALIZED_ASSET_COUNT: u16 = 12;
const GIT_TIMEOUT: Duration = Duration::from_secs(120);
const CARGO_METADATA_TIMEOUT: Duration = Duration::from_secs(300);
const CARGO_BUILD_TIMEOUT: Duration = Duration::from_secs(1_800);
const REJECTED_RELEASE_GIT_ENV: &[&str] = &[
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_NAMESPACE",
    "GIT_SHALLOW_FILE",
    "GIT_REPLACE_REF_BASE",
    "GIT_EXEC_PATH",
];

pub(crate) const BUILD_HELP: &str = "usage: xtask release-build --target <TRIPLE> --output-dir <DIR>\n\nBuilds one accepted target from a clean Git checkout in a fresh temporary Cargo target directory, then stages the binary and its source-bound CycloneDX 1.6 SBOM. Run the compiled xtask directly when a nested `cargo run` is unsuitable.";
pub(crate) const FINALIZE_HELP: &str = "usage: xtask release-finalize --output-dir <DIR>\n\nRequires all five target binaries and SBOMs, then writes release-manifest.json and SHA256SUMS without overwriting different bytes.";
pub(crate) const CHECK_HELP: &str = "usage: xtask release-check --output-dir <DIR>\n\nRecomputes the complete local asset set, binary formats, SBOMs, manifest, and SHA-256 checksums. Success is local consistency evidence, not provenance, signature, approval, upload, or publication.";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BinaryFormat {
    ElfX86_64Static,
    ElfAarch64Static,
    MachOX86_64,
    MachOAarch64,
    PeX86_64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReleaseTarget {
    triple: &'static str,
    executable_name: &'static str,
    format: BinaryFormat,
}

const RELEASE_TARGETS: [ReleaseTarget; 5] = [
    ReleaseTarget {
        triple: "x86_64-unknown-linux-musl",
        executable_name: "forge",
        format: BinaryFormat::ElfX86_64Static,
    },
    ReleaseTarget {
        triple: "aarch64-unknown-linux-musl",
        executable_name: "forge",
        format: BinaryFormat::ElfAarch64Static,
    },
    ReleaseTarget {
        triple: "x86_64-apple-darwin",
        executable_name: "forge",
        format: BinaryFormat::MachOX86_64,
    },
    ReleaseTarget {
        triple: "aarch64-apple-darwin",
        executable_name: "forge",
        format: BinaryFormat::MachOAarch64,
    },
    ReleaseTarget {
        triple: "x86_64-pc-windows-msvc",
        executable_name: "forge.exe",
        format: BinaryFormat::PeX86_64,
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReleaseErrorKind {
    Usage,
    Environment,
    Internal,
}

#[derive(Debug)]
pub(crate) struct ReleaseError {
    kind: ReleaseErrorKind,
    message: String,
}

impl ReleaseError {
    pub(crate) fn kind(&self) -> ReleaseErrorKind {
        self.kind
    }

    fn usage(message: impl Into<String>) -> Self {
        Self {
            kind: ReleaseErrorKind::Usage,
            message: message.into(),
        }
    }

    fn environment(message: impl Into<String>) -> Self {
        Self {
            kind: ReleaseErrorKind::Environment,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            kind: ReleaseErrorKind::Internal,
            message: message.into(),
        }
    }
}

impl fmt::Display for ReleaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ReleaseError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ReleaseCommandOutput {
    Help(&'static str),
    Completed(String),
}

#[derive(Debug)]
struct BuildRequest {
    target: &'static ReleaseTarget,
    output_directory: PathBuf,
}

pub(crate) fn run_build(arguments: &[String]) -> Result<ReleaseCommandOutput, ReleaseError> {
    if is_help(arguments) {
        return Ok(ReleaseCommandOutput::Help(BUILD_HELP));
    }
    let options = parse_options(arguments, &["--target", "--output-dir"])?;
    let request = BuildRequest {
        target: parse_target(required_option(&options, "--target")?)?,
        output_directory: PathBuf::from(required_option(&options, "--output-dir")?),
    };
    let repository = repository_root()?;
    let output = open_output_directory(&repository, &request.output_directory)?;
    let targets = std::slice::from_ref(request.target);
    let before = RepositorySnapshot::capture(&repository, targets)?;
    let build_directory = tempdir().map_err(|error| {
        ReleaseError::environment(format!(
            "failed to create a fresh temporary Cargo target directory: {error}"
        ))
    })?;
    let build_output = RepositoryWriter::new(build_directory.path()).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to pin the fresh Cargo target directory before building: {error}"
        ))
    })?;
    cargo_build(&repository, request.target, build_directory.path())?;
    let after_build = RepositorySnapshot::capture(&repository, targets)?;
    before.require_same(&after_build, "Cargo release build")?;
    let binary = read_built_binary(&build_output, request.target)?;
    validate_binary_format(request.target, &binary)?;
    stage_built(&output, request.target, &binary, &before)?;
    let after_stage = RepositorySnapshot::capture(&repository, targets)?;
    before.require_same(&after_stage, "release asset staging")?;
    Ok(ReleaseCommandOutput::Completed(format!(
        "built and staged {} with its CycloneDX SBOM in {}; local candidate only, not signed or published",
        binary_asset_name(request.target),
        output.root().display()
    )))
}

pub(crate) fn run_finalize(arguments: &[String]) -> Result<ReleaseCommandOutput, ReleaseError> {
    if is_help(arguments) {
        return Ok(ReleaseCommandOutput::Help(FINALIZE_HELP));
    }
    let options = parse_options(arguments, &["--output-dir"])?;
    let output = PathBuf::from(required_option(&options, "--output-dir")?);
    let repository = repository_root()?;
    let output_writer = open_output_directory(&repository, &output)?;
    let before = RepositorySnapshot::capture(&repository, &RELEASE_TARGETS)?;
    finalize(&output_writer, &before)?;
    let after = RepositorySnapshot::capture(&repository, &RELEASE_TARGETS)?;
    before.require_same(&after, "release finalization")?;
    Ok(ReleaseCommandOutput::Completed(format!(
        "finalized the complete local {} asset set in {}; external provenance, signature, approval, upload, and publication remain required",
        RELEASE_VERSION,
        output_writer.root().display()
    )))
}

pub(crate) fn run_check(arguments: &[String]) -> Result<ReleaseCommandOutput, ReleaseError> {
    if is_help(arguments) {
        return Ok(ReleaseCommandOutput::Help(CHECK_HELP));
    }
    let options = parse_options(arguments, &["--output-dir"])?;
    let output = PathBuf::from(required_option(&options, "--output-dir")?);
    let repository = repository_root()?;
    let output_writer = open_output_directory(&repository, &output)?;
    let before = RepositorySnapshot::capture(&repository, &RELEASE_TARGETS)?;
    check(&output_writer, &before)?;
    let after = RepositorySnapshot::capture(&repository, &RELEASE_TARGETS)?;
    before.require_same(&after, "release verification")?;
    Ok(ReleaseCommandOutput::Completed(format!(
        "verified the complete local {} asset set in {}; this does not verify provenance, signature, approval, upload, or publication",
        RELEASE_VERSION,
        output_writer.root().display()
    )))
}

fn is_help(arguments: &[String]) -> bool {
    matches!(arguments, [argument] if argument == "--help" || argument == "help")
}

fn parse_options(
    arguments: &[String],
    allowed: &[&str],
) -> Result<BTreeMap<String, String>, ReleaseError> {
    if arguments.is_empty() || arguments.len() % 2 != 0 {
        return Err(ReleaseError::usage(
            "release command options must be explicit `--name value` pairs",
        ));
    }
    let allowed: BTreeSet<&str> = allowed.iter().copied().collect();
    let mut options = BTreeMap::new();
    for pair in arguments.chunks_exact(2) {
        let name = &pair[0];
        let value = &pair[1];
        if !allowed.contains(name.as_str()) {
            return Err(ReleaseError::usage(format!(
                "unknown release option `{name}`"
            )));
        }
        if value.is_empty() || value.starts_with("--") {
            return Err(ReleaseError::usage(format!(
                "release option `{name}` requires a value"
            )));
        }
        if options.insert(name.clone(), value.clone()).is_some() {
            return Err(ReleaseError::usage(format!(
                "release option `{name}` was provided more than once"
            )));
        }
    }
    Ok(options)
}

fn required_option<'a>(
    options: &'a BTreeMap<String, String>,
    name: &str,
) -> Result<&'a str, ReleaseError> {
    options
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| ReleaseError::usage(format!("missing required release option `{name}`")))
}

fn parse_target(triple: &str) -> Result<&'static ReleaseTarget, ReleaseError> {
    RELEASE_TARGETS
        .iter()
        .find(|target| target.triple == triple)
        .ok_or_else(|| {
            ReleaseError::usage(format!(
                "unsupported release target `{triple}`; accepted targets: {}",
                RELEASE_TARGETS
                    .iter()
                    .map(|target| target.triple)
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })
}

fn repository_root() -> Result<PathBuf, ReleaseError> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| ReleaseError::internal("xtask manifest directory has no repository parent"))
}

fn cargo_program() -> OsString {
    env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RepositorySnapshot {
    source_commit: String,
    status: Vec<u8>,
    cargo_lock: Vec<u8>,
    metadata_by_target: BTreeMap<String, Vec<u8>>,
}

impl RepositorySnapshot {
    fn capture(repository: &Path, targets: &[ReleaseTarget]) -> Result<Self, ReleaseError> {
        require_expected_git_worktree(repository)?;
        let source_commit = git_head(repository)?;
        let status = git_status(repository)?;
        require_clean_status(&status)?;
        let cargo_lock = read_bounded(
            &repository.join("Cargo.lock"),
            MAX_METADATA_BYTES as u64,
            "Cargo.lock",
        )?;
        let mut metadata_by_target = BTreeMap::new();
        for target in targets {
            metadata_by_target.insert(
                target.triple.to_owned(),
                cargo_metadata(repository, target)?,
            );
        }

        require_expected_git_worktree(repository)?;
        let later_lock = read_bounded(
            &repository.join("Cargo.lock"),
            MAX_METADATA_BYTES as u64,
            "Cargo.lock",
        )?;
        let later_status = git_status(repository)?;
        require_clean_status(&later_status)?;
        let later_commit = git_head(repository)?;
        if source_commit != later_commit || status != later_status || cargo_lock != later_lock {
            return Err(ReleaseError::environment(
                "repository HEAD, complete Git status, or Cargo.lock changed while the release snapshot was captured",
            ));
        }

        Ok(Self {
            source_commit,
            status,
            cargo_lock,
            metadata_by_target,
        })
    }

    fn metadata(&self, target: &ReleaseTarget) -> Result<&[u8], ReleaseError> {
        self.metadata_by_target
            .get(target.triple)
            .map(Vec::as_slice)
            .ok_or_else(|| {
                ReleaseError::internal(format!(
                    "release snapshot omitted target-filtered Cargo metadata for {}",
                    target.triple
                ))
            })
    }

    fn require_same(&self, later: &Self, operation: &str) -> Result<(), ReleaseError> {
        if self == later {
            Ok(())
        } else {
            Err(ReleaseError::environment(format!(
                "repository HEAD, complete Git status, Cargo.lock, or target-filtered Cargo metadata changed during {operation}"
            )))
        }
    }
}

fn git_output(
    repository: &Path,
    arguments: &[&str],
    label: &str,
    stdout_limit: usize,
) -> Result<Vec<u8>, ReleaseError> {
    reject_git_redirect_environment(env::vars_os().map(|(key, _)| key))?;
    let canonical_repository = fs::canonicalize(repository).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to resolve release source repository {}: {error}",
            repository.display()
        ))
    })?;
    let mut worktree_argument = OsString::from("--work-tree=");
    worktree_argument.push(canonical_repository.as_os_str());
    let mut argv: Vec<OsString> = HARDENED_GIT_GLOBAL_ARGS
        .iter()
        .map(OsString::from)
        .collect();
    argv.push(worktree_argument);
    argv.extend(arguments.iter().map(OsString::from));
    let mut environment = EnvPolicy::minimal();
    environment.overrides.extend(
        HARDENED_GIT_ENV
            .iter()
            .map(|(key, value)| (OsString::from(key), OsString::from(value))),
    );
    let observation = run_bounded_process(
        repository,
        OsString::from("git"),
        argv,
        environment,
        GIT_TIMEOUT,
        stdout_limit,
        MAX_DIAGNOSTIC_BYTES,
        Mutability::ReadOnly,
        NetworkIntent::Unknown,
        &format!("Git {label}"),
    )?;
    require_process_success(observation, &format!("Git {label}"))
}

fn reject_git_redirect_environment<I>(keys: I) -> Result<(), ReleaseError>
where
    I: IntoIterator<Item = OsString>,
{
    for key in keys {
        if let Some(rejected) = REJECTED_RELEASE_GIT_ENV
            .iter()
            .find(|candidate| git_environment_key_eq(&key, candidate))
        {
            return Err(ReleaseError::environment(format!(
                "ambient Git environment variable `{rejected}` could redirect the release source snapshot; unset it"
            )));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn git_environment_key_eq(key: &std::ffi::OsStr, expected: &str) -> bool {
    key.to_string_lossy().eq_ignore_ascii_case(expected)
}

#[cfg(not(windows))]
fn git_environment_key_eq(key: &std::ffi::OsStr, expected: &str) -> bool {
    key == std::ffi::OsStr::new(expected)
}

fn git_head(repository: &Path) -> Result<String, ReleaseError> {
    let bytes = git_output(
        repository,
        &["rev-parse", "--verify", "HEAD^{commit}"],
        "HEAD read",
        128,
    )?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| ReleaseError::environment("Git HEAD output was not UTF-8"))?
        .trim_end_matches(['\r', '\n']);
    if !matches!(text.len(), 40 | 64)
        || !text
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(ReleaseError::environment(
            "Git HEAD was not one canonical SHA-1 or SHA-256 commit object ID",
        ));
    }
    Ok(text.to_owned())
}

fn git_status(repository: &Path) -> Result<Vec<u8>, ReleaseError> {
    git_output(
        repository,
        &[
            "status",
            "--porcelain=v2",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ],
        "complete status read",
        MAX_METADATA_BYTES,
    )
}

fn require_expected_git_worktree(repository: &Path) -> Result<(), ReleaseError> {
    let bytes = git_output(
        repository,
        &["rev-parse", "--path-format=absolute", "--show-toplevel"],
        "worktree boundary read",
        64 * 1024,
    )?;
    let reported = git_path_from_output(&bytes)?;
    let expected = fs::canonicalize(repository).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to resolve expected release worktree {}: {error}",
            repository.display()
        ))
    })?;
    let actual = fs::canonicalize(&reported).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to resolve Git-reported worktree {}: {error}",
            reported.display()
        ))
    })?;
    if actual == expected {
        Ok(())
    } else {
        Err(ReleaseError::environment(format!(
            "Git worktree boundary {} does not match the release source repository {}",
            actual.display(),
            expected.display()
        )))
    }
}

fn git_path_from_output(bytes: &[u8]) -> Result<PathBuf, ReleaseError> {
    let end = bytes
        .iter()
        .rposition(|byte| !matches!(byte, b'\r' | b'\n'))
        .map_or(0, |index| index + 1);
    let path = &bytes[..end];
    if path.is_empty() || path.contains(&0) || path.contains(&b'\n') || path.contains(&b'\r') {
        return Err(ReleaseError::environment(
            "Git worktree output was empty or contained multiple paths",
        ));
    }
    git_path_from_native_bytes(path)
}

#[cfg(unix)]
fn git_path_from_native_bytes(bytes: &[u8]) -> Result<PathBuf, ReleaseError> {
    use std::os::unix::ffi::OsStringExt as _;

    Ok(PathBuf::from(OsString::from_vec(bytes.to_vec())))
}

#[cfg(not(unix))]
fn git_path_from_native_bytes(bytes: &[u8]) -> Result<PathBuf, ReleaseError> {
    let path = std::str::from_utf8(bytes)
        .map_err(|_| ReleaseError::environment("Git worktree output was not UTF-8"))?;
    Ok(PathBuf::from(path))
}

fn require_clean_status(status: &[u8]) -> Result<(), ReleaseError> {
    if status.is_empty() {
        Ok(())
    } else {
        Err(ReleaseError::environment(
            "release assembly requires a clean Git checkout with no tracked, untracked, or submodule changes",
        ))
    }
}

fn cargo_build(
    repository: &Path,
    target: &ReleaseTarget,
    target_directory: &Path,
) -> Result<(), ReleaseError> {
    let mut arguments = [
        "build",
        "--release",
        "--locked",
        "--offline",
        "-p",
        "forge-cli",
        "--bin",
        "forge",
        "--target",
        target.triple,
        "--target-dir",
    ]
    .into_iter()
    .map(OsString::from)
    .collect::<Vec<_>>();
    arguments.push(target_directory.as_os_str().to_owned());
    let label = format!("Cargo release build for {}", target.triple);
    let observation = run_bounded_process(
        repository,
        cargo_program(),
        arguments,
        cargo_environment(),
        CARGO_BUILD_TIMEOUT,
        MAX_BUILD_STREAM_BYTES,
        MAX_BUILD_STREAM_BYTES,
        Mutability::Unknown,
        NetworkIntent::OfflineRequested,
        &label,
    )?;
    let _ = require_process_success(observation, &label)?;
    Ok(())
}

fn read_built_binary(
    build_output: &RepositoryWriter,
    target: &ReleaseTarget,
) -> Result<Vec<u8>, ReleaseError> {
    validate_visible_root(build_output, "temporary Cargo target")?;
    let relative = Path::new(target.triple)
        .join("release")
        .join(target.executable_name);
    let bytes = build_output
        .read_optional_bounded(&relative, MAX_BINARY_BYTES as usize)
        .map_err(|error| {
            ReleaseError::environment(format!(
                "failed to read the built release binary through the pinned temporary target handle for {}: {error}",
                target.triple
            ))
        })?
        .ok_or_else(|| {
            ReleaseError::environment(format!(
                "Cargo reported success but the pinned temporary target contains no release binary for {}",
                target.triple
            ))
        })?;
    validate_visible_root(build_output, "temporary Cargo target")?;
    Ok(bytes)
}

fn cargo_metadata(repository: &Path, target: &ReleaseTarget) -> Result<Vec<u8>, ReleaseError> {
    let label = format!("Cargo metadata for {}", target.triple);
    let observation = run_bounded_process(
        repository,
        cargo_program(),
        [
            "metadata",
            "--locked",
            "--offline",
            "--format-version",
            "1",
            "--filter-platform",
            target.triple,
        ]
        .into_iter()
        .map(OsString::from)
        .collect(),
        cargo_environment(),
        CARGO_METADATA_TIMEOUT,
        MAX_METADATA_BYTES,
        MAX_DIAGNOSTIC_BYTES,
        Mutability::Unknown,
        NetworkIntent::OfflineRequested,
        &label,
    )?;
    require_process_success(observation, &label)
}

fn cargo_environment() -> EnvPolicy {
    let mut policy = EnvPolicy::minimal();
    policy.inherit.extend(
        env::vars_os()
            .map(|(key, _)| key)
            .filter(|key| is_cargo_build_environment_key(key)),
    );
    policy
        .overrides
        .insert(OsString::from("RUSTUP_AUTO_INSTALL"), OsString::from("0"));
    policy
        .overrides
        .insert(OsString::from("CARGO_NET_OFFLINE"), OsString::from("true"));
    policy
}

fn is_cargo_build_environment_key(key: &OsStr) -> bool {
    let Some(key) = key.to_str() else {
        return false;
    };
    if forge_core::fingerprint::is_secret_like_name(key) {
        return false;
    }
    let key = key.to_ascii_uppercase();
    matches!(
        key.as_str(),
        "AR" | "CC"
            | "CFLAGS"
            | "CPATH"
            | "CXX"
            | "CXXFLAGS"
            | "DEVELOPER_DIR"
            | "INCLUDE"
            | "LDFLAGS"
            | "LIB"
            | "LIBPATH"
            | "LIBRARY_PATH"
            | "MACOSX_DEPLOYMENT_TARGET"
            | "PKG_CONFIG_PATH"
            | "RANLIB"
            | "RUSTC"
            | "RUSTC_WRAPPER"
            | "RUSTC_WORKSPACE_WRAPPER"
            | "RUSTDOC"
            | "RUSTFLAGS"
            | "CARGO_ENCODED_RUSTFLAGS"
            | "RUSTUP_TOOLCHAIN"
            | "SDKROOT"
            | "UNIVERSALCRTSDKDIR"
            | "UCRTVERSION"
            | "VCINSTALLDIR"
            | "VCTOOLSINSTALLDIR"
            | "WINDOWSSDKDIR"
            | "WINDOWSSDKVERSION"
    ) || [
        "AR_",
        "CC_",
        "CFLAGS_",
        "CXX_",
        "CXXFLAGS_",
        "PKG_CONFIG_",
        "RANLIB_",
        "CARGO_TARGET_",
    ]
    .iter()
    .any(|prefix| key.starts_with(prefix))
}

#[allow(clippy::too_many_arguments)]
fn run_bounded_process(
    repository: &Path,
    program: OsString,
    args: Vec<OsString>,
    env: EnvPolicy,
    timeout: Duration,
    stdout_limit: usize,
    stderr_limit: usize,
    mutability: Mutability,
    network: NetworkIntent,
    label: &str,
) -> Result<ProcessObservation, ReleaseError> {
    let runner = SynchronousProcessRunner::new(repository).map_err(|error| {
        ReleaseError::environment(format!("failed to prepare {label}: {error}"))
    })?;
    runner
        .run(&ExecSpec {
            program,
            args,
            cwd: RepoRelativePath::root(),
            env,
            timeout,
            stdin: StdinPolicy::Closed,
            stdout: OutputPolicy::CaptureBounded {
                max_bytes: stdout_limit,
            },
            stderr: OutputPolicy::CaptureBounded {
                max_bytes: stderr_limit,
            },
            mutability,
            network,
            concurrency_key: None,
        })
        .map_err(|error| ReleaseError::environment(format!("failed to run {label}: {error}")))
}

fn require_process_success(
    observation: ProcessObservation,
    label: &str,
) -> Result<Vec<u8>, ReleaseError> {
    if observation.timed_out {
        return Err(ReleaseError::environment(format!("{label} timed out")));
    }
    if observation.interrupted {
        return Err(ReleaseError::environment(format!(
            "{label} was interrupted"
        )));
    }
    if observation.stdout_truncated || observation.stderr_truncated {
        return Err(ReleaseError::environment(format!(
            "{label} exceeded its bounded output policy: stdout={} bytes, stderr={} bytes",
            observation.stdout_total_bytes, observation.stderr_total_bytes
        )));
    }
    if observation.exit_code != Some(0) || observation.signal.is_some() {
        return Err(ReleaseError::environment(format!(
            "{label} failed with exit={:?}, signal={:?}: {}",
            observation.exit_code,
            observation.signal,
            bounded_lossy(&observation.stderr)
        )));
    }
    Ok(observation.stdout)
}

fn bounded_lossy(bytes: &[u8]) -> String {
    let end = bytes.len().min(MAX_DIAGNOSTIC_BYTES);
    let suffix = if bytes.len() > end {
        "…<truncated>"
    } else {
        ""
    };
    format!("{}{suffix}", String::from_utf8_lossy(&bytes[..end]))
}

fn stage_built(
    output: &RepositoryWriter,
    target: &ReleaseTarget,
    binary: &[u8],
    snapshot: &RepositorySnapshot,
) -> Result<(), ReleaseError> {
    validate_stage_directory(output)?;
    validate_binary_format(target, binary)?;
    let sbom = render_sbom(
        target,
        snapshot.metadata(target)?,
        &snapshot.cargo_lock,
        &snapshot.source_commit,
        binary,
    )?;
    preflight_write_once_or_same(output, &binary_asset_name(target), binary)?;
    preflight_write_once_or_same(output, &sbom_asset_name(target), &sbom)?;
    write_once_or_same(output, &binary_asset_name(target), binary)?;
    write_once_or_same(output, &sbom_asset_name(target), &sbom)?;
    validate_visible_root(output, "release output")?;
    Ok(())
}

fn finalize(output: &RepositoryWriter, snapshot: &RepositorySnapshot) -> Result<(), ReleaseError> {
    validate_finalize_directory(output)?;
    validate_staged_assets(output, snapshot)?;
    let manifest = render_manifest(output)?;
    let checksums = render_checksums(output, &manifest)?;
    preflight_write_once_or_same(output, MANIFEST_FILE, &manifest)?;
    preflight_write_once_or_same(output, CHECKSUMS_FILE, &checksums)?;
    write_once_or_same(output, MANIFEST_FILE, &manifest)?;
    write_once_or_same(output, CHECKSUMS_FILE, &checksums)?;
    validate_complete_assets(output, snapshot)?;
    validate_visible_root(output, "release output")?;
    Ok(())
}

fn check(output: &RepositoryWriter, snapshot: &RepositorySnapshot) -> Result<(), ReleaseError> {
    validate_complete_assets(output, snapshot)?;
    validate_visible_root(output, "release output")
}

fn validate_complete_assets(
    output: &RepositoryWriter,
    snapshot: &RepositorySnapshot,
) -> Result<(), ReleaseError> {
    validate_exact_asset_set(output)?;
    validate_staged_assets(output, snapshot)?;

    let manifest = render_manifest(output)?;
    require_exact_bytes(output, MANIFEST_FILE, &manifest, "release manifest")?;
    require_exact_bytes(
        output,
        CHECKSUMS_FILE,
        &render_checksums(output, &manifest)?,
        "release checksums",
    )?;
    validate_exact_asset_set(output)?;
    Ok(())
}

fn validate_staged_assets(
    output: &RepositoryWriter,
    snapshot: &RepositorySnapshot,
) -> Result<(), ReleaseError> {
    for target in &RELEASE_TARGETS {
        let binary_name = binary_asset_name(target);
        let binary = read_output_required(
            output,
            &binary_name,
            MAX_BINARY_BYTES,
            "staged release binary",
        )?;
        validate_binary_format(target, &binary)?;
        let expected_sbom = render_sbom(
            target,
            snapshot.metadata(target)?,
            &snapshot.cargo_lock,
            &snapshot.source_commit,
            &binary,
        )?;
        require_exact_bytes(
            output,
            &sbom_asset_name(target),
            &expected_sbom,
            "CycloneDX SBOM",
        )?;
    }
    Ok(())
}

fn absolute_clean_path(path: &Path) -> Result<PathBuf, ReleaseError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .map_err(|error| {
                ReleaseError::environment(format!("failed to read current directory: {error}"))
            })?
            .join(path)
    };
    for component in absolute.components() {
        if matches!(component, PathComponent::ParentDir) {
            return Err(ReleaseError::environment(format!(
                "release path must not contain `..`: {}",
                path.display()
            )));
        }
    }
    Ok(absolute)
}

fn open_output_directory(repository: &Path, path: &Path) -> Result<RepositoryWriter, ReleaseError> {
    let absolute = absolute_clean_path(path)?;
    let output = RepositoryWriter::new(&absolute).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to pin the existing release output directory {}: {error}",
            absolute.display()
        ))
    })?;
    let repository = fs::canonicalize(repository).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to resolve the source repository boundary {}: {error}",
            repository.display()
        ))
    })?;
    if output.root() == repository || output.root().starts_with(&repository) {
        return Err(ReleaseError::environment(format!(
            "release output must be outside the source repository: {}",
            output.root().display()
        )));
    }
    validate_visible_root(&output, "release output")?;
    Ok(output)
}

fn validate_visible_root(writer: &RepositoryWriter, label: &str) -> Result<(), ReleaseError> {
    writer.validate_visible_root().map_err(|error| {
        ReleaseError::environment(format!(
            "visible {label} path no longer names the pinned directory: {error}"
        ))
    })
}

fn require_regular_file(path: &Path, label: &str) -> Result<PathBuf, ReleaseError> {
    let absolute = absolute_clean_path(path)?;
    let metadata = fs::symlink_metadata(&absolute).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to inspect {label} {}: {error}",
            absolute.display()
        ))
    })?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(ReleaseError::environment(format!(
            "{label} is not a real regular file: {}",
            absolute.display()
        )));
    }
    Ok(absolute)
}

fn read_bounded(path: &Path, limit: u64, label: &str) -> Result<Vec<u8>, ReleaseError> {
    let path = require_regular_file(path, label)?;
    let metadata = fs::metadata(&path).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to inspect {label} {}: {error}",
            path.display()
        ))
    })?;
    if metadata.len() > limit {
        return Err(ReleaseError::environment(format!(
            "{label} {} is {} bytes, above the {limit} byte limit",
            path.display(),
            metadata.len()
        )));
    }
    let file = File::open(&path).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to open {label} {}: {error}",
            path.display()
        ))
    })?;
    let capacity = usize::try_from(metadata.len()).map_err(|_| {
        ReleaseError::environment(format!("{label} length is not representable in memory"))
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| {
            ReleaseError::environment(format!(
                "failed to read {label} {}: {error}",
                path.display()
            ))
        })?;
    if bytes.len() as u64 > limit {
        return Err(ReleaseError::environment(format!(
            "{label} {} grew above the {limit} byte limit while being read",
            path.display()
        )));
    }
    if bytes.len() as u64 != metadata.len() {
        return Err(ReleaseError::environment(format!(
            "{label} changed while being read: {}",
            path.display()
        )));
    }
    Ok(bytes)
}

fn read_output_optional(
    output: &RepositoryWriter,
    name: &str,
    max_bytes: u64,
    label: &str,
) -> Result<Option<Vec<u8>>, ReleaseError> {
    let max_bytes = usize::try_from(max_bytes).map_err(|_| {
        ReleaseError::internal(format!(
            "{label} byte limit is not representable on this host"
        ))
    })?;
    validate_visible_root(output, "release output")?;
    let bytes = output
        .read_optional_bounded(name, max_bytes)
        .map_err(|error| {
            ReleaseError::environment(format!(
                "failed to read pinned release {label} `{name}`: {error}"
            ))
        })?;
    validate_visible_root(output, "release output")?;
    Ok(bytes)
}

fn read_output_required(
    output: &RepositoryWriter,
    name: &str,
    max_bytes: u64,
    label: &str,
) -> Result<Vec<u8>, ReleaseError> {
    read_output_optional(output, name, max_bytes, label)?
        .ok_or_else(|| ReleaseError::environment(format!("release {label} is missing: `{name}`")))
}

fn write_once_or_same(
    output: &RepositoryWriter,
    name: &str,
    bytes: &[u8],
) -> Result<(), ReleaseError> {
    write_once_or_same_with_precreate(output, name, bytes, || Ok(()))
}

fn write_once_or_same_with_precreate(
    output: &RepositoryWriter,
    name: &str,
    bytes: &[u8],
    before_create: impl FnOnce() -> Result<(), ReleaseError>,
) -> Result<(), ReleaseError> {
    if let Some(current) =
        read_output_optional(output, name, MAX_BINARY_BYTES, "asset destination")?
    {
        if current != bytes {
            return Err(ReleaseError::environment(format!(
                "release asset already exists with different bytes: `{name}`"
            )));
        }
        return require_exact_bytes(output, name, bytes, "existing release asset");
    }

    // Keeping this boundary explicit makes the read/create race reproducible in tests.
    before_create()?;
    match output.write_atomic_new(name, bytes) {
        Ok(()) => {}
        Err(error) if error.io_kind() == std::io::ErrorKind::AlreadyExists => {
            return require_exact_bytes(output, name, bytes, "concurrently created release asset");
        }
        Err(error) => {
            return Err(ReleaseError::environment(format!(
                "failed to atomically create pinned release asset `{name}`: {error}"
            )));
        }
    }
    require_exact_bytes(output, name, bytes, "newly created release asset")
}

fn preflight_write_once_or_same(
    output: &RepositoryWriter,
    name: &str,
    bytes: &[u8],
) -> Result<(), ReleaseError> {
    if let Some(current) = read_output_optional(
        output,
        name,
        MAX_BINARY_BYTES,
        "asset destination preflight",
    )? {
        if current != bytes {
            return Err(ReleaseError::environment(format!(
                "release asset already exists with different bytes: `{name}`"
            )));
        }
    }
    Ok(())
}

fn require_exact_bytes(
    output: &RepositoryWriter,
    name: &str,
    expected: &[u8],
    label: &str,
) -> Result<(), ReleaseError> {
    let actual = read_output_required(output, name, MAX_BINARY_BYTES, label)?;
    if actual == expected {
        Ok(())
    } else {
        Err(ReleaseError::environment(format!(
            "{label} differs from deterministic release content: `{name}`"
        )))
    }
}

fn known_stage_names() -> BTreeSet<String> {
    RELEASE_TARGETS
        .iter()
        .flat_map(|target| [binary_asset_name(target), sbom_asset_name(target)])
        .collect()
}

fn finalized_asset_names() -> BTreeSet<String> {
    let mut names = known_stage_names();
    names.insert(MANIFEST_FILE.to_owned());
    names.insert(CHECKSUMS_FILE.to_owned());
    names
}

fn validate_stage_directory(output: &RepositoryWriter) -> Result<(), ReleaseError> {
    if read_output_optional(output, MANIFEST_FILE, MAX_BINARY_BYTES, "release manifest")?.is_some()
        || read_output_optional(
            output,
            CHECKSUMS_FILE,
            MAX_BINARY_BYTES,
            "release checksums",
        )?
        .is_some()
    {
        return Err(ReleaseError::environment(
            "release output is already finalized and cannot be restaged in place",
        ));
    }
    Ok(())
}

fn validate_finalize_directory(output: &RepositoryWriter) -> Result<(), ReleaseError> {
    let mut missing = Vec::new();
    for name in known_stage_names() {
        if read_output_optional(output, &name, MAX_BINARY_BYTES, "staged asset")?.is_none() {
            missing.push(name);
        }
    }
    if !missing.is_empty() {
        return Err(ReleaseError::environment(format!(
            "release output is missing required staged assets: {}",
            missing.join(", ")
        )));
    }
    Ok(())
}

fn validate_exact_asset_set(output: &RepositoryWriter) -> Result<(), ReleaseError> {
    let mut missing = Vec::new();
    for name in finalized_asset_names() {
        if read_output_optional(output, &name, MAX_BINARY_BYTES, "finalized asset")?.is_none() {
            missing.push(name);
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(ReleaseError::environment(format!(
            "release output is missing required finalized assets: [{}]",
            missing.join(", ")
        )))
    }
}

fn binary_asset_name(target: &ReleaseTarget) -> String {
    let suffix = if target.executable_name.ends_with(".exe") {
        ".exe"
    } else {
        ""
    };
    format!("forge-{RELEASE_VERSION}-{}{suffix}", target.triple)
}

fn sbom_asset_name(target: &ReleaseTarget) -> String {
    format!("{}.cdx.json", binary_asset_name(target))
}

fn validate_binary_format(target: &ReleaseTarget, bytes: &[u8]) -> Result<(), ReleaseError> {
    match target.format {
        BinaryFormat::ElfX86_64Static => validate_elf(bytes, 62, target.triple),
        BinaryFormat::ElfAarch64Static => validate_elf(bytes, 183, target.triple),
        BinaryFormat::MachOX86_64 => validate_macho(bytes, 0x0100_0007, target.triple),
        BinaryFormat::MachOAarch64 => validate_macho(bytes, 0x0100_000c, target.triple),
        BinaryFormat::PeX86_64 => validate_pe(bytes, target.triple),
    }
}

fn validate_elf(bytes: &[u8], expected_machine: u16, triple: &str) -> Result<(), ReleaseError> {
    if bytes.len() < 64
        || bytes.get(0..4) != Some(b"\x7fELF")
        || bytes[4] != 2
        || bytes[5] != 1
        || bytes[6] != 1
    {
        return Err(ReleaseError::environment(format!(
            "binary for {triple} is not a 64-bit little-endian ELF executable"
        )));
    }
    if read_u16(bytes, 18)? != expected_machine {
        return Err(ReleaseError::environment(format!(
            "binary architecture does not match release target {triple}"
        )));
    }
    if !matches!(read_u16(bytes, 16)?, 2 | 3) {
        return Err(ReleaseError::environment(format!(
            "ELF file type is not executable or position-independent executable for {triple}"
        )));
    }
    if read_u16(bytes, 52)? < 64 {
        return Err(ReleaseError::environment(format!(
            "ELF header size is invalid for {triple}"
        )));
    }
    let entry = read_u64(bytes, 24)?;
    if entry == 0 {
        return Err(ReleaseError::environment(format!(
            "ELF executable entry point is missing for {triple}"
        )));
    }
    let program_offset = usize::try_from(read_u64(bytes, 32)?).map_err(|_| {
        ReleaseError::environment(format!("ELF program header offset overflows for {triple}"))
    })?;
    let entry_size = usize::from(read_u16(bytes, 54)?);
    let entry_count = usize::from(read_u16(bytes, 56)?);
    if entry_count == 0 || entry_size < 56 {
        return Err(ReleaseError::environment(format!(
            "ELF executable program-header table is missing or invalid for {triple}"
        )));
    }
    let mut executable_entry_segment = false;
    for index in 0..entry_count {
        let offset = program_offset
            .checked_add(index.checked_mul(entry_size).ok_or_else(|| {
                ReleaseError::environment(format!("ELF program headers overflow for {triple}"))
            })?)
            .ok_or_else(|| {
                ReleaseError::environment(format!("ELF program headers overflow for {triple}"))
            })?;
        let end = offset.checked_add(entry_size).ok_or_else(|| {
            ReleaseError::environment(format!("ELF program headers overflow for {triple}"))
        })?;
        if end > bytes.len() {
            return Err(ReleaseError::environment(format!(
                "ELF program headers are truncated for {triple}"
            )));
        }
        let segment_type = read_u32(bytes, offset)?;
        if segment_type == 3 {
            return Err(ReleaseError::environment(format!(
                "Linux release binary for {triple} has a PT_INTERP loader and is not static-compatible"
            )));
        }
        let flags = read_u32(bytes, offset + 4)?;
        if segment_type == 1 {
            let file_offset = read_u64(bytes, offset + 8)?;
            let virtual_address = read_u64(bytes, offset + 16)?;
            let file_size = read_u64(bytes, offset + 32)?;
            let memory_size = read_u64(bytes, offset + 40)?;
            let alignment = read_u64(bytes, offset + 48)?;
            if file_size > memory_size
                || (alignment > 1
                    && (!alignment.is_power_of_two()
                        || file_offset % alignment != virtual_address % alignment))
            {
                return Err(ReleaseError::environment(format!(
                    "ELF load segment has invalid file, memory, or alignment bounds for {triple}"
                )));
            }
            let file_end = file_offset.checked_add(file_size).ok_or_else(|| {
                ReleaseError::environment(format!("ELF file segment overflows for {triple}"))
            })?;
            if file_end > bytes.len() as u64 {
                return Err(ReleaseError::environment(format!(
                    "ELF load segment exceeds the binary bytes for {triple}"
                )));
            }
            let segment_end = virtual_address.checked_add(memory_size).ok_or_else(|| {
                ReleaseError::environment(format!(
                    "ELF executable segment range overflows for {triple}"
                ))
            })?;
            if flags & 1 != 0 && memory_size > 0 && entry >= virtual_address && entry < segment_end
            {
                let entry_delta = entry - virtual_address;
                let entry_file_offset = file_offset.checked_add(entry_delta).ok_or_else(|| {
                    ReleaseError::environment(format!(
                        "ELF entry file offset overflows for {triple}"
                    ))
                })?;
                if entry_delta < file_size && entry_file_offset < bytes.len() as u64 {
                    executable_entry_segment = true;
                }
            }
        }
    }
    if executable_entry_segment {
        Ok(())
    } else {
        Err(ReleaseError::environment(format!(
            "ELF entry point is not covered by an executable PT_LOAD segment for {triple}"
        )))
    }
}

fn validate_macho(bytes: &[u8], expected_cpu: u32, triple: &str) -> Result<(), ReleaseError> {
    if bytes.len() < 32 || bytes.get(0..4) != Some(&[0xcf, 0xfa, 0xed, 0xfe]) {
        return Err(ReleaseError::environment(format!(
            "binary for {triple} is not a 64-bit little-endian Mach-O executable"
        )));
    }
    if read_u32(bytes, 4)? != expected_cpu {
        return Err(ReleaseError::environment(format!(
            "binary architecture does not match release target {triple}"
        )));
    }
    if read_u32(bytes, 12)? != 2 {
        return Err(ReleaseError::environment(format!(
            "Mach-O file type is not MH_EXECUTE for {triple}"
        )));
    }
    let command_count = usize::try_from(read_u32(bytes, 16)?).map_err(|_| {
        ReleaseError::environment(format!("Mach-O load-command count overflows for {triple}"))
    })?;
    let command_bytes = usize::try_from(read_u32(bytes, 20)?).map_err(|_| {
        ReleaseError::environment(format!("Mach-O load-command bytes overflow for {triple}"))
    })?;
    if command_count == 0 || command_bytes == 0 {
        return Err(ReleaseError::environment(format!(
            "Mach-O executable has no load commands for {triple}"
        )));
    }
    let commands_end = 32_usize.checked_add(command_bytes).ok_or_else(|| {
        ReleaseError::environment(format!("Mach-O load commands overflow for {triple}"))
    })?;
    if commands_end > bytes.len() {
        return Err(ReleaseError::environment(format!(
            "Mach-O load commands are truncated for {triple}"
        )));
    }
    let mut offset = 32_usize;
    let mut executable_file_ranges = Vec::new();
    let mut main_entry = None;
    for _ in 0..command_count {
        let command = read_u32(bytes, offset)?;
        let command_size = usize::try_from(read_u32(bytes, offset + 4)?).map_err(|_| {
            ReleaseError::environment(format!("Mach-O load command overflows for {triple}"))
        })?;
        if command_size < 8 || command_size % 8 != 0 {
            return Err(ReleaseError::environment(format!(
                "Mach-O load command is too short for {triple}"
            )));
        }
        let end = offset.checked_add(command_size).ok_or_else(|| {
            ReleaseError::environment(format!("Mach-O load commands overflow for {triple}"))
        })?;
        if end > commands_end {
            return Err(ReleaseError::environment(format!(
                "Mach-O load command exceeds the declared table for {triple}"
            )));
        }
        if command == 0x19 {
            if command_size < 72 {
                return Err(ReleaseError::environment(format!(
                    "Mach-O LC_SEGMENT_64 is too short for {triple}"
                )));
            }
            let section_count = usize::try_from(read_u32(bytes, offset + 64)?).map_err(|_| {
                ReleaseError::environment(format!("Mach-O section count overflows for {triple}"))
            })?;
            let minimum_size = 72_usize
                .checked_add(section_count.checked_mul(80).ok_or_else(|| {
                    ReleaseError::environment(format!(
                        "Mach-O section table overflows for {triple}"
                    ))
                })?)
                .ok_or_else(|| {
                    ReleaseError::environment(format!(
                        "Mach-O section table overflows for {triple}"
                    ))
                })?;
            if command_size < minimum_size {
                return Err(ReleaseError::environment(format!(
                    "Mach-O LC_SEGMENT_64 section table is truncated for {triple}"
                )));
            }
            let virtual_size = read_u64(bytes, offset + 32)?;
            let file_offset = read_u64(bytes, offset + 40)?;
            let file_size = read_u64(bytes, offset + 48)?;
            let maximum_protection = read_u32(bytes, offset + 56)?;
            let initial_protection = read_u32(bytes, offset + 60)?;
            if initial_protection & 4 != 0 {
                let file_end = file_offset.checked_add(file_size).ok_or_else(|| {
                    ReleaseError::environment(format!(
                        "Mach-O executable segment overflows for {triple}"
                    ))
                })?;
                if maximum_protection & 4 == 0
                    || virtual_size == 0
                    || file_size == 0
                    || file_size > virtual_size
                    || file_end > bytes.len() as u64
                {
                    return Err(ReleaseError::environment(format!(
                        "Mach-O executable segment has invalid file or memory bounds for {triple}"
                    )));
                }
                executable_file_ranges.push((file_offset, file_end));
            }
        } else if command == 0x8000_0028 {
            if command_size < 24 || main_entry.is_some() {
                return Err(ReleaseError::environment(format!(
                    "Mach-O LC_MAIN is duplicated or too short for {triple}"
                )));
            }
            main_entry = Some(read_u64(bytes, offset + 8)?);
        }
        offset = end;
    }
    let Some(main_entry) = main_entry else {
        return Err(ReleaseError::environment(format!(
            "Mach-O executable has no LC_MAIN entry point for {triple}"
        )));
    };
    let entry_is_file_backed = main_entry >= commands_end as u64
        && executable_file_ranges
            .iter()
            .any(|(start, end)| main_entry >= *start && main_entry < *end);
    if offset != commands_end || !entry_is_file_backed {
        return Err(ReleaseError::environment(format!(
            "Mach-O executable has an inconsistent table or LC_MAIN is not file-backed by an executable LC_SEGMENT_64 for {triple}"
        )));
    }
    Ok(())
}

fn validate_pe(bytes: &[u8], triple: &str) -> Result<(), ReleaseError> {
    if bytes.len() < 64 || bytes.get(0..2) != Some(b"MZ") {
        return Err(ReleaseError::environment(format!(
            "binary for {triple} is not a PE executable"
        )));
    }
    let header = usize::try_from(read_u32(bytes, 0x3c)?).map_err(|_| {
        ReleaseError::environment(format!("PE header offset overflows for {triple}"))
    })?;
    let coff_end = header.checked_add(24).ok_or_else(|| {
        ReleaseError::environment(format!("PE header offset overflows for {triple}"))
    })?;
    if coff_end > bytes.len() || bytes.get(header..header + 4) != Some(b"PE\0\0") {
        return Err(ReleaseError::environment(format!(
            "binary for {triple} has an invalid PE header"
        )));
    }
    if read_u16(bytes, header + 4)? != 0x8664 {
        return Err(ReleaseError::environment(format!(
            "binary architecture does not match release target {triple}"
        )));
    }
    let section_count = usize::from(read_u16(bytes, header + 6)?);
    let optional_size = usize::from(read_u16(bytes, header + 20)?);
    let characteristics = read_u16(bytes, header + 22)?;
    if characteristics & 0x0002 == 0 || characteristics & 0x2000 != 0 {
        return Err(ReleaseError::environment(format!(
            "PE image for {triple} is not an executable non-DLL image"
        )));
    }
    if section_count == 0 || optional_size < 0x70 {
        return Err(ReleaseError::environment(format!(
            "PE image for {triple} has no sections or an undersized PE32+ optional header"
        )));
    }
    let optional = header + 24;
    let optional_end = optional.checked_add(optional_size).ok_or_else(|| {
        ReleaseError::environment(format!("PE optional header overflows for {triple}"))
    })?;
    if optional_end > bytes.len() || read_u16(bytes, optional)? != 0x020b {
        return Err(ReleaseError::environment(format!(
            "PE image for {triple} has an invalid PE32+ optional header"
        )));
    }
    let entry = read_u32(bytes, optional + 16)?;
    if entry == 0 {
        return Err(ReleaseError::environment(format!(
            "PE executable entry point is missing for {triple}"
        )));
    }
    let section_bytes = section_count.checked_mul(40).ok_or_else(|| {
        ReleaseError::environment(format!("PE section table overflows for {triple}"))
    })?;
    let sections_end = optional_end.checked_add(section_bytes).ok_or_else(|| {
        ReleaseError::environment(format!("PE section table overflows for {triple}"))
    })?;
    if sections_end > bytes.len() {
        return Err(ReleaseError::environment(format!(
            "PE section table is truncated for {triple}"
        )));
    }
    let size_of_image = read_u32(bytes, optional + 56)?;
    let size_of_headers = usize::try_from(read_u32(bytes, optional + 60)?)
        .map_err(|_| ReleaseError::environment(format!("PE header size overflows for {triple}")))?;
    if size_of_image == 0
        || entry >= size_of_image
        || size_of_headers < sections_end
        || size_of_headers > bytes.len()
    {
        return Err(ReleaseError::environment(format!(
            "PE image or header bounds are invalid for {triple}"
        )));
    }
    let mut executable_entry_section = false;
    for index in 0..section_count {
        let offset = optional_end + index * 40;
        let virtual_size = read_u32(bytes, offset + 8)?;
        let virtual_address = read_u32(bytes, offset + 12)?;
        let raw_size = read_u32(bytes, offset + 16)?;
        let raw_offset = read_u32(bytes, offset + 20)?;
        let section_characteristics = read_u32(bytes, offset + 36)?;
        let mapped_size = virtual_size.max(raw_size);
        let section_end = virtual_address.checked_add(mapped_size).ok_or_else(|| {
            ReleaseError::environment(format!("PE executable section overflows for {triple}"))
        })?;
        let raw_end = raw_offset.checked_add(raw_size).ok_or_else(|| {
            ReleaseError::environment(format!("PE raw section range overflows for {triple}"))
        })?;
        if raw_size > 0 && raw_end > bytes.len() as u32 {
            return Err(ReleaseError::environment(format!(
                "PE raw section exceeds the binary bytes for {triple}"
            )));
        }
        if section_characteristics & 0x2000_0000 != 0
            && mapped_size > 0
            && entry >= virtual_address
            && entry < section_end
        {
            let entry_delta = entry - virtual_address;
            let entry_file_offset = raw_offset.checked_add(entry_delta).ok_or_else(|| {
                ReleaseError::environment(format!("PE entry file offset overflows for {triple}"))
            })?;
            if entry_delta < raw_size
                && raw_offset >= size_of_headers as u32
                && entry_file_offset < bytes.len() as u32
            {
                executable_entry_section = true;
            }
        }
    }
    if executable_entry_section {
        Ok(())
    } else {
        Err(ReleaseError::environment(format!(
            "PE entry point is not covered by an executable section for {triple}"
        )))
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, ReleaseError> {
    let raw: [u8; 2] = bytes
        .get(offset..offset.saturating_add(2))
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| ReleaseError::environment("release binary header is truncated"))?;
    Ok(u16::from_le_bytes(raw))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ReleaseError> {
    let raw: [u8; 4] = bytes
        .get(offset..offset.saturating_add(4))
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| ReleaseError::environment("release binary header is truncated"))?;
    Ok(u32::from_le_bytes(raw))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, ReleaseError> {
    let raw: [u8; 8] = bytes
        .get(offset..offset.saturating_add(8))
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| ReleaseError::environment("release binary header is truncated"))?;
    Ok(u64::from_le_bytes(raw))
}

#[derive(Debug, Deserialize)]
struct CargoMetadata {
    packages: Vec<CargoPackage>,
    workspace_members: Vec<String>,
    resolve: Option<CargoResolve>,
}

#[derive(Debug, Deserialize)]
struct CargoPackage {
    id: String,
    name: String,
    version: String,
    source: Option<String>,
    checksum: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CargoResolve {
    nodes: Vec<CargoNode>,
}

#[derive(Debug, Deserialize)]
struct CargoNode {
    id: String,
    deps: Vec<CargoDependency>,
}

#[derive(Debug, Deserialize)]
struct CargoDependency {
    pkg: String,
    dep_kinds: Vec<CargoDependencyKind>,
}

#[derive(Debug, Deserialize)]
struct CargoDependencyKind {
    kind: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDxBom {
    bom_format: &'static str,
    spec_version: &'static str,
    version: u8,
    metadata: BomMetadata,
    components: Vec<BomComponent>,
    dependencies: Vec<BomDependency>,
}

#[derive(Debug, Serialize)]
struct BomMetadata {
    component: BomComponent,
}

#[derive(Debug, Serialize)]
struct BomComponent {
    #[serde(rename = "type")]
    component_type: &'static str,
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    name: String,
    version: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    hashes: Vec<BomHash>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    properties: Vec<BomProperty>,
}

#[derive(Debug, Serialize)]
struct BomHash {
    alg: &'static str,
    content: String,
}

#[derive(Debug, Serialize)]
struct BomProperty {
    name: &'static str,
    value: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BomDependency {
    #[serde(rename = "ref")]
    reference: String,
    depends_on: Vec<String>,
}

fn render_sbom(
    target: &ReleaseTarget,
    metadata_bytes: &[u8],
    cargo_lock: &[u8],
    source_commit: &str,
    binary: &[u8],
) -> Result<Vec<u8>, ReleaseError> {
    let metadata: CargoMetadata = serde_json::from_slice(metadata_bytes).map_err(|error| {
        ReleaseError::environment(format!(
            "Cargo metadata for {} is not valid JSON: {error}",
            target.triple
        ))
    })?;
    let resolve = metadata.resolve.as_ref().ok_or_else(|| {
        ReleaseError::environment(format!(
            "Cargo metadata for {} has no resolved dependency graph",
            target.triple
        ))
    })?;
    let packages: BTreeMap<_, _> = metadata
        .packages
        .iter()
        .map(|package| (package.id.as_str(), package))
        .collect();
    let workspace_members: BTreeSet<_> = metadata
        .workspace_members
        .iter()
        .map(String::as_str)
        .collect();
    let roots: Vec<_> = metadata
        .workspace_members
        .iter()
        .filter_map(|id| packages.get(id.as_str()).copied())
        .filter(|package| package.name == "forge-cli" && package.version == RELEASE_VERSION)
        .collect();
    let [root] = roots.as_slice() else {
        return Err(ReleaseError::environment(format!(
            "Cargo metadata must identify exactly one workspace-member forge-cli {RELEASE_VERSION}, found {}",
            roots.len()
        )));
    };
    let nodes: BTreeMap<_, _> = resolve
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), node))
        .collect();
    let mut selected = BTreeSet::new();
    let mut pending = VecDeque::from([root.id.as_str()]);
    while let Some(id) = pending.pop_front() {
        if !selected.insert(id.to_owned()) {
            continue;
        }
        let package = packages.get(id).ok_or_else(|| {
            ReleaseError::environment(format!("Cargo metadata has no package for `{id}`"))
        })?;
        if package.source.is_none() && !workspace_members.contains(id) {
            return Err(ReleaseError::environment(format!(
                "source-bound SBOM rejects local path dependency outside the exact workspace: `{id}`"
            )));
        }
        let node = nodes.get(id).ok_or_else(|| {
            ReleaseError::environment(format!("Cargo metadata has no resolve node for `{id}`"))
        })?;
        for dependency in &node.deps {
            if is_release_dependency(dependency) {
                pending.push_back(dependency.pkg.as_str());
            }
        }
    }

    let root_ref = format!("pkg:cargo/forge@{RELEASE_VERSION}");
    let mut references = BTreeMap::new();
    for id in &selected {
        let package = packages.get(id.as_str()).ok_or_else(|| {
            ReleaseError::environment(format!("Cargo metadata has no package for `{id}`"))
        })?;
        let reference = if package.id == root.id {
            root_ref.clone()
        } else {
            format!(
                "urn:forge:cargo:blake3:{}",
                blake3::hash(
                    format!(
                        "{}\0{}\0{}",
                        package.name,
                        package.version,
                        package.source.as_deref().unwrap_or("workspace")
                    )
                    .as_bytes()
                )
                .to_hex()
            )
        };
        references.insert(id.clone(), reference);
    }

    let mut component_ids: Vec<_> = selected
        .iter()
        .filter(|id| id.as_str() != root.id)
        .cloned()
        .collect();
    component_ids.sort_by(|left, right| {
        let left = packages.get(left.as_str());
        let right = packages.get(right.as_str());
        left.map(|package| (&package.name, &package.version, &package.source))
            .cmp(&right.map(|package| (&package.name, &package.version, &package.source)))
    });
    let mut components = Vec::with_capacity(component_ids.len());
    for id in &component_ids {
        let package = packages.get(id.as_str()).ok_or_else(|| {
            ReleaseError::internal(format!("selected Cargo package disappeared: `{id}`"))
        })?;
        let hashes = package
            .checksum
            .as_ref()
            .map(|checksum| {
                vec![BomHash {
                    alg: "SHA-256",
                    content: checksum.clone(),
                }]
            })
            .unwrap_or_default();
        let properties = package
            .source
            .as_ref()
            .map(|source| {
                vec![BomProperty {
                    name: "forge:cargo-source",
                    value: source.clone(),
                }]
            })
            .unwrap_or_default();
        components.push(BomComponent {
            component_type: "library",
            bom_ref: references.get(id).cloned().ok_or_else(|| {
                ReleaseError::internal(format!("selected Cargo package has no reference: `{id}`"))
            })?,
            name: package.name.clone(),
            version: package.version.clone(),
            hashes,
            properties,
        });
    }

    let mut dependencies = Vec::with_capacity(selected.len());
    for id in &selected {
        let node = nodes.get(id.as_str()).ok_or_else(|| {
            ReleaseError::internal(format!("selected Cargo node disappeared: `{id}`"))
        })?;
        let mut depends_on: Vec<_> = node
            .deps
            .iter()
            .filter(|dependency| is_release_dependency(dependency))
            .filter_map(|dependency| references.get(&dependency.pkg).cloned())
            .collect();
        depends_on.sort();
        depends_on.dedup();
        dependencies.push(BomDependency {
            reference: references.get(id).cloned().ok_or_else(|| {
                ReleaseError::internal(format!("selected Cargo node has no reference: `{id}`"))
            })?,
            depends_on,
        });
    }
    dependencies.sort_by(|left, right| left.reference.cmp(&right.reference));

    let binary_sha256 = sha256_hex(binary);
    let bom = CycloneDxBom {
        bom_format: "CycloneDX",
        spec_version: "1.6",
        version: 1,
        metadata: BomMetadata {
            component: BomComponent {
                component_type: "application",
                bom_ref: root_ref,
                name: "forge".to_owned(),
                version: RELEASE_VERSION.to_owned(),
                hashes: vec![BomHash {
                    alg: "SHA-256",
                    content: binary_sha256.clone(),
                }],
                properties: vec![
                    BomProperty {
                        name: "forge:target-triple",
                        value: target.triple.to_owned(),
                    },
                    BomProperty {
                        name: "forge:cargo-lock-sha256",
                        value: sha256_hex(cargo_lock),
                    },
                    BomProperty {
                        name: "forge:source-commit",
                        value: source_commit.to_owned(),
                    },
                    BomProperty {
                        name: "forge:binary-sha256",
                        value: binary_sha256,
                    },
                    BomProperty {
                        name: "forge:binary-length",
                        value: binary.len().to_string(),
                    },
                ],
            },
        },
        components,
        dependencies,
    };
    to_pretty_json(&bom, "CycloneDX SBOM")
}

fn is_release_dependency(dependency: &CargoDependency) -> bool {
    dependency.dep_kinds.is_empty()
        || dependency
            .dep_kinds
            .iter()
            .any(|kind| kind.kind.as_deref() != Some("dev"))
}

fn render_manifest(output: &RepositoryWriter) -> Result<Vec<u8>, ReleaseError> {
    let mut artifacts = Vec::with_capacity(RELEASE_TARGETS.len() * 2);
    for target in &RELEASE_TARGETS {
        for (name, kind) in [
            (binary_asset_name(target), ReleaseArtifactKindData::Binary),
            (
                sbom_asset_name(target),
                ReleaseArtifactKindData::CyclonedxSbom,
            ),
        ] {
            let bytes = read_output_required(output, &name, MAX_BINARY_BYTES, "release artifact")?;
            artifacts.push(ReleaseArtifactData {
                name,
                kind,
                target: target.triple.to_owned(),
                length: bytes.len() as u64,
                sha256: ReleaseSha256Data::new(sha256_hex(&bytes)).map_err(|error| {
                    ReleaseError::internal(format!("generated invalid SHA-256 digest: {error}"))
                })?,
            });
        }
    }
    artifacts.sort_by(|left, right| left.name.cmp(&right.name));
    let subjects: Vec<_> = finalized_asset_names().into_iter().collect();
    if subjects.len() != usize::from(FINALIZED_ASSET_COUNT) {
        return Err(ReleaseError::internal(format!(
            "release subject allowlist has {} names, expected {FINALIZED_ASSET_COUNT}",
            subjects.len()
        )));
    }
    let artifacts: [ReleaseArtifactData; 10] =
        artifacts.try_into().map_err(|artifacts: Vec<_>| {
            ReleaseError::internal(format!(
                "release artifact allowlist has {} entries, expected 10",
                artifacts.len()
            ))
        })?;
    let subjects: [String; 12] = subjects.try_into().map_err(|subjects: Vec<_>| {
        ReleaseError::internal(format!(
            "release subject allowlist has {} entries, expected 12",
            subjects.len()
        ))
    })?;
    to_pretty_json(
        &ReleaseManifestData {
            schema: SchemaKind::ReleaseManifest.id(),
            release: ReleaseDescriptorData {
                version: RELEASE_VERSION.to_owned(),
                channel: ReleaseChannelData::ReleaseCandidate,
                distribution: ReleaseDistributionData::GithubRelease,
                status: ReleaseCandidateStatusData::LocalReviewCandidate,
            },
            artifacts,
            provenance: ReleaseProvenanceData {
                status: ReleaseProvenanceStatusData::RequiredExternal,
                predicate_type: ReleasePredicateTypeData::SlsaProvenanceV1,
                signing: ReleaseSigningData::SigstoreKeylessOidc,
                authority_status: ReleaseAuthorityStatusData::UnassignedExternal,
                subject_set: ReleaseSubjectSetData::ExactFinalizedLocalAssets,
                subjects,
            },
            rollback: ReleaseRollbackData {
                retain_published_releases: 2,
                previous_release: None,
                status: ReleaseRollbackStatusData::FirstCandidateNoNMinusOne,
            },
        },
        "release manifest",
    )
}

fn render_checksums(output: &RepositoryWriter, manifest: &[u8]) -> Result<Vec<u8>, ReleaseError> {
    let names = known_stage_names();
    let mut rendered = String::new();
    for name in names {
        let bytes = read_output_required(
            output,
            &name,
            MAX_BINARY_BYTES,
            "checksummed release artifact",
        )?;
        rendered.push_str(&sha256_hex(&bytes));
        rendered.push_str("  ");
        rendered.push_str(&name);
        rendered.push('\n');
    }
    rendered.push_str(&sha256_hex(manifest));
    rendered.push_str("  ");
    rendered.push_str(MANIFEST_FILE);
    rendered.push('\n');
    Ok(rendered.into_bytes())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn to_pretty_json<T: Serialize>(value: &T, label: &str) -> Result<Vec<u8>, ReleaseError> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| ReleaseError::internal(format!("failed to serialize {label}: {error}")))?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::ffi::OsString;
    use std::fs;
    use std::io::Write as _;
    use std::process::Command;
    use std::time::Duration;

    use forge_core::ports::EnvPolicy;
    use forge_core::{Mutability, NetworkIntent};
    use tempfile::tempdir;

    use super::{
        CHECKSUMS_FILE, MANIFEST_FILE, RELEASE_TARGETS, ReleaseError, RepositorySnapshot,
        binary_asset_name, check, finalize, render_sbom, sha256_hex, stage_built,
        validate_binary_format,
    };

    const METADATA: &str = r#"{
      "packages": [
        {"id":"path+file:///repo/crates/forge-cli#0.1.0-rc.1","name":"forge-cli","version":"0.1.0-rc.1","source":null,"checksum":null},
        {"id":"registry+https://github.com/rust-lang/crates.io-index#serde@1.0.229","name":"serde","version":"1.0.229","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"dafc30efc5f0fda1a660d7c0b0b3e2b8ddf0d7b3f05803e9f4b206f50807fd8c"},
        {"id":"registry+https://github.com/rust-lang/crates.io-index#build-helper@1.2.3","name":"build-helper","version":"1.2.3","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":null},
        {"id":"registry+https://github.com/rust-lang/crates.io-index#test-only@4.5.6","name":"test-only","version":"4.5.6","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":null}
      ],
      "workspace_members": ["path+file:///repo/crates/forge-cli#0.1.0-rc.1"],
      "resolve": {"nodes": [
        {"id":"path+file:///repo/crates/forge-cli#0.1.0-rc.1","deps":[
          {"pkg":"registry+https://github.com/rust-lang/crates.io-index#serde@1.0.229","dep_kinds":[{"kind":null,"target":null}]},
          {"pkg":"registry+https://github.com/rust-lang/crates.io-index#build-helper@1.2.3","dep_kinds":[{"kind":"build","target":null}]},
          {"pkg":"registry+https://github.com/rust-lang/crates.io-index#test-only@4.5.6","dep_kinds":[{"kind":"dev","target":null}]}
        ]},
        {"id":"registry+https://github.com/rust-lang/crates.io-index#serde@1.0.229","deps":[]},
        {"id":"registry+https://github.com/rust-lang/crates.io-index#build-helper@1.2.3","deps":[]},
        {"id":"registry+https://github.com/rust-lang/crates.io-index#test-only@4.5.6","deps":[]}
      ]}
    }"#;

    #[test]
    fn sha256_uses_the_standard_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn source_snapshot_rejects_repository_redirect_environment() {
        for key in ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"] {
            assert!(
                super::reject_git_redirect_environment([OsString::from(key)]).is_err(),
                "{key} must not redirect the source snapshot"
            );
        }
        assert!(super::reject_git_redirect_environment([OsString::from("PATH")]).is_ok());
    }

    #[test]
    fn source_snapshot_rejects_an_untracked_file() -> Result<(), ReleaseError> {
        let temporary = tempdir().map_err(|error| ReleaseError::internal(error.to_string()))?;
        let repository = temporary.path().join("repository");
        fs::create_dir(&repository).map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::write(repository.join("tracked.txt"), b"tracked")
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        run_git(&repository, &["init"])?;
        run_git(&repository, &["add", "tracked.txt"])?;
        run_git(
            &repository,
            &[
                "-c",
                "user.name=Forge Test",
                "-c",
                "user.email=forge-test@example.invalid",
                "commit",
                "-m",
                "fixture",
            ],
        )?;
        fs::write(repository.join("untracked.txt"), b"dirty")
            .map_err(|error| ReleaseError::internal(error.to_string()))?;

        assert!(RepositorySnapshot::capture(&repository, &RELEASE_TARGETS[..1]).is_err());
        Ok(())
    }

    #[test]
    fn source_snapshot_binds_the_requested_worktree_despite_local_git_redirects()
    -> Result<(), ReleaseError> {
        let temporary = tempdir().map_err(|error| ReleaseError::internal(error.to_string()))?;
        let repository = temporary.path().join("repository");
        let alternate = temporary.path().join("alternate");
        fs::create_dir(&repository).map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::create_dir(&alternate).map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::write(repository.join("tracked.txt"), b"tracked")
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::write(alternate.join("tracked.txt"), b"tracked")
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        run_git(&repository, &["init"])?;
        run_git(&repository, &["add", "tracked.txt"])?;
        run_git(
            &repository,
            &[
                "-c",
                "user.name=Forge Test",
                "-c",
                "user.email=forge-test@example.invalid",
                "commit",
                "-m",
                "fixture",
            ],
        )?;
        let alternate = alternate.to_str().ok_or_else(|| {
            ReleaseError::internal("temporary alternate worktree path was not UTF-8")
        })?;
        run_git(&repository, &["config", "core.worktree", alternate])?;
        fs::write(repository.join("tracked.txt"), b"dirty source")
            .map_err(|error| ReleaseError::internal(error.to_string()))?;

        super::require_expected_git_worktree(&repository)?;
        assert!(!super::git_status(&repository)?.is_empty());
        assert!(RepositorySnapshot::capture(&repository, &RELEASE_TARGETS[..1]).is_err());
        Ok(())
    }

    #[test]
    fn bounded_release_process_rejects_output_above_the_retention_limit() -> Result<(), ReleaseError>
    {
        let temporary = tempdir().map_err(|error| ReleaseError::internal(error.to_string()))?;
        let executable = env::current_exe().map_err(|error| {
            ReleaseError::internal(format!("failed to locate release test executable: {error}"))
        })?;
        let mut environment = EnvPolicy::minimal();
        environment.overrides.insert(
            OsString::from("FORGE_RELEASE_PROCESS_TEST"),
            OsString::from("huge-output"),
        );
        let observation = super::run_bounded_process(
            temporary.path(),
            executable.into_os_string(),
            [
                "--exact",
                "release::tests::bounded_release_process_test_helper",
                "--nocapture",
            ]
            .into_iter()
            .map(OsString::from)
            .collect(),
            environment,
            Duration::from_secs(10),
            128,
            128,
            Mutability::ReadOnly,
            NetworkIntent::Unknown,
            "release process bound test",
        )?;
        assert!(observation.stdout_truncated);
        assert_eq!(observation.stdout.len(), 128);
        assert!(observation.stdout_total_bytes >= 8_192);
        assert!(super::require_process_success(observation, "release process bound test").is_err());
        Ok(())
    }

    #[test]
    fn bounded_release_process_test_helper() -> Result<(), ReleaseError> {
        if env::var_os("FORGE_RELEASE_PROCESS_TEST").as_deref()
            != Some(std::ffi::OsStr::new("huge-output"))
        {
            return Ok(());
        }
        std::io::stdout()
            .lock()
            .write_all(&[b'x'; 8_192])
            .map_err(|error| ReleaseError::internal(error.to_string()))
    }

    #[test]
    fn cargo_environment_allows_toolchain_controls_but_not_registry_tokens() {
        assert!(super::is_cargo_build_environment_key(std::ffi::OsStr::new(
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER"
        )));
        assert!(super::is_cargo_build_environment_key(std::ffi::OsStr::new(
            "RUSTC_WRAPPER"
        )));
        assert!(!super::is_cargo_build_environment_key(
            std::ffi::OsStr::new("CARGO_REGISTRIES_CRATES_IO_TOKEN")
        ));
        assert!(!super::is_cargo_build_environment_key(
            std::ffi::OsStr::new("CARGO_TARGET_PRIVATE_TOKEN")
        ));
        assert!(super::is_cargo_build_environment_key(std::ffi::OsStr::new(
            "LIB"
        )));
    }

    #[test]
    fn snapshot_comparison_rejects_each_bound_source_input() {
        let before = snapshot();
        let mut changed_head = before.clone();
        changed_head.source_commit = "b".repeat(40);
        assert!(before.require_same(&changed_head, "test").is_err());

        let mut changed_lock = before.clone();
        changed_lock.cargo_lock.push(0);
        assert!(before.require_same(&changed_lock, "test").is_err());

        let mut changed_metadata = before.clone();
        changed_metadata
            .metadata_by_target
            .insert(RELEASE_TARGETS[0].triple.to_owned(), b"different".to_vec());
        assert!(before.require_same(&changed_metadata, "test").is_err());
    }

    #[test]
    fn target_asset_names_are_frozen() {
        assert_eq!(
            RELEASE_TARGETS
                .iter()
                .map(binary_asset_name)
                .collect::<Vec<_>>(),
            [
                "forge-0.1.0-rc.1-x86_64-unknown-linux-musl",
                "forge-0.1.0-rc.1-aarch64-unknown-linux-musl",
                "forge-0.1.0-rc.1-x86_64-apple-darwin",
                "forge-0.1.0-rc.1-aarch64-apple-darwin",
                "forge-0.1.0-rc.1-x86_64-pc-windows-msvc.exe",
            ]
        );
    }

    #[test]
    fn sbom_is_deterministic_and_target_bound() -> Result<(), ReleaseError> {
        let target = &RELEASE_TARGETS[0];
        let binary = fake_binary(target.triple);
        let source_commit = "a".repeat(40);
        let first = render_sbom(
            target,
            METADATA.as_bytes(),
            b"lock",
            &source_commit,
            &binary,
        )?;
        let second = render_sbom(
            target,
            METADATA.as_bytes(),
            b"lock",
            &source_commit,
            &binary,
        )?;
        assert_eq!(first, second);
        let text = String::from_utf8(first)
            .map_err(|error| ReleaseError::internal(format!("test SBOM was not UTF-8: {error}")))?;
        assert!(text.contains("\"specVersion\": \"1.6\""));
        assert!(text.contains(target.triple));
        assert!(text.contains("serde"));
        assert!(text.contains("build-helper"));
        assert!(!text.contains("test-only"));
        assert!(!text.contains("file:///repo"));
        assert!(text.contains(&source_commit));
        assert!(text.contains(&sha256_hex(&binary)));
        assert!(text.contains(&binary.len().to_string()));

        assert_ne!(
            second,
            render_sbom(
                target,
                METADATA.as_bytes(),
                b"different-lock",
                &source_commit,
                &binary,
            )?
        );
        let mut different_binary = binary;
        different_binary.push(1);
        assert_ne!(
            second,
            render_sbom(
                target,
                METADATA.as_bytes(),
                b"lock",
                &source_commit,
                &different_binary,
            )?
        );
        Ok(())
    }

    #[test]
    fn complete_release_round_trip_is_deterministic_and_tamper_evident() -> Result<(), ReleaseError>
    {
        let temporary = tempdir().map_err(|error| ReleaseError::internal(error.to_string()))?;
        let repository = temporary.path().join("repository");
        let output = temporary.path().join("dist");
        fs::create_dir(&repository).map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::create_dir(&output).map_err(|error| ReleaseError::internal(error.to_string()))?;
        let output_writer = super::open_output_directory(&repository, &output)?;
        let snapshot = snapshot();

        for target in &RELEASE_TARGETS {
            stage_built(
                &output_writer,
                target,
                &fake_binary(target.triple),
                &snapshot,
            )?;
        }

        finalize(&output_writer, &snapshot)?;
        let manifest = fs::read(output.join(MANIFEST_FILE))
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        let checksums = fs::read(output.join(CHECKSUMS_FILE))
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        let manifest_json: serde_json::Value = serde_json::from_slice(&manifest)
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        let _: forge_schema::ReleaseManifestData = serde_json::from_slice(&manifest)
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        assert_eq!(manifest_json["schema"], "forge.release-manifest/v1");
        assert_eq!(
            manifest_json["artifacts"].as_array().map(Vec::len),
            Some(10)
        );
        let subjects = manifest_json["provenance"]["subjects"]
            .as_array()
            .ok_or_else(|| ReleaseError::internal("manifest subjects were not an array"))?;
        assert_eq!(subjects.len(), 12);
        assert!(subjects.iter().any(|name| name == CHECKSUMS_FILE));
        assert!(subjects.iter().any(|name| name == MANIFEST_FILE));
        let artifact_names: Vec<_> = manifest_json["artifacts"]
            .as_array()
            .ok_or_else(|| ReleaseError::internal("manifest artifacts were not an array"))?
            .iter()
            .filter_map(|artifact| artifact["name"].as_str())
            .collect();
        assert!(artifact_names.windows(2).all(|pair| pair[0] < pair[1]));

        let mut invalid_manifest = manifest_json.clone();
        invalid_manifest["artifacts"][0]["sha256"] = serde_json::json!("not-a-digest");
        assert!(
            serde_json::from_value::<forge_schema::ReleaseManifestData>(invalid_manifest).is_err()
        );

        finalize(&output_writer, &snapshot)?;
        assert_eq!(
            manifest,
            fs::read(output.join(MANIFEST_FILE))
                .map_err(|error| ReleaseError::internal(error.to_string()))?
        );
        assert_eq!(
            checksums,
            fs::read(output.join(CHECKSUMS_FILE))
                .map_err(|error| ReleaseError::internal(error.to_string()))?
        );
        check(&output_writer, &snapshot)?;

        let tampered = output.join(binary_asset_name(&RELEASE_TARGETS[0]));
        let mut bytes =
            fs::read(&tampered).map_err(|error| ReleaseError::internal(error.to_string()))?;
        bytes.push(0);
        fs::write(&tampered, bytes).map_err(|error| ReleaseError::internal(error.to_string()))?;
        assert!(check(&output_writer, &snapshot).is_err());
        Ok(())
    }

    #[test]
    fn duplicate_target_is_same_bytes_only_and_never_overwritten() -> Result<(), ReleaseError> {
        let temporary = tempdir().map_err(|error| ReleaseError::internal(error.to_string()))?;
        let repository = temporary.path().join("repository");
        let output = temporary.path().join("dist");
        fs::create_dir(&repository).map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::create_dir(&output).map_err(|error| ReleaseError::internal(error.to_string()))?;
        let output_writer = super::open_output_directory(&repository, &output)?;
        let target = &RELEASE_TARGETS[0];
        let binary = fake_binary(target.triple);
        let snapshot = snapshot();

        stage_built(&output_writer, target, &binary, &snapshot)?;
        stage_built(&output_writer, target, &binary, &snapshot)?;
        let mut different = binary.clone();
        different.push(1);
        assert!(stage_built(&output_writer, target, &different, &snapshot).is_err());
        assert_eq!(
            fs::read(output.join(binary_asset_name(target)))
                .map_err(|error| ReleaseError::internal(error.to_string()))?,
            binary
        );
        Ok(())
    }

    #[test]
    fn concurrent_create_is_recovered_only_when_the_winning_bytes_match() -> Result<(), ReleaseError>
    {
        let temporary = tempdir().map_err(|error| ReleaseError::internal(error.to_string()))?;
        let repository = temporary.path().join("repository");
        let output = temporary.path().join("dist");
        fs::create_dir(&repository).map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::create_dir(&output).map_err(|error| ReleaseError::internal(error.to_string()))?;
        let writer = super::open_output_directory(&repository, &output)?;
        let contender = writer.clone();

        super::write_once_or_same_with_precreate(&writer, "matching", b"expected", || {
            contender
                .write_atomic_new("matching", b"expected")
                .map_err(|error| ReleaseError::internal(error.to_string()))
        })?;
        assert_eq!(
            fs::read(output.join("matching"))
                .map_err(|error| ReleaseError::internal(error.to_string()))?,
            b"expected"
        );

        let contender = writer.clone();
        assert!(
            super::write_once_or_same_with_precreate(&writer, "different", b"expected", || {
                contender
                    .write_atomic_new("different", b"winner")
                    .map_err(|error| ReleaseError::internal(error.to_string()))
            },)
            .is_err()
        );
        assert_eq!(
            fs::read(output.join("different"))
                .map_err(|error| ReleaseError::internal(error.to_string()))?,
            b"winner"
        );
        Ok(())
    }

    #[test]
    fn paired_asset_preflight_avoids_deterministic_partial_writes() -> Result<(), ReleaseError> {
        let temporary = tempdir().map_err(|error| ReleaseError::internal(error.to_string()))?;
        let repository = temporary.path().join("repository");
        let stage_output = temporary.path().join("stage-output");
        let finalize_output = temporary.path().join("finalize-output");
        fs::create_dir(&repository).map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::create_dir(&stage_output).map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::create_dir(&finalize_output)
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        let stage_writer = super::open_output_directory(&repository, &stage_output)?;
        let finalize_writer = super::open_output_directory(&repository, &finalize_output)?;
        let snapshot = snapshot();
        let first_target = &RELEASE_TARGETS[0];

        fs::write(
            stage_output.join(super::sbom_asset_name(first_target)),
            b"conflicting SBOM",
        )
        .map_err(|error| ReleaseError::internal(error.to_string()))?;
        assert!(
            stage_built(
                &stage_writer,
                first_target,
                &fake_binary(first_target.triple),
                &snapshot,
            )
            .is_err()
        );
        assert!(!stage_output.join(binary_asset_name(first_target)).exists());

        for target in &RELEASE_TARGETS {
            stage_built(
                &finalize_writer,
                target,
                &fake_binary(target.triple),
                &snapshot,
            )?;
        }
        fs::write(
            finalize_output.join(CHECKSUMS_FILE),
            b"conflicting checksums",
        )
        .map_err(|error| ReleaseError::internal(error.to_string()))?;
        assert!(finalize(&finalize_writer, &snapshot).is_err());
        assert!(!finalize_output.join(MANIFEST_FILE).exists());
        Ok(())
    }

    #[test]
    fn non_candidate_files_are_never_manifest_or_checksum_inputs() -> Result<(), ReleaseError> {
        let temporary = tempdir().map_err(|error| ReleaseError::internal(error.to_string()))?;
        let repository = temporary.path().join("repository");
        let output = temporary.path().join("dist");
        fs::create_dir(&repository).map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::create_dir(&output).map_err(|error| ReleaseError::internal(error.to_string()))?;
        let output_writer = super::open_output_directory(&repository, &output)?;
        fs::write(output.join("operator-notes.txt"), b"not a release asset")
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        let snapshot = snapshot();

        for target in &RELEASE_TARGETS {
            stage_built(
                &output_writer,
                target,
                &fake_binary(target.triple),
                &snapshot,
            )?;
        }
        finalize(&output_writer, &snapshot)?;
        check(&output_writer, &snapshot)?;

        let manifest = fs::read_to_string(output.join(MANIFEST_FILE))
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        let checksums = fs::read_to_string(output.join(CHECKSUMS_FILE))
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        assert!(!manifest.contains("operator-notes.txt"));
        assert!(!checksums.contains("operator-notes.txt"));
        Ok(())
    }

    #[test]
    fn output_directory_must_exist_and_must_not_be_a_symlink() -> Result<(), ReleaseError> {
        let temporary = tempdir().map_err(|error| ReleaseError::internal(error.to_string()))?;
        let repository = temporary.path().join("repository");
        fs::create_dir(&repository).map_err(|error| ReleaseError::internal(error.to_string()))?;
        let missing = temporary.path().join("missing");
        assert!(super::open_output_directory(&repository, &missing).is_err());

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let real = temporary.path().join("real");
            let linked = temporary.path().join("linked");
            fs::create_dir(&real).map_err(|error| ReleaseError::internal(error.to_string()))?;
            symlink(&real, &linked).map_err(|error| ReleaseError::internal(error.to_string()))?;
            assert!(super::open_output_directory(&repository, &linked).is_err());
        }
        Ok(())
    }

    #[test]
    fn output_directory_cannot_be_the_repository_or_any_descendant() -> Result<(), ReleaseError> {
        let temporary = tempdir().map_err(|error| ReleaseError::internal(error.to_string()))?;
        let repository = temporary.path().join("repository");
        let git_output = repository.join(".git").join("dist");
        fs::create_dir_all(&git_output)
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        let target = &RELEASE_TARGETS[0];
        let asset = binary_asset_name(target);

        for output in [&repository, &git_output] {
            assert!(super::open_output_directory(&repository, output).is_err());
            assert!(!output.join(&asset).exists());
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn check_rejects_a_visible_output_root_replacement_even_when_pinned_assets_are_valid()
    -> Result<(), ReleaseError> {
        let temporary = tempdir().map_err(|error| ReleaseError::internal(error.to_string()))?;
        let repository = temporary.path().join("repository");
        let output = temporary.path().join("dist");
        let displaced = temporary.path().join("displaced-dist");
        fs::create_dir(&repository).map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::create_dir(&output).map_err(|error| ReleaseError::internal(error.to_string()))?;
        let writer = super::open_output_directory(&repository, &output)?;
        let snapshot = snapshot();
        for target in &RELEASE_TARGETS {
            stage_built(&writer, target, &fake_binary(target.triple), &snapshot)?;
        }
        finalize(&writer, &snapshot)?;

        fs::rename(&output, &displaced)
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::create_dir(&output).map_err(|error| ReleaseError::internal(error.to_string()))?;
        assert!(check(&writer, &snapshot).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn built_binary_read_uses_the_prebuild_pinned_root_and_rejects_symlinks()
    -> Result<(), ReleaseError> {
        use std::os::unix::fs::symlink;

        let temporary = tempdir().map_err(|error| ReleaseError::internal(error.to_string()))?;
        let build_root = temporary.path().join("build-root");
        let displaced_root = temporary.path().join("displaced-root");
        let attacker_root = temporary.path().join("attacker-root");
        fs::create_dir(&build_root).map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::create_dir(&attacker_root)
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        let pinned = forge_runtime::fs::RepositoryWriter::new(&build_root)
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        let target = &RELEASE_TARGETS[0];
        let attacker_release = attacker_root.join(target.triple).join("release");
        fs::create_dir_all(&attacker_release)
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::write(
            attacker_release.join(target.executable_name),
            fake_binary(target.triple),
        )
        .map_err(|error| ReleaseError::internal(error.to_string()))?;

        fs::rename(&build_root, &displaced_root)
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        symlink(&attacker_root, &build_root)
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        assert!(super::read_built_binary(&pinned, target).is_err());

        let original_release = displaced_root.join(target.triple).join("release");
        fs::create_dir_all(&original_release)
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        symlink(
            attacker_release.join(target.executable_name),
            original_release.join(target.executable_name),
        )
        .map_err(|error| ReleaseError::internal(error.to_string()))?;
        assert!(super::read_built_binary(&pinned, target).is_err());
        Ok(())
    }

    #[test]
    fn executable_validators_reject_structurally_invalid_images() {
        for target in &RELEASE_TARGETS {
            assert!(validate_binary_format(target, &fake_binary(target.triple)).is_ok());
        }

        let mut dynamic = fake_elf(62);
        dynamic[64..68].copy_from_slice(&3_u32.to_le_bytes());
        assert!(validate_binary_format(&RELEASE_TARGETS[0], &dynamic).is_err());

        let mut wrong_type = fake_elf(62);
        wrong_type[16..18].copy_from_slice(&0_u16.to_le_bytes());
        assert!(validate_binary_format(&RELEASE_TARGETS[0], &wrong_type).is_err());

        let mut no_elf_entry = fake_elf(62);
        no_elf_entry[24..32].copy_from_slice(&0_u64.to_le_bytes());
        assert!(validate_binary_format(&RELEASE_TARGETS[0], &no_elf_entry).is_err());

        let mut non_executable_elf = fake_elf(62);
        non_executable_elf[68..72].copy_from_slice(&4_u32.to_le_bytes());
        assert!(validate_binary_format(&RELEASE_TARGETS[0], &non_executable_elf).is_err());

        let mut bss_entry_elf = fake_elf(62);
        bss_entry_elf[96..104].copy_from_slice(&32_u64.to_le_bytes());
        assert!(validate_binary_format(&RELEASE_TARGETS[0], &bss_entry_elf).is_err());

        let mut out_of_file_elf = fake_elf(62);
        out_of_file_elf[72..80].copy_from_slice(&100_u64.to_le_bytes());
        assert!(validate_binary_format(&RELEASE_TARGETS[0], &out_of_file_elf).is_err());

        let mut wrong_macho_type = fake_macho(0x0100_0007);
        wrong_macho_type[12..16].copy_from_slice(&1_u32.to_le_bytes());
        assert!(validate_binary_format(&RELEASE_TARGETS[2], &wrong_macho_type).is_err());

        let mut non_executable_macho = fake_macho(0x0100_0007);
        non_executable_macho[92..96].copy_from_slice(&0_u32.to_le_bytes());
        assert!(validate_binary_format(&RELEASE_TARGETS[2], &non_executable_macho).is_err());

        let mut no_macho_entry = fake_macho(0x0100_0007);
        no_macho_entry[104..108].copy_from_slice(&0_u32.to_le_bytes());
        assert!(validate_binary_format(&RELEASE_TARGETS[2], &no_macho_entry).is_err());

        let mut out_of_file_macho = fake_macho(0x0100_0007);
        out_of_file_macho[80..88].copy_from_slice(&1000_u64.to_le_bytes());
        assert!(validate_binary_format(&RELEASE_TARGETS[2], &out_of_file_macho).is_err());

        let mut pe_dll = fake_pe();
        pe_dll[0x56..0x58].copy_from_slice(&0x2002_u16.to_le_bytes());
        assert!(validate_binary_format(&RELEASE_TARGETS[4], &pe_dll).is_err());

        let mut no_pe_entry = fake_pe();
        no_pe_entry[0x68..0x6c].copy_from_slice(&0_u32.to_le_bytes());
        assert!(validate_binary_format(&RELEASE_TARGETS[4], &no_pe_entry).is_err());

        let mut non_executable_pe = fake_pe();
        non_executable_pe[0xec..0xf0].copy_from_slice(&0_u32.to_le_bytes());
        assert!(validate_binary_format(&RELEASE_TARGETS[4], &non_executable_pe).is_err());

        let mut bss_entry_pe = fake_pe();
        bss_entry_pe[0xd8..0xdc].copy_from_slice(&0_u32.to_le_bytes());
        assert!(validate_binary_format(&RELEASE_TARGETS[4], &bss_entry_pe).is_err());

        let mut out_of_file_pe = fake_pe();
        out_of_file_pe[0xdc..0xe0].copy_from_slice(&0x180_u32.to_le_bytes());
        assert!(validate_binary_format(&RELEASE_TARGETS[4], &out_of_file_pe).is_err());
    }

    #[test]
    fn sbom_requires_the_exact_workspace_root() {
        let metadata = METADATA.replace(
            "\"workspace_members\": [\"path+file:///repo/crates/forge-cli#0.1.0-rc.1\"]",
            "\"workspace_members\": []",
        );
        assert!(
            render_sbom(
                &RELEASE_TARGETS[0],
                metadata.as_bytes(),
                b"lock",
                &"a".repeat(40),
                &fake_binary(RELEASE_TARGETS[0].triple),
            )
            .is_err()
        );
    }

    #[test]
    fn sbom_rejects_a_local_dependency_outside_the_workspace() {
        let metadata = METADATA.replacen(
            "\"source\":\"registry+https://github.com/rust-lang/crates.io-index\"",
            "\"source\":null",
            1,
        );
        assert!(
            render_sbom(
                &RELEASE_TARGETS[0],
                metadata.as_bytes(),
                b"lock",
                &"a".repeat(40),
                &fake_binary(RELEASE_TARGETS[0].triple),
            )
            .is_err()
        );
    }

    fn snapshot() -> RepositorySnapshot {
        RepositorySnapshot {
            source_commit: "a".repeat(40),
            status: Vec::new(),
            cargo_lock: b"lock".to_vec(),
            metadata_by_target: RELEASE_TARGETS
                .iter()
                .map(|target| (target.triple.to_owned(), METADATA.as_bytes().to_vec()))
                .collect(),
        }
    }

    fn run_git(repository: &std::path::Path, arguments: &[&str]) -> Result<(), ReleaseError> {
        let mut command = Command::new("git");
        command.current_dir(repository).args(arguments);
        for key in super::REJECTED_RELEASE_GIT_ENV {
            command.env_remove(key);
        }
        let output = command
            .output()
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(ReleaseError::internal(format!(
                "test Git command failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )))
        }
    }

    fn fake_binary(triple: &str) -> Vec<u8> {
        match triple {
            "x86_64-unknown-linux-musl" => fake_elf(62),
            "aarch64-unknown-linux-musl" => fake_elf(183),
            "x86_64-apple-darwin" => fake_macho(0x0100_0007),
            "aarch64-apple-darwin" => fake_macho(0x0100_000c),
            "x86_64-pc-windows-msvc" => fake_pe(),
            _ => Vec::new(),
        }
    }

    fn fake_elf(machine: u16) -> Vec<u8> {
        let mut bytes = vec![0; 120];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&machine.to_le_bytes());
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x40_0040_u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
        bytes[68..72].copy_from_slice(&5_u32.to_le_bytes());
        bytes[80..88].copy_from_slice(&0x40_0000_u64.to_le_bytes());
        bytes[96..104].copy_from_slice(&120_u64.to_le_bytes());
        bytes[104..112].copy_from_slice(&120_u64.to_le_bytes());
        bytes[112..120].copy_from_slice(&4096_u64.to_le_bytes());
        bytes
    }

    fn fake_macho(cpu: u32) -> Vec<u8> {
        let mut bytes = vec![0; 160];
        bytes[0..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        bytes[4..8].copy_from_slice(&cpu.to_le_bytes());
        bytes[12..16].copy_from_slice(&2_u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&2_u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&96_u32.to_le_bytes());
        bytes[32..36].copy_from_slice(&0x19_u32.to_le_bytes());
        bytes[36..40].copy_from_slice(&72_u32.to_le_bytes());
        bytes[64..72].copy_from_slice(&160_u64.to_le_bytes());
        bytes[80..88].copy_from_slice(&160_u64.to_le_bytes());
        bytes[88..92].copy_from_slice(&7_u32.to_le_bytes());
        bytes[92..96].copy_from_slice(&5_u32.to_le_bytes());
        bytes[104..108].copy_from_slice(&0x8000_0028_u32.to_le_bytes());
        bytes[108..112].copy_from_slice(&24_u32.to_le_bytes());
        bytes[112..120].copy_from_slice(&136_u64.to_le_bytes());
        bytes
    }

    fn fake_pe() -> Vec<u8> {
        let mut bytes = vec![0; 0x200];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x40_u32.to_le_bytes());
        bytes[0x40..0x44].copy_from_slice(b"PE\0\0");
        bytes[0x44..0x46].copy_from_slice(&0x8664_u16.to_le_bytes());
        bytes[0x46..0x48].copy_from_slice(&1_u16.to_le_bytes());
        bytes[0x54..0x56].copy_from_slice(&0x70_u16.to_le_bytes());
        bytes[0x56..0x58].copy_from_slice(&0x0002_u16.to_le_bytes());
        bytes[0x58..0x5a].copy_from_slice(&0x020b_u16.to_le_bytes());
        bytes[0x68..0x6c].copy_from_slice(&0x1000_u32.to_le_bytes());
        bytes[0x90..0x94].copy_from_slice(&0x2000_u32.to_le_bytes());
        bytes[0x94..0x98].copy_from_slice(&0x100_u32.to_le_bytes());
        bytes[0xd0..0xd4].copy_from_slice(&0x100_u32.to_le_bytes());
        bytes[0xd4..0xd8].copy_from_slice(&0x1000_u32.to_le_bytes());
        bytes[0xd8..0xdc].copy_from_slice(&0x100_u32.to_le_bytes());
        bytes[0xdc..0xe0].copy_from_slice(&0x100_u32.to_le_bytes());
        bytes[0xec..0xf0].copy_from_slice(&0x2000_0000_u32.to_le_bytes());
        bytes
    }
}
