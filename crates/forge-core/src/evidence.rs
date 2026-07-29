//! Deterministic evidence normalization and receipt-validity rules.
//!
//! This module transforms or compares already-computed facts. It deliberately owns no hashing,
//! filesystem, process, clock, network, persistence, JSON parsing, or wire-format behavior.

use std::collections::{BTreeMap, BTreeSet};

use forge_schema::{Digest, RepoId};

use crate::domain::CommandEnforcement;
use crate::ports::{ProcessErrorKind, ProcessObservation};
use crate::{CoverageDimension, Intent, Mutability, SuccessPredicate};

/// Pure command-success normalization behavior bound into the Forge behavior dependency.
pub const SUCCESS_NORMALIZATION_PROTOCOL_VERSION: &str = "forge.success-normalization/v1";

/// Receipt dependency and applicability comparison behavior bound into the Forge behavior
/// dependency.
pub const RECEIPT_VALIDITY_PROTOCOL_VERSION: &str = "forge.receipt-validity/v2";

/// A dependency value whose absence cannot be confused with a real identifier or digest.
///
/// Forge must never manufacture a sentinel string for missing knowledge. `Unknown` is explicit
/// and is always non-passing when either side of a receipt comparison contains it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DependencyValue<T> {
    Known(T),
    Unknown,
}

/// The base commit and task-acceptance dependency of a receipt.
///
/// `Known` contains a canonical digest of every applicable base/task input. A caller must use
/// `NotApplicable` only when neither input applies. Missing or unreliable knowledge is `Unknown`,
/// which can never satisfy evidence.
///
/// The evaluator never infers whether `NotApplicable` is semantically valid. That decision belongs
/// to the future authoritative receipt builder.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BaseTaskDependency {
    Known(Digest),
    NotApplicable,
    Unknown,
}

/// One dimension in the complete dependency fingerprint.
///
/// Declaration order is also the stable comparison and reporting order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EvidenceDependency {
    Repository,
    Scope,
    Command,
    Toolchain,
    Environment,
    Policy,
    BaseTask,
    ForgeBehavior,
}

impl EvidenceDependency {
    /// Stable human- and machine-readable name for this dependency dimension.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Repository => "repository",
            Self::Scope => "scope",
            Self::Command => "command",
            Self::Toolchain => "toolchain",
            Self::Environment => "environment",
            Self::Policy => "policy",
            Self::BaseTask => "base-task",
            Self::ForgeBehavior => "forge-behavior",
        }
    }
}

/// Every fact whose equality is required before a receipt can be reused.
///
/// For a recorded receipt, `scope` is the after-execution scope digest. The corresponding
/// before-execution digest lives on [`ReceiptValidityInput`] because it is an execution invariant,
/// not a reusable dependency value. The authoritative builder must establish that context; this
/// evaluator only compares the supplied typed facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceDependencyFingerprint {
    repository: DependencyValue<RepoId>,
    scope: DependencyValue<Digest>,
    command: DependencyValue<Digest>,
    toolchain: DependencyValue<Digest>,
    environment: DependencyValue<Digest>,
    policy: DependencyValue<Digest>,
    base_task: BaseTaskDependency,
    forge_behavior: DependencyValue<Digest>,
}

/// The three per-command dependency dimensions that must be aggregated in execution order.
///
/// Values are already privacy-safe digests or explicit unknowns. Raw command environment values
/// must never be passed through this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionDependencyFingerprint {
    command: DependencyValue<Digest>,
    toolchain: DependencyValue<Digest>,
    environment: DependencyValue<Digest>,
}

impl ExecutionDependencyFingerprint {
    #[must_use]
    pub fn new(
        command: DependencyValue<Digest>,
        toolchain: DependencyValue<Digest>,
        environment: DependencyValue<Digest>,
    ) -> Self {
        Self {
            command,
            toolchain,
            environment,
        }
    }

    #[must_use]
    pub const fn command(&self) -> &DependencyValue<Digest> {
        &self.command
    }

    #[must_use]
    pub const fn toolchain(&self) -> &DependencyValue<Digest> {
        &self.toolchain
    }

    #[must_use]
    pub const fn environment(&self) -> &DependencyValue<Digest> {
        &self.environment
    }
}

impl EvidenceDependencyFingerprint {
    /// Constructs a complete dependency fingerprint from authoritative, already-computed facts.
    ///
    /// Unknown values remain explicit and make receipt reuse fail closed. The constructor does not
    /// infer missing dependencies or permit `NotApplicable` on any axis except base/task.
    #[must_use]
    pub fn new(
        repository: DependencyValue<RepoId>,
        scope: DependencyValue<Digest>,
        execution: ExecutionDependencyFingerprint,
        policy: DependencyValue<Digest>,
        base_task: BaseTaskDependency,
        forge_behavior: DependencyValue<Digest>,
    ) -> Self {
        Self {
            repository,
            scope,
            command: execution.command,
            toolchain: execution.toolchain,
            environment: execution.environment,
            policy,
            base_task,
            forge_behavior,
        }
    }

    #[must_use]
    pub const fn repository(&self) -> &DependencyValue<RepoId> {
        &self.repository
    }

    #[must_use]
    pub const fn scope(&self) -> &DependencyValue<Digest> {
        &self.scope
    }

    #[must_use]
    pub const fn command(&self) -> &DependencyValue<Digest> {
        &self.command
    }

    #[must_use]
    pub const fn toolchain(&self) -> &DependencyValue<Digest> {
        &self.toolchain
    }

    #[must_use]
    pub const fn environment(&self) -> &DependencyValue<Digest> {
        &self.environment
    }

    #[must_use]
    pub const fn policy(&self) -> &DependencyValue<Digest> {
        &self.policy
    }

    #[must_use]
    pub const fn base_task(&self) -> &BaseTaskDependency {
        &self.base_task
    }

    #[must_use]
    pub const fn forge_behavior(&self) -> &DependencyValue<Digest> {
        &self.forge_behavior
    }
}

/// Normalized result recorded by a receipt.
///
/// Outcome is intentionally independent from dependency validity: a stale failure is not a
/// current failure, and a current failure must not be hidden merely because it is not a pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EvidenceOutcome {
    Pass,
    ProductFailure,
    InfrastructureFailure,
    Inconclusive,
    TimedOut,
    Interrupted,
    Unknown,
}

/// Caller-provided result of applying the command-specific JSON error contract to complete stdout.
///
/// Forge core deliberately does not invent a JSON field path. The authoritative command provider
/// owns that parsing contract and reports only this typed result. `Invalid` means the output did
/// not satisfy the declared JSON contract and is therefore a product failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JsonErrorStatus {
    NoErrors,
    HasErrors,
    Invalid,
}

/// Pure input for normalizing one process boundary result.
///
/// A process observation carries complete stdout byte count even when retained output is bounded.
/// JSON status is optional because most predicates do not need it. A caller using
/// [`SuccessPredicate::JsonHasNoErrors`] must provide a status derived from the complete output;
/// absence fails closed as [`EvidenceOutcome::Unknown`].
#[derive(Debug, Clone, Copy)]
pub enum ProcessOutcomeInput<'a> {
    Observation {
        observation: &'a ProcessObservation,
        json_errors: Option<JsonErrorStatus>,
    },
    InfrastructureFailure(ProcessErrorKind),
}

impl<'a> ProcessOutcomeInput<'a> {
    #[must_use]
    pub const fn observation(
        observation: &'a ProcessObservation,
        json_errors: Option<JsonErrorStatus>,
    ) -> Self {
        Self::Observation {
            observation,
            json_errors,
        }
    }

    #[must_use]
    pub const fn infrastructure_failure(kind: ProcessErrorKind) -> Self {
        Self::InfrastructureFailure(kind)
    }
}

/// Normalizes a process result according to one declared success predicate.
///
/// Timeout, interruption, and process-boundary failures take precedence over product predicates.
/// Empty conjunctions, contradictory observations, absent JSON status, and incomplete process
/// termination facts never become passes.
#[must_use]
pub fn normalize_evidence_outcome(
    predicate: &SuccessPredicate,
    input: ProcessOutcomeInput<'_>,
) -> EvidenceOutcome {
    let ProcessOutcomeInput::Observation {
        observation,
        json_errors,
    } = input
    else {
        return EvidenceOutcome::InfrastructureFailure;
    };

    if observation.timed_out && observation.interrupted {
        return EvidenceOutcome::Unknown;
    }
    if observation.timed_out {
        return EvidenceOutcome::TimedOut;
    }
    if observation.interrupted {
        return EvidenceOutcome::Interrupted;
    }
    let retained_stdout_bytes = u64::try_from(observation.stdout.len()).unwrap_or(u64::MAX);
    if observation.exit_code.is_some() && observation.signal.is_some()
        || retained_stdout_bytes > observation.stdout_total_bytes
        || observation.stdout_total_bytes == 0 && observation.stdout_truncated
    {
        return EvidenceOutcome::Unknown;
    }
    if observation.exit_code.is_none() {
        return if observation.signal.is_some() {
            EvidenceOutcome::ProductFailure
        } else {
            EvidenceOutcome::Inconclusive
        };
    }

    evaluate_success_predicate(predicate, observation, json_errors)
}

fn evaluate_success_predicate(
    predicate: &SuccessPredicate,
    observation: &ProcessObservation,
    json_errors: Option<JsonErrorStatus>,
) -> EvidenceOutcome {
    let mut aggregate = EvidenceOutcome::Pass;
    let mut pending = vec![predicate];
    while let Some(predicate) = pending.pop() {
        let outcome = match predicate {
            SuccessPredicate::ExitZero => exit_zero_outcome(observation),
            SuccessPredicate::ExitZeroAndStdoutEmpty => match exit_zero_outcome(observation) {
                EvidenceOutcome::Pass if observation.stdout_total_bytes == 0 => {
                    EvidenceOutcome::Pass
                }
                EvidenceOutcome::Pass | EvidenceOutcome::ProductFailure => {
                    EvidenceOutcome::ProductFailure
                }
                outcome => outcome,
            },
            SuccessPredicate::JsonHasNoErrors => match json_errors {
                Some(JsonErrorStatus::NoErrors) => EvidenceOutcome::Pass,
                Some(JsonErrorStatus::HasErrors | JsonErrorStatus::Invalid) => {
                    EvidenceOutcome::ProductFailure
                }
                None => EvidenceOutcome::Unknown,
            },
            SuccessPredicate::All(predicates) if predicates.is_empty() => {
                EvidenceOutcome::ProductFailure
            }
            SuccessPredicate::All(predicates) => {
                pending.extend(predicates.iter().rev());
                continue;
            }
        };
        aggregate = combine_predicate_outcomes(aggregate, outcome);
        if matches!(aggregate, EvidenceOutcome::ProductFailure) {
            return aggregate;
        }
    }
    aggregate
}

const fn exit_zero_outcome(observation: &ProcessObservation) -> EvidenceOutcome {
    match observation.exit_code {
        Some(0) => EvidenceOutcome::Pass,
        Some(_) => EvidenceOutcome::ProductFailure,
        None => EvidenceOutcome::Inconclusive,
    }
}

const fn combine_predicate_outcomes(
    accumulated: EvidenceOutcome,
    next: EvidenceOutcome,
) -> EvidenceOutcome {
    use EvidenceOutcome::{Pass, ProductFailure, Unknown};

    match (accumulated, next) {
        (ProductFailure, _) | (_, ProductFailure) => ProductFailure,
        (Pass, Pass) => Pass,
        // Process-boundary outcomes return before predicate recursion. Of the remaining predicate
        // outcomes, every pair not handled above contains `Unknown` and is therefore non-proving.
        _ => Unknown,
    }
}

/// One normalized command observation supplied to Receipt-level aggregation.
///
/// The command's enforcement is kept beside its outcome so an advisory check can remain visible
/// without silently becoming a project admission gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandEvidenceObservation {
    enforcement: CommandEnforcement,
    outcome: EvidenceOutcome,
    coverage: BTreeSet<CoverageDimension>,
}

impl CommandEvidenceObservation {
    #[must_use]
    pub fn new(
        enforcement: CommandEnforcement,
        outcome: EvidenceOutcome,
        coverage: impl IntoIterator<Item = CoverageDimension>,
    ) -> Self {
        Self {
            enforcement,
            outcome,
            coverage: coverage.into_iter().collect(),
        }
    }

    #[must_use]
    pub const fn enforcement(&self) -> CommandEnforcement {
        self.enforcement
    }

    #[must_use]
    pub const fn outcome(&self) -> EvidenceOutcome {
        self.outcome
    }

    #[must_use]
    pub const fn coverage(&self) -> &BTreeSet<CoverageDimension> {
        &self.coverage
    }
}

/// Deterministic result of aggregating an ordered command chain into one Receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptEvidenceAggregation {
    outcome: EvidenceOutcome,
    verified: BTreeSet<CoverageDimension>,
    advisory: BTreeSet<CoverageDimension>,
    not_verified: BTreeSet<CoverageDimension>,
}

impl ReceiptEvidenceAggregation {
    #[must_use]
    pub const fn outcome(&self) -> EvidenceOutcome {
        self.outcome
    }

    #[must_use]
    pub const fn verified(&self) -> &BTreeSet<CoverageDimension> {
        &self.verified
    }

    #[must_use]
    pub const fn advisory(&self) -> &BTreeSet<CoverageDimension> {
        &self.advisory
    }

    #[must_use]
    pub const fn not_verified(&self) -> &BTreeSet<CoverageDimension> {
        &self.not_verified
    }
}

/// Aggregates command observations in execution order without promoting advisory checks.
///
/// The first non-passing required observation is the Receipt outcome. Observations after such a
/// failure violate the v0 stop-on-required-failure protocol and make the aggregate unknown. A
/// chain containing only advisory observations is also unknown because it has no admission gate.
#[must_use]
pub fn aggregate_command_evidence(
    observations: &[CommandEvidenceObservation],
) -> ReceiptEvidenceAggregation {
    let mut required_seen = false;
    let mut required_failure = None;
    let mut sequence_violation = false;
    let mut verified = BTreeSet::new();
    let mut advisory_pass = BTreeSet::new();
    let mut non_passing = BTreeSet::new();

    for observation in observations {
        if required_failure.is_some() {
            sequence_violation = true;
        }
        match observation.enforcement {
            CommandEnforcement::Required => {
                required_seen = true;
                if observation.outcome == EvidenceOutcome::Pass {
                    verified.extend(observation.coverage.iter().cloned());
                } else {
                    non_passing.extend(observation.coverage.iter().cloned());
                    required_failure.get_or_insert(observation.outcome);
                }
            }
            CommandEnforcement::Advisory => {
                if observation.outcome == EvidenceOutcome::Pass {
                    advisory_pass.extend(observation.coverage.iter().cloned());
                } else {
                    non_passing.extend(observation.coverage.iter().cloned());
                }
            }
        }
    }

    let outcome = if sequence_violation || !required_seen {
        EvidenceOutcome::Unknown
    } else {
        required_failure.unwrap_or(EvidenceOutcome::Pass)
    };
    let not_verified = non_passing
        .difference(&verified)
        .cloned()
        .collect::<BTreeSet<_>>();
    let advisory = advisory_pass
        .difference(&verified)
        .filter(|dimension| !not_verified.contains(*dimension))
        .cloned()
        .collect();
    ReceiptEvidenceAggregation {
        outcome,
        verified,
        advisory,
        not_verified,
    }
}

/// Local-only Evidence state. It cannot express or imply merge, release, or deployment approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalEvidenceState {
    Insufficient,
    Failing,
    Sufficient,
    Unknown,
}

/// Policy sufficiency and its explicitly separated local/external gaps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalEvidenceEvaluation {
    state: LocalEvidenceState,
    satisfied: Vec<String>,
    not_verified: Vec<String>,
    external_required: Vec<String>,
}

impl LocalEvidenceEvaluation {
    #[must_use]
    pub const fn state(&self) -> LocalEvidenceState {
        self.state
    }

    #[must_use]
    pub fn satisfied(&self) -> &[String] {
        &self.satisfied
    }

    #[must_use]
    pub fn not_verified(&self) -> &[String] {
        &self.not_verified
    }

    #[must_use]
    pub fn external_required(&self) -> &[String] {
        &self.external_required
    }
}

/// Evaluates required local intents against the newest current Receipt for each intent.
///
/// Requirements also named in `external_requirements` remain external and never become locally
/// satisfiable. Unknown custom requirements stay in `not_verified`. When risk/policy knowledge is
/// incomplete, the explicit `risk-classification` gap prevents an empty list from looking green.
#[must_use]
pub fn evaluate_local_evidence(
    requirements_complete: bool,
    evidence_requirements: impl IntoIterator<Item = String>,
    external_requirements: impl IntoIterator<Item = String>,
    newest_current_receipts: &BTreeMap<Intent, ReceiptValidity>,
) -> LocalEvidenceEvaluation {
    let required = evidence_requirements.into_iter().collect::<BTreeSet<_>>();
    let external = external_requirements.into_iter().collect::<BTreeSet<_>>();
    let mut satisfied = BTreeSet::new();
    let mut not_verified = BTreeSet::new();
    let mut has_product_failure = false;
    let mut has_unknown_observation = false;

    for requirement in required.difference(&external) {
        let Some(intent) = intent_from_requirement(requirement) else {
            not_verified.insert(requirement.clone());
            continue;
        };
        let Some(validity) = newest_current_receipts.get(&intent) else {
            not_verified.insert(requirement.clone());
            continue;
        };
        if validity.is_current_passing_local_observation() {
            satisfied.insert(requirement.clone());
            continue;
        }
        not_verified.insert(requirement.clone());
        if validity.dependency_validity() == DependencyValidity::Current {
            match validity.outcome() {
                EvidenceOutcome::ProductFailure => has_product_failure = true,
                EvidenceOutcome::InfrastructureFailure
                | EvidenceOutcome::Inconclusive
                | EvidenceOutcome::TimedOut
                | EvidenceOutcome::Interrupted
                | EvidenceOutcome::Unknown => has_unknown_observation = true,
                EvidenceOutcome::Pass => {
                    if validity.applicability() == ReceiptApplicability::Unknown {
                        has_unknown_observation = true;
                    }
                }
            }
        }
    }

    if !requirements_complete {
        not_verified.insert(String::from("risk-classification"));
    }
    let state = if !requirements_complete || has_unknown_observation {
        LocalEvidenceState::Unknown
    } else if has_product_failure {
        LocalEvidenceState::Failing
    } else if not_verified.is_empty() {
        LocalEvidenceState::Sufficient
    } else {
        LocalEvidenceState::Insufficient
    };
    LocalEvidenceEvaluation {
        state,
        satisfied: satisfied.into_iter().collect(),
        not_verified: not_verified.into_iter().collect(),
        external_required: external.into_iter().collect(),
    }
}

const fn intent_from_requirement(requirement: &str) -> Option<Intent> {
    match requirement.as_bytes() {
        b"setup" => Some(Intent::Setup),
        b"format-check" => Some(Intent::FormatCheck),
        b"format" => Some(Intent::Format),
        b"check" => Some(Intent::Check),
        b"fix" => Some(Intent::Fix),
        b"test" => Some(Intent::Test),
        b"verify" => Some(Intent::Verify),
        b"build" => Some(Intent::Build),
        _ => None,
    }
}

/// The receipt facts needed by the pure validity evaluator.
///
/// Fields remain private so callers use the complete constructor. The authoritative builder owns
/// after-scope and `NotApplicable` semantics; the evaluator does not infer either from ambient
/// context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptValidityInput {
    dependencies: EvidenceDependencyFingerprint,
    scope_before: DependencyValue<Digest>,
    mutability: Mutability,
    outcome: EvidenceOutcome,
}

impl ReceiptValidityInput {
    /// Constructs the pure validity input from authoritative receipt facts.
    #[must_use]
    pub fn new(
        dependencies: EvidenceDependencyFingerprint,
        scope_before: DependencyValue<Digest>,
        mutability: Mutability,
        outcome: EvidenceOutcome,
    ) -> Self {
        Self {
            dependencies,
            scope_before,
            mutability,
            outcome,
        }
    }

    #[must_use]
    pub const fn dependencies(&self) -> &EvidenceDependencyFingerprint {
        &self.dependencies
    }

    #[must_use]
    pub const fn scope_before(&self) -> &DependencyValue<Digest> {
        &self.scope_before
    }

    #[must_use]
    pub const fn mutability(&self) -> Mutability {
        self.mutability
    }

    #[must_use]
    pub const fn outcome(&self) -> EvidenceOutcome {
        self.outcome
    }
}

/// Stable typed reason for the dependency-validity axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DependencyReason {
    Changed(EvidenceDependency),
    Unknown(EvidenceDependency),
}

impl DependencyReason {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Changed(_) => "dependency-changed",
            Self::Unknown(_) => "dependency-unknown",
        }
    }

    #[must_use]
    pub const fn dependency(self) -> EvidenceDependency {
        match self {
            Self::Changed(dependency) | Self::Unknown(dependency) => dependency,
        }
    }
}

/// Stable typed reason for the local-observation applicability axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ApplicabilityReason {
    ReadOnlyScopeChangedDuringRun,
    ExternalSideEffectScopeChangedDuringRun,
    WorkingTreeWriteRequiresReadOnlyFollowUp,
    MutabilityUnknown,
}

impl ApplicabilityReason {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ReadOnlyScopeChangedDuringRun => "read-only-scope-changed-during-run",
            Self::ExternalSideEffectScopeChangedDuringRun => {
                "external-side-effect-scope-changed-during-run"
            }
            Self::WorkingTreeWriteRequiresReadOnlyFollowUp => {
                "working-tree-write-requires-read-only-follow-up"
            }
            Self::MutabilityUnknown => "mutability-unknown",
        }
    }
}

/// Whether every recorded dependency is known and still equal to the current dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DependencyValidity {
    Current,
    Stale,
    Unknown,
}

/// Whether this receipt can directly support a local command-observation decision.
///
/// `Eligible` for an external-side-effect command says only that its local repository scope stayed
/// stable. It never grants, replaces, or implies external authority or attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReceiptApplicability {
    Eligible,
    NonProving,
    Unknown,
}

/// Complete result of one receipt-to-current-state comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptValidity {
    dependency_validity: DependencyValidity,
    applicability: ReceiptApplicability,
    outcome: EvidenceOutcome,
    dependency_reasons: Vec<DependencyReason>,
    applicability_reasons: Vec<ApplicabilityReason>,
}

impl ReceiptValidity {
    #[must_use]
    pub const fn dependency_validity(&self) -> DependencyValidity {
        self.dependency_validity
    }

    #[must_use]
    pub const fn applicability(&self) -> ReceiptApplicability {
        self.applicability
    }

    #[must_use]
    pub const fn outcome(&self) -> EvidenceOutcome {
        self.outcome
    }

    /// Every dependency mismatch or unknown, in stable dependency order.
    #[must_use]
    pub fn dependency_reasons(&self) -> &[DependencyReason] {
        &self.dependency_reasons
    }

    /// Every local-observation applicability reason, in deterministic evaluation order.
    #[must_use]
    pub fn applicability_reasons(&self) -> &[ApplicabilityReason] {
        &self.applicability_reasons
    }

    /// Whether this one receipt is a current passing local command observation.
    ///
    /// This predicate does not evaluate coverage across receipts, policy sufficiency, external
    /// requirements, authority, or attestations. In particular, an eligible
    /// [`Mutability::ExternalSideEffect`] observation never grants external authority.
    #[must_use]
    pub const fn is_current_passing_local_observation(&self) -> bool {
        matches!(self.dependency_validity, DependencyValidity::Current)
            && matches!(self.applicability, ReceiptApplicability::Eligible)
            && matches!(self.outcome, EvidenceOutcome::Pass)
    }
}

/// Compares a receipt with the current complete dependency fingerprint.
///
/// The function deliberately does not stop at the first mismatch. Callers receive every known
/// reason in a deterministic order so one rerun can explain the whole invalidation surface.
#[must_use]
pub fn evaluate_receipt_validity(
    receipt: &ReceiptValidityInput,
    current: &EvidenceDependencyFingerprint,
) -> ReceiptValidity {
    let recorded = &receipt.dependencies;
    let mut dependency_reasons = Vec::new();

    compare_dependency(
        &mut dependency_reasons,
        EvidenceDependency::Repository,
        &recorded.repository,
        &current.repository,
    );
    compare_dependency(
        &mut dependency_reasons,
        EvidenceDependency::Scope,
        &recorded.scope,
        &current.scope,
    );
    if matches!(receipt.scope_before, DependencyValue::Unknown) {
        push_unknown(&mut dependency_reasons, EvidenceDependency::Scope);
    }
    compare_dependency(
        &mut dependency_reasons,
        EvidenceDependency::Command,
        &recorded.command,
        &current.command,
    );
    compare_dependency(
        &mut dependency_reasons,
        EvidenceDependency::Toolchain,
        &recorded.toolchain,
        &current.toolchain,
    );
    compare_dependency(
        &mut dependency_reasons,
        EvidenceDependency::Environment,
        &recorded.environment,
        &current.environment,
    );
    compare_dependency(
        &mut dependency_reasons,
        EvidenceDependency::Policy,
        &recorded.policy,
        &current.policy,
    );

    match (&recorded.base_task, &current.base_task) {
        (BaseTaskDependency::Unknown, _) | (_, BaseTaskDependency::Unknown) => {
            push_unknown(&mut dependency_reasons, EvidenceDependency::BaseTask);
        }
        (recorded, current) => push_changed(
            &mut dependency_reasons,
            EvidenceDependency::BaseTask,
            recorded != current,
        ),
    }

    compare_dependency(
        &mut dependency_reasons,
        EvidenceDependency::ForgeBehavior,
        &recorded.forge_behavior,
        &current.forge_behavior,
    );

    let mut applicability_reasons = Vec::new();
    let applicability = match receipt.mutability {
        Mutability::ReadOnly => scope_preserving_applicability(
            &receipt.scope_before,
            &recorded.scope,
            &mut applicability_reasons,
            ApplicabilityReason::ReadOnlyScopeChangedDuringRun,
        ),
        Mutability::ExternalSideEffect => scope_preserving_applicability(
            &receipt.scope_before,
            &recorded.scope,
            &mut applicability_reasons,
            ApplicabilityReason::ExternalSideEffectScopeChangedDuringRun,
        ),
        Mutability::WorkingTreeWrite => {
            applicability_reasons
                .push(ApplicabilityReason::WorkingTreeWriteRequiresReadOnlyFollowUp);
            ReceiptApplicability::NonProving
        }
        Mutability::Unknown => {
            applicability_reasons.push(ApplicabilityReason::MutabilityUnknown);
            ReceiptApplicability::Unknown
        }
    };

    let has_changed_dependency = dependency_reasons
        .iter()
        .any(|reason| matches!(reason, DependencyReason::Changed(_)));
    let has_unknown_dependency = dependency_reasons
        .iter()
        .any(|reason| matches!(reason, DependencyReason::Unknown(_)));
    let dependency_validity = if has_changed_dependency {
        DependencyValidity::Stale
    } else if has_unknown_dependency {
        DependencyValidity::Unknown
    } else {
        DependencyValidity::Current
    };

    ReceiptValidity {
        dependency_validity,
        applicability,
        outcome: receipt.outcome,
        dependency_reasons,
        applicability_reasons,
    }
}

fn push_changed(
    dependency_reasons: &mut Vec<DependencyReason>,
    dependency: EvidenceDependency,
    changed: bool,
) {
    if changed {
        dependency_reasons.push(DependencyReason::Changed(dependency));
    }
}

fn scope_preserving_applicability(
    scope_before: &DependencyValue<Digest>,
    scope_after: &DependencyValue<Digest>,
    applicability_reasons: &mut Vec<ApplicabilityReason>,
    changed_reason: ApplicabilityReason,
) -> ReceiptApplicability {
    match (scope_before, scope_after) {
        (DependencyValue::Known(before), DependencyValue::Known(after)) if before == after => {
            ReceiptApplicability::Eligible
        }
        (DependencyValue::Known(_), DependencyValue::Known(_)) => {
            applicability_reasons.push(changed_reason);
            ReceiptApplicability::NonProving
        }
        (DependencyValue::Unknown, _) | (_, DependencyValue::Unknown) => {
            ReceiptApplicability::Unknown
        }
    }
}

fn compare_dependency<T: PartialEq>(
    dependency_reasons: &mut Vec<DependencyReason>,
    dependency: EvidenceDependency,
    recorded: &DependencyValue<T>,
    current: &DependencyValue<T>,
) {
    match (recorded, current) {
        (DependencyValue::Known(recorded), DependencyValue::Known(current)) => {
            push_changed(dependency_reasons, dependency, recorded != current);
        }
        (DependencyValue::Unknown, _) | (_, DependencyValue::Unknown) => {
            push_unknown(dependency_reasons, dependency);
        }
    }
}

fn push_unknown(dependency_reasons: &mut Vec<DependencyReason>, dependency: EvidenceDependency) {
    let reason = DependencyReason::Unknown(dependency);
    if !dependency_reasons.contains(&reason) {
        dependency_reasons.push(reason);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use super::{
        ApplicabilityReason, BaseTaskDependency, CommandEvidenceObservation, DependencyReason,
        DependencyValidity, DependencyValue, EvidenceDependency, EvidenceDependencyFingerprint,
        EvidenceOutcome, ExecutionDependencyFingerprint, JsonErrorStatus, LocalEvidenceState,
        ProcessOutcomeInput, ReceiptApplicability, ReceiptValidity, ReceiptValidityInput,
        aggregate_command_evidence, evaluate_local_evidence, evaluate_receipt_validity,
        normalize_evidence_outcome,
    };
    use crate::domain::CommandEnforcement;
    use crate::ports::{ProcessErrorKind, ProcessObservation};
    use crate::{CoverageDimension, Intent, Mutability, SuccessPredicate};
    use forge_schema::{Digest, RepoId};

    type FingerprintMutation = fn(&mut EvidenceDependencyFingerprint);

    fn digest(value: &str) -> Digest {
        Digest::from(value)
    }

    fn known_digest(value: &str) -> DependencyValue<Digest> {
        DependencyValue::Known(digest(value))
    }

    fn known_repository(value: &str) -> DependencyValue<RepoId> {
        DependencyValue::Known(RepoId::from(value))
    }

    fn fingerprint() -> EvidenceDependencyFingerprint {
        EvidenceDependencyFingerprint::new(
            known_repository("repo:one"),
            known_digest("scope:one"),
            ExecutionDependencyFingerprint::new(
                known_digest("command:one"),
                known_digest("toolchain:one"),
                known_digest("environment:one"),
            ),
            known_digest("policy:one"),
            BaseTaskDependency::Known(digest("base-task:one")),
            known_digest("forge-behavior:one"),
        )
    }

    fn receipt(
        dependencies: EvidenceDependencyFingerprint,
        mutability: Mutability,
        outcome: EvidenceOutcome,
    ) -> ReceiptValidityInput {
        let scope_before = dependencies.scope.clone();
        ReceiptValidityInput::new(dependencies, scope_before, mutability, outcome)
    }

    fn validity(outcome: EvidenceOutcome, mutability: Mutability) -> ReceiptValidity {
        let current = fingerprint();
        evaluate_receipt_validity(&receipt(current.clone(), mutability, outcome), &current)
    }

    fn process_observation(exit_code: Option<i32>, stdout_total_bytes: u64) -> ProcessObservation {
        ProcessObservation {
            exit_code,
            signal: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdout_digest: digest("stdout"),
            stderr_digest: digest("stderr"),
            stdout_total_bytes,
            stderr_total_bytes: 0,
            stdout_truncated: stdout_total_bytes > 0,
            stderr_truncated: false,
            duration: Duration::from_millis(1),
            timed_out: false,
            interrupted: false,
        }
    }

    #[test]
    fn exit_and_stdout_predicates_use_complete_process_facts() {
        let success = process_observation(Some(0), 0);
        let failed = process_observation(Some(2), 0);
        let nonempty_but_not_retained = process_observation(Some(0), 12);

        assert_eq!(
            normalize_evidence_outcome(
                &SuccessPredicate::ExitZero,
                ProcessOutcomeInput::observation(&success, None),
            ),
            EvidenceOutcome::Pass
        );
        assert_eq!(
            normalize_evidence_outcome(
                &SuccessPredicate::ExitZero,
                ProcessOutcomeInput::observation(&failed, None),
            ),
            EvidenceOutcome::ProductFailure
        );
        assert_eq!(
            normalize_evidence_outcome(
                &SuccessPredicate::ExitZeroAndStdoutEmpty,
                ProcessOutcomeInput::observation(&success, None),
            ),
            EvidenceOutcome::Pass
        );
        assert_eq!(
            normalize_evidence_outcome(
                &SuccessPredicate::ExitZeroAndStdoutEmpty,
                ProcessOutcomeInput::observation(&nonempty_but_not_retained, None),
            ),
            EvidenceOutcome::ProductFailure
        );
    }

    #[test]
    fn json_predicate_consumes_only_the_callers_typed_parse_result() {
        let observation = process_observation(Some(0), 17);
        for (status, expected) in [
            (Some(JsonErrorStatus::NoErrors), EvidenceOutcome::Pass),
            (
                Some(JsonErrorStatus::HasErrors),
                EvidenceOutcome::ProductFailure,
            ),
            (
                Some(JsonErrorStatus::Invalid),
                EvidenceOutcome::ProductFailure,
            ),
            (None, EvidenceOutcome::Unknown),
        ] {
            assert_eq!(
                normalize_evidence_outcome(
                    &SuccessPredicate::JsonHasNoErrors,
                    ProcessOutcomeInput::observation(&observation, status),
                ),
                expected
            );
        }
    }

    #[test]
    fn all_is_recursive_order_independent_and_never_vacuously_passes() {
        let observation = process_observation(Some(0), 0);
        let nested = SuccessPredicate::All(vec![
            SuccessPredicate::ExitZero,
            SuccessPredicate::All(vec![
                SuccessPredicate::ExitZeroAndStdoutEmpty,
                SuccessPredicate::JsonHasNoErrors,
            ]),
        ]);
        assert_eq!(
            normalize_evidence_outcome(
                &nested,
                ProcessOutcomeInput::observation(&observation, Some(JsonErrorStatus::NoErrors),),
            ),
            EvidenceOutcome::Pass
        );

        let failed_and_unknown = SuccessPredicate::All(vec![
            SuccessPredicate::JsonHasNoErrors,
            SuccessPredicate::ExitZeroAndStdoutEmpty,
        ]);
        let nonempty = process_observation(Some(0), 1);
        assert_eq!(
            normalize_evidence_outcome(
                &failed_and_unknown,
                ProcessOutcomeInput::observation(&nonempty, None),
            ),
            EvidenceOutcome::ProductFailure
        );
        assert_eq!(
            normalize_evidence_outcome(
                &SuccessPredicate::All(Vec::new()),
                ProcessOutcomeInput::observation(&observation, None),
            ),
            EvidenceOutcome::ProductFailure
        );
    }

    #[test]
    fn execution_boundary_states_take_precedence_and_fail_closed() {
        let mut observation = process_observation(Some(0), 0);
        observation.timed_out = true;
        assert_eq!(
            normalize_evidence_outcome(
                &SuccessPredicate::ExitZero,
                ProcessOutcomeInput::observation(&observation, None),
            ),
            EvidenceOutcome::TimedOut
        );

        observation.timed_out = false;
        observation.interrupted = true;
        assert_eq!(
            normalize_evidence_outcome(
                &SuccessPredicate::ExitZero,
                ProcessOutcomeInput::observation(&observation, None),
            ),
            EvidenceOutcome::Interrupted
        );

        observation.timed_out = true;
        assert_eq!(
            normalize_evidence_outcome(
                &SuccessPredicate::ExitZero,
                ProcessOutcomeInput::observation(&observation, None),
            ),
            EvidenceOutcome::Unknown
        );

        for kind in [ProcessErrorKind::Spawn, ProcessErrorKind::Output] {
            assert_eq!(
                normalize_evidence_outcome(
                    &SuccessPredicate::ExitZero,
                    ProcessOutcomeInput::infrastructure_failure(kind),
                ),
                EvidenceOutcome::InfrastructureFailure
            );
        }
    }

    #[test]
    fn abnormal_or_incomplete_termination_never_passes() {
        let mut signalled = process_observation(None, 0);
        signalled.signal = Some(9);
        assert_eq!(
            normalize_evidence_outcome(
                &SuccessPredicate::ExitZero,
                ProcessOutcomeInput::observation(&signalled, None),
            ),
            EvidenceOutcome::ProductFailure
        );

        let incomplete = process_observation(None, 0);
        assert_eq!(
            normalize_evidence_outcome(
                &SuccessPredicate::ExitZero,
                ProcessOutcomeInput::observation(&incomplete, None),
            ),
            EvidenceOutcome::Inconclusive
        );

        let mut contradictory = process_observation(Some(0), 0);
        contradictory.signal = Some(9);
        assert_eq!(
            normalize_evidence_outcome(
                &SuccessPredicate::ExitZero,
                ProcessOutcomeInput::observation(&contradictory, None),
            ),
            EvidenceOutcome::Unknown
        );

        let mut impossible_output = process_observation(Some(0), 0);
        impossible_output.stdout_truncated = true;
        assert_eq!(
            normalize_evidence_outcome(
                &SuccessPredicate::ExitZeroAndStdoutEmpty,
                ProcessOutcomeInput::observation(&impossible_output, None),
            ),
            EvidenceOutcome::Unknown
        );
    }

    fn unknown_cases() -> [(EvidenceDependency, FingerprintMutation); 8] {
        [
            (EvidenceDependency::Repository, |fingerprint| {
                fingerprint.repository = DependencyValue::Unknown;
            }),
            (EvidenceDependency::Scope, |fingerprint| {
                fingerprint.scope = DependencyValue::Unknown;
            }),
            (EvidenceDependency::Command, |fingerprint| {
                fingerprint.command = DependencyValue::Unknown;
            }),
            (EvidenceDependency::Toolchain, |fingerprint| {
                fingerprint.toolchain = DependencyValue::Unknown;
            }),
            (EvidenceDependency::Environment, |fingerprint| {
                fingerprint.environment = DependencyValue::Unknown;
            }),
            (EvidenceDependency::Policy, |fingerprint| {
                fingerprint.policy = DependencyValue::Unknown;
            }),
            (EvidenceDependency::BaseTask, |fingerprint| {
                fingerprint.base_task = BaseTaskDependency::Unknown;
            }),
            (EvidenceDependency::ForgeBehavior, |fingerprint| {
                fingerprint.forge_behavior = DependencyValue::Unknown;
            }),
        ]
    }

    #[test]
    fn every_dependency_mutation_makes_the_receipt_stale() {
        let cases: [(EvidenceDependency, FingerprintMutation); 8] = [
            (EvidenceDependency::Repository, |fingerprint| {
                fingerprint.repository = known_repository("repo:two");
            }),
            (EvidenceDependency::Scope, |fingerprint| {
                fingerprint.scope = known_digest("scope:two");
            }),
            (EvidenceDependency::Command, |fingerprint| {
                fingerprint.command = known_digest("command:two");
            }),
            (EvidenceDependency::Toolchain, |fingerprint| {
                fingerprint.toolchain = known_digest("toolchain:two");
            }),
            (EvidenceDependency::Environment, |fingerprint| {
                fingerprint.environment = known_digest("environment:two");
            }),
            (EvidenceDependency::Policy, |fingerprint| {
                fingerprint.policy = known_digest("policy:two");
            }),
            (EvidenceDependency::BaseTask, |fingerprint| {
                fingerprint.base_task = BaseTaskDependency::Known(digest("base-task:two"));
            }),
            (EvidenceDependency::ForgeBehavior, |fingerprint| {
                fingerprint.forge_behavior = known_digest("forge-behavior:two");
            }),
        ];

        for (dependency, mutate) in cases {
            let recorded = fingerprint();
            let receipt = receipt(
                recorded.clone(),
                Mutability::ReadOnly,
                EvidenceOutcome::Pass,
            );
            let mut current = recorded;
            mutate(&mut current);

            let validity = evaluate_receipt_validity(&receipt, &current);

            assert_eq!(
                validity.dependency_validity(),
                DependencyValidity::Stale,
                "{} mutation",
                dependency.as_str()
            );
            assert_eq!(
                validity.dependency_reasons(),
                &[DependencyReason::Changed(dependency)],
                "{} mutation",
                dependency.as_str()
            );
            assert!(validity.applicability_reasons().is_empty());
            assert!(!validity.is_current_passing_local_observation());
        }
    }

    #[test]
    fn every_unknown_dependency_on_either_side_is_non_passing() {
        for recorded_is_unknown in [true, false] {
            for (dependency, make_unknown) in unknown_cases() {
                let mut recorded = fingerprint();
                let mut current = recorded.clone();
                if recorded_is_unknown {
                    make_unknown(&mut recorded);
                } else {
                    make_unknown(&mut current);
                }
                let receipt = receipt(recorded, Mutability::ReadOnly, EvidenceOutcome::Pass);

                let validity = evaluate_receipt_validity(&receipt, &current);

                assert_eq!(
                    validity.dependency_validity(),
                    DependencyValidity::Unknown,
                    "{} unknown on {} side",
                    dependency.as_str(),
                    if recorded_is_unknown {
                        "recorded"
                    } else {
                        "current"
                    }
                );
                assert_eq!(
                    validity.dependency_reasons(),
                    &[DependencyReason::Unknown(dependency)],
                    "{} unknown",
                    dependency.as_str()
                );
                assert!(!validity.is_current_passing_local_observation());
            }
        }
    }

    #[test]
    fn comparison_preserves_all_unknown_dependency_reasons() {
        let recorded = fingerprint();
        let receipt = receipt(
            recorded.clone(),
            Mutability::ReadOnly,
            EvidenceOutcome::Pass,
        );
        let mut current = recorded;
        for (_, make_unknown) in unknown_cases() {
            make_unknown(&mut current);
        }

        let validity = evaluate_receipt_validity(&receipt, &current);

        assert_eq!(validity.dependency_validity(), DependencyValidity::Unknown);
        assert_eq!(
            validity.dependency_reasons(),
            &[
                DependencyReason::Unknown(EvidenceDependency::Repository),
                DependencyReason::Unknown(EvidenceDependency::Scope),
                DependencyReason::Unknown(EvidenceDependency::Command),
                DependencyReason::Unknown(EvidenceDependency::Toolchain),
                DependencyReason::Unknown(EvidenceDependency::Environment),
                DependencyReason::Unknown(EvidenceDependency::Policy),
                DependencyReason::Unknown(EvidenceDependency::BaseTask),
                DependencyReason::Unknown(EvidenceDependency::ForgeBehavior),
            ]
        );
        assert!(!validity.is_current_passing_local_observation());
    }

    #[test]
    fn unknown_read_only_before_scope_is_non_passing() {
        let current = fingerprint();
        let mut receipt = receipt(current.clone(), Mutability::ReadOnly, EvidenceOutcome::Pass);
        receipt.scope_before = DependencyValue::Unknown;

        let validity = evaluate_receipt_validity(&receipt, &current);

        assert_eq!(validity.dependency_validity(), DependencyValidity::Unknown);
        assert_eq!(validity.applicability(), ReceiptApplicability::Unknown);
        assert_eq!(
            validity.dependency_reasons(),
            &[DependencyReason::Unknown(EvidenceDependency::Scope)]
        );
        assert!(validity.applicability_reasons().is_empty());
        assert!(!validity.is_current_passing_local_observation());
    }

    #[test]
    fn changed_and_unknown_reasons_are_both_retained_in_dependency_order() {
        let recorded = fingerprint();
        let mut receipt = receipt(
            recorded.clone(),
            Mutability::ReadOnly,
            EvidenceOutcome::Pass,
        );
        receipt.scope_before = DependencyValue::Unknown;
        let mut current = recorded;
        current.repository = known_repository("repo:two");
        current.command = DependencyValue::Unknown;
        current.policy = DependencyValue::Unknown;

        let validity = evaluate_receipt_validity(&receipt, &current);

        assert_eq!(validity.dependency_validity(), DependencyValidity::Stale);
        assert_eq!(validity.applicability(), ReceiptApplicability::Unknown);
        assert_eq!(
            validity.dependency_reasons(),
            &[
                DependencyReason::Changed(EvidenceDependency::Repository),
                DependencyReason::Unknown(EvidenceDependency::Scope),
                DependencyReason::Unknown(EvidenceDependency::Command),
                DependencyReason::Unknown(EvidenceDependency::Policy),
            ]
        );
        assert!(validity.applicability_reasons().is_empty());
        assert!(!validity.is_current_passing_local_observation());
    }

    #[test]
    fn comparison_preserves_every_detected_reason_in_stable_order() {
        let recorded = fingerprint();
        let mut receipt = receipt(
            recorded.clone(),
            Mutability::ReadOnly,
            EvidenceOutcome::Pass,
        );
        receipt.scope_before = known_digest("scope:before");
        let current = EvidenceDependencyFingerprint {
            repository: known_repository("repo:two"),
            scope: known_digest("scope:two"),
            command: known_digest("command:two"),
            toolchain: known_digest("toolchain:two"),
            environment: known_digest("environment:two"),
            policy: known_digest("policy:two"),
            base_task: BaseTaskDependency::Known(digest("base-task:two")),
            forge_behavior: known_digest("forge-behavior:two"),
        };

        let validity = evaluate_receipt_validity(&receipt, &current);

        assert_eq!(
            validity.dependency_reasons(),
            &[
                DependencyReason::Changed(EvidenceDependency::Repository),
                DependencyReason::Changed(EvidenceDependency::Scope),
                DependencyReason::Changed(EvidenceDependency::Command),
                DependencyReason::Changed(EvidenceDependency::Toolchain),
                DependencyReason::Changed(EvidenceDependency::Environment),
                DependencyReason::Changed(EvidenceDependency::Policy),
                DependencyReason::Changed(EvidenceDependency::BaseTask),
                DependencyReason::Changed(EvidenceDependency::ForgeBehavior),
            ]
        );
        assert_eq!(
            validity.applicability_reasons(),
            &[ApplicabilityReason::ReadOnlyScopeChangedDuringRun]
        );
    }

    #[test]
    fn known_and_not_applicable_base_task_states_are_not_interchangeable() {
        let recorded = fingerprint();
        let mut current = recorded.clone();
        current.base_task = BaseTaskDependency::NotApplicable;
        let receipt = receipt(recorded, Mutability::ReadOnly, EvidenceOutcome::Pass);

        let validity = evaluate_receipt_validity(&receipt, &current);

        assert_eq!(
            validity.dependency_reasons(),
            &[DependencyReason::Changed(EvidenceDependency::BaseTask)]
        );
        assert!(validity.applicability_reasons().is_empty());
        assert_eq!(validity.dependency_validity(), DependencyValidity::Stale);
    }

    #[test]
    fn equal_not_applicable_base_task_states_can_pass() {
        let mut current = fingerprint();
        current.base_task = BaseTaskDependency::NotApplicable;
        let receipt = receipt(current.clone(), Mutability::ReadOnly, EvidenceOutcome::Pass);

        let validity = evaluate_receipt_validity(&receipt, &current);

        assert_eq!(validity.dependency_validity(), DependencyValidity::Current);
        assert!(validity.dependency_reasons().is_empty());
        assert!(validity.applicability_reasons().is_empty());
        assert!(validity.is_current_passing_local_observation());
    }

    #[test]
    fn stale_failure_remains_a_failure_without_becoming_current() {
        let recorded = fingerprint();
        let mut current = recorded.clone();
        current.command = known_digest("command:two");
        let receipt = receipt(
            recorded,
            Mutability::ReadOnly,
            EvidenceOutcome::ProductFailure,
        );

        let validity = evaluate_receipt_validity(&receipt, &current);

        assert_eq!(validity.dependency_validity(), DependencyValidity::Stale);
        assert_eq!(validity.outcome(), EvidenceOutcome::ProductFailure);
        assert!(!validity.is_current_passing_local_observation());
    }

    #[test]
    fn current_failure_is_not_misclassified_as_stale() {
        let current = fingerprint();
        let receipt = receipt(
            current.clone(),
            Mutability::ReadOnly,
            EvidenceOutcome::ProductFailure,
        );

        let validity = evaluate_receipt_validity(&receipt, &current);

        assert_eq!(validity.dependency_validity(), DependencyValidity::Current);
        assert_eq!(validity.outcome(), EvidenceOutcome::ProductFailure);
        assert!(validity.dependency_reasons().is_empty());
        assert!(validity.applicability_reasons().is_empty());
        assert!(!validity.is_current_passing_local_observation());
    }

    #[test]
    fn unknown_outcome_never_passes_with_current_dependencies() {
        let current = fingerprint();
        let receipt = receipt(
            current.clone(),
            Mutability::ReadOnly,
            EvidenceOutcome::Unknown,
        );

        let validity = evaluate_receipt_validity(&receipt, &current);

        assert_eq!(validity.dependency_validity(), DependencyValidity::Current);
        assert_eq!(validity.outcome(), EvidenceOutcome::Unknown);
        assert!(!validity.is_current_passing_local_observation());
    }

    #[test]
    fn read_only_receipt_requires_before_after_and_current_scope_to_match() {
        struct Case {
            name: &'static str,
            before: &'static str,
            after: &'static str,
            current: &'static str,
            dependency_validity: DependencyValidity,
            applicability: ReceiptApplicability,
            dependency_reasons: &'static [DependencyReason],
            applicability_reasons: &'static [ApplicabilityReason],
            is_current_passing: bool,
        }

        let cases = [
            Case {
                name: "all equal",
                before: "scope:one",
                after: "scope:one",
                current: "scope:one",
                dependency_validity: DependencyValidity::Current,
                applicability: ReceiptApplicability::Eligible,
                dependency_reasons: &[],
                applicability_reasons: &[],
                is_current_passing: true,
            },
            Case {
                name: "changed during run",
                before: "scope:before",
                after: "scope:one",
                current: "scope:one",
                dependency_validity: DependencyValidity::Current,
                applicability: ReceiptApplicability::NonProving,
                dependency_reasons: &[],
                applicability_reasons: &[ApplicabilityReason::ReadOnlyScopeChangedDuringRun],
                is_current_passing: false,
            },
            Case {
                name: "changed after run",
                before: "scope:one",
                after: "scope:one",
                current: "scope:current",
                dependency_validity: DependencyValidity::Stale,
                applicability: ReceiptApplicability::Eligible,
                dependency_reasons: &[DependencyReason::Changed(EvidenceDependency::Scope)],
                applicability_reasons: &[],
                is_current_passing: false,
            },
            Case {
                name: "after differs from both before and current",
                before: "scope:before",
                after: "scope:after",
                current: "scope:current",
                dependency_validity: DependencyValidity::Stale,
                applicability: ReceiptApplicability::NonProving,
                dependency_reasons: &[DependencyReason::Changed(EvidenceDependency::Scope)],
                applicability_reasons: &[ApplicabilityReason::ReadOnlyScopeChangedDuringRun],
                is_current_passing: false,
            },
        ];

        for case in cases {
            let mut recorded = fingerprint();
            recorded.scope = known_digest(case.after);
            let mut current = recorded.clone();
            current.scope = known_digest(case.current);
            let receipt = ReceiptValidityInput {
                dependencies: recorded,
                scope_before: known_digest(case.before),
                mutability: Mutability::ReadOnly,
                outcome: EvidenceOutcome::Pass,
            };

            let validity = evaluate_receipt_validity(&receipt, &current);

            assert_eq!(
                validity.dependency_validity(),
                case.dependency_validity,
                "{}",
                case.name
            );
            assert_eq!(
                validity.applicability(),
                case.applicability,
                "{}",
                case.name
            );
            assert_eq!(
                validity.dependency_reasons(),
                case.dependency_reasons,
                "{}",
                case.name
            );
            assert_eq!(
                validity.applicability_reasons(),
                case.applicability_reasons,
                "{}",
                case.name
            );
            assert_eq!(
                validity.is_current_passing_local_observation(),
                case.is_current_passing,
                "{}",
                case.name
            );
        }
    }

    #[test]
    fn working_tree_write_receipt_does_not_directly_prove_the_after_state() {
        let current = fingerprint();
        let receipt = receipt(
            current.clone(),
            Mutability::WorkingTreeWrite,
            EvidenceOutcome::Pass,
        );

        let validity = evaluate_receipt_validity(&receipt, &current);

        assert_eq!(validity.dependency_validity(), DependencyValidity::Current);
        assert_eq!(validity.applicability(), ReceiptApplicability::NonProving);
        assert!(validity.dependency_reasons().is_empty());
        assert_eq!(
            validity.applicability_reasons(),
            &[ApplicabilityReason::WorkingTreeWriteRequiresReadOnlyFollowUp]
        );
        assert!(!validity.is_current_passing_local_observation());
    }

    #[test]
    fn external_side_effect_with_stable_scope_can_satisfy_local_evidence() {
        let current = fingerprint();
        let receipt = receipt(
            current.clone(),
            Mutability::ExternalSideEffect,
            EvidenceOutcome::Pass,
        );

        let validity = evaluate_receipt_validity(&receipt, &current);

        assert_eq!(validity.dependency_validity(), DependencyValidity::Current);
        assert_eq!(validity.applicability(), ReceiptApplicability::Eligible);
        assert!(validity.dependency_reasons().is_empty());
        assert!(validity.applicability_reasons().is_empty());
        assert!(validity.is_current_passing_local_observation());
    }

    #[test]
    fn external_side_effect_with_changed_scope_is_non_proving() {
        let current = fingerprint();
        let mut receipt = receipt(
            current.clone(),
            Mutability::ExternalSideEffect,
            EvidenceOutcome::Pass,
        );
        receipt.scope_before = known_digest("scope:before");

        let validity = evaluate_receipt_validity(&receipt, &current);

        assert_eq!(validity.dependency_validity(), DependencyValidity::Current);
        assert_eq!(validity.applicability(), ReceiptApplicability::NonProving);
        assert!(validity.dependency_reasons().is_empty());
        assert_eq!(
            validity.applicability_reasons(),
            &[ApplicabilityReason::ExternalSideEffectScopeChangedDuringRun]
        );
        assert!(!validity.is_current_passing_local_observation());
    }

    #[test]
    fn unknown_mutability_never_passes() {
        let current = fingerprint();
        let receipt = receipt(current.clone(), Mutability::Unknown, EvidenceOutcome::Pass);

        let validity = evaluate_receipt_validity(&receipt, &current);

        assert_eq!(validity.dependency_validity(), DependencyValidity::Current);
        assert_eq!(validity.applicability(), ReceiptApplicability::Unknown);
        assert!(validity.dependency_reasons().is_empty());
        assert_eq!(
            validity.applicability_reasons(),
            &[ApplicabilityReason::MutabilityUnknown]
        );
        assert!(!validity.is_current_passing_local_observation());
    }

    #[test]
    fn advisory_failure_stays_visible_without_failing_required_receipt() {
        let aggregation = aggregate_command_evidence(&[
            CommandEvidenceObservation::new(
                CommandEnforcement::Required,
                EvidenceOutcome::Pass,
                [CoverageDimension::Compile],
            ),
            CommandEvidenceObservation::new(
                CommandEnforcement::Advisory,
                EvidenceOutcome::ProductFailure,
                [CoverageDimension::Lint],
            ),
        ]);

        assert_eq!(aggregation.outcome(), EvidenceOutcome::Pass);
        assert_eq!(
            aggregation.verified(),
            &[CoverageDimension::Compile].into_iter().collect()
        );
        assert!(aggregation.advisory().is_empty());
        assert_eq!(
            aggregation.not_verified(),
            &[CoverageDimension::Lint].into_iter().collect()
        );
    }

    #[test]
    fn passing_advisory_coverage_is_separate_from_verified_coverage() {
        let aggregation = aggregate_command_evidence(&[
            CommandEvidenceObservation::new(
                CommandEnforcement::Required,
                EvidenceOutcome::Pass,
                [CoverageDimension::Compile],
            ),
            CommandEvidenceObservation::new(
                CommandEnforcement::Advisory,
                EvidenceOutcome::Pass,
                [CoverageDimension::Lint],
            ),
        ]);

        assert_eq!(aggregation.outcome(), EvidenceOutcome::Pass);
        assert_eq!(
            aggregation.advisory(),
            &[CoverageDimension::Lint].into_iter().collect()
        );
        assert!(aggregation.not_verified().is_empty());
    }

    #[test]
    fn advisory_only_and_post_failure_sequences_fail_closed() {
        let advisory_only = aggregate_command_evidence(&[CommandEvidenceObservation::new(
            CommandEnforcement::Advisory,
            EvidenceOutcome::Pass,
            [CoverageDimension::Lint],
        )]);
        let post_failure = aggregate_command_evidence(&[
            CommandEvidenceObservation::new(
                CommandEnforcement::Required,
                EvidenceOutcome::ProductFailure,
                [CoverageDimension::Compile],
            ),
            CommandEvidenceObservation::new(
                CommandEnforcement::Required,
                EvidenceOutcome::Pass,
                [CoverageDimension::UnitTest],
            ),
        ]);

        assert_eq!(advisory_only.outcome(), EvidenceOutcome::Unknown);
        assert_eq!(post_failure.outcome(), EvidenceOutcome::Unknown);
    }

    #[test]
    fn local_sufficiency_never_consumes_external_requirements() {
        let receipts = BTreeMap::from([(
            Intent::Check,
            validity(EvidenceOutcome::Pass, Mutability::ReadOnly),
        )]);

        let evaluation = evaluate_local_evidence(
            true,
            [String::from("check"), String::from("protected-ci")],
            [String::from("protected-ci")],
            &receipts,
        );

        assert_eq!(evaluation.state(), LocalEvidenceState::Sufficient);
        assert_eq!(evaluation.satisfied(), ["check"]);
        assert!(evaluation.not_verified().is_empty());
        assert_eq!(evaluation.external_required(), ["protected-ci"]);
    }

    #[test]
    fn current_product_failure_beats_missing_requirements() {
        let receipts = BTreeMap::from([(
            Intent::Check,
            validity(EvidenceOutcome::ProductFailure, Mutability::ReadOnly),
        )]);

        let evaluation = evaluate_local_evidence(
            true,
            [String::from("check"), String::from("test")],
            Vec::new(),
            &receipts,
        );

        assert_eq!(evaluation.state(), LocalEvidenceState::Failing);
        assert_eq!(evaluation.not_verified(), ["check", "test"]);
    }

    #[test]
    fn incomplete_risk_or_inconclusive_current_receipt_is_unknown() {
        let receipts = BTreeMap::from([(
            Intent::Check,
            validity(EvidenceOutcome::Inconclusive, Mutability::ReadOnly),
        )]);
        let incomplete = evaluate_local_evidence(false, Vec::new(), Vec::new(), &BTreeMap::new());
        let inconclusive =
            evaluate_local_evidence(true, [String::from("check")], Vec::new(), &receipts);

        assert_eq!(incomplete.state(), LocalEvidenceState::Unknown);
        assert_eq!(incomplete.not_verified(), ["risk-classification"]);
        assert_eq!(inconclusive.state(), LocalEvidenceState::Unknown);
        assert_eq!(inconclusive.not_verified(), ["check"]);
    }

    #[test]
    fn passing_receipt_applicability_distinguishes_unknown_from_non_proving() {
        let unknown = BTreeMap::from([(
            Intent::Check,
            validity(EvidenceOutcome::Pass, Mutability::Unknown),
        )]);
        let non_proving = BTreeMap::from([(
            Intent::Check,
            validity(EvidenceOutcome::Pass, Mutability::WorkingTreeWrite),
        )]);

        let unknown = evaluate_local_evidence(true, [String::from("check")], Vec::new(), &unknown);
        let non_proving =
            evaluate_local_evidence(true, [String::from("check")], Vec::new(), &non_proving);

        assert_eq!(unknown.state(), LocalEvidenceState::Unknown);
        assert_eq!(unknown.not_verified(), ["check"]);
        assert_eq!(non_proving.state(), LocalEvidenceState::Insufficient);
        assert_eq!(non_proving.not_verified(), ["check"]);
    }

    #[test]
    fn custom_local_requirement_remains_an_explicit_gap() {
        let evaluation = evaluate_local_evidence(
            true,
            [String::from("real-database-integration")],
            Vec::new(),
            &BTreeMap::new(),
        );

        assert_eq!(evaluation.state(), LocalEvidenceState::Insufficient);
        assert_eq!(evaluation.not_verified(), ["real-database-integration"]);
    }

    #[test]
    fn reason_codes_are_stable_per_axis() {
        let changed = DependencyReason::Changed(EvidenceDependency::Policy);
        let unknown = DependencyReason::Unknown(EvidenceDependency::BaseTask);

        assert_eq!(changed.code(), "dependency-changed");
        assert_eq!(changed.dependency(), EvidenceDependency::Policy);
        assert_eq!(unknown.code(), "dependency-unknown");
        assert_eq!(unknown.dependency(), EvidenceDependency::BaseTask);
        assert_eq!(
            ApplicabilityReason::ExternalSideEffectScopeChangedDuringRun.code(),
            "external-side-effect-scope-changed-during-run"
        );
        assert_eq!(
            ApplicabilityReason::WorkingTreeWriteRequiresReadOnlyFollowUp.code(),
            "working-tree-write-requires-read-only-follow-up"
        );
    }
}
