//! Deterministic receipt-validity rules.
//!
//! This module compares already-computed facts. It deliberately owns no hashing, filesystem,
//! process, clock, network, persistence, or wire-format behavior.
//!
//! Construction is intentionally unavailable outside this module until M6 provides one
//! authoritative builder for canonical dependency digests and receipt execution facts.

use forge_schema::{Digest, RepoId};

use crate::Mutability;

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
/// not a reusable dependency value. A future authoritative builder must establish that context;
/// this evaluator only compares the supplied typed facts.
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

/// The receipt facts needed by the pure validity evaluator.
///
/// Fields remain private until one authoritative builder owns after-scope and `NotApplicable`
/// semantics. The evaluator does not infer either from ambient context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptValidityInput {
    dependencies: EvidenceDependencyFingerprint,
    scope_before: DependencyValue<Digest>,
    mutability: Mutability,
    outcome: EvidenceOutcome,
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
    use super::{
        ApplicabilityReason, BaseTaskDependency, DependencyReason, DependencyValidity,
        DependencyValue, EvidenceDependency, EvidenceDependencyFingerprint, EvidenceOutcome,
        ReceiptApplicability, ReceiptValidityInput, evaluate_receipt_validity,
    };
    use crate::Mutability;
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
        EvidenceDependencyFingerprint {
            repository: known_repository("repo:one"),
            scope: known_digest("scope:one"),
            command: known_digest("command:one"),
            toolchain: known_digest("toolchain:one"),
            environment: known_digest("environment:one"),
            policy: known_digest("policy:one"),
            base_task: BaseTaskDependency::Known(digest("base-task:one")),
            forge_behavior: known_digest("forge-behavior:one"),
        }
    }

    fn receipt(
        dependencies: EvidenceDependencyFingerprint,
        mutability: Mutability,
        outcome: EvidenceOutcome,
    ) -> ReceiptValidityInput {
        ReceiptValidityInput {
            scope_before: dependencies.scope.clone(),
            dependencies,
            mutability,
            outcome,
        }
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
