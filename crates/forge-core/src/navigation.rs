//! Deterministic, I/O-free reduction of current repository observations to one next action.

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

use crate::domain::{CommandResolution, CommandSpec, Intent, Provenance, ResolvedCommandSet};
use crate::evidence::{
    DependencyValidity, EvidenceOutcome, LocalEvidenceState, ReceiptValidity,
    evaluate_local_evidence,
};

/// Whether the inputs needed for a trustworthy navigation decision were observed completely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NavigationInputIntegrity {
    Complete,
    Insufficient(NavigationIssue),
    Corrupt(NavigationIssue),
}

/// A sourced reason that current state cannot be interpreted as complete or valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NavigationIssue {
    reason: String,
    provenance: Vec<Provenance>,
}

impl NavigationIssue {
    pub fn new(
        reason: impl Into<String>,
        provenance: Vec<Provenance>,
    ) -> Result<Self, NavigationError> {
        let reason = reason.into();
        validate_nonempty("navigation issue reason", &reason)?;
        let provenance = validate_provenance("navigation issue", provenance)?;
        Ok(Self { reason, provenance })
    }

    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    #[must_use]
    pub fn provenance(&self) -> &[Provenance] {
        &self.provenance
    }
}

/// A blocker category. Protected actions sort first because they require escalation, not repair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NavigationBlockerKind {
    ProtectedAction,
    GitOperation,
    Environment,
}

/// One sourced blocker retained in the decision for diagnosis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NavigationBlocker {
    kind: NavigationBlockerKind,
    id: String,
    reason: String,
    provenance: Vec<Provenance>,
}

impl NavigationBlocker {
    pub fn new(
        kind: NavigationBlockerKind,
        id: impl Into<String>,
        reason: impl Into<String>,
        provenance: Vec<Provenance>,
    ) -> Result<Self, NavigationError> {
        let id = id.into();
        let reason = reason.into();
        validate_nonempty("navigation blocker id", &id)?;
        validate_nonempty("navigation blocker reason", &reason)?;
        let provenance = validate_provenance("navigation blocker", provenance)?;
        Ok(Self {
            kind,
            id,
            reason,
            provenance,
        })
    }

    #[must_use]
    pub const fn kind(&self) -> NavigationBlockerKind {
        self.kind
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    #[must_use]
    pub fn provenance(&self) -> &[Provenance] {
        &self.provenance
    }
}

/// Whether host adapters affect the current task and, if so, whether they are current.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterObservationStatus {
    NotRequired,
    Current,
    Drifted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterObservation {
    status: AdapterObservationStatus,
    provenance: Vec<Provenance>,
}

impl AdapterObservation {
    pub fn new(
        status: AdapterObservationStatus,
        provenance: Vec<Provenance>,
    ) -> Result<Self, NavigationError> {
        Ok(Self {
            status,
            provenance: validate_provenance("adapter observation", provenance)?,
        })
    }

    #[must_use]
    pub const fn status(&self) -> AdapterObservationStatus {
        self.status
    }

    #[must_use]
    pub fn provenance(&self) -> &[Provenance] {
        &self.provenance
    }
}

/// Whether Git reports changes relevant to the current navigation scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeObservation {
    has_changes: bool,
    provenance: Vec<Provenance>,
}

impl ChangeObservation {
    pub fn new(has_changes: bool, provenance: Vec<Provenance>) -> Result<Self, NavigationError> {
        Ok(Self {
            has_changes,
            provenance: validate_provenance("change observation", provenance)?,
        })
    }

    #[must_use]
    pub const fn has_changes(&self) -> bool {
        self.has_changes
    }

    #[must_use]
    pub fn provenance(&self) -> &[Provenance] {
        &self.provenance
    }
}

/// Current Receipt facts retained by the caller's read-only state evaluation.
///
/// The reducer consumes the newest dependency-current Receipt for each intent. Historical or stale
/// Receipts must not be projected into this map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptObservation {
    Unavailable {
        provenance: Vec<Provenance>,
    },
    Current {
        requirements_complete: bool,
        evidence_requirements: BTreeSet<String>,
        external_requirements: BTreeSet<String>,
        newest_current: BTreeMap<Intent, ReceiptValidity>,
        provenance: Vec<Provenance>,
    },
    Insufficient(NavigationIssue),
    Corrupt(NavigationIssue),
}

impl ReceiptObservation {
    pub fn unavailable(provenance: Vec<Provenance>) -> Result<Self, NavigationError> {
        Ok(Self::Unavailable {
            provenance: validate_provenance("receipt observation", provenance)?,
        })
    }

    pub fn current(
        requirements_complete: bool,
        evidence_requirements: impl IntoIterator<Item = String>,
        external_requirements: impl IntoIterator<Item = String>,
        newest_current: BTreeMap<Intent, ReceiptValidity>,
        provenance: Vec<Provenance>,
    ) -> Result<Self, NavigationError> {
        Ok(Self::Current {
            requirements_complete,
            evidence_requirements: evidence_requirements.into_iter().collect(),
            external_requirements: external_requirements.into_iter().collect(),
            newest_current,
            provenance: validate_provenance("receipt observation", provenance)?,
        })
    }
}

/// Complete observed inputs. The reducer does not acquire or repair any of these facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NavigationInput {
    pub integrity: NavigationInputIntegrity,
    pub blockers: Vec<NavigationBlocker>,
    pub adapters: AdapterObservation,
    pub changes: ChangeObservation,
    pub receipts: ReceiptObservation,
    pub commands: BTreeMap<Intent, ResolvedCommandSet>,
}

/// Deterministic navigation states, including current Receipt-backed verification states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NavigationState {
    Unknown,
    Blocked,
    AdaptersDrifted,
    Idle,
    ChecksFailing,
    ChangedUnverified,
    PartiallyVerified,
    LocalVerified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NavigationAction {
    RunDoctor,
    ResolveBlocker,
    StopAndEscalate,
    SyncAdapters,
    None,
    FixFailures,
    RunIntent,
}

/// One deterministic primary action with the facts required to explain or execute it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NavigationDecision {
    state: NavigationState,
    action: NavigationAction,
    intent: Option<Intent>,
    project_commands: Vec<CommandSpec>,
    reason: String,
    provenance: Vec<Provenance>,
    blockers: Vec<NavigationBlocker>,
}

struct ResolvedNavigationCommands {
    commands: Vec<CommandSpec>,
    provenance: Vec<Provenance>,
}

impl NavigationDecision {
    #[must_use]
    pub const fn state(&self) -> NavigationState {
        self.state
    }

    #[must_use]
    pub const fn action(&self) -> NavigationAction {
        self.action
    }

    #[must_use]
    pub const fn intent(&self) -> Option<Intent> {
        self.intent
    }

    #[must_use]
    pub fn project_commands(&self) -> &[CommandSpec] {
        &self.project_commands
    }

    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    #[must_use]
    pub fn provenance(&self) -> &[Provenance] {
        &self.provenance
    }

    #[must_use]
    pub fn blockers(&self) -> &[NavigationBlocker] {
        &self.blockers
    }
}

/// Invalid sourced input that would make a deterministic decision misleading.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NavigationError {
    #[error("{field} is empty")]
    EmptyText { field: &'static str },
    #[error("{location} has no provenance")]
    EmptyProvenance { location: &'static str },
    #[error("{location} contains an empty provenance rule id")]
    EmptyProvenanceRuleId { location: &'static str },
    #[error("{location} contains empty provenance detail")]
    EmptyProvenanceDetail { location: &'static str },
    #[error("{location} contains a provenance range without a source path")]
    ProvenanceRangeWithoutPath { location: &'static str },
    #[error("navigation blocker id `{id}` occurs more than once")]
    DuplicateBlocker { id: String },
    #[error("resolved command `{command_id}` declares intent {actual:?}, expected {expected:?}")]
    CommandIntentMismatch {
        command_id: String,
        expected: Intent,
        actual: Intent,
    },
    #[error("resolved {intent:?} intent has no executable project command")]
    ResolvedIntentWithoutCommands { intent: Intent },
    #[error("local Evidence is failing without a current required product-failure Receipt")]
    FailingWithoutProductFailure,
}

/// Applies the accepted first-match priority table without performing I/O.
pub fn reduce_next(input: NavigationInput) -> Result<NavigationDecision, NavigationError> {
    let NavigationInput {
        integrity,
        blockers,
        adapters,
        changes,
        receipts,
        commands,
    } = input;

    if let NavigationInputIntegrity::Insufficient(issue)
    | NavigationInputIntegrity::Corrupt(issue) = integrity
    {
        return Ok(issue_decision(issue));
    }
    let (
        requirements_complete,
        mut evidence_requirements,
        external_requirements,
        newest_current,
        receipt_provenance,
    ) = match receipts {
        ReceiptObservation::Unavailable { provenance } => (
            true,
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeMap::new(),
            provenance,
        ),
        ReceiptObservation::Current {
            requirements_complete,
            evidence_requirements,
            external_requirements,
            newest_current,
            provenance,
        } => (
            requirements_complete,
            evidence_requirements,
            external_requirements,
            newest_current,
            provenance,
        ),
        ReceiptObservation::Insufficient(issue) | ReceiptObservation::Corrupt(issue) => {
            return Ok(issue_decision(issue));
        }
    };

    let blockers = canonical_blockers(blockers)?;
    if let Some(primary) = blockers.first() {
        let action = if primary.kind == NavigationBlockerKind::ProtectedAction {
            NavigationAction::StopAndEscalate
        } else {
            NavigationAction::ResolveBlocker
        };
        let mut provenance = blockers
            .iter()
            .flat_map(|blocker| blocker.provenance.iter().cloned())
            .collect();
        canonicalize_provenance(&mut provenance);
        return Ok(decision(
            NavigationState::Blocked,
            action,
            None,
            Vec::new(),
            format!("{}: {}", primary.id, primary.reason),
            provenance,
            blockers,
        ));
    }

    if adapters.status == AdapterObservationStatus::Drifted {
        return Ok(decision(
            NavigationState::AdaptersDrifted,
            NavigationAction::SyncAdapters,
            None,
            Vec::new(),
            "managed adapters required by the current task are drifted".to_owned(),
            adapters.provenance,
            Vec::new(),
        ));
    }

    if !changes.has_changes {
        return Ok(decision(
            NavigationState::Idle,
            NavigationAction::None,
            None,
            Vec::new(),
            "no worktree or branch changes require navigation".to_owned(),
            changes.provenance,
            Vec::new(),
        ));
    }

    // A current passing check Receipt is the baseline for every changed scope, independently of
    // the risk-specific requirements layered on top of it.
    evidence_requirements.insert(String::from("check"));
    let local = evaluate_local_evidence(
        requirements_complete,
        evidence_requirements.iter().cloned(),
        external_requirements.iter().cloned(),
        &newest_current,
    );
    let required_intents = required_local_intents(&evidence_requirements, &external_requirements);
    let check_observation = newest_current.get(&Intent::Check);

    // A missing check is actionable even when risk classification is incomplete: every changed
    // scope requires that baseline, so running it cannot understate any additional requirement.
    // An inconclusive current check remains unknown rather than being silently replaced.
    if local.state() == LocalEvidenceState::Unknown && check_observation.is_some() {
        let mut provenance = changes.provenance;
        provenance.extend(receipt_provenance);
        canonicalize_provenance(&mut provenance);
        return Ok(decision(
            NavigationState::Unknown,
            NavigationAction::RunDoctor,
            None,
            Vec::new(),
            "current Receipt sufficiency is unknown; inspect the Evidence diagnostics".to_owned(),
            provenance,
            Vec::new(),
        ));
    }

    if local.state() == LocalEvidenceState::Failing {
        let failed_intent = required_intents
            .iter()
            .copied()
            .find(|intent| {
                newest_current.get(intent).is_some_and(|validity| {
                    validity.dependency_validity() == DependencyValidity::Current
                        && validity.outcome() == EvidenceOutcome::ProductFailure
                })
            })
            .ok_or(NavigationError::FailingWithoutProductFailure)?;
        let Some(resolved) = resolved_commands_for(failed_intent, &commands)? else {
            return Ok(missing_command_decision(
                failed_intent,
                changes.provenance,
                receipt_provenance,
                commands.get(&failed_intent),
            ));
        };
        let mut provenance = changes.provenance;
        provenance.extend(receipt_provenance);
        provenance.extend(resolved.provenance);
        canonicalize_provenance(&mut provenance);
        return Ok(decision(
            NavigationState::ChecksFailing,
            NavigationAction::FixFailures,
            Some(failed_intent),
            resolved.commands,
            format!(
                "the newest current {} Receipt records a project failure",
                intent_name(failed_intent)
            ),
            provenance,
            Vec::new(),
        ));
    }

    if local.state() == LocalEvidenceState::Sufficient {
        let mut provenance = changes.provenance;
        provenance.extend(receipt_provenance);
        canonicalize_provenance(&mut provenance);
        return Ok(decision(
            NavigationState::LocalVerified,
            NavigationAction::None,
            None,
            Vec::new(),
            "all required local Receipt observations are current and passing".to_owned(),
            provenance,
            Vec::new(),
        ));
    }

    let check_is_current =
        check_observation.is_some_and(ReceiptValidity::is_current_passing_local_observation);
    let missing_intent = if check_is_current {
        required_intents.iter().copied().find(|intent| {
            !newest_current
                .get(intent)
                .is_some_and(ReceiptValidity::is_current_passing_local_observation)
        })
    } else {
        Some(Intent::Check)
    };
    let Some(missing_intent) = missing_intent else {
        let mut provenance = changes.provenance;
        provenance.extend(receipt_provenance);
        canonicalize_provenance(&mut provenance);
        return Ok(decision(
            NavigationState::Unknown,
            NavigationAction::RunDoctor,
            None,
            Vec::new(),
            format!(
                "local Evidence is missing unsupported requirements: {}",
                local.not_verified().join(", ")
            ),
            provenance,
            Vec::new(),
        ));
    };
    let Some(resolved) = resolved_commands_for(missing_intent, &commands)? else {
        return Ok(missing_command_decision(
            missing_intent,
            changes.provenance,
            receipt_provenance,
            commands.get(&missing_intent),
        ));
    };
    let mut provenance = changes.provenance;
    provenance.extend(receipt_provenance);
    provenance.extend(resolved.provenance);
    canonicalize_provenance(&mut provenance);
    let (state, reason) = if missing_intent == Intent::Check {
        (
            NavigationState::ChangedUnverified,
            String::from("changes exist and no current passing check Receipt covers the scope"),
        )
    } else {
        (
            NavigationState::PartiallyVerified,
            format!(
                "check is current, but required {} Evidence is not current and passing",
                intent_name(missing_intent)
            ),
        )
    };
    Ok(decision(
        state,
        NavigationAction::RunIntent,
        Some(missing_intent),
        resolved.commands,
        reason,
        provenance,
        Vec::new(),
    ))
}

fn required_local_intents(
    evidence_requirements: &BTreeSet<String>,
    external_requirements: &BTreeSet<String>,
) -> Vec<Intent> {
    evidence_requirements
        .difference(external_requirements)
        .filter_map(|requirement| intent_from_requirement(requirement))
        .collect()
}

fn intent_from_requirement(requirement: &str) -> Option<Intent> {
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

fn resolved_commands_for(
    intent: Intent,
    command_sets: &BTreeMap<Intent, ResolvedCommandSet>,
) -> Result<Option<ResolvedNavigationCommands>, NavigationError> {
    let Some(command_set) = command_sets.get(&intent) else {
        return Ok(None);
    };
    if command_set.resolution() != CommandResolution::Resolved {
        return Ok(None);
    }
    let commands = command_set
        .executable_commands()
        .ok_or(NavigationError::ResolvedIntentWithoutCommands { intent })?
        .to_vec();
    for command in &commands {
        if command.intent != intent {
            return Err(NavigationError::CommandIntentMismatch {
                command_id: command.id.as_str().to_owned(),
                expected: intent,
                actual: command.intent,
            });
        }
    }
    let provenance = validate_provenance(
        "resolved navigation command",
        command_set.provenance.clone(),
    )?;
    Ok(Some(ResolvedNavigationCommands {
        commands,
        provenance,
    }))
}

fn missing_command_decision(
    intent: Intent,
    mut change_provenance: Vec<Provenance>,
    receipt_provenance: Vec<Provenance>,
    command_set: Option<&ResolvedCommandSet>,
) -> NavigationDecision {
    if let Some(command_set) = command_set {
        change_provenance.extend(command_set.provenance.iter().cloned());
    }
    change_provenance.extend(receipt_provenance);
    canonicalize_provenance(&mut change_provenance);
    decision(
        NavigationState::Unknown,
        NavigationAction::RunDoctor,
        None,
        Vec::new(),
        format!(
            "required {} Evidence has no resolved executable project command",
            intent_name(intent)
        ),
        change_provenance,
        Vec::new(),
    )
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

fn issue_decision(issue: NavigationIssue) -> NavigationDecision {
    decision(
        NavigationState::Unknown,
        NavigationAction::RunDoctor,
        None,
        Vec::new(),
        issue.reason,
        issue.provenance,
        Vec::new(),
    )
}

fn decision(
    state: NavigationState,
    action: NavigationAction,
    intent: Option<Intent>,
    project_commands: Vec<CommandSpec>,
    reason: String,
    provenance: Vec<Provenance>,
    blockers: Vec<NavigationBlocker>,
) -> NavigationDecision {
    NavigationDecision {
        state,
        action,
        intent,
        project_commands,
        reason,
        provenance,
        blockers,
    }
}

fn canonical_blockers(
    mut blockers: Vec<NavigationBlocker>,
) -> Result<Vec<NavigationBlocker>, NavigationError> {
    blockers.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.id.cmp(&right.id))
            .then_with(|| left.reason.cmp(&right.reason))
            .then_with(|| left.provenance.cmp(&right.provenance))
    });
    let mut ids = BTreeSet::new();
    for blocker in &blockers {
        if !ids.insert(blocker.id.as_str()) {
            return Err(NavigationError::DuplicateBlocker {
                id: blocker.id.clone(),
            });
        }
    }
    Ok(blockers)
}

fn validate_nonempty(field: &'static str, value: &str) -> Result<(), NavigationError> {
    if value.trim().is_empty() {
        Err(NavigationError::EmptyText { field })
    } else {
        Ok(())
    }
}

fn validate_provenance(
    location: &'static str,
    mut provenance: Vec<Provenance>,
) -> Result<Vec<Provenance>, NavigationError> {
    if provenance.is_empty() {
        return Err(NavigationError::EmptyProvenance { location });
    }
    for source in &provenance {
        if source.rule_id.trim().is_empty() {
            return Err(NavigationError::EmptyProvenanceRuleId { location });
        }
        if source.detail.trim().is_empty() {
            return Err(NavigationError::EmptyProvenanceDetail { location });
        }
        if source.source_range.is_some() && source.source_path.is_none() {
            return Err(NavigationError::ProvenanceRangeWithoutPath { location });
        }
    }
    canonicalize_provenance(&mut provenance);
    Ok(provenance)
}

fn canonicalize_provenance(provenance: &mut Vec<Provenance>) {
    provenance.sort();
    provenance.dedup();
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::error::Error;

    use forge_schema::{CommandId, Digest, RepoId};

    use crate::RepoRelativePath;
    use crate::domain::{
        CommandSource, CommandSpec, Confidence, Intent, Mutability, Provenance, ResolvedCommandSet,
    };
    use crate::evidence::{
        BaseTaskDependency, DependencyValue, EvidenceDependencyFingerprint, EvidenceOutcome,
        ExecutionDependencyFingerprint, ReceiptValidity, ReceiptValidityInput,
        evaluate_receipt_validity,
    };

    use super::{
        AdapterObservation, AdapterObservationStatus, ChangeObservation, NavigationAction,
        NavigationBlocker, NavigationBlockerKind, NavigationDecision, NavigationError,
        NavigationInput, NavigationInputIntegrity, NavigationIssue, NavigationState,
        ReceiptObservation, reduce_next,
    };

    fn provenance(id: &str) -> Provenance {
        Provenance {
            rule_id: id.to_owned(),
            source_path: None,
            source_range: None,
            detail: format!("{id} fixture observation"),
        }
    }

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    fn adapter(status: AdapterObservationStatus) -> TestResult<AdapterObservation> {
        Ok(AdapterObservation::new(
            status,
            vec![provenance("adapter.fixture")],
        )?)
    }

    fn changes(has_changes: bool) -> TestResult<ChangeObservation> {
        Ok(ChangeObservation::new(
            has_changes,
            vec![provenance("changes.fixture")],
        )?)
    }

    fn receipts() -> TestResult<ReceiptObservation> {
        Ok(ReceiptObservation::current(
            true,
            Vec::new(),
            Vec::new(),
            BTreeMap::new(),
            vec![provenance("receipts.current-empty")],
        )?)
    }

    fn command_set(intent: Intent) -> TestResult<ResolvedCommandSet> {
        let intent_name = super::intent_name(intent);
        let mut command = CommandSpec::new(
            intent_name,
            intent,
            "cargo",
            RepoRelativePath::root(),
            CommandSource::LanguageDefault {
                provider: "rust".to_owned(),
                rule: format!("cargo-{intent_name}"),
            },
        )
        .with_args([intent_name, "--workspace"]);
        command.confidence = Confidence::High;
        Ok(ResolvedCommandSet::resolved(
            vec![command],
            vec![provenance(&format!("provider.rust.{intent_name}"))],
            Confidence::High,
            Confidence::High,
        )?)
    }

    fn validity_with_scope(
        outcome: EvidenceOutcome,
        recorded_scope: &str,
        current_scope: &str,
    ) -> ReceiptValidity {
        let known = |value: &str| DependencyValue::Known(Digest::from(value));
        let dependencies_for_scope = |scope: &str| {
            EvidenceDependencyFingerprint::new(
                DependencyValue::Known(RepoId::from("repo:fixture")),
                known(scope),
                ExecutionDependencyFingerprint::new(
                    known("command:current"),
                    known("toolchain:current"),
                    known("environment:current"),
                ),
                known("policy:current"),
                BaseTaskDependency::Known(Digest::from("base-task:current")),
                known("forge-behavior:current"),
            )
        };
        let recorded_dependencies = dependencies_for_scope(recorded_scope);
        let current_dependencies = dependencies_for_scope(current_scope);
        let receipt = ReceiptValidityInput::new(
            recorded_dependencies,
            known(recorded_scope),
            Mutability::ReadOnly,
            outcome,
        );
        evaluate_receipt_validity(&receipt, &current_dependencies)
    }

    fn current_validity(outcome: EvidenceOutcome) -> ReceiptValidity {
        validity_with_scope(outcome, "scope:current", "scope:current")
    }

    fn stale_validity(outcome: EvidenceOutcome) -> ReceiptValidity {
        validity_with_scope(outcome, "scope:recorded", "scope:current")
    }

    fn current_receipts(
        requirements: &[&str],
        newest: impl IntoIterator<Item = (Intent, EvidenceOutcome)>,
    ) -> TestResult<ReceiptObservation> {
        Ok(ReceiptObservation::current(
            true,
            requirements.iter().map(|value| (*value).to_owned()),
            Vec::new(),
            newest
                .into_iter()
                .map(|(intent, outcome)| (intent, current_validity(outcome)))
                .collect(),
            vec![provenance("receipts.current")],
        )?)
    }

    fn input(has_changes: bool) -> TestResult<NavigationInput> {
        Ok(NavigationInput {
            integrity: NavigationInputIntegrity::Complete,
            blockers: Vec::new(),
            adapters: adapter(AdapterObservationStatus::Current)?,
            changes: changes(has_changes)?,
            receipts: receipts()?,
            commands: BTreeMap::from([(Intent::Check, command_set(Intent::Check)?)]),
        })
    }

    fn decision(input: NavigationInput) -> TestResult<NavigationDecision> {
        Ok(reduce_next(input)?)
    }

    fn blocker(kind: NavigationBlockerKind, id: &str) -> TestResult<NavigationBlocker> {
        Ok(NavigationBlocker::new(
            kind,
            id,
            format!("{id} blocks progress"),
            vec![provenance(&format!("blocker.{id}"))],
        )?)
    }

    #[test]
    fn first_match_priority_is_strict_before_receipt_backed_states() -> TestResult {
        let issue = NavigationIssue::new(
            "inventory is incomplete",
            vec![provenance("input.incomplete")],
        )?;
        let mut unknown = input(true)?;
        unknown.integrity = NavigationInputIntegrity::Insufficient(issue);
        unknown.blockers = vec![blocker(
            NavigationBlockerKind::ProtectedAction,
            "protected",
        )?];
        unknown.adapters = adapter(AdapterObservationStatus::Drifted)?;

        let mut blocked = input(true)?;
        blocked.blockers = vec![blocker(NavigationBlockerKind::GitOperation, "merge")?];
        blocked.adapters = adapter(AdapterObservationStatus::Drifted)?;

        let mut drifted = input(false)?;
        drifted.adapters = adapter(AdapterObservationStatus::Drifted)?;

        let cases = [
            (
                unknown,
                NavigationState::Unknown,
                NavigationAction::RunDoctor,
            ),
            (
                blocked,
                NavigationState::Blocked,
                NavigationAction::ResolveBlocker,
            ),
            (
                drifted,
                NavigationState::AdaptersDrifted,
                NavigationAction::SyncAdapters,
            ),
            (input(false)?, NavigationState::Idle, NavigationAction::None),
            (
                input(true)?,
                NavigationState::ChangedUnverified,
                NavigationAction::RunIntent,
            ),
        ];
        for (input, state, action) in cases {
            let observed = decision(input)?;
            assert_eq!(observed.state(), state);
            assert_eq!(observed.action(), action);
        }
        Ok(())
    }

    #[test]
    fn corrupt_receipt_observation_has_input_priority() -> TestResult {
        let mut observed = input(true)?;
        observed.receipts = ReceiptObservation::Corrupt(NavigationIssue::new(
            "receipt state is corrupt",
            vec![provenance("receipts.corrupt")],
        )?);
        observed.blockers = vec![blocker(NavigationBlockerKind::Environment, "missing-git")?];
        assert_eq!(decision(observed)?.state(), NavigationState::Unknown);
        Ok(())
    }

    #[test]
    fn protected_blocker_escalates_and_blocker_permutations_are_stable() -> TestResult {
        let blockers = vec![
            blocker(NavigationBlockerKind::Environment, "toolchain")?,
            blocker(NavigationBlockerKind::ProtectedAction, "release")?,
            blocker(NavigationBlockerKind::GitOperation, "rebase")?,
        ];
        let mut forward = input(true)?;
        forward.blockers = blockers.clone();
        let mut reverse = input(true)?;
        reverse.blockers = blockers.into_iter().rev().collect();

        let forward = decision(forward)?;
        let reverse = decision(reverse)?;
        assert_eq!(forward, reverse);
        assert_eq!(forward.action(), NavigationAction::StopAndEscalate);
        assert_eq!(forward.blockers()[0].id(), "release");
        Ok(())
    }

    #[test]
    fn changed_unverified_exposes_real_check_commands_and_provenance() -> TestResult {
        let observed = decision(input(true)?)?;
        assert_eq!(observed.intent(), Some(Intent::Check));
        assert_eq!(observed.project_commands().len(), 1);
        assert_eq!(observed.project_commands()[0].id, CommandId::from("check"));
        assert!(
            observed
                .provenance()
                .iter()
                .any(|source| source.rule_id == "provider.rust.check")
        );
        assert!(!observed.reason().is_empty());
        Ok(())
    }

    #[test]
    fn missing_or_unresolved_check_never_fabricates_run_intent() -> TestResult {
        let mut missing = input(true)?;
        missing.commands.remove(&Intent::Check);
        let missing = decision(missing)?;
        assert_eq!(missing.state(), NavigationState::Unknown);
        assert_eq!(missing.action(), NavigationAction::RunDoctor);
        assert!(missing.project_commands().is_empty());

        let mut unresolved = input(true)?;
        unresolved.commands.insert(
            Intent::Check,
            ResolvedCommandSet::unknown(Vec::new(), vec![provenance("commands.unknown")]),
        );
        let unresolved = decision(unresolved)?;
        assert_eq!(unresolved.state(), NavigationState::Unknown);
        assert_eq!(unresolved.intent(), None);
        Ok(())
    }

    #[test]
    fn current_receipts_drive_all_m6_navigation_states() -> TestResult {
        let mut failing = input(true)?;
        failing.receipts = current_receipts(
            &["check", "test"],
            [(Intent::Check, EvidenceOutcome::ProductFailure)],
        )?;
        let failing = decision(failing)?;
        assert_eq!(failing.state(), NavigationState::ChecksFailing);
        assert_eq!(failing.action(), NavigationAction::FixFailures);
        assert_eq!(failing.intent(), Some(Intent::Check));

        let mut partial = input(true)?;
        partial
            .commands
            .insert(Intent::Test, command_set(Intent::Test)?);
        partial.receipts =
            current_receipts(&["check", "test"], [(Intent::Check, EvidenceOutcome::Pass)])?;
        let partial = decision(partial)?;
        assert_eq!(partial.state(), NavigationState::PartiallyVerified);
        assert_eq!(partial.action(), NavigationAction::RunIntent);
        assert_eq!(partial.intent(), Some(Intent::Test));
        assert_eq!(partial.project_commands()[0].intent, Intent::Test);

        let mut verified = input(true)?;
        verified.receipts = current_receipts(
            &["check", "test"],
            [
                (Intent::Check, EvidenceOutcome::Pass),
                (Intent::Test, EvidenceOutcome::Pass),
            ],
        )?;
        let verified = decision(verified)?;
        assert_eq!(verified.state(), NavigationState::LocalVerified);
        assert_eq!(verified.action(), NavigationAction::None);
        assert!(verified.project_commands().is_empty());
        Ok(())
    }

    #[test]
    fn required_failure_precedes_missing_check_and_missing_intents_are_stable() -> TestResult {
        let mut failing_test = input(true)?;
        failing_test
            .commands
            .insert(Intent::Test, command_set(Intent::Test)?);
        failing_test.receipts =
            current_receipts(&["test"], [(Intent::Test, EvidenceOutcome::ProductFailure)])?;
        let failing_test = decision(failing_test)?;
        assert_eq!(failing_test.state(), NavigationState::ChecksFailing);
        assert_eq!(failing_test.intent(), Some(Intent::Test));

        let mut multiple_missing = input(true)?;
        multiple_missing
            .commands
            .insert(Intent::Test, command_set(Intent::Test)?);
        multiple_missing
            .commands
            .insert(Intent::Verify, command_set(Intent::Verify)?);
        multiple_missing.receipts = current_receipts(
            &["verify", "test", "check"],
            [(Intent::Check, EvidenceOutcome::Pass)],
        )?;
        let multiple_missing = decision(multiple_missing)?;
        assert_eq!(multiple_missing.state(), NavigationState::PartiallyVerified);
        assert_eq!(multiple_missing.intent(), Some(Intent::Test));
        Ok(())
    }

    #[test]
    fn current_failure_is_not_masked_by_an_earlier_stale_failure() -> TestResult {
        let mut observed = input(true)?;
        observed
            .commands
            .insert(Intent::Test, command_set(Intent::Test)?);
        observed.receipts = ReceiptObservation::current(
            true,
            [String::from("check"), String::from("test")],
            Vec::new(),
            BTreeMap::from([
                (
                    Intent::Check,
                    stale_validity(EvidenceOutcome::ProductFailure),
                ),
                (
                    Intent::Test,
                    current_validity(EvidenceOutcome::ProductFailure),
                ),
            ]),
            vec![provenance("receipts.stale-and-current")],
        )?;

        let observed = decision(observed)?;
        assert_eq!(observed.state(), NavigationState::ChecksFailing);
        assert_eq!(observed.action(), NavigationAction::FixFailures);
        assert_eq!(observed.intent(), Some(Intent::Test));
        Ok(())
    }

    #[test]
    fn uncertain_or_unsupported_required_evidence_fails_closed() -> TestResult {
        let mut infrastructure = input(true)?;
        infrastructure.receipts = current_receipts(
            &["check"],
            [(Intent::Check, EvidenceOutcome::InfrastructureFailure)],
        )?;
        let infrastructure = decision(infrastructure)?;
        assert_eq!(infrastructure.state(), NavigationState::Unknown);
        assert_eq!(infrastructure.action(), NavigationAction::RunDoctor);

        let mut unsupported = input(true)?;
        unsupported.receipts = current_receipts(
            &["check", "custom-security-scan"],
            [(Intent::Check, EvidenceOutcome::Pass)],
        )?;
        let unsupported = decision(unsupported)?;
        assert_eq!(unsupported.state(), NavigationState::Unknown);
        assert!(unsupported.reason().contains("custom-security-scan"));
        Ok(())
    }

    #[test]
    fn constructors_reject_unsourced_or_empty_observations() {
        assert!(matches!(
            NavigationIssue::new(" ", vec![provenance("issue")]),
            Err(NavigationError::EmptyText { .. })
        ));
        assert!(matches!(
            ChangeObservation::new(true, Vec::new()),
            Err(NavigationError::EmptyProvenance { .. })
        ));
        assert!(matches!(
            NavigationBlocker::new(
                NavigationBlockerKind::Environment,
                "tool",
                "missing",
                Vec::new(),
            ),
            Err(NavigationError::EmptyProvenance { .. })
        ));
    }

    #[test]
    fn duplicate_blocker_ids_are_rejected_independent_of_input_order() -> TestResult {
        let mut observed = input(true)?;
        observed.blockers = vec![
            blocker(NavigationBlockerKind::Environment, "same")?,
            blocker(NavigationBlockerKind::GitOperation, "same")?,
        ];
        assert!(matches!(
            reduce_next(observed),
            Err(NavigationError::DuplicateBlocker { id }) if id == "same"
        ));
        Ok(())
    }
}
