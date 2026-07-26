//! Deterministic, I/O-free reduction of current repository observations to one next action.

use std::collections::BTreeSet;

use thiserror::Error;

use crate::domain::{CommandResolution, CommandSpec, Intent, Provenance, ResolvedCommandSet};

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

/// M5's explicit seam for M6 Receipt evaluation.
///
/// `Unavailable` is the normal M5 input. Insufficient or corrupt observations take the first
/// navigation priority; no M6 verification state is inferred here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptObservation {
    Unavailable { provenance: Vec<Provenance> },
    Insufficient(NavigationIssue),
    Corrupt(NavigationIssue),
}

impl ReceiptObservation {
    pub fn unavailable(provenance: Vec<Provenance>) -> Result<Self, NavigationError> {
        Ok(Self::Unavailable {
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
    pub check_commands: Option<ResolvedCommandSet>,
}

/// M5 navigation states. Receipt-backed states are intentionally deferred to M6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NavigationState {
    Unknown,
    Blocked,
    AdaptersDrifted,
    Idle,
    ChangedUnverified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NavigationAction {
    RunDoctor,
    ResolveBlocker,
    StopAndEscalate,
    SyncAdapters,
    None,
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
    #[error("resolved check command `{command_id}` declares intent {actual:?}, expected Check")]
    CheckCommandIntentMismatch { command_id: String, actual: Intent },
    #[error("resolved check intent has no executable project command")]
    ResolvedCheckWithoutCommands,
}

/// Applies the accepted first-match priority table without performing I/O.
pub fn reduce_next(input: NavigationInput) -> Result<NavigationDecision, NavigationError> {
    let NavigationInput {
        integrity,
        blockers,
        adapters,
        changes,
        receipts,
        check_commands,
    } = input;

    if let NavigationInputIntegrity::Insufficient(issue)
    | NavigationInputIntegrity::Corrupt(issue) = integrity
    {
        return Ok(issue_decision(issue));
    }
    let receipt_provenance = match receipts {
        ReceiptObservation::Unavailable { provenance } => provenance,
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

    let Some(check_commands) = check_commands else {
        let mut provenance = changes.provenance;
        provenance.extend(receipt_provenance);
        canonicalize_provenance(&mut provenance);
        return Ok(decision(
            NavigationState::Unknown,
            NavigationAction::RunDoctor,
            None,
            Vec::new(),
            "changes exist, but the check command was not observed".to_owned(),
            provenance,
            Vec::new(),
        ));
    };
    if check_commands.resolution() != CommandResolution::Resolved {
        let mut provenance = changes.provenance;
        provenance.extend(check_commands.provenance.iter().cloned());
        provenance.extend(receipt_provenance);
        canonicalize_provenance(&mut provenance);
        return Ok(decision(
            NavigationState::Unknown,
            NavigationAction::RunDoctor,
            None,
            Vec::new(),
            "changes exist, but the check intent is not resolved to an executable project command"
                .to_owned(),
            provenance,
            Vec::new(),
        ));
    }
    let commands = check_commands
        .executable_commands()
        .ok_or(NavigationError::ResolvedCheckWithoutCommands)?
        .to_vec();
    for command in &commands {
        if command.intent != Intent::Check {
            return Err(NavigationError::CheckCommandIntentMismatch {
                command_id: command.id.as_str().to_owned(),
                actual: command.intent,
            });
        }
    }
    let command_provenance =
        validate_provenance("resolved check command", check_commands.provenance.clone())?;
    let mut provenance = changes.provenance;
    provenance.extend(command_provenance);
    provenance.extend(receipt_provenance);
    canonicalize_provenance(&mut provenance);
    Ok(decision(
        NavigationState::ChangedUnverified,
        NavigationAction::RunIntent,
        Some(Intent::Check),
        commands,
        "changes exist and M5 has no valid check Receipt for the current scope".to_owned(),
        provenance,
        Vec::new(),
    ))
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
    use std::error::Error;

    use forge_schema::CommandId;

    use crate::RepoRelativePath;
    use crate::domain::{
        CommandSource, CommandSpec, Confidence, Intent, Provenance, ResolvedCommandSet,
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
        Ok(ReceiptObservation::unavailable(vec![provenance(
            "receipts.m5-unavailable",
        )])?)
    }

    fn check_commands() -> TestResult<ResolvedCommandSet> {
        let mut command = CommandSpec::new(
            "check",
            Intent::Check,
            "cargo",
            RepoRelativePath::root(),
            CommandSource::LanguageDefault {
                provider: "rust".to_owned(),
                rule: "cargo-check".to_owned(),
            },
        )
        .with_args(["check", "--workspace"]);
        command.confidence = Confidence::High;
        Ok(ResolvedCommandSet::resolved(
            vec![command],
            vec![provenance("provider.rust.check")],
            Confidence::High,
            Confidence::High,
        )?)
    }

    fn input(has_changes: bool) -> TestResult<NavigationInput> {
        Ok(NavigationInput {
            integrity: NavigationInputIntegrity::Complete,
            blockers: Vec::new(),
            adapters: adapter(AdapterObservationStatus::Current)?,
            changes: changes(has_changes)?,
            receipts: receipts()?,
            check_commands: Some(check_commands()?),
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
    fn first_match_priority_is_strict_for_all_m5_states() -> TestResult {
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
        missing.check_commands = None;
        let missing = decision(missing)?;
        assert_eq!(missing.state(), NavigationState::Unknown);
        assert_eq!(missing.action(), NavigationAction::RunDoctor);
        assert!(missing.project_commands().is_empty());

        let mut unresolved = input(true)?;
        unresolved.check_commands = Some(ResolvedCommandSet::unknown(
            Vec::new(),
            vec![provenance("commands.unknown")],
        ));
        let unresolved = decision(unresolved)?;
        assert_eq!(unresolved.state(), NavigationState::Unknown);
        assert_eq!(unresolved.intent(), None);
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
