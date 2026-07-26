//! Read-only composition of risk, context, adapter, Git, and command facts for `forge next`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use forge_core::context::{
    ContextCandidate, ContextSelection, ContextSelectionError, ContextSignal,
    select_default_context_paths,
};
use forge_core::navigation::{
    AdapterObservation as NavigationAdapterObservation, AdapterObservationStatus,
    ChangeObservation, NavigationAction, NavigationBlocker, NavigationBlockerKind,
    NavigationDecision, NavigationError, NavigationInput, NavigationInputIntegrity,
    NavigationIssue, NavigationState, ReceiptObservation, reduce_next,
};
use forge_core::{
    AppError, Assumption, Confidence, ExitCode, Intent, InventoryKind, ProjectModel, Provenance,
    RepoRelativePath, RiskAssessment, RiskLevel, WorkState, assess_risk,
};
use forge_detect::model::{ModelDetectionCompletion, NavigationSnapshot};
use forge_detect::policy::PolicyBaseCompleteness;
use forge_schema::{
    AssumptionData, CommandData, ConfidenceData, ContextPathData, IntentData, NextActionData,
    NextData, NextStateData, RiskAssessmentData, RiskLevelData, WirePath,
};

use crate::args::Cli;
use crate::{adapters, explain};

/// One deterministic navigation result and the envelope metadata derived with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NextOutcome {
    pub(crate) wire: NextData,
    pub(crate) exit_code: ExitCode,
    pub(crate) truncated: bool,
}

/// Computes one next action from a single retained detection snapshot.
pub(crate) fn execute(cli: &Cli, cancellation: Arc<AtomicBool>) -> Result<NextOutcome, AppError> {
    let detected = explain::detect(cli, cancellation)?;
    let adapter_observation = adapters::observe_managed(&detected.model)?;
    let changed_paths = detected.navigation.changed_paths();
    let risk = assess_risk(
        &detected.navigation.effective_policy,
        changed_paths.as_deref().unwrap_or_default(),
    );
    let context = select_default_context_paths(context_candidates(
        &detected.model,
        &detected.navigation,
        changed_paths.as_deref().unwrap_or_default(),
    )?)
    .map_err(map_context_error)?;

    let integrity =
        navigation_integrity(detected.completion, &detected.model, &detected.navigation)?;
    let blockers = navigation_blockers(&detected.model, &risk)?;
    let adapters = navigation_adapter_observation(&adapter_observation)?;
    let changes = ChangeObservation::new(
        changed_paths
            .as_ref()
            .is_some_and(|paths| !paths.is_empty()),
        vec![provenance(
            "navigation.git-status.v1",
            None,
            "the retained porcelain-v2 snapshot supplied exact worktree paths",
        )],
    )
    .map_err(map_navigation_error)?;
    let receipts = ReceiptObservation::unavailable(vec![provenance(
        "navigation.receipts-unavailable.v1",
        None,
        "M5 does not infer Receipt validity before the M6 evidence protocol is available",
    )])
    .map_err(map_navigation_error)?;
    let check_commands = detected.model.commands.get(&Intent::Check).cloned();
    let decision = reduce_next(NavigationInput {
        integrity,
        blockers,
        adapters,
        changes,
        receipts,
        check_commands,
    })
    .map_err(map_navigation_error)?;

    let wire = project_next(
        &detected,
        &decision,
        &risk,
        &context,
        changed_paths.is_some(),
    )?;
    Ok(NextOutcome {
        exit_code: completion_or(detected.completion, navigation_exit_code(decision.state())),
        wire,
        truncated: context.truncated,
    })
}

fn navigation_integrity(
    completion: ModelDetectionCompletion,
    model: &ProjectModel,
    navigation: &NavigationSnapshot,
) -> Result<NavigationInputIntegrity, AppError> {
    let issue = match model.repository.work_state {
        WorkState::Corrupt => Some((
            true,
            "Git operation markers or repository status are corrupt",
            "navigation.git-corrupt.v1",
        )),
        WorkState::Unknown => Some((
            false,
            "Git operation or worktree state could not be classified",
            "navigation.git-state-unknown.v1",
        )),
        _ if navigation.status.is_none() => Some((
            false,
            "the retained Git status snapshot is unavailable",
            "navigation.git-status-unavailable.v1",
        )),
        _ if completion != ModelDetectionCompletion::Complete => Some((
            false,
            "project detection completed with bounded missing facts",
            "navigation.project-model-partial.v1",
        )),
        _ if navigation.policy_base_completeness == PolicyBaseCompleteness::Unknown => Some((
            false,
            "an approved branch comparison and custom-policy base are unavailable for this committed repository",
            "navigation.approved-base-unknown.v1",
        )),
        _ => None,
    };
    let Some((corrupt, reason, rule_id)) = issue else {
        return Ok(NavigationInputIntegrity::Complete);
    };
    let issue = NavigationIssue::new(
        reason,
        vec![provenance(
            rule_id,
            None,
            "the accepted v0 design does not define a safe fallback for this missing fact",
        )],
    )
    .map_err(map_navigation_error)?;
    Ok(if corrupt {
        NavigationInputIntegrity::Corrupt(issue)
    } else {
        NavigationInputIntegrity::Insufficient(issue)
    })
}

fn navigation_blockers(
    model: &ProjectModel,
    risk: &RiskAssessment,
) -> Result<Vec<NavigationBlocker>, AppError> {
    let mut blockers = Vec::new();
    let git_blocker = match model.repository.work_state {
        WorkState::Conflicted => Some((
            "git/conflicted",
            "resolve index conflicts before verification",
        )),
        WorkState::Merging => Some((
            "git/merging",
            "finish or abort the merge before verification",
        )),
        WorkState::Rebasing => Some((
            "git/rebasing",
            "finish or abort the rebase before verification",
        )),
        WorkState::Clean
        | WorkState::Dirty
        | WorkState::Unborn
        | WorkState::Corrupt
        | WorkState::Unknown => None,
    };
    if let Some((id, reason)) = git_blocker {
        blockers.push(
            NavigationBlocker::new(
                NavigationBlockerKind::GitOperation,
                id,
                reason,
                vec![provenance(
                    "navigation.git-operation.v1",
                    None,
                    "repository operation markers determine the current Git work state",
                )],
            )
            .map_err(map_navigation_error)?,
        );
    }

    for requirement in &risk.external_requirements {
        let mut sources = risk.provenance.clone();
        if sources.is_empty() {
            sources.push(provenance(
                "navigation.external-requirement.v1",
                None,
                "effective risk policy requires external authority",
            ));
        }
        blockers.push(
            NavigationBlocker::new(
                NavigationBlockerKind::ProtectedAction,
                format!("external/{requirement}"),
                format!("external requirement `{requirement}` is not locally satisfiable"),
                sources,
            )
            .map_err(map_navigation_error)?,
        );
    }
    Ok(blockers)
}

fn navigation_adapter_observation(
    observation: &adapters::AdapterObservation,
) -> Result<NavigationAdapterObservation, AppError> {
    let status = if !observation.managed {
        AdapterObservationStatus::NotRequired
    } else if observation.changed {
        AdapterObservationStatus::Drifted
    } else {
        AdapterObservationStatus::Current
    };
    let mut sources = observation
        .statuses
        .iter()
        .map(|adapter| {
            provenance(
                "navigation.managed-adapter.v1",
                Some(adapter.path.clone()),
                "adapter state was classified against the private adoption manifest",
            )
        })
        .collect::<Vec<_>>();
    if sources.is_empty() {
        sources.push(provenance(
            "navigation.managed-adapter.v1",
            None,
            "no private adoption manifest requires a host adapter",
        ));
    }
    NavigationAdapterObservation::new(status, sources).map_err(map_navigation_error)
}

fn context_candidates(
    model: &ProjectModel,
    navigation: &NavigationSnapshot,
    changed_paths: &[RepoRelativePath],
) -> Result<Vec<ContextCandidate>, AppError> {
    let mut candidates = Vec::new();
    for path in changed_paths {
        candidates.push(context_candidate(
            ContextSignal::ExactChange,
            path.clone(),
            "exact path from the retained Git status snapshot",
            vec![provenance(
                "context.exact-change.v1",
                Some(WirePath::from_path(path.as_path())),
                "Git porcelain-v2 reported this path as changed",
            )],
            Confidence::High,
        )?);
    }

    let affected_units = model
        .units
        .iter()
        .filter(|unit| {
            changed_paths
                .iter()
                .any(|path| path_is_within(path, &unit.root))
        })
        .map(|unit| unit.id.clone())
        .collect::<BTreeSet<_>>();
    let units_by_id = model
        .units
        .iter()
        .map(|unit| (unit.id.as_str(), unit))
        .collect::<BTreeMap<_, _>>();

    for unit in model
        .units
        .iter()
        .filter(|unit| affected_units.contains(&unit.id))
    {
        candidates.push(context_candidate(
            ContextSignal::UnitManifest,
            unit.manifest.clone(),
            format!("manifest for affected project unit `{}`", unit.display_name),
            unit.provenance.clone(),
            unit.confidence,
        )?);
        for edge in &unit.dependencies {
            if let Some(dependency) = units_by_id.get(edge.dependency.as_str()) {
                candidates.push(context_candidate(
                    ContextSignal::KnownDependency,
                    dependency.manifest.clone(),
                    format!("manifest for dependency of `{}`", unit.display_name),
                    edge.provenance.clone(),
                    edge.confidence,
                )?);
            }
        }
    }
    for unit in &model.units {
        for edge in &unit.dependencies {
            if affected_units.contains(&edge.dependency) {
                candidates.push(context_candidate(
                    ContextSignal::KnownDependency,
                    unit.manifest.clone(),
                    format!("manifest for reverse dependency `{}`", unit.display_name),
                    edge.provenance.clone(),
                    edge.confidence,
                )?);
            }
        }
    }

    for changed in changed_paths {
        for entry in navigation
            .inventory
            .entries
            .iter()
            .filter(|entry| entry.kind == InventoryKind::File)
        {
            if named_test_for(changed.as_path(), &entry.path) {
                let path = RepoRelativePath::new(&entry.path).map_err(|error| {
                    internal_error(
                        "repository inventory retained an invalid context path",
                        error.to_string(),
                    )
                })?;
                candidates.push(context_candidate(
                    ContextSignal::NamedTest,
                    path.clone(),
                    "same-directory test name corresponds to a changed source path",
                    vec![provenance(
                        "context.named-test.v1",
                        Some(WirePath::from_path(path.as_path())),
                        "bounded inventory metadata matched a supported test naming convention",
                    )],
                    Confidence::Medium,
                )?);
            }
        }
    }

    if !changed_paths.is_empty() {
        for entry in navigation.inventory.entries.iter().filter(|entry| {
            entry.kind == InventoryKind::File
                && matches!(
                    entry.path.to_str(),
                    Some("CODEOWNERS" | ".github/CODEOWNERS" | "docs/CODEOWNERS")
                )
        }) {
            let path = RepoRelativePath::new(&entry.path).map_err(|error| {
                internal_error(
                    "repository inventory retained an invalid ownership path",
                    error.to_string(),
                )
            })?;
            candidates.push(context_candidate(
                ContextSignal::UncertainImpact,
                path.clone(),
                "ownership file exists, but v0 did not parse a matching rule for the changed paths",
                vec![provenance(
                    "context.codeowners-unresolved.v1",
                    Some(WirePath::from_path(path.as_path())),
                    "inventory proves the file exists but not that one of its rules matches",
                )],
                Confidence::Unknown,
            )?);
        }
    }
    Ok(candidates)
}

fn context_candidate(
    signal: ContextSignal,
    path: RepoRelativePath,
    reason: impl Into<String>,
    provenance: Vec<Provenance>,
    confidence: Confidence,
) -> Result<ContextCandidate, AppError> {
    ContextCandidate::new(signal, path, reason, provenance, confidence).map_err(map_context_error)
}

fn path_is_within(path: &RepoRelativePath, root: &RepoRelativePath) -> bool {
    root.as_path() == Path::new(".") || path.as_path().starts_with(root.as_path())
}

fn named_test_for(changed: &Path, candidate: &Path) -> bool {
    if changed == candidate || normalized_parent(changed) != normalized_parent(candidate) {
        return false;
    }
    let Some(stem) = changed.file_stem().and_then(|value| value.to_str()) else {
        return false;
    };
    let Some(name) = candidate.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    name == format!("{stem}_test.go")
        || name == format!("{stem}_test.rs")
        || name == format!("{stem}_tests.rs")
}

fn normalized_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn project_next(
    detected: &explain::DetectedProject,
    decision: &NavigationDecision,
    risk: &RiskAssessment,
    context: &ContextSelection,
    status_available: bool,
) -> Result<NextData, AppError> {
    let project_commands = project_decision_commands(detected, decision)?;
    let mut assumptions = detected.wire.assumptions.clone();
    assumptions.extend(risk.uncertain_assumptions.iter().map(assumption_to_wire));
    assumptions.extend(context.assumptions.iter().map(|path| AssumptionData {
        statement: format!(
            "context impact for `{}` remains uncertain: {}",
            WirePath::from_path(path.path.as_path()).display,
            path.reason
        ),
        provenance: provenance_ids(&path.provenance),
        confidence: confidence_to_wire(path.confidence),
    }));
    if detected.navigation.policy_base_completeness == PolicyBaseCompleteness::Unknown {
        assumptions.push(AssumptionData {
            statement: String::from(
                "the committed repository has no accepted contract for selecting the branch and prior custom-policy base",
            ),
            provenance: vec![String::from("navigation.approved-base-unknown.v1")],
            confidence: ConfidenceData::Unknown,
        });
    }
    canonicalize_assumptions(&mut assumptions);

    let risk_complete = detected.completion == ModelDetectionCompletion::Complete
        && status_available
        && detected.navigation.policy_base_completeness == PolicyBaseCompleteness::Complete
        && !risk_has_unclassified_paths(risk);
    let risk_level = if risk_complete || risk.level == RiskLevel::Critical {
        risk_level_to_wire(risk.level)
    } else {
        RiskLevelData::Unknown
    };

    Ok(NextData {
        state: state_to_wire(decision.state()),
        required_action: action_to_wire(decision.action()),
        intent: decision.intent().map(intent_to_wire),
        project_commands,
        // Advertising an unimplemented evidence command would make the M5 result non-actionable.
        receipt_command: None,
        context_paths: context
            .paths
            .iter()
            .map(|path| ContextPathData {
                path: WirePath::from_path(path.path.as_path()),
                why: path.reason.clone(),
            })
            .collect(),
        risk: RiskAssessmentData {
            level: risk_level,
            matched: risk
                .matched
                .iter()
                .map(|matched| matched.rule_id.clone())
                .collect(),
            provenance: risk_provenance_ids(risk),
        },
        blockers: decision
            .blockers()
            .iter()
            .map(|blocker| format!("{}: {}", blocker.id(), blocker.reason()))
            .collect(),
        reason: decision.reason().to_owned(),
        provenance: provenance_ids(decision.provenance()),
        uncertain_assumptions: assumptions,
    })
}

fn project_decision_commands(
    detected: &explain::DetectedProject,
    decision: &NavigationDecision,
) -> Result<Vec<CommandData>, AppError> {
    if decision.project_commands().is_empty() {
        return Ok(Vec::new());
    }
    let intent = decision.intent().ok_or_else(|| {
        internal_error(
            "navigation returned commands without an intent",
            "the pure reducer violated its action contract",
        )
    })?;
    let key = intent_name(intent);
    let available = detected.wire.commands.get(key).ok_or_else(|| {
        internal_error(
            "navigation command projection is missing",
            format!("project model wire output has no `{key}` command set"),
        )
    })?;
    let by_id = available
        .iter()
        .map(|command| (command.id.as_str(), command))
        .collect::<BTreeMap<_, _>>();
    decision
        .project_commands()
        .iter()
        .map(|command| {
            by_id
                .get(command.id.as_str())
                .cloned()
                .cloned()
                .ok_or_else(|| {
                    internal_error(
                        "navigation command projection diverged from the project model",
                        format!("command `{}` was not retained in wire output", command.id),
                    )
                })
        })
        .collect()
}

fn risk_has_unclassified_paths(risk: &RiskAssessment) -> bool {
    risk.uncertain_assumptions.iter().any(|assumption| {
        assumption.provenance.iter().any(|source| {
            matches!(
                source.rule_id.as_str(),
                "risk/path-non-utf8" | "risk/path-unmatched" | "risk/no-input"
            )
        })
    })
}

fn risk_provenance_ids(risk: &RiskAssessment) -> Vec<String> {
    let mut sources = risk.provenance.clone();
    sources.extend(
        risk.uncertain_assumptions
            .iter()
            .flat_map(|assumption| assumption.provenance.iter().cloned()),
    );
    provenance_ids(&sources)
}

fn assumption_to_wire(assumption: &Assumption) -> AssumptionData {
    AssumptionData {
        statement: assumption.statement.clone(),
        provenance: provenance_ids(&assumption.provenance),
        confidence: confidence_to_wire(assumption.confidence),
    }
}

fn canonicalize_assumptions(assumptions: &mut Vec<AssumptionData>) {
    assumptions.sort_by(|left, right| {
        left.statement
            .cmp(&right.statement)
            .then_with(|| left.provenance.cmp(&right.provenance))
    });
    assumptions.dedup();
}

fn provenance_ids(provenance: &[Provenance]) -> Vec<String> {
    let mut ids = provenance
        .iter()
        .map(|source| source.rule_id.clone())
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    ids
}

fn provenance(rule_id: &str, source_path: Option<WirePath>, detail: &str) -> Provenance {
    Provenance {
        rule_id: rule_id.to_owned(),
        source_path,
        source_range: None,
        detail: detail.to_owned(),
    }
}

const fn state_to_wire(state: NavigationState) -> NextStateData {
    match state {
        NavigationState::Unknown => NextStateData::Unknown,
        NavigationState::Blocked => NextStateData::Blocked,
        NavigationState::AdaptersDrifted => NextStateData::AdaptersDrifted,
        NavigationState::Idle => NextStateData::Idle,
        NavigationState::ChangedUnverified => NextStateData::ChangedUnverified,
    }
}

const fn action_to_wire(action: NavigationAction) -> NextActionData {
    match action {
        NavigationAction::RunDoctor => NextActionData::RunDoctor,
        NavigationAction::ResolveBlocker => NextActionData::ResolveBlocker,
        NavigationAction::StopAndEscalate => NextActionData::StopAndEscalate,
        NavigationAction::SyncAdapters => NextActionData::SyncAdapters,
        NavigationAction::None => NextActionData::None,
        NavigationAction::RunIntent => NextActionData::RunIntent,
    }
}

const fn intent_to_wire(intent: Intent) -> IntentData {
    match intent {
        Intent::Setup => IntentData::Setup,
        Intent::FormatCheck => IntentData::FormatCheck,
        Intent::Format => IntentData::Format,
        Intent::Check => IntentData::Check,
        Intent::Fix => IntentData::Fix,
        Intent::Test => IntentData::Test,
        Intent::Verify => IntentData::Verify,
        Intent::Build => IntentData::Build,
    }
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

const fn confidence_to_wire(confidence: Confidence) -> ConfidenceData {
    match confidence {
        Confidence::Unknown => ConfidenceData::Unknown,
        Confidence::Low => ConfidenceData::Low,
        Confidence::Medium => ConfidenceData::Medium,
        Confidence::High => ConfidenceData::High,
    }
}

const fn risk_level_to_wire(level: RiskLevel) -> RiskLevelData {
    match level {
        RiskLevel::Unknown => RiskLevelData::Unknown,
        RiskLevel::Low => RiskLevelData::Low,
        RiskLevel::Medium => RiskLevelData::Medium,
        RiskLevel::High => RiskLevelData::High,
        RiskLevel::Critical => RiskLevelData::Critical,
    }
}

const fn navigation_exit_code(state: NavigationState) -> ExitCode {
    match state {
        NavigationState::Idle => ExitCode::Ok,
        NavigationState::Blocked => ExitCode::EnvironmentUnmet,
        NavigationState::Unknown
        | NavigationState::AdaptersDrifted
        | NavigationState::ChangedUnverified => ExitCode::Negative,
    }
}

const fn completion_or(completion: ModelDetectionCompletion, requested: ExitCode) -> ExitCode {
    match completion {
        ModelDetectionCompletion::Complete | ModelDetectionCompletion::Partial => requested,
        ModelDetectionCompletion::TimedOut => ExitCode::Timeout,
        ModelDetectionCompletion::Interrupted => ExitCode::Interrupted,
    }
}

fn map_context_error(error: ContextSelectionError) -> AppError {
    internal_error(
        "context selection violated an internal invariant",
        error.to_string(),
    )
}

fn map_navigation_error(error: NavigationError) -> AppError {
    internal_error(
        "navigation reduction violated an internal invariant",
        error.to_string(),
    )
}

fn internal_error(what: impl Into<String>, detail: impl Into<String>) -> AppError {
    AppError::internal(
        "FGE0501",
        what,
        "forge next",
        detail,
        "report this as a Forge implementation defect",
    )
}

/// Renders the same typed result used by JSON output without loading repository bodies.
pub(crate) fn render_human(outcome: &NextOutcome) -> String {
    let data = &outcome.wire;
    let mut output = String::new();
    let _ = writeln!(output, "state: {}", next_state_name(data.state));
    let _ = writeln!(output, "action: {}", next_action_name(data.required_action));
    let _ = writeln!(output, "reason: {}", data.reason);
    let _ = writeln!(output, "risk: {}", risk_level_name(data.risk.level));
    for command in &data.project_commands {
        let _ = writeln!(
            output,
            "command: {:?} {:?} (cwd {})",
            command.program, command.args, command.cwd.display
        );
    }
    for path in &data.context_paths {
        let _ = writeln!(output, "context: {} ({})", path.path.display, path.why);
    }
    for blocker in &data.blockers {
        let _ = writeln!(output, "blocker: {blocker}");
    }
    for assumption in &data.uncertain_assumptions {
        let _ = writeln!(output, "assumption: {}", assumption.statement);
    }
    if outcome.truncated {
        output.push_str("context: truncated by the deterministic byte budget\n");
    }
    output
}

const fn next_state_name(state: NextStateData) -> &'static str {
    match state {
        NextStateData::Blocked => "blocked",
        NextStateData::AdaptersDrifted => "adapters-drifted",
        NextStateData::Idle => "idle",
        NextStateData::ChecksFailing => "checks-failing",
        NextStateData::ChangedUnverified => "changed-unverified",
        NextStateData::PartiallyVerified => "partially-verified",
        NextStateData::LocalVerified => "local-verified",
        NextStateData::Unknown => "unknown",
        _ => "unknown",
    }
}

const fn next_action_name(action: NextActionData) -> &'static str {
    match action {
        NextActionData::RunDoctor => "run-doctor",
        NextActionData::ResolveBlocker => "resolve-blocker",
        NextActionData::StopAndEscalate => "stop-and-escalate",
        NextActionData::SyncAdapters => "sync-adapters",
        NextActionData::None => "none",
        NextActionData::FixFailures => "fix-failures",
        NextActionData::RunIntent => "run-intent",
        NextActionData::CollectEvidence => "collect-evidence",
        NextActionData::Unknown => "unknown",
        _ => "unknown",
    }
}

const fn risk_level_name(level: RiskLevelData) -> &'static str {
    match level {
        RiskLevelData::Low => "low",
        RiskLevelData::Medium => "medium",
        RiskLevelData::High => "high",
        RiskLevelData::Critical => "critical",
        RiskLevelData::Unknown => "unknown",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use forge_core::navigation::NavigationState;
    use forge_core::{ExitCode, RepoRelativePath};

    use super::{named_test_for, navigation_exit_code, path_is_within};

    #[test]
    fn named_tests_require_supported_same_directory_conventions() {
        assert!(named_test_for(
            Path::new("src/parser.go"),
            Path::new("src/parser_test.go")
        ));
        assert!(named_test_for(
            Path::new("src/parser.rs"),
            Path::new("src/parser_tests.rs")
        ));
        assert!(!named_test_for(
            Path::new("src/parser.rs"),
            Path::new("tests/parser_tests.rs")
        ));
        assert!(!named_test_for(
            Path::new("src/parser.rs"),
            Path::new("src/other_tests.rs")
        ));
    }

    #[test]
    fn root_and_nested_units_contain_paths_lexically() -> Result<(), Box<dyn std::error::Error>> {
        let path = RepoRelativePath::new("crates/core/src/lib.rs")?;
        assert!(path_is_within(&path, &RepoRelativePath::root()));
        assert!(path_is_within(
            &path,
            &RepoRelativePath::new("crates/core")?
        ));
        assert!(!path_is_within(
            &path,
            &RepoRelativePath::new("crates/cli")?
        ));
        Ok(())
    }

    #[test]
    fn navigation_exit_codes_distinguish_idle_negative_and_blocked_states() {
        assert_eq!(navigation_exit_code(NavigationState::Idle), ExitCode::Ok);
        assert_eq!(
            navigation_exit_code(NavigationState::ChangedUnverified),
            ExitCode::Negative
        );
        assert_eq!(
            navigation_exit_code(NavigationState::Blocked),
            ExitCode::EnvironmentUnmet
        );
    }
}
