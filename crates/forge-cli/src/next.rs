//! Read-only composition of risk, context, adapter, Git, and command facts for `forge next`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

use forge_core::context::{
    ContextCandidate, ContextSelection, ContextSelectionError, ContextSignal,
    select_default_context_paths,
};
use forge_core::doctor::{DoctorCheckId, DoctorCheckStatus, DoctorSkipReason};
use forge_core::fingerprint::validate_command_privacy;
use forge_core::navigation::{
    AdapterObservation as NavigationAdapterObservation, AdapterObservationStatus,
    ChangeObservation, NavigationAction, NavigationBlocker, NavigationBlockerKind,
    NavigationDecision, NavigationError, NavigationInput, NavigationInputIntegrity,
    NavigationIssue, NavigationState, reduce_next,
};
use forge_core::ports::RepositoryFilePort as _;
use forge_core::{
    AppError, CommandSpec, Confidence, ExitCode, Intent, InventoryKind, OperationControl as _,
    ProjectModel, Provenance, RepoRelativePath, ResolvedCommandSet, RiskAssessment, RiskLevel,
    WorkState, assess_risk, assumption_to_wire, command_detail_v2_to_wire,
    portable_relative_utf8_path,
};
use forge_detect::model::{InventoryCacheStatus, ModelDetectionCompletion, NavigationSnapshot};
use forge_detect::policy::PolicyBaseCompleteness;
use forge_runtime::control::OperationBudget;
use forge_runtime::fs::NativeFileSystem;
use forge_schema::{
    AssumptionData, CommandData, ConfidenceData, ContextPathData, IntentData, NextActionData,
    NextData, NextStateData, RiskAssessmentData, RiskLevelData, WirePath,
};

use crate::args::Cli;
use crate::{adapters, doctor, evidence_view, explain};

const CONTEXT_OWNERSHIP_MAX_BYTES: usize = 1024 * 1024;
const CONTEXT_DOCUMENT_MAX_BYTES: usize = 256 * 1024;
const CONTEXT_DOCUMENT_TOTAL_BYTES: usize = 4 * 1024 * 1024;
const CONTEXT_DOCUMENT_MAX_FILES: usize = 64;

/// One deterministic navigation result and the envelope metadata derived with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NextOutcome {
    pub(crate) wire: NextData,
    pub(crate) exit_code: ExitCode,
    pub(crate) truncated: bool,
    pub(crate) inventory_cache_status: InventoryCacheStatus,
}

/// Computes one next action from a single retained detection snapshot.
pub(crate) fn execute_controlled(
    cli: &Cli,
    control: &OperationBudget,
) -> Result<NextOutcome, AppError> {
    let detected = explain::detect_controlled(cli, control)?;
    let doctor = doctor::execute_postcheck_controlled(cli, &detected, control)?;
    control
        .checkpoint()
        .map_err(|error| explain::map_operation_control_error(error, "navigation analysis"))?;
    let adapter_observation =
        adapters::observe_managed(&detected.model, detected.navigation.config.as_ref())?;
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
    let blockers = navigation_blockers(&detected.model, &risk, &doctor)?;
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
    let receipts = evidence_view::navigation_receipts_controlled(cli, &detected, &risk, control)?;
    let state_terminal_exit_code = receipts.terminal_exit_code;
    let decision = reduce_next(NavigationInput {
        integrity,
        blockers,
        adapters,
        changes,
        receipts: receipts.observation,
        commands: detected.model.commands.clone(),
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
        exit_code: state_terminal_exit_code.unwrap_or_else(|| {
            completion_or(detected.completion, navigation_exit_code(decision.state()))
        }),
        wire,
        truncated: context.truncated,
        inventory_cache_status: detected.inventory_cache_status,
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
            "the immutable HEAD policy base could not be read and validated for this committed repository",
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
    doctor: &doctor::DoctorOutcome,
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

    let environment_checks = [
        (
            DoctorCheckId::StateLayout,
            "environment/state-layout",
            "private Forge state failed its safe layout check",
        ),
        (
            DoctorCheckId::ToolchainRequired,
            "environment/toolchain",
            "a required project tool is unavailable or failed its bounded probe",
        ),
        (
            DoctorCheckId::PathSafety,
            "environment/path-safety",
            "repository or managed-target path safety failed",
        ),
    ];
    for (check_id, blocker_id, reason) in environment_checks {
        let check = doctor.check(check_id).ok_or_else(|| {
            internal_error(
                "doctor observation is missing a registered navigation check",
                check_id.to_string(),
            )
        })?;
        if check.status() == DoctorCheckStatus::Fail
            || (check_id == DoctorCheckId::ToolchainRequired
                && doctor.toolchain_runtime_unavailable())
        {
            blockers.push(
                NavigationBlocker::new(
                    NavigationBlockerKind::Environment,
                    blocker_id,
                    reason,
                    vec![provenance(
                        "navigation.doctor-environment.v1",
                        None,
                        "a typed doctor check established a local environment blocker",
                    )],
                )
                .map_err(map_navigation_error)?,
            );
        }
    }
    let process = doctor
        .check(DoctorCheckId::ProcessCapability)
        .ok_or_else(|| {
            internal_error(
                "doctor observation is missing a registered navigation check",
                DoctorCheckId::ProcessCapability.to_string(),
            )
        })?;
    if process.status() == DoctorCheckStatus::Fail
        || (process.status() == DoctorCheckStatus::Skipped
            && process.skip_reason() == Some(DoctorSkipReason::PlatformLimitation))
    {
        blockers.push(
            NavigationBlocker::new(
                NavigationBlockerKind::Environment,
                "environment/process-capability",
                "this platform cannot provide the bounded process-tree capability required for project commands",
                vec![provenance(
                    "navigation.doctor-process-capability.v1",
                    None,
                    "the typed doctor capability check reported a platform limitation",
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
        candidates.extend(codeowners_context(model, changed_paths)?);
        candidates.extend(exact_document_context(model, changed_paths)?);
    }
    Ok(candidates)
}

fn codeowners_context(
    model: &ProjectModel,
    changed_paths: &[RepoRelativePath],
) -> Result<Vec<ContextCandidate>, AppError> {
    let mut visible = model
        .assets
        .entries
        .iter()
        .filter(|asset| asset.kind == "ownership.codeowners")
        .collect::<Vec<_>>();
    visible.sort_by_key(|asset| codeowners_precedence(&asset.path));
    let Some(selected) = visible.first().copied() else {
        return Ok(Vec::new());
    };
    let path = selected.path.clone();
    let source_path = Some(WirePath::from_path(path.as_path()));

    if changed_paths
        .iter()
        .any(|changed| changed.as_path().to_str().is_none())
    {
        return Ok(vec![uncertain_context_candidate(
            path,
            "ownership impact cannot be checked losslessly for a non-UTF-8 changed path",
            "context.codeowners-non-utf8-path.v1",
        )?]);
    }

    if model.assets.confidence == Confidence::Unknown && codeowners_precedence(&path) != 0 {
        return Ok(vec![context_candidate(
            ContextSignal::UncertainImpact,
            path,
            "ownership precedence is uncertain because bounded asset discovery was incomplete",
            vec![provenance(
                "context.codeowners-precedence-unknown.v1",
                source_path,
                "a higher-precedence conventional CODEOWNERS path may be outside the retained inventory",
            )],
            Confidence::Unknown,
        )?]);
    }

    let text = match NativeFileSystem.read_confined_bounded(
        &model.repository.root,
        &path,
        CONTEXT_OWNERSHIP_MAX_BYTES,
    ) {
        Ok(Some(bytes)) => match String::from_utf8(bytes) {
            Ok(text) => text,
            Err(_) => {
                return Ok(vec![uncertain_context_candidate(
                    path,
                    "ownership rules are not valid UTF-8",
                    "context.codeowners-unreadable.v1",
                )?]);
            }
        },
        Ok(None) | Err(_) => {
            return Ok(vec![uncertain_context_candidate(
                path,
                "ownership rules could not be completely and safely read within the v0 bound",
                "context.codeowners-unreadable.v1",
            )?]);
        }
    };

    match doctor::codeowners_matches_any_path(&text, &model.repository.root, changed_paths) {
        Ok(true) => {
            let mut sources = selected.provenance.clone();
            sources.push(provenance(
                "context.codeowners-match.v1",
                source_path,
                "a supported CODEOWNERS rule matched at least one exact changed path",
            ));
            Ok(vec![context_candidate(
                ContextSignal::CodeOwner,
                path,
                "CODEOWNERS rule matches an exact changed path",
                sources,
                selected.confidence,
            )?])
        }
        Ok(false) => Ok(Vec::new()),
        Err(_) => Ok(vec![uncertain_context_candidate(
            path,
            "ownership rules use invalid or unsupported CODEOWNERS syntax",
            "context.codeowners-unresolved.v1",
        )?]),
    }
}

fn exact_document_context(
    model: &ProjectModel,
    changed_paths: &[RepoRelativePath],
) -> Result<Vec<ContextCandidate>, AppError> {
    let documents = model
        .assets
        .entries
        .iter()
        .filter(|asset| {
            matches!(
                asset.kind.as_str(),
                "documentation.contributing"
                    | "documentation.architecture-decision"
                    | "documentation.runbook"
            )
        })
        .collect::<Vec<_>>();
    if documents.is_empty() {
        return Ok(Vec::new());
    }

    let changed_utf8 = changed_paths
        .iter()
        .filter_map(|path| portable_relative_utf8_path(path.as_path()))
        .collect::<Vec<_>>();
    if changed_utf8.len() != changed_paths.len() {
        return Ok(vec![uncertain_context_candidate(
            documents[0].path.clone(),
            "exact document impact cannot be checked for a non-UTF-8 changed path",
            "context.document-non-utf8-path.v1",
        )?]);
    }

    let mut candidates = Vec::new();
    let mut remaining_bytes = CONTEXT_DOCUMENT_TOTAL_BYTES;
    for (index, document) in documents.iter().enumerate() {
        if index >= CONTEXT_DOCUMENT_MAX_FILES || remaining_bytes == 0 {
            candidates.push(uncertain_context_candidate(
                document.path.clone(),
                "additional conventional documents were omitted by the bounded v0 scan",
                "context.document-scan-truncated.v1",
            )?);
            break;
        }
        let read_limit = remaining_bytes.min(CONTEXT_DOCUMENT_MAX_BYTES);
        let bytes = match NativeFileSystem.read_confined_bounded(
            &model.repository.root,
            &document.path,
            read_limit,
        ) {
            Ok(Some(bytes)) => bytes,
            Ok(None) | Err(_) => {
                candidates.push(uncertain_context_candidate(
                    document.path.clone(),
                    "document could not be completely and safely read within the v0 bound",
                    "context.document-unreadable.v1",
                )?);
                continue;
            }
        };
        remaining_bytes = remaining_bytes.saturating_sub(bytes.len());
        let text = match std::str::from_utf8(&bytes) {
            Ok(text) => text,
            Err(_) => {
                candidates.push(uncertain_context_candidate(
                    document.path.clone(),
                    "document is not valid UTF-8",
                    "context.document-unreadable.v1",
                )?);
                continue;
            }
        };
        let Some(matched_path) = changed_utf8
            .iter()
            .find(|path| text.contains(path.as_str()))
        else {
            continue;
        };
        let mut sources = document.provenance.clone();
        sources.push(provenance(
            "context.exact-document-match.v1",
            Some(WirePath::from_path(document.path.as_path())),
            "a bounded conventional document contained one exact changed repository path",
        ));
        candidates.push(context_candidate(
            ContextSignal::ExactDocumentMatch,
            document.path.clone(),
            format!("document contains the exact changed path `{matched_path}`"),
            sources,
            document.confidence,
        )?);
    }
    Ok(candidates)
}

fn uncertain_context_candidate(
    path: RepoRelativePath,
    reason: &str,
    rule_id: &str,
) -> Result<ContextCandidate, AppError> {
    context_candidate(
        ContextSignal::UncertainImpact,
        path.clone(),
        reason,
        vec![provenance(
            rule_id,
            Some(WirePath::from_path(path.as_path())),
            "bounded context discovery could not establish an exact relationship",
        )],
        Confidence::Unknown,
    )
}

fn codeowners_precedence(path: &RepoRelativePath) -> u8 {
    let path = path.as_path();
    if path == Path::new(".github").join("CODEOWNERS") {
        0
    } else if path == Path::new("CODEOWNERS") {
        1
    } else if path == Path::new("docs").join("CODEOWNERS") {
        2
    } else {
        3
    }
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
    let mut assumptions = detected
        .model
        .assumptions
        .iter()
        .map(assumption_to_wire)
        .collect::<Vec<_>>();
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
                "the committed repository's immutable HEAD policy base could not be read or validated",
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
        receipt_command: (decision.action() == NavigationAction::RunIntent)
            .then(|| {
                decision
                    .intent()
                    .map(|intent| format!("forge evidence run {}", intent_name(intent)))
            })
            .flatten(),
        context_paths: context
            .paths
            .iter()
            .map(|path| ContextPathData {
                path: WirePath::from_path(path.path.as_path()),
                why: path.reason.clone(),
                provenance: provenance_ids(&path.provenance),
                confidence: Some(confidence_to_wire(path.confidence)),
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
    project_selected_commands(
        &detected.model.commands,
        intent,
        decision.project_commands(),
    )
}

fn project_selected_commands(
    command_sets: &BTreeMap<Intent, ResolvedCommandSet>,
    intent: Intent,
    selected: &[CommandSpec],
) -> Result<Vec<CommandData>, AppError> {
    let key = intent_name(intent);
    let available = command_sets.get(&intent).ok_or_else(|| {
        internal_error(
            "navigation command projection is missing",
            format!("project model has no `{key}` command set"),
        )
    })?;
    let by_id = available
        .commands()
        .iter()
        .map(|command| (command.id.as_str(), command))
        .collect::<BTreeMap<_, _>>();
    selected
        .iter()
        .map(|command| {
            validate_command_privacy(command).map_err(|_| explain::command_privacy_error())?;
            let retained = by_id.get(command.id.as_str()).copied().ok_or_else(|| {
                internal_error(
                    "navigation command projection diverged from the project model",
                    format!(
                        "command `{}` was not retained in the project model",
                        command.id
                    ),
                )
            })?;
            if retained != command {
                return Err(internal_error(
                    "navigation command projection diverged from the project model",
                    "a selected command differs from its retained project-model command",
                ));
            }
            command_detail_v2_to_wire(command)
                .map(|detail| detail.command)
                .map_err(explain::map_projection_error)
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
        NavigationState::ChecksFailing => NextStateData::ChecksFailing,
        NavigationState::ChangedUnverified => NextStateData::ChangedUnverified,
        NavigationState::PartiallyVerified => NextStateData::PartiallyVerified,
        NavigationState::LocalVerified => NextStateData::LocalVerified,
    }
}

const fn action_to_wire(action: NavigationAction) -> NextActionData {
    match action {
        NavigationAction::RunDoctor => NextActionData::RunDoctor,
        NavigationAction::ResolveBlocker => NextActionData::ResolveBlocker,
        NavigationAction::StopAndEscalate => NextActionData::StopAndEscalate,
        NavigationAction::SyncAdapters => NextActionData::SyncAdapters,
        NavigationAction::None => NextActionData::None,
        NavigationAction::FixFailures => NextActionData::FixFailures,
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
        NavigationState::Idle | NavigationState::LocalVerified => ExitCode::Ok,
        NavigationState::Blocked => ExitCode::EnvironmentUnmet,
        NavigationState::Unknown
        | NavigationState::AdaptersDrifted
        | NavigationState::ChecksFailing
        | NavigationState::ChangedUnverified
        | NavigationState::PartiallyVerified => ExitCode::Negative,
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
    if let Some(command) = &data.receipt_command {
        let _ = writeln!(output, "receipt command: {command}");
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
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    use forge_core::navigation::{NavigationAction, NavigationState};
    use forge_core::{
        CommandSource, CommandSpec, Confidence, ExitCode, Intent, Provenance, RepoRelativePath,
        ResolvedCommandSet, command_detail_v2_to_wire,
    };
    use forge_schema::{
        IntentData, NextActionData, NextData, NextStateData, RiskAssessmentData, RiskLevelData,
    };

    use super::{
        InventoryCacheStatus, NextOutcome, action_to_wire, codeowners_precedence, named_test_for,
        navigation_exit_code, path_is_within, project_selected_commands, render_human,
        state_to_wire,
    };

    fn provenance() -> Vec<Provenance> {
        vec![Provenance {
            rule_id: String::from("test.fixture"),
            source_path: None,
            source_range: None,
            detail: String::from("test evidence"),
        }]
    }

    fn command(id: &str, intent: Intent) -> CommandSpec {
        CommandSpec::new(
            id,
            intent,
            "cargo",
            RepoRelativePath::root(),
            CommandSource::ExplicitConfig,
        )
        .with_args(["check"])
    }

    fn resolved(
        command: CommandSpec,
    ) -> Result<ResolvedCommandSet, forge_core::InvalidCommandResolution> {
        ResolvedCommandSet::resolved(
            vec![command],
            provenance(),
            Confidence::High,
            Confidence::High,
        )
    }

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
    fn codeowners_precedence_uses_native_repository_components()
    -> Result<(), Box<dyn std::error::Error>> {
        let github = RepoRelativePath::new(PathBuf::from(".github").join("CODEOWNERS"))?;
        let root = RepoRelativePath::new("CODEOWNERS")?;
        let docs = RepoRelativePath::new(PathBuf::from("docs").join("CODEOWNERS"))?;

        assert_eq!(codeowners_precedence(&github), 0);
        assert_eq!(codeowners_precedence(&root), 1);
        assert_eq!(codeowners_precedence(&docs), 2);
        Ok(())
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
            navigation_exit_code(NavigationState::LocalVerified),
            ExitCode::Ok
        );
        assert_eq!(
            navigation_exit_code(NavigationState::ChangedUnverified),
            ExitCode::Negative
        );
        assert_eq!(
            navigation_exit_code(NavigationState::ChecksFailing),
            ExitCode::Negative
        );
        assert_eq!(
            navigation_exit_code(NavigationState::PartiallyVerified),
            ExitCode::Negative
        );
        assert_eq!(
            navigation_exit_code(NavigationState::Blocked),
            ExitCode::EnvironmentUnmet
        );
    }

    #[test]
    fn receipt_backed_states_and_actions_use_the_existing_next_v1_variants() {
        assert_eq!(
            state_to_wire(NavigationState::ChecksFailing),
            NextStateData::ChecksFailing
        );
        assert_eq!(
            state_to_wire(NavigationState::PartiallyVerified),
            NextStateData::PartiallyVerified
        );
        assert_eq!(
            state_to_wire(NavigationState::LocalVerified),
            NextStateData::LocalVerified
        );
        assert_eq!(
            action_to_wire(NavigationAction::FixFailures),
            NextActionData::FixFailures
        );
    }

    #[test]
    fn next_projects_only_selected_safe_commands_and_preserves_existing_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let secret = "unrelated-next-secret";
        let mut selected = command("selected-check", Intent::Check);
        selected
            .env
            .insert(OsString::from("AUTHOR"), OsString::from("Ada"));
        selected
            .env
            .insert(OsString::from("BUILD_REGION"), OsString::from("us-east-1"));
        let unrelated =
            command("unrelated-setup", Intent::Setup).with_args(["check", "--token", secret]);
        let command_sets = BTreeMap::from([
            (Intent::Check, resolved(selected.clone())?),
            (Intent::Setup, resolved(unrelated)?),
        ]);

        let projected = project_selected_commands(
            &command_sets,
            Intent::Check,
            std::slice::from_ref(&selected),
        )?;
        let expected = command_detail_v2_to_wire(&selected)?.command;
        assert_eq!(
            serde_json::to_vec(&projected[0])?,
            serde_json::to_vec(&expected)?
        );
        assert_eq!(projected[0].environment_names, ["AUTHOR", "BUILD_REGION"]);

        let outcome = NextOutcome {
            wire: NextData {
                state: NextStateData::ChangedUnverified,
                required_action: NextActionData::RunIntent,
                intent: Some(IntentData::Check),
                project_commands: projected,
                receipt_command: None,
                context_paths: Vec::new(),
                risk: RiskAssessmentData {
                    level: RiskLevelData::Unknown,
                    matched: Vec::new(),
                    provenance: Vec::new(),
                },
                blockers: Vec::new(),
                reason: String::from("test decision"),
                provenance: Vec::new(),
                uncertain_assumptions: Vec::new(),
            },
            exit_code: ExitCode::Negative,
            truncated: false,
            inventory_cache_status: InventoryCacheStatus::Disabled,
        };
        let outputs = [
            render_human(&outcome),
            serde_json::to_string(&outcome.wire)?,
        ];
        assert!(outputs[1].contains("AUTHOR"));
        assert!(outputs[1].contains("BUILD_REGION"));
        for output in outputs {
            assert!(
                !output.contains(secret),
                "unrelated command leaked: {output}"
            );
            assert!(
                !output.contains("--token"),
                "unrelated argv leaked: {output}"
            );
        }
        Ok(())
    }

    #[test]
    fn next_rejects_an_unsafe_selected_command_without_rendering_its_metadata()
    -> Result<(), Box<dyn std::error::Error>> {
        let secret = "selected-next-secret";
        let mut selected =
            command("unsafe-check", Intent::Check).with_args(["check", "--token", secret]);
        selected
            .env
            .insert(OsString::from("API_TOKEN"), OsString::from(secret));
        let command_sets = BTreeMap::from([(Intent::Check, resolved(selected.clone())?)]);

        let error = project_selected_commands(
            &command_sets,
            Intent::Check,
            std::slice::from_ref(&selected),
        )
        .err()
        .ok_or_else(|| std::io::Error::other("unsafe selected command did not fail closed"))?;

        assert_eq!(error.diagnostic().code.as_str(), "FGE1103");
        for output in [
            error.to_string(),
            serde_json::to_string(error.diagnostic())?,
            format!("{error:?}"),
        ] {
            for forbidden in [secret, "--token", "API_TOKEN"] {
                assert!(
                    !output.contains(forbidden),
                    "leaked {forbidden:?}: {output}"
                );
            }
        }
        Ok(())
    }
}
