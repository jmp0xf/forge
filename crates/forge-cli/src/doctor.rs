//! Read-only composition of the fixed v0 doctor registry.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use forge_core::doctor::{
    DoctorCheck, DoctorCheckId, DoctorCheckStatus, DoctorOverall, DoctorReport,
    DoctorValidationError,
};
use forge_core::{
    AppError, CommandResolution, Confidence, ExitCode, Intent, ProjectModel, WorkState,
};
use forge_detect::model::ModelDetectionCompletion;
use forge_runtime::state::{AtomicStateStore, GitStateLayout};
use forge_schema::{CheckStatusData, DoctorCheckData, DoctorData};

use crate::adapters::{self, AdapterObservation};
use crate::args::Cli;
use crate::{explain, init};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DoctorOutcome {
    pub(crate) wire: DoctorData,
    pub(crate) exit_code: ExitCode,
}

pub(crate) fn execute(cli: &Cli, cancellation: Arc<AtomicBool>) -> Result<DoctorOutcome, AppError> {
    let detected = explain::detect(cli, cancellation)?;
    let state = state_layout_check(&detected.model)?;
    let adapter_observation = if state.status() == DoctorCheckStatus::Pass {
        Some(adapters::observe_managed(&detected.model)?)
    } else {
        None
    };
    let checks = build_checks(
        &detected.model,
        detected.completion,
        &detected.navigation,
        state,
        adapter_observation.as_ref(),
    )?;
    let report = DoctorReport::new(checks).map_err(map_validation_error)?;
    let exit_code = completion_exit_code(detected.completion).unwrap_or(match report.overall() {
        DoctorOverall::Pass => ExitCode::Ok,
        DoctorOverall::Fail | DoctorOverall::Unknown => ExitCode::Negative,
    });
    let wire = DoctorData {
        overall: overall_to_wire(report.overall()),
        checks: report.checks().iter().map(check_to_wire).collect(),
        // v0 does not execute additional version commands. Provider metadata probes already prove
        // supported tools sufficiently for this check without expanding the executable surface.
        tool_versions: BTreeMap::new(),
        assumptions: detected.wire.assumptions,
    };
    Ok(DoctorOutcome { wire, exit_code })
}

fn build_checks(
    model: &ProjectModel,
    completion: ModelDetectionCompletion,
    navigation: &forge_detect::model::NavigationSnapshot,
    state_layout: DoctorCheck,
    adapters: Option<&AdapterObservation>,
) -> Result<Vec<DoctorCheck>, AppError> {
    let mut checks = Vec::with_capacity(DoctorCheckId::ALL.len());
    checks.push(git_repository_check(model)?);
    checks.push(git_operation_check(model)?);
    checks.push(state_layout);
    checks.push(config_check(navigation)?);
    checks.push(project_units_check(model)?);
    checks.push(project_commands_check(model)?);
    checks.push(toolchain_check(model, completion)?);
    checks.push(adapter_check(adapters)?);
    checks.push(ci_check(model)?);
    checks.push(ownership_check(model)?);
    checks.push(path_safety_check(navigation, adapters)?);
    checks.push(process_capability_check(completion)?);
    Ok(checks)
}

fn git_repository_check(model: &ProjectModel) -> Result<DoctorCheck, AppError> {
    let (status, detail, next) = if model.repository_confidence == Confidence::Unknown {
        (
            DoctorCheckStatus::Unknown,
            "Git repository facts are partial or unavailable",
            "inspect the repository and rerun `forge doctor`",
        )
    } else {
        (
            DoctorCheckStatus::Pass,
            "Git repository identity and worktree facts were read successfully",
            "no repository repair is required",
        )
    };
    check(DoctorCheckId::GitRepository, status, detail, next)
}

fn git_operation_check(model: &ProjectModel) -> Result<DoctorCheck, AppError> {
    let (status, detail, next) = match model.repository.work_state {
        WorkState::Conflicted => (
            DoctorCheckStatus::Fail,
            "the worktree contains unresolved conflicts",
            "resolve or abort the conflicting Git operation before continuing",
        ),
        WorkState::Merging => (
            DoctorCheckStatus::Fail,
            "a merge operation is in progress",
            "finish or abort the merge before continuing",
        ),
        WorkState::Rebasing => (
            DoctorCheckStatus::Fail,
            "a rebase operation is in progress",
            "finish or abort the rebase before continuing",
        ),
        WorkState::Corrupt => (
            DoctorCheckStatus::Fail,
            "Git operation state is internally inconsistent",
            "repair the repository before continuing",
        ),
        WorkState::Unknown => (
            DoctorCheckStatus::Unknown,
            "Git operation state could not be proven",
            "inspect Git operation markers and rerun `forge doctor`",
        ),
        WorkState::Clean | WorkState::Dirty | WorkState::Unborn => (
            DoctorCheckStatus::Pass,
            "no conflicting merge or rebase operation is active",
            "no Git operation repair is required",
        ),
    };
    check(DoctorCheckId::GitOperation, status, detail, next)
}

fn state_layout_check(model: &ProjectModel) -> Result<DoctorCheck, AppError> {
    let layout = GitStateLayout::new(&model.repository.git_dir, &model.repository.git_common_dir);
    match AtomicStateStore::open_existing_read_only(layout) {
        Ok(Some(_)) => check(
            DoctorCheckId::StateLayout,
            DoctorCheckStatus::Pass,
            "existing private Forge state is confined to the resolved Git directory",
            "no private-state repair is required",
        ),
        Ok(None) => check(
            DoctorCheckId::StateLayout,
            DoctorCheckStatus::Pass,
            "optional private Forge state is absent",
            "run `forge init --apply` only when repository integration is desired",
        ),
        Err(error) => check(
            DoctorCheckId::StateLayout,
            DoctorCheckStatus::Fail,
            format!(
                "private Forge state is unsafe or unreadable: {}",
                init::sanitize_text(&error.to_string())
            ),
            "repair or remove the unsafe private state, then rerun `forge doctor`",
        ),
    }
}

fn config_check(
    navigation: &forge_detect::model::NavigationSnapshot,
) -> Result<DoctorCheck, AppError> {
    let detail = if navigation.config.is_some() {
        "the selected Forge configuration parsed as schema v1"
    } else {
        "no Forge configuration is present; built-in defaults remain authoritative"
    };
    check(
        DoctorCheckId::ConfigSchema,
        DoctorCheckStatus::Pass,
        detail,
        "no configuration repair is required",
    )
}

fn project_units_check(model: &ProjectModel) -> Result<DoctorCheck, AppError> {
    let (status, detail, next) = if model.unit_inventory_confidence == Confidence::Unknown {
        (
            DoctorCheckStatus::Unknown,
            "project unit discovery is partial",
            "resolve the reported inventory or provider uncertainty and rerun `forge doctor`",
        )
    } else {
        (
            DoctorCheckStatus::Pass,
            "project unit discovery completed within its configured bounds",
            "no unit-discovery repair is required",
        )
    };
    check(DoctorCheckId::ProjectUnits, status, detail, next)
}

fn project_commands_check(model: &ProjectModel) -> Result<DoctorCheck, AppError> {
    let mut ambiguous = Vec::new();
    let mut unknown = Vec::new();
    for intent in Intent::ALL {
        match model.commands[&intent].resolution() {
            CommandResolution::Ambiguous => ambiguous.push(intent_name(intent)),
            CommandResolution::Unknown => unknown.push(intent_name(intent)),
            CommandResolution::Resolved | CommandResolution::Absent => {}
        }
    }
    if !ambiguous.is_empty() {
        return check(
            DoctorCheckId::ProjectCommands,
            DoctorCheckStatus::Fail,
            format!(
                "project command resolution is ambiguous for {}",
                ambiguous.join(", ")
            ),
            "make command ownership explicit in `forge.toml` or remove the conflicting runner target",
        );
    }
    if !unknown.is_empty() {
        return check(
            DoctorCheckId::ProjectCommands,
            DoctorCheckStatus::Unknown,
            format!("project commands are unresolved for {}", unknown.join(", ")),
            "resolve the reported runner or provider uncertainty and rerun `forge doctor`",
        );
    }
    check(
        DoctorCheckId::ProjectCommands,
        DoctorCheckStatus::Pass,
        "every v0 command intent is explicitly resolved or absent",
        "no command-resolution repair is required",
    )
}

fn toolchain_check(
    model: &ProjectModel,
    completion: ModelDetectionCompletion,
) -> Result<DoctorCheck, AppError> {
    if model.units.is_empty() {
        let has_project_command = model
            .commands
            .values()
            .any(|commands| commands.resolution() == CommandResolution::Resolved);
        return if has_project_command {
            check(
                DoctorCheckId::ToolchainRequired,
                DoctorCheckStatus::Unknown,
                "project runner commands exist without a supported provider toolchain probe",
                "verify the runner-declared tools explicitly before executing project commands",
            )
        } else {
            check(
                DoctorCheckId::ToolchainRequired,
                DoctorCheckStatus::Pass,
                "the detected repository requires no supported language toolchain",
                "no toolchain action is required",
            )
        };
    }
    match completion {
        ModelDetectionCompletion::Complete => check(
            DoctorCheckId::ToolchainRequired,
            DoctorCheckStatus::Pass,
            "supported language-provider metadata probes completed",
            "use the resolved project commands for further verification",
        ),
        ModelDetectionCompletion::Partial => check(
            DoctorCheckId::ToolchainRequired,
            DoctorCheckStatus::Unknown,
            "one or more supported language-provider probes were incomplete",
            "fix the provider diagnostics and rerun `forge doctor`",
        ),
        ModelDetectionCompletion::TimedOut => check(
            DoctorCheckId::ToolchainRequired,
            DoctorCheckStatus::Unknown,
            "a supported language-provider probe timed out",
            "increase `--timeout` or repair the toolchain before retrying",
        ),
        ModelDetectionCompletion::Interrupted => check(
            DoctorCheckId::ToolchainRequired,
            DoctorCheckStatus::Unknown,
            "a supported language-provider probe was interrupted",
            "rerun `forge doctor` when ready",
        ),
    }
}

fn adapter_check(observation: Option<&AdapterObservation>) -> Result<DoctorCheck, AppError> {
    let Some(observation) = observation else {
        return check(
            DoctorCheckId::AdaptersDrift,
            DoctorCheckStatus::Unknown,
            "adapter drift could not be inspected because private-state safety failed",
            "repair private state and rerun `forge doctor`",
        );
    };
    if !observation.managed {
        return check(
            DoctorCheckId::AdaptersDrift,
            DoctorCheckStatus::Pass,
            "this repository has not adopted Forge-managed host adapters",
            "run `forge init` only when managed adapters are desired",
        );
    }
    if observation.changed {
        check(
            DoctorCheckId::AdaptersDrift,
            DoctorCheckStatus::Fail,
            format!(
                "{} managed adapter target(s) were inspected and at least one drifted",
                observation.statuses.len()
            ),
            "review `forge adapters check`, then run `forge adapters sync --apply` if appropriate",
        )
    } else {
        check(
            DoctorCheckId::AdaptersDrift,
            DoctorCheckStatus::Pass,
            format!(
                "all {} managed adapter target(s) match their authoritative source",
                observation.statuses.len()
            ),
            "no adapter synchronization is required",
        )
    }
}

fn ci_check(model: &ProjectModel) -> Result<DoctorCheck, AppError> {
    let workflows = model
        .assets
        .entries
        .iter()
        .filter(|asset| asset.kind == "ci.github-actions")
        .count();
    check(
        DoctorCheckId::CiVisible,
        DoctorCheckStatus::Unknown,
        format!(
            "{workflows} local GitHub workflow asset(s) are visible; server-side protection is not observable from this clone"
        ),
        "verify required checks and branch protection in the hosting platform",
    )
}

fn ownership_check(model: &ProjectModel) -> Result<DoctorCheck, AppError> {
    let visible = model
        .assets
        .entries
        .iter()
        .any(|asset| asset.kind == "ownership.codeowners");
    if visible {
        check(
            DoctorCheckId::OwnershipVisible,
            DoctorCheckStatus::Pass,
            "a conventional CODEOWNERS file is visible in the repository",
            "confirm hosting-platform ownership enforcement for protected changes",
        )
    } else {
        check(
            DoctorCheckId::OwnershipVisible,
            DoctorCheckStatus::Unknown,
            "no conventional CODEOWNERS file is visible",
            "identify the human authority for protected changes before modifying them",
        )
    }
}

fn path_safety_check(
    navigation: &forge_detect::model::NavigationSnapshot,
    adapters: Option<&AdapterObservation>,
) -> Result<DoctorCheck, AppError> {
    if adapters.is_none() {
        return check(
            DoctorCheckId::PathSafety,
            DoctorCheckStatus::Fail,
            "private-state path safety validation failed",
            "repair unsafe state paths before allowing Forge writes",
        );
    }
    if !navigation.inventory.skipped.is_empty() {
        return check(
            DoctorCheckId::PathSafety,
            DoctorCheckStatus::Unknown,
            format!(
                "repository inventory skipped {} path(s) or bounded observations",
                navigation.inventory.skipped.len()
            ),
            "review skipped inventory facts before relying on complete path coverage",
        );
    }
    check(
        DoctorCheckId::PathSafety,
        DoctorCheckStatus::Pass,
        "repository inventory and managed-target confinement checks completed",
        "no path-safety repair is required",
    )
}

fn process_capability_check(completion: ModelDetectionCompletion) -> Result<DoctorCheck, AppError> {
    let (status, detail, next) = match completion {
        ModelDetectionCompletion::Complete | ModelDetectionCompletion::Partial => (
            DoctorCheckStatus::Pass,
            "bounded subprocess execution and process-tree control are available",
            "no process-runtime repair is required",
        ),
        ModelDetectionCompletion::TimedOut => (
            DoctorCheckStatus::Unknown,
            "the current detection budget expired while controlling a subprocess",
            "increase `--timeout` or repair the blocked tool before retrying",
        ),
        ModelDetectionCompletion::Interrupted => (
            DoctorCheckStatus::Unknown,
            "the current detection subprocess was interrupted",
            "rerun `forge doctor` when ready",
        ),
    };
    check(DoctorCheckId::ProcessCapability, status, detail, next)
}

fn check(
    id: DoctorCheckId,
    status: DoctorCheckStatus,
    detail: impl Into<String>,
    next: impl Into<String>,
) -> Result<DoctorCheck, AppError> {
    DoctorCheck::new(id, status, detail, next, None).map_err(map_validation_error)
}

fn map_validation_error(error: DoctorValidationError) -> AppError {
    AppError::internal(
        "FGE0401",
        "the doctor registry violated an internal invariant",
        "doctor registry",
        error.to_string(),
        "report this as a Forge implementation defect",
    )
}

fn check_to_wire(check: &DoctorCheck) -> DoctorCheckData {
    DoctorCheckData {
        id: check.id().as_str().to_owned(),
        status: status_to_wire(check.status()),
        detail: check.detail().to_owned(),
        next: check.next().to_owned(),
    }
}

const fn status_to_wire(status: DoctorCheckStatus) -> CheckStatusData {
    match status {
        DoctorCheckStatus::Pass => CheckStatusData::Pass,
        DoctorCheckStatus::Fail => CheckStatusData::Fail,
        DoctorCheckStatus::Unknown => CheckStatusData::Unknown,
        DoctorCheckStatus::Skipped => CheckStatusData::Skipped,
    }
}

const fn overall_to_wire(status: DoctorOverall) -> CheckStatusData {
    match status {
        DoctorOverall::Pass => CheckStatusData::Pass,
        DoctorOverall::Fail => CheckStatusData::Fail,
        DoctorOverall::Unknown => CheckStatusData::Unknown,
    }
}

const fn completion_exit_code(completion: ModelDetectionCompletion) -> Option<ExitCode> {
    match completion {
        ModelDetectionCompletion::Complete | ModelDetectionCompletion::Partial => None,
        ModelDetectionCompletion::TimedOut => Some(ExitCode::Timeout),
        ModelDetectionCompletion::Interrupted => Some(ExitCode::Interrupted),
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

pub(crate) fn render_human(outcome: &DoctorOutcome) -> String {
    let mut output = String::new();
    let _ = writeln!(
        output,
        "Forge doctor: {}",
        match outcome.wire.overall {
            CheckStatusData::Pass => "pass",
            CheckStatusData::Fail => "fail",
            CheckStatusData::Skipped => "skipped",
            CheckStatusData::Unknown => "unknown",
            _ => "unknown",
        }
    );
    for check in &outcome.wire.checks {
        let status = match check.status {
            CheckStatusData::Pass => "pass",
            CheckStatusData::Fail => "fail",
            CheckStatusData::Skipped => "skipped",
            CheckStatusData::Unknown => "unknown",
            _ => "unknown",
        };
        let _ = writeln!(output, "[{status}] {}: {}", check.id, check.detail);
        let _ = writeln!(output, "  next: {}", check.next);
    }
    output
}
