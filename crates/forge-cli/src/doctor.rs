//! Read-only composition of the fixed v0 doctor registry.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt::Write as _;
use std::time::Duration;

use forge_core::doctor::{
    DoctorCheck, DoctorCheckId, DoctorCheckStatus, DoctorOverall, DoctorReport, DoctorSkipReason,
    DoctorValidationError,
};
use forge_core::domain::CommandEnforcement;
use forge_core::fingerprint::validate_command_privacy;
use forge_core::ports::{EnvPolicy, ExecSpec};
use forge_core::{
    AppError, CommandResolution, CommandSpec, Confidence, ExitCode, Intent, OperationControl as _,
    OperationControlError, ProjectModel, RepoRelativePath, ResolvedCommandSet, RiskLevel,
    WorkState, assumption_to_wire,
};
use forge_detect::model::ModelDetectionCompletion;
use forge_detect::policy::PolicyBaseCompleteness;
use forge_detect::workflow::parse_github_actions_run_steps;
use forge_runtime::control::OperationBudget;
use forge_runtime::fs::NativeFileSystem;
use forge_runtime::process::{
    ExecutableAvailability, ProcessTreeCapability, SynchronousProcessRunner,
    process_tree_capability,
};
use forge_runtime::toolchain::{
    ToolchainProbeFailure, ToolchainProbeKind, ToolchainProbeRequest, ToolchainVersionReport,
    probe_toolchain_versions_controlled, required_probes_for_command,
};
use forge_schema::{CheckStatusData, DoctorCheckData, DoctorData, DoctorSkipReasonData};
use ignore::gitignore::GitignoreBuilder;

use crate::adapters::{self, AdapterObservation, ValidatedAdapterState};
use crate::args::Cli;
use crate::{evidence_view, explain, init};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DoctorOutcome {
    pub(crate) wire: DoctorData,
    pub(crate) exit_code: ExitCode,
    checks: Vec<DoctorCheck>,
    toolchain_runtime_unavailable: bool,
}

#[derive(Debug)]
struct StateLayoutInspection {
    check: DoctorCheck,
    terminal_exit_code: Option<ExitCode>,
    adapter_state: Option<ValidatedAdapterState>,
    adapter_state_invalid: bool,
}

impl DoctorOutcome {
    pub(crate) fn check(&self, id: DoctorCheckId) -> Option<&DoctorCheck> {
        self.checks.iter().find(|check| check.id() == id)
    }

    pub(crate) const fn toolchain_runtime_unavailable(&self) -> bool {
        self.toolchain_runtime_unavailable
    }
}

const DEFAULT_DOCTOR_TOOLCHAIN_BUDGET: Duration = Duration::from_secs(10);
const DOCTOR_VISIBLE_FILE_MAX_BYTES: u64 = forge_core::inventory::DEFAULT_MAX_TEXT_FILE_BYTES;

pub(crate) fn execute_controlled(
    cli: &Cli,
    control: &OperationBudget,
) -> Result<DoctorOutcome, AppError> {
    let detected = explain::detect_controlled(cli, control)?;
    execute_detected(cli, &detected, control)
}

pub(crate) fn execute_postcheck_controlled(
    cli: &Cli,
    detected: &explain::DetectedProject,
    control: &OperationBudget,
) -> Result<DoctorOutcome, AppError> {
    execute_detected(cli, detected, control)
}

fn execute_detected(
    _cli: &Cli,
    detected: &explain::DetectedProject,
    control: &OperationBudget,
) -> Result<DoctorOutcome, AppError> {
    control
        .checkpoint()
        .map_err(|error| explain::map_operation_control_error(error, "doctor state inspection"))?;
    let state = state_layout_check(detected, control)?;
    let target_safety = adapters::observe_default_target_safety(
        &detected.model,
        detected.navigation.config.as_ref(),
    );
    let adapter_observation = if state.check.status() != DoctorCheckStatus::Fail
        && !matches!(target_safety, adapters::AdapterTargetSafety::Unsafe { .. })
    {
        state
            .adapter_state
            .as_ref()
            .map(|adapter_state| {
                adapters::observe_managed_from_validated_state(
                    &detected.model,
                    detected.navigation.config.as_ref(),
                    adapter_state,
                )
            })
            .transpose()?
    } else {
        None
    };
    let toolchain_requirements = ToolchainRequirements::from_model(&detected.model);
    let toolchain = match SynchronousProcessRunner::new(&detected.model.repository.root) {
        Ok(runner) => {
            let runner = runner.with_cancellation_flag(control.cancellation_flag());
            inspect_toolchains(&runner, &toolchain_requirements, control)
        }
        Err(_) => ToolchainInspection {
            runtime_unavailable: toolchain_requirements.required_probe_count() > 0,
            ..ToolchainInspection::default()
        },
    };
    let state_terminal_exit_code = state.terminal_exit_code;
    let checks = build_checks(DoctorCheckContext {
        model: &detected.model,
        completion: detected.completion,
        navigation: &detected.navigation,
        state_layout: state.check,
        adapters: adapter_observation.as_ref(),
        adapter_state_invalid: state.adapter_state_invalid,
        toolchain_requirements: &toolchain_requirements,
        toolchain: &toolchain,
        target_safety: &target_safety,
    })?;
    let report = DoctorReport::new(checks).map_err(map_validation_error)?;
    let checks = report.checks().to_vec();
    let exit_code = completion_exit_code(detected.completion)
        .or(state_terminal_exit_code)
        .or_else(|| toolchain.terminal_exit_code())
        .unwrap_or(match report.overall() {
            DoctorOverall::Pass => ExitCode::Ok,
            DoctorOverall::Fail | DoctorOverall::Unknown => ExitCode::Negative,
        });
    let wire = DoctorData {
        overall: overall_to_wire(report.overall()),
        checks: report.checks().iter().map(check_to_wire).collect(),
        tool_versions: toolchain.versions.clone(),
        assumptions: detected
            .model
            .assumptions
            .iter()
            .map(assumption_to_wire)
            .collect(),
    };
    Ok(DoctorOutcome {
        wire,
        exit_code,
        checks,
        toolchain_runtime_unavailable: toolchain.terminal_exit_code()
            == Some(ExitCode::EnvironmentUnmet),
    })
}

fn doctor_probe_environment(command_environment: &BTreeMap<OsString, OsString>) -> EnvPolicy {
    let mut overrides = command_environment.clone();
    overrides.insert(OsString::from("CARGO_NET_OFFLINE"), OsString::from("true"));
    overrides.insert(OsString::from("GOTOOLCHAIN"), OsString::from("local"));
    EnvPolicy::minimal_with_overrides(overrides)
}

#[cfg(test)]
fn remaining_toolchain_budget(
    operation_timeout: Option<Duration>,
    operation_elapsed: Duration,
) -> Duration {
    operation_timeout
        .map(|timeout| timeout.saturating_sub(operation_elapsed))
        .unwrap_or(DEFAULT_DOCTOR_TOOLCHAIN_BUDGET)
        .min(DEFAULT_DOCTOR_TOOLCHAIN_BUDGET)
}

struct DoctorCheckContext<'a> {
    model: &'a ProjectModel,
    completion: ModelDetectionCompletion,
    navigation: &'a forge_detect::model::NavigationSnapshot,
    state_layout: DoctorCheck,
    adapters: Option<&'a AdapterObservation>,
    adapter_state_invalid: bool,
    toolchain_requirements: &'a ToolchainRequirements,
    toolchain: &'a ToolchainInspection,
    target_safety: &'a adapters::AdapterTargetSafety,
}

fn build_checks(context: DoctorCheckContext<'_>) -> Result<Vec<DoctorCheck>, AppError> {
    let mut checks = Vec::with_capacity(DoctorCheckId::ALL.len());
    checks.push(git_repository_check(context.model)?);
    checks.push(git_operation_check(context.model)?);
    checks.push(context.state_layout);
    checks.push(config_check(context.navigation)?);
    checks.push(project_units_check(context.model)?);
    checks.push(project_commands_check(context.model)?);
    checks.push(toolchain_check(
        context.toolchain_requirements,
        context.completion,
        context.toolchain,
    )?);
    checks.push(adapter_check(
        context.adapters,
        context.adapter_state_invalid,
    )?);
    checks.push(ci_check(context.model)?);
    checks.push(ownership_check(context.model, context.navigation)?);
    checks.push(path_safety_check(
        context.navigation,
        context.adapters,
        context.target_safety,
    )?);
    checks.push(process_capability_check(context.completion)?);
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

fn state_layout_check(
    detected: &explain::DetectedProject,
    control: &OperationBudget,
) -> Result<StateLayoutInspection, AppError> {
    let adapter_state = match adapters::validate_retained_adapter_state(&detected.model) {
        Ok(state) => state,
        Err(error) => {
            let exit_code = error.exit_code();
            let persisted_contract_failure =
                matches!(&error, adapters::AdapterStateValidationError::Manifest(_));
            return state_layout_failure(
                format!(
                    "private Forge adapter state is unsafe or invalid: {}",
                    init::sanitize_text(&error.to_string())
                ),
                exit_code,
                true,
                persisted_contract_failure,
            );
        }
    };
    if !adapter_state.exists() {
        return Ok(StateLayoutInspection {
            check: check(
                DoctorCheckId::StateLayout,
                DoctorCheckStatus::Unknown,
                "optional private Forge state is absent, so this read-only check cannot prove state writing or exclusive locking",
                "run `forge init --apply` only when repository integration is desired, then verify the authorized write",
            )?,
            terminal_exit_code: None,
            adapter_state: Some(adapter_state),
            adapter_state_invalid: false,
        });
    }

    let log_max_bytes = match evidence_view::configured_log_max_bytes(detected) {
        Ok(bytes) => bytes,
        Err(error) => {
            return state_layout_failure(
                format!(
                    "private Forge state could not be validated under the configured bounds: {}",
                    init::sanitize_text(&error.to_string())
                ),
                error.exit_code(),
                false,
                false,
            );
        }
    };
    if let Err(error) =
        evidence_view::validate_retained_receipt_state_controlled(detected, log_max_bytes, control)
    {
        let exit_code = crate::state_diagnostic::state_error_exit_code(&error);
        return state_layout_failure(
            format!(
                "private Forge Evidence state is unsafe or invalid: {}",
                init::sanitize_text(&error.to_string())
            ),
            exit_code,
            false,
            true,
        );
    }

    Ok(StateLayoutInspection {
        check: check(
            DoctorCheckId::StateLayout,
            DoctorCheckStatus::Unknown,
            "existing private Forge state, adapter manifest, and typed Receipt/Evidence closure are readable and valid, but this read-only check did not exercise writing or exclusive locking",
            "run an authorized state-writing Forge operation before relying on write and lock capability",
        )?,
        terminal_exit_code: None,
        adapter_state: Some(adapter_state),
        adapter_state_invalid: false,
    })
}

fn state_layout_failure(
    detail: String,
    exit_code: ExitCode,
    adapter_state_invalid: bool,
    persisted_contract_failure: bool,
) -> Result<StateLayoutInspection, AppError> {
    let status = match exit_code {
        ExitCode::DataError | ExitCode::Internal => DoctorCheckStatus::Fail,
        ExitCode::Ok
        | ExitCode::Negative
        | ExitCode::EnvironmentUnmet
        | ExitCode::Usage
        | ExitCode::Temporary
        | ExitCode::Timeout
        | ExitCode::Interrupted => DoctorCheckStatus::Unknown,
    };
    let terminal_exit_code = match exit_code {
        ExitCode::Timeout | ExitCode::Interrupted => Some(exit_code),
        ExitCode::DataError if persisted_contract_failure => Some(exit_code),
        ExitCode::Ok
        | ExitCode::Negative
        | ExitCode::EnvironmentUnmet
        | ExitCode::Usage
        | ExitCode::DataError
        | ExitCode::Temporary
        | ExitCode::Internal => None,
    };
    Ok(StateLayoutInspection {
        check: check(
            DoctorCheckId::StateLayout,
            status,
            detail,
            "repair or upgrade the private state without replacing unrecognized data, then rerun `forge doctor`",
        )?,
        terminal_exit_code,
        adapter_state: None,
        adapter_state_invalid,
    })
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct ToolchainRequirements {
    contexts: BTreeMap<ToolchainProbeContext, BTreeSet<ToolchainProbeKind>>,
    unverified_commands: Vec<CommandSpec>,
    has_units: bool,
    has_project_command: bool,
    has_unverified_requirement: bool,
    privacy_unknown: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ToolchainProbeContext {
    cwd: RepoRelativePath,
    environment: BTreeMap<OsString, OsString>,
}

impl ToolchainRequirements {
    fn from_model(model: &ProjectModel) -> Self {
        let mut requirements = Self {
            contexts: BTreeMap::new(),
            unverified_commands: Vec::new(),
            has_units: !model.units.is_empty(),
            has_project_command: false,
            has_unverified_requirement: false,
            privacy_unknown: false,
        };

        for commands in model.commands.values() {
            let Some(commands) = commands.executable_commands() else {
                continue;
            };
            for command in commands {
                if command.enforcement != CommandEnforcement::Required {
                    continue;
                }
                requirements.has_project_command = true;
                requirements.observe_command(command);
            }
        }

        requirements
    }

    fn observe_command(&mut self, command: &CommandSpec) {
        if validate_command_privacy(command).is_err() {
            self.privacy_unknown = true;
            return;
        }
        let Some(probes) = required_probes_for_command(command) else {
            self.has_unverified_requirement = true;
            if !self.unverified_commands.contains(command) {
                self.unverified_commands.push(command.clone());
            }
            return;
        };
        let context = ToolchainProbeContext {
            cwd: command.cwd.clone(),
            environment: command.env.clone(),
        };
        self.contexts.entry(context).or_default().extend(probes);
    }

    fn required_probe_count(&self) -> usize {
        self.contexts.values().map(BTreeSet::len).sum()
    }

    #[cfg(test)]
    fn from_commands(commands: &[CommandSpec]) -> Self {
        let mut requirements = Self {
            contexts: BTreeMap::new(),
            unverified_commands: Vec::new(),
            has_units: !commands.is_empty(),
            has_project_command: false,
            has_unverified_requirement: false,
            privacy_unknown: false,
        };
        for command in commands {
            if command.enforcement != CommandEnforcement::Required {
                continue;
            }
            requirements.has_project_command = true;
            requirements.observe_command(command);
        }
        requirements
    }
}

fn inspect_toolchains(
    runner: &SynchronousProcessRunner,
    requirements: &ToolchainRequirements,
    control: &OperationBudget,
) -> ToolchainInspection {
    let mut inspection = ToolchainInspection::default();
    for command in &requirements.unverified_commands {
        if let Err(error) = control.checkpoint() {
            inspection.record_failure(
                "project-command executable",
                control_toolchain_failure(error),
            );
            break;
        }
        match runner.executable_availability(&ExecSpec::from_project_command(command)) {
            Ok(ExecutableAvailability::Available) => {}
            Ok(ExecutableAvailability::Unavailable) => inspection.record_failure(
                "project-command executable",
                ToolchainProbeFailure::ExecutableUnavailable,
            ),
            Ok(ExecutableAvailability::Unknown) | Err(_) => {}
        }
    }
    for (context, probes) in &requirements.contexts {
        let permit = match control.checkpoint() {
            Ok(permit) => permit,
            Err(error) => {
                let failure = control_toolchain_failure(error);
                inspection.required_probe_count += probes.len();
                for probe in probes {
                    inspection.record_failure(probe.as_str(), failure);
                }
                continue;
            }
        };
        let remaining = permit.cap(DEFAULT_DOCTOR_TOOLCHAIN_BUDGET);
        if remaining.is_zero() {
            inspection.required_probe_count += probes.len();
            for probe in probes {
                inspection.record_failure(probe.as_str(), ToolchainProbeFailure::TimedOut);
            }
            continue;
        }
        let request = ToolchainProbeRequest::for_probes(
            context.cwd.clone(),
            doctor_probe_environment(&context.environment),
            probes.iter().copied(),
        )
        .with_total_timeout(remaining);
        inspection.merge_report(
            probes,
            probe_toolchain_versions_controlled(runner, &request, control),
        );
    }
    inspection
}

const fn control_toolchain_failure(error: OperationControlError) -> ToolchainProbeFailure {
    match error {
        OperationControlError::TimedOut => ToolchainProbeFailure::TimedOut,
        OperationControlError::Interrupted => ToolchainProbeFailure::Interrupted,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct ToolchainInspection {
    versions: BTreeMap<String, String>,
    failures: BTreeMap<String, BTreeSet<ToolchainProbeFailure>>,
    version_conflicts: BTreeSet<String>,
    required_probe_count: usize,
    proven_probe_count: usize,
    missing_probe_count: usize,
    runtime_unavailable: bool,
}

impl ToolchainInspection {
    fn merge_report(
        &mut self,
        expected: &BTreeSet<ToolchainProbeKind>,
        report: ToolchainVersionReport,
    ) {
        self.required_probe_count += expected.len();
        for probe in expected {
            let name = probe.as_str();
            if report.proven().contains(name) {
                self.proven_probe_count += 1;
            } else if let Some(failure) = report.failures().get(name) {
                self.record_failure(name, *failure);
            } else {
                self.missing_probe_count += 1;
            }
        }
        for (name, version) in report.versions() {
            self.record_version(name, version);
        }
    }

    fn record_version(&mut self, name: &str, version: &str) {
        if self.version_conflicts.contains(name) {
            return;
        }
        match self.versions.get(name) {
            Some(existing) if existing != version => {
                self.versions.remove(name);
                self.version_conflicts.insert(name.to_owned());
            }
            Some(_) => {}
            None => {
                self.versions.insert(name.to_owned(), version.to_owned());
            }
        }
    }

    fn record_failure(&mut self, tool: &str, failure: ToolchainProbeFailure) {
        self.failures
            .entry(tool.to_owned())
            .or_default()
            .insert(failure);
    }

    fn terminal_exit_code(&self) -> Option<ExitCode> {
        if self
            .failures
            .values()
            .any(|issues| issues.contains(&ToolchainProbeFailure::Interrupted))
        {
            Some(ExitCode::Interrupted)
        } else if self
            .failures
            .values()
            .any(|issues| issues.contains(&ToolchainProbeFailure::TimedOut))
        {
            Some(ExitCode::Timeout)
        } else if self.runtime_unavailable
            || self
                .failures
                .values()
                .any(|issues| issues.contains(&ToolchainProbeFailure::RuntimeUnavailable))
        {
            Some(ExitCode::EnvironmentUnmet)
        } else {
            None
        }
    }
}

fn toolchain_check(
    requirements: &ToolchainRequirements,
    completion: ModelDetectionCompletion,
    inspection: &ToolchainInspection,
) -> Result<DoctorCheck, AppError> {
    if requirements.privacy_unknown {
        return check(
            DoctorCheckId::ToolchainRequired,
            DoctorCheckStatus::Unknown,
            "one or more required project commands cannot be diagnosed without exposing credential-like metadata",
            "remove credentials from project command metadata and provide them through an approved runtime secret mechanism",
        );
    }
    let failures = formatted_probe_issues(inspection, |failure| {
        matches!(
            failure,
            ToolchainProbeFailure::ExecutableUnavailable | ToolchainProbeFailure::Failed
        )
    });
    if !failures.is_empty() {
        return check(
            DoctorCheckId::ToolchainRequired,
            DoctorCheckStatus::Fail,
            format!("required toolchain probes failed: {failures}"),
            "install or repair the named project tool, then rerun `forge doctor`",
        );
    }

    let completion_detail = match completion {
        ModelDetectionCompletion::Complete => None,
        ModelDetectionCompletion::Partial => {
            Some("project detection was partial, so the complete required tool set is unknown")
        }
        ModelDetectionCompletion::TimedOut => {
            Some("project detection timed out before the complete required tool set was known")
        }
        ModelDetectionCompletion::Interrupted => Some(
            "project detection was interrupted before the complete required tool set was known",
        ),
    };
    if let Some(detail) = completion_detail {
        return check(
            DoctorCheckId::ToolchainRequired,
            DoctorCheckStatus::Unknown,
            detail,
            "resolve the detection diagnostic and rerun `forge doctor`",
        );
    }

    if inspection.runtime_unavailable {
        return check(
            DoctorCheckId::ToolchainRequired,
            DoctorCheckStatus::Unknown,
            "the bounded process runtime was unavailable for required toolchain probes",
            "repair the process runtime and rerun `forge doctor`",
        );
    }
    let unknown = formatted_probe_issues(inspection, |failure| {
        !matches!(
            failure,
            ToolchainProbeFailure::ExecutableUnavailable | ToolchainProbeFailure::Failed
        )
    });
    if !unknown.is_empty() {
        return check(
            DoctorCheckId::ToolchainRequired,
            DoctorCheckStatus::Unknown,
            format!("required toolchain versions could not be proven: {unknown}"),
            "repair the bounded version probe and rerun `forge doctor`",
        );
    }
    if inspection.missing_probe_count > 0 {
        return check(
            DoctorCheckId::ToolchainRequired,
            DoctorCheckStatus::Unknown,
            format!(
                "{} required command dependency probe(s) returned no validated result",
                inspection.missing_probe_count
            ),
            "repair the bounded version probe and rerun `forge doctor`",
        );
    }
    if !inspection.version_conflicts.is_empty() {
        return check(
            DoctorCheckId::ToolchainRequired,
            DoctorCheckStatus::Unknown,
            format!(
                "command contexts reported different versions for {}",
                inspection
                    .version_conflicts
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            "use an explicit consistent toolchain or inspect each command context separately",
        );
    }
    if requirements.has_unverified_requirement {
        return check(
            DoctorCheckId::ToolchainRequired,
            DoctorCheckStatus::Unknown,
            "one or more project commands require a tool without a safe v0 version probe",
            "verify the runner-declared tool explicitly before executing project commands",
        );
    }
    if requirements.contexts.is_empty() {
        return if requirements.has_units || requirements.has_project_command {
            check(
                DoctorCheckId::ToolchainRequired,
                DoctorCheckStatus::Unknown,
                "the detected project requires no tool with a supported v0 version probe",
                "verify the project-declared tools explicitly before executing commands",
            )
        } else {
            check(
                DoctorCheckId::ToolchainRequired,
                DoctorCheckStatus::Pass,
                "the complete project scan found no required language toolchain",
                "no toolchain action is required",
            )
        };
    }
    if inspection.proven_probe_count != inspection.required_probe_count
        || inspection.required_probe_count != requirements.required_probe_count()
    {
        return check(
            DoctorCheckId::ToolchainRequired,
            DoctorCheckStatus::Unknown,
            "not every resolved command dependency has complete bounded probe evidence",
            "repair the incomplete probe and rerun `forge doctor`",
        );
    }

    let observed = inspection
        .versions
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    let version_detail = if observed.is_empty() {
        String::from("no standalone version is exposed")
    } else {
        format!("readable versions: {observed}")
    };
    check(
        DoctorCheckId::ToolchainRequired,
        DoctorCheckStatus::Pass,
        format!(
            "all {} resolved command dependency probes passed; {version_detail}",
            inspection.required_probe_count
        ),
        "use the resolved project commands for further verification",
    )
}

fn formatted_probe_issues(
    inspection: &ToolchainInspection,
    include: impl Fn(ToolchainProbeFailure) -> bool,
) -> String {
    let mut formatted = Vec::new();
    for (tool, issues) in &inspection.failures {
        for issue in issues {
            if include(*issue) {
                formatted.push(format!("{tool} ({})", probe_failure_label(*issue)));
            }
        }
    }
    formatted.join(", ")
}

const fn probe_failure_label(failure: ToolchainProbeFailure) -> &'static str {
    match failure {
        ToolchainProbeFailure::ExecutableUnavailable => "unavailable",
        ToolchainProbeFailure::Failed => "failed",
        ToolchainProbeFailure::TimedOut => "timed out",
        ToolchainProbeFailure::Interrupted => "interrupted",
        ToolchainProbeFailure::Truncated => "output exceeded its bound",
        ToolchainProbeFailure::Malformed => "version output was malformed",
        ToolchainProbeFailure::RuntimeUnavailable => "process runtime was unavailable",
    }
}

fn adapter_check(
    observation: Option<&AdapterObservation>,
    adapter_state_invalid: bool,
) -> Result<DoctorCheck, AppError> {
    if adapter_state_invalid {
        return check(
            DoctorCheckId::AdaptersDrift,
            DoctorCheckStatus::Fail,
            "the private adapter manifest is invalid or cannot be interpreted safely",
            "upgrade Forge for a future manifest, or delete only the rebuildable manifest after reviewing the managed targets",
        );
    }
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
    let workflows: Vec<_> = model
        .assets
        .entries
        .iter()
        .filter(|asset| asset.kind == "ci.github-actions")
        .collect();
    if workflows.is_empty() {
        return check(
            DoctorCheckId::CiVisible,
            DoctorCheckStatus::Unknown,
            "no local GitHub workflow is visible; server-side protection is not observable from this clone",
            "add or identify CI that invokes the required project-native verification entry, then verify hosting-platform protection",
        );
    }
    if model.assets.confidence == Confidence::Unknown {
        return check(
            DoctorCheckId::CiVisible,
            DoctorCheckStatus::Unknown,
            "the repository inventory is incomplete, so the visible workflow set cannot prove CI coverage",
            "repair inventory read failures and rerun `forge doctor`",
        );
    }

    let required = match required_ci_commands(&model.commands) {
        Ok(required) => required,
        Err(detail) => {
            return check(
                DoctorCheckId::CiVisible,
                DoctorCheckStatus::Unknown,
                format!("{detail}; server-side protection is not observable from this clone"),
                "resolve the project verification command and verify hosting-platform protection",
            );
        }
    };
    if let Some(privacy_unknown) = ci_command_privacy_check(&required)? {
        return Ok(privacy_unknown);
    }
    let mut invocations = BTreeSet::new();
    for workflow in &workflows {
        let text = match read_complete_repository_text(model, &workflow.path) {
            Ok(text) => text,
            Err(detail) => {
                return check(
                    DoctorCheckId::CiVisible,
                    DoctorCheckStatus::Unknown,
                    format!(
                        "workflow `{}` could not be completely and safely read: {detail}",
                        workflow.path.as_path().display()
                    ),
                    "repair the workflow path or reduce it below the bounded-read limit, then rerun `forge doctor`",
                );
            }
        };
        let steps = match parse_github_actions_run_steps(&text) {
            Ok(steps) => steps,
            Err(error) => {
                return check(
                    DoctorCheckId::CiVisible,
                    DoctorCheckStatus::Fail,
                    format!(
                        "workflow `{}` is not a complete valid command surface: {error}",
                        workflow.path.as_path().display()
                    ),
                    "repair the workflow YAML before relying on local CI evidence",
                );
            }
        };
        for step in steps {
            if step.conditional || step.shell.is_some() || step.failure_may_be_ignored {
                continue;
            }
            let Some(cwd) = workflow_working_directory(step.working_directory.as_deref()) else {
                continue;
            };
            let Ok(commands) = literal_shell_commands(&step.script) else {
                continue;
            };
            // A single literal command has no preceding shell statement that could terminate,
            // redefine, or conditionally bypass the expected invocation.
            if commands.len() != 1 {
                continue;
            }
            invocations.extend(commands.into_iter().map(|argv| LiteralInvocation {
                cwd: cwd.clone(),
                argv,
            }));
        }
    }

    let mut expected = BTreeSet::new();
    for command in &required {
        let Some(invocation) = literal_invocation(command) else {
            return check(
                DoctorCheckId::CiVisible,
                DoctorCheckStatus::Unknown,
                format!(
                    "required project command `{}` contains a non-UTF-8 program or argument that workflow text cannot prove",
                    command.id
                ),
                "make the project command representation statically comparable or verify CI manually",
            );
        };
        expected.insert(invocation);
    }
    let missing: Vec<_> = expected.difference(&invocations).collect();
    if missing.is_empty() {
        check(
            DoctorCheckId::CiVisible,
            DoctorCheckStatus::Unknown,
            format!(
                "{} safely parsed local workflow(s) invoke all {} required project-native verification command(s), but server-side required-check and branch-protection settings remain unobservable",
                workflows.len(),
                expected.len()
            ),
            "verify required checks and branch protection in the hosting platform",
        )
    } else {
        check(
            DoctorCheckId::CiVisible,
            DoctorCheckStatus::Unknown,
            format!(
                "local workflows do not statically prove invocation of required project command(s): {}; server-side protection is not observable from this clone",
                missing
                    .iter()
                    .map(|invocation| describe_literal_invocation(invocation))
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
            "invoke the required project-native verification entry from CI or verify the unsupported workflow indirection manually",
        )
    }
}

fn ownership_check(
    model: &ProjectModel,
    navigation: &forge_detect::model::NavigationSnapshot,
) -> Result<DoctorCheck, AppError> {
    let mut visible: Vec<_> = model
        .assets
        .entries
        .iter()
        .filter(|asset| asset.kind == "ownership.codeowners")
        .collect();
    if visible.is_empty() {
        return check(
            DoctorCheckId::OwnershipVisible,
            DoctorCheckStatus::Unknown,
            "no conventional CODEOWNERS file is visible",
            "identify the human authority for protected changes before modifying them",
        );
    }
    if model.assets.confidence == Confidence::Unknown
        || model.policy.confidence == Confidence::Unknown
        || navigation.policy_base_completeness != PolicyBaseCompleteness::Complete
    {
        return check(
            DoctorCheckId::OwnershipVisible,
            DoctorCheckStatus::Unknown,
            "repository or effective-policy discovery is incomplete, so visible ownership rules cannot prove high-risk coverage",
            "repair repository and policy discovery before relying on CODEOWNERS coverage",
        );
    }
    if navigation.inventory.entries.iter().any(|entry| {
        entry.kind == forge_core::InventoryKind::Symlink
            && matches!(
                entry.path.to_str(),
                Some(".github/CODEOWNERS" | "CODEOWNERS" | "docs/CODEOWNERS")
            )
    }) {
        return check(
            DoctorCheckId::OwnershipVisible,
            DoctorCheckStatus::Unknown,
            "a conventional CODEOWNERS location is a symbolic link and was not followed",
            "replace the symbolic link with a reviewed regular CODEOWNERS file before relying on visible ownership",
        );
    }

    visible.sort_by_key(|asset| codeowners_precedence(&asset.path));
    let selected = visible[0];
    let text = match read_complete_repository_text(model, &selected.path) {
        Ok(text) => text,
        Err(detail) => {
            return check(
                DoctorCheckId::OwnershipVisible,
                DoctorCheckStatus::Unknown,
                format!(
                    "CODEOWNERS `{}` could not be completely and safely read: {detail}",
                    selected.path.as_path().display()
                ),
                "repair the ownership file path or reduce it below the bounded-read limit, then rerun `forge doctor`",
            );
        }
    };
    let rules = match parse_codeowners(&text) {
        Ok(rules) => rules,
        Err(error) => {
            return check(
                DoctorCheckId::OwnershipVisible,
                DoctorCheckStatus::Fail,
                format!(
                    "CODEOWNERS `{}` has invalid rule syntax: {error}",
                    selected.path.as_path().display()
                ),
                "repair every non-comment CODEOWNERS rule before relying on visible ownership",
            );
        }
    };
    if rules.is_empty() {
        return check(
            DoctorCheckId::OwnershipVisible,
            DoctorCheckStatus::Unknown,
            format!(
                "CODEOWNERS `{}` contains no effective non-comment rule",
                selected.path.as_path().display()
            ),
            "add reviewed owners for the repository's high-risk paths",
        );
    }

    let required_patterns: BTreeSet<_> = navigation
        .effective_policy
        .rules()
        .filter(|rule| matches!(rule.level(), RiskLevel::High | RiskLevel::Critical))
        .flat_map(|rule| {
            rule.paths()
                .iter()
                .map(|pattern| pattern.as_str().to_owned())
        })
        .collect();
    if required_patterns.is_empty() {
        return check(
            DoctorCheckId::OwnershipVisible,
            DoctorCheckStatus::Unknown,
            "the effective policy exposes no high/critical path patterns to verify against CODEOWNERS",
            "repair effective-policy discovery before relying on visible ownership",
        );
    }
    let missing: Vec<_> = required_patterns
        .iter()
        .filter(|risk| {
            !rules
                .iter()
                .any(|rule| codeowners_pattern_covers(&rule.pattern, risk))
        })
        .cloned()
        .collect();
    if missing.is_empty() {
        check(
            DoctorCheckId::OwnershipVisible,
            DoctorCheckStatus::Pass,
            format!(
                "CODEOWNERS `{}` has {} valid rule(s) visibly covering all {} high/critical effective-policy path pattern(s); hosting enforcement remains unobservable",
                selected.path.as_path().display(),
                rules.len(),
                required_patterns.len()
            ),
            "confirm hosting-platform owner-review enforcement for protected changes",
        )
    } else {
        let preview = missing
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        let remainder = missing.len().saturating_sub(5);
        let suffix = if remainder == 0 {
            String::new()
        } else {
            format!(" and {remainder} more")
        };
        check(
            DoctorCheckId::OwnershipVisible,
            DoctorCheckStatus::Unknown,
            format!(
                "CODEOWNERS `{}` does not visibly cover high/critical path pattern(s): {preview}{suffix}",
                selected.path.as_path().display()
            ),
            "add reviewed CODEOWNERS coverage for every high/critical effective-policy path pattern",
        )
    }
}

fn read_complete_repository_text(
    model: &ProjectModel,
    path: &RepoRelativePath,
) -> Result<String, &'static str> {
    let text = NativeFileSystem
        .read_bounded_text(&model.repository.root, path, DOCTOR_VISIBLE_FILE_MAX_BYTES)
        .map_err(|_| "the path is unreadable or traverses a symbolic link")?;
    if text.truncated {
        return Err("the file exceeds the bounded-read limit");
    }
    if text.binary {
        return Err("the file contains binary data");
    }
    String::from_utf8(text.bytes).map_err(|_| "the file is not valid UTF-8")
}

fn required_ci_commands(
    command_sets: &BTreeMap<Intent, ResolvedCommandSet>,
) -> Result<Vec<&CommandSpec>, &'static str> {
    let verify = &command_sets[&Intent::Verify];
    match verify.resolution() {
        CommandResolution::Resolved => {
            if verify.resolution_confidence == Confidence::Unknown {
                return Err("the project verify entry has unknown resolution confidence");
            }
            let required: Vec<_> = verify
                .commands()
                .iter()
                .filter(|command| command.enforcement == CommandEnforcement::Required)
                .collect();
            if required.is_empty() {
                return Err("the resolved project verify entry has no required command");
            }
            if required
                .iter()
                .any(|command| command.confidence == Confidence::Unknown)
            {
                return Err("a required project verify command has unknown confidence");
            }
            return Ok(required);
        }
        CommandResolution::Ambiguous | CommandResolution::Unknown => {
            return Err("the project verify entry is not unambiguously resolved");
        }
        CommandResolution::Absent => {}
    }

    let mut required = Vec::new();
    for intent in [
        Intent::FormatCheck,
        Intent::Check,
        Intent::Test,
        Intent::Build,
    ] {
        let resolved = &command_sets[&intent];
        match resolved.resolution() {
            CommandResolution::Resolved
                if resolved.resolution_confidence != Confidence::Unknown =>
            {
                let resolved_required: Vec<_> = resolved
                    .commands()
                    .iter()
                    .filter(|command| command.enforcement == CommandEnforcement::Required)
                    .collect();
                if resolved_required
                    .iter()
                    .any(|command| command.confidence == Confidence::Unknown)
                {
                    return Err("a required verification command has unknown confidence");
                }
                required.extend(resolved_required);
            }
            CommandResolution::Resolved
            | CommandResolution::Ambiguous
            | CommandResolution::Unknown => {
                return Err("a required verification intent is not unambiguously resolved");
            }
            CommandResolution::Absent => {}
        }
    }
    if required.is_empty() {
        Err("no required project-native verification command is resolved")
    } else {
        Ok(required)
    }
}

fn ci_command_privacy_check(required: &[&CommandSpec]) -> Result<Option<DoctorCheck>, AppError> {
    if required
        .iter()
        .any(|command| validate_command_privacy(command).is_err())
    {
        return check(
            DoctorCheckId::CiVisible,
            DoctorCheckStatus::Unknown,
            "a required project command cannot be compared with local CI without exposing credential-like metadata",
            "remove credentials from project command metadata and provide them through an approved runtime secret mechanism",
        )
        .map(Some);
    }
    Ok(None)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct LiteralInvocation {
    cwd: RepoRelativePath,
    argv: Vec<String>,
}

fn describe_literal_invocation(invocation: &LiteralInvocation) -> String {
    format!(
        "cwd `{}` argv {:?}",
        invocation.cwd.as_path().display(),
        invocation.argv
    )
}

fn literal_invocation(command: &CommandSpec) -> Option<LiteralInvocation> {
    let mut argv = Vec::with_capacity(command.args.len() + 1);
    argv.push(command.program.to_str()?.to_owned());
    argv.extend(
        command
            .args
            .iter()
            .map(|argument| argument.to_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()?,
    );
    Some(LiteralInvocation {
        cwd: command.cwd.clone(),
        argv,
    })
}

fn workflow_working_directory(value: Option<&str>) -> Option<RepoRelativePath> {
    let value = value.unwrap_or(".");
    if value.is_empty() || value.contains("${{") || value.contains('$') || value.contains('`') {
        return None;
    }
    RepoRelativePath::new(value).ok()
}

fn literal_shell_commands(script: &str) -> Result<Vec<Vec<String>>, ()> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Quote {
        None,
        Single,
        Double,
    }

    fn finish_word(word: &mut String, word_started: &mut bool, command: &mut Vec<String>) {
        if *word_started {
            command.push(std::mem::take(word));
            *word_started = false;
        }
    }

    fn finish_command(
        word: &mut String,
        word_started: &mut bool,
        command: &mut Vec<String>,
        commands: &mut Vec<Vec<String>>,
        required: bool,
    ) -> Result<bool, ()> {
        finish_word(word, word_started, command);
        if command.is_empty() {
            return if required { Err(()) } else { Ok(false) };
        }
        if matches!(
            command[0].as_str(),
            "if" | "then"
                | "else"
                | "elif"
                | "fi"
                | "for"
                | "while"
                | "until"
                | "case"
                | "esac"
                | "do"
                | "done"
                | "function"
        ) {
            return Err(());
        }
        commands.push(std::mem::take(command));
        Ok(true)
    }

    let mut characters = script.chars().peekable();
    let mut quote = Quote::None;
    let mut word = String::new();
    let mut word_started = false;
    let mut command = Vec::new();
    let mut commands = Vec::new();
    let mut requires_followup = false;
    while let Some(character) = characters.next() {
        match quote {
            Quote::Single => match character {
                '\'' => quote = Quote::None,
                _ => {
                    word_started = true;
                    word.push(character);
                }
            },
            Quote::Double => match character {
                '"' => quote = Quote::None,
                '$' | '`' => return Err(()),
                '\\' => {
                    word_started = true;
                    word.push(characters.next().ok_or(())?);
                }
                _ => {
                    word_started = true;
                    word.push(character);
                }
            },
            Quote::None => match character {
                '\'' => {
                    word_started = true;
                    quote = Quote::Single;
                }
                '"' => {
                    word_started = true;
                    quote = Quote::Double;
                }
                ' ' | '\t' | '\r' => {
                    finish_word(&mut word, &mut word_started, &mut command);
                }
                '\n' => {
                    if finish_command(
                        &mut word,
                        &mut word_started,
                        &mut command,
                        &mut commands,
                        false,
                    )? {
                        requires_followup = false;
                    }
                }
                '#' if !word_started => {
                    for next in characters.by_ref() {
                        if next == '\n' {
                            break;
                        }
                    }
                    if finish_command(
                        &mut word,
                        &mut word_started,
                        &mut command,
                        &mut commands,
                        false,
                    )? {
                        requires_followup = false;
                    }
                }
                ';' => {
                    finish_command(
                        &mut word,
                        &mut word_started,
                        &mut command,
                        &mut commands,
                        true,
                    )?;
                    requires_followup = false;
                }
                '&' if characters.peek() == Some(&'&') => {
                    characters.next();
                    finish_command(
                        &mut word,
                        &mut word_started,
                        &mut command,
                        &mut commands,
                        true,
                    )?;
                    requires_followup = true;
                }
                '|' | '&' | '<' | '>' | '(' | ')' | '{' | '}' | '$' | '`' => return Err(()),
                '\\' => {
                    let escaped = characters.next().ok_or(())?;
                    if escaped != '\n' {
                        word_started = true;
                        word.push(escaped);
                    }
                }
                _ => {
                    word_started = true;
                    word.push(character);
                }
            },
        }
    }
    if quote != Quote::None {
        return Err(());
    }
    if finish_command(
        &mut word,
        &mut word_started,
        &mut command,
        &mut commands,
        false,
    )? {
        requires_followup = false;
    }
    if requires_followup {
        return Err(());
    }
    Ok(commands)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CodeownersRule {
    pattern: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CodeownersSyntaxError {
    line: usize,
    reason: &'static str,
}

impl std::fmt::Display for CodeownersSyntaxError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "line {} {}", self.line, self.reason)
    }
}

impl std::error::Error for CodeownersSyntaxError {}

fn parse_codeowners(text: &str) -> Result<Vec<CodeownersRule>, CodeownersSyntaxError> {
    let mut rules = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line_number = index + 1;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 2 {
            return Err(CodeownersSyntaxError {
                line: line_number,
                reason: "must contain a pattern followed by at least one owner",
            });
        }
        let pattern = fields[0];
        if pattern.starts_with('!')
            || pattern.contains(['[', ']', '\\'])
            || pattern.contains("//")
            || pattern == "/"
        {
            return Err(CodeownersSyntaxError {
                line: line_number,
                reason: "uses unsupported or invalid pattern syntax",
            });
        }
        if fields[1..].iter().any(|owner| !valid_codeowner(owner)) {
            return Err(CodeownersSyntaxError {
                line: line_number,
                reason: "contains an invalid owner token",
            });
        }
        rules.push(CodeownersRule {
            pattern: pattern.to_owned(),
        });
    }
    Ok(rules)
}

/// Returns whether at least one valid CODEOWNERS rule matches an exact changed path.
///
/// CODEOWNERS intentionally follows gitignore matching for its supported pattern subset. The
/// parser above rejects CODEOWNERS exceptions that gitignore would otherwise interpret
/// differently (`!`, character classes, and backslash escapes), then the already-reviewed
/// gitignore implementation supplies directory and wildcard semantics.
pub(crate) fn codeowners_matches_any_path(
    text: &str,
    repository_root: &std::path::Path,
    changed_paths: &[RepoRelativePath],
) -> Result<bool, CodeownersSyntaxError> {
    let rules = parse_codeowners(text)?;
    let mut builder = GitignoreBuilder::new(repository_root);
    for rule in rules {
        builder
            .add_line(None, &rule.pattern)
            .map_err(|_| CodeownersSyntaxError {
                line: 0,
                reason: "could not be compiled with supported gitignore semantics",
            })?;
    }
    let matcher = builder.build().map_err(|_| CodeownersSyntaxError {
        line: 0,
        reason: "could not be compiled with supported gitignore semantics",
    })?;
    Ok(changed_paths.iter().any(|path| {
        matcher
            .matched_path_or_any_parents(repository_root.join(path.as_path()), false)
            .is_ignore()
    }))
}

fn valid_codeowner(owner: &str) -> bool {
    if let Some(handle) = owner.strip_prefix('@') {
        let mut parts = handle.split('/');
        let organization_or_user = parts.next();
        let team = parts.next();
        return parts.next().is_none()
            && organization_or_user.is_some_and(valid_codeowner_slug)
            && team.is_none_or(valid_codeowner_slug);
    }
    let mut parts = owner.split('@');
    matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some(local), Some(domain), None) if valid_email_local(local) && valid_email_domain(domain)
    )
}

fn valid_codeowner_slug(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-')
}

fn valid_email_local(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('.')
        && !value.ends_with('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
}

fn valid_email_domain(value: &str) -> bool {
    let labels = value.split('.').collect::<Vec<_>>();
    labels.len() >= 2 && labels.into_iter().all(valid_codeowner_slug)
}

fn codeowners_precedence(path: &RepoRelativePath) -> u8 {
    match path.as_path().to_str() {
        Some(".github/CODEOWNERS") => 0,
        Some("CODEOWNERS") => 1,
        Some("docs/CODEOWNERS") => 2,
        _ => 3,
    }
}

fn codeowners_pattern_covers(codeowners: &str, risk: &str) -> bool {
    let codeowners = codeowners.strip_prefix('/').unwrap_or(codeowners);
    if matches!(codeowners, "*" | "**") || codeowners == risk {
        return true;
    }
    let Some(prefix) = codeowners.strip_suffix("/**") else {
        return false;
    };
    !prefix.is_empty() && (risk == prefix || risk.starts_with(&format!("{prefix}/")))
}

fn path_safety_check(
    navigation: &forge_detect::model::NavigationSnapshot,
    adapters: Option<&AdapterObservation>,
    target_safety: &adapters::AdapterTargetSafety,
) -> Result<DoctorCheck, AppError> {
    match target_safety {
        adapters::AdapterTargetSafety::Unsafe { path } => {
            return check(
                DoctorCheckId::PathSafety,
                DoctorCheckStatus::Fail,
                format!(
                    "selected managed target `{}` is a symbolic link, directory, or otherwise unsafe regular-file target",
                    path.as_path().display()
                ),
                "replace the target with a reviewed regular file or disable that adapter before allowing Forge writes",
            );
        }
        adapters::AdapterTargetSafety::Unknown { reason } => {
            return check(
                DoctorCheckId::PathSafety,
                DoctorCheckStatus::Unknown,
                *reason,
                "repair the bounded target inspection and rerun `forge doctor`",
            );
        }
        adapters::AdapterTargetSafety::Safe { .. } => {}
    }
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
    let inspected_targets = match target_safety {
        adapters::AdapterTargetSafety::Safe { inspected_targets } => *inspected_targets,
        adapters::AdapterTargetSafety::Unsafe { .. }
        | adapters::AdapterTargetSafety::Unknown { .. } => 0,
    };
    check(
        DoctorCheckId::PathSafety,
        DoctorCheckStatus::Pass,
        format!(
            "repository inventory and {inspected_targets} automatically selected managed target confinement check(s) completed"
        ),
        "no path-safety repair is required",
    )
}

fn process_capability_check(completion: ModelDetectionCompletion) -> Result<DoctorCheck, AppError> {
    let capability = process_tree_capability();
    let backend = match capability {
        ProcessTreeCapability::UnixProcessGroup => "Unix process-group isolation",
        ProcessTreeCapability::WindowsJobObject => "Windows Job Object isolation",
        ProcessTreeCapability::Unsupported => {
            return skipped_check(
                DoctorCheckId::ProcessCapability,
                DoctorSkipReason::PlatformLimitation,
                "this target has no complete process-tree isolation backend",
                "use a supported Unix or Windows target before relying on bounded execution",
            );
        }
    };
    let (status, detail, next) = match completion {
        ModelDetectionCompletion::Complete => (
            DoctorCheckStatus::Pass,
            format!("the compiled runtime provides {backend} for timeout and cancellation"),
            "no local process-runtime repair is required",
        ),
        ModelDetectionCompletion::Partial => (
            DoctorCheckStatus::Unknown,
            format!(
                "the compiled runtime provides {backend}, but project detection completed only partially"
            ),
            "repair partial detection before relying on bounded project-command execution",
        ),
        ModelDetectionCompletion::TimedOut => (
            DoctorCheckStatus::Unknown,
            format!(
                "a detection subprocess timed out under {backend}, but this check did not independently inspect for surviving descendants"
            ),
            "inspect for surviving child processes, then repair or retry with an appropriate timeout",
        ),
        ModelDetectionCompletion::Interrupted => (
            DoctorCheckStatus::Unknown,
            format!(
                "a detection subprocess was interrupted under {backend}, but this check did not independently inspect for surviving descendants"
            ),
            "inspect for surviving child processes, then rerun `forge doctor` when ready",
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

fn skipped_check(
    id: DoctorCheckId,
    reason: DoctorSkipReason,
    detail: impl Into<String>,
    next: impl Into<String>,
) -> Result<DoctorCheck, AppError> {
    DoctorCheck::new(id, DoctorCheckStatus::Skipped, detail, next, Some(reason))
        .map_err(map_validation_error)
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
        skip_reason: check.skip_reason().map(skip_reason_to_wire),
        detail: check.detail().to_owned(),
        next: check.next().to_owned(),
    }
}

const fn skip_reason_to_wire(reason: DoctorSkipReason) -> DoctorSkipReasonData {
    match reason {
        DoctorSkipReason::UserFlag => DoctorSkipReasonData::UserFlag,
        DoctorSkipReason::PlatformLimitation => DoctorSkipReasonData::PlatformLimitation,
        DoctorSkipReason::Budget => DoctorSkipReasonData::Budget,
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

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::ffi::OsString;
    use std::path::Path;
    use std::time::Duration;

    use forge_core::doctor::{DoctorCheck, DoctorCheckId, DoctorCheckStatus, DoctorSkipReason};
    use forge_core::domain::CommandEnforcement;
    use forge_core::{
        CommandSource, CommandSpec, Confidence, ExitCode, Intent, Provenance, RepoRelativePath,
        ResolvedCommandSet,
    };
    use forge_detect::model::ModelDetectionCompletion;
    use forge_runtime::toolchain::{ToolchainProbeFailure, ToolchainProbeKind};
    use forge_schema::{CheckStatusData, DoctorData};

    use super::{
        DoctorOutcome, ToolchainInspection, ToolchainRequirements, check_to_wire,
        ci_command_privacy_check, codeowners_matches_any_path, codeowners_pattern_covers,
        doctor_probe_environment, literal_shell_commands, parse_codeowners,
        process_capability_check, remaining_toolchain_budget, render_human, required_ci_commands,
        state_layout_failure, toolchain_check,
    };

    fn provenance() -> Vec<Provenance> {
        vec![Provenance {
            rule_id: String::from("test.fixture"),
            source_path: None,
            source_range: None,
            detail: String::from("test evidence"),
        }]
    }

    fn intent_command<const N: usize>(id: &str, intent: Intent, args: [&str; N]) -> CommandSpec {
        CommandSpec::new(
            id,
            intent,
            "cargo",
            RepoRelativePath::root(),
            CommandSource::ExplicitConfig,
        )
        .with_args(args)
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
    fn doctor_toolchain_probes_disable_implicit_downloads() {
        let environment = doctor_probe_environment(&BTreeMap::new());

        assert_eq!(
            environment
                .overrides
                .get(&OsString::from("CARGO_NET_OFFLINE")),
            Some(&OsString::from("true"))
        );
        assert_eq!(
            environment.overrides.get(&OsString::from("GOTOOLCHAIN")),
            Some(&OsString::from("local"))
        );
    }

    #[test]
    fn state_layout_promotes_only_control_termination_and_persisted_contract_failures()
    -> Result<(), forge_core::AppError> {
        for exit_code in [
            ExitCode::Ok,
            ExitCode::Negative,
            ExitCode::EnvironmentUnmet,
            ExitCode::Usage,
            ExitCode::DataError,
            ExitCode::Temporary,
            ExitCode::Internal,
        ] {
            assert_eq!(
                state_layout_failure(String::from("fixture"), exit_code, false, false)?
                    .terminal_exit_code,
                None,
                "ordinary state failure {exit_code:?} escaped the Doctor report boundary",
            );
        }
        for exit_code in [ExitCode::Timeout, ExitCode::Interrupted] {
            assert_eq!(
                state_layout_failure(String::from("fixture"), exit_code, false, false)?
                    .terminal_exit_code,
                Some(exit_code),
            );
        }
        assert_eq!(
            state_layout_failure(String::from("fixture"), ExitCode::DataError, false, true)?
                .terminal_exit_code,
            Some(ExitCode::DataError),
        );
        Ok(())
    }

    #[test]
    fn skipped_checks_retain_their_typed_wire_reason() -> Result<(), Box<dyn std::error::Error>> {
        let check = DoctorCheck::new(
            DoctorCheckId::ProcessCapability,
            DoctorCheckStatus::Skipped,
            "platform backend is unavailable",
            "use a supported platform",
            Some(DoctorSkipReason::PlatformLimitation),
        )?;

        let wire = check_to_wire(&check);
        assert_eq!(wire.status, CheckStatusData::Skipped);
        assert_eq!(
            wire.skip_reason,
            Some(forge_schema::DoctorSkipReasonData::PlatformLimitation)
        );
        Ok(())
    }

    #[test]
    fn unsafe_required_commands_produce_only_generic_doctor_output()
    -> Result<(), Box<dyn std::error::Error>> {
        let secret = "doctor-secret-sentinel";
        let mut unsafe_command =
            intent_command("unsafe-check", Intent::Check, ["check", "--token", secret]);
        unsafe_command
            .env
            .insert(OsString::from("API_TOKEN"), OsString::from(secret));

        let requirements = ToolchainRequirements::from_commands(&[unsafe_command.clone()]);
        assert!(requirements.privacy_unknown);
        assert!(requirements.contexts.is_empty());
        let toolchain = toolchain_check(
            &requirements,
            ModelDetectionCompletion::Complete,
            &ToolchainInspection::default(),
        )?;
        let ci = ci_command_privacy_check(&[&unsafe_command])?.ok_or_else(|| {
            std::io::Error::other("unsafe required CI command was not marked unknown")
        })?;
        assert_eq!(toolchain.status(), DoctorCheckStatus::Unknown);
        assert_eq!(ci.status(), DoctorCheckStatus::Unknown);

        let outcome = DoctorOutcome {
            wire: DoctorData {
                overall: CheckStatusData::Unknown,
                checks: vec![check_to_wire(&toolchain), check_to_wire(&ci)],
                tool_versions: BTreeMap::new(),
                assumptions: Vec::new(),
            },
            exit_code: ExitCode::Negative,
            checks: vec![toolchain, ci],
            toolchain_runtime_unavailable: false,
        };
        for output in [
            render_human(&outcome),
            serde_json::to_string(&outcome.wire)?,
            format!("{outcome:?}"),
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

    #[test]
    fn benign_environment_and_unrelated_unsafe_commands_do_not_block_doctor()
    -> Result<(), Box<dyn std::error::Error>> {
        let secret = "unrelated-doctor-secret";
        let mut safe = intent_command("safe-check", Intent::Check, ["check"]);
        safe.env
            .insert(OsString::from("AUTHOR"), OsString::from("Ada"));
        safe.env
            .insert(OsString::from("BUILD_REGION"), OsString::from("us-east-1"));
        let mut advisory = intent_command("advisory", Intent::Fix, ["fix", "--token", secret]);
        advisory.enforcement = CommandEnforcement::Advisory;

        let requirements = ToolchainRequirements::from_commands(&[safe.clone(), advisory]);
        assert!(!requirements.privacy_unknown);
        assert!(requirements.contexts.keys().any(|context| {
            context.environment.contains_key(&OsString::from("AUTHOR"))
                && context
                    .environment
                    .contains_key(&OsString::from("BUILD_REGION"))
        }));

        let verify = intent_command("safe-verify", Intent::Verify, ["test"]);
        let unrelated = intent_command("unsafe-setup", Intent::Setup, ["setup", "--token", secret]);
        let mut command_sets = Intent::ALL
            .into_iter()
            .map(|intent| {
                (
                    intent,
                    ResolvedCommandSet::absent(provenance(), Confidence::High),
                )
            })
            .collect::<BTreeMap<_, _>>();
        command_sets.insert(Intent::Verify, resolved(verify)?);
        command_sets.insert(Intent::Setup, resolved(unrelated)?);
        let required = required_ci_commands(&command_sets).map_err(std::io::Error::other)?;
        assert_eq!(required.len(), 1);
        assert!(ci_command_privacy_check(&required)?.is_none());
        Ok(())
    }

    #[test]
    fn global_timeout_is_a_remaining_total_budget_with_a_safe_default_cap() {
        assert_eq!(
            remaining_toolchain_budget(Some(Duration::from_millis(75)), Duration::from_millis(25),),
            Duration::from_millis(50)
        );
        assert_eq!(
            remaining_toolchain_budget(Some(Duration::from_millis(25)), Duration::from_millis(30),),
            Duration::ZERO
        );
        assert_eq!(
            remaining_toolchain_budget(None, Duration::from_secs(60)),
            super::DEFAULT_DOCTOR_TOOLCHAIN_BUDGET
        );
    }

    #[test]
    fn shell_evidence_requires_literal_commands_at_command_boundaries() {
        assert_eq!(
            literal_shell_commands(
                "# cargo test is documentation\necho 'cargo test'\ncargo check && cargo test\n"
            ),
            Ok(vec![
                vec![String::from("echo"), String::from("cargo test")],
                vec![String::from("cargo"), String::from("check")],
                vec![String::from("cargo"), String::from("test")],
            ])
        );
        assert_eq!(
            literal_shell_commands("cargo test \"\""),
            Ok(vec![vec![
                String::from("cargo"),
                String::from("test"),
                String::new(),
            ]])
        );
        for unsupported in [
            "cargo test &&",
            "cargo test | tee result",
            "if true; then cargo test; fi",
            "cargo $COMMAND",
        ] {
            assert!(
                literal_shell_commands(unsupported).is_err(),
                "{unsupported}"
            );
        }
    }

    #[test]
    fn codeowners_requires_valid_owners_and_conservative_pattern_coverage()
    -> Result<(), Box<dyn std::error::Error>> {
        let rules = parse_codeowners(
            "# reviewed ownership\n/.github/workflows/** @org/platform\ndocs/adr/** architect@example.com\n",
        )?;
        assert_eq!(rules.len(), 2);
        assert!(codeowners_pattern_covers(
            &rules[0].pattern,
            ".github/workflows/**"
        ));
        assert!(codeowners_pattern_covers(
            &rules[1].pattern,
            "docs/adr/security/**"
        ));
        assert!(!codeowners_pattern_covers(&rules[1].pattern, "SECURITY.md"));
        assert!(codeowners_pattern_covers("*", "**/migrations/**"));

        for invalid in [
            "docs/**\n",
            "!docs/** @owner\n",
            "docs/[ab] @owner\n",
            "docs/** owner-without-email\n",
            "docs/** @owner/team/extra\n",
            "docs/** @-owner\n",
            "docs/** person@.example\n",
            "docs/** @owner # inline comments are not valid owners\n",
        ] {
            assert!(parse_codeowners(invalid).is_err(), "{invalid}");
        }
        Ok(())
    }

    #[test]
    fn codeowners_path_matching_reuses_supported_gitignore_semantics()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = Path::new("repository");
        assert!(codeowners_matches_any_path(
            "src/** @org/source\n",
            root,
            &[RepoRelativePath::new("src/lib.rs")?],
        )?);
        assert!(codeowners_matches_any_path(
            "*.rs @org/rust\n",
            root,
            &[RepoRelativePath::new("nested/lib.rs")?],
        )?);
        assert!(codeowners_matches_any_path(
            "/docs/ @org/docs\n",
            root,
            &[RepoRelativePath::new("docs/adr/0001.md")?],
        )?);
        assert!(!codeowners_matches_any_path(
            "docs/** @org/docs\n",
            root,
            &[RepoRelativePath::new("src/lib.rs")?],
        )?);
        Ok(())
    }

    #[test]
    fn complete_repository_without_units_or_commands_needs_no_toolchain()
    -> Result<(), Box<dyn std::error::Error>> {
        let requirements = ToolchainRequirements {
            contexts: Default::default(),
            unverified_commands: Vec::new(),
            has_units: false,
            has_project_command: false,
            has_unverified_requirement: false,
            privacy_unknown: false,
        };

        let check = toolchain_check(
            &requirements,
            ModelDetectionCompletion::Complete,
            &ToolchainInspection::default(),
        )?;

        assert_eq!(check.status(), DoctorCheckStatus::Pass);
        Ok(())
    }

    #[test]
    fn partial_detection_never_upgrades_an_empty_requirement_set_to_pass()
    -> Result<(), Box<dyn std::error::Error>> {
        let requirements = ToolchainRequirements {
            contexts: Default::default(),
            unverified_commands: Vec::new(),
            has_units: false,
            has_project_command: false,
            has_unverified_requirement: false,
            privacy_unknown: false,
        };

        let check = toolchain_check(
            &requirements,
            ModelDetectionCompletion::Partial,
            &ToolchainInspection::default(),
        )?;

        assert_eq!(check.status(), DoctorCheckStatus::Unknown);
        Ok(())
    }

    #[test]
    fn a_required_command_without_a_probe_result_is_unknown()
    -> Result<(), Box<dyn std::error::Error>> {
        let requirements =
            ToolchainRequirements::from_commands(&[command("cargo", ["check"], ".")?]);

        let check = toolchain_check(
            &requirements,
            ModelDetectionCompletion::Complete,
            &ToolchainInspection::default(),
        )?;

        assert_eq!(check.status(), DoctorCheckStatus::Unknown);
        assert!(
            check
                .detail()
                .contains("not every resolved command dependency")
        );
        Ok(())
    }

    #[test]
    fn advisory_commands_do_not_become_required_toolchain_dependencies()
    -> Result<(), Box<dyn std::error::Error>> {
        let required = command("cargo", ["check"], ".")?;
        let mut advisory = command("project-advisory-linter", ["scan"], ".")?;
        advisory.enforcement = CommandEnforcement::Advisory;

        let requirements = ToolchainRequirements::from_commands(&[required, advisory]);

        assert_eq!(requirements.required_probe_count(), 2);
        assert!(!requirements.has_unverified_requirement);
        assert!(requirements.has_project_command);
        Ok(())
    }

    #[test]
    fn definite_tool_failures_fail_while_incomplete_evidence_stays_unknown()
    -> Result<(), Box<dyn std::error::Error>> {
        let requirements =
            ToolchainRequirements::from_commands(&[command("cargo", ["check"], ".")?]);
        for failure in [
            ToolchainProbeFailure::ExecutableUnavailable,
            ToolchainProbeFailure::Failed,
        ] {
            let inspection = inspection_with_failure(failure);
            let check = toolchain_check(
                &requirements,
                ModelDetectionCompletion::Complete,
                &inspection,
            )?;
            assert_eq!(check.status(), DoctorCheckStatus::Fail);
            assert_eq!(inspection.terminal_exit_code(), None);
        }
        for failure in [
            ToolchainProbeFailure::Truncated,
            ToolchainProbeFailure::Malformed,
        ] {
            let inspection = inspection_with_failure(failure);
            let check = toolchain_check(
                &requirements,
                ModelDetectionCompletion::Complete,
                &inspection,
            )?;
            assert_eq!(check.status(), DoctorCheckStatus::Unknown);
            assert_eq!(inspection.terminal_exit_code(), None);
        }
        Ok(())
    }

    #[test]
    fn probe_timeout_and_runtime_failure_keep_stable_exit_codes()
    -> Result<(), Box<dyn std::error::Error>> {
        let requirements =
            ToolchainRequirements::from_commands(&[command("cargo", ["check"], ".")?]);
        for (failure, exit_code) in [
            (ToolchainProbeFailure::TimedOut, ExitCode::Timeout),
            (
                ToolchainProbeFailure::RuntimeUnavailable,
                ExitCode::EnvironmentUnmet,
            ),
            (ToolchainProbeFailure::Interrupted, ExitCode::Interrupted),
        ] {
            let inspection = inspection_with_failure(failure);
            let check = toolchain_check(
                &requirements,
                ModelDetectionCompletion::Complete,
                &inspection,
            )?;
            assert_eq!(check.status(), DoctorCheckStatus::Unknown);
            assert_eq!(inspection.terminal_exit_code(), Some(exit_code));
        }
        Ok(())
    }

    fn inspection_with_failure(failure: ToolchainProbeFailure) -> ToolchainInspection {
        ToolchainInspection {
            versions: BTreeMap::new(),
            failures: BTreeMap::from([(String::from("cargo"), BTreeSet::from([failure]))]),
            required_probe_count: 1,
            runtime_unavailable: false,
            ..ToolchainInspection::default()
        }
    }

    fn command<const N: usize>(
        program: &str,
        args: [&str; N],
        cwd: &str,
    ) -> Result<CommandSpec, Box<dyn std::error::Error>> {
        Ok(CommandSpec::new(
            format!("fixture-{program}-{cwd}"),
            Intent::Check,
            program,
            RepoRelativePath::new(cwd)?,
            CommandSource::ExplicitConfig,
        )
        .with_args(args))
    }

    #[test]
    fn command_grammar_requires_components_without_guessing_plugins()
    -> Result<(), Box<dyn std::error::Error>> {
        for subcommand in ["check", "test", "build"] {
            let rust =
                ToolchainRequirements::from_commands(&[command("cargo", [subcommand], ".")?]);
            assert_eq!(
                rust.contexts.values().next(),
                Some(&BTreeSet::from([
                    ToolchainProbeKind::Cargo,
                    ToolchainProbeKind::Rustc,
                ]))
            );
        }
        let fmt = ToolchainRequirements::from_commands(&[command("cargo", ["fmt"], ".")?]);
        assert_eq!(
            fmt.contexts.values().next(),
            Some(&BTreeSet::from([
                ToolchainProbeKind::Cargo,
                ToolchainProbeKind::CargoFmt,
            ]))
        );
        let clippy = ToolchainRequirements::from_commands(&[command("cargo", ["clippy"], ".")?]);
        assert_eq!(
            clippy.contexts.values().next(),
            Some(&BTreeSet::from([
                ToolchainProbeKind::Cargo,
                ToolchainProbeKind::Rustc,
                ToolchainProbeKind::CargoClippy,
            ]))
        );
        for subcommand in ["test", "build", "vet"] {
            let go = ToolchainRequirements::from_commands(&[command("go", [subcommand], ".")?]);
            assert_eq!(
                go.contexts.values().next(),
                Some(&BTreeSet::from([ToolchainProbeKind::Go]))
            );
        }
        let gofmt = ToolchainRequirements::from_commands(&[command("gofmt", ["-l"], ".")?]);
        assert_eq!(
            gofmt.contexts.values().next(),
            Some(&BTreeSet::from([
                ToolchainProbeKind::Go,
                ToolchainProbeKind::Gofmt,
            ]))
        );
        for args in [["audit"], ["+nightly"]] {
            let unknown = ToolchainRequirements::from_commands(&[command("cargo", args, ".")?]);
            assert!(unknown.has_unverified_requirement);
            assert!(unknown.contexts.is_empty());
        }
        Ok(())
    }

    #[test]
    fn command_contexts_preserve_cwd_and_environment_and_deduplicate()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut root = command("cargo", ["check"], ".")?;
        root.env
            .insert(OsString::from("RUSTUP_TOOLCHAIN"), OsString::from("stable"));
        let duplicate = root.clone();
        let mut nested = command("cargo", ["check"], "nested")?;
        nested.env.insert(
            OsString::from("RUSTUP_TOOLCHAIN"),
            OsString::from("nightly"),
        );

        let requirements = ToolchainRequirements::from_commands(&[root, duplicate, nested]);

        assert_eq!(requirements.contexts.len(), 2);
        assert_eq!(requirements.required_probe_count(), 4);
        assert!(requirements.contexts.keys().any(|context| {
            context.cwd.as_path() == std::path::Path::new("nested")
                && context.environment.get(&OsString::from("RUSTUP_TOOLCHAIN"))
                    == Some(&OsString::from("nightly"))
        }));
        Ok(())
    }

    #[test]
    fn missing_components_fail_and_unrepresentable_versions_stay_unknown()
    -> Result<(), Box<dyn std::error::Error>> {
        for (program, args, missing) in
            [("cargo", ["fmt"], "cargo-fmt"), ("gofmt", ["-l"], "gofmt")]
        {
            let requirements =
                ToolchainRequirements::from_commands(&[command(program, args, ".")?]);
            let inspection = ToolchainInspection {
                failures: BTreeMap::from([(
                    String::from(missing),
                    BTreeSet::from([ToolchainProbeFailure::ExecutableUnavailable]),
                )]),
                required_probe_count: requirements.required_probe_count(),
                ..ToolchainInspection::default()
            };
            assert_eq!(
                toolchain_check(
                    &requirements,
                    ModelDetectionCompletion::Complete,
                    &inspection,
                )?
                .status(),
                DoctorCheckStatus::Fail
            );
        }

        let requirements =
            ToolchainRequirements::from_commands(&[command("cargo", ["check"], ".")?]);
        let mut inspection = ToolchainInspection {
            required_probe_count: 2,
            proven_probe_count: 2,
            ..ToolchainInspection::default()
        };
        inspection.record_version("rustc", "1.85.0");
        inspection.record_version("rustc", "1.86.0");
        assert!(!inspection.versions.contains_key("rustc"));
        assert!(inspection.version_conflicts.contains("rustc"));
        assert_eq!(
            toolchain_check(
                &requirements,
                ModelDetectionCompletion::Complete,
                &inspection,
            )?
            .status(),
            DoctorCheckStatus::Unknown
        );
        Ok(())
    }

    #[test]
    fn process_capability_uses_the_compiled_backend_without_overstating_failed_runs()
    -> Result<(), Box<dyn std::error::Error>> {
        let complete = process_capability_check(ModelDetectionCompletion::Complete)?;
        if forge_runtime::process::process_tree_capability()
            == forge_runtime::process::ProcessTreeCapability::Unsupported
        {
            assert_eq!(complete.status(), DoctorCheckStatus::Skipped);
        } else {
            assert_eq!(complete.status(), DoctorCheckStatus::Pass);
        }
        for completion in [
            ModelDetectionCompletion::Partial,
            ModelDetectionCompletion::TimedOut,
            ModelDetectionCompletion::Interrupted,
        ] {
            let check = process_capability_check(completion)?;
            let expected = if forge_runtime::process::process_tree_capability()
                == forge_runtime::process::ProcessTreeCapability::Unsupported
            {
                DoctorCheckStatus::Skipped
            } else {
                DoctorCheckStatus::Unknown
            };
            assert_eq!(check.status(), expected);
        }
        Ok(())
    }
}
