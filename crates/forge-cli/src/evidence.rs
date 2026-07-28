//! Execution and persistence boundary for `forge evidence run`.
//!
//! The project model remains authoritative: this module executes only an explicitly resolved
//! command chain, preserves its argv representation, and records a typed Receipt without retaining
//! raw child output.

use std::fmt::Write as _;
use std::time::{Duration, Instant};

use forge_core::domain::CommandEnforcement;
use forge_core::evidence::{
    BaseTaskDependency, CommandEvidenceObservation, DependencyValue, EvidenceDependencyFingerprint,
    EvidenceOutcome, ExecutionDependencyFingerprint, ProcessOutcomeInput,
    aggregate_command_evidence, normalize_evidence_outcome,
};
use forge_core::fingerprint::{
    aggregate_ordered_execution_dependencies, bind_command_set_confidence,
    command_dependency_digest, evidence_behavior_digest, process_output_unavailable_digests,
    validate_command_privacy, worktree_base_task_dependency,
};
use forge_core::ports::{
    Clock, DEFAULT_CAPTURE_LIMIT_BYTES, ExecSpec, Hasher, OutputPolicy, ProcessError,
    ProcessObservation, ProcessPort,
};
use forge_core::scope::{PreparedScope, ScopeHead, scope_dependency_digest};
use forge_core::{
    AppError, CommandSpec, Confidence, ExitCode, Intent, OperationControl, OperationControlError,
    ProjectModel, ProjectModelWireError, WorkState, command_detail_v2_to_wire,
    comparison_basis_v2_to_wire, coverage_dimension_name, evidence_outcome_to_wire, intent_to_wire,
    process_error_kind_to_wire, receipt_dependencies_v2_to_wire,
};
use forge_detect::model::ModelDetectionCompletion;
use forge_detect::policy::PolicyBaseCompleteness;
use forge_runtime::clock::SystemClock;
use forge_runtime::control::OperationBudget;
use forge_runtime::git::GitCli;
use forge_runtime::hash::Blake3Hasher;
use forge_runtime::process::{
    SynchronousProcessRunner, empty_process_output_digests, process_environment_dependency_digest,
};
use forge_runtime::scope::{ScopeAcquisitionError, acquire_repository_scope_controlled};
use forge_runtime::state::{
    AtomicStateStore, EvidenceStateDecodeError, GitStateLayout, StateError, format_utc_rfc3339,
};
use forge_runtime::toolchain::{
    ToolchainProbeRequest, probe_toolchain_dependency_digest_controlled,
    required_probes_for_command,
};
use forge_schema::{
    CommandDiagnosticSummaryStateV2Data, CommandDiagnosticSummaryV2Data, CommandObservationV2Data,
    ConfidenceData, Diagnostic, Envelope, ReceiptId, ReceiptV2Data, SchemaKind, Severity,
};

use crate::args::{Cli, EvidenceRunArgs, IntentChoice};
use crate::evidence_state::{JsonEvidenceStateCodec, prepare_receipt};
use crate::explain;

const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EvidenceRunOutcome {
    pub(crate) receipt_bytes: Vec<u8>,
    pub(crate) receipt_object: String,
    pub(crate) intent: Intent,
    pub(crate) outcome: EvidenceOutcome,
    pub(crate) observation_count: usize,
    pub(crate) non_proving_reasons: Vec<&'static str>,
    pub(crate) exit_code: ExitCode,
}

#[derive(Debug)]
struct CommandChainResult {
    observations: Vec<CommandObservationV2Data>,
    aggregate_inputs: Vec<CommandEvidenceObservation>,
    execution_dependencies: Vec<ExecutionDependencyFingerprint>,
    duration_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CommandExecutionPolicy {
    output_limit_bytes: usize,
    timeout_override: Option<Duration>,
}

fn observed_diagnostic_summary(
    stdout_total_bytes: u64,
    stderr_total_bytes: u64,
) -> CommandDiagnosticSummaryV2Data {
    CommandDiagnosticSummaryV2Data {
        state: CommandDiagnosticSummaryStateV2Data::Observed,
        stdout_total_bytes: Some(stdout_total_bytes),
        stderr_total_bytes: Some(stderr_total_bytes),
    }
}

fn unavailable_diagnostic_summary() -> CommandDiagnosticSummaryV2Data {
    CommandDiagnosticSummaryV2Data {
        state: CommandDiagnosticSummaryStateV2Data::Unavailable,
        stdout_total_bytes: None,
        stderr_total_bytes: None,
    }
}

impl Default for CommandExecutionPolicy {
    fn default() -> Self {
        Self {
            output_limit_bytes: DEFAULT_CAPTURE_LIMIT_BYTES,
            timeout_override: None,
        }
    }
}

#[derive(Debug)]
enum CommandChainError {
    Projection(ProjectModelWireError),
}

pub(crate) fn execute_controlled<F>(
    cli: &Cli,
    args: &EvidenceRunArgs,
    control: &OperationBudget,
    before_run: F,
) -> Result<EvidenceRunOutcome, AppError>
where
    F: FnOnce(&[CommandSpec]) -> Result<(), AppError>,
{
    execute_with_clock_controlled(cli, args, control, &SystemClock, before_run)
}

fn execute_with_clock_controlled<C, F>(
    cli: &Cli,
    args: &EvidenceRunArgs,
    control: &OperationBudget,
    clock: &C,
    before_run: F,
) -> Result<EvidenceRunOutcome, AppError>
where
    C: Clock + ?Sized,
    F: FnOnce(&[CommandSpec]) -> Result<(), AppError>,
{
    let detected = explain::detect_controlled(cli, control)?;
    require_usable_detection(detected.completion)?;
    require_compatible_work_state(detected.model.repository.work_state)?;

    let intent = intent_from_choice(args.intent);
    let command_set =
        detected.model.commands.get(&intent).ok_or_else(|| {
            unresolved_intent_error(intent, "the detected model has no intent entry")
        })?;
    let commands = command_set.executable_commands().ok_or_else(|| {
        unresolved_intent_error(
            intent,
            "the intent is absent, ambiguous, or unknown rather than explicitly resolved",
        )
    })?;
    if commands.is_empty() {
        return Err(unresolved_intent_error(
            intent,
            "the resolved intent contains no executable command",
        ));
    }

    // Command projection and the human preview intentionally preserve argv and environment names.
    // Reject credential-like literals before either output or any evidence-specific subprocess can
    // observe the selected command.
    validate_command_chain_privacy(commands)?;

    // Detection already projects the complete model, but project each selected command before any
    // side effect so a future wire incompatibility cannot be discovered only after a mutating run.
    for command in commands {
        command_detail_v2_to_wire(command).map_err(map_projection_error)?;
    }

    // Establish and fully validate the private state boundary before previewing or running any
    // project command. Holding the worktree lock through persistence prevents a pre-existing lock,
    // malformed object, unsafe ACL, or recoverable GC residue from being discovered only after a
    // project side effect has already occurred.
    control
        .checkpoint()
        .map_err(|error| explain::map_operation_control_error(error, "evidence state preflight"))?;
    let layout = GitStateLayout::new(
        detected.model.repository.git_dir.clone(),
        detected.model.repository.git_common_dir.clone(),
    );
    let store = AtomicStateStore::new_evidence(layout).map_err(map_state_error)?;
    let lock = store.try_lock().map_err(map_state_error)?;
    let codec = JsonEvidenceStateCodec;
    let log_max_bytes = crate::evidence_view::configured_log_max_bytes(&detected)?;
    // Validate the complete retained closure before project side effects, but do not collect it.
    // ADR-0021 permits GC only after the new immutable Receipt has been persisted successfully.
    store
        .visit_evidence_state_snapshot_controlled(log_max_bytes, &codec, control, |_| {
            control.checkpoint().map(|_| ()).map_err(|error| {
                std::io::Error::new(operation_control_io_kind(error), error.to_string())
            })
        })
        .map_err(map_state_error)?;
    control
        .checkpoint()
        .map_err(|error| explain::map_operation_control_error(error, "project command preview"))?;
    before_run(commands)?;

    let git = GitCli::new().with_operation_budget(control.clone());
    let repository_root = &detected.model.repository.root;
    let scope_before = acquire_repository_scope_controlled(&git, repository_root, control)
        .map_err(|error| map_scope_error(error, "before command execution"))?;
    require_same_detection_baseline(&detected.model, &scope_before)?;

    let started_at = clock.now();
    let started_at_text = format_utc_rfc3339(started_at).map_err(map_timestamp_error)?;
    let runner = SynchronousProcessRunner::new(repository_root)
        .map_err(|error| map_process_error(error, "initialize project command runner"))?
        .with_cancellation_flag(control.cancellation_flag());
    let hasher = Blake3Hasher;
    let provenance = command_set.provenance.as_slice();
    let execution_policy = command_execution_policy(cli, &detected.navigation)?;
    let chain = run_command_chain_with_policy_controlled(
        &runner,
        &hasher,
        commands,
        execution_policy,
        control,
        |command, spec| {
            let command_dependency = command_dependency_digest(&hasher, command, provenance)
                .unwrap_or(DependencyValue::Unknown);
            let environment = process_environment_dependency_digest(spec, &hasher)
                .unwrap_or(DependencyValue::Unknown);
            let toolchain =
                required_probes_for_command(command).map_or(DependencyValue::Unknown, |probes| {
                    let request = ToolchainProbeRequest::for_probes(
                        spec.cwd.clone(),
                        spec.env.clone(),
                        probes,
                    );
                    probe_toolchain_dependency_digest_controlled(
                        &runner, &request, &hasher, control,
                    )
                });
            ExecutionDependencyFingerprint::new(command_dependency, toolchain, environment)
        },
    )
    .map_err(map_command_chain_error)?;

    let scope_before_digest =
        scope_dependency_digest(&hasher, &DependencyValue::Known(scope_before.clone()));
    // Once a project command has run, losing its observation makes recovery and diagnosis harder.
    // Preserve a complete after-scope when one exists, including a changed HEAD, and represent an
    // unavailable after-scope as typed `unknown`. Those two exceptional states are permanently
    // non-proving; neither is retried, substituted with the before-scope, or used to move the
    // immutable comparison basis.
    let (scope_after_digest, post_run_error) =
        match acquire_repository_scope_controlled(&git, repository_root, control) {
            Ok(scope_after) => {
                let post_run_error = head_change_error(&scope_before, &scope_after);
                (
                    scope_dependency_digest(&hasher, &DependencyValue::Known(scope_after)),
                    post_run_error,
                )
            }
            Err(error) => (
                DependencyValue::Unknown,
                Some(map_post_run_scope_error(error)),
            ),
        };
    let ordered_execution =
        aggregate_ordered_execution_dependencies(&hasher, &chain.execution_dependencies);
    let ordered_execution = bind_command_set_confidence(
        &hasher,
        &ordered_execution,
        command_set.resolution_confidence,
        command_set.coverage_confidence,
    );
    let policy = policy_dependency(
        &detected.model,
        detected.navigation.policy_base_completeness,
    );
    let policy_base = policy_base_dependency(
        detected.navigation.policy_base_digest.clone(),
        detected.navigation.policy_base_completeness,
    );
    let repository = if detected.model.repository_confidence == Confidence::Unknown
        || detected.model.repository_provenance.is_empty()
    {
        DependencyValue::Unknown
    } else {
        DependencyValue::Known(detected.model.repository.id.clone())
    };
    let dependencies = EvidenceDependencyFingerprint::new(
        repository,
        scope_after_digest.clone(),
        ordered_execution,
        policy,
        worktree_base_task_dependency(&hasher, scope_before.head()),
        DependencyValue::Known(evidence_behavior_digest(&hasher)),
    );
    let aggregation = aggregate_command_evidence(&chain.aggregate_inputs);
    let non_proving_reasons = evidence_run_non_proving_reasons(
        &dependencies,
        commands,
        aggregation.outcome(),
        &scope_before_digest,
        &scope_after_digest,
    );
    let comparison_basis = comparison_basis_v2_to_wire(scope_before.head(), &policy_base)
        .map_err(|_| post_run_comparison_basis_error())?;
    let receipt = ReceiptV2Data {
        id: ReceiptId::new(String::new()),
        intent: intent_to_wire(intent),
        resolution_confidence: Some(confidence_to_wire(command_set.resolution_confidence)),
        coverage_confidence: Some(confidence_to_wire(command_set.coverage_confidence)),
        observations: chain.observations,
        comparison_basis,
        dependencies: receipt_dependencies_v2_to_wire(&dependencies, &scope_before_digest),
        started_at: started_at_text,
        duration_ms: chain.duration_ms,
        outcome: evidence_outcome_to_wire(aggregation.outcome()),
        coverage: aggregation
            .verified()
            .iter()
            .map(coverage_dimension_name)
            .collect(),
        log_refs: Vec::new(),
    };

    // Identity assignment and validation happen while holding the same worktree lock as the
    // immutable write. The exact prepared bytes are both persisted and returned to JSON callers.
    let prepared = prepare_receipt(Envelope::success(
        SchemaKind::Receipt,
        TOOL_VERSION,
        receipt,
    ))
    .map_err(map_post_run_receipt_preparation_error)?;
    let now = clock.now();
    store
        .persist_current_receipt(&lock, now, prepared.object_name(), prepared.bytes(), &codec)
        .map_err(map_post_run_state_error)?;
    if let Some(error) = post_run_error {
        return Err(with_persisted_observation(
            error,
            prepared.object_name().as_str(),
        ));
    }
    if control.checkpoint().is_ok() {
        explain::publish_inventory_cache_after_state_write(&detected);
    }

    Ok(EvidenceRunOutcome {
        receipt_bytes: prepared.bytes().to_vec(),
        receipt_object: prepared.object_name().as_str().to_owned(),
        intent,
        outcome: aggregation.outcome(),
        observation_count: chain.aggregate_inputs.len(),
        non_proving_reasons,
        exit_code: outcome_exit_code(aggregation.outcome()),
    })
}

#[cfg(test)]
fn run_command_chain<P, F>(
    process: &P,
    commands: &[CommandSpec],
    fingerprint: F,
) -> Result<CommandChainResult, CommandChainError>
where
    P: ProcessPort + ?Sized,
    F: FnMut(&CommandSpec, &ExecSpec) -> ExecutionDependencyFingerprint,
{
    run_command_chain_with_policy(
        process,
        &Blake3Hasher,
        commands,
        CommandExecutionPolicy::default(),
        fingerprint,
    )
}

#[cfg(test)]
fn run_command_chain_with_policy<P, H, F>(
    process: &P,
    marker_hasher: &H,
    commands: &[CommandSpec],
    execution_policy: CommandExecutionPolicy,
    fingerprint: F,
) -> Result<CommandChainResult, CommandChainError>
where
    P: ProcessPort + ?Sized,
    H: Hasher + ?Sized,
    F: FnMut(&CommandSpec, &ExecSpec) -> ExecutionDependencyFingerprint,
{
    run_command_chain_with_policy_controlled(
        process,
        marker_hasher,
        commands,
        execution_policy,
        &forge_core::UnlimitedOperationControl,
        fingerprint,
    )
}

fn run_command_chain_with_policy_controlled<P, H, F>(
    process: &P,
    marker_hasher: &H,
    commands: &[CommandSpec],
    execution_policy: CommandExecutionPolicy,
    control: &dyn OperationControl,
    mut fingerprint: F,
) -> Result<CommandChainResult, CommandChainError>
where
    P: ProcessPort + ?Sized,
    H: Hasher + ?Sized,
    F: FnMut(&CommandSpec, &ExecSpec) -> ExecutionDependencyFingerprint,
{
    let mut observations = Vec::with_capacity(commands.len());
    let mut aggregate_inputs = Vec::with_capacity(commands.len());
    let mut execution_dependencies = Vec::with_capacity(commands.len());
    let mut duration_ms = 0_u64;

    for command in commands {
        let mut spec = ExecSpec::from_project_command(command);
        if let Some(timeout) = execution_policy.timeout_override {
            spec.timeout = spec.timeout.min(timeout);
        }
        let output_policy = OutputPolicy::CaptureBounded {
            max_bytes: execution_policy.output_limit_bytes,
        };
        spec.stdout = output_policy;
        spec.stderr = output_policy;
        // `CommandSpec.timeout` is the project-declared, whole-second command contract retained in
        // Receipts and command dependencies. A tighter CLI deadline is runtime policy only: keep
        // its full precision on `ExecSpec` without rewriting the declared command.
        let detail = command_detail_v2_to_wire(command).map_err(CommandChainError::Projection)?;
        let permit = match control.checkpoint() {
            Ok(permit) => permit,
            Err(error) => {
                let outcome = operation_control_evidence_outcome(error);
                let (stdout_digest, stderr_digest) = empty_process_output_digests();
                observations.push(CommandObservationV2Data {
                    command: detail,
                    raw_exit_code: None,
                    signal: None,
                    outcome: evidence_outcome_to_wire(outcome),
                    duration_ms: 0,
                    timed_out: error == OperationControlError::TimedOut,
                    interrupted: error == OperationControlError::Interrupted,
                    process_error_kind: None,
                    diagnostic_summary: Some(observed_diagnostic_summary(0, 0)),
                    stdout_digest,
                    stdout_total_bytes: Some(0),
                    json_error_status: None,
                    stderr_digest,
                    stdout_truncated: Some(false),
                    stderr_truncated: Some(false),
                    output_truncated: false,
                    log_refs: Vec::new(),
                });
                aggregate_inputs.push(CommandEvidenceObservation::new(
                    command.enforcement,
                    outcome,
                    command.coverage.iter().cloned(),
                ));
                execution_dependencies.push(ExecutionDependencyFingerprint::new(
                    DependencyValue::Unknown,
                    DependencyValue::Unknown,
                    DependencyValue::Unknown,
                ));
                break;
            }
        };
        spec.timeout = permit.cap(spec.timeout);
        let dependency = fingerprint(command, &spec);
        let permit = match control.checkpoint() {
            Ok(permit) => permit,
            Err(error) => {
                let outcome = operation_control_evidence_outcome(error);
                let (stdout_digest, stderr_digest) = empty_process_output_digests();
                observations.push(CommandObservationV2Data {
                    command: detail,
                    raw_exit_code: None,
                    signal: None,
                    outcome: evidence_outcome_to_wire(outcome),
                    duration_ms: 0,
                    timed_out: error == OperationControlError::TimedOut,
                    interrupted: error == OperationControlError::Interrupted,
                    process_error_kind: None,
                    diagnostic_summary: Some(observed_diagnostic_summary(0, 0)),
                    stdout_digest,
                    stdout_total_bytes: Some(0),
                    json_error_status: None,
                    stderr_digest,
                    stdout_truncated: Some(false),
                    stderr_truncated: Some(false),
                    output_truncated: false,
                    log_refs: Vec::new(),
                });
                aggregate_inputs.push(CommandEvidenceObservation::new(
                    command.enforcement,
                    outcome,
                    command.coverage.iter().cloned(),
                ));
                execution_dependencies.push(dependency);
                break;
            }
        };
        spec.timeout = permit.cap(spec.timeout);
        let boundary_started = Instant::now();
        let observation = match process.run(&spec) {
            Ok(observation) => observation,
            Err(error) => {
                let outcome = normalize_evidence_outcome(
                    &command.success,
                    ProcessOutcomeInput::infrastructure_failure(error.kind()),
                );
                let observation_duration_ms = duration_millis(boundary_started.elapsed());
                duration_ms = duration_ms.saturating_add(observation_duration_ms);
                let (stdout_digest, stderr_digest) =
                    process_output_unavailable_digests(marker_hasher);
                observations.push(CommandObservationV2Data {
                    command: detail,
                    raw_exit_code: None,
                    signal: None,
                    outcome: evidence_outcome_to_wire(outcome),
                    duration_ms: observation_duration_ms,
                    timed_out: false,
                    interrupted: false,
                    process_error_kind: Some(process_error_kind_to_wire(error.kind())),
                    diagnostic_summary: Some(unavailable_diagnostic_summary()),
                    stdout_digest,
                    stdout_total_bytes: None,
                    json_error_status: None,
                    stderr_digest,
                    stdout_truncated: None,
                    stderr_truncated: None,
                    // No output observation exists. The legacy combined flag remains
                    // conservative and must never make the marker look like empty output.
                    output_truncated: true,
                    log_refs: Vec::new(),
                });
                aggregate_inputs.push(CommandEvidenceObservation::new(
                    command.enforcement,
                    outcome,
                    command.coverage.iter().cloned(),
                ));
                execution_dependencies.push(dependency);
                if command.enforcement == CommandEnforcement::Required {
                    break;
                }
                continue;
            }
        };
        // No provider currently exposes an authoritative complete-stdout JSON parser. Supplying a
        // guessed status would turn `JsonHasNoErrors` into false proof, so it remains absent.
        let mut outcome = normalize_evidence_outcome(
            &command.success,
            ProcessOutcomeInput::observation(&observation, None),
        );
        if stderr_prevents_reusable_outcome(&observation) {
            outcome = EvidenceOutcome::Unknown;
        }
        let observation_duration_ms = duration_millis(observation.duration);
        duration_ms = duration_ms.saturating_add(observation_duration_ms);
        // The compatibility field carries stdout length for success predicates. The fixed-size
        // diagnostic summary records both complete stream lengths without retaining output text.
        let output_truncated = observation.stdout_truncated || observation.stderr_truncated;
        observations.push(CommandObservationV2Data {
            command: detail,
            raw_exit_code: observation.exit_code,
            signal: observation.signal,
            outcome: evidence_outcome_to_wire(outcome),
            duration_ms: observation_duration_ms,
            timed_out: observation.timed_out,
            interrupted: observation.interrupted,
            process_error_kind: None,
            diagnostic_summary: Some(observed_diagnostic_summary(
                observation.stdout_total_bytes,
                observation.stderr_total_bytes,
            )),
            stdout_digest: observation.stdout_digest,
            stdout_total_bytes: Some(observation.stdout_total_bytes),
            json_error_status: None,
            stderr_digest: observation.stderr_digest,
            stdout_truncated: Some(observation.stdout_truncated),
            stderr_truncated: Some(observation.stderr_truncated),
            output_truncated,
            log_refs: Vec::new(),
        });
        aggregate_inputs.push(CommandEvidenceObservation::new(
            command.enforcement,
            outcome,
            command.coverage.iter().cloned(),
        ));
        execution_dependencies.push(dependency);
        if observation.timed_out || observation.interrupted {
            break;
        }
        if command.enforcement == CommandEnforcement::Required && outcome != EvidenceOutcome::Pass {
            break;
        }
    }

    Ok(CommandChainResult {
        observations,
        aggregate_inputs,
        execution_dependencies,
        duration_ms,
    })
}

const fn operation_control_evidence_outcome(error: OperationControlError) -> EvidenceOutcome {
    match error {
        OperationControlError::TimedOut => EvidenceOutcome::TimedOut,
        OperationControlError::Interrupted => EvidenceOutcome::Interrupted,
    }
}

const fn operation_control_io_kind(error: OperationControlError) -> std::io::ErrorKind {
    match error {
        OperationControlError::TimedOut => std::io::ErrorKind::TimedOut,
        OperationControlError::Interrupted => std::io::ErrorKind::Interrupted,
    }
}

fn command_execution_policy(
    cli: &Cli,
    navigation: &forge_detect::model::NavigationSnapshot,
) -> Result<CommandExecutionPolicy, AppError> {
    let configured_limit = navigation
        .config
        .as_ref()
        .and_then(|config| config.policy.max_in_memory_stream_bytes);
    let output_limit_bytes = configured_limit
        .map(usize::try_from)
        .transpose()
        .map_err(|_| {
            AppError::data(
                "FGE1214",
                "the configured in-memory stream bound is unsupported on this platform",
                "policy.max_in_memory_stream_bytes",
                "the configured byte count cannot be represented by this process architecture",
                "choose a smaller non-negative byte count and rerun the evidence command",
            )
        })?
        .unwrap_or(DEFAULT_CAPTURE_LIMIT_BYTES);
    Ok(CommandExecutionPolicy {
        output_limit_bytes,
        timeout_override: explain::operation_timeout(cli)?,
    })
}

fn stderr_prevents_reusable_outcome(observation: &ProcessObservation) -> bool {
    u64::try_from(observation.stderr.len()).unwrap_or(u64::MAX) > observation.stderr_total_bytes
}

const fn confidence_to_wire(confidence: Confidence) -> ConfidenceData {
    match confidence {
        Confidence::Unknown => ConfidenceData::Unknown,
        Confidence::Low => ConfidenceData::Low,
        Confidence::Medium => ConfidenceData::Medium,
        Confidence::High => ConfidenceData::High,
    }
}

fn validate_command_chain_privacy(commands: &[CommandSpec]) -> Result<(), AppError> {
    for command in commands {
        validate_command_privacy(command).map_err(map_command_privacy_error)?;
    }
    Ok(())
}

const fn intent_from_choice(choice: IntentChoice) -> Intent {
    match choice {
        IntentChoice::Setup => Intent::Setup,
        IntentChoice::FormatCheck => Intent::FormatCheck,
        IntentChoice::Format => Intent::Format,
        IntentChoice::Check => Intent::Check,
        IntentChoice::Fix => Intent::Fix,
        IntentChoice::Test => Intent::Test,
        IntentChoice::Verify => Intent::Verify,
        IntentChoice::Build => Intent::Build,
    }
}

fn require_usable_detection(completion: ModelDetectionCompletion) -> Result<(), AppError> {
    match completion {
        ModelDetectionCompletion::Complete | ModelDetectionCompletion::Partial => Ok(()),
        ModelDetectionCompletion::TimedOut => Err(AppError::new(
            ExitCode::Timeout,
            Diagnostic::new(
                "FGE3201",
                Severity::Error,
                "project detection timed out before an evidence run could start",
                "project model",
                "a timed-out model cannot authorize project command execution",
                "increase `--timeout` or reduce repository discovery cost, then retry",
            ),
        )),
        ModelDetectionCompletion::Interrupted => Err(AppError::new(
            ExitCode::Interrupted,
            Diagnostic::new(
                "FGE3202",
                Severity::Error,
                "project detection was interrupted before an evidence run could start",
                "project model",
                "the requested command chain was not executed",
                "rerun `forge evidence run <intent>` when ready",
            ),
        )),
    }
}

fn require_compatible_work_state(work_state: WorkState) -> Result<(), AppError> {
    if matches!(
        work_state,
        WorkState::Clean | WorkState::Dirty | WorkState::Unborn
    ) {
        return Ok(());
    }
    Err(AppError::environment_unmet(
        "FGE3203",
        "the repository state is incompatible with an evidence run",
        "Git worktree state",
        format!(
            "the detected state is {}; merge, rebase, conflict, corrupt, and unknown states cannot form the v0 HEAD comparison basis",
            work_state_name(work_state)
        ),
        "finish or abort the in-progress Git operation, repair the repository state, then retry",
    ))
}

fn require_same_detection_baseline(
    model: &ProjectModel,
    scope: &PreparedScope,
) -> Result<(), AppError> {
    let same = match (model.repository.head.as_ref(), scope.head()) {
        (Some(detected), ScopeHead::Commit(acquired)) => detected
            .as_git_object_id()
            .as_bytes()
            .eq_ignore_ascii_case(acquired.lowercase_hex()),
        (None, ScopeHead::Unborn(_)) => model.repository.work_state == WorkState::Unborn,
        _ => false,
    };
    if same {
        return Ok(());
    }
    Err(AppError::environment_unmet(
        "FGE3204",
        "the repository baseline changed during evidence preparation",
        "HEAD comparison basis",
        "project detection and the before-execution scope did not observe the same HEAD state",
        "stop concurrent Git changes and rerun `forge evidence run <intent>`",
    ))
}

fn head_change_error(before: &PreparedScope, after: &PreparedScope) -> Option<AppError> {
    if before.head() == after.head() {
        return None;
    }
    Some(AppError::environment_unmet(
        "FGE3215",
        "HEAD changed while the project command was running",
        "HEAD comparison basis",
        "the after-execution scope no longer has the immutable baseline used to prepare proving Evidence",
        "project commands may have run; inspect their worktree and external effects, restore a stable HEAD, then rerun `forge evidence run <intent>`",
    ))
}

fn policy_dependency(
    model: &ProjectModel,
    base_completeness: PolicyBaseCompleteness,
) -> DependencyValue<forge_schema::Digest> {
    if base_completeness != PolicyBaseCompleteness::Complete
        || model.policy.confidence == Confidence::Unknown
        || model.policy.provenance.is_empty()
    {
        return DependencyValue::Unknown;
    }
    model
        .policy
        .digest
        .clone()
        .map_or(DependencyValue::Unknown, DependencyValue::Known)
}

fn policy_base_dependency(
    digest: Option<forge_schema::Digest>,
    completeness: PolicyBaseCompleteness,
) -> DependencyValue<forge_schema::Digest> {
    if completeness != PolicyBaseCompleteness::Complete {
        return DependencyValue::Unknown;
    }
    digest.map_or(DependencyValue::Unknown, DependencyValue::Known)
}

const fn outcome_exit_code(outcome: EvidenceOutcome) -> ExitCode {
    match outcome {
        EvidenceOutcome::Pass => ExitCode::Ok,
        EvidenceOutcome::ProductFailure => ExitCode::Negative,
        EvidenceOutcome::TimedOut => ExitCode::Timeout,
        EvidenceOutcome::Interrupted => ExitCode::Interrupted,
        EvidenceOutcome::InfrastructureFailure
        | EvidenceOutcome::Inconclusive
        | EvidenceOutcome::Unknown => ExitCode::EnvironmentUnmet,
    }
}

fn duration_millis(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn unresolved_intent_error(intent: Intent, detail: &str) -> AppError {
    AppError::environment_unmet(
        "FGE3205",
        format!("the {} intent is not executable", intent_name(intent)),
        format!("project command intent `{}`", intent_name(intent)),
        detail,
        "define one unambiguous project-native command for this intent, then rerun `forge explain`",
    )
}

fn map_command_chain_error(error: CommandChainError) -> AppError {
    match error {
        CommandChainError::Projection(error) => map_projection_error(error),
    }
}

fn map_process_error(error: ProcessError, location: &str) -> AppError {
    AppError::environment_unmet(
        "FGE3206",
        "a project command could not produce a complete process observation",
        location,
        error.to_string(),
        "repair the executable, working directory, permissions, or environment, then retry",
    )
}

fn map_scope_error(error: ScopeAcquisitionError, phase: &str) -> AppError {
    if let ScopeAcquisitionError::Git(source) = &error {
        return match source.kind() {
            forge_core::GitErrorKind::TimedOut => AppError::new(
                ExitCode::Timeout,
                Diagnostic::new(
                    "FGE3207",
                    Severity::Error,
                    "repository scope acquisition timed out",
                    phase,
                    error.to_string(),
                    "increase `--timeout` or reduce repository state, then retry",
                ),
            ),
            forge_core::GitErrorKind::Interrupted => AppError::new(
                ExitCode::Interrupted,
                Diagnostic::new(
                    "FGE3208",
                    Severity::Error,
                    "repository scope acquisition was interrupted",
                    phase,
                    error.to_string(),
                    "rerun `forge evidence run <intent>` when ready",
                ),
            ),
            _ => AppError::environment_unmet(
                "FGE3209",
                "the repository scope could not be acquired completely",
                phase,
                error.to_string(),
                "repair the Git repository or unreadable worktree path, then retry",
            ),
        };
    }
    AppError::environment_unmet(
        "FGE3209",
        "the repository scope could not be acquired completely",
        phase,
        error.to_string(),
        "stop concurrent repository changes or repair the affected worktree path, then retry",
    )
}

fn map_post_run_scope_error(error: ScopeAcquisitionError) -> AppError {
    with_post_run_recovery(
        map_scope_error(error, "after command execution"),
        "project commands may have run; inspect their worktree and external effects, repair the repository state, then retry",
    )
}

fn map_projection_error(error: ProjectModelWireError) -> AppError {
    AppError::data(
        "FGE3210",
        "the resolved command cannot be recorded losslessly",
        SchemaKind::Receipt.id(),
        error.to_string(),
        "use representable project command metadata, then rerun `forge explain`",
    )
}

fn map_command_privacy_error(error: forge_core::fingerprint::FingerprintError) -> AppError {
    AppError::data(
        "FGE3216",
        "the selected project command cannot be recorded privately",
        "project command metadata",
        error.to_string(),
        "remove credential-like literal arguments or explicit environment overrides and use the normal external credential provider",
    )
}

fn post_run_comparison_basis_error() -> AppError {
    AppError::internal(
        "FGE3211",
        "the acquired comparison basis cannot be represented",
        SchemaKind::Receipt.id(),
        "the validated scope contained an invalid Git object identity",
        "project commands may have run; inspect their effects and report this as a Forge implementation defect",
    )
}

fn map_timestamp_error(error: forge_runtime::state::UtcTimestampError) -> AppError {
    AppError::internal(
        "FGE3212",
        "the evidence timestamp cannot be represented",
        "system clock",
        error.to_string(),
        "correct the system clock or report an in-range conversion failure",
    )
}

fn map_post_run_receipt_preparation_error(error: EvidenceStateDecodeError) -> AppError {
    AppError::internal(
        "FGE3213",
        "the generated Receipt failed its typed write boundary",
        SchemaKind::Receipt.id(),
        error.to_string(),
        "project commands may have run; inspect their effects and report this as a Forge implementation defect",
    )
}

fn map_state_error(error: StateError) -> AppError {
    let exit_code = match error.io_kind() {
        std::io::ErrorKind::WouldBlock => ExitCode::Temporary,
        std::io::ErrorKind::TimedOut => ExitCode::Timeout,
        std::io::ErrorKind::Interrupted => ExitCode::Interrupted,
        std::io::ErrorKind::InvalidData => ExitCode::DataError,
        _ => ExitCode::EnvironmentUnmet,
    };
    AppError::new(
        exit_code,
        Diagnostic::new(
            "FGE3214",
            Severity::Error,
            "the Receipt could not be persisted safely",
            "worktree-private Evidence state",
            error.to_string(),
            "repair the private Git state path or retry after the competing Forge process exits",
        ),
    )
}

fn map_post_run_state_error(error: StateError) -> AppError {
    with_post_run_recovery(
        map_state_error(error),
        "project commands may have run; inspect their worktree and external effects, repair the private Git state path, then retry",
    )
}

fn with_post_run_recovery(error: AppError, next: &str) -> AppError {
    let diagnostic = error.diagnostic();
    AppError::new(
        error.exit_code(),
        Diagnostic::new(
            diagnostic.code.clone(),
            diagnostic.severity,
            diagnostic.what.clone(),
            diagnostic.location.clone(),
            diagnostic.why.clone(),
            next,
        ),
    )
}

pub(crate) fn with_persisted_observation(error: AppError, object_name: &str) -> AppError {
    let diagnostic = error.diagnostic();
    let receipt_id = format!("receipt:blake3:{object_name}");
    let receipt_path = format!("receipts/v2/{object_name}.json");
    AppError::new(
        error.exit_code(),
        Diagnostic::new(
            diagnostic.code.clone(),
            diagnostic.severity,
            diagnostic.what.clone(),
            diagnostic.location.clone(),
            format!(
                "{}; the completed project-command observations were preserved in observation-only (non-proving) Receipt `{receipt_id}` at `{receipt_path}`",
                diagnostic.why
            ),
            diagnostic.next.clone(),
        ),
    )
}

fn evidence_run_non_proving_reasons(
    dependencies: &EvidenceDependencyFingerprint,
    commands: &[CommandSpec],
    outcome: EvidenceOutcome,
    scope_before: &DependencyValue<forge_schema::Digest>,
    scope_after: &DependencyValue<forge_schema::Digest>,
) -> Vec<&'static str> {
    let mut reasons = Vec::new();
    for (name, value_is_unknown) in [
        (
            "repository dependency is unknown",
            matches!(dependencies.repository(), DependencyValue::Unknown),
        ),
        (
            "scope dependency is unknown",
            matches!(dependencies.scope(), DependencyValue::Unknown),
        ),
        (
            "command dependency is unknown",
            matches!(dependencies.command(), DependencyValue::Unknown),
        ),
        (
            "toolchain dependency is unknown",
            matches!(dependencies.toolchain(), DependencyValue::Unknown),
        ),
        (
            "environment dependency is unknown",
            matches!(dependencies.environment(), DependencyValue::Unknown),
        ),
        (
            "policy dependency is unknown",
            matches!(dependencies.policy(), DependencyValue::Unknown),
        ),
        (
            "base/task dependency is unknown",
            matches!(dependencies.base_task(), BaseTaskDependency::Unknown),
        ),
        (
            "Forge behavior dependency is unknown",
            matches!(dependencies.forge_behavior(), DependencyValue::Unknown),
        ),
    ] {
        if value_is_unknown {
            reasons.push(name);
        }
    }
    if outcome != EvidenceOutcome::Pass {
        reasons.push("command outcome is not passing");
    }
    if scope_before != scope_after {
        reasons.push("repository scope changed during execution");
    }
    if commands
        .iter()
        .any(|command| command.mutability == forge_core::Mutability::WorkingTreeWrite)
    {
        reasons.push("a mutating command requires a later read-only confirmation");
    }
    reasons
}

pub(crate) fn render_human(outcome: &EvidenceRunOutcome) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "intent: {}", intent_name(outcome.intent));
    let _ = writeln!(output, "outcome: {}", outcome_name(outcome.outcome));
    let _ = writeln!(output, "commands observed: {}", outcome.observation_count);
    if outcome.non_proving_reasons.is_empty() {
        let _ = writeln!(
            output,
            "receipt applicability: eligible for current-state and policy evaluation"
        );
    } else {
        let _ = writeln!(
            output,
            "receipt applicability: observation-only (non-proving)"
        );
        for reason in &outcome.non_proving_reasons {
            let _ = writeln!(output, "  - {reason}");
        }
    }
    let _ = writeln!(output, "receipt object: {}", outcome.receipt_object);
    output
}

pub(crate) fn render_command_plan(commands: &[CommandSpec]) -> String {
    let mut output = String::new();
    for (index, command) in commands.iter().enumerate() {
        let _ = writeln!(
            output,
            "command {}/{}: {}",
            index.saturating_add(1),
            commands.len(),
            command.id
        );
        let _ = writeln!(output, "  program: {:?}", command.program);
        let _ = writeln!(output, "  args: {:?}", command.args);
        let _ = writeln!(output, "  cwd: {:?}", command.cwd.as_path());
        let _ = writeln!(output, "  timeout: {:?}", command.timeout);
        let _ = writeln!(output, "  mutability: {:?}", command.mutability);
        let _ = writeln!(output, "  network: {:?}", command.network);
        let _ = writeln!(output, "  enforcement: {:?}", command.enforcement);
        let _ = writeln!(output, "  success: {:?}", command.success);
        let _ = writeln!(output, "  coverage: {:?}", command.coverage);
        let environment_names = command.env.keys().collect::<Vec<_>>();
        if !environment_names.is_empty() {
            let _ = writeln!(
                output,
                "  environment override names: {environment_names:?} (values redacted)"
            );
        }
        let _ = writeln!(output, "  source: {:?}", command.source);
    }
    output
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

const fn work_state_name(work_state: WorkState) -> &'static str {
    match work_state {
        WorkState::Clean => "clean",
        WorkState::Dirty => "dirty",
        WorkState::Conflicted => "conflicted",
        WorkState::Merging => "merging",
        WorkState::Rebasing => "rebasing",
        WorkState::Unborn => "unborn",
        WorkState::Corrupt => "corrupt",
        WorkState::Unknown => "unknown",
    }
}

const fn outcome_name(outcome: EvidenceOutcome) -> &'static str {
    match outcome {
        EvidenceOutcome::Pass => "pass",
        EvidenceOutcome::ProductFailure => "product-failure",
        EvidenceOutcome::InfrastructureFailure => "infrastructure-failure",
        EvidenceOutcome::Inconclusive => "inconclusive",
        EvidenceOutcome::TimedOut => "timed-out",
        EvidenceOutcome::Interrupted => "interrupted",
        EvidenceOutcome::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::{BTreeSet, VecDeque};
    use std::ffi::OsString;
    use std::io;
    use std::time::Duration;

    use forge_core::domain::{
        CommandEnforcement, CommandSource, Confidence, CoverageDimension, Mutability,
        NetworkIntent, SuccessPredicate,
    };
    use forge_core::evidence::{
        BaseTaskDependency, DependencyValue, EvidenceDependencyFingerprint,
        ExecutionDependencyFingerprint,
    };
    use forge_core::ports::{ExecSpec, OutputPolicy, ProcessError, ProcessErrorKind, ProcessPort};
    use forge_core::scope::{PreparedScope, ScopeHead, ScopeObjectId};
    use forge_core::{
        AppError, CommandSpec, Digest, ExitCode, GitError, GitErrorKind, GitObjectFormat,
        OperationControl, OperationControlError, OperationPermit, RepoId, RepoRelativePath,
    };
    use forge_runtime::hash::Blake3Hasher;
    use forge_runtime::scope::ScopeAcquisitionError;

    use super::{
        CommandExecutionPolicy, EvidenceOutcome, aggregate_command_evidence,
        evidence_run_non_proving_reasons, head_change_error, map_post_run_scope_error,
        outcome_exit_code, render_command_plan, run_command_chain, run_command_chain_with_policy,
        run_command_chain_with_policy_controlled, validate_command_chain_privacy,
        with_persisted_observation,
    };

    #[derive(Debug)]
    struct FakeProcess {
        results: RefCell<VecDeque<Result<forge_core::ports::ProcessObservation, ProcessError>>>,
        seen: RefCell<Vec<ExecSpec>>,
    }

    #[derive(Debug)]
    struct ScriptedControl {
        steps: RefCell<VecDeque<Result<OperationPermit, OperationControlError>>>,
    }

    impl ScriptedControl {
        fn new(
            steps: impl IntoIterator<Item = Result<OperationPermit, OperationControlError>>,
        ) -> Self {
            Self {
                steps: RefCell::new(steps.into_iter().collect()),
            }
        }
    }

    impl OperationControl for ScriptedControl {
        fn checkpoint(&self) -> Result<OperationPermit, OperationControlError> {
            self.steps
                .borrow_mut()
                .pop_front()
                .unwrap_or(Err(OperationControlError::TimedOut))
        }
    }

    impl FakeProcess {
        fn new(results: Vec<Result<forge_core::ports::ProcessObservation, ProcessError>>) -> Self {
            Self {
                results: RefCell::new(results.into()),
                seen: RefCell::new(Vec::new()),
            }
        }
    }

    impl ProcessPort for FakeProcess {
        fn run(
            &self,
            spec: &ExecSpec,
        ) -> Result<forge_core::ports::ProcessObservation, ProcessError> {
            self.seen.borrow_mut().push(spec.clone());
            self.results.borrow_mut().pop_front().ok_or_else(|| {
                ProcessError::new(
                    ProcessErrorKind::Wait,
                    "read fake process result",
                    io::Error::new(io::ErrorKind::UnexpectedEof, "no fake result"),
                )
            })?
        }
    }

    fn command(
        id: &str,
        enforcement: CommandEnforcement,
        success: SuccessPredicate,
        coverage: CoverageDimension,
    ) -> CommandSpec {
        let mut command = CommandSpec::new(
            id,
            forge_core::Intent::Check,
            "tool",
            RepoRelativePath::root(),
            CommandSource::LanguageDefault {
                provider: String::from("fixture"),
                rule: String::from("fixture-command"),
            },
        )
        .with_args([id]);
        command.timeout = Duration::from_secs(5);
        command.mutability = Mutability::ReadOnly;
        command.network = NetworkIntent::OfflineRequested;
        command.enforcement = enforcement;
        command.success = success;
        command.confidence = Confidence::High;
        command.coverage = BTreeSet::from([coverage]);
        command
    }

    fn observation(exit_code: i32) -> forge_core::ports::ProcessObservation {
        forge_core::ports::ProcessObservation {
            exit_code: Some(exit_code),
            signal: None,
            stdout: b"retained".to_vec(),
            stderr: b"error".to_vec(),
            stdout_digest: Digest::new("blake3:stdout"),
            stderr_digest: Digest::new("blake3:stderr"),
            stdout_total_bytes: 21,
            stderr_total_bytes: 13,
            stdout_truncated: true,
            stderr_truncated: false,
            duration: Duration::from_millis(7),
            timed_out: false,
            interrupted: false,
        }
    }

    fn known_dependencies(
        _command: &CommandSpec,
        _spec: &ExecSpec,
    ) -> ExecutionDependencyFingerprint {
        ExecutionDependencyFingerprint::new(
            DependencyValue::Known(Digest::new("blake3:command")),
            DependencyValue::Known(Digest::new("blake3:toolchain")),
            DependencyValue::Known(Digest::new("blake3:environment")),
        )
    }

    fn known_evidence_dependencies() -> EvidenceDependencyFingerprint {
        let known = |value: &str| DependencyValue::Known(Digest::new(value));
        EvidenceDependencyFingerprint::new(
            DependencyValue::Known(RepoId::from("local:fixture")),
            known("blake3:scope"),
            ExecutionDependencyFingerprint::new(
                known("blake3:command"),
                known("blake3:toolchain"),
                known("blake3:environment"),
            ),
            known("blake3:policy"),
            BaseTaskDependency::Known(Digest::new("blake3:base-task")),
            known("blake3:behavior"),
        )
    }

    #[test]
    fn external_side_effect_is_proving_when_scope_is_stable() {
        let mut external = command(
            "external",
            CommandEnforcement::Required,
            SuccessPredicate::ExitZero,
            CoverageDimension::Compile,
        );
        external.mutability = Mutability::ExternalSideEffect;
        let scope = DependencyValue::Known(Digest::new("blake3:scope"));

        assert!(
            evidence_run_non_proving_reasons(
                &known_evidence_dependencies(),
                &[external],
                EvidenceOutcome::Pass,
                &scope,
                &scope,
            )
            .is_empty()
        );

        let mut working_tree = command(
            "working-tree",
            CommandEnforcement::Required,
            SuccessPredicate::ExitZero,
            CoverageDimension::Format,
        );
        working_tree.mutability = Mutability::WorkingTreeWrite;
        assert_eq!(
            evidence_run_non_proving_reasons(
                &known_evidence_dependencies(),
                &[working_tree],
                EvidenceOutcome::Pass,
                &scope,
                &scope,
            ),
            ["a mutating command requires a later read-only confirmation"]
        );
    }

    #[test]
    fn command_budget_retains_completed_observations_and_starts_no_later_command()
    -> Result<(), Box<dyn std::error::Error>> {
        let commands = vec![
            command(
                "first",
                CommandEnforcement::Required,
                SuccessPredicate::ExitZero,
                CoverageDimension::Compile,
            ),
            command(
                "second",
                CommandEnforcement::Required,
                SuccessPredicate::ExitZero,
                CoverageDimension::UnitTest,
            ),
        ];
        let process = FakeProcess::new(vec![Ok(observation(0))]);
        let control = ScriptedControl::new([
            Ok(OperationPermit::limited(Duration::from_millis(40))),
            Ok(OperationPermit::limited(Duration::from_millis(30))),
            Err(OperationControlError::TimedOut),
        ]);

        let chain = run_command_chain_with_policy_controlled(
            &process,
            &Blake3Hasher,
            &commands,
            CommandExecutionPolicy::default(),
            &control,
            known_dependencies,
        )
        .map_err(|error| io::Error::other(format!("command chain failed: {error:?}")))?;

        assert_eq!(process.seen.borrow().len(), 1);
        assert_eq!(process.seen.borrow()[0].timeout, Duration::from_millis(30));
        assert_eq!(chain.observations.len(), 2);
        assert!(!chain.observations[0].timed_out);
        assert!(chain.observations[1].timed_out);
        assert_eq!(
            chain.observations[1]
                .diagnostic_summary
                .as_ref()
                .map(|summary| (
                    summary.state,
                    summary.stdout_total_bytes,
                    summary.stderr_total_bytes,
                )),
            Some((
                forge_schema::CommandDiagnosticSummaryStateV2Data::Observed,
                Some(0),
                Some(0),
            ))
        );
        assert_eq!(
            chain.aggregate_inputs[1].outcome(),
            EvidenceOutcome::TimedOut
        );
        Ok(())
    }

    #[test]
    fn execution_policy_caps_command_timeout_and_sets_both_retention_bounds()
    -> Result<(), Box<dyn std::error::Error>> {
        let commands = vec![command(
            "bounded",
            CommandEnforcement::Required,
            SuccessPredicate::ExitZero,
            CoverageDimension::Compile,
        )];
        let mut timed_out = observation(0);
        timed_out.timed_out = true;
        let process = FakeProcess::new(vec![Ok(timed_out)]);
        let fingerprint_timeouts = RefCell::new(Vec::new());

        let chain = run_command_chain_with_policy(
            &process,
            &Blake3Hasher,
            &commands,
            CommandExecutionPolicy {
                output_limit_bytes: 17,
                timeout_override: Some(Duration::from_millis(23)),
            },
            |command, spec| {
                fingerprint_timeouts
                    .borrow_mut()
                    .push((command.timeout, spec.timeout));
                known_dependencies(command, spec)
            },
        )
        .map_err(|error| io::Error::other(format!("{error:?}")))?;

        let seen = process.seen.borrow();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].timeout, Duration::from_millis(23));
        assert_eq!(
            fingerprint_timeouts.into_inner(),
            [(Duration::from_secs(5), Duration::from_millis(23))]
        );
        assert_eq!(chain.observations[0].command.command.timeout_seconds, 5);
        assert!(chain.observations[0].timed_out);
        assert_eq!(
            chain.observations[0].outcome,
            forge_schema::OutcomeData::TimedOut
        );
        assert_eq!(
            chain.observations[0].diagnostic_summary,
            Some(forge_schema::CommandDiagnosticSummaryV2Data {
                state: forge_schema::CommandDiagnosticSummaryStateV2Data::Observed,
                stdout_total_bytes: Some(21),
                stderr_total_bytes: Some(13),
            })
        );
        assert_eq!(
            seen[0].stdout,
            OutputPolicy::CaptureBounded { max_bytes: 17 }
        );
        assert_eq!(seen[0].stderr, seen[0].stdout);
        Ok(())
    }

    #[test]
    fn operation_control_interrupts_record_empty_observed_summaries_at_both_boundaries()
    -> Result<(), Box<dyn std::error::Error>> {
        for steps in [
            vec![Err(OperationControlError::Interrupted)],
            vec![
                Ok(OperationPermit::unlimited()),
                Err(OperationControlError::Interrupted),
            ],
        ] {
            let command = command(
                "interrupted",
                CommandEnforcement::Required,
                SuccessPredicate::ExitZero,
                CoverageDimension::Compile,
            );
            let process = FakeProcess::new(Vec::new());
            let control = ScriptedControl::new(steps);

            let chain = run_command_chain_with_policy_controlled(
                &process,
                &Blake3Hasher,
                &[command],
                CommandExecutionPolicy::default(),
                &control,
                known_dependencies,
            )
            .map_err(|error| io::Error::other(format!("{error:?}")))?;

            assert!(process.seen.borrow().is_empty());
            assert_eq!(chain.observations.len(), 1);
            assert!(chain.observations[0].interrupted);
            assert_eq!(
                chain.observations[0].diagnostic_summary,
                Some(forge_schema::CommandDiagnosticSummaryV2Data {
                    state: forge_schema::CommandDiagnosticSummaryStateV2Data::Observed,
                    stdout_total_bytes: Some(0),
                    stderr_total_bytes: Some(0),
                })
            );
        }
        Ok(())
    }

    #[test]
    fn process_interruption_records_complete_stream_counts()
    -> Result<(), Box<dyn std::error::Error>> {
        let command = command(
            "interrupted",
            CommandEnforcement::Required,
            SuccessPredicate::ExitZero,
            CoverageDimension::Compile,
        );
        let mut interrupted = observation(0);
        interrupted.timed_out = false;
        interrupted.interrupted = true;
        let process = FakeProcess::new(vec![Ok(interrupted)]);

        let chain = run_command_chain(&process, &[command], known_dependencies)
            .map_err(|error| io::Error::other(format!("{error:?}")))?;

        assert_eq!(
            chain.observations[0].outcome,
            forge_schema::OutcomeData::Interrupted
        );
        assert_eq!(
            chain.observations[0].diagnostic_summary,
            Some(forge_schema::CommandDiagnosticSummaryV2Data {
                state: forge_schema::CommandDiagnosticSummaryStateV2Data::Observed,
                stdout_total_bytes: Some(21),
                stderr_total_bytes: Some(13),
            })
        );
        Ok(())
    }

    #[test]
    fn execution_policy_never_relaxes_a_stricter_project_timeout()
    -> Result<(), Box<dyn std::error::Error>> {
        let commands = vec![command(
            "bounded",
            CommandEnforcement::Required,
            SuccessPredicate::ExitZero,
            CoverageDimension::Compile,
        )];
        let process = FakeProcess::new(vec![Ok(observation(0))]);

        run_command_chain_with_policy(
            &process,
            &Blake3Hasher,
            &commands,
            CommandExecutionPolicy {
                output_limit_bytes: 17,
                timeout_override: Some(Duration::from_secs(6)),
            },
            known_dependencies,
        )
        .map_err(|error| io::Error::other(format!("{error:?}")))?;

        assert_eq!(process.seen.borrow()[0].timeout, Duration::from_secs(5));
        Ok(())
    }

    #[test]
    fn required_failure_stops_and_records_the_complete_wire_observation()
    -> Result<(), Box<dyn std::error::Error>> {
        let commands = vec![
            command(
                "first",
                CommandEnforcement::Required,
                SuccessPredicate::ExitZero,
                CoverageDimension::Compile,
            ),
            command(
                "second",
                CommandEnforcement::Required,
                SuccessPredicate::ExitZero,
                CoverageDimension::Lint,
            ),
        ];
        let process = FakeProcess::new(vec![Ok(observation(7)), Ok(observation(0))]);

        let chain = run_command_chain(&process, &commands, known_dependencies)
            .map_err(|error| io::Error::other(format!("{error:?}")))?;

        assert_eq!(process.seen.borrow().len(), 1);
        assert_eq!(process.seen.borrow()[0].program, "tool");
        assert_eq!(process.seen.borrow()[0].args, ["first"]);
        assert_eq!(chain.observations.len(), 1);
        let recorded = &chain.observations[0];
        assert_eq!(recorded.raw_exit_code, Some(7));
        assert_eq!(recorded.signal, None);
        assert_eq!(recorded.stdout_total_bytes, Some(21));
        assert_eq!(
            recorded.diagnostic_summary,
            Some(forge_schema::CommandDiagnosticSummaryV2Data {
                state: forge_schema::CommandDiagnosticSummaryStateV2Data::Observed,
                stdout_total_bytes: Some(21),
                stderr_total_bytes: Some(13),
            })
        );
        assert_eq!(recorded.stdout_digest.as_str(), "blake3:stdout");
        assert_eq!(recorded.stderr_digest.as_str(), "blake3:stderr");
        assert_eq!(recorded.stdout_truncated, Some(true));
        assert_eq!(recorded.stderr_truncated, Some(false));
        assert!(recorded.output_truncated);
        assert_eq!(recorded.json_error_status, None);
        assert!(recorded.log_refs.is_empty());
        assert_eq!(chain.duration_ms, 7);
        assert_eq!(chain.execution_dependencies.len(), 1);
        assert_eq!(
            aggregate_command_evidence(&chain.aggregate_inputs).outcome(),
            EvidenceOutcome::ProductFailure
        );
        Ok(())
    }

    #[test]
    fn advisory_failure_does_not_skip_the_later_required_gate()
    -> Result<(), Box<dyn std::error::Error>> {
        let commands = vec![
            command(
                "advisory",
                CommandEnforcement::Advisory,
                SuccessPredicate::ExitZero,
                CoverageDimension::Lint,
            ),
            command(
                "required",
                CommandEnforcement::Required,
                SuccessPredicate::ExitZero,
                CoverageDimension::Compile,
            ),
        ];
        let process = FakeProcess::new(vec![Ok(observation(9)), Ok(observation(0))]);

        let chain = run_command_chain(&process, &commands, known_dependencies)
            .map_err(|error| io::Error::other(format!("{error:?}")))?;
        let aggregate = aggregate_command_evidence(&chain.aggregate_inputs);

        assert_eq!(process.seen.borrow().len(), 2);
        assert_eq!(aggregate.outcome(), EvidenceOutcome::Pass);
        assert_eq!(
            aggregate.verified(),
            &BTreeSet::from([CoverageDimension::Compile])
        );
        assert_eq!(
            aggregate.not_verified(),
            &BTreeSet::from([CoverageDimension::Lint])
        );
        Ok(())
    }

    #[test]
    fn json_success_predicate_without_a_provider_parser_is_unknown_and_stops()
    -> Result<(), Box<dyn std::error::Error>> {
        let commands = vec![
            command(
                "json",
                CommandEnforcement::Required,
                SuccessPredicate::JsonHasNoErrors,
                CoverageDimension::Compile,
            ),
            command(
                "later",
                CommandEnforcement::Required,
                SuccessPredicate::ExitZero,
                CoverageDimension::Lint,
            ),
        ];
        let process = FakeProcess::new(vec![Ok(observation(0)), Ok(observation(0))]);

        let chain = run_command_chain(&process, &commands, known_dependencies)
            .map_err(|error| io::Error::other(format!("{error:?}")))?;

        assert_eq!(process.seen.borrow().len(), 1);
        assert_eq!(
            aggregate_command_evidence(&chain.aggregate_inputs).outcome(),
            EvidenceOutcome::Unknown
        );
        assert_eq!(chain.observations[0].json_error_status, None);
        Ok(())
    }

    #[test]
    fn required_process_boundary_error_is_a_typed_non_output_observation()
    -> Result<(), Box<dyn std::error::Error>> {
        let commands = vec![command(
            "broken",
            CommandEnforcement::Required,
            SuccessPredicate::ExitZero,
            CoverageDimension::Compile,
        )];
        let process = FakeProcess::new(vec![Err(ProcessError::new(
            ProcessErrorKind::ExecutableUnavailable,
            "start fake command",
            io::Error::new(io::ErrorKind::NotFound, "missing"),
        ))]);

        let chain = run_command_chain(&process, &commands, known_dependencies)
            .map_err(|error| io::Error::other(format!("{error:?}")))?;

        assert_eq!(chain.observations.len(), 1);
        assert_eq!(chain.execution_dependencies.len(), 1);
        let recorded = &chain.observations[0];
        assert_eq!(
            recorded.process_error_kind,
            Some(forge_schema::ProcessErrorKindV2Data::ExecutableUnavailable)
        );
        assert_eq!(
            recorded.outcome,
            forge_schema::OutcomeData::InfrastructureFailure
        );
        assert_eq!(recorded.raw_exit_code, None);
        assert_eq!(recorded.signal, None);
        assert_eq!(
            recorded.diagnostic_summary,
            Some(forge_schema::CommandDiagnosticSummaryV2Data {
                state: forge_schema::CommandDiagnosticSummaryStateV2Data::Unavailable,
                stdout_total_bytes: None,
                stderr_total_bytes: None,
            })
        );
        assert_eq!(recorded.stdout_total_bytes, None);
        assert_eq!(recorded.stdout_truncated, None);
        assert_eq!(recorded.stderr_truncated, None);
        assert!(recorded.output_truncated);
        assert_ne!(recorded.stdout_digest, recorded.stderr_digest);
        assert_eq!(
            aggregate_command_evidence(&chain.aggregate_inputs).outcome(),
            EvidenceOutcome::InfrastructureFailure
        );
        Ok(())
    }

    #[test]
    fn diagnostic_summary_never_persists_captured_output_or_process_error_text()
    -> Result<(), Box<dyn std::error::Error>> {
        const SECRET: &str = "forge-secret-sentinel-7c9169b8";
        let command = command(
            "private-output",
            CommandEnforcement::Required,
            SuccessPredicate::ExitZero,
            CoverageDimension::Compile,
        );
        let mut private_output = observation(0);
        private_output.stdout = [b"\xff".as_slice(), SECRET.as_bytes()].concat();
        private_output.stderr =
            [b"\xfe".as_slice(), format!("stderr-{SECRET}").as_bytes()].concat();
        private_output.stdout_total_bytes = 700_000;
        private_output.stderr_total_bytes = 800_000;
        private_output.stdout_truncated = true;
        private_output.stderr_truncated = true;
        let process = FakeProcess::new(vec![Ok(private_output)]);
        let chain = run_command_chain(&process, std::slice::from_ref(&command), known_dependencies)
            .map_err(|error| io::Error::other(format!("{error:?}")))?;
        assert_eq!(
            chain.observations[0].diagnostic_summary,
            Some(forge_schema::CommandDiagnosticSummaryV2Data {
                state: forge_schema::CommandDiagnosticSummaryStateV2Data::Observed,
                stdout_total_bytes: Some(700_000),
                stderr_total_bytes: Some(800_000),
            })
        );
        let encoded = serde_json::to_vec(&chain.observations)?;
        assert!(
            !encoded
                .windows(SECRET.len())
                .any(|window| window == SECRET.as_bytes())
        );

        let process = FakeProcess::new(vec![Err(ProcessError::new(
            ProcessErrorKind::Spawn,
            "spawn private command",
            io::Error::other(format!("/private/path/{SECRET}")),
        ))]);
        let chain = run_command_chain(&process, &[command], known_dependencies)
            .map_err(|error| io::Error::other(format!("{error:?}")))?;
        let encoded = serde_json::to_vec(&chain.observations)?;
        assert!(
            !encoded
                .windows(SECRET.len())
                .any(|window| window == SECRET.as_bytes())
        );
        Ok(())
    }

    #[test]
    fn process_failure_preserves_prior_observations_and_stops_before_later_required_commands()
    -> Result<(), Box<dyn std::error::Error>> {
        let commands = vec![
            command(
                "first",
                CommandEnforcement::Required,
                SuccessPredicate::ExitZero,
                CoverageDimension::Compile,
            ),
            command(
                "broken",
                CommandEnforcement::Required,
                SuccessPredicate::ExitZero,
                CoverageDimension::Lint,
            ),
            command(
                "later",
                CommandEnforcement::Required,
                SuccessPredicate::ExitZero,
                CoverageDimension::UnitTest,
            ),
        ];
        let process = FakeProcess::new(vec![
            Ok(observation(0)),
            Err(ProcessError::new(
                ProcessErrorKind::Wait,
                "wait for fake command",
                io::Error::other("wait failed"),
            )),
            Ok(observation(0)),
        ]);

        let chain = run_command_chain(&process, &commands, known_dependencies)
            .map_err(|error| io::Error::other(format!("{error:?}")))?;

        assert_eq!(process.seen.borrow().len(), 2);
        assert_eq!(chain.observations.len(), 2);
        assert_eq!(chain.execution_dependencies.len(), 2);
        assert_eq!(
            chain.observations[0].outcome,
            forge_schema::OutcomeData::Pass
        );
        assert_eq!(
            chain.observations[1].process_error_kind,
            Some(forge_schema::ProcessErrorKindV2Data::Wait)
        );
        assert_eq!(
            aggregate_command_evidence(&chain.aggregate_inputs).outcome(),
            EvidenceOutcome::InfrastructureFailure
        );
        Ok(())
    }

    #[test]
    fn advisory_process_failure_continues_to_a_later_required_gate()
    -> Result<(), Box<dyn std::error::Error>> {
        let commands = vec![
            command(
                "advisory-broken",
                CommandEnforcement::Advisory,
                SuccessPredicate::ExitZero,
                CoverageDimension::Lint,
            ),
            command(
                "required",
                CommandEnforcement::Required,
                SuccessPredicate::ExitZero,
                CoverageDimension::Compile,
            ),
        ];
        let process = FakeProcess::new(vec![
            Err(ProcessError::new(
                ProcessErrorKind::Spawn,
                "spawn fake command",
                io::Error::other("spawn failed"),
            )),
            Ok(observation(0)),
        ]);

        let chain = run_command_chain(&process, &commands, known_dependencies)
            .map_err(|error| io::Error::other(format!("{error:?}")))?;
        let aggregate = aggregate_command_evidence(&chain.aggregate_inputs);

        assert_eq!(process.seen.borrow().len(), 2);
        assert_eq!(chain.observations.len(), 2);
        assert_eq!(aggregate.outcome(), EvidenceOutcome::Pass);
        assert_eq!(
            aggregate.verified(),
            &BTreeSet::from([CoverageDimension::Compile])
        );
        assert_eq!(
            aggregate.not_verified(),
            &BTreeSet::from([CoverageDimension::Lint])
        );
        Ok(())
    }

    #[test]
    fn per_stream_truncation_keeps_stderr_only_exit_zero_reproducible()
    -> Result<(), Box<dyn std::error::Error>> {
        let commands = vec![command(
            "stderr-heavy",
            CommandEnforcement::Required,
            SuccessPredicate::ExitZero,
            CoverageDimension::Compile,
        )];
        let mut result = observation(0);
        result.stdout = Vec::new();
        result.stdout_total_bytes = 0;
        result.stdout_truncated = false;
        result.stderr_truncated = true;
        let process = FakeProcess::new(vec![Ok(result)]);

        let chain = run_command_chain(&process, &commands, known_dependencies)
            .map_err(|error| io::Error::other(format!("{error:?}")))?;

        assert_eq!(
            chain.observations[0].outcome,
            forge_schema::OutcomeData::Pass
        );
        assert_eq!(chain.observations[0].stdout_truncated, Some(false));
        assert_eq!(chain.observations[0].stderr_truncated, Some(true));
        assert_eq!(
            chain.observations[0]
                .diagnostic_summary
                .as_ref()
                .and_then(|summary| summary.stderr_total_bytes),
            Some(13)
        );
        assert!(chain.observations[0].output_truncated);
        assert_eq!(
            aggregate_command_evidence(&chain.aggregate_inputs).outcome(),
            EvidenceOutcome::Pass
        );
        Ok(())
    }

    #[test]
    fn secret_like_environment_is_rejected_before_preview_or_project_process()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut command = command(
            "private-env",
            CommandEnforcement::Required,
            SuccessPredicate::ExitZero,
            CoverageDimension::Compile,
        );
        command.env.insert(
            OsString::from("CLIENT_SECRET"),
            OsString::from("must-never-appear"),
        );
        let error = match validate_command_chain_privacy(&[command]) {
            Err(error) => error,
            Ok(()) => return Err(io::Error::other("secret-like environment was accepted").into()),
        };

        assert_eq!(error.exit_code(), ExitCode::DataError);
        let rendered = format!("{:?}", error.diagnostic());
        assert!(!rendered.contains("CLIENT_SECRET"));
        assert!(!rendered.contains("must-never-appear"));
        Ok(())
    }

    #[test]
    fn secret_like_argv_is_rejected_before_preview_wire_or_project_process()
    -> Result<(), Box<dyn std::error::Error>> {
        for (args, literal) in [
            (vec!["--token=literal-inline"], "literal-inline"),
            (vec!["--password", "literal-following"], "literal-following"),
            (
                vec!["Authorization: Bearer literal-header"],
                "literal-header",
            ),
            (
                vec!["https://user:literal-uri@example.invalid"],
                "literal-uri",
            ),
            (vec!["ACCESS_KEY=literal-assignment"], "literal-assignment"),
        ] {
            let mut command = command(
                "private-argv",
                CommandEnforcement::Required,
                SuccessPredicate::ExitZero,
                CoverageDimension::Compile,
            );
            command.args = args.into_iter().map(OsString::from).collect();
            let error = match validate_command_chain_privacy(&[command]) {
                Err(error) => error,
                Ok(()) => {
                    return Err(io::Error::other("secret-like argv was accepted").into());
                }
            };

            assert_eq!(error.exit_code(), ExitCode::DataError);
            assert_eq!(error.diagnostic().code.as_str(), "FGE3216");
            let rendered = format!("{:?}", error.diagnostic());
            assert!(!rendered.contains(literal));
        }
        Ok(())
    }

    #[test]
    fn evidence_outcomes_use_the_stable_run_exit_codes() {
        assert_eq!(outcome_exit_code(EvidenceOutcome::Pass), ExitCode::Ok);
        assert_eq!(
            outcome_exit_code(EvidenceOutcome::ProductFailure),
            ExitCode::Negative
        );
        assert_eq!(
            outcome_exit_code(EvidenceOutcome::InfrastructureFailure),
            ExitCode::EnvironmentUnmet
        );
        assert_eq!(
            outcome_exit_code(EvidenceOutcome::Inconclusive),
            ExitCode::EnvironmentUnmet
        );
        assert_eq!(
            outcome_exit_code(EvidenceOutcome::Unknown),
            ExitCode::EnvironmentUnmet
        );
        assert_eq!(
            outcome_exit_code(EvidenceOutcome::TimedOut),
            ExitCode::Timeout
        );
        assert_eq!(
            outcome_exit_code(EvidenceOutcome::Interrupted),
            ExitCode::Interrupted
        );
    }

    #[test]
    fn human_command_plan_is_transparent_without_exposing_environment_values() {
        let mut command = command(
            "visible",
            CommandEnforcement::Required,
            SuccessPredicate::ExitZero,
            CoverageDimension::Compile,
        );
        command.env.insert(
            OsString::from("VISIBLE_MODE"),
            OsString::from("private-value"),
        );

        let rendered = render_command_plan(&[command]);

        assert!(rendered.contains("command 1/1: visible"));
        assert!(rendered.contains("program: \"tool\""));
        assert!(rendered.contains("args: [\"visible\"]"));
        assert!(rendered.contains("VISIBLE_MODE"));
        assert!(!rendered.contains("private-value"));
    }

    #[test]
    fn a_head_change_is_a_terminal_issue_after_retaining_the_after_scope()
    -> Result<(), Box<dyn std::error::Error>> {
        let before = PreparedScope::new(
            ScopeHead::Commit(ScopeObjectId::new(
                GitObjectFormat::Sha1,
                b"1111111111111111111111111111111111111111",
            )?),
            Vec::new(),
        )?;
        let after = PreparedScope::new(
            ScopeHead::Commit(ScopeObjectId::new(
                GitObjectFormat::Sha1,
                b"2222222222222222222222222222222222222222",
            )?),
            Vec::new(),
        )?;

        let error = head_change_error(&before, &after)
            .ok_or_else(|| io::Error::other("different HEAD identities were accepted"))?;

        assert_eq!(error.exit_code(), ExitCode::EnvironmentUnmet);
        assert_eq!(error.diagnostic().code.as_str(), "FGE3215");
        Ok(())
    }

    #[test]
    fn post_run_error_names_only_the_successfully_persisted_observation() {
        let error = with_persisted_observation(
            AppError::environment_unmet(
                "FGE3209",
                "scope unavailable",
                "after command execution",
                "repository changed",
                "repair the repository and retry",
            ),
            "0123456789abcdef",
        );

        assert_eq!(error.exit_code(), ExitCode::EnvironmentUnmet);
        assert_eq!(error.diagnostic().code.as_str(), "FGE3209");
        assert!(
            error
                .diagnostic()
                .why
                .contains("receipt:blake3:0123456789abcdef")
        );
        assert!(
            error
                .diagnostic()
                .why
                .contains("receipts/v2/0123456789abcdef.json")
        );
        assert!(
            error
                .diagnostic()
                .why
                .contains("observation-only (non-proving)")
        );
    }

    #[test]
    fn persisted_post_run_scope_failures_keep_their_typed_terminal_exit() {
        for (kind, expected_exit, expected_code) in [
            (
                GitErrorKind::CommandFailed,
                ExitCode::EnvironmentUnmet,
                "FGE3209",
            ),
            (GitErrorKind::TimedOut, ExitCode::Timeout, "FGE3207"),
            (GitErrorKind::Interrupted, ExitCode::Interrupted, "FGE3208"),
        ] {
            let error = map_post_run_scope_error(ScopeAcquisitionError::Git(GitError::new(
                kind,
                "status",
                "fixture failure",
            )));
            let error = with_persisted_observation(error, "0123456789abcdef");

            assert_eq!(error.exit_code(), expected_exit, "Git error kind {kind:?}");
            assert_eq!(
                error.diagnostic().code.as_str(),
                expected_code,
                "Git error kind {kind:?}"
            );
            assert!(
                error
                    .diagnostic()
                    .why
                    .contains("receipt:blake3:0123456789abcdef")
            );
        }
    }
}
