//! Read-only recomputation and explicit export of current local Evidence.
//!
//! Persisted Evidence objects are historical summaries only. Every invocation reloads immutable
//! Receipt objects through the validating codec, recomputes all current dependencies from one
//! retained project detection and one whole-repository scope, and applies the effective policy
//! again. A second detection and scope acquisition must match before any result is emitted or
//! persisted. `show` and `verify` never create application state; only `export` persists the
//! canonical bytes it also emits in JSON mode.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io;

use forge_core::evidence::{
    BaseTaskDependency, DependencyValidity, DependencyValue, EvidenceDependencyFingerprint,
    EvidenceOutcome, ExecutionDependencyFingerprint, LocalEvidenceState, ReceiptValidity,
    ReceiptValidityInput, evaluate_local_evidence, evaluate_receipt_validity,
};
use forge_core::fingerprint::{
    aggregate_ordered_execution_dependencies, bind_command_set_confidence,
    command_dependency_digest, evidence_behavior_digest, validate_command_privacy,
    worktree_base_task_dependency,
};
use forge_core::navigation::{NavigationIssue, ReceiptObservation};
use forge_core::ports::{Clock, ExecSpec};
use forge_core::scope::{
    PreparedScope, ScopeHead, prepared_scope_dependency_digest, scope_dependency_digest,
};
use forge_core::{
    AppError, CommandSpec, Confidence, ExitCode, GitErrorKind, Intent, Mutability,
    OperationControl, OperationControlError, ProjectModel, RiskAssessment, RiskLevel, WorkState,
    assess_risk, comparison_basis_v2_to_wire, coverage_dimension_name,
    local_evidence_state_to_wire, non_satisfying_receipt_validity_v2_to_wire,
};
use forge_detect::model::ModelDetectionCompletion;
use forge_detect::policy::PolicyBaseCompleteness;
use forge_detect::rust::rust_coverage_expectations;
use forge_runtime::clock::SystemClock;
use forge_runtime::control::OperationBudget;
use forge_runtime::fs::FileSystemError;
use forge_runtime::git::GitCli;
use forge_runtime::hash::Blake3Hasher;
use forge_runtime::process::{SynchronousProcessRunner, process_environment_dependency_digest};
use forge_runtime::scope::{
    ScopeAcquisitionError, acquire_repository_scope_controlled,
    prepare_repository_scope_candidate_controlled,
};
use forge_runtime::state::{
    AtomicStateStore, EvidenceStateDecodeError, EvidenceStateObjectKind, EvidenceStateVersion,
    GitStateLayout, StateError, UtcTimestamp, format_utc_rfc3339,
};
use forge_runtime::toolchain::{
    ToolchainProbeRequest, probe_toolchain_dependency_digest_controlled,
    required_probes_for_command,
};
use forge_schema::{
    ComparisonContextV2Data, CurrentReceiptSchemaV2Data, Diagnostic, DigestDependencyV2Data,
    Envelope, EvidenceId, EvidenceV2Data, ExternalRequirementData,
    HistoricalDependencyValidityV2Data, HistoricalReceiptApplicabilityV2Data,
    HistoricalReceiptReasonV2Data, IntentData, LocalEvidenceStateData, PassingOutcomeV2Data,
    RiskAssessmentData, RiskLevelData, SchemaKind, Severity, StaleReceiptV2Data, TrustLevelData,
    ValidReceiptV2Data,
};

use crate::args::Cli;
use crate::evidence_state::{
    JsonEvidenceStateCodec, ReceiptBindingFact, ReceiptEvaluationProjection, load_evidence,
    load_receipt, prepare_evidence, validate_evidence_receipt_bindings,
};
use crate::explain;

const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_LOG_MAX_BYTES: usize = 10 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EvidenceViewCommand {
    Show,
    Verify,
    Export,
}

impl EvidenceViewCommand {
    const fn name(self) -> &'static str {
        match self {
            Self::Show => "show",
            Self::Verify => "verify",
            Self::Export => "export",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EvidenceViewOutcome {
    pub(crate) evidence_bytes: Vec<u8>,
    pub(crate) evidence_object: String,
    pub(crate) data: EvidenceV2Data,
    pub(crate) command: EvidenceViewCommand,
    pub(crate) persisted: bool,
    pub(crate) exit_code: ExitCode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NavigationReceiptsOutcome {
    pub(crate) observation: ReceiptObservation,
    pub(crate) terminal_exit_code: Option<ExitCode>,
}

/// Adds the immutable Evidence identity to a terminal error observed after export persistence.
pub(crate) fn with_persisted_evidence(error: AppError, object_name: &str) -> AppError {
    let diagnostic = error.diagnostic();
    let evidence_id = format!("evidence:blake3:{object_name}");
    let evidence_path = format!("evidence/v2/{object_name}.json");
    AppError::new(
        error.exit_code(),
        Diagnostic::new(
            diagnostic.code.clone(),
            diagnostic.severity,
            diagnostic.what.clone(),
            diagnostic.location.clone(),
            format!(
                "{}; the completed Evidence export was preserved as `{evidence_id}` at `{evidence_path}`",
                diagnostic.why
            ),
            diagnostic.next.clone(),
        ),
    )
}

#[derive(Debug, Clone)]
struct CommonDependencies {
    repository: DependencyValue<forge_schema::RepoId>,
    scope: DependencyValue<forge_schema::Digest>,
    policy: DependencyValue<forge_schema::Digest>,
    base_task: BaseTaskDependency,
    forge_behavior: DependencyValue<forge_schema::Digest>,
}

#[derive(Debug)]
struct EvaluatedReceipt {
    binding: ReceiptBindingFact,
    valid: Option<ValidReceiptV2Data>,
    stale: Option<StaleReceiptV2Data>,
    newest_candidate: Option<NewestReceiptCandidate>,
}

#[derive(Debug)]
struct NewestReceiptCandidate {
    intent: Intent,
    started_at: UtcTimestamp,
    id: String,
    validity: ReceiptValidity,
    verified: Vec<String>,
    advisory: Vec<String>,
    not_verified: Vec<String>,
}

struct ReceiptAggregate {
    newest: BTreeMap<Intent, ReceiptValidity>,
    valid: Vec<ValidReceiptV2Data>,
    stale: Vec<StaleReceiptV2Data>,
    decision_verified: BTreeSet<String>,
    decision_advisory: BTreeSet<String>,
    decision_not_verified: BTreeSet<String>,
}

struct RetainedReceiptEvaluation {
    scope_digest: DependencyValue<forge_schema::Digest>,
    policy_base: DependencyValue<forge_schema::Digest>,
    layout: GitStateLayout,
    receipt_facts: Vec<ReceiptBindingFact>,
    aggregate: ReceiptAggregate,
}

struct LoadedReceiptSnapshot {
    receipt_facts: Vec<ReceiptBindingFact>,
    evaluated: Vec<EvaluatedReceipt>,
}

struct ReceiptEvaluator<'a> {
    model: &'a ProjectModel,
    runner: &'a SynchronousProcessRunner,
    common: CommonDependencies,
    hasher: Blake3Hasher,
    execution_cache: BTreeMap<(Intent, usize), ExecutionDependencyFingerprint>,
    control: &'a dyn OperationControl,
}

pub(crate) fn execute_controlled(
    cli: &Cli,
    command: EvidenceViewCommand,
    control: &OperationBudget,
) -> Result<EvidenceViewOutcome, AppError> {
    execute_with_clock_controlled(cli, command, control, &SystemClock)
}

fn execute_with_clock_controlled<C: Clock + ?Sized>(
    cli: &Cli,
    command: EvidenceViewCommand,
    control: &OperationBudget,
    clock: &C,
) -> Result<EvidenceViewOutcome, AppError> {
    let detected = explain::detect_controlled(cli, control)?;
    require_evaluable_detection(detected.completion)?;
    require_compatible_work_state(detected.model.repository.work_state)?;

    let git = configured_git_controlled(control);
    let (
        scope,
        RetainedReceiptEvaluation {
            scope_digest,
            policy_base,
            layout,
            receipt_facts,
            aggregate,
        },
    ) = evaluate_retained_receipts_controlled(&detected, &git, control)?;
    let hasher = Blake3Hasher;
    let codec = JsonEvidenceStateCodec;

    let risk_paths = detected.navigation.changed_paths();
    let risk = assess_risk(
        &detected.navigation.effective_policy,
        risk_paths.as_deref().unwrap_or_default(),
    );
    let requirements_complete = requirements_are_complete(&detected, &risk, risk_paths.is_some());
    let local = evaluate_local_evidence(
        requirements_complete,
        risk.evidence_requirements.clone(),
        risk.external_requirements.clone(),
        &aggregate.newest,
    );

    let mut not_verified = local
        .not_verified()
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    not_verified.extend(aggregate.decision_not_verified);
    add_missing_coverage_expectations(
        rust_coverage_expectations(&detected.model)
            .iter()
            .map(coverage_dimension_name),
        &aggregate.decision_verified,
        &aggregate.decision_advisory,
        &mut not_verified,
    );
    let coverage_and_gaps = partition_coverage(
        aggregate.decision_verified,
        aggregate.decision_advisory,
        not_verified,
        local.external_required(),
    );

    let confirmation = explain::detect_controlled(cli, control)?;
    require_evaluable_detection(confirmation.completion)?;
    require_compatible_work_state(confirmation.model.repository.work_state)?;
    require_stable_detection(&detected, &confirmation)?;
    let confirmed_scope =
        acquire_repository_scope_controlled(&git, &confirmation.model.repository.root, control)
            .map_err(map_scope_confirmation_error)?;
    require_same_detection_baseline(&confirmation.model, &confirmed_scope)?;
    let confirmed_scope_digest =
        scope_dependency_digest(&hasher, &DependencyValue::Known(confirmed_scope.clone()));
    require_stable_scope(
        &scope,
        &scope_digest,
        &confirmed_scope,
        &confirmed_scope_digest,
    )?;

    let comparison_basis = comparison_basis_v2_to_wire(scope.head(), &policy_base)
        .map_err(|_| comparison_basis_error())?;
    let created_at = clock.now();
    let created_at_text = format_utc_rfc3339(created_at).map_err(map_timestamp_error)?;
    let data = EvidenceV2Data {
        id: EvidenceId::new(String::new()),
        created_at: created_at_text,
        repository: detected.model.repository.id.clone(),
        comparison: ComparisonContextV2Data {
            basis: comparison_basis,
            candidate_scope_digest: match &scope_digest {
                DependencyValue::Known(digest) => DigestDependencyV2Data::Known(digest.clone()),
                DependencyValue::Unknown => DigestDependencyV2Data::Unknown,
            },
        },
        risk: risk_to_wire(&risk),
        valid_receipts: aggregate.valid,
        stale_receipts: aggregate.stale,
        coverage_and_gaps,
        local_state: local_evidence_state_to_wire(local.state()),
        external_requirements: external_requirements_to_wire(local.external_required()),
        external_attestations: Vec::new(),
        log_refs: Vec::new(),
    };
    let prepared = prepare_evidence(
        Envelope::success(SchemaKind::Evidence, TOOL_VERSION, data.clone()),
        receipt_facts.iter(),
    )
    .map_err(map_decode_error)?;
    let evidence_object = prepared.object_name().as_str().to_owned();
    let evidence_bytes = prepared.bytes().to_vec();
    let persisted = if command == EvidenceViewCommand::Export {
        control
            .checkpoint()
            .map_err(|error| explain::map_operation_control_error(error, "evidence export"))?;
        let store = AtomicStateStore::new_evidence(layout).map_err(map_state_error)?;
        let lock = store.try_lock().map_err(map_state_error)?;
        store
            .persist_current_evidence(
                &lock,
                created_at,
                prepared.object_name(),
                prepared.bytes(),
                &codec,
            )
            .map_err(map_state_error)?;
        if control.checkpoint().is_ok() {
            explain::publish_inventory_cache_after_state_write(&detected);
        }
        true
    } else {
        false
    };
    let exit_code = match command {
        EvidenceViewCommand::Show | EvidenceViewCommand::Export => ExitCode::Ok,
        EvidenceViewCommand::Verify => verify_exit_code(local.state()),
    };
    Ok(EvidenceViewOutcome {
        evidence_bytes,
        evidence_object,
        data,
        command,
        persisted,
        exit_code,
    })
}

/// Recomputes the newest current Receipt set used by `forge next` without acquiring a second
/// project model. Non-navigable project states still validate any existing private state so a
/// malformed object cannot be mistaken for an absent Receipt.
fn navigation_receipts_are_validation_only(
    completion: ModelDetectionCompletion,
    work_state: WorkState,
) -> bool {
    completion != ModelDetectionCompletion::Complete
        || !matches!(
            work_state,
            WorkState::Clean | WorkState::Dirty | WorkState::Unborn
        )
}

pub(crate) fn navigation_receipts_controlled(
    _cli: &Cli,
    detected: &explain::DetectedProject,
    risk: &RiskAssessment,
    control: &OperationBudget,
) -> Result<NavigationReceiptsOutcome, AppError> {
    let log_max_bytes = configured_log_max_bytes(detected)?;
    if navigation_receipts_are_validation_only(
        detected.completion,
        detected.model.repository.work_state,
    ) {
        if let Err(error) =
            validate_retained_receipt_state_controlled(detected, log_max_bytes, control)
        {
            return navigation_receipt_state_error(error);
        }
        let observation = ReceiptObservation::unavailable(vec![forge_core::Provenance {
            rule_id: String::from("navigation.receipts-validation-only.v1"),
            source_path: None,
            source_range: None,
            detail: String::from(
                "private Receipt objects were validated, but the earlier navigation priority does not require current applicability",
            ),
        }])
        .map_err(map_navigation_error)?;
        return Ok(NavigationReceiptsOutcome {
            observation,
            terminal_exit_code: None,
        });
    }

    // Validate the complete retained object graph before deciding whether current applicability can
    // affect navigation. A clean repository still needs this read so corrupt or future private
    // state cannot be hidden behind the earlier idle priority.
    let retained_snapshot =
        match load_retained_receipt_state_controlled(detected, log_max_bytes, None, control) {
            Ok(snapshot) => snapshot,
            Err(error) => return navigation_receipt_state_error(error),
        };
    if detected
        .navigation
        .changed_paths()
        .as_ref()
        .is_some_and(Vec::is_empty)
    {
        let observation = ReceiptObservation::unavailable(vec![forge_core::Provenance {
            rule_id: String::from("navigation.receipts-not-applicable-clean.v1"),
            source_path: None,
            source_range: None,
            detail: String::from(
                "the complete private Receipt/Evidence state was validated, but no changed path exists for current applicability to affect navigation",
            ),
        }])
        .map_err(map_navigation_error)?;
        return Ok(NavigationReceiptsOutcome {
            observation,
            terminal_exit_code: None,
        });
    }

    // An empty, fully validated state snapshot has no dependency claim to compare with the
    // current repository. Avoid constructing a potentially large scope merely to prove that an
    // empty Receipt set stays empty.
    if retained_snapshot.receipt_facts.is_empty() {
        let observation = ReceiptObservation::current(
            requirements_are_complete(
                detected,
                risk,
                detected.navigation.changed_paths().is_some(),
            ),
            risk.evidence_requirements.clone(),
            risk.external_requirements.clone(),
            BTreeMap::new(),
            vec![forge_core::Provenance {
                rule_id: String::from("navigation.no-retained-receipts.v1"),
                source_path: None,
                source_range: None,
                detail: String::from(
                    "the complete read-only private-state snapshot contained no Receipt object, so no current scope comparison was applicable",
                ),
            }],
        )
        .map_err(map_navigation_error)?;
        return Ok(NavigationReceiptsOutcome {
            observation,
            terminal_exit_code: None,
        });
    }

    let git = configured_git_controlled(control);
    let retained = if let Some(seed) = detected.navigation.scope_seed.as_ref() {
        let candidate = prepare_repository_scope_candidate_controlled(
            &detected.model.repository.root,
            &seed.status,
            &seed.index_entries,
            control,
        )
        .map_err(map_scope_error)?;
        let retained = evaluate_retained_receipts_with_scope_controlled(
            detected,
            candidate.prepared_scope(),
            control,
        )?;
        // Receipt evaluation above may read mutable private state and run toolchain probes. Keep
        // this confirmation after every dependent read. A successful confirmation returns the
        // exact scope already digested by the evaluator, so recomputing or comparing it is
        // redundant.
        let confirmed_scope = candidate
            .confirm_controlled(&git, control)
            .map_err(map_scope_confirmation_error)?;
        require_same_detection_baseline(&detected.model, &confirmed_scope)?;
        retained
    } else {
        let (retained_scope, retained) =
            evaluate_retained_receipts_controlled(detected, &git, control)?;
        let confirmed_scope =
            acquire_repository_scope_controlled(&git, &detected.model.repository.root, control)
                .map_err(map_scope_confirmation_error)?;
        require_same_detection_baseline(&detected.model, &confirmed_scope)?;
        let confirmed_scope_digest = DependencyValue::Known(prepared_scope_dependency_digest(
            &Blake3Hasher,
            &confirmed_scope,
        ));
        require_stable_scope(
            &retained_scope,
            &retained.scope_digest,
            &confirmed_scope,
            &confirmed_scope_digest,
        )?;
        retained
    };
    let observation = ReceiptObservation::current(
        requirements_are_complete(
            detected,
            risk,
            detected.navigation.changed_paths().is_some(),
        ),
        risk.evidence_requirements.clone(),
        risk.external_requirements.clone(),
        retained.aggregate.newest,
        vec![forge_core::Provenance {
            rule_id: String::from("navigation.current-receipts.v1"),
            source_path: None,
            source_range: None,
            detail: String::from(
                "private Receipt state was validated and current dependencies were recomputed from the retained project snapshot",
            ),
        }],
    )
    .map_err(map_navigation_error)?;
    Ok(NavigationReceiptsOutcome {
        observation,
        terminal_exit_code: None,
    })
}

fn configured_git_controlled(control: &OperationBudget) -> GitCli {
    GitCli::new().with_operation_budget(control.clone())
}

fn evaluate_retained_receipts_controlled(
    detected: &explain::DetectedProject,
    git: &GitCli,
    control: &OperationBudget,
) -> Result<(PreparedScope, RetainedReceiptEvaluation), AppError> {
    let scope = acquire_repository_scope_controlled(git, &detected.model.repository.root, control)
        .map_err(map_scope_error)?;
    let retained = evaluate_retained_receipts_with_scope_controlled(detected, &scope, control)?;
    Ok((scope, retained))
}

fn evaluate_retained_receipts_with_scope_controlled(
    detected: &explain::DetectedProject,
    scope: &PreparedScope,
    control: &OperationBudget,
) -> Result<RetainedReceiptEvaluation, AppError> {
    require_same_detection_baseline(&detected.model, scope)?;

    let hasher = Blake3Hasher;
    let scope_digest = DependencyValue::Known(prepared_scope_dependency_digest(&hasher, scope));
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
    let common = CommonDependencies {
        repository,
        scope: scope_digest.clone(),
        policy,
        base_task: worktree_base_task_dependency(&hasher, scope.head()),
        forge_behavior: DependencyValue::Known(evidence_behavior_digest(&hasher)),
    };
    let runner = SynchronousProcessRunner::new(&detected.model.repository.root)
        .map_err(map_process_setup_error)?
        .with_cancellation_flag(control.cancellation_flag());
    let mut evaluator = ReceiptEvaluator {
        model: &detected.model,
        runner: &runner,
        common,
        hasher,
        execution_cache: BTreeMap::new(),
        control,
    };
    let log_max_bytes = configured_log_max_bytes(detected)?;
    let loaded = load_retained_receipt_state_controlled(
        detected,
        log_max_bytes,
        Some(&mut evaluator),
        control,
    )
    .map_err(map_state_error)?;
    Ok(RetainedReceiptEvaluation {
        scope_digest,
        policy_base,
        layout: evidence_layout(detected),
        receipt_facts: loaded.receipt_facts,
        aggregate: aggregate_receipts(loaded.evaluated),
    })
}

/// Validates the complete retained Receipt/Evidence closure without creating or repairing state.
///
/// The typed [`StateError`] is intentionally preserved so doctor and navigation can distinguish a
/// future layout from corruption without parsing diagnostics or exposing private paths.
pub(crate) fn validate_retained_receipt_state_controlled(
    detected: &explain::DetectedProject,
    configured_log_max_bytes: usize,
    control: &dyn OperationControl,
) -> Result<(), StateError> {
    load_retained_receipt_state_controlled(detected, configured_log_max_bytes, None, control)
        .map(|_| ())
}

fn load_retained_receipt_state_controlled(
    detected: &explain::DetectedProject,
    configured_log_max_bytes: usize,
    mut evaluator: Option<&mut ReceiptEvaluator<'_>>,
    control: &dyn OperationControl,
) -> Result<LoadedReceiptSnapshot, StateError> {
    control
        .checkpoint()
        .map_err(operation_control_state_error)?;
    let layout = evidence_layout(detected);
    let codec = JsonEvidenceStateCodec;
    let mut receipt_facts = Vec::new();
    let mut evaluated = Vec::new();
    if let Some(store) = AtomicStateStore::open_existing_evidence_read_only(layout)? {
        store.visit_evidence_state_snapshot_controlled(
            configured_log_max_bytes,
            &codec,
            control,
            |mut object| {
                control.checkpoint().map_err(|error| {
                    io::Error::new(operation_control_io_kind(error), error.to_string())
                })?;
                match object.kind() {
                    EvidenceStateObjectKind::Receipt(version) => {
                        let bytes = read_snapshot_bytes(&mut object)?;
                        let receipt = load_receipt(version, object.object_name(), &bytes)
                            .map_err(decode_io_error)?;
                        let projection =
                            receipt.evaluation_projection().map_err(decode_io_error)?;
                        if let Some(evaluator) = evaluator.as_deref_mut() {
                            let result = evaluator.evaluate(projection).map_err(decode_io_error)?;
                            receipt_facts.push(result.binding.clone());
                            evaluated.push(result);
                        } else {
                            receipt_facts.push(projection.binding);
                        }
                    }
                    EvidenceStateObjectKind::Evidence(version) => {
                        let bytes = read_snapshot_bytes(&mut object)?;
                        let evidence = load_evidence(version, object.object_name(), &bytes)
                            .map_err(decode_io_error)?;
                        validate_evidence_receipt_bindings(&evidence, &receipt_facts)
                            .map_err(decode_io_error)?;
                    }
                    EvidenceStateObjectKind::LogV1 => {}
                }
                Ok(())
            },
        )?;
    }
    Ok(LoadedReceiptSnapshot {
        receipt_facts,
        evaluated,
    })
}

fn operation_control_state_error(error: OperationControlError) -> StateError {
    StateError::Io {
        operation: "check evidence operation budget",
        path: std::path::PathBuf::from("evidence-state"),
        source: io::Error::new(operation_control_io_kind(error), error.to_string()),
    }
}

const fn operation_control_io_kind(error: OperationControlError) -> io::ErrorKind {
    match error {
        OperationControlError::TimedOut => io::ErrorKind::TimedOut,
        OperationControlError::Interrupted => io::ErrorKind::Interrupted,
    }
}

fn evidence_layout(detected: &explain::DetectedProject) -> GitStateLayout {
    GitStateLayout::new(
        detected.model.repository.git_dir.clone(),
        detected.model.repository.git_common_dir.clone(),
    )
}

impl ReceiptEvaluator<'_> {
    fn evaluate(
        &mut self,
        projection: ReceiptEvaluationProjection,
    ) -> Result<EvaluatedReceipt, EvidenceStateDecodeError> {
        if projection.version == EvidenceStateVersion::V1 {
            return Ok(EvaluatedReceipt {
                binding: projection.binding,
                valid: None,
                stale: Some(StaleReceiptV2Data::ReceiptV1 {
                    id: projection.id,
                    intent: projection.intent,
                    outcome: forge_core::evidence_outcome_to_wire(projection.outcome),
                    dependency_validity: HistoricalDependencyValidityV2Data::Unknown,
                    applicability: HistoricalReceiptApplicabilityV2Data::Unknown,
                    reason: HistoricalReceiptReasonV2Data::HistoricalIncompatible,
                }),
                newest_candidate: None,
            });
        }

        let Some(intent) = projection.domain_intent else {
            return self.non_proving_current(projection);
        };
        let Some(current_projection) = projection.current else {
            return self.non_proving_current(projection);
        };
        let current_execution = self.current_execution(
            intent,
            current_projection.commands.len(),
            projection.outcome,
        );
        let current = EvidenceDependencyFingerprint::new(
            self.common.repository.clone(),
            self.common.scope.clone(),
            current_execution,
            self.common.policy.clone(),
            self.common.base_task.clone(),
            self.common.forge_behavior.clone(),
        );
        let validity = evaluate_receipt_validity(&current_projection.recorded, &current);
        let Some(started_at) = projection.started_at else {
            return Err(EvidenceStateDecodeError::InvalidTimestamp);
        };
        let is_current_pass = validity.is_current_passing_local_observation();
        let newest_candidate = (validity.dependency_validity() == DependencyValidity::Current)
            .then(|| NewestReceiptCandidate {
                intent,
                started_at,
                id: projection.id.as_str().to_owned(),
                validity: validity.clone(),
                verified: if is_current_pass {
                    projection.coverage.clone()
                } else {
                    Vec::new()
                },
                advisory: current_projection.advisory.clone(),
                not_verified: current_projection.not_verified.clone(),
            });
        if is_current_pass {
            return Ok(EvaluatedReceipt {
                binding: projection.binding,
                valid: Some(ValidReceiptV2Data {
                    schema: CurrentReceiptSchemaV2Data::ReceiptV2,
                    id: projection.id,
                    intent: projection.intent,
                    outcome: PassingOutcomeV2Data::Pass,
                    coverage: projection.coverage,
                }),
                stale: None,
                newest_candidate,
            });
        }
        Ok(EvaluatedReceipt {
            binding: projection.binding,
            valid: None,
            stale: Some(StaleReceiptV2Data::ReceiptV2 {
                id: projection.id,
                intent: projection.intent,
                validity: non_satisfying_receipt_validity_v2_to_wire(&validity)
                    .map_err(|_| EvidenceStateDecodeError::Malformed)?,
            }),
            newest_candidate,
        })
    }

    fn non_proving_current(
        &self,
        projection: ReceiptEvaluationProjection,
    ) -> Result<EvaluatedReceipt, EvidenceStateDecodeError> {
        let unknown_execution = ExecutionDependencyFingerprint::new(
            DependencyValue::Unknown,
            DependencyValue::Unknown,
            DependencyValue::Unknown,
        );
        let unknown = EvidenceDependencyFingerprint::new(
            DependencyValue::Unknown,
            DependencyValue::Unknown,
            unknown_execution,
            DependencyValue::Unknown,
            BaseTaskDependency::Unknown,
            DependencyValue::Unknown,
        );
        let recorded = ReceiptValidityInput::new(
            unknown,
            DependencyValue::Unknown,
            Mutability::Unknown,
            projection.outcome,
        );
        let current = EvidenceDependencyFingerprint::new(
            self.common.repository.clone(),
            self.common.scope.clone(),
            ExecutionDependencyFingerprint::new(
                DependencyValue::Unknown,
                DependencyValue::Unknown,
                DependencyValue::Unknown,
            ),
            self.common.policy.clone(),
            self.common.base_task.clone(),
            self.common.forge_behavior.clone(),
        );
        let validity = evaluate_receipt_validity(&recorded, &current);
        Ok(EvaluatedReceipt {
            binding: projection.binding,
            valid: None,
            stale: Some(StaleReceiptV2Data::ReceiptV2 {
                id: projection.id,
                intent: projection.intent,
                validity: non_satisfying_receipt_validity_v2_to_wire(&validity)
                    .map_err(|_| EvidenceStateDecodeError::Malformed)?,
            }),
            newest_candidate: None,
        })
    }

    fn current_execution(
        &mut self,
        intent: Intent,
        observed_commands: usize,
        recorded_outcome: EvidenceOutcome,
    ) -> ExecutionDependencyFingerprint {
        let Some(command_set) = self.model.commands.get(&intent) else {
            return unknown_execution_dependencies();
        };
        let Some(commands) = command_set.executable_commands() else {
            return unknown_execution_dependencies();
        };
        if command_set.resolution_confidence == Confidence::Unknown {
            return unknown_execution_dependencies();
        }
        let selected = &commands
            [..selected_command_count(commands.len(), observed_commands, recorded_outcome)];
        let key = (intent, selected.len());
        if let Some(cached) = self.execution_cache.get(&key) {
            return cached.clone();
        }
        let dependencies = selected
            .iter()
            .map(|command| self.command_execution_dependency(command, &command_set.provenance))
            .collect::<Vec<_>>();
        let aggregate = aggregate_ordered_execution_dependencies(&self.hasher, &dependencies);
        let aggregate = bind_command_set_confidence(
            &self.hasher,
            &aggregate,
            command_set.resolution_confidence,
            command_set.coverage_confidence,
        );
        self.execution_cache.insert(key, aggregate.clone());
        aggregate
    }

    fn command_execution_dependency(
        &self,
        command: &CommandSpec,
        provenance: &[forge_core::Provenance],
    ) -> ExecutionDependencyFingerprint {
        if self.control.checkpoint().is_err() {
            return unknown_execution_dependencies();
        }
        if validate_command_privacy(command).is_err() {
            return unknown_execution_dependencies();
        }
        let spec = ExecSpec::from_project_command(command);
        let command_dependency = command_dependency_digest(&self.hasher, command, provenance)
            .unwrap_or(DependencyValue::Unknown);
        let environment = process_environment_dependency_digest(&spec, &self.hasher)
            .unwrap_or(DependencyValue::Unknown);
        let toolchain =
            required_probes_for_command(command).map_or(DependencyValue::Unknown, |probes| {
                let request =
                    ToolchainProbeRequest::for_probes(spec.cwd.clone(), spec.env.clone(), probes);
                probe_toolchain_dependency_digest_controlled(
                    self.runner,
                    &request,
                    &self.hasher,
                    self.control,
                )
            });
        ExecutionDependencyFingerprint::new(command_dependency, toolchain, environment)
    }
}

fn unknown_execution_dependencies() -> ExecutionDependencyFingerprint {
    ExecutionDependencyFingerprint::new(
        DependencyValue::Unknown,
        DependencyValue::Unknown,
        DependencyValue::Unknown,
    )
}

fn selected_command_count(
    current_commands: usize,
    observed_commands: usize,
    recorded_outcome: EvidenceOutcome,
) -> usize {
    if recorded_outcome == EvidenceOutcome::Pass {
        current_commands
    } else {
        observed_commands.min(current_commands)
    }
}

fn aggregate_receipts(evaluated: Vec<EvaluatedReceipt>) -> ReceiptAggregate {
    let mut newest = BTreeMap::<Intent, NewestReceiptCandidate>::new();
    let mut valid = Vec::new();
    let mut stale = Vec::new();
    for receipt in evaluated {
        if let Some(candidate) = receipt.newest_candidate {
            let replace = newest
                .get(&candidate.intent)
                .is_none_or(|existing| candidate_is_newer(&candidate, existing));
            if replace {
                newest.insert(candidate.intent, candidate);
            }
        }
        valid.extend(receipt.valid);
        stale.extend(receipt.stale);
    }
    valid.sort_by(|left, right| {
        intent_data_name(left.intent)
            .cmp(intent_data_name(right.intent))
            .then_with(|| left.id.as_str().cmp(right.id.as_str()))
    });
    stale.sort_by(|left, right| stale_receipt_id(left).cmp(stale_receipt_id(right)));
    let mut newest_validity = BTreeMap::new();
    let mut decision_verified = BTreeSet::new();
    let mut decision_advisory = BTreeSet::new();
    let mut decision_not_verified = BTreeSet::new();
    for (intent, receipt) in newest {
        newest_validity.insert(intent, receipt.validity);
        decision_verified.extend(receipt.verified);
        decision_advisory.extend(receipt.advisory);
        decision_not_verified.extend(receipt.not_verified);
    }
    ReceiptAggregate {
        newest: newest_validity,
        valid,
        stale,
        decision_verified,
        decision_advisory,
        decision_not_verified,
    }
}

fn candidate_is_newer(
    candidate: &NewestReceiptCandidate,
    existing: &NewestReceiptCandidate,
) -> bool {
    receipt_order_is_newer(
        candidate.started_at,
        candidate.id.as_str(),
        existing.started_at,
        existing.id.as_str(),
    )
}

fn receipt_order_is_newer(
    candidate_started_at: UtcTimestamp,
    candidate_id: &str,
    existing_started_at: UtcTimestamp,
    existing_id: &str,
) -> bool {
    (candidate_started_at, candidate_id) > (existing_started_at, existing_id)
}

fn partition_coverage(
    mut verified: BTreeSet<String>,
    mut advisory: BTreeSet<String>,
    mut not_verified: BTreeSet<String>,
    external_required: &[String],
) -> forge_schema::CoverageStatementData {
    let external_required = external_required.iter().cloned().collect::<BTreeSet<_>>();
    not_verified.retain(|dimension| !external_required.contains(dimension));
    advisory.retain(|dimension| {
        !external_required.contains(dimension) && !not_verified.contains(dimension)
    });
    verified.retain(|dimension| {
        !external_required.contains(dimension)
            && !not_verified.contains(dimension)
            && !advisory.contains(dimension)
    });
    forge_schema::CoverageStatementData {
        verified: verified.into_iter().collect(),
        advisory: advisory.into_iter().collect(),
        not_verified: not_verified.into_iter().collect(),
        external_required: external_required.into_iter().collect(),
    }
}

fn add_missing_coverage_expectations(
    expected: impl IntoIterator<Item = String>,
    verified: &BTreeSet<String>,
    advisory: &BTreeSet<String>,
    not_verified: &mut BTreeSet<String>,
) {
    for dimension in expected {
        if !verified.contains(&dimension)
            && !advisory.contains(&dimension)
            && !not_verified.contains(&dimension)
        {
            not_verified.insert(dimension);
        }
    }
}

fn read_snapshot_bytes(
    object: &mut forge_runtime::state::EvidenceStateObjectSnapshot<'_>,
) -> io::Result<Vec<u8>> {
    let size = usize::try_from(object.size())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "state object size overflow"))?;
    let mut bytes = Vec::with_capacity(size);
    object.bytes().read_to_end(&mut bytes)?;
    if bytes.len() != size {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "state object ended before its validated size",
        ));
    }
    Ok(bytes)
}

fn decode_io_error(error: EvidenceStateDecodeError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

pub(crate) fn configured_log_max_bytes(
    detected: &explain::DetectedProject,
) -> Result<usize, AppError> {
    let configured = detected
        .navigation
        .config
        .as_ref()
        .and_then(|config| config.policy.max_log_file_bytes);
    configured.map_or(Ok(DEFAULT_LOG_MAX_BYTES), |value| {
        usize::try_from(value).map_err(|_| {
            AppError::data(
                "FGE3301",
                "the configured Evidence log bound is not representable on this platform",
                "policy.max_log_file_bytes",
                "the configured unsigned byte count exceeds the platform address space",
                "choose a smaller positive log bound and rerun the Evidence command",
            )
        })
    })
}

fn requirements_are_complete(
    detected: &explain::DetectedProject,
    risk: &RiskAssessment,
    status_available: bool,
) -> bool {
    detected.completion == ModelDetectionCompletion::Complete
        && status_available
        && detected.navigation.policy_base_completeness == PolicyBaseCompleteness::Complete
        && detected.model.policy.confidence != Confidence::Unknown
        && !detected.model.policy.provenance.is_empty()
        && !risk_has_unclassified_paths(risk)
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

fn risk_to_wire(risk: &RiskAssessment) -> RiskAssessmentData {
    let mut provenance = risk
        .provenance
        .iter()
        .chain(
            risk.uncertain_assumptions
                .iter()
                .flat_map(|assumption| assumption.provenance.iter()),
        )
        .map(|source| source.rule_id.clone())
        .collect::<Vec<_>>();
    provenance.sort();
    provenance.dedup();
    RiskAssessmentData {
        level: match risk.level {
            RiskLevel::Low => RiskLevelData::Low,
            RiskLevel::Medium => RiskLevelData::Medium,
            RiskLevel::High => RiskLevelData::High,
            RiskLevel::Critical => RiskLevelData::Critical,
            RiskLevel::Unknown => RiskLevelData::Unknown,
        },
        matched: risk
            .matched
            .iter()
            .map(|matched| matched.rule_id.clone())
            .collect(),
        provenance,
    }
}

fn external_requirements_to_wire(requirements: &[String]) -> Vec<ExternalRequirementData> {
    requirements
        .iter()
        .map(|id| ExternalRequirementData {
            id: id.clone(),
            // Policy stores an identifier, not a verifiable authority mechanism. Guessing from a
            // name such as `protected-ci` would manufacture trust semantics, so v0 remains unknown.
            trust_level: TrustLevelData::Unknown,
            reason: String::from(
                "effective risk policy requires an external input that local Evidence cannot satisfy",
            ),
        })
        .collect()
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

fn require_evaluable_detection(completion: ModelDetectionCompletion) -> Result<(), AppError> {
    match completion {
        ModelDetectionCompletion::Complete | ModelDetectionCompletion::Partial => Ok(()),
        ModelDetectionCompletion::TimedOut => Err(AppError::new(
            ExitCode::Timeout,
            Diagnostic::new(
                "FGE3302",
                Severity::Error,
                "project detection timed out before local Evidence could be evaluated",
                "project model",
                "the comparison context is incomplete",
                "increase `--timeout` or reduce repository discovery cost, then retry",
            ),
        )),
        ModelDetectionCompletion::Interrupted => Err(AppError::new(
            ExitCode::Interrupted,
            Diagnostic::new(
                "FGE3303",
                Severity::Error,
                "project detection was interrupted before local Evidence could be evaluated",
                "project model",
                "no Evidence decision was produced",
                "rerun the Evidence command when ready",
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
        "FGE3304",
        "the repository state has no stable v0 Evidence comparison",
        "Git worktree state",
        "merge, rebase, conflict, corrupt, and unknown states cannot form the v0 HEAD comparison basis",
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
        "FGE3305",
        "the repository baseline changed during Evidence preparation",
        "HEAD comparison basis",
        "project detection and current scope did not observe the same HEAD state",
        "stop concurrent Git changes and rerun the Evidence command",
    ))
}

fn require_stable_detection(
    retained: &explain::DetectedProject,
    confirmation: &explain::DetectedProject,
) -> Result<(), AppError> {
    if retained.completion == confirmation.completion
        && retained.model == confirmation.model
        && retained.navigation == confirmation.navigation
    {
        return Ok(());
    }
    Err(AppError::environment_unmet(
        "FGE3312",
        "project detection changed while local Evidence was being evaluated",
        "project model and navigation snapshot",
        "the confirmation scan did not reproduce the retained command, policy, provenance, or repository facts",
        "stop concurrent repository changes and rerun the Evidence command",
    ))
}

fn require_stable_scope(
    retained: &PreparedScope,
    retained_digest: &DependencyValue<forge_schema::Digest>,
    confirmation: &PreparedScope,
    confirmation_digest: &DependencyValue<forge_schema::Digest>,
) -> Result<(), AppError> {
    if retained == confirmation && retained_digest == confirmation_digest {
        return Ok(());
    }
    Err(scope_drift_error(
        "the confirmation scope did not reproduce the retained HEAD and content identities",
    ))
}

fn map_scope_error(error: ScopeAcquisitionError) -> AppError {
    match error {
        ScopeAcquisitionError::Control(error) => {
            explain::map_operation_control_error(error, "whole-repository Evidence scope")
        }
        ScopeAcquisitionError::Git(error) => match error.kind() {
            GitErrorKind::TimedOut => explain::map_operation_control_error(
                OperationControlError::TimedOut,
                "whole-repository Evidence scope",
            ),
            GitErrorKind::Interrupted => explain::map_operation_control_error(
                OperationControlError::Interrupted,
                "whole-repository Evidence scope",
            ),
            GitErrorKind::ExecutableUnavailable
            | GitErrorKind::UnsafeEnvironment
            | GitErrorKind::NotRepository
            | GitErrorKind::CorruptRepository
            | GitErrorKind::OutputLimit
            | GitErrorKind::InvalidData
            | GitErrorKind::CommandFailed
            | GitErrorKind::Io => scope_acquisition_error(error.into()),
        },
        error => scope_acquisition_error(error),
    }
}

fn map_scope_confirmation_error(error: ScopeAcquisitionError) -> AppError {
    match error {
        error @ (ScopeAcquisitionError::RepositoryChanged
        | ScopeAcquisitionError::WorktreePathChanged { .. }) => {
            scope_drift_error(error.to_string())
        }
        error => map_scope_error(error),
    }
}

fn scope_acquisition_error(error: ScopeAcquisitionError) -> AppError {
    AppError::environment_unmet(
        "FGE3306",
        "the current repository scope could not be acquired completely",
        "whole-repository Evidence scope",
        error.to_string(),
        "repair the Git repository or unreadable worktree path, then retry",
    )
}

fn scope_drift_error(detail: impl Into<String>) -> AppError {
    AppError::environment_unmet(
        "FGE3313",
        "repository scope changed while local Evidence was being evaluated",
        "whole-repository Evidence scope",
        detail,
        "stop concurrent worktree or Git changes and rerun the Evidence command",
    )
}

fn map_process_setup_error(error: forge_core::ports::ProcessError) -> AppError {
    AppError::environment_unmet(
        "FGE3307",
        "the bounded metadata process runner could not be initialized",
        "Evidence dependency probes",
        error.to_string(),
        "ensure the repository root is a readable real directory, then retry",
    )
}

fn map_state_error(error: StateError) -> AppError {
    let exit_code = crate::state_diagnostic::state_error_exit_code(&error);
    AppError::new(
        exit_code,
        Diagnostic::new(
            "FGE3308",
            Severity::Error,
            "private Evidence state is invalid or unavailable",
            "worktree-private Git state",
            error.to_string(),
            "repair the private state permissions or corruption, then rerun the Evidence command",
        ),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetainedStateIssueKind {
    Future,
    Corrupt,
}

fn navigation_receipt_state_error(
    error: StateError,
) -> Result<NavigationReceiptsOutcome, AppError> {
    let Some(kind) = retained_state_issue_kind(&error) else {
        return Err(map_state_error(error));
    };
    let (reason, rule_id, detail) = match kind {
        RetainedStateIssueKind::Future => (
            "retained private Evidence state uses a newer schema or layout than this Forge binary supports",
            "navigation.receipts-future.v1",
            "navigation preserved the future state unchanged and cannot interpret it as current Receipt evidence",
        ),
        RetainedStateIssueKind::Corrupt => (
            "retained private Evidence state is corrupt and cannot be used for navigation",
            "navigation.receipts-corrupt.v1",
            "the read-only typed state boundary rejected the retained object graph without repairing or exposing it",
        ),
    };
    let issue = NavigationIssue::new(
        reason,
        vec![forge_core::Provenance {
            rule_id: rule_id.to_owned(),
            source_path: None,
            source_range: None,
            detail: detail.to_owned(),
        }],
    )
    .map_err(map_navigation_error)?;
    let observation = match kind {
        RetainedStateIssueKind::Future => ReceiptObservation::Insufficient(issue),
        RetainedStateIssueKind::Corrupt => ReceiptObservation::Corrupt(issue),
    };
    Ok(NavigationReceiptsOutcome {
        observation,
        terminal_exit_code: Some(ExitCode::DataError),
    })
}

fn retained_state_issue_kind(error: &StateError) -> Option<RetainedStateIssueKind> {
    match error {
        StateError::UnsupportedEvidenceStateVersion { .. }
        | StateError::ObjectDecode {
            reason: EvidenceStateDecodeError::FutureSchema,
            ..
        } => Some(RetainedStateIssueKind::Future),
        StateError::InvalidLayout { .. }
        | StateError::UnsafeKey { .. }
        | StateError::ReservedStatePath { .. }
        | StateError::EntryLimit { .. }
        | StateError::RetainedObjectCountExceeded { .. }
        | StateError::ObjectTooLarge { .. }
        | StateError::ObjectDecode { .. }
        | StateError::ObjectIdentityMismatch { .. }
        | StateError::ObjectContentAddressMismatch { .. }
        | StateError::MissingReference { .. }
        | StateError::RetainedBudgetExceeded { .. }
        | StateError::ScanByteLimit { .. }
        | StateError::ReferenceLimit { .. }
        | StateError::StateSizeOverflow => Some(RetainedStateIssueKind::Corrupt),
        StateError::PathSafety(FileSystemError::Io { source, .. })
            if source.kind() == io::ErrorKind::InvalidData =>
        {
            Some(RetainedStateIssueKind::Corrupt)
        }
        StateError::PathSafety(FileSystemError::Io { .. }) => None,
        StateError::PathSafety(_) => Some(RetainedStateIssueKind::Corrupt),
        StateError::Io { source, .. } if source.kind() == io::ErrorKind::InvalidData => {
            Some(RetainedStateIssueKind::Corrupt)
        }
        // Lock contention, ordinary I/O/permission failure, platform limitations, and an observed
        // concurrent state change are operational failures rather than evidence of corruption.
        _ => None,
    }
}

fn map_decode_error(error: EvidenceStateDecodeError) -> AppError {
    AppError::data(
        "FGE3309",
        "the recomputed Evidence document is internally inconsistent",
        SchemaKind::Evidence.id(),
        error.to_string(),
        "report this as a Forge implementation defect",
    )
}

fn map_navigation_error(error: forge_core::navigation::NavigationError) -> AppError {
    AppError::internal(
        "FGE3314",
        "the current Receipt observation cannot be represented for navigation",
        "forge next",
        error.to_string(),
        "report this as a Forge implementation defect",
    )
}

fn map_timestamp_error(error: forge_runtime::state::UtcTimestampError) -> AppError {
    AppError::internal(
        "FGE3310",
        "the Evidence creation time cannot be represented",
        SchemaKind::Evidence.id(),
        error.to_string(),
        "correct the system clock or report this as a Forge implementation defect",
    )
}

fn comparison_basis_error() -> AppError {
    AppError::internal(
        "FGE3311",
        "the acquired comparison basis cannot be represented",
        SchemaKind::Evidence.id(),
        "the validated scope contained an invalid Git object identity",
        "report this as a Forge implementation defect",
    )
}

const fn verify_exit_code(state: LocalEvidenceState) -> ExitCode {
    match state {
        LocalEvidenceState::Sufficient => ExitCode::Ok,
        LocalEvidenceState::Insufficient | LocalEvidenceState::Failing => ExitCode::Negative,
        LocalEvidenceState::Unknown => ExitCode::EnvironmentUnmet,
    }
}

fn stale_receipt_id(receipt: &StaleReceiptV2Data) -> &str {
    match receipt {
        StaleReceiptV2Data::ReceiptV1 { id, .. } | StaleReceiptV2Data::ReceiptV2 { id, .. } => {
            id.as_str()
        }
        StaleReceiptV2Data::Unknown => "",
        _ => "",
    }
}

const fn intent_data_name(intent: IntentData) -> &'static str {
    match intent {
        IntentData::Setup => "setup",
        IntentData::FormatCheck => "format-check",
        IntentData::Format => "format",
        IntentData::Check => "check",
        IntentData::Fix => "fix",
        IntentData::Test => "test",
        IntentData::Verify => "verify",
        IntentData::Build => "build",
        IntentData::Unknown => "unknown",
        _ => "unknown",
    }
}

const fn local_state_name(state: LocalEvidenceStateData) -> &'static str {
    match state {
        LocalEvidenceStateData::Insufficient => "insufficient",
        LocalEvidenceStateData::Failing => "failing",
        LocalEvidenceStateData::Sufficient => "sufficient",
        LocalEvidenceStateData::Unknown => "unknown",
        _ => "unknown",
    }
}

pub(crate) fn render_human(outcome: &EvidenceViewOutcome) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "# Forge local evidence");
    let _ = writeln!(output);
    let _ = writeln!(output, "- operation: {}", outcome.command.name());
    let _ = writeln!(
        output,
        "- local state: {}",
        local_state_name(outcome.data.local_state)
    );
    let _ = writeln!(
        output,
        "- worktree comparison: current HEAD baseline (not a PR or merge approval)"
    );
    let _ = writeln!(output, "- evidence object: {}", outcome.evidence_object);
    let _ = writeln!(output, "- persisted privately: {}", outcome.persisted);
    let _ = writeln!(output);
    let _ = writeln!(
        output,
        "## Current passing receipts ({})",
        outcome.data.valid_receipts.len()
    );
    for receipt in &outcome.data.valid_receipts {
        let _ = writeln!(
            output,
            "- `{}`: {} ({})",
            receipt.id.as_str(),
            intent_data_name(receipt.intent),
            receipt.coverage.join(", ")
        );
    }
    let _ = writeln!(output);
    let _ = writeln!(
        output,
        "## Historical, stale, or non-passing receipts ({})",
        outcome.data.stale_receipts.len()
    );
    for receipt in &outcome.data.stale_receipts {
        match receipt {
            StaleReceiptV2Data::ReceiptV1 { id, intent, .. } => {
                let _ = writeln!(
                    output,
                    "- `{}`: {} (historical-incompatible)",
                    id.as_str(),
                    intent_data_name(*intent)
                );
            }
            StaleReceiptV2Data::ReceiptV2 {
                id,
                intent,
                validity,
            } => {
                let reasons = validity
                    .as_inner()
                    .reasons
                    .iter()
                    .map(|reason| format!("{reason:?}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                let _ = writeln!(
                    output,
                    "- `{}`: {} ({})",
                    id.as_str(),
                    intent_data_name(*intent),
                    reasons
                );
            }
            StaleReceiptV2Data::Unknown => {
                let _ = writeln!(output, "- unknown future receipt summary (non-proving)");
            }
            _ => {
                let _ = writeln!(output, "- unknown future receipt summary (non-proving)");
            }
        }
    }
    let coverage = &outcome.data.coverage_and_gaps;
    let _ = writeln!(output);
    let _ = writeln!(output, "## Coverage and gaps");
    let _ = writeln!(output, "- verified: {}", joined_or_none(&coverage.verified));
    let _ = writeln!(output, "- advisory: {}", joined_or_none(&coverage.advisory));
    let _ = writeln!(
        output,
        "- not verified: {}",
        joined_or_none(&coverage.not_verified)
    );
    let _ = writeln!(
        output,
        "- external required: {}",
        joined_or_none(&coverage.external_required)
    );
    output
}

fn joined_or_none(values: &[String]) -> String {
    if values.is_empty() {
        String::from("none")
    } else {
        values.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::error::Error;
    use std::io;
    use std::path::PathBuf;
    use std::time::{Duration, UNIX_EPOCH};

    use forge_core::evidence::{DependencyValue, EvidenceOutcome};
    use forge_core::scope::{PreparedScope, ScopeHead, scope_dependency_digest};
    use forge_core::{
        AdapterInventory, AssetInventory, Assumption, Confidence, EffectivePolicy, ExitCode,
        GitError, GitErrorKind, GitObjectFormat, InventorySkip, OperationControlError,
        ProjectModel, ProjectModelInputs, Provenance, RepoFacts, RepoRelativePath, RiskAssessment,
        RiskLevel, WorkState,
    };
    use forge_detect::model::ModelDetectionCompletion;
    use forge_detect::policy::PolicyBaseCompleteness;
    use forge_runtime::hash::Blake3Hasher;
    use forge_runtime::scope::ScopeAcquisitionError;
    use forge_runtime::state::parse_utc_rfc3339;
    use forge_schema::RepoId;

    use super::{
        add_missing_coverage_expectations, map_scope_confirmation_error,
        navigation_receipts_are_validation_only, partition_coverage, receipt_order_is_newer,
        require_same_detection_baseline, require_stable_detection, require_stable_scope,
        requirements_are_complete, selected_command_count, with_persisted_evidence,
    };
    use crate::explain::DetectedProject;

    fn provenance(rule_id: &str) -> Provenance {
        Provenance {
            rule_id: rule_id.to_owned(),
            source_path: None,
            source_range: None,
            detail: String::from("test evidence"),
        }
    }

    #[test]
    fn post_export_terminal_error_retains_the_persisted_evidence_identity() {
        let error = forge_core::AppError::new(
            ExitCode::Timeout,
            forge_schema::Diagnostic::new(
                "FGE2004",
                forge_schema::Severity::Error,
                "fixture timeout",
                "evidence result",
                "fixture reason",
                "retry",
            ),
        );

        let error = with_persisted_evidence(error, "0123456789abcdef");

        assert_eq!(error.exit_code(), ExitCode::Timeout);
        assert_eq!(error.diagnostic().code.as_str(), "FGE2004");
        assert!(
            error
                .diagnostic()
                .why
                .contains("evidence:blake3:0123456789abcdef")
        );
        assert!(
            error
                .diagnostic()
                .why
                .contains("evidence/v2/0123456789abcdef.json")
        );
    }

    fn project_model(work_state: WorkState) -> ProjectModel {
        let evidence = || vec![provenance("test.evidence-view")];
        ProjectModel::new(ProjectModelInputs {
            repository: RepoFacts {
                id: RepoId::from("local:blake3:evidence-view-test"),
                root: PathBuf::from("/repo"),
                git_dir: PathBuf::from("/repo/.git"),
                git_common_dir: PathBuf::from("/repo/.git"),
                is_linked_worktree: false,
                head: None,
                branch: None,
                upstream: None,
                work_state,
            },
            repository_provenance: evidence(),
            repository_confidence: Confidence::High,
            unit_inventory_provenance: evidence(),
            unit_inventory_confidence: Confidence::High,
            assets: AssetInventory::new(Vec::new(), evidence(), Confidence::High),
            adapters: AdapterInventory::new(Vec::new(), evidence(), Confidence::High),
            policy: EffectivePolicy::new(None, evidence(), Confidence::High),
        })
    }

    fn classified_risk() -> RiskAssessment {
        RiskAssessment {
            level: RiskLevel::Low,
            matched: Vec::new(),
            provenance: Vec::new(),
            evidence_requirements: Vec::new(),
            external_requirements: Vec::new(),
            uncertain_assumptions: Vec::new(),
        }
    }

    #[test]
    fn navigation_receipts_validate_each_independent_non_navigable_axis() {
        let cases = [
            (ModelDetectionCompletion::Complete, WorkState::Clean, false),
            (ModelDetectionCompletion::Complete, WorkState::Dirty, false),
            (ModelDetectionCompletion::Complete, WorkState::Unborn, false),
            (
                ModelDetectionCompletion::Complete,
                WorkState::Conflicted,
                true,
            ),
            (ModelDetectionCompletion::Complete, WorkState::Merging, true),
            (
                ModelDetectionCompletion::Complete,
                WorkState::Rebasing,
                true,
            ),
            (ModelDetectionCompletion::Complete, WorkState::Corrupt, true),
            (ModelDetectionCompletion::Complete, WorkState::Unknown, true),
            (ModelDetectionCompletion::Partial, WorkState::Unborn, true),
            (ModelDetectionCompletion::TimedOut, WorkState::Clean, true),
            (
                ModelDetectionCompletion::Interrupted,
                WorkState::Dirty,
                true,
            ),
        ];

        for (completion, work_state, expected) in cases {
            assert_eq!(
                navigation_receipts_are_validation_only(completion, work_state),
                expected,
                "unexpected validation-only decision for {completion:?}/{work_state:?}"
            );
        }
    }

    #[test]
    fn coverage_partitions_are_disjoint_with_conservative_priority() {
        let statement = partition_coverage(
            BTreeSet::from([
                String::from("verified-only"),
                String::from("advisory-wins"),
                String::from("not-verified-wins"),
                String::from("external-wins"),
            ]),
            BTreeSet::from([
                String::from("advisory-wins"),
                String::from("not-verified-wins"),
                String::from("external-wins"),
            ]),
            BTreeSet::from([
                String::from("not-verified-wins"),
                String::from("external-wins"),
            ]),
            &[String::from("external-wins")],
        );

        assert_eq!(statement.verified, ["verified-only"]);
        assert_eq!(statement.advisory, ["advisory-wins"]);
        assert_eq!(statement.not_verified, ["not-verified-wins"]);
        assert_eq!(statement.external_required, ["external-wins"]);
    }

    #[test]
    fn missing_expectations_fill_only_unobserved_coverage() {
        let verified = BTreeSet::from([
            String::from("compile"),
            String::from("custom:rust-compile"),
            String::from("failure-wins"),
        ]);
        let advisory = BTreeSet::from([String::from("lint"), String::from("custom:rust-lint")]);
        let mut not_verified = BTreeSet::from([String::from("failure-wins")]);

        add_missing_coverage_expectations(
            [
                String::from("compile"),
                String::from("lint"),
                String::from("unit-test"),
                String::from("custom:rust-compile"),
                String::from("custom:rust-lint"),
                String::from("custom:rust-unit-test"),
            ],
            &verified,
            &advisory,
            &mut not_verified,
        );

        let statement = partition_coverage(
            verified,
            advisory,
            not_verified,
            &[String::from("custom:rust-unit-test")],
        );
        assert_eq!(statement.verified, ["compile", "custom:rust-compile"]);
        assert_eq!(statement.advisory, ["custom:rust-lint", "lint"]);
        assert_eq!(statement.not_verified, ["failure-wins", "unit-test"]);
        assert_eq!(statement.external_required, ["custom:rust-unit-test"]);
    }

    #[test]
    fn go_generic_test_coverage_does_not_fill_rust_namespaced_expectations() {
        let verified =
            BTreeSet::from([String::from("integration-test"), String::from("unit-test")]);
        let advisory = BTreeSet::new();
        let mut not_verified = BTreeSet::new();

        add_missing_coverage_expectations(
            [
                String::from("integration-test"),
                String::from("unit-test"),
                String::from("custom:rust-integration-test-local"),
                String::from("custom:rust-unit-test"),
            ],
            &verified,
            &advisory,
            &mut not_verified,
        );

        let statement = partition_coverage(verified, advisory, not_verified, &[]);
        assert_eq!(statement.verified, ["integration-test", "unit-test"]);
        assert_eq!(
            statement.not_verified,
            [
                "custom:rust-integration-test-local",
                "custom:rust-unit-test"
            ]
        );
        assert!(statement.advisory.is_empty());
        assert!(statement.external_required.is_empty());
    }

    #[test]
    fn receipt_order_uses_started_at_then_immutable_id() -> Result<(), Box<dyn Error>> {
        let earlier = UNIX_EPOCH + Duration::from_secs(1);
        let later = UNIX_EPOCH + Duration::from_secs(2);

        assert!(receipt_order_is_newer(
            later.into(),
            "a",
            earlier.into(),
            "z"
        ));
        assert!(receipt_order_is_newer(
            earlier.into(),
            "z",
            earlier.into(),
            "a"
        ));
        assert!(!receipt_order_is_newer(
            earlier.into(),
            "a",
            earlier.into(),
            "z"
        ));
        let same_windows_tick = parse_utc_rfc3339("2026-07-27T00:00:00.123456700Z")?;
        let later_inside_windows_tick = parse_utc_rfc3339("2026-07-27T00:00:00.123456789Z")?;
        assert!(receipt_order_is_newer(
            later_inside_windows_tick,
            "a",
            same_windows_tick,
            "z"
        ));
        Ok(())
    }

    #[test]
    fn current_command_chain_matches_pass_or_observed_failure_prefix() {
        assert_eq!(selected_command_count(4, 1, EvidenceOutcome::Pass), 4);
        assert_eq!(
            selected_command_count(4, 2, EvidenceOutcome::ProductFailure),
            2
        );
        assert_eq!(selected_command_count(4, 9, EvidenceOutcome::Unknown), 4);
    }

    #[test]
    fn scope_confirmation_fails_closed_on_any_snapshot_drift()
    -> Result<(), Box<dyn std::error::Error>> {
        let retained = PreparedScope::new(ScopeHead::Unborn(GitObjectFormat::Sha1), Vec::new())?;
        let changed = PreparedScope::new(ScopeHead::Unborn(GitObjectFormat::Sha256), Vec::new())?;
        let retained_digest =
            scope_dependency_digest(&Blake3Hasher, &DependencyValue::Known(retained.clone()));
        let changed_digest =
            scope_dependency_digest(&Blake3Hasher, &DependencyValue::Known(changed.clone()));

        assert!(
            require_stable_scope(&retained, &retained_digest, &retained, &retained_digest).is_ok()
        );
        let error =
            match require_stable_scope(&retained, &retained_digest, &changed, &retained_digest) {
                Err(error) => error,
                Ok(()) => {
                    return Err(
                        io::Error::other("scope drift unexpectedly passed confirmation").into(),
                    );
                }
            };
        assert_eq!(error.exit_code(), ExitCode::EnvironmentUnmet);
        assert_eq!(error.diagnostic().code.as_str(), "FGE3313");

        let error =
            match require_stable_scope(&retained, &retained_digest, &retained, &changed_digest) {
                Err(error) => error,
                Ok(()) => {
                    return Err(io::Error::other(
                        "scope digest drift unexpectedly passed confirmation",
                    )
                    .into());
                }
            };
        assert_eq!(error.exit_code(), ExitCode::EnvironmentUnmet);
        assert_eq!(error.diagnostic().code.as_str(), "FGE3313");
        Ok(())
    }

    #[test]
    fn scope_confirmation_preserves_terminal_drift_and_acquisition_error_classes()
    -> Result<(), Box<dyn Error>> {
        let terminal_cases = [
            (
                ScopeAcquisitionError::Control(OperationControlError::TimedOut),
                ExitCode::Timeout,
                "FGE2004",
            ),
            (
                ScopeAcquisitionError::Control(OperationControlError::Interrupted),
                ExitCode::Interrupted,
                "FGE2005",
            ),
            (
                ScopeAcquisitionError::Git(GitError::new(
                    GitErrorKind::TimedOut,
                    "status",
                    "fixture timeout",
                )),
                ExitCode::Timeout,
                "FGE2004",
            ),
            (
                ScopeAcquisitionError::Git(GitError::new(
                    GitErrorKind::Interrupted,
                    "status",
                    "fixture interruption",
                )),
                ExitCode::Interrupted,
                "FGE2005",
            ),
        ];
        for (source, exit_code, diagnostic_code) in terminal_cases {
            let error = map_scope_confirmation_error(source);
            assert_eq!(error.exit_code(), exit_code);
            assert_eq!(error.diagnostic().code.as_str(), diagnostic_code);
        }

        let drift_cases = [
            ScopeAcquisitionError::RepositoryChanged,
            ScopeAcquisitionError::WorktreePathChanged {
                path: RepoRelativePath::new("src/lib.rs")?,
            },
        ];
        for source in drift_cases {
            let error = map_scope_confirmation_error(source);
            assert_eq!(error.exit_code(), ExitCode::EnvironmentUnmet);
            assert_eq!(error.diagnostic().code.as_str(), "FGE3313");
        }

        let error = map_scope_confirmation_error(ScopeAcquisitionError::MissingHead);
        assert_eq!(error.exit_code(), ExitCode::EnvironmentUnmet);
        assert_eq!(error.diagnostic().code.as_str(), "FGE3306");
        Ok(())
    }

    #[test]
    fn detection_baseline_rejects_an_unborn_scope_without_an_unborn_model()
    -> Result<(), Box<dyn Error>> {
        let scope = PreparedScope::new(ScopeHead::Unborn(GitObjectFormat::Sha1), Vec::new())?;
        assert!(require_same_detection_baseline(&project_model(WorkState::Unborn), &scope).is_ok());

        let error = match require_same_detection_baseline(&project_model(WorkState::Clean), &scope)
        {
            Err(error) => error,
            Ok(()) => {
                return Err(
                    io::Error::other("a clean model without HEAD matched an unborn scope").into(),
                );
            }
        };
        assert_eq!(error.exit_code(), ExitCode::EnvironmentUnmet);
        assert_eq!(error.diagnostic().code.as_str(), "FGE3305");
        Ok(())
    }

    #[test]
    fn detection_confirmation_rejects_each_independent_snapshot_drift() -> Result<(), Box<dyn Error>>
    {
        let retained = DetectedProject::test_fixture(project_model(WorkState::Unborn))?;
        assert!(require_stable_detection(&retained, &retained).is_ok());

        let mut completion_drift = retained.clone();
        completion_drift.completion = ModelDetectionCompletion::Partial;
        let error = match require_stable_detection(&retained, &completion_drift) {
            Err(error) => error,
            Ok(()) => return Err(io::Error::other("completion drift passed confirmation").into()),
        };
        assert_eq!(error.diagnostic().code.as_str(), "FGE3312");

        let mut model_drift = retained.clone();
        model_drift.model.repository.work_state = WorkState::Dirty;
        let error = match require_stable_detection(&retained, &model_drift) {
            Err(error) => error,
            Ok(()) => return Err(io::Error::other("model drift passed confirmation").into()),
        };
        assert_eq!(error.diagnostic().code.as_str(), "FGE3312");

        let mut navigation_drift = retained.clone();
        navigation_drift
            .navigation
            .inventory
            .skipped
            .push(InventorySkip {
                path: None,
                reason: String::from("test-only inventory drift"),
            });
        let error = match require_stable_detection(&retained, &navigation_drift) {
            Err(error) => error,
            Ok(()) => {
                return Err(io::Error::other("navigation drift passed confirmation").into());
            }
        };
        assert_eq!(error.diagnostic().code.as_str(), "FGE3312");
        Ok(())
    }

    #[test]
    fn requirement_completeness_needs_every_detection_and_policy_fact() -> Result<(), Box<dyn Error>>
    {
        let detected = DetectedProject::test_fixture(project_model(WorkState::Unborn))?;
        let risk = classified_risk();
        assert!(requirements_are_complete(&detected, &risk, true));

        let mut partial = detected.clone();
        partial.completion = ModelDetectionCompletion::Partial;
        assert!(!requirements_are_complete(&partial, &risk, true));
        assert!(!requirements_are_complete(&detected, &risk, false));

        let mut incomplete_base = detected.clone();
        incomplete_base.navigation.policy_base_completeness = PolicyBaseCompleteness::Unknown;
        assert!(!requirements_are_complete(&incomplete_base, &risk, true));

        let mut unknown_policy = detected.clone();
        unknown_policy.model.policy.confidence = Confidence::Unknown;
        assert!(!requirements_are_complete(&unknown_policy, &risk, true));

        let mut unproven_policy = detected.clone();
        unproven_policy.model.policy.provenance.clear();
        assert!(!requirements_are_complete(&unproven_policy, &risk, true));

        let mut unclassified = risk;
        unclassified.uncertain_assumptions.push(Assumption::new(
            "one changed path was not classified",
            vec![provenance("risk/path-unmatched")],
            Confidence::Low,
        ));
        assert!(!requirements_are_complete(&detected, &unclassified, true));
        Ok(())
    }
}
