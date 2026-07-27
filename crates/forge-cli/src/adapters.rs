//! Read-only adapter drift inspection and explicit synchronization.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use forge_core::ports::RepositoryFilePort as _;
use forge_core::{AppError, Digest, ExitCode, OperationControl as _, RepoRelativePath};
use forge_detect::config::ForgeConfig;
use forge_detect::model::ModelDetectionCompletion;
use forge_render::managed_block::ManagedBlockError;
use forge_render::{
    ADAPTER_FILE_MAX_BYTES, AdapterInspectionState, AdapterSelection, AdapterTarget, ApplyReport,
    ChangePlan, FileEditKind, FileEditReason, InitAdapterInspection, InitPlanOptions,
    ManagedBlockKind, PlanError, inspect_init_targets, managed_adapter_spec_for_path, plan_init,
};
use forge_runtime::control::OperationBudget;
use forge_runtime::fs::NativeFileSystem;
use forge_runtime::hash::Blake3Hasher;
use forge_runtime::state::{AtomicStateStore, GitStateLayout, StateError};
use forge_schema::{
    AdapterDriftData, AdapterStatusData, AdaptersData, ManagedBlockId, PathEncoding, WirePath,
};

use crate::adapter_manifest::{
    ADAPTER_BEHAVIOR_VERSION, AdapterManifest, AdapterManifestEntry, AdapterManifestError,
    load_adapter_manifest,
};
use crate::args::{AdapterChoice, AdaptersArgs, AdaptersCommand, AdaptersSyncArgs, Cli, InitArgs};
use crate::{explain, init};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdaptersMode {
    Check,
    SyncDryRun,
    SyncApply,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InspectionDepth {
    StatusOnly,
    PlanAndPreview,
}

/// A deterministic adapter result plus the internal plan used for human preview output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdaptersOutcome {
    pub(crate) wire: AdaptersData,
    pub(crate) exit_code: ExitCode,
    plan: Option<ChangePlan>,
    previews: Vec<AdapterPreview>,
    mode: AdaptersMode,
    completion: ModelDetectionCompletion,
    pub(crate) apply_report: Option<ApplyReport>,
}

/// Read-only adapter facts shared by `doctor` and `next`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdapterObservation {
    /// Whether a private manifest proves that this repository adopted managed adapters.
    pub(crate) managed: bool,
    pub(crate) statuses: Vec<AdapterStatusData>,
    pub(crate) changed: bool,
}

/// A private adapter manifest validated together with its confined state store.
#[derive(Debug, Clone)]
pub(crate) struct ValidatedAdapterState {
    exists: bool,
    manifest: Option<AdapterManifest>,
}

impl ValidatedAdapterState {
    pub(crate) const fn exists(&self) -> bool {
        self.exists
    }

    fn into_manifest(self) -> Option<AdapterManifest> {
        self.manifest
    }
}

/// Typed failure retained for doctor so invalid state still produces a doctor report.
#[derive(Debug)]
pub(crate) enum AdapterStateValidationError {
    State(StateError),
    Manifest(AdapterManifestError),
}

impl AdapterStateValidationError {
    pub(crate) fn exit_code(&self) -> ExitCode {
        match self {
            Self::State(error) => crate::state_diagnostic::state_error_exit_code(error),
            Self::Manifest(AdapterManifestError::Io { kind, .. }) => {
                crate::state_diagnostic::io_error_kind_exit_code(*kind)
            }
            Self::Manifest(
                AdapterManifestError::InvalidJson { .. }
                | AdapterManifestError::MissingSchema
                | AdapterManifestError::UnsupportedSchema { .. }
                | AdapterManifestError::WrongRepository
                | AdapterManifestError::DuplicateAdapter
                | AdapterManifestError::NonCanonicalOrder
                | AdapterManifestError::InvalidField { .. }
                | AdapterManifestError::TooLarge,
            ) => ExitCode::DataError,
        }
    }
}

impl std::fmt::Display for AdapterStateValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::State(error) => write!(formatter, "{error}"),
            Self::Manifest(error) => write!(formatter, "{error}"),
        }
    }
}

/// Read-only safety of the adapter targets selected by a normal unmanaged init.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AdapterTargetSafety {
    Safe { inspected_targets: usize },
    Unsafe { path: RepoRelativePath },
    Unknown { reason: &'static str },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AdapterPreview {
    kind: FileEditKind,
    reason: FileEditReason,
    path: RepoRelativePath,
    block_id: ManagedBlockId,
    expected_postimage: Digest,
    postimage: Vec<u8>,
    force_authorized: bool,
}

#[derive(Debug)]
struct InspectionOutcome {
    options: InitPlanOptions,
    plan: Option<ChangePlan>,
    statuses: Vec<AdapterStatusData>,
    previews: Vec<AdapterPreview>,
    changed: bool,
    user_edited: bool,
}

/// Observes only adapters already adopted through the private manifest.
///
/// An unmanaged repository is not drifted merely because Forge could initialize it.
pub(crate) fn observe_managed(
    model: &forge_core::ProjectModel,
    config: Option<&ForgeConfig>,
) -> Result<AdapterObservation, AppError> {
    let state =
        validate_retained_adapter_state(model).map_err(map_adapter_state_validation_error)?;
    observe_managed_from_validated_state(model, config, &state)
}

/// Validates the generic private-state boundary and its bounded adapter manifest without writing.
pub(crate) fn validate_retained_adapter_state(
    model: &forge_core::ProjectModel,
) -> Result<ValidatedAdapterState, AdapterStateValidationError> {
    let layout = GitStateLayout::new(&model.repository.git_dir, &model.repository.git_common_dir);
    let Some(store) = AtomicStateStore::open_existing_read_only(layout)
        .map_err(AdapterStateValidationError::State)?
    else {
        return Ok(ValidatedAdapterState {
            exists: false,
            manifest: None,
        });
    };
    let manifest = load_adapter_manifest(&store, &model.repository.id)
        .map_err(AdapterStateValidationError::Manifest)?;
    Ok(ValidatedAdapterState {
        exists: true,
        manifest,
    })
}

/// Inspects managed targets from an already validated private manifest snapshot.
pub(crate) fn observe_managed_from_validated_state(
    model: &forge_core::ProjectModel,
    config: Option<&ForgeConfig>,
    state: &ValidatedAdapterState,
) -> Result<AdapterObservation, AppError> {
    let Some(manifest) = state.manifest.as_ref() else {
        return Ok(AdapterObservation {
            managed: false,
            statuses: Vec::new(),
            changed: false,
        });
    };
    let inspected = inspect_adapter_state(
        model,
        Some(manifest),
        &[],
        config,
        InspectionDepth::StatusOnly,
    )?;
    Ok(AdapterObservation {
        managed: true,
        statuses: inspected.statuses,
        changed: inspected.changed,
    })
}

/// Inspects the same automatically selected targets as a default init without treating a missing
/// managed block as drift or write authorization.
pub(crate) fn observe_default_target_safety(
    model: &forge_core::ProjectModel,
    config: Option<&ForgeConfig>,
) -> AdapterTargetSafety {
    let options = InitPlanOptions {
        adapter_selection: init::adapter_selection_overrides(config),
        ..InitPlanOptions::default()
    };
    match inspect_init_targets(model, &NativeFileSystem, &Blake3Hasher, &options) {
        Ok(inspection) => AdapterTargetSafety::Safe {
            inspected_targets: inspection.targets.len(),
        },
        Err(PlanError::Read { path, .. }) => AdapterTargetSafety::Unsafe { path },
        Err(PlanError::AdapterFileLimit { .. } | PlanError::AttributesFileLimit { .. }) => {
            AdapterTargetSafety::Unknown {
                reason: "a selected adapter or attributes file exceeded its bounded read limit",
            }
        }
        Err(_) => AdapterTargetSafety::Unknown {
            reason: "the selected adapter target set could not be completely inspected",
        },
    }
}

pub(crate) fn execute_controlled(
    cli: &Cli,
    args: &AdaptersArgs,
    control: &OperationBudget,
) -> Result<AdaptersOutcome, AppError> {
    let (mode, force_values) = request_mode(args)?;
    let detected = explain::detect_controlled(cli, control)?;
    control
        .checkpoint()
        .map_err(|error| explain::map_operation_control_error(error, "adapter inspection"))?;
    let manifest = load_manifest(&detected.model)?;
    let inspected = inspect_adapter_state(
        &detected.model,
        manifest.as_ref(),
        force_values,
        detected.navigation.config.as_ref(),
        if mode == AdaptersMode::Check {
            InspectionDepth::StatusOnly
        } else {
            InspectionDepth::PlanAndPreview
        },
    )?;
    let InspectionOutcome {
        options,
        plan,
        statuses,
        previews,
        changed,
        user_edited,
    } = inspected;

    if mode != AdaptersMode::SyncApply || plan.is_none() {
        let requested_exit = if (mode == AdaptersMode::Check && changed) || user_edited {
            ExitCode::Negative
        } else {
            ExitCode::Ok
        };
        return Ok(AdaptersOutcome {
            wire: AdaptersData {
                adapters: statuses,
                changed,
                applied: false,
            },
            exit_code: completion_or(detected.completion, requested_exit),
            plan,
            previews,
            mode,
            completion: detected.completion,
            apply_report: None,
        });
    }

    let plan = plan.ok_or_else(inspection_changed_error)?;
    ensure_manifest_is_migratable(manifest.as_ref(), &plan)?;
    let init_args = InitArgs {
        dry_run: false,
        apply: true,
        allow_dirty: false,
        with_runner: None,
        with_ci: None,
        adapter: options
            .adapters
            .iter()
            .chain(&options.adopted_adapters)
            .filter_map(|adapter| {
                (*adapter == AdapterTarget::Claude).then_some(AdapterChoice::Claude)
            })
            .collect(),
        force_block: force_values.to_vec(),
    };
    control
        .checkpoint()
        .map_err(|error| explain::map_operation_control_error(error, "adapter synchronization"))?;
    let applied = init::execute_with_manifest_precondition_controlled(
        cli,
        &init_args,
        control,
        init::AdapterManifestPrecondition::Expected(manifest.clone()),
    )
    .map_err(|failure| {
        let (error, _report) = failure.into_parts();
        error
    })?;
    let postcheck_plan = applied.postcheck_plan.as_ref().ok_or_else(|| {
        AppError::internal(
            "FGE0222",
            "adapter synchronization has no certified post-check plan",
            "adapters sync --apply",
            "the delegated init apply succeeded without retaining its verified post-check",
            "report this as a Forge implementation defect",
        )
    })?;
    let applied_manifest = applied.manifest.as_ref().ok_or_else(|| {
        AppError::internal(
            "FGE0223",
            "adapter synchronization has no persisted manifest",
            "adapters sync --apply",
            "the delegated init apply succeeded without retaining the state it persisted",
            "report this as a Forge implementation defect",
        )
    })?;
    let statuses = certified_statuses(postcheck_plan, applied_manifest)?;
    let previews = plan_previews(&applied.plan);
    Ok(AdaptersOutcome {
        wire: AdaptersData {
            adapters: statuses,
            changed,
            applied: true,
        },
        exit_code: ExitCode::Ok,
        plan: Some(applied.plan),
        previews,
        mode,
        completion: applied.completion,
        apply_report: applied.apply_report,
    })
}

fn inspect_adapter_state(
    model: &forge_core::ProjectModel,
    manifest: Option<&AdapterManifest>,
    force_values: &[String],
    config: Option<&ForgeConfig>,
    depth: InspectionDepth,
) -> Result<InspectionOutcome, AppError> {
    let options = plan_options(manifest, force_values, config)?;
    let filesystem = NativeFileSystem;
    let hasher = Blake3Hasher;
    let mut inspection = inspect_init_targets(model, &filesystem, &hasher, &options)
        .map_err(|error| init::map_plan_error_app(error, "adapter drift inspection"))?;
    let plan = match depth {
        InspectionDepth::StatusOnly => None,
        InspectionDepth::PlanAndPreview => {
            match plan_init(model, &filesystem, &hasher, &options) {
                Ok(plan) => Some(plan),
                Err(PlanError::ManagedBlock {
                    source: ManagedBlockError::UserEdited { .. },
                    ..
                }) => {
                    // Refresh the complete target set after the fail-closed planner observes a
                    // conflict. This avoids collapsing a multi-target preview to only the first
                    // edited block.
                    inspection = inspect_init_targets(model, &filesystem, &hasher, &options)
                        .map_err(|error| {
                            init::map_plan_error_app(error, "adapter drift inspection")
                        })?;
                    None
                }
                Err(error) => return Err(init::map_plan_error_app(error, "adapter drift plan")),
            }
        }
    };
    let statuses = classify_inspection(&inspection, manifest, &model.repository.root, &filesystem)?;
    let previews = if depth == InspectionDepth::PlanAndPreview {
        inspection_previews(&inspection, &options)
    } else {
        Vec::new()
    };
    let changed = statuses
        .iter()
        .any(|status| status.drift != AdapterDriftData::NoDrift);
    let user_edited = statuses
        .iter()
        .any(|status| status.drift == AdapterDriftData::UserEdited);
    if depth == InspectionDepth::PlanAndPreview && plan.is_none() && !user_edited {
        return Err(inspection_changed_error());
    }

    Ok(InspectionOutcome {
        options,
        plan,
        statuses,
        previews,
        changed,
        user_edited,
    })
}

fn request_mode(args: &AdaptersArgs) -> Result<(AdaptersMode, &[String]), AppError> {
    match &args.command {
        AdaptersCommand::Check => Ok((AdaptersMode::Check, &[])),
        AdaptersCommand::Sync(sync) => {
            validate_sync_mode(sync)?;
            Ok((
                if sync.apply {
                    AdaptersMode::SyncApply
                } else {
                    AdaptersMode::SyncDryRun
                },
                &sync.force_block,
            ))
        }
    }
}

fn validate_sync_mode(args: &AdaptersSyncArgs) -> Result<(), AppError> {
    if args.apply && args.dry_run {
        Err(AppError::usage(
            "FGE1207",
            "adapter sync cannot select both preview and apply modes",
            "--dry-run / --apply",
            "the two modes have different side-effect contracts",
            "select at most one mode; omitting both is a dry-run",
        ))
    } else {
        Ok(())
    }
}

fn load_manifest(model: &forge_core::ProjectModel) -> Result<Option<AdapterManifest>, AppError> {
    validate_retained_adapter_state(model)
        .map(ValidatedAdapterState::into_manifest)
        .map_err(map_adapter_state_validation_error)
}

fn plan_options(
    manifest: Option<&AdapterManifest>,
    force_values: &[String],
    config: Option<&ForgeConfig>,
) -> Result<InitPlanOptions, AppError> {
    let mut adopted_adapters = BTreeSet::new();
    if let Some(manifest) = manifest {
        for entry in manifest.adapters() {
            let path = manifest_entry_path(entry)?;
            let Some(spec) = managed_adapter_spec_for_path(&path) else {
                continue;
            };
            if entry.block_id().as_str() == spec.block.id()
                && matches!(spec.selection, AdapterSelection::ExplicitOrDetected)
            {
                adopted_adapters.insert(spec.target);
            }
        }
    }
    let mut force_blocks = Vec::with_capacity(force_values.len());
    let mut unique = BTreeSet::new();
    for value in force_values {
        let block = match value.as_str() {
            "project-index" => ManagedBlockKind::ProjectIndex,
            "claude-pointer" => ManagedBlockKind::ClaudePointer,
            _ => {
                return Err(AppError::usage(
                    "FGE1202",
                    "unknown managed block selected for replacement",
                    "--force-block",
                    format!("`{value}` is not owned by this Forge build"),
                    "use `--force-block project-index` or `--force-block claude-pointer`",
                ));
            }
        };
        if !unique.insert(block) {
            return Err(AppError::usage(
                "FGE1203",
                "the same managed block was selected more than once",
                "--force-block",
                format!("`{value}` occurs more than once"),
                "remove the duplicate option",
            ));
        }
        force_blocks.push(block);
    }
    Ok(InitPlanOptions {
        adapters: Vec::new(),
        adopted_adapters: adopted_adapters.into_iter().collect(),
        adapter_selection: init::adapter_selection_overrides(config),
        force_blocks,
        runner: None,
    })
}

fn classify_inspection(
    inspection: &InitAdapterInspection,
    manifest: Option<&AdapterManifest>,
    repository_root: &std::path::Path,
    filesystem: &NativeFileSystem,
) -> Result<Vec<AdapterStatusData>, AppError> {
    let behavior_stale =
        manifest.is_some_and(|manifest| manifest.behavior_version() != ADAPTER_BEHAVIOR_VERSION);
    let source_stale =
        manifest.is_some_and(|manifest| manifest.source_digest() != &inspection.model_digest);
    let rendered_targets_changed = inspection.targets.iter().any(|target| {
        matches!(
            &target.state,
            AdapterInspectionState::Edit(edit)
                if matches!(
                    edit.reason,
                    FileEditReason::MissingFile
                        | FileEditReason::MissingManagedBlock
                        | FileEditReason::AssetChanged
                )
        )
    });
    let unexplained_source_stale = source_stale && !rendered_targets_changed;
    let mut visited = BTreeSet::new();
    let mut statuses = Vec::new();

    for target in &inspection.targets {
        let spec = managed_adapter_spec_for_path(&target.path)
            .ok_or_else(|| unknown_adapter_error(&target.path))?;
        if spec.block != target.desired.kind {
            return Err(unknown_adapter_error(&target.path));
        }
        let block_id = ManagedBlockId::new(spec.block.id());
        let entry = manifest_entry(manifest, &target.path, &block_id)?;
        visited.insert((target.path.clone(), block_id.clone()));
        let (drift, detail) = if behavior_stale {
            (
                AdapterDriftData::ManifestStale,
                "adapter manifest behavior version is incompatible with this renderer".to_owned(),
            )
        } else {
            match &target.state {
                AdapterInspectionState::Satisfied {
                    full_postimage_digest,
                } => match (manifest, entry) {
                    (None, _) => (
                        AdapterDriftData::ManifestStale,
                        "managed content matches, but its rebuildable private manifest is absent"
                            .to_owned(),
                    ),
                    (Some(_), None) => (
                        AdapterDriftData::ManifestStale,
                        "managed content matches, but the private manifest has no matching entry"
                            .to_owned(),
                    ),
                    (Some(_), Some(_)) if unexplained_source_stale => (
                        AdapterDriftData::ManifestStale,
                        "managed content matches current project facts, but the private manifest source digest is stale"
                            .to_owned(),
                    ),
                    (Some(_), Some(entry)) if entry.postimage_digest() == full_postimage_digest => (
                        AdapterDriftData::NoDrift,
                        "managed content and private manifest match".to_owned(),
                    ),
                    (Some(_), Some(_)) => (
                        AdapterDriftData::NoDrift,
                        "managed block matches; surrounding user-owned bytes differ and are preserved"
                            .to_owned(),
                    ),
                },
                AdapterInspectionState::EquivalentUnmanaged { .. } if entry.is_some() => (
                    AdapterDriftData::GeneratedMissing,
                    "manifest records a generated block, but only equivalent unmanaged content remains"
                        .to_owned(),
                ),
                AdapterInspectionState::EquivalentUnmanaged { .. } => (
                    AdapterDriftData::NoDrift,
                    "existing unmanaged content already provides the requested adapter behavior"
                        .to_owned(),
                ),
                AdapterInspectionState::Edit(edit) => match edit.reason {
                    FileEditReason::UserEdited => (
                        AdapterDriftData::UserEdited,
                        "managed block body no longer matches its declared hash".to_owned(),
                    ),
                    FileEditReason::MissingFile | FileEditReason::MissingManagedBlock
                        if entry.is_some() =>
                    {
                        (
                            AdapterDriftData::GeneratedMissing,
                            "manifest records this generated block, but its file or managed block is missing"
                                .to_owned(),
                        )
                    }
                    FileEditReason::MissingFile
                    | FileEditReason::MissingManagedBlock
                    | FileEditReason::AssetChanged => (
                        AdapterDriftData::AssetChanged,
                        "authoritative project facts render different managed content".to_owned(),
                    ),
                },
            }
        };
        statuses.push(status(spec.host, &target.path, block_id, drift, detail));
    }

    if let Some(manifest) = manifest {
        for entry in manifest.adapters() {
            let path = manifest_entry_path(entry)?;
            let identity = (path.clone(), entry.block_id().clone());
            if visited.contains(&identity) {
                continue;
            }
            let existing = filesystem
                .read_confined_bounded(repository_root, &path, ADAPTER_FILE_MAX_BYTES)
                .map_err(|error| read_adapter_error(&path, error.kind()))?;
            let (drift, detail) = if behavior_stale {
                (
                    AdapterDriftData::ManifestStale,
                    "manifest entry was produced by an incompatible renderer behavior version"
                        .to_owned(),
                )
            } else if existing.is_none() {
                (
                    AdapterDriftData::GeneratedMissing,
                    "manifest records this generated block, but its target is missing".to_owned(),
                )
            } else {
                (
                    AdapterDriftData::ManifestStale,
                    "manifest entry is no longer part of the current adapter plan".to_owned(),
                )
            };
            statuses.push(status(
                entry.host(),
                &path,
                entry.block_id().clone(),
                drift,
                detail,
            ));
        }
    }
    sort_statuses(&mut statuses);
    Ok(statuses)
}

fn inspection_previews(
    inspection: &InitAdapterInspection,
    options: &InitPlanOptions,
) -> Vec<AdapterPreview> {
    let forced = options
        .force_blocks
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    inspection
        .targets
        .iter()
        .filter_map(|target| {
            let AdapterInspectionState::Edit(edit) = &target.state else {
                return None;
            };
            Some(AdapterPreview {
                kind: edit_kind(edit.reason),
                reason: edit.reason,
                path: target.path.clone(),
                block_id: ManagedBlockId::new(target.desired.kind.id()),
                expected_postimage: edit.full_postimage_digest.clone(),
                postimage: edit.preview_postimage.clone(),
                force_authorized: edit.reason != FileEditReason::UserEdited
                    || forced.contains(&target.desired.kind),
            })
        })
        .collect()
}

fn plan_previews(plan: &ChangePlan) -> Vec<AdapterPreview> {
    plan.edits
        .iter()
        .map(|edit| AdapterPreview {
            kind: edit.kind,
            reason: edit.reason,
            path: edit.path.clone(),
            block_id: ManagedBlockId::new(edit.desired.kind.id()),
            expected_postimage: edit.expected_postimage.clone(),
            postimage: edit.preview_postimage.clone(),
            force_authorized: edit.reason != FileEditReason::UserEdited || edit.force,
        })
        .collect()
}

const fn edit_kind(reason: FileEditReason) -> FileEditKind {
    match reason {
        FileEditReason::MissingFile => FileEditKind::Create,
        FileEditReason::MissingManagedBlock
        | FileEditReason::AssetChanged
        | FileEditReason::UserEdited => FileEditKind::ReplaceManagedBlock,
    }
}

fn manifest_entry<'a>(
    manifest: Option<&'a AdapterManifest>,
    path: &RepoRelativePath,
    block_id: &ManagedBlockId,
) -> Result<Option<&'a AdapterManifestEntry>, AppError> {
    let Some(manifest) = manifest else {
        return Ok(None);
    };
    for entry in manifest.adapters() {
        if entry.block_id() == block_id && manifest_entry_path(entry)? == *path {
            return Ok(Some(entry));
        }
    }
    Ok(None)
}

fn manifest_entry_path(entry: &AdapterManifestEntry) -> Result<RepoRelativePath, AppError> {
    let path = entry.path().to_path_buf().map_err(|error| {
        AppError::data(
            "FGE1210",
            "adapter manifest contains an unusable path",
            "generated-v1.json",
            init::sanitize_text(&error.to_string()),
            "delete the rebuildable private manifest and rerun forge init --apply",
        )
    })?;
    RepoRelativePath::new(path).map_err(|error| {
        AppError::data(
            "FGE1210",
            "adapter manifest contains an unsafe path",
            "generated-v1.json",
            init::sanitize_text(&error.to_string()),
            "delete the rebuildable private manifest and rerun forge init --apply",
        )
    })
}

fn inspection_changed_error() -> AppError {
    AppError::new(
        ExitCode::Temporary,
        forge_schema::Diagnostic::new(
            "FGE2223",
            forge_schema::Severity::Error,
            "adapter targets changed during drift inspection",
            "adapter inspection",
            "the read-only inspector and fail-closed planner observed different conflict states",
            "rerun the adapter command after concurrent changes stop",
        ),
    )
}

fn ensure_manifest_is_migratable(
    manifest: Option<&AdapterManifest>,
    plan: &ChangePlan,
) -> Result<(), AppError> {
    let Some(manifest) = manifest else {
        return Ok(());
    };
    let mut planned = BTreeSet::new();
    for edit in &plan.edits {
        planned.insert((
            edit.path.clone(),
            ManagedBlockId::new(edit.desired.kind.id()),
        ));
    }
    for skipped in &plan.skipped {
        if let Some(satisfied) = &skipped.satisfied_managed {
            planned.insert((
                skipped.path.clone(),
                ManagedBlockId::new(satisfied.kind.id()),
            ));
        }
    }
    for entry in manifest.adapters() {
        let identity = (manifest_entry_path(entry)?, entry.block_id().clone());
        if !planned.contains(&identity) {
            return Err(AppError::data(
                "FGE1213",
                "adapter manifest contains an entry outside the current managed plan",
                "generated-v1.json",
                format!(
                    "host `{}` path `{}` block `{}` cannot be migrated without risking an orphaned generated block",
                    init::sanitize_text(entry.host()),
                    init::sanitize_text(&entry.path().display),
                    entry.block_id().as_str(),
                ),
                "review or delete the rebuildable private manifest before applying synchronization",
            ));
        }
    }
    Ok(())
}

fn certified_statuses(
    plan: &ChangePlan,
    manifest: &AdapterManifest,
) -> Result<Vec<AdapterStatusData>, AppError> {
    if !plan.edits.is_empty()
        || manifest.behavior_version() != ADAPTER_BEHAVIOR_VERSION
        || manifest.source_digest() != &plan.model_digest
    {
        return Err(AppError::internal(
            "FGE0224",
            "adapter synchronization post-check is not converged",
            "adapters sync --apply",
            "the retained post-check plan and persisted manifest do not describe the same no-op state",
            "report this as a Forge implementation defect",
        ));
    }
    let mut statuses = Vec::new();
    for skipped in &plan.skipped {
        let Some(satisfied) = &skipped.satisfied_managed else {
            continue;
        };
        let spec = managed_adapter_spec_for_path(&skipped.path)
            .ok_or_else(|| unknown_adapter_error(&skipped.path))?;
        if spec.block != satisfied.kind {
            return Err(unknown_adapter_error(&skipped.path));
        }
        let block_id = ManagedBlockId::new(satisfied.kind.id());
        if manifest_entry(Some(manifest), &skipped.path, &block_id)?.is_none() {
            return Err(AppError::internal(
                "FGE0225",
                "persisted adapter manifest omitted a certified target",
                init::display_repository_path(skipped.path.as_path()),
                "the manifest does not contain the managed block proven by the post-check",
                "report this as a Forge implementation defect",
            ));
        }
        statuses.push(status(
            spec.host,
            &skipped.path,
            block_id,
            AdapterDriftData::NoDrift,
            "Forge synchronized and post-checked this managed adapter".to_owned(),
        ));
    }
    if statuses.len() != manifest.adapters().len() {
        return Err(AppError::internal(
            "FGE0226",
            "persisted adapter manifest contains an uncertified target",
            "generated-v1.json",
            "the manifest entry count differs from the certified post-check target count",
            "report this as a Forge implementation defect",
        ));
    }
    sort_statuses(&mut statuses);
    Ok(statuses)
}

fn status(
    host: &str,
    path: &RepoRelativePath,
    block_id: ManagedBlockId,
    drift: AdapterDriftData,
    detail: String,
) -> AdapterStatusData {
    AdapterStatusData {
        host: host.to_owned(),
        path: WirePath::from_path(path.as_path()),
        block_id,
        drift,
        detail,
    }
}

fn sort_statuses(statuses: &mut [AdapterStatusData]) {
    statuses.sort_by(|left, right| {
        wire_path_sort_key(&left.path)
            .cmp(&wire_path_sort_key(&right.path))
            .then_with(|| left.block_id.as_str().cmp(right.block_id.as_str()))
            .then_with(|| left.host.cmp(&right.host))
    });
}

fn wire_path_sort_key(path: &WirePath) -> (u8, &str) {
    let encoding = match path.encoding {
        PathEncoding::Utf8 => 0,
        PathEncoding::UnixBytes => 1,
        PathEncoding::WindowsWide => 2,
        PathEncoding::Unknown => 3,
        _ => 4,
    };
    (
        encoding,
        path.raw_base64.as_deref().unwrap_or(&path.display),
    )
}

fn completion_or(completion: ModelDetectionCompletion, normal: ExitCode) -> ExitCode {
    match completion {
        ModelDetectionCompletion::Complete | ModelDetectionCompletion::Partial => normal,
        ModelDetectionCompletion::TimedOut => ExitCode::Timeout,
        ModelDetectionCompletion::Interrupted => ExitCode::Interrupted,
    }
}

fn map_state_error(error: StateError, location: &str) -> AppError {
    let exit_code = crate::state_diagnostic::state_error_exit_code(&error);
    AppError::new(
        exit_code,
        forge_schema::Diagnostic::new(
            "FGE2220",
            forge_schema::Severity::Error,
            "Forge private adapter state is unavailable",
            location,
            init::sanitize_text(&error.to_string()),
            "fix the Git private-state path or permissions, then rerun the adapter command",
        ),
    )
}

fn map_adapter_state_validation_error(error: AdapterStateValidationError) -> AppError {
    match error {
        AdapterStateValidationError::State(error) => {
            map_state_error(error, "adapter manifest state")
        }
        AdapterStateValidationError::Manifest(error) => map_manifest_load_error(error),
    }
}

fn map_manifest_load_error(error: AdapterManifestError) -> AppError {
    let detail = init::sanitize_text(&error.to_string());
    if error.io_kind().is_some() {
        AppError::environment_unmet(
            "FGE2221",
            "the private adapter manifest could not be read",
            "generated-v1.json",
            detail,
            "fix the Git private-state path or permissions, then rerun the adapter command",
        )
    } else {
        AppError::data(
            "FGE1211",
            "the private adapter manifest is invalid",
            "generated-v1.json",
            detail,
            "delete this rebuildable private state and rerun forge init --apply",
        )
    }
}

fn unknown_adapter_error(path: &RepoRelativePath) -> AppError {
    AppError::internal(
        "FGE0221",
        "planned managed target has no adapter identity",
        init::display_repository_path(path.as_path()),
        "the renderer and adapter registry disagree",
        "report this as a Forge implementation defect",
    )
}

fn read_adapter_error(path: &RepoRelativePath, kind: std::io::ErrorKind) -> AppError {
    AppError::environment_unmet(
        "FGE2222",
        "adapter target could not be read safely",
        init::display_repository_path(path.as_path()),
        format!("confined repository read failed ({kind:?})"),
        "fix the target path, permissions, or symbolic-link boundary, then rerun the adapter command",
    )
}

pub(crate) fn render_human(outcome: &AdaptersOutcome) -> String {
    let mut output = String::new();
    let mode = match outcome.mode {
        AdaptersMode::Check => "check",
        AdaptersMode::SyncDryRun => "sync-dry-run",
        AdaptersMode::SyncApply => "sync-applied",
    };
    let _ = writeln!(output, "mode: {mode}");
    let _ = writeln!(output, "detection: {}", completion_name(outcome.completion));
    let _ = writeln!(output, "changed: {}", outcome.wire.changed);
    let _ = writeln!(output, "applied: {}", outcome.wire.applied);
    for adapter in &outcome.wire.adapters {
        let _ = writeln!(
            output,
            "  - {} {} block={} drift={}: {}",
            adapter.host,
            init::sanitize_text(&adapter.path.display),
            adapter.block_id.as_str(),
            drift_name(adapter.drift),
            init::sanitize_text(&adapter.detail),
        );
    }
    if outcome.mode != AdaptersMode::Check {
        let _ = writeln!(output, "executable plan: {}", outcome.plan.is_some());
        let _ = writeln!(output, "proposed edits: {}", outcome.previews.len());
        for preview in &outcome.previews {
            let _ = writeln!(
                output,
                "  - {} {} block={} reason={} force-authorized={} postimage={}",
                edit_kind_name(preview.kind),
                init::display_repository_path(preview.path.as_path()),
                preview.block_id.as_str(),
                edit_reason_name(preview.reason),
                preview.force_authorized,
                preview.expected_postimage.as_str(),
            );
            for segment in String::from_utf8_lossy(&preview.postimage).split_inclusive('\n') {
                let _ = writeln!(output, "      | {}", init::sanitize_text(segment));
            }
        }
    }
    output
}

const fn drift_name(drift: AdapterDriftData) -> &'static str {
    match drift {
        AdapterDriftData::AssetChanged => "asset-changed",
        AdapterDriftData::UserEdited => "user-edited",
        AdapterDriftData::GeneratedMissing => "generated-missing",
        AdapterDriftData::ManifestStale => "manifest-stale",
        AdapterDriftData::NoDrift => "no-drift",
        AdapterDriftData::Unknown => "unknown",
        _ => "unknown",
    }
}

const fn completion_name(completion: ModelDetectionCompletion) -> &'static str {
    match completion {
        ModelDetectionCompletion::Complete => "complete",
        ModelDetectionCompletion::Partial => "partial",
        ModelDetectionCompletion::TimedOut => "timed-out",
        ModelDetectionCompletion::Interrupted => "interrupted",
    }
}

const fn edit_kind_name(kind: FileEditKind) -> &'static str {
    match kind {
        FileEditKind::Create => "create",
        FileEditKind::ReplaceManagedBlock => "replace-managed-block",
    }
}

const fn edit_reason_name(reason: FileEditReason) -> &'static str {
    match reason {
        FileEditReason::MissingFile => "missing-file",
        FileEditReason::MissingManagedBlock => "missing-managed-block",
        FileEditReason::AssetChanged => "asset-changed",
        FileEditReason::UserEdited => "user-edited",
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::path::Path;

    use forge_core::{Digest, RepoId, RepoRelativePath};
    use forge_render::{
        AdapterInspectionState, AdapterSelection, DesiredManagedBlock, InitAdapterTargetInspection,
        adapter_specs,
    };
    use forge_schema::{AdapterDriftData, ManagedBlockId};

    use super::{
        ADAPTER_BEHAVIOR_VERSION, AdapterManifest, AdapterManifestEntry, InitAdapterInspection,
        NativeFileSystem, classify_inspection,
    };

    #[test]
    fn drift_classifier_consumes_owned_registry_identities_without_host_matches()
    -> Result<(), Box<dyn Error>> {
        let repository = RepoId::new(format!("local:{}", digest('a').as_str()));
        let source_digest = digest('b');
        let postimage_digest = digest('c');
        let mut targets = Vec::new();
        let mut entries = Vec::new();
        for spec in adapter_specs()
            .iter()
            .filter(|spec| spec.owns_managed_projection())
        {
            let path = RepoRelativePath::new(spec.path)?;
            targets.push(InitAdapterTargetInspection {
                path: path.clone(),
                desired: DesiredManagedBlock {
                    kind: spec.block,
                    body: String::from("fixture"),
                },
                state: AdapterInspectionState::Satisfied {
                    full_postimage_digest: postimage_digest.clone(),
                },
            });
            entries.push(AdapterManifestEntry::new(
                spec.host,
                &path,
                ManagedBlockId::new(spec.block.id()),
                postimage_digest.clone(),
            )?);
        }
        let inspection = InitAdapterInspection {
            repository: repository.clone(),
            model_digest: source_digest.clone(),
            assumptions: Vec::new(),
            gaps: Vec::new(),
            targets,
            reused_adapters: Vec::new(),
        };
        let manifest =
            AdapterManifest::new(repository, source_digest, ADAPTER_BEHAVIOR_VERSION, entries)?;

        let statuses = classify_inspection(
            &inspection,
            Some(&manifest),
            Path::new("/unused"),
            &NativeFileSystem,
        )?;
        let owned_count = adapter_specs()
            .iter()
            .filter(|spec| spec.owns_managed_projection())
            .count();
        assert_eq!(statuses.len(), owned_count);
        for spec in adapter_specs() {
            if spec.owns_managed_projection() {
                assert!(statuses.iter().any(|status| {
                    status.host == spec.host
                        && status.path.display == spec.path
                        && status.block_id.as_str() == spec.block.id()
                        && status.drift == AdapterDriftData::NoDrift
                }));
            }
            if let AdapterSelection::ExplicitReuse { source } = spec.selection {
                let source_spec = adapter_specs()
                    .iter()
                    .find(|candidate| candidate.target == source)
                    .ok_or("reuse source is not registered")?;
                assert!(statuses.iter().any(|status| {
                    status.host == source_spec.host
                        && status.path.display == source_spec.path
                        && status.block_id.as_str() == source_spec.block.id()
                }));
            }
        }
        Ok(())
    }

    fn digest(seed: char) -> Digest {
        Digest::new(format!("blake3:{}", seed.to_string().repeat(64)))
    }
}
