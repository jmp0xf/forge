//! Read-only adapter drift inspection and explicit synchronization.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use forge_core::ports::RepositoryFilePort as _;
use forge_core::{AppError, Digest, ExitCode, RepoRelativePath};
use forge_detect::model::ModelDetectionCompletion;
use forge_render::managed_block::ManagedBlockError;
use forge_render::{
    ADAPTER_FILE_MAX_BYTES, AdapterInspectionState, AdapterTarget, ChangePlan, FileEditKind,
    FileEditReason, InitAdapterInspection, InitPlanOptions, ManagedBlockKind, PlanError,
    inspect_init_targets, plan_init,
};
use forge_runtime::fs::NativeFileSystem;
use forge_runtime::hash::Blake3Hasher;
use forge_runtime::state::{AtomicStateStore, GitStateLayout, StateError};
use forge_schema::{
    AdapterDriftData, AdapterStatusData, AdaptersData, ManagedBlockId, PathEncoding, WirePath,
};

use crate::adapter_manifest::{
    ADAPTER_BEHAVIOR_VERSION, AdapterManifest, AdapterManifestEntry, AdapterManifestError,
    load_adapter_manifest, managed_adapter_identity,
};
use crate::args::{AdapterChoice, AdaptersArgs, AdaptersCommand, AdaptersSyncArgs, Cli, InitArgs};
use crate::{explain, init};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdaptersMode {
    Check,
    SyncDryRun,
    SyncApply,
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

pub(crate) fn execute(
    cli: &Cli,
    args: &AdaptersArgs,
    cancellation: Arc<AtomicBool>,
) -> Result<AdaptersOutcome, AppError> {
    let (mode, force_values) = request_mode(args)?;
    let detected = explain::detect(cli, Arc::clone(&cancellation))?;
    let manifest = load_manifest(&detected.model)?;
    let options = plan_options(manifest.as_ref(), force_values)?;
    let filesystem = NativeFileSystem;
    let hasher = Blake3Hasher;
    let mut inspection = inspect_init_targets(&detected.model, &filesystem, &hasher, &options)
        .map_err(|error| init::map_plan_error_app(error, "adapter drift inspection"))?;
    let plan = match plan_init(&detected.model, &filesystem, &hasher, &options) {
        Ok(plan) => Some(plan),
        Err(PlanError::ManagedBlock {
            source: ManagedBlockError::UserEdited { .. },
            ..
        }) => {
            // Refresh the complete target set after the fail-closed planner observes a conflict.
            // This avoids collapsing a multi-target check to only the first edited block.
            inspection = inspect_init_targets(&detected.model, &filesystem, &hasher, &options)
                .map_err(|error| init::map_plan_error_app(error, "adapter drift inspection"))?;
            None
        }
        Err(error) => return Err(init::map_plan_error_app(error, "adapter drift plan")),
    };
    let statuses = classify_inspection(
        &inspection,
        manifest.as_ref(),
        &detected.model.repository.root,
        &filesystem,
    )?;
    let previews = inspection_previews(&inspection, &options);
    let changed = statuses
        .iter()
        .any(|status| status.drift != AdapterDriftData::NoDrift);
    let user_edited = statuses
        .iter()
        .any(|status| status.drift == AdapterDriftData::UserEdited);
    if plan.is_none() && !user_edited {
        return Err(inspection_changed_error());
    }

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
            .filter_map(|adapter| {
                (*adapter == AdapterTarget::Claude).then_some(AdapterChoice::Claude)
            })
            .collect(),
        force_block: force_values.to_vec(),
    };
    let applied = init::execute_with_manifest_precondition(
        cli,
        &init_args,
        cancellation,
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
    let layout = GitStateLayout::new(&model.repository.git_dir, &model.repository.git_common_dir);
    let Some(store) = AtomicStateStore::open_existing_read_only(layout)
        .map_err(|error| map_state_error(error, "adapter manifest state"))?
    else {
        return Ok(None);
    };
    match load_adapter_manifest(&store, &model.repository.id) {
        Ok(manifest) => Ok(manifest),
        Err(error) => Err(map_manifest_load_error(error)),
    }
}

fn plan_options(
    manifest: Option<&AdapterManifest>,
    force_values: &[String],
) -> Result<InitPlanOptions, AppError> {
    let adapters = manifest
        .is_some_and(|manifest| {
            manifest
                .adapters()
                .iter()
                .any(|entry| entry.block_id().as_str() == ManagedBlockKind::ClaudePointer.id())
        })
        .then_some(AdapterTarget::Claude)
        .into_iter()
        .collect();
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
        adapters,
        force_blocks,
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
        let (host, kind) = managed_adapter_identity(&target.path)
            .ok_or_else(|| unknown_adapter_error(&target.path))?;
        if kind != target.desired.kind {
            return Err(unknown_adapter_error(&target.path));
        }
        let block_id = ManagedBlockId::new(kind.id());
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
        statuses.push(status(host, &target.path, block_id, drift, detail));
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
        let (host, registered_kind) = managed_adapter_identity(&skipped.path)
            .ok_or_else(|| unknown_adapter_error(&skipped.path))?;
        if registered_kind != satisfied.kind {
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
            host,
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
    AppError::environment_unmet(
        "FGE2220",
        "Forge private adapter state is unavailable",
        location,
        init::sanitize_text(&error.to_string()),
        "fix the Git private-state path or permissions, then rerun the adapter command",
    )
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
