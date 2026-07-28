//! Read-only P1-P9 assembly of the generic v0 project model.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use forge_core::ports::{FileSystemPort, GitPort, Hasher, ProcessPort};
use forge_core::{
    Assumption, CommandSource, CommandSpec, Confidence, Diagnostic, Digest, GitError, GitErrorKind,
    GitFileSet, GitIndexEntry, Intent, InvalidCommandResolution, Inventory, InventoryError,
    InventoryKind, InventoryOptions, OperationControl, OperationControlError, ProjectModel,
    ProjectModelError, ProjectModelInputs, ProjectUnit, Provenance, RelativePathError,
    RepoRelativePath, Severity, UnlimitedOperationControl, portable_relative_utf8_path,
};

use crate::assets::{AssetDiscoveryError, StandardAssetDiscovery, discover_standard_assets};
use crate::config::{
    ConfigError, DEFAULT_MAX_CONFIG_FILE_BYTES, ForgeConfig, ProjectConfig,
    load_default_forge_config_controlled, load_forge_config_at_controlled, parse_forge_config_blob,
};
use crate::go::{
    GoProvider, GoProviderContext, GoProviderError, GoProviderIssue, GoProviderIssueKind,
};
use crate::inventory_cache::{
    InventoryCachePublication, InventoryCacheReadPort, MAX_INDEX_SNAPSHOT_BYTES,
    index_projection_digest_controlled, index_snapshot_digest_controlled,
    inventory_cache_basis_is_eligible_controlled, inventory_cache_key,
    load_cached_inventory_controlled, prepare_cached_inventory_controlled,
};
#[cfg(test)]
use crate::inventory_cache::{index_projection_digest, prepare_cached_inventory};
use crate::policy::{PolicyBaseCompleteness, PolicyResolutionError, resolve_effective_policy};
use crate::repository::{
    RepositoryDetection, RepositoryDetectionError, detect_repository_controlled,
};
use crate::resolution::{
    CommandLayer, CommandLayerKind, CommandPlanCandidate, CommandResolutionLayers,
    compose_ordered_language_plans, resolve_command_intents,
};
use crate::runner::{RunnerDiscovery, RunnerDiscoveryCompleteness, RunnerKind, discover_runner};
use crate::rust::{
    CargoMetadataCompletion, CargoMetadataOutcome, RustDetectionContext, RustDetectionError,
    RustProvider,
};
use crate::script::{
    ScriptDiscovery, ScriptDiscoveryCompleteness, discover_standard_script, standard_script_intent,
};

const DEFAULT_METADATA_TIMEOUT: Duration = Duration::from_secs(60);

/// Read-only generic detection controls. Provider-specific controls are added in M3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelDetectionOptions {
    pub inventory: InventoryOptions,
    pub config_path: Option<RepoRelativePath>,
    pub metadata_timeout: Duration,
}

impl Default for ModelDetectionOptions {
    fn default() -> Self {
        Self {
            inventory: InventoryOptions::default(),
            config_path: None,
            metadata_timeout: DEFAULT_METADATA_TIMEOUT,
        }
    }
}

/// Runtime-only inputs that must never participate in a model or cache identity.
#[derive(Clone, Copy)]
pub struct ModelDetectionExecution<'a> {
    inventory_cache: Option<&'a dyn InventoryCacheReadPort>,
    control: &'a dyn OperationControl,
}

impl fmt::Debug for ModelDetectionExecution<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ModelDetectionExecution")
            .field("inventory_cache", &self.inventory_cache.is_some())
            .field("control", &"<operation-control>")
            .finish()
    }
}

impl<'a> ModelDetectionExecution<'a> {
    #[must_use]
    pub const fn new(control: &'a dyn OperationControl) -> Self {
        Self {
            inventory_cache: None,
            control,
        }
    }

    #[must_use]
    pub const fn with_inventory_cache(
        mut self,
        inventory_cache: &'a dyn InventoryCacheReadPort,
    ) -> Self {
        self.inventory_cache = Some(inventory_cache);
        self
    }
}

/// Whether all model-detection stages completed without a bounded degradation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelDetectionCompletion {
    Complete,
    Partial,
    TimedOut,
    Interrupted,
}

/// Whether one model detection bypassed, rejected, missed, or reused the inventory cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InventoryCacheStatus {
    Disabled,
    Ineligible,
    Miss,
    Hit,
}

/// A finalized model retained independently from its typed completion state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelDetectionOutcome {
    pub model: ProjectModel,
    pub completion: ModelDetectionCompletion,
    pub inventory_cache_status: InventoryCacheStatus,
    /// Complete cache bytes retained in memory for an authorized state-writing caller to publish.
    pub inventory_cache_publication: Option<InventoryCachePublication>,
    /// Read-only inputs retained for deterministic doctor/risk/navigation evaluation.
    pub navigation: NavigationSnapshot,
}

/// Repository observations that are intentionally not part of the public `ProjectModel`.
///
/// Keeping exact status, inventory, and parsed policy inputs beside the model lets navigation use
/// the same bounded detection snapshot without widening the stable model or racing a second scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NavigationSnapshot {
    pub status: Option<forge_core::PorcelainV2Status>,
    pub inventory: Inventory,
    pub config: Option<ForgeConfig>,
    pub config_path: RepoRelativePath,
    /// Known lower-bound content used by risk/navigation, paired with explicit base completeness.
    pub effective_policy: forge_core::EffectivePolicyContent,
    pub policy_base_completeness: PolicyBaseCompleteness,
    /// Digest of built-in policy plus accepted HEAD policy; never includes candidate changes.
    pub policy_base_digest: Option<forge_core::Digest>,
    /// Typed source or failure for the immutable policy predecessor.
    pub policy_base_origin: PolicyBaseOrigin,
    /// Exact clean-worktree scope input retained only after a real inventory-cache hit.
    ///
    /// The cache-hit path brackets repository status and index parsing with one raw-index identity.
    /// A consumer must still confirm the current HEAD, index, and worktree after using this seed.
    pub scope_seed: Option<NavigationScopeSeed>,
}

/// Process-local exact scope input recovered while accepting an inventory-cache hit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NavigationScopeSeed {
    pub status: forge_core::PorcelainV2Status,
    pub index_entries: Vec<GitIndexEntry>,
}

/// How the immutable policy predecessor was resolved for this detection snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyBaseOrigin {
    /// An unborn repository has no predecessor commit; the built-in minimum is the complete base.
    Unborn,
    /// The selected config path is absent from the exact baseline commit.
    HeadConfigAbsent,
    /// A regular config blob was read and validated from the exact baseline commit.
    HeadConfig,
    /// Repository status did not provide an immutable commit to query.
    HeadUnavailable,
    /// Git could not safely read the selected path from the baseline commit.
    HeadReadFailed { kind: GitErrorKind },
    /// The bounded baseline blob was present but not a valid Forge configuration.
    HeadConfigMalformed,
}

impl PolicyBaseOrigin {
    #[must_use]
    pub const fn completeness(self) -> PolicyBaseCompleteness {
        match self {
            Self::Unborn | Self::HeadConfigAbsent | Self::HeadConfig => {
                PolicyBaseCompleteness::Complete
            }
            Self::HeadUnavailable | Self::HeadReadFailed { .. } | Self::HeadConfigMalformed => {
                PolicyBaseCompleteness::Unknown
            }
        }
    }
}

impl NavigationSnapshot {
    /// Stable changed paths, or `None` when Git status was unavailable.
    #[must_use]
    pub fn changed_paths(&self) -> Option<Vec<RepoRelativePath>> {
        self.status
            .as_ref()
            .map(forge_core::PorcelainV2Status::changed_paths)
    }
}

/// A typed failure from one generic project-model assembly stage.
#[derive(Debug)]
pub enum ModelDetectionError {
    Control(OperationControlError),
    Repository(RepositoryDetectionError),
    GitInventory(GitError),
    Inventory(InventoryError),
    Assets(AssetDiscoveryError),
    Config(ConfigError),
    Policy(PolicyResolutionError),
    RustProvider(RustDetectionError),
    GoProvider(GoProviderError),
    InvalidInventoryPath {
        path: PathBuf,
        source: RelativePathError,
    },
    CommandResolution(InvalidCommandResolution),
    InvalidModel(ProjectModelError),
}

impl fmt::Display for ModelDetectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Control(error) => error.fmt(formatter),
            Self::Repository(error) => error.fmt(formatter),
            Self::GitInventory(error) => write!(formatter, "Git inventory failed: {error}"),
            Self::Inventory(error) => error.fmt(formatter),
            Self::Assets(error) => error.fmt(formatter),
            Self::Config(error) => error.fmt(formatter),
            Self::Policy(error) => write!(formatter, "effective policy resolution failed: {error}"),
            Self::RustProvider(error) => write!(formatter, "Rust provider failed: {error}"),
            Self::GoProvider(error) => write!(formatter, "Go provider failed: {error}"),
            Self::InvalidInventoryPath { path, source } => write!(
                formatter,
                "inventory runner path {path:?} is not repository-relative: {source}"
            ),
            Self::CommandResolution(error) => error.fmt(formatter),
            Self::InvalidModel(error) => error.fmt(formatter),
        }
    }
}

impl Error for ModelDetectionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Control(error) => Some(error),
            Self::Repository(error) => Some(error),
            Self::GitInventory(error) => Some(error),
            Self::Inventory(error) => Some(error),
            Self::Assets(error) => Some(error),
            Self::Config(error) => Some(error),
            Self::Policy(error) => Some(error),
            Self::RustProvider(error) => Some(error),
            Self::GoProvider(error) => Some(error),
            Self::InvalidInventoryPath { source, .. } => Some(source),
            Self::CommandResolution(error) => Some(error),
            Self::InvalidModel(error) => Some(error),
        }
    }
}

impl From<OperationControlError> for ModelDetectionError {
    fn from(error: OperationControlError) -> Self {
        Self::Control(error)
    }
}

/// Detects a finalized generic project model without executing project-owned commands.
pub fn detect_project_model(
    start: &Path,
    git: &dyn GitPort,
    filesystem: &dyn FileSystemPort,
    process: &dyn ProcessPort,
    hasher: &dyn Hasher,
    options: &ModelDetectionOptions,
) -> Result<ModelDetectionOutcome, ModelDetectionError> {
    detect_project_model_controlled(
        start,
        git,
        filesystem,
        process,
        hasher,
        options,
        &UnlimitedOperationControl,
    )
}

/// Detects a model with one shared operation-wide deadline and cancellation source.
pub fn detect_project_model_controlled(
    start: &Path,
    git: &dyn GitPort,
    filesystem: &dyn FileSystemPort,
    process: &dyn ProcessPort,
    hasher: &dyn Hasher,
    options: &ModelDetectionOptions,
    control: &dyn OperationControl,
) -> Result<ModelDetectionOutcome, ModelDetectionError> {
    detect_project_model_with_cache_controlled(
        start,
        git,
        filesystem,
        process,
        hasher,
        options,
        ModelDetectionExecution::new(control),
    )
}

/// Detects a project model while optionally reusing a complete clean-commit inventory.
///
/// Cache content is an optimization only: an ineligible, missing, malformed, unsafe, or
/// inconsistent entry falls back to the authoritative filesystem inventory.
pub fn detect_project_model_with_cache(
    start: &Path,
    git: &dyn GitPort,
    filesystem: &dyn FileSystemPort,
    process: &dyn ProcessPort,
    hasher: &dyn Hasher,
    options: &ModelDetectionOptions,
    inventory_cache: Option<&dyn InventoryCacheReadPort>,
) -> Result<ModelDetectionOutcome, ModelDetectionError> {
    let execution = ModelDetectionExecution::new(&UnlimitedOperationControl);
    let execution =
        inventory_cache.map_or(execution, |cache| execution.with_inventory_cache(cache));
    detect_project_model_with_cache_controlled(
        start, git, filesystem, process, hasher, options, execution,
    )
}

/// Detects with optional cache reuse without including clock or cancellation state in cache keys.
pub fn detect_project_model_with_cache_controlled(
    start: &Path,
    git: &dyn GitPort,
    filesystem: &dyn FileSystemPort,
    process: &dyn ProcessPort,
    hasher: &dyn Hasher,
    options: &ModelDetectionOptions,
    execution: ModelDetectionExecution<'_>,
) -> Result<ModelDetectionOutcome, ModelDetectionError> {
    let ModelDetectionExecution {
        inventory_cache,
        control,
    } = execution;
    control.checkpoint()?;
    let index_snapshot_before = if inventory_cache.is_some() {
        control.checkpoint()?;
        optional_cache_git_result(git.index_snapshot_bytes(start, MAX_INDEX_SNAPSHOT_BYTES))?
            .map(|bytes| index_snapshot_digest_controlled(&bytes, hasher, control))
            .transpose()?
    } else {
        None
    };
    let repository = detect_repository_controlled(start, git, filesystem, hasher, control)
        .map_err(ModelDetectionError::Repository)?;
    control.checkpoint()?;
    let stable_index_snapshot = if let Some(before) = index_snapshot_before {
        optional_cache_git_result(
            git.index_snapshot_bytes(&repository.facts.root, MAX_INDEX_SNAPSHOT_BYTES),
        )?
        .map(|bytes| index_snapshot_digest_controlled(&bytes, hasher, control))
        .transpose()?
        .filter(|after| after == &before)
    } else {
        None
    };
    let (config, config_path) = load_config_controlled(
        filesystem,
        &repository.facts.root,
        options.config_path.as_ref(),
        control,
    )?;
    control.checkpoint()?;
    let policy_base = load_policy_base_config(git, &repository, &config_path);
    let mut inventory_cache_status = if inventory_cache.is_some() {
        InventoryCacheStatus::Ineligible
    } else {
        InventoryCacheStatus::Disabled
    };
    let mut cache_basis = if inventory_cache.is_some() {
        control.checkpoint()?;
        let policy_resolution = resolve_effective_policy(
            policy_base.config.as_ref(),
            config.as_ref(),
            &config_path,
            policy_base.origin.completeness(),
            hasher,
        )
        .map_err(ModelDetectionError::Policy)?;
        if let Some(index_snapshot) = stable_index_snapshot {
            if let Some(index_entries) =
                optional_cache_git_result(git.index_entries(&repository.facts.root))?
            {
                index_projection_digest_controlled(&index_entries, hasher, control)?.and_then(
                    |index_projection| {
                        inventory_cache_key(
                            &repository,
                            &index_projection,
                            options.inventory,
                            &policy_resolution.effective.digest(hasher),
                            policy_resolution.base_completeness,
                            hasher,
                        )
                        .map(|key| InventoryCacheBasis {
                            key,
                            index_snapshot,
                            index_projection,
                            index_entries,
                        })
                    },
                )
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };
    if cache_basis.is_some() {
        inventory_cache_status = InventoryCacheStatus::Miss;
    }
    control.checkpoint()?;
    let cached_inventory = if let Some((cache, basis)) = inventory_cache.zip(cache_basis.as_ref()) {
        let candidate = load_cached_inventory_controlled(
            cache,
            &basis.key,
            &basis.index_projection,
            &basis.index_entries,
            options.inventory,
            hasher,
            control,
        )?;
        if candidate.is_some()
            && cached_projection_matches_index_controlled(
                git,
                hasher,
                &repository.facts.root,
                cache_basis.as_ref().map(|basis| &basis.index_snapshot),
                control,
            )?
        {
            candidate
        } else {
            None
        }
    } else {
        None
    };
    control.checkpoint()?;
    let mut inventory_cache_publication = None;
    let (inventory, file_set, navigation_scope_seed) = match cached_inventory {
        Some(cached) => {
            inventory_cache_status = InventoryCacheStatus::Hit;
            let scope_seed = repository
                .status
                .clone()
                .zip(cache_basis.take().map(|basis| basis.index_entries))
                .map(|(status, index_entries)| NavigationScopeSeed {
                    status,
                    index_entries,
                });
            (cached.inventory, cached.file_set, scope_seed)
        }
        None => {
            control.checkpoint()?;
            let file_set = git
                .file_set(&repository.facts.root)
                .map_err(ModelDetectionError::GitInventory)?;
            let inventory = filesystem
                .inventory_controlled(
                    &repository.facts.root,
                    Some(&file_set),
                    options.inventory,
                    control,
                )
                .map_err(ModelDetectionError::Inventory)?;
            control.checkpoint()?;
            if let Some(basis) = cache_basis.as_ref() {
                match git.index_entries(&repository.facts.root) {
                    Ok(index_entries)
                        if index_entries == basis.index_entries
                            && inventory_cache_basis_is_eligible_controlled(
                                &file_set,
                                &index_entries,
                                &inventory,
                                control,
                            )? =>
                    {
                        control.checkpoint()?;
                        if cache_snapshot_is_stable(
                            git,
                            filesystem,
                            hasher,
                            CachePublicationSnapshot {
                                repository: &repository,
                                file_set: &file_set,
                                index_entries: &index_entries,
                                index_snapshot: &basis.index_snapshot,
                                inventory: &inventory,
                            },
                            control,
                        )? {
                            inventory_cache_publication = prepare_cached_inventory_controlled(
                                &basis.key,
                                &basis.index_projection,
                                &inventory,
                                hasher,
                                control,
                            )?;
                        }
                    }
                    Ok(_) | Err(_) => inventory_cache_status = InventoryCacheStatus::Ineligible,
                }
            }
            (inventory, file_set, None)
        }
    };
    let detection_inventory =
        project_detection_inventory(&inventory, config.as_ref().map(|config| &config.project));
    let mut language = detect_language_providers(
        &repository,
        detection_inventory.as_ref(),
        &file_set,
        filesystem,
        process,
        hasher,
        ProviderOperation {
            metadata_timeout: options.metadata_timeout,
            control,
        },
    )?;
    if config.as_ref().is_some_and(|config| {
        !config.project.include.is_empty() || !config.project.exclude.is_empty()
    }) {
        language.provenance.push(project_boundary_provenance(
            &config_path,
            "project include/exclude patterns bounded language and runner discovery",
        ));
        language.provenance.sort();
        language.provenance.dedup();
    }
    let asset_control_error = control.checkpoint().err();
    if let Some(error) = asset_control_error {
        record_control_error(error, &mut language.timed_out, &mut language.interrupted);
        language.complete = false;
        language.confidence = Confidence::Unknown;
    }
    let standard_assets = match asset_control_error {
        Some(error) => stopped_asset_discovery(error),
        None => discover_standard_assets(&inventory).map_err(ModelDetectionError::Assets)?,
    };
    let runners = match asset_control_error {
        Some(error) => stopped_runner_scan(error),
        None => match control.checkpoint() {
            Ok(_) => scan_runners_controlled(
                filesystem,
                &repository.facts.root,
                detection_inventory.as_ref(),
                options.inventory.max_text_file_bytes,
                control,
            )?,
            Err(error) => stopped_runner_scan(error),
        },
    };
    if let Some(error) = runners.control_error {
        record_control_error(error, &mut language.timed_out, &mut language.interrupted);
        language.complete = false;
        language.confidence = Confidence::Unknown;
    }

    assemble_project_model(
        repository,
        inventory,
        standard_assets,
        PolicyAssemblyInput {
            config,
            base_config: policy_base.config,
            base_origin: policy_base.origin,
            base_diagnostic: policy_base.diagnostic,
            config_path: &config_path,
            hasher,
        },
        runners,
        language,
        InventoryCacheDetection {
            status: inventory_cache_status,
            publication: inventory_cache_publication,
            navigation_scope_seed,
        },
    )
}

#[derive(Debug)]
struct InventoryCacheDetection {
    status: InventoryCacheStatus,
    publication: Option<InventoryCachePublication>,
    navigation_scope_seed: Option<NavigationScopeSeed>,
}

#[derive(Debug)]
struct InventoryCacheBasis {
    key: Digest,
    index_snapshot: Digest,
    index_projection: Digest,
    index_entries: Vec<GitIndexEntry>,
}

struct CachePublicationSnapshot<'a> {
    repository: &'a RepositoryDetection,
    file_set: &'a GitFileSet,
    index_entries: &'a [GitIndexEntry],
    index_snapshot: &'a Digest,
    inventory: &'a Inventory,
}

fn cache_snapshot_is_stable(
    git: &dyn GitPort,
    filesystem: &dyn FileSystemPort,
    hasher: &dyn Hasher,
    before: CachePublicationSnapshot<'_>,
    control: &dyn OperationControl,
) -> Result<bool, ModelDetectionError> {
    control.checkpoint()?;
    let Some(status_before) = before.repository.status.as_ref() else {
        return Ok(false);
    };
    let root = &before.repository.facts.root;
    let Some(status_after) = optional_cache_git_result(git.status(root))? else {
        return Ok(false);
    };
    if status_before != &status_after {
        return Ok(false);
    }
    let Some(file_set_after) = optional_cache_git_result(git.file_set(root))? else {
        return Ok(false);
    };
    if before.file_set != &file_set_after {
        return Ok(false);
    }
    let Some(index_after) = optional_cache_git_result(git.index_entries(root))? else {
        return Ok(false);
    };
    let Some(index_snapshot_after) =
        optional_cache_git_result(git.index_snapshot_bytes(root, MAX_INDEX_SNAPSHOT_BYTES))?
    else {
        return Ok(false);
    };
    Ok(before.index_entries == index_after
        && index_snapshot_digest_controlled(&index_snapshot_after, hasher, control)?
            == *before.index_snapshot
        && inventory_matches_repository_for_publication(
            before.inventory,
            &file_set_after,
            filesystem,
            root,
            control,
        )?)
}

fn inventory_matches_repository_for_publication(
    inventory: &Inventory,
    file_set: &GitFileSet,
    filesystem: &dyn FileSystemPort,
    repository_root: &Path,
    control: &dyn OperationControl,
) -> Result<bool, ModelDetectionError> {
    if !inventory.skipped.is_empty() || !file_set.untracked.is_empty() {
        return Ok(false);
    }
    let mut cached_paths = BTreeMap::new();
    for entry in &inventory.entries {
        control.checkpoint()?;
        let Ok(path) = RepoRelativePath::new(&entry.path) else {
            return Ok(false);
        };
        cached_paths.insert(path, (entry.kind, entry.size_bytes));
    }
    if cached_paths.len() != inventory.entries.len()
        || cached_paths.len() != file_set.tracked.len()
        || cached_paths.keys().ne(file_set.tracked.iter())
    {
        return Ok(false);
    }
    for (path, (expected_kind, expected_size)) in &cached_paths {
        control.checkpoint()?;
        let matches = filesystem
            .path_metadata(repository_root, path)
            .is_ok_and(|actual| {
                matches!(
                    (*expected_kind, actual.kind),
                    (InventoryKind::File, forge_core::PathKind::File)
                        | (InventoryKind::Symlink, forge_core::PathKind::Symlink)
                        | (InventoryKind::Directory, forge_core::PathKind::Directory)
                        | (InventoryKind::Other, forge_core::PathKind::Other)
                ) && expected_size
                    .is_none_or(|expected_size| actual.size_bytes == Some(expected_size))
            });
        if !matches {
            return Ok(false);
        }
    }
    control.checkpoint()?;
    Ok(true)
}

fn cached_projection_matches_index_controlled(
    git: &dyn GitPort,
    hasher: &dyn Hasher,
    repository_root: &Path,
    expected_snapshot: Option<&Digest>,
    control: &dyn OperationControl,
) -> Result<bool, ModelDetectionError> {
    control.checkpoint()?;
    let Some(expected_snapshot) = expected_snapshot else {
        return Ok(false);
    };
    let Some(bytes) = optional_cache_git_result(
        git.index_snapshot_bytes(repository_root, MAX_INDEX_SNAPSHOT_BYTES),
    )?
    else {
        return Ok(false);
    };
    Ok(index_snapshot_digest_controlled(&bytes, hasher, control)? == *expected_snapshot)
}

fn optional_cache_git_result<T>(
    result: Result<T, GitError>,
) -> Result<Option<T>, ModelDetectionError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error)
            if matches!(
                error.kind(),
                GitErrorKind::TimedOut | GitErrorKind::Interrupted
            ) =>
        {
            Err(ModelDetectionError::GitInventory(error))
        }
        Err(_) => Ok(None),
    }
}

fn project_detection_inventory<'a>(
    inventory: &'a Inventory,
    project: Option<&ProjectConfig>,
) -> Cow<'a, Inventory> {
    let Some(project) = project else {
        return Cow::Borrowed(inventory);
    };
    if project.include.is_empty() && project.exclude.is_empty() {
        return Cow::Borrowed(inventory);
    }
    Cow::Owned(Inventory {
        entries: inventory
            .entries
            .iter()
            .filter(|entry| project_path_selected(&entry.path, project))
            .cloned()
            .collect(),
        skipped: inventory
            .skipped
            .iter()
            .filter(|skip| {
                skip.path
                    .as_ref()
                    .is_none_or(|path| project_path_selected(path, project))
            })
            .cloned()
            .collect(),
    })
}

fn project_path_selected(path: &Path, project: &ProjectConfig) -> bool {
    let Some(path) = portable_relative_utf8_path(path).filter(|path| path != ".") else {
        return project.include.is_empty();
    };
    let included =
        project.include.is_empty() || project.include.iter().any(|pattern| pattern.matches(&path));
    included && !project.exclude.iter().any(|pattern| pattern.matches(&path))
}

#[derive(Debug)]
struct PolicyBaseLoad {
    config: Option<ForgeConfig>,
    origin: PolicyBaseOrigin,
    diagnostic: Option<Diagnostic>,
}

fn load_policy_base_config<G>(
    git: &G,
    repository: &RepositoryDetection,
    config_path: &RepoRelativePath,
) -> PolicyBaseLoad
where
    G: GitPort + ?Sized,
{
    let Some(head) = repository.facts.head.as_ref() else {
        let origin = if repository.facts.work_state == forge_core::WorkState::Unborn {
            PolicyBaseOrigin::Unborn
        } else {
            PolicyBaseOrigin::HeadUnavailable
        };
        return PolicyBaseLoad {
            config: None,
            origin,
            diagnostic: policy_base_diagnostic(origin, &repository.facts.root),
        };
    };
    match git.read_commit_file_bounded(
        &repository.facts.root,
        head.as_git_object_id(),
        config_path,
        DEFAULT_MAX_CONFIG_FILE_BYTES,
    ) {
        Ok(None) => PolicyBaseLoad {
            config: None,
            origin: PolicyBaseOrigin::HeadConfigAbsent,
            diagnostic: None,
        },
        Ok(Some(bytes)) => match parse_forge_config_blob(&bytes) {
            Ok(config) => PolicyBaseLoad {
                config: Some(config),
                origin: PolicyBaseOrigin::HeadConfig,
                diagnostic: None,
            },
            Err(_) => {
                let origin = PolicyBaseOrigin::HeadConfigMalformed;
                PolicyBaseLoad {
                    config: None,
                    origin,
                    diagnostic: policy_base_diagnostic(origin, &repository.facts.root),
                }
            }
        },
        Err(error) => {
            let origin = PolicyBaseOrigin::HeadReadFailed { kind: error.kind() };
            PolicyBaseLoad {
                config: None,
                origin,
                diagnostic: policy_base_diagnostic(origin, &repository.facts.root),
            }
        }
    }
}

fn policy_base_diagnostic(origin: PolicyBaseOrigin, root: &Path) -> Option<Diagnostic> {
    let (code, what, why, next) = match origin {
        PolicyBaseOrigin::Unborn
        | PolicyBaseOrigin::HeadConfigAbsent
        | PolicyBaseOrigin::HeadConfig => return None,
        PolicyBaseOrigin::HeadUnavailable => (
            "FGE2227",
            "the immutable policy base is unavailable",
            "repository status did not provide an exact baseline commit",
            "repair Git status access before relying on reusable evidence",
        ),
        PolicyBaseOrigin::HeadReadFailed { kind } => (
            "FGE2227",
            "the immutable policy base could not be read",
            match kind {
                GitErrorKind::OutputLimit => {
                    "the baseline config blob exceeded its bounded read limit"
                }
                _ => "the exact baseline commit path could not be read safely",
            },
            "repair the Git repository or baseline config path before relying on reusable evidence",
        ),
        PolicyBaseOrigin::HeadConfigMalformed => (
            "FGE2228",
            "the immutable policy base is malformed",
            "the baseline config blob failed strict schema or text validation",
            "repair and commit the selected Forge configuration before relying on reusable evidence",
        ),
    };
    Some(Diagnostic::new(
        code,
        Severity::Warning,
        what,
        root.display().to_string(),
        why,
        next,
    ))
}

fn load_config_controlled<F>(
    filesystem: &F,
    repository_root: &Path,
    selected: Option<&RepoRelativePath>,
    control: &dyn OperationControl,
) -> Result<(Option<ForgeConfig>, RepoRelativePath), ModelDetectionError>
where
    F: FileSystemPort + ?Sized,
{
    if let Some(path) = selected {
        let config = load_forge_config_at_controlled(filesystem, repository_root, path, control)
            .map_err(ModelDetectionError::Config)?;
        return Ok((Some(config), path.clone()));
    }
    let path = RepoRelativePath::new(forge_core::branding::CONFIG_FILE).map_err(|source| {
        ModelDetectionError::InvalidInventoryPath {
            path: PathBuf::from(forge_core::branding::CONFIG_FILE),
            source,
        }
    })?;
    let config = load_default_forge_config_controlled(filesystem, repository_root, control)
        .map_err(ModelDetectionError::Config)?;
    Ok((config, path))
}

#[derive(Debug)]
struct RunnerScan {
    discoveries: Vec<RunnerDiscovery>,
    scripts: Vec<ScriptDiscovery>,
    failures: Vec<Provenance>,
    global_complete: bool,
    unknown_script_intents: BTreeSet<Intent>,
    control_error: Option<OperationControlError>,
}

fn stopped_asset_discovery(error: OperationControlError) -> StandardAssetDiscovery {
    let provenance = vec![Provenance {
        rule_id: String::from("inventory.standard-assets.operation-control.v1"),
        source_path: None,
        source_range: None,
        detail: format!("standard asset discovery was not started: {error}"),
    }];
    StandardAssetDiscovery {
        assets: forge_core::AssetInventory::unknown(provenance.clone()),
        adapters: forge_core::AdapterInventory::unknown(provenance),
    }
}

fn stopped_runner_scan(error: OperationControlError) -> RunnerScan {
    RunnerScan {
        discoveries: Vec::new(),
        scripts: Vec::new(),
        failures: vec![Provenance {
            rule_id: String::from("runner.operation-control.v1"),
            source_path: None,
            source_range: None,
            detail: format!("runner discovery was not started: {error}"),
        }],
        global_complete: false,
        unknown_script_intents: Intent::ALL.into_iter().collect(),
        control_error: Some(error),
    }
}

fn scan_runners_controlled<F>(
    filesystem: &F,
    repository_root: &Path,
    inventory: &Inventory,
    max_text_file_bytes: u64,
    control: &dyn OperationControl,
) -> Result<RunnerScan, ModelDetectionError>
where
    F: FileSystemPort + ?Sized,
{
    let mut discoveries = Vec::new();
    let mut scripts = Vec::new();
    let mut failures = Vec::new();
    let mut global_complete = inventory.skipped.is_empty();
    let mut unknown_script_intents = BTreeSet::new();
    let mut control_error = None;
    for entry in &inventory.entries {
        let runner_kind = runner_kind_for_path(&entry.path);
        let script_intent = standard_script_intent(&entry.path);
        if runner_kind.is_none() && script_intent.is_none() {
            continue;
        }
        if let Err(error) = control.checkpoint() {
            control_error = Some(error);
            global_complete = false;
            unknown_script_intents.extend(Intent::ALL);
            break;
        }
        let path = RepoRelativePath::new(&entry.path).map_err(|source| {
            ModelDetectionError::InvalidInventoryPath {
                path: entry.path.clone(),
                source,
            }
        })?;
        if entry.kind != InventoryKind::File {
            failures.push(runner_failure_provenance(
                &path,
                "project entrypoint path is not a regular file and was not followed",
            ));
            if runner_kind.is_some() {
                global_complete = false;
            }
            unknown_script_intents.extend(script_intent);
            continue;
        }
        match filesystem.read_bounded_text_controlled(
            repository_root,
            &path,
            max_text_file_bytes,
            control,
        ) {
            Ok(text) => {
                if let Some(kind) = runner_kind {
                    let discovery = discover_runner(kind, &path, &text);
                    global_complete &=
                        discovery.completeness() == RunnerDiscoveryCompleteness::Complete;
                    discoveries.push(discovery);
                }
                if script_intent.is_some() {
                    let discovery = discover_standard_script(&path, &text);
                    if discovery.completeness() == ScriptDiscoveryCompleteness::Unknown {
                        unknown_script_intents.extend(discovery.intent());
                    }
                    scripts.push(discovery);
                }
            }
            Err(InventoryError::Control(error)) => {
                control_error = Some(error);
                global_complete = false;
                unknown_script_intents.extend(Intent::ALL);
                break;
            }
            Err(_) => {
                failures.push(runner_failure_provenance(
                    &path,
                    "project entrypoint could not be read through the bounded repository port",
                ));
                if runner_kind.is_some() {
                    global_complete = false;
                }
                unknown_script_intents.extend(script_intent);
            }
        }
    }
    Ok(RunnerScan {
        discoveries,
        scripts,
        failures,
        global_complete,
        unknown_script_intents,
        control_error,
    })
}

fn runner_kind_for_path(path: &Path) -> Option<RunnerKind> {
    match path.file_name()?.to_str()? {
        "Makefile" => Some(RunnerKind::Make),
        "justfile" | "Justfile" => Some(RunnerKind::Just),
        "Taskfile.yml" | "Taskfile.yaml" => Some(RunnerKind::Task),
        _ => None,
    }
}

#[derive(Debug)]
struct LanguageDetection {
    units: Vec<ProjectUnit>,
    plans: Vec<CommandPlanCandidate>,
    provenance: Vec<Provenance>,
    confidence: Confidence,
    complete: bool,
    timed_out: bool,
    interrupted: bool,
    diagnostics: Vec<Diagnostic>,
    assumptions: Vec<Assumption>,
}

#[derive(Clone, Copy)]
struct ProviderOperation<'a> {
    metadata_timeout: Duration,
    control: &'a dyn OperationControl,
}

fn detect_language_providers(
    repository: &RepositoryDetection,
    inventory: &Inventory,
    file_set: &GitFileSet,
    filesystem: &dyn FileSystemPort,
    process: &dyn ProcessPort,
    hasher: &dyn Hasher,
    operation: ProviderOperation<'_>,
) -> Result<LanguageDetection, ModelDetectionError> {
    let ProviderOperation {
        metadata_timeout,
        control,
    } = operation;
    let rust_relevant = has_manifest(inventory, "Cargo.toml");
    let go_relevant = has_manifest(inventory, "go.mod") || has_manifest(inventory, "go.work");
    let mut units = Vec::new();
    let mut plan_fragments = Vec::new();
    let mut provenance = vec![Provenance {
        rule_id: String::from("units.provider-order.v1"),
        source_path: None,
        source_range: None,
        detail: String::from(
            "relevant built-in providers were evaluated in stable Rust then Go order",
        ),
    }];
    let mut complete = inventory.skipped.is_empty();
    let mut timed_out = false;
    let mut interrupted = false;
    let mut diagnostics = Vec::new();
    let mut assumptions = Vec::new();

    if rust_relevant {
        let result = RustProvider
            .detect_project_controlled(
                &RustDetectionContext {
                    repository_root: &repository.facts.root,
                    inventory,
                    filesystem,
                    process,
                    hasher,
                    metadata_timeout,
                },
                control,
            )
            .map_err(ModelDetectionError::RustProvider)?;
        if let Some(error) = result.control_error {
            record_control_error(error, &mut timed_out, &mut interrupted);
            complete = false;
        }
        for completion in &result.metadata_completions {
            interrupted |= completion.interrupted;
            timed_out |= completion.timed_out;
            if completion.outcome != CargoMetadataOutcome::Succeeded {
                let (diagnostic, assumption) = rust_incomplete_evidence(completion);
                diagnostics.push(diagnostic);
                assumptions.push(assumption);
                complete = false;
            }
        }
        complete &= result.confidence == Confidence::High;
        units.extend(result.units);
        plan_fragments.extend(result.command_plan_fragments);
        provenance.extend(result.provenance);
    }

    let mut operation_error = control.checkpoint().err();
    if let Some(error) = operation_error {
        record_control_error(error, &mut timed_out, &mut interrupted);
        complete = false;
    }

    if go_relevant {
        let result = if let Some(error) = operation_error {
            let issue = GoProviderIssue {
                kind: match error {
                    OperationControlError::TimedOut => GoProviderIssueKind::MetadataTimedOut,
                    OperationControlError::Interrupted => GoProviderIssueKind::MetadataInterrupted,
                },
                path: None,
                detail: error.to_string(),
            };
            crate::go::GoProviderResult {
                units: Vec::new(),
                plans: Vec::new(),
                provenance: vec![Provenance {
                    rule_id: String::from("go.operation-control.v1"),
                    source_path: None,
                    source_range: None,
                    detail: String::from(
                        "Go provider work was not started after the shared operation budget stopped",
                    ),
                }],
                issues: vec![issue],
                confidence: Confidence::Unknown,
                complete: false,
            }
        } else {
            let changed_paths = repository.changed_paths();
            GoProvider
                .analyze_controlled(
                    GoProviderContext {
                        repository_root: &repository.facts.root,
                        inventory,
                        git_files: file_set,
                        changed_files: changed_paths.as_deref(),
                        file_system: filesystem,
                        process,
                        hasher,
                        metadata_timeout,
                    },
                    control,
                )
                .map_err(ModelDetectionError::GoProvider)?
        };
        for issue in &result.issues {
            interrupted |= issue.kind == GoProviderIssueKind::MetadataInterrupted;
            timed_out |= issue.kind == GoProviderIssueKind::MetadataTimedOut;
            let (diagnostic, assumption) = go_issue_evidence(issue);
            diagnostics.push(diagnostic);
            assumptions.push(assumption);
        }
        complete &= result.complete;
        units.extend(result.units);
        plan_fragments.extend(result.plans);
        provenance.extend(result.provenance);
        if operation_error.is_none() {
            operation_error = control.checkpoint().err();
            if let Some(error) = operation_error {
                record_control_error(error, &mut timed_out, &mut interrupted);
                complete = false;
            }
        }
    }

    units.sort_by(|left, right| {
        left.root
            .cmp(&right.root)
            .then_with(|| left.manifest.cmp(&right.manifest))
            .then_with(|| left.id.cmp(&right.id))
    });
    provenance.sort();
    provenance.dedup();
    Ok(LanguageDetection {
        units,
        plans: compose_ordered_language_plans(plan_fragments),
        provenance,
        confidence: if complete {
            Confidence::Medium
        } else {
            Confidence::Unknown
        },
        complete,
        timed_out,
        interrupted,
        diagnostics,
        assumptions,
    })
}

fn record_control_error(
    error: OperationControlError,
    timed_out: &mut bool,
    interrupted: &mut bool,
) {
    match error {
        OperationControlError::TimedOut => *timed_out = true,
        OperationControlError::Interrupted => *interrupted = true,
    }
}

fn has_manifest(inventory: &Inventory, name: &str) -> bool {
    inventory
        .entries
        .iter()
        .any(|entry| entry.path.file_name() == Some(OsStr::new(name)))
}

fn rust_incomplete_evidence(completion: &CargoMetadataCompletion) -> (Diagnostic, Assumption) {
    let reason = rust_outcome_reason(&completion.outcome);
    let location = completion.manifest.as_path().display().to_string();
    let provenance = Provenance {
        rule_id: String::from("rust.provider-incomplete.v1"),
        source_path: Some(completion.manifest.as_path().into()),
        source_range: None,
        detail: reason.to_owned(),
    };
    (
        Diagnostic::new(
            "FGE2210",
            Severity::Warning,
            "Rust metadata detection was incomplete",
            location,
            reason,
            "repair the declared Rust toolchain or manifest, then rerun Forge detection",
        ),
        Assumption::new(
            format!("Rust unit and command scope remain uncertain because {reason}"),
            vec![provenance],
            Confidence::Unknown,
        ),
    )
}

fn rust_outcome_reason(outcome: &CargoMetadataOutcome) -> &'static str {
    match outcome {
        CargoMetadataOutcome::Succeeded => "Cargo metadata completed successfully",
        CargoMetadataOutcome::ManifestNotRegular { .. } => {
            "the inventoried Cargo manifest was not a regular file"
        }
        CargoMetadataOutcome::ManifestProbeFailed { .. } => {
            "the Cargo manifest could not be inspected safely"
        }
        CargoMetadataOutcome::ProcessFailed { .. } => "the Cargo metadata process could not start",
        CargoMetadataOutcome::ExitFailure => "Cargo metadata exited unsuccessfully",
        CargoMetadataOutcome::TimedOut => "Cargo metadata exceeded its configured timeout",
        CargoMetadataOutcome::Interrupted => "Cargo metadata was interrupted",
        CargoMetadataOutcome::OutputTruncated => "Cargo metadata exceeded its bounded output",
        CargoMetadataOutcome::InvalidOutput(_) => {
            "Cargo metadata output failed structural or repository-boundary validation"
        }
    }
}

fn go_issue_evidence(issue: &GoProviderIssue) -> (Diagnostic, Assumption) {
    if issue.kind == GoProviderIssueKind::ImpactScopeBroadened {
        let provenance = Provenance {
            rule_id: String::from("go.impact-broadened.v1"),
            source_path: issue.path.as_ref().map(|path| path.as_path().into()),
            source_range: None,
            detail: issue.detail.clone(),
        };
        return (
            Diagnostic::new(
                "FGE2211",
                Severity::Info,
                "Go change impact was conservatively broadened",
                issue.path.as_ref().map_or_else(
                    || String::from("Go provider"),
                    |path| path.as_path().display().to_string(),
                ),
                issue.detail.clone(),
                "run the widened project-native commands; a narrower scope would require additional project evidence",
            ),
            Assumption::new(
                "Go impact could not be narrowed, so the complete validated module or workspace remains in scope",
                vec![provenance],
                Confidence::Medium,
            ),
        );
    }
    let reason = go_issue_reason(issue.kind);
    let location = issue.path.as_ref().map_or_else(
        || String::from("Go provider"),
        |path| path.as_path().display().to_string(),
    );
    let provenance = Provenance {
        rule_id: String::from("go.provider-incomplete.v1"),
        source_path: issue.path.as_ref().map(|path| path.as_path().into()),
        source_range: None,
        detail: reason.to_owned(),
    };
    (
        Diagnostic::new(
            "FGE2211",
            Severity::Warning,
            "Go project detection was incomplete",
            location,
            reason,
            "repair the Go workspace or toolchain evidence, then rerun Forge detection",
        ),
        Assumption::new(
            format!("Go unit, impact, or command scope remains uncertain because {reason}"),
            vec![provenance],
            Confidence::Unknown,
        ),
    )
}

fn go_issue_reason(kind: GoProviderIssueKind) -> &'static str {
    match kind {
        GoProviderIssueKind::InvalidRepositoryRoot => "the repository root was invalid",
        GoProviderIssueKind::InventoryIncomplete => "the repository inventory was incomplete",
        GoProviderIssueKind::InvalidInventoryPath => "an inventoried Go path was invalid",
        GoProviderIssueKind::InvalidManifestKind => "a Go manifest was not a regular file",
        GoProviderIssueKind::ManifestProbeFailed => "a Go manifest could not be inspected safely",
        GoProviderIssueKind::InvalidUsePath => "a go.work use path was invalid",
        GoProviderIssueKind::UseTargetNotDirectory => "a go.work use target was not a directory",
        GoProviderIssueKind::UseManifestNotRegular => {
            "a go.work module manifest was not a regular file"
        }
        GoProviderIssueKind::MetadataUnavailable => "Go workspace metadata could not start",
        GoProviderIssueKind::MetadataTimedOut => "Go workspace metadata timed out",
        GoProviderIssueKind::MetadataInterrupted => "Go workspace metadata was interrupted",
        GoProviderIssueKind::MetadataOutputLimit => {
            "Go workspace metadata exceeded its output bound"
        }
        GoProviderIssueKind::MetadataCommandFailed => "Go workspace metadata exited unsuccessfully",
        GoProviderIssueKind::MetadataInvalid => "Go workspace metadata was invalid",
        GoProviderIssueKind::DuplicateWorkspaceMembership => {
            "a Go module belonged to multiple workspaces"
        }
        GoProviderIssueKind::OverlappingWorkspace => "Go workspace roots overlapped",
        GoProviderIssueKind::ChangedScopeUnavailable => "the changed Go path set was unavailable",
        GoProviderIssueKind::ChangedPathUnknown => "a changed path could not be mapped safely",
        GoProviderIssueKind::GeneratedStatusUnknown => {
            "generated Go source status could not be proven"
        }
        GoProviderIssueKind::ImpactScopeBroadened => "Go change impact required a broader scope",
    }
}

struct PolicyAssemblyInput<'a> {
    config: Option<ForgeConfig>,
    base_config: Option<ForgeConfig>,
    base_origin: PolicyBaseOrigin,
    base_diagnostic: Option<Diagnostic>,
    config_path: &'a RepoRelativePath,
    hasher: &'a dyn Hasher,
}

fn assemble_project_model(
    repository: RepositoryDetection,
    inventory: Inventory,
    standard_assets: StandardAssetDiscovery,
    policy_input: PolicyAssemblyInput<'_>,
    runners: RunnerScan,
    language: LanguageDetection,
    inventory_cache: InventoryCacheDetection,
) -> Result<ModelDetectionOutcome, ModelDetectionError> {
    let PolicyAssemblyInput {
        config,
        base_config,
        base_origin,
        base_diagnostic,
        config_path,
        hasher,
    } = policy_input;
    let InventoryCacheDetection {
        status: inventory_cache_status,
        publication: inventory_cache_publication,
        navigation_scope_seed,
    } = inventory_cache;
    let timeout = config
        .as_ref()
        .and_then(|config| config.policy.default_timeout_seconds)
        .unwrap_or(300);
    let generic_partial = repository.confidence == Confidence::Unknown
        || !inventory.skipped.is_empty()
        || !runners.global_complete
        || !runners.unknown_script_intents.is_empty()
        || standard_assets.assets.confidence == Confidence::Unknown
        || standard_assets.adapters.confidence == Confidence::Unknown;
    let completion = model_detection_completion(
        language.interrupted,
        language.timed_out,
        generic_partial || !language.complete,
    );
    let explicit_config = explicit_config_layer(config.as_ref(), config_path, timeout);
    let existing_project = existing_project_layer(runners, timeout);
    let language_default = language_default_layer(&language);
    let commands = resolve_command_intents(&CommandResolutionLayers {
        explicit_config,
        existing_project,
        language_default,
    })
    .map_err(ModelDetectionError::CommandResolution)?;
    let policy_base_completeness = base_origin.completeness();
    let policy_resolution = resolve_effective_policy(
        base_config.as_ref(),
        config.as_ref(),
        config_path,
        policy_base_completeness,
        hasher,
    )
    .map_err(ModelDetectionError::Policy)?;
    let policy = policy_resolution.model_policy.clone();

    let RepositoryDetection {
        facts,
        status,
        provenance: repository_provenance,
        confidence: repository_confidence,
        diagnostics: repository_diagnostics,
    } = repository;

    let mut model = ProjectModel::new(ProjectModelInputs {
        repository: facts,
        repository_provenance,
        repository_confidence,
        unit_inventory_provenance: language.provenance,
        unit_inventory_confidence: language.confidence,
        assets: standard_assets.assets,
        adapters: standard_assets.adapters,
        policy,
    });
    model.units = language.units;
    model.commands = commands;
    model.diagnostics = repository_diagnostics;
    model.diagnostics.extend(base_diagnostic);
    model.diagnostics.extend(language.diagnostics);
    model.assumptions = language.assumptions;
    model.assumptions.extend(configured_full_scope_assumptions(
        config.as_ref(),
        config_path,
    ));
    let model = model
        .finalize()
        .map_err(ModelDetectionError::InvalidModel)?;
    Ok(ModelDetectionOutcome {
        model,
        completion,
        inventory_cache_status,
        inventory_cache_publication,
        navigation: NavigationSnapshot {
            status,
            inventory,
            config,
            config_path: config_path.clone(),
            effective_policy: policy_resolution.effective,
            policy_base_completeness,
            policy_base_digest: policy_resolution.policy_base_digest,
            policy_base_origin: base_origin,
            scope_seed: navigation_scope_seed,
        },
    })
}

fn configured_full_scope_assumptions(
    config: Option<&ForgeConfig>,
    config_path: &RepoRelativePath,
) -> Vec<Assumption> {
    let Some(config) = config else {
        return Vec::new();
    };
    config
        .commands
        .iter()
        .filter(|(_, command)| !command.inputs.is_empty())
        .map(|(intent, _)| {
            Assumption::new(
                format!(
                    "Configured {} input patterns are validated, but v0 conservatively fingerprints the complete repository scope.",
                    intent_name(*intent)
                ),
                vec![Provenance {
                    rule_id: String::from("config.command-inputs.full-scope.v1"),
                    source_path: Some(config_path.as_path().into()),
                    source_range: None,
                    detail: String::from(
                        "full-repository scope prevents unsafe evidence reuse when input narrowing cannot be proven complete",
                    ),
                }],
                Confidence::High,
            )
        })
        .collect()
}

fn model_detection_completion(
    interrupted: bool,
    timed_out: bool,
    partial: bool,
) -> ModelDetectionCompletion {
    if interrupted {
        ModelDetectionCompletion::Interrupted
    } else if timed_out {
        ModelDetectionCompletion::TimedOut
    } else if partial {
        ModelDetectionCompletion::Partial
    } else {
        ModelDetectionCompletion::Complete
    }
}

fn explicit_config_layer(
    config: Option<&ForgeConfig>,
    config_path: &RepoRelativePath,
    timeout_seconds: u64,
) -> CommandLayer {
    let mut candidates = Vec::new();
    if let Some(config) = config {
        for (intent, configured) in &config.commands {
            let mut command = CommandSpec::new(
                format!("config.{}", intent_name(*intent)),
                *intent,
                &configured.program,
                configured.cwd.clone(),
                CommandSource::ExplicitConfig,
            )
            .with_args(&configured.args);
            command.timeout = Duration::from_secs(timeout_seconds);
            command.mutability = configured.mutability;
            command.network = configured.network;
            if configured.network == forge_core::NetworkIntent::OfflineRequested {
                command.env.extend([
                    (OsString::from("CARGO_NET_OFFLINE"), OsString::from("true")),
                    (OsString::from("RUSTUP_AUTO_INSTALL"), OsString::from("0")),
                    (OsString::from("GOPROXY"), OsString::from("off")),
                    (OsString::from("GOSUMDB"), OsString::from("off")),
                    (OsString::from("GOTOOLCHAIN"), OsString::from("local")),
                ]);
            }
            command.success = configured.success.clone();
            command.coverage = configured.coverage.clone();
            command.enforcement = configured.enforcement;
            command.confidence = Confidence::High;
            let coverage_confidence = if configured.coverage.is_empty() {
                Confidence::Unknown
            } else {
                Confidence::High
            };
            candidates.push(CommandPlanCandidate::single(
                command,
                vec![config_provenance(
                    config_path,
                    "configured command is declared directly in the selected Forge configuration",
                )],
                coverage_confidence,
            ));
        }
    }
    CommandLayer::complete(
        CommandLayerKind::ExplicitConfig,
        candidates,
        vec![config_provenance(
            config_path,
            if config.is_some() {
                "selected Forge configuration was parsed completely"
            } else {
                "default root Forge configuration was absent"
            },
        )],
        Confidence::High,
    )
}

fn existing_project_layer(runners: RunnerScan, timeout_seconds: u64) -> CommandLayer {
    let RunnerScan {
        discoveries,
        scripts,
        failures,
        global_complete,
        unknown_script_intents,
        control_error: _,
    } = runners;
    let mut candidates = Vec::new();
    let mut provenance = failures;
    for discovery in discoveries {
        provenance.extend(discovery.provenance().iter().cloned());
        for candidate in discovery.candidates() {
            let mut command = candidate.command.clone();
            command.timeout = Duration::from_secs(timeout_seconds);
            candidates.push(CommandPlanCandidate::single(
                command,
                candidate.provenance.clone(),
                Confidence::Unknown,
            ));
        }
    }
    for discovery in scripts {
        provenance.extend(discovery.provenance().iter().cloned());
        if let Some(command) = discovery.command() {
            let mut command = command.clone();
            command.timeout = Duration::from_secs(timeout_seconds);
            candidates.push(CommandPlanCandidate::single(
                command,
                discovery.provenance().to_vec(),
                Confidence::Unknown,
            ));
        }
    }
    provenance.push(Provenance {
        rule_id: String::from("runner.inventory.v1"),
        source_path: None,
        source_range: None,
        detail: if global_complete && unknown_script_intents.is_empty() {
            String::from("all inventoried supported runner files were scanned completely")
        } else if global_complete {
            String::from(
                "runner discovery was complete; exact script uncertainty is limited to its named intent",
            )
        } else {
            String::from("the supported runner surface was not observed completely")
        },
    });
    if !global_complete {
        CommandLayer::unknown(CommandLayerKind::ExistingProject, candidates, provenance)
    } else if unknown_script_intents.is_empty() {
        CommandLayer::complete(
            CommandLayerKind::ExistingProject,
            candidates,
            provenance,
            Confidence::Medium,
        )
    } else {
        CommandLayer::partially_unknown(
            CommandLayerKind::ExistingProject,
            candidates,
            provenance,
            Confidence::Medium,
            unknown_script_intents,
        )
    }
}

fn language_default_layer(language: &LanguageDetection) -> CommandLayer {
    if language.complete {
        CommandLayer::complete(
            CommandLayerKind::LanguageDefault,
            language.plans.clone(),
            language.provenance.clone(),
            language.confidence,
        )
    } else {
        CommandLayer::unknown(
            CommandLayerKind::LanguageDefault,
            language.plans.clone(),
            language.provenance.clone(),
        )
    }
}

fn config_provenance(path: &RepoRelativePath, detail: &str) -> Provenance {
    Provenance {
        rule_id: String::from("config.command-surface.v1"),
        source_path: Some(path.as_path().into()),
        source_range: None,
        detail: detail.to_owned(),
    }
}

fn project_boundary_provenance(path: &RepoRelativePath, detail: &str) -> Provenance {
    Provenance {
        rule_id: String::from("config.project-boundary.v1"),
        source_path: Some(path.as_path().into()),
        source_range: None,
        detail: detail.to_owned(),
    }
}

fn runner_failure_provenance(path: &RepoRelativePath, detail: &str) -> Provenance {
    Provenance {
        rule_id: String::from("runner.bounded-read-failed.v1"),
        source_path: Some(path.as_path().into()),
        source_range: None,
        detail: detail.to_owned(),
    }
}

fn intent_name(intent: Intent) -> &'static str {
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

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::{BTreeMap, BTreeSet, VecDeque};
    use std::ffi::OsString;
    use std::io;
    use std::path::{Path, PathBuf};

    use forge_core::domain::CommandEnforcement;
    use forge_core::inventory::DEFAULT_MAX_TEXT_FILE_BYTES;
    use forge_core::ports::{ExecSpec, ProcessError, ProcessErrorKind, ProcessObservation};
    use forge_core::{
        BoundedText, BranchHead, BranchOid, BranchStatus, CommandResolution, Confidence,
        CoverageDimension, Digest, GitFileSet, GitIndexEntry, GitIndexTag, GitObjectFormat,
        InventoryEntry, Mutability, NetworkIntent, OperationControl, OperationControlError,
        OperationPermit, PathKind, PathMetadata, PorcelainV2Status, RepoFacts, RepoId,
        SuccessPredicate, WorkState, parse_git_index_reader, parse_status_porcelain_v2,
    };
    use serde_json::json;

    use crate::inventory_cache::{InventoryCacheWritePort, publish_cached_inventory};
    use crate::test_support::{repository_path, repository_root};

    use super::*;

    fn repository() -> RepositoryDetection {
        RepositoryDetection {
            facts: RepoFacts {
                id: RepoId::from("local:blake3:model-test"),
                root: repository_root().to_path_buf(),
                git_dir: repository_path(".git"),
                git_common_dir: repository_path(".git"),
                is_linked_worktree: false,
                head: None,
                branch: None,
                upstream: None,
                work_state: WorkState::Unborn,
            },
            status: None,
            provenance: vec![Provenance {
                rule_id: String::from("test.repository"),
                source_path: None,
                source_range: None,
                detail: String::from("test repository facts"),
            }],
            confidence: Confidence::High,
            diagnostics: Vec::new(),
        }
    }

    #[derive(Debug)]
    struct ModelGit {
        file_set: GitFileSet,
        index_entries: Vec<GitIndexEntry>,
        index_snapshot: Vec<u8>,
        index_snapshot_responses: RefCell<VecDeque<Vec<u8>>>,
        index_snapshot_reads: Cell<usize>,
        status: PorcelainV2Status,
        status_after_first_read: Option<PorcelainV2Status>,
        status_reads: Cell<usize>,
        head_file: Result<Option<Vec<u8>>, GitError>,
    }

    impl GitPort for ModelGit {
        fn repository_root(&self, _start: &Path) -> Result<PathBuf, GitError> {
            Ok(repository_root().to_path_buf())
        }

        fn git_dir(&self, _start: &Path) -> Result<PathBuf, GitError> {
            Ok(repository_path(".git"))
        }

        fn git_common_dir(&self, _start: &Path) -> Result<PathBuf, GitError> {
            Ok(repository_path(".git"))
        }

        fn status(&self, _root: &Path) -> Result<PorcelainV2Status, GitError> {
            let read = self.status_reads.get();
            self.status_reads.set(read.saturating_add(1));
            Ok(if read == 0 {
                self.status.clone()
            } else {
                self.status_after_first_read
                    .clone()
                    .unwrap_or_else(|| self.status.clone())
            })
        }

        fn file_set(&self, _root: &Path) -> Result<GitFileSet, GitError> {
            Ok(self.file_set.clone())
        }

        fn index_entries(&self, _root: &Path) -> Result<Vec<GitIndexEntry>, GitError> {
            Ok(self.index_entries.clone())
        }

        fn index_snapshot_bytes(
            &self,
            _root: &Path,
            max_bytes: usize,
        ) -> Result<Vec<u8>, GitError> {
            self.index_snapshot_reads
                .set(self.index_snapshot_reads.get().saturating_add(1));
            let bytes = self
                .index_snapshot_responses
                .borrow_mut()
                .pop_front()
                .unwrap_or_else(|| self.index_snapshot.clone());
            if bytes.len() > max_bytes {
                return Err(GitError::new(
                    GitErrorKind::OutputLimit,
                    "index-snapshot",
                    "fixture index snapshot exceeded its read bound",
                ));
            }
            Ok(bytes)
        }

        fn read_commit_file_bounded(
            &self,
            _root: &Path,
            _commit: &forge_core::GitObjectId,
            _path: &RepoRelativePath,
            _max_bytes: u64,
        ) -> Result<Option<Vec<u8>>, GitError> {
            self.head_file.clone()
        }
    }

    #[derive(Debug, Clone)]
    struct ModelFileSystem {
        inventory: Inventory,
        metadata: BTreeMap<RepoRelativePath, PathMetadata>,
        texts: BTreeMap<RepoRelativePath, BoundedText>,
        inventory_calls: Cell<usize>,
    }

    impl ModelFileSystem {
        fn new(inventory: Inventory) -> Self {
            let metadata = inventory
                .entries
                .iter()
                .filter_map(|entry| {
                    RepoRelativePath::new(&entry.path).ok().map(|path| {
                        let kind = match entry.kind {
                            InventoryKind::Directory => PathKind::Directory,
                            InventoryKind::File => PathKind::File,
                            InventoryKind::Symlink => PathKind::Symlink,
                            InventoryKind::Other => PathKind::Other,
                        };
                        (
                            path,
                            PathMetadata {
                                kind,
                                size_bytes: entry.size_bytes,
                            },
                        )
                    })
                })
                .collect();
            Self {
                inventory,
                metadata,
                texts: BTreeMap::new(),
                inventory_calls: Cell::new(0),
            }
        }

        fn with_text(mut self, path: RepoRelativePath, bytes: impl Into<Vec<u8>>) -> Self {
            self.texts.insert(
                path,
                BoundedText {
                    bytes: bytes.into(),
                    truncated: false,
                    binary: false,
                },
            );
            self
        }
    }

    impl FileSystemPort for ModelFileSystem {
        fn read(&self, _path: &Path) -> io::Result<Vec<u8>> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "raw reads are outside this model fake",
            ))
        }

        fn inventory(
            &self,
            _root: &Path,
            _file_set: Option<&GitFileSet>,
            _options: InventoryOptions,
        ) -> Result<Inventory, InventoryError> {
            self.inventory_calls
                .set(self.inventory_calls.get().saturating_add(1));
            Ok(self.inventory.clone())
        }

        fn read_bounded_text(
            &self,
            _root: &Path,
            path: &RepoRelativePath,
            _max_text_file_bytes: u64,
        ) -> Result<BoundedText, InventoryError> {
            Ok(self.texts.get(path).cloned().unwrap_or(BoundedText {
                bytes: Vec::new(),
                truncated: false,
                binary: false,
            }))
        }

        fn path_kind(&self, _root: &Path, path: &RepoRelativePath) -> io::Result<PathKind> {
            Ok(self
                .metadata
                .get(path)
                .map_or(PathKind::Missing, |metadata| metadata.kind))
        }

        fn path_metadata(&self, _root: &Path, path: &RepoRelativePath) -> io::Result<PathMetadata> {
            Ok(self
                .metadata
                .get(path)
                .copied()
                .unwrap_or_else(PathMetadata::missing))
        }

        fn write_atomic(&self, _path: &Path, _bytes: &[u8]) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "model detection must not write",
            ))
        }

        fn exists(&self, _path: &Path) -> bool {
            false
        }
    }

    #[derive(Debug, Default)]
    struct ModelProcess {
        responses: RefCell<VecDeque<ProcessObservation>>,
        calls: RefCell<Vec<ExecSpec>>,
    }

    impl ModelProcess {
        fn with_responses(responses: Vec<ProcessObservation>) -> Self {
            Self {
                responses: RefCell::new(responses.into()),
                calls: RefCell::new(Vec::new()),
            }
        }
    }

    impl ProcessPort for ModelProcess {
        fn run(&self, spec: &ExecSpec) -> Result<ProcessObservation, ProcessError> {
            self.calls.borrow_mut().push(spec.clone());
            self.responses.borrow_mut().pop_front().ok_or_else(|| {
                ProcessError::new(
                    ProcessErrorKind::Spawn,
                    "model fixture process response",
                    io::Error::other("unexpected provider process execution"),
                )
            })
        }
    }

    #[derive(Debug)]
    struct ExpireAfterFirstProcess<'a> {
        calls: &'a RefCell<Vec<ExecSpec>>,
    }

    impl OperationControl for ExpireAfterFirstProcess<'_> {
        fn checkpoint(&self) -> Result<OperationPermit, OperationControlError> {
            if self.calls.borrow().is_empty() {
                Ok(OperationPermit::limited(Duration::from_millis(30)))
            } else {
                Err(OperationControlError::TimedOut)
            }
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct ModelHasher;

    impl Hasher for ModelHasher {
        fn digest(&self, chunks: &[&[u8]]) -> Digest {
            let mut state = 0xcbf2_9ce4_8422_2325_u64;
            for chunk in chunks {
                for byte in *chunk {
                    state ^= u64::from(*byte);
                    state = state.wrapping_mul(0x0000_0100_0000_01b3);
                }
            }
            Digest::new(format!("model:{state:016x}"))
        }
    }

    #[derive(Debug, Default)]
    struct ModelInventoryCache {
        entries: RefCell<BTreeMap<String, Vec<u8>>>,
        loads: Cell<usize>,
        stores: Cell<usize>,
    }

    impl InventoryCacheReadPort for ModelInventoryCache {
        fn load(&self, key: &Digest, _max_bytes: usize) -> io::Result<Option<Vec<u8>>> {
            self.loads.set(self.loads.get().saturating_add(1));
            Ok(self.entries.borrow().get(key.as_str()).cloned())
        }
    }

    impl InventoryCacheWritePort for ModelInventoryCache {
        fn store_new(&self, key: &Digest, bytes: &[u8]) -> io::Result<()> {
            self.stores.set(self.stores.get().saturating_add(1));
            self.entries
                .borrow_mut()
                .entry(key.as_str().to_owned())
                .or_insert_with(|| bytes.to_vec());
            Ok(())
        }
    }

    fn model_inventory(entries: &[(&str, InventoryKind)]) -> Inventory {
        Inventory {
            entries: entries
                .iter()
                .map(|(path, kind)| InventoryEntry {
                    path: PathBuf::from(path),
                    kind: *kind,
                    size_bytes: Some(usize::from(*kind == InventoryKind::File) as u64),
                })
                .collect(),
            skipped: Vec::new(),
        }
    }

    #[test]
    fn unbounded_project_detection_borrows_the_authoritative_inventory() {
        let inventory = model_inventory(&[("Cargo.toml", InventoryKind::File)]);

        let absent = project_detection_inventory(&inventory, None);
        let unbounded = project_detection_inventory(&inventory, Some(&ProjectConfig::default()));

        assert!(matches!(
            absent,
            Cow::Borrowed(selected) if std::ptr::eq(selected, &inventory)
        ));
        assert!(matches!(
            unbounded,
            Cow::Borrowed(selected) if std::ptr::eq(selected, &inventory)
        ));
    }

    #[test]
    fn project_boundaries_filter_provider_and_runner_discovery_without_mutating_inventory()
    -> Result<(), Box<dyn Error>> {
        let inventory = model_inventory(&[
            ("Cargo.toml", InventoryKind::File),
            ("src/lib.rs", InventoryKind::File),
            ("fixtures/generated/example/Cargo.toml", InventoryKind::File),
            ("fixtures/generated/example/Makefile", InventoryKind::File),
        ]);
        let project = ProjectConfig {
            include: Vec::new(),
            exclude: vec![forge_core::PathPattern::new("fixtures/**")?],
        };

        let selected = project_detection_inventory(&inventory, Some(&project));

        assert!(matches!(&selected, Cow::Owned(_)));
        assert_eq!(inventory.entries.len(), 4);
        assert_eq!(
            selected
                .entries
                .iter()
                .map(|entry| entry.path.as_path())
                .collect::<Vec<_>>(),
            [Path::new("Cargo.toml"), Path::new("src/lib.rs")]
        );
        Ok(())
    }

    fn model_git(inventory: &Inventory) -> Result<ModelGit, Box<dyn Error>> {
        let tracked = inventory
            .entries
            .iter()
            .filter(|entry| entry.kind == InventoryKind::File)
            .map(|entry| RepoRelativePath::new(&entry.path))
            .collect::<Result<Vec<_>, _>>()?;
        let file_set = GitFileSet::new(tracked, Vec::new());
        let mut encoded_index = Vec::new();
        for path in &file_set.tracked {
            encoded_index
                .extend_from_slice(b"H 100644 1111111111111111111111111111111111111111 0\t");
            let path = path.as_path().to_str().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "model fixture index path is not valid UTF-8",
                )
            })?;
            encoded_index.extend_from_slice(path.as_bytes());
            encoded_index.push(0);
        }
        let index_entries = parse_git_index_reader(
            io::Cursor::new(encoded_index),
            GitObjectFormat::Sha1,
            1024 * 1024,
            file_set.tracked.len(),
        )?;
        Ok(ModelGit {
            file_set,
            index_entries,
            index_snapshot: b"model-index-v1".to_vec(),
            index_snapshot_responses: RefCell::new(VecDeque::new()),
            index_snapshot_reads: Cell::new(0),
            status: PorcelainV2Status {
                object_format: GitObjectFormat::Sha1,
                branch: BranchStatus {
                    oid: Some(BranchOid::Unborn),
                    head: Some(BranchHead::Detached),
                    ..BranchStatus::default()
                },
                entries: Vec::new(),
            },
            status_after_first_read: None,
            status_reads: Cell::new(0),
            head_file: Ok(None),
        })
    }

    fn committed_status() -> Result<PorcelainV2Status, forge_core::PorcelainV2ParseError> {
        parse_status_porcelain_v2(
            b"# branch.oid 1111111111111111111111111111111111111111\0# branch.head main\0",
            GitObjectFormat::Sha1,
        )
    }

    #[test]
    fn clean_commit_inventory_cache_hit_skips_the_authoritative_rescan()
    -> Result<(), Box<dyn std::error::Error>> {
        let inventory = model_inventory(&[("README.md", InventoryKind::File)]);
        let mut git = model_git(&inventory)?;
        git.status = committed_status()?;
        let filesystem = ModelFileSystem::new(inventory);
        let process = ModelProcess::default();
        let cache = ModelInventoryCache::default();

        let first = detect_project_model_with_cache(
            repository_root(),
            &git,
            &filesystem,
            &process,
            &ModelHasher,
            &ModelDetectionOptions::default(),
            Some(&cache),
        )?;
        assert_eq!(first.inventory_cache_status, InventoryCacheStatus::Miss);
        assert_eq!(filesystem.inventory_calls.get(), 1);
        assert_eq!(cache.loads.get(), 1);
        assert_eq!(cache.stores.get(), 0);
        let publication = first
            .inventory_cache_publication
            .as_ref()
            .ok_or("stable cache miss did not retain a publication")?;
        publish_cached_inventory(&cache, publication)?;
        assert_eq!(cache.stores.get(), 1);

        let second = detect_project_model_with_cache(
            repository_root(),
            &git,
            &filesystem,
            &process,
            &ModelHasher,
            &ModelDetectionOptions::default(),
            Some(&cache),
        )?;

        assert_eq!(second.inventory_cache_status, InventoryCacheStatus::Hit);
        assert!(second.inventory_cache_publication.is_none());
        let scope_seed = second
            .navigation
            .scope_seed
            .as_ref()
            .ok_or("cache hit did not retain its exact process-local scope seed")?;
        assert_eq!(scope_seed.status, git.status);
        assert_eq!(scope_seed.index_entries, git.index_entries);
        assert_eq!(second.model, first.model);
        assert_eq!(second.completion, first.completion);
        assert_eq!(
            second
                .navigation
                .inventory
                .entries
                .iter()
                .map(|entry| (&entry.path, entry.kind))
                .collect::<Vec<_>>(),
            first
                .navigation
                .inventory
                .entries
                .iter()
                .map(|entry| (&entry.path, entry.kind))
                .collect::<Vec<_>>()
        );
        assert!(
            second
                .navigation
                .inventory
                .entries
                .iter()
                .all(|entry| entry.size_bytes.is_none()),
            "shared projection must not retain worktree-local byte sizes"
        );
        assert_eq!(filesystem.inventory_calls.get(), 1);
        assert_eq!(cache.loads.get(), 2);
        assert_eq!(cache.stores.get(), 1);
        assert_eq!(git.index_snapshot_reads.get(), 6);
        Ok(())
    }

    #[test]
    fn cached_paths_must_match_the_current_index_projection()
    -> Result<(), Box<dyn std::error::Error>> {
        let cached_inventory = model_inventory(&[("README.md", InventoryKind::File)]);
        let mut first_git = model_git(&cached_inventory)?;
        first_git.status = committed_status()?;
        let cache = ModelInventoryCache::default();
        let first = detect_project_model_with_cache(
            repository_root(),
            &first_git,
            &ModelFileSystem::new(cached_inventory),
            &ModelProcess::default(),
            &ModelHasher,
            &ModelDetectionOptions::default(),
            Some(&cache),
        )?;
        publish_cached_inventory(
            &cache,
            first
                .inventory_cache_publication
                .as_ref()
                .ok_or("stable cache miss did not retain a publication")?,
        )?;

        let live_inventory = model_inventory(&[("OTHER.md", InventoryKind::File)]);
        let mut second_git = model_git(&live_inventory)?;
        second_git.status = committed_status()?;
        let filesystem = ModelFileSystem::new(live_inventory.clone());
        let second = detect_project_model_with_cache(
            repository_root(),
            &second_git,
            &filesystem,
            &ModelProcess::default(),
            &ModelHasher,
            &ModelDetectionOptions::default(),
            Some(&cache),
        )?;

        assert_eq!(second.inventory_cache_status, InventoryCacheStatus::Miss);
        assert_eq!(second.navigation.inventory, live_inventory);
        assert_eq!(filesystem.inventory_calls.get(), 1);
        Ok(())
    }

    #[test]
    fn rehashed_attestation_under_the_live_key_cannot_replace_current_index_paths()
    -> Result<(), Box<dyn std::error::Error>> {
        let live_inventory = model_inventory(&[("README.md", InventoryKind::File)]);
        let mut git = model_git(&live_inventory)?;
        git.status = committed_status()?;

        let legitimate_cache = ModelInventoryCache::default();
        let first = detect_project_model_with_cache(
            repository_root(),
            &git,
            &ModelFileSystem::new(live_inventory.clone()),
            &ModelProcess::default(),
            &ModelHasher,
            &ModelDetectionOptions::default(),
            Some(&legitimate_cache),
        )?;
        publish_cached_inventory(
            &legitimate_cache,
            first
                .inventory_cache_publication
                .as_ref()
                .ok_or("stable cache miss did not retain a publication")?,
        )?;
        let live_key = legitimate_cache
            .entries
            .borrow()
            .keys()
            .next()
            .cloned()
            .ok_or("published cache did not retain its key")?;
        let live_projection = index_projection_digest(&git.index_entries, &ModelHasher)
            .ok_or("ordinary model index did not produce a projection")?;

        // The cache digest is an integrity check, not an authority boundary: an attacker who can
        // write the cache can recompute it. Publish a structurally valid attestation under the live
        // key and projection from an inventory containing a different path.
        let forged_inventory = model_inventory(&[("OTHER.md", InventoryKind::File)]);
        let forged_cache = ModelInventoryCache::default();
        let forged_publication = prepare_cached_inventory(
            &Digest::new(live_key),
            &live_projection,
            &forged_inventory,
            &ModelHasher,
        )
        .ok_or("forged fixture could not produce a structurally valid cache envelope")?;
        publish_cached_inventory(&forged_cache, &forged_publication)?;

        let filesystem = ModelFileSystem::new(live_inventory.clone());
        let detected = detect_project_model_with_cache(
            repository_root(),
            &git,
            &filesystem,
            &ModelProcess::default(),
            &ModelHasher,
            &ModelDetectionOptions::default(),
            Some(&forged_cache),
        )?;

        assert_eq!(detected.inventory_cache_status, InventoryCacheStatus::Hit);
        assert_eq!(
            detected.navigation.inventory.entries,
            vec![InventoryEntry {
                path: PathBuf::from("README.md"),
                kind: InventoryKind::File,
                size_bytes: None,
            }]
        );
        assert_eq!(forged_cache.loads.get(), 1);
        assert_eq!(filesystem.inventory_calls.get(), 0);
        Ok(())
    }

    #[test]
    fn index_change_while_status_is_sampled_disables_cache_reuse()
    -> Result<(), Box<dyn std::error::Error>> {
        let inventory = model_inventory(&[("README.md", InventoryKind::File)]);
        let mut git = model_git(&inventory)?;
        git.status = committed_status()?;
        git.index_snapshot_responses
            .borrow_mut()
            .extend([b"index-before".to_vec(), b"index-after".to_vec()]);
        let filesystem = ModelFileSystem::new(inventory);
        let cache = ModelInventoryCache::default();

        let outcome = detect_project_model_with_cache(
            repository_root(),
            &git,
            &filesystem,
            &ModelProcess::default(),
            &ModelHasher,
            &ModelDetectionOptions::default(),
            Some(&cache),
        )?;

        assert_eq!(
            outcome.inventory_cache_status,
            InventoryCacheStatus::Ineligible
        );
        assert!(outcome.inventory_cache_publication.is_none());
        assert_eq!(cache.loads.get(), 0);
        assert_eq!(filesystem.inventory_calls.get(), 1);
        assert_eq!(git.index_snapshot_reads.get(), 2);
        Ok(())
    }

    #[test]
    fn index_change_during_authoritative_scan_prevents_cache_publication()
    -> Result<(), Box<dyn std::error::Error>> {
        let inventory = model_inventory(&[("README.md", InventoryKind::File)]);
        let mut git = model_git(&inventory)?;
        git.status = committed_status()?;
        git.index_snapshot_responses.borrow_mut().extend([
            b"stable-index".to_vec(),
            b"stable-index".to_vec(),
            b"changed-index".to_vec(),
        ]);
        let filesystem = ModelFileSystem::new(inventory);
        let cache = ModelInventoryCache::default();

        let outcome = detect_project_model_with_cache(
            repository_root(),
            &git,
            &filesystem,
            &ModelProcess::default(),
            &ModelHasher,
            &ModelDetectionOptions::default(),
            Some(&cache),
        )?;

        assert_eq!(outcome.inventory_cache_status, InventoryCacheStatus::Miss);
        assert!(outcome.inventory_cache_publication.is_none());
        assert_eq!(cache.loads.get(), 1);
        assert_eq!(filesystem.inventory_calls.get(), 1);
        assert_eq!(git.index_snapshot_reads.get(), 3);
        Ok(())
    }

    #[test]
    fn opaque_or_incomplete_index_state_is_never_cache_eligible()
    -> Result<(), Box<dyn std::error::Error>> {
        for case in ["assume-unchanged", "skip-worktree", "unmerged", "untracked"] {
            let inventory = model_inventory(&[("README.md", InventoryKind::File)]);
            let mut git = model_git(&inventory)?;
            git.status = committed_status()?;
            match case {
                "assume-unchanged" => {
                    git.index_entries[0].tag = GitIndexTag::AssumeUnchanged { underlying: b'H' };
                }
                "skip-worktree" => git.index_entries[0].tag = GitIndexTag::SkipWorktree,
                "unmerged" => git.index_entries[0].stage = 1,
                "untracked" => {
                    git.file_set
                        .untracked
                        .push(RepoRelativePath::new("scratch.txt")?);
                    git.status = parse_status_porcelain_v2(
                        b"# branch.oid 1111111111111111111111111111111111111111\0# branch.head main\0? scratch.txt\0",
                        GitObjectFormat::Sha1,
                    )?;
                }
                _ => return Err("unknown cache eligibility fixture".into()),
            }
            let filesystem = ModelFileSystem::new(inventory);
            let cache = ModelInventoryCache::default();

            let outcome = detect_project_model_with_cache(
                repository_root(),
                &git,
                &filesystem,
                &ModelProcess::default(),
                &ModelHasher,
                &ModelDetectionOptions::default(),
                Some(&cache),
            )?;

            assert_eq!(
                outcome.inventory_cache_status,
                InventoryCacheStatus::Ineligible,
                "case {case}"
            );
            assert_eq!(cache.loads.get(), 0, "case {case}");
            assert_eq!(cache.stores.get(), 0, "case {case}");
            assert!(outcome.inventory_cache_publication.is_none(), "case {case}");
            assert_eq!(filesystem.inventory_calls.get(), 1, "case {case}");
        }
        Ok(())
    }

    #[test]
    fn cache_hit_does_not_share_or_reprobe_worktree_local_sizes()
    -> Result<(), Box<dyn std::error::Error>> {
        let cached_inventory = model_inventory(&[("README.md", InventoryKind::File)]);
        let mut git = model_git(&cached_inventory)?;
        git.status = committed_status()?;
        let cache = ModelInventoryCache::default();
        let first_filesystem = ModelFileSystem::new(cached_inventory);
        let first = detect_project_model_with_cache(
            repository_root(),
            &git,
            &first_filesystem,
            &ModelProcess::default(),
            &ModelHasher,
            &ModelDetectionOptions::default(),
            Some(&cache),
        )?;
        assert_eq!(first.inventory_cache_status, InventoryCacheStatus::Miss);
        publish_cached_inventory(
            &cache,
            first
                .inventory_cache_publication
                .as_ref()
                .ok_or("stable cache miss did not retain a publication")?,
        )?;

        let live_inventory = Inventory {
            entries: vec![InventoryEntry {
                path: PathBuf::from("README.md"),
                kind: InventoryKind::File,
                size_bytes: Some(2),
            }],
            skipped: Vec::new(),
        };
        let live_filesystem = ModelFileSystem::new(live_inventory.clone());
        let second = detect_project_model_with_cache(
            repository_root(),
            &git,
            &live_filesystem,
            &ModelProcess::default(),
            &ModelHasher,
            &ModelDetectionOptions::default(),
            Some(&cache),
        )?;

        assert_eq!(second.inventory_cache_status, InventoryCacheStatus::Hit);
        assert_eq!(second.navigation.inventory.entries.len(), 1);
        assert_eq!(
            second.navigation.inventory.entries[0].path,
            Path::new("README.md")
        );
        assert_eq!(second.navigation.inventory.entries[0].size_bytes, None);
        assert_eq!(live_filesystem.inventory_calls.get(), 0);
        Ok(())
    }

    #[test]
    fn cache_hit_uses_the_attested_projection_without_per_path_metadata_probes()
    -> Result<(), Box<dyn std::error::Error>> {
        let cached_inventory = model_inventory(&[("README.md", InventoryKind::File)]);
        let mut git = model_git(&cached_inventory)?;
        git.status = committed_status()?;
        let cache = ModelInventoryCache::default();
        let first = detect_project_model_with_cache(
            repository_root(),
            &git,
            &ModelFileSystem::new(cached_inventory),
            &ModelProcess::default(),
            &ModelHasher,
            &ModelDetectionOptions::default(),
            Some(&cache),
        )?;
        publish_cached_inventory(
            &cache,
            first
                .inventory_cache_publication
                .as_ref()
                .ok_or("stable cache miss did not retain a publication")?,
        )?;

        let live_inventory = model_inventory(&[]);
        let live_filesystem = ModelFileSystem::new(live_inventory.clone());
        let second = detect_project_model_with_cache(
            repository_root(),
            &git,
            &live_filesystem,
            &ModelProcess::default(),
            &ModelHasher,
            &ModelDetectionOptions::default(),
            Some(&cache),
        )?;

        assert_eq!(second.inventory_cache_status, InventoryCacheStatus::Hit);
        assert!(second.inventory_cache_publication.is_none());
        assert_eq!(second.navigation.inventory.entries.len(), 1);
        assert_eq!(
            second.navigation.inventory.entries[0].path,
            Path::new("README.md")
        );
        assert_eq!(live_filesystem.inventory_calls.get(), 0);
        Ok(())
    }

    #[test]
    fn repository_change_during_inventory_scan_prevents_cache_publication()
    -> Result<(), Box<dyn std::error::Error>> {
        let inventory = model_inventory(&[("README.md", InventoryKind::File)]);
        let mut git = model_git(&inventory)?;
        git.status = committed_status()?;
        let mut changed = git.status.clone();
        changed.branch.head = Some(BranchHead::Detached);
        git.status_after_first_read = Some(changed);
        let filesystem = ModelFileSystem::new(inventory);
        let cache = ModelInventoryCache::default();

        let outcome = detect_project_model_with_cache(
            repository_root(),
            &git,
            &filesystem,
            &ModelProcess::default(),
            &ModelHasher,
            &ModelDetectionOptions::default(),
            Some(&cache),
        )?;

        assert_eq!(outcome.inventory_cache_status, InventoryCacheStatus::Miss);
        assert!(outcome.inventory_cache_publication.is_none());
        assert_eq!(cache.loads.get(), 1);
        assert_eq!(cache.stores.get(), 0);
        assert_eq!(filesystem.inventory_calls.get(), 1);
        Ok(())
    }

    /// Opaque placeholder: these model-provider tests do not consume process-output digests.
    fn ignored_process_digest(stream: &str) -> Digest {
        Digest::new(format!("fixture:non-canonical-model-{stream}"))
    }

    fn observation(stdout: Vec<u8>) -> ProcessObservation {
        ProcessObservation {
            exit_code: Some(0),
            signal: None,
            stdout_total_bytes: stdout.len() as u64,
            stderr_total_bytes: 0,
            stdout,
            stderr: Vec::new(),
            stdout_digest: ignored_process_digest("stdout"),
            stderr_digest: ignored_process_digest("stderr"),
            stdout_truncated: false,
            stderr_truncated: false,
            duration: Duration::from_millis(1),
            timed_out: false,
            interrupted: false,
        }
    }

    fn rust_metadata() -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&json!({
            "packages": [{
                "name": "rust-root",
                "id": "path+file:///repo#rust-root@0.1.0",
                "manifest_path": repository_path("Cargo.toml").to_string_lossy(),
                "dependencies": []
            }],
            "workspace_members": ["path+file:///repo#rust-root@0.1.0"],
            "workspace_default_members": ["path+file:///repo#rust-root@0.1.0"],
            "resolve": null,
            "workspace_root": repository_root().to_string_lossy(),
            "version": 1
        }))
    }

    fn file(path: &str, contents: &[u8]) -> (InventoryEntry, RunnerDiscovery) {
        let relative = RepoRelativePath::new(path).unwrap_or_else(|_| RepoRelativePath::root());
        let kind = runner_kind_for_path(relative.as_path()).unwrap_or(RunnerKind::Make);
        (
            InventoryEntry {
                path: PathBuf::from(path),
                kind: InventoryKind::File,
                size_bytes: Some(contents.len() as u64),
            },
            discover_runner(
                kind,
                &relative,
                &forge_core::BoundedText {
                    bytes: contents.to_vec(),
                    truncated: false,
                    binary: false,
                },
            ),
        )
    }

    fn assemble(
        inventory: Inventory,
        config: Option<&ForgeConfig>,
        discoveries: Vec<RunnerDiscovery>,
        complete: bool,
    ) -> Result<ProjectModel, ModelDetectionError> {
        let standard_assets =
            discover_standard_assets(&inventory).map_err(ModelDetectionError::Assets)?;
        let relevant_manifest = has_manifest(&inventory, "Cargo.toml")
            || has_manifest(&inventory, "go.mod")
            || has_manifest(&inventory, "go.work");
        let complete_language = inventory.skipped.is_empty() && !relevant_manifest;
        let language = LanguageDetection {
            units: Vec::new(),
            plans: Vec::new(),
            provenance: vec![Provenance {
                rule_id: String::from("test.language"),
                source_path: None,
                source_range: None,
                detail: String::from("test language detection fixture"),
            }],
            confidence: if complete_language {
                Confidence::Medium
            } else {
                Confidence::Unknown
            },
            complete: complete_language,
            timed_out: false,
            interrupted: false,
            diagnostics: Vec::new(),
            assumptions: Vec::new(),
        };
        assemble_project_model(
            repository(),
            inventory,
            standard_assets,
            PolicyAssemblyInput {
                config: config.cloned(),
                base_config: None,
                base_origin: PolicyBaseOrigin::Unborn,
                base_diagnostic: None,
                config_path: &RepoRelativePath::new("forge.toml").map_err(|source| {
                    ModelDetectionError::InvalidInventoryPath {
                        path: PathBuf::from("forge.toml"),
                        source,
                    }
                })?,
                hasher: &ModelHasher,
            },
            RunnerScan {
                discoveries,
                scripts: Vec::new(),
                failures: Vec::new(),
                global_complete: complete,
                unknown_script_intents: BTreeSet::new(),
                control_error: None,
            },
            language,
            InventoryCacheDetection {
                status: InventoryCacheStatus::Disabled,
                publication: None,
                navigation_scope_seed: None,
            },
        )
        .map(|outcome| outcome.model)
    }

    #[test]
    fn complete_zero_config_runner_resolves_without_claiming_coverage()
    -> Result<(), Box<dyn std::error::Error>> {
        let (entry, runner) = file("Makefile", b"test:\n\t@cargo test\n");
        let model = assemble(
            Inventory {
                entries: vec![entry],
                skipped: Vec::new(),
            },
            None,
            vec![runner],
            true,
        )?;

        assert_eq!(model.commands.len(), Intent::ALL.len());
        assert_eq!(
            model.commands[&Intent::Test].resolution(),
            CommandResolution::Resolved
        );
        assert!(
            model.commands[&Intent::Test]
                .commands()
                .iter()
                .all(|command| command.coverage.is_empty())
        );
        assert_eq!(
            model.commands[&Intent::Verify].resolution(),
            CommandResolution::Absent
        );
        assert!(model.units.is_empty());
        assert_eq!(model.unit_inventory_confidence, Confidence::Medium);
        Ok(())
    }

    #[test]
    fn multiple_project_runners_are_ambiguous_not_arbitrarily_selected()
    -> Result<(), Box<dyn std::error::Error>> {
        let (make_entry, make) = file("Makefile", b"test:\n\t@cargo test\n");
        let (just_entry, just) = file("justfile", b"test:\n    cargo test\n");
        let model = assemble(
            Inventory {
                entries: vec![make_entry, just_entry],
                skipped: Vec::new(),
            },
            None,
            vec![make, just],
            true,
        )?;

        let test = &model.commands[&Intent::Test];
        assert_eq!(test.resolution(), CommandResolution::Ambiguous);
        assert_eq!(test.commands().len(), 2);
        assert_eq!(test.executable_commands(), None);
        Ok(())
    }

    #[test]
    fn conventional_project_script_precedes_language_defaults_without_claiming_coverage()
    -> Result<(), Box<dyn std::error::Error>> {
        let inventory = model_inventory(&[("scripts/test.sh", InventoryKind::File)]);
        let git = model_git(&inventory)?;
        let script_path = RepoRelativePath::new("scripts/test.sh")?;
        let filesystem = ModelFileSystem::new(inventory).with_text(
            script_path.clone(),
            b"#!/usr/bin/env bash\necho test\n".to_vec(),
        );
        let outcome = detect_project_model(
            repository_root(),
            &git,
            &filesystem,
            &ModelProcess::default(),
            &ModelHasher,
            &ModelDetectionOptions::default(),
        )?;

        let test = &outcome.model.commands[&Intent::Test];
        assert_eq!(test.resolution(), CommandResolution::Resolved);
        assert_eq!(test.resolution_confidence, Confidence::Medium);
        assert_eq!(test.coverage_confidence, Confidence::Unknown);
        let command = &test.commands()[0];
        assert_eq!(command.program, "bash");
        assert_eq!(command.args, [script_path.as_path().as_os_str()]);
        assert!(matches!(
            &command.source,
            CommandSource::ExistingProjectTarget { path, target }
                if path == &script_path && target == "script-entrypoint"
        ));
        Ok(())
    }

    #[test]
    fn competing_scripts_for_one_intent_are_ambiguous() -> Result<(), Box<dyn std::error::Error>> {
        let inventory = model_inventory(&[
            ("scripts/test.sh", InventoryKind::File),
            ("tools/test.sh", InventoryKind::File),
        ]);
        let git = model_git(&inventory)?;
        let filesystem = ModelFileSystem::new(inventory)
            .with_text(
                RepoRelativePath::new("scripts/test.sh")?,
                b"#!/usr/bin/env bash\n".to_vec(),
            )
            .with_text(
                RepoRelativePath::new("tools/test.sh")?,
                b"#!/usr/bin/env bash\n".to_vec(),
            );

        let outcome = detect_project_model(
            repository_root(),
            &git,
            &filesystem,
            &ModelProcess::default(),
            &ModelHasher,
            &ModelDetectionOptions::default(),
        )?;

        let test = &outcome.model.commands[&Intent::Test];
        assert_eq!(test.resolution(), CommandResolution::Ambiguous);
        assert_eq!(test.commands().len(), 2);
        assert_eq!(test.executable_commands(), None);
        Ok(())
    }

    #[test]
    fn runner_and_script_for_one_intent_are_ambiguous() -> Result<(), Box<dyn std::error::Error>> {
        let inventory = model_inventory(&[
            ("Makefile", InventoryKind::File),
            ("scripts/test.sh", InventoryKind::File),
        ]);
        let git = model_git(&inventory)?;
        let filesystem = ModelFileSystem::new(inventory)
            .with_text(
                RepoRelativePath::new("Makefile")?,
                b"test:\n\t@cargo test\n".to_vec(),
            )
            .with_text(
                RepoRelativePath::new("scripts/test.sh")?,
                b"#!/usr/bin/env bash\n".to_vec(),
            );

        let outcome = detect_project_model(
            repository_root(),
            &git,
            &filesystem,
            &ModelProcess::default(),
            &ModelHasher,
            &ModelDetectionOptions::default(),
        )?;

        let test = &outcome.model.commands[&Intent::Test];
        assert_eq!(test.resolution(), CommandResolution::Ambiguous);
        assert_eq!(test.commands().len(), 2);
        assert_eq!(test.executable_commands(), None);
        Ok(())
    }

    #[test]
    fn unknown_verify_script_does_not_hide_independent_rust_intents()
    -> Result<(), Box<dyn std::error::Error>> {
        let inventory = model_inventory(&[
            ("Cargo.toml", InventoryKind::File),
            ("hack/verify.py", InventoryKind::File),
        ]);
        let git = model_git(&inventory)?;
        let filesystem = ModelFileSystem::new(inventory).with_text(
            RepoRelativePath::new("hack/verify.py")?,
            b"print('not a proven invocation')\n".to_vec(),
        );
        let process = ModelProcess::with_responses(vec![observation(rust_metadata()?)]);

        let outcome = detect_project_model(
            repository_root(),
            &git,
            &filesystem,
            &process,
            &ModelHasher,
            &ModelDetectionOptions::default(),
        )?;

        assert_eq!(
            outcome.model.commands[&Intent::Verify].resolution(),
            CommandResolution::Unknown
        );
        for intent in [
            Intent::FormatCheck,
            Intent::Format,
            Intent::Check,
            Intent::Test,
        ] {
            assert_eq!(
                outcome.model.commands[&intent].resolution(),
                CommandResolution::Resolved,
                "{intent:?} must remain independently resolved"
            );
        }
        assert_eq!(
            outcome.model.commands[&Intent::Build].resolution(),
            CommandResolution::Absent,
            "an unrelated absent intent must not become unknown"
        );
        Ok(())
    }

    #[test]
    fn incomplete_provider_result_keeps_language_commands_unknown()
    -> Result<(), Box<dyn std::error::Error>> {
        let inventory = Inventory {
            entries: vec![InventoryEntry {
                path: PathBuf::from("Cargo.toml"),
                kind: InventoryKind::File,
                size_bytes: Some(1),
            }],
            skipped: Vec::new(),
        };

        let first = assemble(inventory.clone(), None, Vec::new(), true)?;
        let second = assemble(inventory, None, Vec::new(), true)?;

        assert_eq!(first, second);
        assert_eq!(first.unit_inventory_confidence, Confidence::Unknown);
        assert!(first.units.is_empty());
        assert!(first.commands.values().all(|commands| {
            commands.resolution() == CommandResolution::Unknown
                && commands.executable_commands().is_none()
        }));
        Ok(())
    }

    #[test]
    fn explicit_config_wins_over_an_incomplete_runner_surface()
    -> Result<(), Box<dyn std::error::Error>> {
        let config = crate::config::parse_forge_config(
            r#"
schema = 1
[commands.test]
program = "cargo"
args = ["test", "--workspace"]
inputs = ["crates/**", "Cargo.toml"]
mutability = "external-side-effect"
network = "inherit"
success = "exit-zero-and-stdout-empty"
coverage = ["unit-test", "integration-test", "custom:workspace-contract"]
enforcement = "advisory"
"#,
        )?;
        let (_, unknown_runner) = file("Makefile", b"include commands.mk\ntest:\n");
        let model = assemble(
            Inventory::default(),
            Some(&config),
            vec![unknown_runner],
            false,
        )?;

        let test = &model.commands[&Intent::Test];
        assert_eq!(test.resolution(), CommandResolution::Resolved);
        assert_eq!(test.coverage_confidence, Confidence::High);
        assert_eq!(test.commands()[0].program, "cargo");
        assert_eq!(test.commands()[0].args, ["test", "--workspace"]);
        assert_eq!(
            test.commands()[0].mutability,
            Mutability::ExternalSideEffect
        );
        assert_eq!(test.commands()[0].network, NetworkIntent::Inherit);
        assert_eq!(
            test.commands()[0].success,
            SuccessPredicate::ExitZeroAndStdoutEmpty
        );
        assert_eq!(
            test.commands()[0].coverage,
            BTreeSet::from([
                CoverageDimension::UnitTest,
                CoverageDimension::IntegrationTest,
                CoverageDimension::Custom(String::from("workspace-contract")),
            ])
        );
        assert_eq!(test.commands()[0].enforcement, CommandEnforcement::Advisory);
        assert_eq!(
            config.commands[&Intent::Test].inputs,
            ["crates/**", "Cargo.toml"]
        );
        assert!(model.assumptions.iter().any(|assumption| {
            assumption
                .statement
                .contains("fingerprints the complete repository scope")
                && assumption
                    .provenance
                    .iter()
                    .any(|source| source.rule_id == "config.command-inputs.full-scope.v1")
        }));
        assert_eq!(
            model.commands[&Intent::Verify].resolution(),
            CommandResolution::Unknown
        );
        Ok(())
    }

    #[test]
    fn explicit_offline_request_sets_supported_ecosystem_guards()
    -> Result<(), Box<dyn std::error::Error>> {
        let config = crate::config::parse_forge_config(
            r#"
schema = 1
[commands.verify]
program = "make"
args = ["verify"]
network = "offline-requested"
"#,
        )?;
        let model = assemble(Inventory::default(), Some(&config), Vec::new(), false)?;
        let command = &model.commands[&Intent::Verify].commands()[0];

        assert_eq!(command.network, NetworkIntent::OfflineRequested);
        assert_eq!(
            command.env,
            BTreeMap::from([
                (OsString::from("CARGO_NET_OFFLINE"), OsString::from("true")),
                (OsString::from("GOPROXY"), OsString::from("off")),
                (OsString::from("GOSUMDB"), OsString::from("off")),
                (OsString::from("GOTOOLCHAIN"), OsString::from("local")),
                (OsString::from("RUSTUP_AUTO_INSTALL"), OsString::from("0")),
            ])
        );
        Ok(())
    }

    #[test]
    fn runner_kind_is_exact_and_does_not_guess_similar_names() {
        assert_eq!(
            runner_kind_for_path(Path::new("Makefile")),
            Some(RunnerKind::Make)
        );
        assert_eq!(
            runner_kind_for_path(Path::new("tools/Justfile")),
            Some(RunnerKind::Just)
        );
        assert_eq!(
            runner_kind_for_path(Path::new("Taskfile.yaml")),
            Some(RunnerKind::Task)
        );
        assert_eq!(runner_kind_for_path(Path::new("Makefile.backup")), None);
    }

    #[test]
    fn mixed_repository_runs_rust_then_go_and_composes_one_language_plan()
    -> Result<(), Box<dyn std::error::Error>> {
        let inventory = model_inventory(&[
            ("Cargo.toml", InventoryKind::File),
            ("go.work", InventoryKind::File),
            ("gomod", InventoryKind::Directory),
            ("gomod/go.mod", InventoryKind::File),
            ("gomod/main.go", InventoryKind::File),
        ]);
        let git = model_git(&inventory)?;
        let expected_inventory = inventory.clone();
        let filesystem = ModelFileSystem::new(inventory);
        let process = ModelProcess::with_responses(vec![
            observation(rust_metadata()?),
            observation(serde_json::to_vec(&json!({
                "Use": [{"DiskPath": "./gomod"}]
            }))?),
        ]);

        let outcome = detect_project_model(
            repository_root(),
            &git,
            &filesystem,
            &process,
            &ModelHasher,
            &ModelDetectionOptions::default(),
        )?;

        assert_eq!(outcome.completion, ModelDetectionCompletion::Complete);
        assert_eq!(
            outcome.inventory_cache_status,
            InventoryCacheStatus::Disabled
        );
        assert!(outcome.model.diagnostics.is_empty());
        assert_eq!(outcome.navigation.inventory, expected_inventory);
        assert_eq!(outcome.navigation.status, Some(git.status.clone()));
        assert_eq!(outcome.navigation.changed_paths(), Some(Vec::new()));
        assert_eq!(outcome.navigation.config, None);
        assert_eq!(
            outcome.navigation.config_path.as_path(),
            Path::new("forge.toml")
        );
        assert_eq!(
            outcome.navigation.policy_base_completeness,
            PolicyBaseCompleteness::Complete
        );
        assert!(outcome.navigation.policy_base_digest.is_some());
        assert_eq!(outcome.navigation.effective_policy.rules().len(), 9);
        assert!(outcome.model.policy.digest.is_some());
        assert_eq!(outcome.model.policy.confidence, Confidence::High);
        let calls = process.calls.borrow();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].program, OsString::from("cargo"));
        assert_eq!(calls[1].program, OsString::from("go"));
        assert!(
            outcome
                .model
                .units
                .iter()
                .any(|unit| unit.language.as_str() == "rust")
        );
        assert!(outcome.model.units.iter().any(|unit| {
            unit.language.as_str() == "rust" && unit.confidence == Confidence::High
        }));
        assert!(
            outcome
                .model
                .units
                .iter()
                .any(|unit| unit.language.as_str() == "go")
        );
        let check = &outcome.model.commands[&Intent::Check];
        assert_eq!(check.resolution(), CommandResolution::Resolved);
        assert!(check.commands().len() >= 3);
        assert_eq!(check.commands()[0].program, "cargo");
        assert!(
            check
                .commands()
                .iter()
                .skip(1)
                .any(|command| command.program == "go" || command.program == "gofmt")
        );
        Ok(())
    }

    #[test]
    fn total_budget_is_shared_from_rust_to_go_without_losing_rust_facts()
    -> Result<(), Box<dyn std::error::Error>> {
        let inventory = model_inventory(&[
            ("Cargo.toml", InventoryKind::File),
            ("go.work", InventoryKind::File),
            ("gomod", InventoryKind::Directory),
            ("gomod/go.mod", InventoryKind::File),
        ]);
        let git = model_git(&inventory)?;
        let filesystem = ModelFileSystem::new(inventory);
        let mut rust_failure = observation(Vec::new());
        rust_failure.exit_code = Some(1);
        let process = ModelProcess::with_responses(vec![rust_failure]);
        let control = ExpireAfterFirstProcess {
            calls: &process.calls,
        };

        let outcome = detect_project_model_controlled(
            repository_root(),
            &git,
            &filesystem,
            &process,
            &ModelHasher,
            &ModelDetectionOptions::default(),
            &control,
        )?;

        assert_eq!(outcome.completion, ModelDetectionCompletion::TimedOut);
        assert!(
            outcome
                .model
                .units
                .iter()
                .any(|unit| unit.language.as_str() == "rust")
        );
        assert!(
            outcome
                .model
                .units
                .iter()
                .all(|unit| unit.language.as_str() != "go")
        );
        assert_eq!(outcome.model.unit_inventory_confidence, Confidence::Unknown);
        let calls = process.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].program, OsString::from("cargo"));
        assert_eq!(calls[0].timeout, Duration::from_millis(30));
        assert!(
            outcome
                .model
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.what == "Go project detection was incomplete")
        );
        Ok(())
    }

    #[test]
    fn committed_head_config_is_the_complete_non_weakenable_policy_base()
    -> Result<(), Box<dyn std::error::Error>> {
        let inventory = model_inventory(&[("README.md", InventoryKind::File)]);
        let mut git = model_git(&inventory)?;
        git.status = committed_status()?;
        git.head_file = Ok(Some(
            br#"
schema = 1
[[risk]]
id = "risk/accepted-head"
level = "high"
paths = ["accepted/**"]
external = ["owner-review"]
"#
            .to_vec(),
        ));
        let filesystem = ModelFileSystem::new(inventory);
        let process = ModelProcess::default();

        let outcome = detect_project_model(
            repository_root(),
            &git,
            &filesystem,
            &process,
            &ModelHasher,
            &ModelDetectionOptions::default(),
        )?;

        assert_eq!(outcome.completion, ModelDetectionCompletion::Complete);
        assert_eq!(
            outcome.navigation.policy_base_origin,
            PolicyBaseOrigin::HeadConfig
        );
        assert_eq!(
            outcome.navigation.policy_base_completeness,
            PolicyBaseCompleteness::Complete
        );
        assert!(outcome.navigation.policy_base_digest.is_some());
        assert_eq!(outcome.model.policy.confidence, Confidence::High);
        let rule = outcome
            .navigation
            .effective_policy
            .rule("risk/accepted-head")
            .ok_or("accepted HEAD rule was not retained")?;
        assert_eq!(rule.level(), forge_core::RiskLevel::High);
        assert!(rule.external_requirements().contains("owner-review"));
        Ok(())
    }

    #[test]
    fn absent_head_config_uses_a_complete_builtin_base() -> Result<(), Box<dyn std::error::Error>> {
        let inventory = model_inventory(&[("README.md", InventoryKind::File)]);
        let mut git = model_git(&inventory)?;
        git.status = committed_status()?;
        git.head_file = Ok(None);
        let outcome = detect_project_model(
            repository_root(),
            &git,
            &ModelFileSystem::new(inventory),
            &ModelProcess::default(),
            &ModelHasher,
            &ModelDetectionOptions::default(),
        )?;

        assert_eq!(
            outcome.navigation.policy_base_origin,
            PolicyBaseOrigin::HeadConfigAbsent
        );
        assert_eq!(
            outcome.navigation.policy_base_completeness,
            PolicyBaseCompleteness::Complete
        );
        assert_eq!(outcome.model.policy.confidence, Confidence::High);
        Ok(())
    }

    #[test]
    fn unreadable_or_malformed_head_config_is_typed_unknown_without_breaking_detection()
    -> Result<(), Box<dyn std::error::Error>> {
        let inventory = model_inventory(&[("README.md", InventoryKind::File)]);
        for (head_file, expected_origin, diagnostic_code) in [
            (
                Err(GitError::new(
                    GitErrorKind::Io,
                    "read-commit-file",
                    "fixture failure",
                )),
                PolicyBaseOrigin::HeadReadFailed {
                    kind: GitErrorKind::Io,
                },
                "FGE2227",
            ),
            (
                Ok(Some(b"not valid toml = [".to_vec())),
                PolicyBaseOrigin::HeadConfigMalformed,
                "FGE2228",
            ),
        ] {
            let mut git = model_git(&inventory)?;
            git.status = committed_status()?;
            git.head_file = head_file;
            let cache = ModelInventoryCache::default();
            let outcome = detect_project_model_with_cache(
                repository_root(),
                &git,
                &ModelFileSystem::new(inventory.clone()),
                &ModelProcess::default(),
                &ModelHasher,
                &ModelDetectionOptions::default(),
                Some(&cache),
            )?;

            assert_eq!(outcome.completion, ModelDetectionCompletion::Complete);
            assert_eq!(outcome.navigation.policy_base_origin, expected_origin);
            assert_eq!(
                outcome.navigation.policy_base_completeness,
                PolicyBaseCompleteness::Unknown
            );
            assert_eq!(outcome.navigation.policy_base_digest, None);
            assert_eq!(outcome.model.policy.confidence, Confidence::Unknown);
            assert_eq!(
                outcome.inventory_cache_status,
                InventoryCacheStatus::Ineligible
            );
            assert_eq!(cache.loads.get(), 0);
            assert_eq!(cache.stores.get(), 0);
            assert!(
                outcome
                    .model
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code.as_str() == diagnostic_code)
            );
        }
        Ok(())
    }

    #[test]
    fn metadata_failure_keeps_static_model_and_redacted_uncertainty()
    -> Result<(), Box<dyn std::error::Error>> {
        let inventory = model_inventory(&[("Cargo.toml", InventoryKind::File)]);
        let git = model_git(&inventory)?;
        let filesystem = ModelFileSystem::new(inventory);
        let mut failure = observation(Vec::new());
        failure.exit_code = Some(1);
        failure.stderr = b"SECRET_RAW_TOOL_OUTPUT".to_vec();
        failure.stderr_total_bytes = failure.stderr.len() as u64;
        let process = ModelProcess::with_responses(vec![failure]);

        let outcome = detect_project_model(
            repository_root(),
            &git,
            &filesystem,
            &process,
            &ModelHasher,
            &ModelDetectionOptions::default(),
        )?;

        assert_eq!(outcome.completion, ModelDetectionCompletion::Partial);
        assert_eq!(outcome.model.units.len(), 1);
        assert_eq!(outcome.model.units[0].confidence, Confidence::Low);
        assert_eq!(
            outcome.model.commands[&Intent::Check].resolution(),
            CommandResolution::Unknown
        );
        assert!(!outcome.model.diagnostics.is_empty());
        assert!(!outcome.model.assumptions.is_empty());
        assert!(outcome.model.diagnostics.iter().all(|diagnostic| {
            !diagnostic.what.contains("SECRET_RAW_TOOL_OUTPUT")
                && !diagnostic.why.contains("SECRET_RAW_TOOL_OUTPUT")
                && !diagnostic.next.contains("SECRET_RAW_TOOL_OUTPUT")
        }));
        assert!(outcome.model.assumptions.iter().all(|assumption| {
            !assumption.statement.contains("SECRET_RAW_TOOL_OUTPUT")
                && assumption
                    .provenance
                    .iter()
                    .all(|item| !item.detail.contains("SECRET_RAW_TOOL_OUTPUT"))
        }));
        Ok(())
    }

    #[test]
    fn timeout_retains_static_units_and_typed_completion() -> Result<(), Box<dyn std::error::Error>>
    {
        let inventory = model_inventory(&[("Cargo.toml", InventoryKind::File)]);
        let git = model_git(&inventory)?;
        let filesystem = ModelFileSystem::new(inventory);
        let mut timeout = observation(Vec::new());
        timeout.exit_code = None;
        timeout.timed_out = true;
        let process = ModelProcess::with_responses(vec![timeout]);

        let outcome = detect_project_model(
            repository_root(),
            &git,
            &filesystem,
            &process,
            &ModelHasher,
            &ModelDetectionOptions::default(),
        )?;

        assert_eq!(outcome.completion, ModelDetectionCompletion::TimedOut);
        assert_eq!(outcome.model.units.len(), 1);
        assert!(!outcome.model.diagnostics.is_empty());
        Ok(())
    }

    #[test]
    fn interruption_has_priority_over_timeout_without_losing_model()
    -> Result<(), Box<dyn std::error::Error>> {
        let inventory = model_inventory(&[("Cargo.toml", InventoryKind::File)]);
        let git = model_git(&inventory)?;
        let filesystem = ModelFileSystem::new(inventory);
        let mut interrupted = observation(Vec::new());
        interrupted.exit_code = None;
        interrupted.timed_out = true;
        interrupted.interrupted = true;
        let process = ModelProcess::with_responses(vec![interrupted]);

        let outcome = detect_project_model(
            repository_root(),
            &git,
            &filesystem,
            &process,
            &ModelHasher,
            &ModelDetectionOptions::default(),
        )?;

        assert_eq!(outcome.completion, ModelDetectionCompletion::Interrupted);
        assert_eq!(outcome.model.units.len(), 1);
        assert_eq!(
            outcome.model.commands[&Intent::Test].resolution(),
            CommandResolution::Unknown
        );
        Ok(())
    }

    #[test]
    fn repository_without_language_manifests_runs_no_tool_probe()
    -> Result<(), Box<dyn std::error::Error>> {
        let inventory = model_inventory(&[("README.md", InventoryKind::File)]);
        let git = model_git(&inventory)?;
        let filesystem = ModelFileSystem::new(inventory);
        let process = ModelProcess::default();

        let outcome = detect_project_model(
            repository_root(),
            &git,
            &filesystem,
            &process,
            &ModelHasher,
            &ModelDetectionOptions::default(),
        )?;

        assert_eq!(outcome.completion, ModelDetectionCompletion::Complete);
        assert!(process.calls.borrow().is_empty());
        assert!(outcome.model.units.is_empty());
        assert!(
            outcome
                .model
                .commands
                .values()
                .all(|commands| commands.resolution() == CommandResolution::Absent)
        );
        Ok(())
    }

    #[test]
    fn generic_default_text_bound_matches_inventory_bootstrap_bound() {
        assert_eq!(
            ModelDetectionOptions::default()
                .inventory
                .max_text_file_bytes,
            DEFAULT_MAX_TEXT_FILE_BYTES
        );
        assert_eq!(
            ModelDetectionOptions::default().metadata_timeout,
            Duration::from_secs(60)
        );
    }

    #[test]
    fn policy_base_origin_distinguishes_complete_and_failed_sources() {
        assert_eq!(
            PolicyBaseOrigin::Unborn.completeness(),
            PolicyBaseCompleteness::Complete
        );
        assert_eq!(
            PolicyBaseOrigin::HeadConfigAbsent.completeness(),
            PolicyBaseCompleteness::Complete
        );
        assert_eq!(
            PolicyBaseOrigin::HeadConfig.completeness(),
            PolicyBaseCompleteness::Complete
        );
        assert_eq!(
            PolicyBaseOrigin::HeadReadFailed {
                kind: GitErrorKind::Io,
            }
            .completeness(),
            PolicyBaseCompleteness::Unknown
        );
        assert_eq!(
            PolicyBaseOrigin::HeadConfigMalformed.completeness(),
            PolicyBaseCompleteness::Unknown
        );
    }
}
