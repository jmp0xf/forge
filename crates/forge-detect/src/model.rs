//! Read-only P1-P9 assembly of the generic v0 project model.

use std::error::Error;
use std::ffi::OsStr;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use forge_core::ports::{FileSystemPort, GitPort, Hasher, ProcessPort};
use forge_core::{
    Assumption, CommandSource, CommandSpec, Confidence, Diagnostic, GitError, GitFileSet, Intent,
    InvalidCommandResolution, Inventory, InventoryError, InventoryKind, InventoryOptions,
    ProjectModel, ProjectModelError, ProjectModelInputs, ProjectUnit, Provenance,
    RelativePathError, RepoRelativePath, Severity,
};

use crate::assets::{AssetDiscoveryError, StandardAssetDiscovery, discover_standard_assets};
use crate::config::{ConfigError, ForgeConfig, load_default_forge_config, load_forge_config_at};
use crate::go::{
    GoProvider, GoProviderContext, GoProviderError, GoProviderIssue, GoProviderIssueKind,
};
use crate::policy::{PolicyBaseCompleteness, PolicyResolutionError, resolve_effective_policy};
use crate::repository::{RepositoryDetection, RepositoryDetectionError, detect_repository};
use crate::resolution::{
    CommandLayer, CommandLayerKind, CommandPlanCandidate, CommandResolutionLayers,
    compose_ordered_language_plans, resolve_command_intents,
};
use crate::runner::{RunnerDiscovery, RunnerDiscoveryCompleteness, RunnerKind, discover_runner};
use crate::rust::{
    CargoMetadataCompletion, CargoMetadataOutcome, RustDetectionContext, RustDetectionError,
    RustProvider,
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

/// Whether all model-detection stages completed without a bounded degradation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelDetectionCompletion {
    Complete,
    Partial,
    TimedOut,
    Interrupted,
}

/// A finalized model retained independently from its typed completion state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelDetectionOutcome {
    pub model: ProjectModel,
    pub completion: ModelDetectionCompletion,
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

/// Detects a finalized generic project model without executing project-owned commands.
pub fn detect_project_model(
    start: &Path,
    git: &dyn GitPort,
    filesystem: &dyn FileSystemPort,
    process: &dyn ProcessPort,
    hasher: &dyn Hasher,
    options: &ModelDetectionOptions,
) -> Result<ModelDetectionOutcome, ModelDetectionError> {
    let repository = detect_repository(start, git, filesystem, hasher)
        .map_err(ModelDetectionError::Repository)?;
    let file_set = git
        .file_set(&repository.facts.root)
        .map_err(ModelDetectionError::GitInventory)?;
    let inventory = filesystem
        .inventory(&repository.facts.root, Some(&file_set), options.inventory)
        .map_err(ModelDetectionError::Inventory)?;
    let language = detect_language_providers(
        &repository,
        &inventory,
        &file_set,
        filesystem,
        process,
        hasher,
        options.metadata_timeout,
    )?;
    let standard_assets =
        discover_standard_assets(&inventory).map_err(ModelDetectionError::Assets)?;
    let (config, config_path) = load_config(
        filesystem,
        &repository.facts.root,
        options.config_path.as_ref(),
    )?;
    let runners = scan_runners(
        filesystem,
        &repository.facts.root,
        &inventory,
        options.inventory.max_text_file_bytes,
    )?;

    assemble_project_model(
        repository,
        inventory,
        standard_assets,
        PolicyAssemblyInput {
            config,
            config_path: &config_path,
            hasher,
        },
        runners,
        language,
    )
}

fn load_config<F>(
    filesystem: &F,
    repository_root: &Path,
    selected: Option<&RepoRelativePath>,
) -> Result<(Option<ForgeConfig>, RepoRelativePath), ModelDetectionError>
where
    F: FileSystemPort + ?Sized,
{
    if let Some(path) = selected {
        let config = load_forge_config_at(filesystem, repository_root, path)
            .map_err(ModelDetectionError::Config)?;
        return Ok((Some(config), path.clone()));
    }
    let path = RepoRelativePath::new(forge_core::branding::CONFIG_FILE).map_err(|source| {
        ModelDetectionError::InvalidInventoryPath {
            path: PathBuf::from(forge_core::branding::CONFIG_FILE),
            source,
        }
    })?;
    let config = load_default_forge_config(filesystem, repository_root)
        .map_err(ModelDetectionError::Config)?;
    Ok((config, path))
}

#[derive(Debug)]
struct RunnerScan {
    discoveries: Vec<RunnerDiscovery>,
    failures: Vec<Provenance>,
    complete: bool,
}

fn scan_runners<F>(
    filesystem: &F,
    repository_root: &Path,
    inventory: &Inventory,
    max_text_file_bytes: u64,
) -> Result<RunnerScan, ModelDetectionError>
where
    F: FileSystemPort + ?Sized,
{
    let mut discoveries = Vec::new();
    let mut failures = Vec::new();
    for entry in &inventory.entries {
        let Some(kind) = runner_kind_for_path(&entry.path) else {
            continue;
        };
        let path = RepoRelativePath::new(&entry.path).map_err(|source| {
            ModelDetectionError::InvalidInventoryPath {
                path: entry.path.clone(),
                source,
            }
        })?;
        if entry.kind != InventoryKind::File {
            failures.push(runner_failure_provenance(
                &path,
                "runner path is not a regular file and was not followed",
            ));
            continue;
        }
        match filesystem.read_bounded_text(repository_root, &path, max_text_file_bytes) {
            Ok(text) => discoveries.push(discover_runner(kind, &path, &text)),
            Err(_) => failures.push(runner_failure_provenance(
                &path,
                "runner file could not be read through the bounded repository port",
            )),
        }
    }
    let complete = inventory.skipped.is_empty()
        && failures.is_empty()
        && discoveries
            .iter()
            .all(|discovery| discovery.completeness() == RunnerDiscoveryCompleteness::Complete);
    Ok(RunnerScan {
        discoveries,
        failures,
        complete,
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

fn detect_language_providers(
    repository: &RepositoryDetection,
    inventory: &Inventory,
    file_set: &GitFileSet,
    filesystem: &dyn FileSystemPort,
    process: &dyn ProcessPort,
    hasher: &dyn Hasher,
    metadata_timeout: Duration,
) -> Result<LanguageDetection, ModelDetectionError> {
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
            .detect_project(&RustDetectionContext {
                repository_root: &repository.facts.root,
                inventory,
                filesystem,
                process,
                hasher,
                metadata_timeout,
            })
            .map_err(ModelDetectionError::RustProvider)?;
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

    if go_relevant {
        let changed_paths = repository.changed_paths();
        let result = GoProvider
            .analyze(GoProviderContext {
                repository_root: &repository.facts.root,
                inventory,
                git_files: file_set,
                changed_files: changed_paths.as_deref(),
                file_system: filesystem,
                process,
                hasher,
                metadata_timeout,
            })
            .map_err(ModelDetectionError::GoProvider)?;
        for issue in &result.issues {
            interrupted |= issue.kind == GoProviderIssueKind::MetadataInterrupted;
            timed_out |= issue.kind == GoProviderIssueKind::MetadataTimedOut;
            let (diagnostic, assumption) = go_incomplete_evidence(issue);
            diagnostics.push(diagnostic);
            assumptions.push(assumption);
        }
        complete &= result.complete;
        units.extend(result.units);
        plan_fragments.extend(result.plans);
        provenance.extend(result.provenance);
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

fn go_incomplete_evidence(issue: &GoProviderIssue) -> (Diagnostic, Assumption) {
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
) -> Result<ModelDetectionOutcome, ModelDetectionError> {
    let PolicyAssemblyInput {
        config,
        config_path,
        hasher,
    } = policy_input;
    let timeout = config
        .as_ref()
        .and_then(|config| config.policy.default_timeout_seconds)
        .unwrap_or(300);
    let generic_partial = repository.confidence == Confidence::Unknown
        || !inventory.skipped.is_empty()
        || !runners.complete
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
    let policy_base_completeness =
        policy_base_completeness(repository.facts.work_state, repository.facts.head.is_some());
    let policy_resolution = resolve_effective_policy(
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
    model.diagnostics.extend(language.diagnostics);
    model.assumptions = language.assumptions;
    let model = model
        .finalize()
        .map_err(ModelDetectionError::InvalidModel)?;
    Ok(ModelDetectionOutcome {
        model,
        completion,
        navigation: NavigationSnapshot {
            status,
            inventory,
            config,
            config_path: config_path.clone(),
            effective_policy: policy_resolution.effective,
            policy_base_completeness,
        },
    })
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

fn policy_base_completeness(
    work_state: forge_core::WorkState,
    has_head: bool,
) -> PolicyBaseCompleteness {
    if work_state == forge_core::WorkState::Unborn && !has_head {
        PolicyBaseCompleteness::Complete
    } else {
        PolicyBaseCompleteness::Unknown
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
            command.confidence = Confidence::High;
            candidates.push(CommandPlanCandidate::single(
                command,
                vec![config_provenance(
                    config_path,
                    "configured command is declared directly in the selected Forge configuration",
                )],
                Confidence::Unknown,
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
        failures,
        complete,
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
    provenance.push(Provenance {
        rule_id: String::from("runner.inventory.v1"),
        source_path: None,
        source_range: None,
        detail: if complete {
            String::from("all inventoried supported runner files were scanned completely")
        } else {
            String::from("the supported runner surface was not observed completely")
        },
    });
    if complete {
        CommandLayer::complete(
            CommandLayerKind::ExistingProject,
            candidates,
            provenance,
            Confidence::Medium,
        )
    } else {
        CommandLayer::unknown(CommandLayerKind::ExistingProject, candidates, provenance)
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
    use std::cell::RefCell;
    use std::collections::{BTreeMap, VecDeque};
    use std::ffi::OsString;
    use std::io;
    use std::path::{Path, PathBuf};

    use forge_core::inventory::DEFAULT_MAX_TEXT_FILE_BYTES;
    use forge_core::ports::{ExecSpec, ProcessError, ProcessErrorKind, ProcessObservation};
    use forge_core::{
        BoundedText, BranchHead, BranchOid, BranchStatus, CommandResolution, Confidence, Digest,
        GitFileSet, GitObjectFormat, InventoryEntry, PathKind, PorcelainV2Status, RepoFacts,
        RepoId, WorkState,
    };
    use serde_json::json;

    use super::*;

    fn repository() -> RepositoryDetection {
        RepositoryDetection {
            facts: RepoFacts {
                id: RepoId::from("local:blake3:model-test"),
                root: PathBuf::from("/repo"),
                git_dir: PathBuf::from("/repo/.git"),
                git_common_dir: PathBuf::from("/repo/.git"),
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

    #[derive(Debug, Clone)]
    struct ModelGit {
        file_set: GitFileSet,
        status: PorcelainV2Status,
    }

    impl GitPort for ModelGit {
        fn repository_root(&self, _start: &Path) -> Result<PathBuf, GitError> {
            Ok(PathBuf::from("/repo"))
        }

        fn git_dir(&self, _start: &Path) -> Result<PathBuf, GitError> {
            Ok(PathBuf::from("/repo/.git"))
        }

        fn git_common_dir(&self, _start: &Path) -> Result<PathBuf, GitError> {
            Ok(PathBuf::from("/repo/.git"))
        }

        fn status(&self, _root: &Path) -> Result<PorcelainV2Status, GitError> {
            Ok(self.status.clone())
        }

        fn file_set(&self, _root: &Path) -> Result<GitFileSet, GitError> {
            Ok(self.file_set.clone())
        }
    }

    #[derive(Debug, Clone)]
    struct ModelFileSystem {
        inventory: Inventory,
        kinds: BTreeMap<RepoRelativePath, PathKind>,
    }

    impl ModelFileSystem {
        fn new(inventory: Inventory) -> Self {
            let kinds = inventory
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
                        (path, kind)
                    })
                })
                .collect();
            Self { inventory, kinds }
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
            Ok(self.inventory.clone())
        }

        fn read_bounded_text(
            &self,
            _root: &Path,
            _path: &RepoRelativePath,
            _max_text_file_bytes: u64,
        ) -> Result<BoundedText, InventoryError> {
            Ok(BoundedText {
                bytes: Vec::new(),
                truncated: false,
                binary: false,
            })
        }

        fn path_kind(&self, _root: &Path, path: &RepoRelativePath) -> io::Result<PathKind> {
            Ok(self.kinds.get(path).copied().unwrap_or(PathKind::Missing))
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

    fn model_inventory(entries: &[(&str, InventoryKind)]) -> Inventory {
        Inventory {
            entries: entries
                .iter()
                .map(|(path, kind)| InventoryEntry {
                    path: PathBuf::from(path),
                    kind: *kind,
                    size_bytes: usize::from(*kind == InventoryKind::File) as u64,
                })
                .collect(),
            skipped: Vec::new(),
        }
    }

    fn model_git(inventory: &Inventory) -> Result<ModelGit, RelativePathError> {
        let tracked = inventory
            .entries
            .iter()
            .filter(|entry| entry.kind == InventoryKind::File)
            .map(|entry| RepoRelativePath::new(&entry.path))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ModelGit {
            file_set: GitFileSet::new(tracked, Vec::new()),
            status: PorcelainV2Status {
                object_format: GitObjectFormat::Sha1,
                branch: BranchStatus {
                    oid: Some(BranchOid::Unborn),
                    head: Some(BranchHead::Detached),
                    ..BranchStatus::default()
                },
                entries: Vec::new(),
            },
        })
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
                "manifest_path": "/repo/Cargo.toml",
                "dependencies": []
            }],
            "workspace_members": ["path+file:///repo#rust-root@0.1.0"],
            "workspace_default_members": ["path+file:///repo#rust-root@0.1.0"],
            "resolve": null,
            "workspace_root": "/repo",
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
                size_bytes: contents.len() as u64,
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
                failures: Vec::new(),
                complete,
            },
            language,
        )
        .map(|outcome| outcome.model)
    }

    fn policy_completeness_for_fixture(
        work_state: WorkState,
        has_head: bool,
    ) -> PolicyBaseCompleteness {
        policy_base_completeness(work_state, has_head)
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
    fn incomplete_provider_result_keeps_language_commands_unknown()
    -> Result<(), Box<dyn std::error::Error>> {
        let inventory = Inventory {
            entries: vec![InventoryEntry {
                path: PathBuf::from("Cargo.toml"),
                kind: InventoryKind::File,
                size_bytes: 1,
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
        assert_eq!(test.commands()[0].program, "cargo");
        assert_eq!(test.commands()[0].args, ["test", "--workspace"]);
        assert_eq!(
            model.commands[&Intent::Verify].resolution(),
            CommandResolution::Unknown
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
            Path::new("/repo"),
            &git,
            &filesystem,
            &process,
            &ModelHasher,
            &ModelDetectionOptions::default(),
        )?;

        assert_eq!(outcome.completion, ModelDetectionCompletion::Complete);
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
            Path::new("/repo"),
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
            Path::new("/repo"),
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
            Path::new("/repo"),
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
            Path::new("/repo"),
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
    fn only_an_unborn_repository_has_a_complete_policy_base() {
        assert_eq!(
            policy_completeness_for_fixture(WorkState::Unborn, false),
            PolicyBaseCompleteness::Complete
        );
        assert_eq!(
            policy_completeness_for_fixture(WorkState::Clean, true),
            PolicyBaseCompleteness::Unknown
        );
        assert_eq!(
            policy_completeness_for_fixture(WorkState::Unknown, false),
            PolicyBaseCompleteness::Unknown
        );
    }
}
