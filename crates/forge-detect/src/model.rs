//! Read-only P1-P9 assembly of the generic v0 project model.

use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use forge_core::ports::{FileSystemPort, GitPort, Hasher};
use forge_core::{
    CommandSource, CommandSpec, Confidence, EffectivePolicy, GitError, Intent,
    InvalidCommandResolution, Inventory, InventoryError, InventoryKind, InventoryOptions,
    ProjectModel, ProjectModelError, ProjectModelInputs, Provenance, RelativePathError,
    RepoRelativePath,
};

use crate::assets::{AssetDiscoveryError, StandardAssetDiscovery, discover_standard_assets};
use crate::config::{ConfigError, ForgeConfig, load_default_forge_config, load_forge_config_at};
use crate::repository::{RepositoryDetection, RepositoryDetectionError, detect_repository};
use crate::resolution::{
    CommandLayer, CommandLayerKind, CommandPlanCandidate, CommandResolutionLayers,
    resolve_command_intents,
};
use crate::runner::{RunnerDiscovery, RunnerDiscoveryCompleteness, RunnerKind, discover_runner};

/// Read-only generic detection controls. Provider-specific controls are added in M3.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ModelDetectionOptions {
    pub inventory: InventoryOptions,
    pub config_path: Option<RepoRelativePath>,
}

/// A typed failure from one generic project-model assembly stage.
#[derive(Debug)]
pub enum ModelDetectionError {
    Repository(RepositoryDetectionError),
    GitInventory(GitError),
    Inventory(InventoryError),
    Assets(AssetDiscoveryError),
    Config(ConfigError),
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
            Self::InvalidInventoryPath { source, .. } => Some(source),
            Self::CommandResolution(error) => Some(error),
            Self::InvalidModel(error) => Some(error),
        }
    }
}

/// Detects a finalized generic project model without executing project-owned commands.
pub fn detect_project_model<G, F, H>(
    start: &Path,
    git: &G,
    filesystem: &F,
    hasher: &H,
    options: &ModelDetectionOptions,
) -> Result<ProjectModel, ModelDetectionError>
where
    G: GitPort + ?Sized,
    F: FileSystemPort + ?Sized,
    H: Hasher + ?Sized,
{
    let repository = detect_repository(start, git, filesystem, hasher)
        .map_err(ModelDetectionError::Repository)?;
    let file_set = git
        .file_set(&repository.facts.root)
        .map_err(ModelDetectionError::GitInventory)?;
    let inventory = filesystem
        .inventory(&repository.facts.root, Some(&file_set), options.inventory)
        .map_err(ModelDetectionError::Inventory)?;
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
        config.as_ref(),
        &config_path,
        runners,
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

fn assemble_project_model(
    repository: RepositoryDetection,
    inventory: Inventory,
    standard_assets: StandardAssetDiscovery,
    config: Option<&ForgeConfig>,
    config_path: &RepoRelativePath,
    runners: RunnerScan,
) -> Result<ProjectModel, ModelDetectionError> {
    let timeout = config
        .and_then(|config| config.policy.default_timeout_seconds)
        .unwrap_or(300);
    let explicit_config = explicit_config_layer(config, config_path, timeout);
    let existing_project = existing_project_layer(runners, timeout);
    let (language_default, unit_provenance, unit_confidence) =
        language_default_layer(&inventory, &standard_assets);
    let commands = resolve_command_intents(&CommandResolutionLayers {
        explicit_config,
        existing_project,
        language_default,
    })
    .map_err(ModelDetectionError::CommandResolution)?;
    let policy = unresolved_effective_policy(config, config_path);

    let mut model = ProjectModel::new(ProjectModelInputs {
        repository: repository.facts,
        repository_provenance: repository.provenance,
        repository_confidence: repository.confidence,
        unit_inventory_provenance: unit_provenance,
        unit_inventory_confidence: unit_confidence,
        assets: standard_assets.assets,
        adapters: standard_assets.adapters,
        policy,
    });
    model.commands = commands;
    model.diagnostics = repository.diagnostics;
    model.finalize().map_err(ModelDetectionError::InvalidModel)
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

fn language_default_layer(
    inventory: &Inventory,
    standard_assets: &StandardAssetDiscovery,
) -> (CommandLayer, Vec<Provenance>, Confidence) {
    let supported_manifest = standard_assets
        .assets
        .entries
        .iter()
        .any(|asset| asset.kind.starts_with("manifest."));
    let complete = inventory.skipped.is_empty() && !supported_manifest;
    let provenance = vec![Provenance {
        rule_id: String::from("units.generic-detection.v1"),
        source_path: None,
        source_range: None,
        detail: if supported_manifest {
            String::from("supported manifests were inventoried; provider resolution belongs to M3")
        } else if inventory.skipped.is_empty() {
            String::from("no supported language manifest was present in the complete inventory")
        } else {
            String::from("partial inventory cannot prove the supported unit set is empty")
        },
    }];
    if complete {
        (
            CommandLayer::complete(
                CommandLayerKind::LanguageDefault,
                Vec::new(),
                provenance.clone(),
                Confidence::Medium,
            ),
            provenance,
            Confidence::Medium,
        )
    } else {
        (
            CommandLayer::unknown(
                CommandLayerKind::LanguageDefault,
                Vec::new(),
                provenance.clone(),
            ),
            provenance,
            Confidence::Unknown,
        )
    }
}

fn unresolved_effective_policy(
    config: Option<&ForgeConfig>,
    config_path: &RepoRelativePath,
) -> EffectivePolicy {
    EffectivePolicy::unknown(vec![Provenance {
        rule_id: String::from("policy.effective.pending-v1"),
        source_path: config.is_some().then(|| config_path.as_path().into()),
        source_range: None,
        detail: if config.is_some() {
            String::from("configuration was parsed, but effective policy merging belongs to M5")
        } else {
            String::from("effective built-in policy resolution belongs to M5")
        },
    }])
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
    use std::path::{Path, PathBuf};

    use forge_core::inventory::DEFAULT_MAX_TEXT_FILE_BYTES;
    use forge_core::{CommandResolution, Confidence, InventoryEntry, RepoFacts, RepoId, WorkState};

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
        assemble_project_model(
            repository(),
            inventory,
            standard_assets,
            config,
            &RepoRelativePath::new("forge.toml").map_err(|source| {
                ModelDetectionError::InvalidInventoryPath {
                    path: PathBuf::from("forge.toml"),
                    source,
                }
            })?,
            RunnerScan {
                discoveries,
                failures: Vec::new(),
                complete,
            },
        )
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
    fn supported_manifest_is_explicitly_unknown_until_provider_milestone()
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
    fn generic_default_text_bound_matches_inventory_bootstrap_bound() {
        assert_eq!(
            ModelDetectionOptions::default()
                .inventory
                .max_text_file_bytes,
            DEFAULT_MAX_TEXT_FILE_BYTES
        );
    }
}
