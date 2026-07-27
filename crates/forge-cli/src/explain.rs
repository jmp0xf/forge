//! Read-only CLI composition for generic project-model detection and explanation.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::io;
use std::path::Path;
use std::time::Duration;

use forge_core::branding::{CLI_NAME, CONFIG_FILE};
use forge_core::fingerprint::validate_command_privacy;
use forge_core::ports::{GitPort as _, ProcessError};
use forge_core::{
    AppError, ExitCode, GitError, GitErrorKind, InventoryError, OperationControl as _,
    OperationControlError, ProjectModel, ProjectModelWireError, RepoRelativePath,
    project_model_to_wire,
};
use forge_detect::config::{ConfigError, ConfigLoadError};
use forge_detect::inventory_cache::{
    InventoryCachePublication, InventoryCacheReadPort, InventoryCacheWritePort,
    MAX_INVENTORY_CACHE_BYTES, publish_cached_inventory,
};
use forge_detect::model::{
    InventoryCacheStatus, ModelDetectionCompletion, ModelDetectionError, ModelDetectionExecution,
    ModelDetectionOptions, NavigationSnapshot, detect_project_model_with_cache_controlled,
};
use forge_runtime::control::OperationBudget;
use forge_runtime::fs::NativeFileSystem;
use forge_runtime::git::GitCli;
use forge_runtime::hash::Blake3Hasher;
use forge_runtime::process::SynchronousProcessRunner;
use forge_runtime::state::{
    GitStateLayout, SharedCacheKind, SharedCacheStore, SharedCacheWrite, StateError,
};
use forge_schema::{
    CommandResolutionData, ConfidenceData, Diagnostic, ProjectModelData, ProvenanceData,
    SchemaKind, Severity,
};

use crate::args::Cli;

/// One repository scan retained as the domain-model source of truth for command-specific views.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DetectedProject {
    pub(crate) model: ProjectModel,
    pub(crate) completion: ModelDetectionCompletion,
    pub(crate) inventory_cache_status: InventoryCacheStatus,
    pub(crate) navigation: NavigationSnapshot,
    inventory_cache_publication: Option<InventoryCachePublication>,
}

#[cfg(test)]
impl DetectedProject {
    /// Builds the smallest complete detection snapshot needed by CLI unit tests that verify
    /// cross-scan stability. Production detections continue to come only from [`detect`].
    pub(crate) fn test_fixture(model: ProjectModel) -> Result<Self, Box<dyn std::error::Error>> {
        let effective_policy = forge_core::EffectivePolicyContent::new(
            Vec::<forge_core::RiskRule>::new(),
            forge_core::EvidenceRequirements::default(),
        )?;
        Ok(Self {
            model,
            completion: ModelDetectionCompletion::Complete,
            inventory_cache_status: InventoryCacheStatus::Disabled,
            navigation: NavigationSnapshot {
                status: None,
                inventory: forge_core::Inventory::default(),
                config: None,
                config_path: RepoRelativePath::new(CONFIG_FILE)?,
                effective_policy,
                policy_base_completeness: forge_detect::policy::PolicyBaseCompleteness::Complete,
                policy_base_digest: None,
                policy_base_origin: forge_detect::model::PolicyBaseOrigin::Unborn,
                scope_seed: None,
            },
            inventory_cache_publication: None,
        })
    }
}

#[derive(Debug)]
struct SharedInventoryCache {
    store: SharedCacheStore,
}

impl InventoryCacheReadPort for SharedInventoryCache {
    fn load(&self, key: &forge_core::Digest, max_bytes: usize) -> io::Result<Option<Vec<u8>>> {
        self.store
            .load(
                SharedCacheKind::Inventory,
                key,
                max_bytes.min(MAX_INVENTORY_CACHE_BYTES),
            )
            .map_err(state_error_as_io)
    }
}

impl InventoryCacheWritePort for SharedInventoryCache {
    fn store_new(&self, key: &forge_core::Digest, bytes: &[u8]) -> io::Result<()> {
        match self
            .store
            .store_immutable(SharedCacheKind::Inventory, key, bytes)
            .map_err(state_error_as_io)?
        {
            SharedCacheWrite::Created | SharedCacheWrite::AlreadyPresent => Ok(()),
        }
    }
}

fn state_error_as_io(error: StateError) -> io::Error {
    io::Error::new(error.io_kind(), error.to_string())
}

/// Detects using the single command-wide budget constructed by the CLI dispatcher.
pub(crate) fn detect_controlled(
    cli: &Cli,
    control: &OperationBudget,
) -> Result<DetectedProject, AppError> {
    checkpoint(control, "project detection")?;
    let start = cli.dir.as_deref().unwrap_or_else(|| Path::new("."));
    let config_path = cli
        .config
        .as_ref()
        .map(RepoRelativePath::new)
        .transpose()
        .map_err(|error| {
            AppError::usage(
                "FGE1001",
                "the selected configuration path is not repository-relative",
                "--config",
                error.to_string(),
                "pass a path inside the repository without an absolute prefix or `..`",
            )
        })?;
    let git = GitCli::new().with_operation_budget(control.clone());
    let repository_root = git.repository_root(start).map_err(|error| {
        let detail = error.to_string();
        map_git_error(&error, "repository root", detail)
    })?;
    let process = SynchronousProcessRunner::new(&repository_root)
        .map_err(map_process_setup_error)?
        .with_cancellation_flag(control.cancellation_flag());
    let filesystem = NativeFileSystem;
    let hasher = Blake3Hasher;
    checkpoint(control, "inventory cache discovery")?;
    let inventory_cache = if cli.no_cache {
        None
    } else {
        git.git_dir(&repository_root)
            .ok()
            .zip(git.git_common_dir(&repository_root).ok())
            .and_then(|(git_dir, common_dir)| {
                SharedCacheStore::new(&GitStateLayout::new(git_dir, common_dir)).ok()
            })
            .map(|store| SharedInventoryCache { store })
    };
    checkpoint(control, "inventory cache discovery")?;
    let default_options = ModelDetectionOptions::default();
    let execution = ModelDetectionExecution::new(control);
    let execution = inventory_cache.as_ref().map_or(execution, |cache| {
        execution.with_inventory_cache(cache as &dyn InventoryCacheReadPort)
    });
    let outcome = detect_project_model_with_cache_controlled(
        &repository_root,
        &git,
        &filesystem,
        &process,
        &hasher,
        &ModelDetectionOptions {
            config_path,
            ..default_options
        },
        execution,
    )
    .map_err(map_detection_error)?;
    Ok(DetectedProject {
        model: outcome.model,
        completion: outcome.completion,
        inventory_cache_status: outcome.inventory_cache_status,
        navigation: outcome.navigation,
        inventory_cache_publication: outcome.inventory_cache_publication,
    })
}

fn checkpoint(control: &OperationBudget, location: &str) -> Result<(), AppError> {
    control
        .checkpoint()
        .map(|_| ())
        .map_err(|error| map_operation_control_error(error, location))
}

/// Publishes a retained cache candidate only after the caller's authoritative write succeeded.
///
/// The shared cache is an optimization, so an unavailable or colliding entry does not change the
/// already-completed operation's result.
pub(crate) fn publish_inventory_cache_after_state_write(detected: &DetectedProject) {
    let Some(publication) = detected.inventory_cache_publication.as_ref() else {
        return;
    };
    let layout = GitStateLayout::new(
        &detected.model.repository.git_dir,
        &detected.model.repository.git_common_dir,
    );
    let Ok(store) = SharedCacheStore::new(&layout) else {
        return;
    };
    let cache = SharedInventoryCache { store };
    let _ignored = publish_cached_inventory(&cache, publication);
}

/// Validates every command that `forge explain` exposes, then performs the full model projection.
pub(crate) fn project_for_output(model: &ProjectModel) -> Result<ProjectModelData, AppError> {
    for command_set in model.commands.values() {
        for command in command_set.commands() {
            validate_command_privacy(command).map_err(|_| command_privacy_error())?;
        }
    }
    project_model_to_wire(model).map_err(map_projection_error)
}

pub(crate) fn command_privacy_error() -> AppError {
    AppError::data(
        "FGE1103",
        "project command metadata cannot be displayed safely",
        "project command",
        "a project command contains credential-like metadata",
        "remove credentials from project command metadata and provide them through an approved runtime secret mechanism",
    )
}

pub(crate) const fn inventory_cache_status_name(status: InventoryCacheStatus) -> &'static str {
    match status {
        InventoryCacheStatus::Disabled => "disabled",
        InventoryCacheStatus::Ineligible => "ineligible",
        InventoryCacheStatus::Miss => "miss",
        InventoryCacheStatus::Hit => "hit",
    }
}

fn parse_duration(value: &str) -> Result<Duration, AppError> {
    let (digits, multiplier) = if let Some(digits) = value.strip_suffix("ms") {
        (digits, 1_u64)
    } else if let Some(digits) = value.strip_suffix('s') {
        (digits, 1_000_u64)
    } else if let Some(digits) = value.strip_suffix('m') {
        (digits, 60_000_u64)
    } else if let Some(digits) = value.strip_suffix('h') {
        (digits, 3_600_000_u64)
    } else {
        return Err(invalid_duration(value));
    };
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid_duration(value));
    }
    let amount = digits
        .parse::<u64>()
        .ok()
        .and_then(|amount| amount.checked_mul(multiplier))
        .filter(|amount| *amount > 0)
        .ok_or_else(|| invalid_duration(value))?;
    Ok(Duration::from_millis(amount))
}

pub(crate) fn operation_timeout(cli: &Cli) -> Result<Option<Duration>, AppError> {
    cli.timeout.as_deref().map(parse_duration).transpose()
}

fn invalid_duration(value: &str) -> AppError {
    AppError::usage(
        "FGE1002",
        "the operation timeout is invalid",
        "--timeout",
        format!("`{value}` is not a positive bounded duration"),
        "use an integer followed by `ms`, `s`, `m`, or `h`, for example `90s`",
    )
}

fn map_detection_error(error: ModelDetectionError) -> AppError {
    match error {
        ModelDetectionError::Control(error) => {
            map_operation_control_error(error, "project detection")
        }
        ModelDetectionError::Repository(error) => map_git_error(
            error.source_error(),
            "repository detection",
            error.to_string(),
        ),
        ModelDetectionError::GitInventory(error) => {
            let detail = error.to_string();
            map_git_error(&error, "Git repository inventory", detail)
        }
        ModelDetectionError::Inventory(InventoryError::Git(error)) => {
            let detail = error.to_string();
            map_git_error(&error, "repository inventory", detail)
        }
        ModelDetectionError::Inventory(InventoryError::Control(error)) => {
            map_operation_control_error(error, "repository inventory")
        }
        ModelDetectionError::Inventory(InventoryError::EntryLimit {
            max_entries,
            observed,
        }) => AppError::new(
            ExitCode::Timeout,
            Diagnostic::new(
                "FGE1003",
                Severity::Error,
                "repository detection exceeded its bounded inventory capacity",
                "repository inventory",
                format!(
                    "the inventory observed {observed} entries, above the {max_entries}-entry bound"
                ),
                format!(
                    "narrow generated or vendored content through the project's standard ignore files, then rerun `{CLI_NAME} explain`"
                ),
            ),
        ),
        ModelDetectionError::Inventory(error) => AppError::environment_unmet(
            "FGE1004",
            "repository inventory could not be read safely",
            "repository inventory",
            error.to_string(),
            format!(
                "fix the repository path, permissions, or symlink boundary, then rerun `{CLI_NAME} explain`"
            ),
        ),
        ModelDetectionError::Config(ConfigError::Load {
            reason:
                ConfigLoadError::ReadFailed {
                    kind: io::ErrorKind::TimedOut,
                },
        }) => {
            map_operation_control_error(OperationControlError::TimedOut, "repository configuration")
        }
        ModelDetectionError::Config(ConfigError::Load {
            reason:
                ConfigLoadError::ReadFailed {
                    kind: io::ErrorKind::Interrupted,
                },
        }) => map_operation_control_error(
            OperationControlError::Interrupted,
            "repository configuration",
        ),
        ModelDetectionError::Config(error) => AppError::data(
            "FGE1101",
            format!("{CLI_NAME} configuration is invalid or unreadable"),
            CONFIG_FILE,
            error.to_string(),
            format!(
                "correct or remove the selected configuration, then rerun `{CLI_NAME} explain`"
            ),
        ),
        ModelDetectionError::Policy(error) => AppError::internal(
            "FGE0009",
            "the effective policy could not be assembled",
            "effective policy",
            error.to_string(),
            "report this as a Forge implementation defect",
        ),
        ModelDetectionError::RustProvider(error) => internal_detection_error(error.to_string()),
        ModelDetectionError::GoProvider(error) => internal_detection_error(error.to_string()),
        ModelDetectionError::Assets(error) => internal_detection_error(error.to_string()),
        ModelDetectionError::InvalidInventoryPath { path, source } => {
            internal_detection_error(format!("invalid inventory path {path:?}: {source}"))
        }
        ModelDetectionError::CommandResolution(error) => {
            internal_detection_error(error.to_string())
        }
        ModelDetectionError::InvalidModel(error) => internal_detection_error(error.to_string()),
    }
}

pub(crate) fn map_operation_control_error(
    error: OperationControlError,
    location: &str,
) -> AppError {
    match error {
        OperationControlError::TimedOut => AppError::new(
            ExitCode::Timeout,
            Diagnostic::new(
                "FGE2004",
                Severity::Error,
                "Forge operation timed out",
                location,
                error.to_string(),
                "increase `--timeout` or reduce the requested operation scope, then retry",
            ),
        ),
        OperationControlError::Interrupted => AppError::new(
            ExitCode::Interrupted,
            Diagnostic::new(
                "FGE2005",
                Severity::Error,
                "Forge operation was interrupted",
                location,
                error.to_string(),
                "rerun the command when ready",
            ),
        ),
    }
}

fn map_process_setup_error(error: ProcessError) -> AppError {
    AppError::environment_unmet(
        "FGE2002",
        "the bounded metadata process runner could not be initialized",
        "repository process boundary",
        error.to_string(),
        format!(
            "ensure the repository root is a readable real directory, then rerun `{CLI_NAME} explain`"
        ),
    )
}

fn map_git_error(error: &GitError, location: &str, detail: String) -> AppError {
    match error.kind() {
        GitErrorKind::TimedOut => AppError::new(
            ExitCode::Timeout,
            Diagnostic::new(
                "FGE2004",
                Severity::Error,
                "Git inspection timed out",
                location,
                detail,
                format!(
                    "increase `--timeout` or make the repository available, then rerun `{CLI_NAME} explain`"
                ),
            ),
        ),
        GitErrorKind::Interrupted => AppError::new(
            ExitCode::Interrupted,
            Diagnostic::new(
                "FGE2005",
                Severity::Error,
                "Git inspection was interrupted",
                location,
                detail,
                format!("rerun `{CLI_NAME} explain` when ready"),
            ),
        ),
        GitErrorKind::OutputLimit => AppError::new(
            ExitCode::Timeout,
            Diagnostic::new(
                "FGE2006",
                Severity::Error,
                "Git inspection exceeded a bounded output limit",
                location,
                detail,
                "reduce generated repository state or split the repository before retrying",
            ),
        ),
        GitErrorKind::ExecutableUnavailable
        | GitErrorKind::UnsafeEnvironment
        | GitErrorKind::NotRepository
        | GitErrorKind::CorruptRepository
        | GitErrorKind::InvalidData
        | GitErrorKind::CommandFailed
        | GitErrorKind::Io => AppError::environment_unmet(
            "FGE2001",
            "Git repository inspection could not complete",
            location,
            detail,
            format!(
                "ensure Git is installed and the selected directory is a readable repository, then rerun `{CLI_NAME} explain`"
            ),
        ),
    }
}

fn internal_detection_error(detail: String) -> AppError {
    AppError::internal(
        "FGE0009",
        "project-model detection violated an internal invariant",
        "project model",
        detail,
        format!(
            "report this as a {CLI_NAME} implementation defect with the command and repository shape"
        ),
    )
}

pub(crate) fn map_projection_error(error: ProjectModelWireError) -> AppError {
    match error {
        ProjectModelWireError::InvalidModel(error) => internal_detection_error(error.to_string()),
        error => AppError::data(
            "FGE1102",
            "the detected project model cannot be represented losslessly",
            SchemaKind::ProjectModel.id(),
            error.to_string(),
            format!(
                "use UTF-8 command names and integral-second timeouts, then rerun `{CLI_NAME} explain`"
            ),
        ),
    }
}

/// Renders the same structured model used by JSON output without rescanning the repository.
pub(crate) fn render_human(model: &ProjectModelData) -> String {
    let mut output = String::new();
    let repository_confidence = model
        .repository_evidence
        .as_ref()
        .map_or("unknown", |evidence| confidence_name(evidence.confidence));
    let _ = writeln!(output, "repository: {}", model.repository.as_str());
    let _ = writeln!(output, "root: {}", model.repository_root.display);
    let _ = writeln!(output, "work state: {}", model.work_state);
    let _ = writeln!(output, "repository confidence: {repository_confidence}");
    if let Some(evidence) = &model.repository_evidence {
        render_provenance(&mut output, "repository source", &evidence.provenance);
    }

    let _ = writeln!(output, "units: {}", model.units.len());
    for unit in &model.units {
        let _ = writeln!(
            output,
            "  - {} [{} {}] at {}",
            unit.display_name, unit.language, unit.kind, unit.root.display
        );
    }

    output.push_str("commands:\n");
    if let Some(command_sets) = &model.command_sets {
        for (intent, command_set) in command_sets {
            let _ = writeln!(
                output,
                "  {intent}: {} (resolution {}, coverage {})",
                resolution_name(command_set.resolution),
                confidence_name(command_set.resolution_confidence),
                confidence_name(command_set.coverage_confidence),
            );
            for candidate in &command_set.candidates {
                let _ = writeln!(
                    output,
                    "    - {:?} {:?} (cwd {}, source {})",
                    candidate.command.program,
                    candidate.command.args,
                    candidate.command.cwd.display,
                    candidate.command.source,
                );
            }
            render_provenance(&mut output, "    source", &command_set.provenance);
        }
    }

    let _ = writeln!(output, "assets: {}", model.assets.len());
    for asset in &model.assets {
        let _ = writeln!(output, "  - {}: {}", asset.kind, asset.path.display);
    }
    let _ = writeln!(output, "adapters: {}", model.adapters.len());
    for adapter in &model.adapters {
        let _ = writeln!(output, "  - {}: {}", adapter.host, adapter.path.display);
    }
    let policy_confidence = model
        .policy_evidence
        .as_ref()
        .map_or("unknown", |evidence| confidence_name(evidence.confidence));
    let _ = writeln!(
        output,
        "policy: {} (confidence {policy_confidence})",
        model
            .policy_digest
            .as_ref()
            .map_or("unknown", |digest| digest.as_str()),
    );
    let assumptions = model
        .assumptions
        .iter()
        .map(|assumption| {
            (
                confidence_name(assumption.confidence),
                assumption.statement.as_str(),
            )
        })
        .collect::<BTreeSet<_>>();
    if assumptions.len() != model.assumptions.len() {
        let _ = writeln!(
            output,
            "assumptions: {} distinct ({} source observations)",
            assumptions.len(),
            model.assumptions.len(),
        );
    }
    for (confidence, statement) in assumptions {
        let _ = writeln!(output, "assumption [{}]: {}", confidence, statement);
    }
    for diagnostic in &model.diagnostics {
        let _ = writeln!(output, "\n{diagnostic}");
    }
    output
}

fn render_provenance(output: &mut String, label: &str, provenance: &[ProvenanceData]) {
    for source in provenance {
        let _ = writeln!(output, "{label}: {} — {}", source.rule_id, source.detail);
    }
}

const fn confidence_name(confidence: ConfidenceData) -> &'static str {
    match confidence {
        ConfidenceData::High => "high",
        ConfidenceData::Medium => "medium",
        ConfidenceData::Low => "low",
        ConfidenceData::Unknown => "unknown",
        _ => "unknown",
    }
}

const fn resolution_name(resolution: CommandResolutionData) -> &'static str {
    match resolution {
        CommandResolutionData::Resolved => "resolved",
        CommandResolutionData::Absent => "absent",
        CommandResolutionData::Ambiguous => "ambiguous",
        CommandResolutionData::Unknown => "unknown",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::time::Duration;

    use forge_core::{
        AdapterInventory, AppError, AssetInventory, CommandSource, CommandSpec, Confidence,
        EffectivePolicy, ExitCode, Intent, ProjectModel, ProjectModelInputs, Provenance, RepoFacts,
        RepoRelativePath, ResolvedCommandSet, WorkState, project_model_to_wire,
    };
    use forge_schema::RepoId;

    use super::{parse_duration, project_for_output};

    fn provenance(rule_id: &str) -> Provenance {
        Provenance {
            rule_id: rule_id.to_owned(),
            source_path: None,
            source_range: None,
            detail: String::from("test evidence"),
        }
    }

    fn model_with_check_command(
        command: CommandSpec,
    ) -> Result<ProjectModel, Box<dyn std::error::Error>> {
        let evidence = || vec![provenance("test.fixture")];
        let mut model = ProjectModel::new(ProjectModelInputs {
            repository: RepoFacts {
                id: RepoId::from("local:blake3:explain-privacy-test"),
                root: PathBuf::from("/repo"),
                git_dir: PathBuf::from("/repo/.git"),
                git_common_dir: PathBuf::from("/repo/.git"),
                is_linked_worktree: false,
                head: None,
                branch: None,
                upstream: None,
                work_state: WorkState::Clean,
            },
            repository_provenance: evidence(),
            repository_confidence: Confidence::High,
            unit_inventory_provenance: evidence(),
            unit_inventory_confidence: Confidence::High,
            assets: AssetInventory::new(Vec::new(), evidence(), Confidence::High),
            adapters: AdapterInventory::new(Vec::new(), evidence(), Confidence::High),
            policy: EffectivePolicy::new(None, evidence(), Confidence::High),
        });
        for intent in Intent::ALL {
            model.commands.insert(
                intent,
                ResolvedCommandSet::absent(evidence(), Confidence::High),
            );
        }
        model.commands.insert(
            Intent::Check,
            ResolvedCommandSet::resolved(
                vec![command],
                evidence(),
                Confidence::High,
                Confidence::High,
            )?,
        );
        Ok(model)
    }

    fn check_command() -> CommandSpec {
        CommandSpec::new(
            "check",
            Intent::Check,
            "cargo",
            RepoRelativePath::root(),
            CommandSource::ExplicitConfig,
        )
        .with_args(["check"])
    }

    #[test]
    fn duration_parser_accepts_explicit_positive_units() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(parse_duration("250ms")?, Duration::from_millis(250));
        assert_eq!(parse_duration("90s")?, Duration::from_secs(90));
        assert_eq!(parse_duration("2m")?, Duration::from_secs(120));
        assert_eq!(parse_duration("1h")?, Duration::from_secs(3_600));
        Ok(())
    }

    #[test]
    fn duration_parser_rejects_ambiguous_zero_fractional_and_overflow_values() {
        for invalid in ["", "0s", "1", "1.5s", "-1s", "18446744073709551615h"] {
            let error = parse_duration(invalid).err();
            assert!(error.is_some(), "accepted invalid duration {invalid:?}");
            assert_eq!(
                error.as_ref().map(AppError::exit_code),
                Some(ExitCode::Usage)
            );
        }
    }

    #[test]
    fn explain_preserves_safe_projection_bytes_and_benign_environment_names()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut command = check_command();
        command
            .env
            .insert(OsString::from("AUTHOR"), OsString::from("Ada"));
        command
            .env
            .insert(OsString::from("BUILD_REGION"), OsString::from("us-east-1"));
        let model = model_with_check_command(command)?;

        let expected = project_model_to_wire(&model)?;
        let projected = project_for_output(&model)?;

        assert_eq!(
            serde_json::to_vec(&projected)?,
            serde_json::to_vec(&expected)?
        );
        assert_eq!(
            projected.commands["check"][0].environment_names,
            ["AUTHOR", "BUILD_REGION"]
        );
        Ok(())
    }

    #[test]
    fn explain_rejects_unsafe_commands_without_rendering_secret_metadata()
    -> Result<(), Box<dyn std::error::Error>> {
        let secret = "explain-secret-sentinel";
        let argument_command = check_command().with_args(["check", "--token", secret]);
        let mut environment_command = check_command();
        environment_command
            .env
            .insert(OsString::from("API_TOKEN"), OsString::from(secret));

        for (command, forbidden) in [
            (argument_command, vec![secret, "--token"]),
            (environment_command, vec![secret, "API_TOKEN"]),
        ] {
            let error = project_for_output(&model_with_check_command(command)?)
                .err()
                .ok_or_else(|| {
                    std::io::Error::other("unsafe explain command did not fail closed")
                })?;
            assert_eq!(error.diagnostic().code.as_str(), "FGE1103");
            let rendered = [
                error.to_string(),
                serde_json::to_string(error.diagnostic())?,
                format!("{error:?}"),
            ];
            for output in rendered {
                for value in &forbidden {
                    assert!(!output.contains(value), "leaked {value:?}: {output}");
                }
            }
        }
        Ok(())
    }
}
