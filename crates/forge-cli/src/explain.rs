//! Read-only CLI composition for generic project-model detection and explanation.

use std::fmt::Write as _;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use forge_core::branding::{CLI_NAME, CONFIG_FILE};
use forge_core::ports::{GitPort as _, ProcessError};
use forge_core::{
    AppError, ExitCode, GitError, GitErrorKind, InventoryError, ProjectModel,
    ProjectModelWireError, RepoRelativePath, project_model_to_wire,
};
use forge_detect::model::{
    ModelDetectionCompletion, ModelDetectionError, ModelDetectionOptions, detect_project_model,
};
use forge_runtime::fs::NativeFileSystem;
use forge_runtime::git::GitCli;
use forge_runtime::hash::Blake3Hasher;
use forge_runtime::process::SynchronousProcessRunner;
use forge_schema::{
    CommandResolutionData, ConfidenceData, Diagnostic, ProjectModelData, ProvenanceData,
    SchemaKind, Severity,
};

use crate::args::Cli;

/// One repository scan retained in both its domain and public wire forms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DetectedProject {
    pub(crate) model: ProjectModel,
    pub(crate) wire: ProjectModelData,
    pub(crate) completion: ModelDetectionCompletion,
}

/// Detects and projects the model used by both human and JSON explain output.
pub(crate) fn detect(
    cli: &Cli,
    cancellation: Arc<AtomicBool>,
) -> Result<DetectedProject, AppError> {
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
    let timeout = cli.timeout.as_deref().map(parse_duration).transpose()?;
    let git = timeout
        .map_or_else(GitCli::new, |timeout| GitCli::new().with_timeout(timeout))
        .with_cancellation_flag(Arc::clone(&cancellation));
    let repository_root = git.repository_root(start).map_err(|error| {
        let detail = error.to_string();
        map_git_error(&error, "repository root", detail)
    })?;
    let process = SynchronousProcessRunner::new(&repository_root)
        .map_err(map_process_setup_error)?
        .with_cancellation_flag(cancellation);
    let filesystem = NativeFileSystem;
    let hasher = Blake3Hasher;
    let default_options = ModelDetectionOptions::default();
    let outcome = detect_project_model(
        &repository_root,
        &git,
        &filesystem,
        &process,
        &hasher,
        &ModelDetectionOptions {
            config_path,
            metadata_timeout: timeout.unwrap_or(default_options.metadata_timeout),
            ..default_options
        },
    )
    .map_err(map_detection_error)?;
    let wire = project_model_to_wire(&outcome.model).map_err(map_projection_error)?;

    Ok(DetectedProject {
        model: outcome.model,
        wire,
        completion: outcome.completion,
    })
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
        ModelDetectionError::Config(error) => AppError::data(
            "FGE1101",
            format!("{CLI_NAME} configuration is invalid or unreadable"),
            CONFIG_FILE,
            error.to_string(),
            format!(
                "correct or remove the selected configuration, then rerun `{CLI_NAME} explain`"
            ),
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

fn map_projection_error(error: ProjectModelWireError) -> AppError {
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
    for assumption in &model.assumptions {
        let _ = writeln!(
            output,
            "assumption [{}]: {}",
            confidence_name(assumption.confidence),
            assumption.statement
        );
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
    use std::time::Duration;

    use forge_core::{AppError, ExitCode};

    use super::parse_duration;

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
}
