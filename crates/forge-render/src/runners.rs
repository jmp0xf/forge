//! Explicit, deterministic project-runner rendering.
//!
//! A generated runner is a project-native interface, not a wrapper around Forge. The v0 surface
//! intentionally adds only `verify`: it composes already-resolved, required read/check/test/build
//! commands while leaving every narrower project command at its existing native entrypoint.

use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::{Component, Path};

use forge_core::RepoRelativePath;
use forge_core::domain::{
    AssetInfo, CommandEnforcement, CommandResolution, CommandSource, CommandSpec, Confidence,
    Intent, ProjectModel, Provenance, ResolvedCommandSet,
};
use forge_core::fingerprint::{is_secret_like_name, validate_argv_privacy};

use crate::managed_block::contains_managed_marker_token;

const VERIFY_INTENTS: [Intent; 4] = [
    Intent::FormatCheck,
    Intent::Check,
    Intent::Test,
    Intent::Build,
];

/// One explicitly selected v0 project runner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunnerTarget {
    Make,
    Just,
    Task,
}

impl RunnerTarget {
    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            Self::Make => "Makefile",
            Self::Just => "justfile",
            Self::Task => "Taskfile.yml",
        }
    }

    #[must_use]
    pub const fn program(self) -> &'static str {
        match self {
            Self::Make => "make",
            Self::Just => "just",
            Self::Task => "task",
        }
    }

    const fn file_option(self) -> &'static str {
        match self {
            Self::Make => "--file",
            Self::Just => "--justfile",
            Self::Task => "--taskfile",
        }
    }

    const fn asset_kind(self) -> &'static str {
        match self {
            Self::Make => "runner.make",
            Self::Just => "runner.just",
            Self::Task => "runner.task",
        }
    }

    // Make and Just bodies use POSIX shell quoting and `env`; Task is the portable v0 Windows
    // projection. Keep this check shared by rendering and model projection so they cannot diverge.
    const fn is_supported_on_current_platform(self) -> bool {
        #[cfg(windows)]
        {
            matches!(self, Self::Task)
        }
        #[cfg(not(windows))]
        {
            true
        }
    }
}

/// A runner command cannot be represented without changing its argv or leaking host state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunnerRenderError {
    NoRequiredCommands,
    NonUtf8 {
        command_id: String,
        field: &'static str,
    },
    UnsafeText {
        command_id: String,
        field: &'static str,
    },
    InvalidEnvironmentName {
        command_id: String,
    },
    SecretLikeEnvironment {
        command_id: String,
    },
    SecretLikeArgument {
        command_id: String,
    },
    HostSpecificValue {
        command_id: String,
        field: &'static str,
    },
    InvalidProjectedModel(String),
    UnsupportedPlatform {
        runner: RunnerTarget,
    },
}

impl fmt::Display for RunnerRenderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRequiredCommands => formatter.write_str(
                "no resolved required format-check, check, test, or build command can back a verify target",
            ),
            Self::NonUtf8 { command_id, field } => write!(
                formatter,
                "command `{command_id}` has a non-UTF-8 {field} that cannot be rendered losslessly"
            ),
            Self::UnsafeText { command_id, field } => write!(
                formatter,
                "command `{command_id}` has control, template, or managed-marker text in {field}"
            ),
            Self::InvalidEnvironmentName { command_id } => write!(
                formatter,
                "command `{command_id}` has an environment name outside the portable identifier syntax"
            ),
            Self::SecretLikeEnvironment { command_id } => write!(
                formatter,
                "command `{command_id}` has a secret-like environment name that cannot be persisted in a runner"
            ),
            Self::SecretLikeArgument { command_id } => write!(
                formatter,
                "command `{command_id}` has a secret-like argument that cannot be persisted in a runner"
            ),
            Self::HostSpecificValue { command_id, field } => write!(
                formatter,
                "command `{command_id}` has a host-specific absolute value in {field}"
            ),
            Self::InvalidProjectedModel(detail) => {
                write!(formatter, "projected runner model is invalid: {detail}")
            }
            Self::UnsupportedPlatform { runner } => write!(
                formatter,
                "the explicit `{}` runner recipe is not portable on this platform",
                runner.program()
            ),
        }
    }
}

impl Error for RunnerRenderError {}

/// Renders the selected runner without executing or interpreting any project command.
pub fn render_runner_body(
    model: &ProjectModel,
    runner: RunnerTarget,
) -> Result<String, RunnerRenderError> {
    if !runner.is_supported_on_current_platform() {
        return Err(RunnerRenderError::UnsupportedPlatform { runner });
    }

    let commands = required_verify_commands(model);
    if commands.is_empty() {
        return Err(RunnerRenderError::NoRequiredCommands);
    }
    match runner {
        RunnerTarget::Make => render_make(model, &commands),
        RunnerTarget::Just => render_just(model, &commands),
        RunnerTarget::Task => render_task(model, &commands),
    }
}

/// Projects the runner asset and its canonical `verify` command before adapters are rendered.
///
/// The real post-apply detector will observe the same path, argv, source, and confidence. This
/// keeps `AGENTS.md` stable across the write/post-check boundary without mutating detection state.
pub fn project_runner_model(
    model: &ProjectModel,
    runner: RunnerTarget,
) -> Result<ProjectModel, RunnerRenderError> {
    if !runner.is_supported_on_current_platform() {
        return Err(RunnerRenderError::UnsupportedPlatform { runner });
    }
    let mut projected = model.clone();
    let path = RepoRelativePath::new(runner.path())
        .map_err(|error| RunnerRenderError::InvalidProjectedModel(error.to_string()))?;
    if !projected
        .assets
        .entries
        .iter()
        .any(|asset| asset.kind == runner.asset_kind() && asset.path == path)
    {
        projected.assets.entries.push(AssetInfo::new(
            runner.asset_kind(),
            path.clone(),
            vec![runner_provenance(
                runner,
                "the explicitly selected runner will exist after the reviewed init plan",
            )],
            Confidence::Medium,
        ));
    }

    let mut command = CommandSpec::new(
        format!("runner.{}.generated.verify", runner.program()),
        Intent::Verify,
        runner.program(),
        RepoRelativePath::root(),
        CommandSource::ExistingProjectTarget {
            path: path.clone(),
            target: String::from("verify"),
        },
    )
    .with_args([
        OsString::from(runner.file_option()),
        path.as_path().as_os_str().to_os_string(),
        OsString::from("verify"),
    ]);
    command.confidence = Confidence::Medium;
    let resolved = ResolvedCommandSet::resolved(
        vec![command],
        vec![runner_provenance(
            runner,
            "the generated literal verify target is statically callable",
        )],
        Confidence::Medium,
        Confidence::Unknown,
    )
    .map_err(|error| RunnerRenderError::InvalidProjectedModel(error.to_string()))?;
    projected.commands.insert(Intent::Verify, resolved);
    projected
        .finalize()
        .map_err(|error| RunnerRenderError::InvalidProjectedModel(error.to_string()))
}

pub(crate) fn required_verify_commands(model: &ProjectModel) -> Vec<&CommandSpec> {
    let mut commands = Vec::new();
    for intent in VERIFY_INTENTS {
        let Some(command_set) = model.commands.get(&intent) else {
            continue;
        };
        if command_set.resolution() != CommandResolution::Resolved
            || !publishable(command_set.resolution_confidence)
        {
            continue;
        }
        let Some(resolved) = command_set.executable_commands() else {
            continue;
        };
        commands.extend(resolved.iter().filter(|command| {
            command.enforcement == CommandEnforcement::Required && publishable(command.confidence)
        }));
    }
    commands
}

/// Renders one required project command for the POSIX shell used by the generated GitHub job.
///
/// GitHub expressions also use double braces, so the Just dialect's existing text validation is
/// the conservative shared subset: it rejects both template injection and values that cannot be
/// represented losslessly in the workflow's shell command.
pub(crate) fn render_github_actions_shell_command(
    model: &ProjectModel,
    command: &CommandSpec,
) -> Result<String, RunnerRenderError> {
    render_shell_command(model, command, RunnerTarget::Just)
}

fn render_make(
    model: &ProjectModel,
    commands: &[&CommandSpec],
) -> Result<String, RunnerRenderError> {
    let mut output = String::from(".PHONY: verify\nverify:");
    for command in commands {
        let line = render_shell_command(model, command, RunnerTarget::Make)?;
        output.push_str("\n\t");
        output.push_str(&line.replace('$', "$$"));
    }
    Ok(output)
}

fn render_just(
    model: &ProjectModel,
    commands: &[&CommandSpec],
) -> Result<String, RunnerRenderError> {
    let mut output = String::from("verify:");
    for command in commands {
        output.push_str("\n    ");
        output.push_str(&render_shell_command(model, command, RunnerTarget::Just)?);
    }
    Ok(output)
}

fn render_task(
    model: &ProjectModel,
    commands: &[&CommandSpec],
) -> Result<String, RunnerRenderError> {
    let mut output = String::from("version: 3\n\ntasks:\n  verify:\n    cmds:");
    for command in commands {
        let command_id = command.id.as_str();
        let argv = render_argv(command, RunnerTarget::Task)?;
        output.push_str("\n      - cmd: ");
        output.push_str(&yaml_string(&argv));
        if command.cwd != RepoRelativePath::root() {
            let cwd = safe_path_text(command, command.cwd.as_path(), RunnerTarget::Task, "cwd")?;
            output.push_str("\n        dir: ");
            output.push_str(&yaml_string(cwd));
        }
        if !command.env.is_empty() {
            output.push_str("\n        env:");
            for (name, value) in &command.env {
                let name = environment_name(command_id, name)?;
                let value = environment_value(model, command, name, value, RunnerTarget::Task)?;
                output.push_str("\n          ");
                output.push_str(name);
                output.push_str(": ");
                output.push_str(&yaml_string(&value));
            }
        }
    }
    Ok(output)
}

fn render_shell_command(
    model: &ProjectModel,
    command: &CommandSpec,
    runner: RunnerTarget,
) -> Result<String, RunnerRenderError> {
    let mut output = String::new();
    if command.cwd != RepoRelativePath::root() {
        let cwd = safe_path_text(command, command.cwd.as_path(), runner, "cwd")?;
        output.push_str("cd ");
        output.push_str(&shell_word(cwd));
        output.push_str(" && ");
    }
    if !command.env.is_empty() {
        output.push_str("env");
        for (name, value) in &command.env {
            let name = environment_name(command.id.as_str(), name)?;
            let value = environment_value(model, command, name, value, runner)?;
            output.push(' ');
            output.push_str(&shell_word(&format!("{name}={value}")));
        }
        output.push(' ');
    }
    output.push_str(&render_argv(command, runner)?);
    Ok(output)
}

fn render_argv(command: &CommandSpec, runner: RunnerTarget) -> Result<String, RunnerRenderError> {
    validate_argv_privacy(std::iter::once(&command.program).chain(command.args.iter())).map_err(
        |_| RunnerRenderError::SecretLikeArgument {
            command_id: command.id.as_str().to_owned(),
        },
    )?;
    let mut words = Vec::with_capacity(command.args.len() + 1);
    words.push(shell_word(safe_os_text(
        command,
        &command.program,
        runner,
        "program",
    )?));
    for argument in &command.args {
        words.push(shell_word(safe_os_text(
            command, argument, runner, "argument",
        )?));
    }
    Ok(words.join(" "))
}

fn environment_name<'a>(command_id: &str, name: &'a OsStr) -> Result<&'a str, RunnerRenderError> {
    let Some(name) = name.to_str() else {
        return Err(RunnerRenderError::NonUtf8 {
            command_id: command_id.to_owned(),
            field: "environment name",
        });
    };
    let mut bytes = name.bytes();
    let valid = bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric());
    if valid {
        if is_secret_like_name(name) {
            Err(RunnerRenderError::SecretLikeEnvironment {
                command_id: command_id.to_owned(),
            })
        } else {
            Ok(name)
        }
    } else {
        Err(RunnerRenderError::InvalidEnvironmentName {
            command_id: command_id.to_owned(),
        })
    }
}

fn environment_value(
    model: &ProjectModel,
    command: &CommandSpec,
    name: &str,
    value: &OsStr,
    runner: RunnerTarget,
) -> Result<String, RunnerRenderError> {
    let value = safe_os_text(command, value, runner, "environment value")?;
    if name == "GOWORK" {
        let path = Path::new(value);
        if path.is_absolute() {
            let relative = path.strip_prefix(&model.repository.root).map_err(|_| {
                RunnerRenderError::HostSpecificValue {
                    command_id: command.id.as_str().to_owned(),
                    field: "GOWORK",
                }
            })?;
            return relative_from(command.cwd.as_path(), relative).ok_or_else(|| {
                RunnerRenderError::HostSpecificValue {
                    command_id: command.id.as_str().to_owned(),
                    field: "GOWORK",
                }
            });
        }
    }
    if looks_host_specific(value) {
        return Err(RunnerRenderError::HostSpecificValue {
            command_id: command.id.as_str().to_owned(),
            field: "environment value",
        });
    }
    Ok(value.to_owned())
}

fn relative_from(cwd: &Path, target: &Path) -> Option<String> {
    if target.is_absolute()
        || cwd.is_absolute()
        || target
            .components()
            .any(|part| matches!(part, Component::ParentDir))
        || cwd
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return None;
    }
    let depth = cwd
        .components()
        .filter(|part| matches!(part, Component::Normal(_)))
        .count();
    let mut relative = Path::new("").to_path_buf();
    for _ in 0..depth {
        relative.push("..");
    }
    relative.push(target);
    let text = relative.to_str()?;
    Some(if text.is_empty() {
        String::from(".")
    } else {
        text.to_owned()
    })
}

fn safe_path_text<'a>(
    command: &CommandSpec,
    path: &'a Path,
    runner: RunnerTarget,
    field: &'static str,
) -> Result<&'a str, RunnerRenderError> {
    if path.is_absolute() {
        return Err(RunnerRenderError::HostSpecificValue {
            command_id: command.id.as_str().to_owned(),
            field,
        });
    }
    safe_text(command.id.as_str(), path.to_str(), runner, field)
}

fn safe_os_text<'a>(
    command: &CommandSpec,
    value: &'a OsStr,
    runner: RunnerTarget,
    field: &'static str,
) -> Result<&'a str, RunnerRenderError> {
    safe_text(command.id.as_str(), value.to_str(), runner, field)
}

fn safe_text<'a>(
    command_id: &str,
    value: Option<&'a str>,
    runner: RunnerTarget,
    field: &'static str,
) -> Result<&'a str, RunnerRenderError> {
    let Some(value) = value else {
        return Err(RunnerRenderError::NonUtf8 {
            command_id: command_id.to_owned(),
            field,
        });
    };
    if value.is_empty()
        || value.chars().any(char::is_control)
        || contains_managed_marker_token(value)
        || (matches!(runner, RunnerTarget::Just | RunnerTarget::Task)
            && (value.contains("{{") || value.contains("}}")))
    {
        return Err(RunnerRenderError::UnsafeText {
            command_id: command_id.to_owned(),
            field,
        });
    }
    if looks_host_specific(value) {
        return Err(RunnerRenderError::HostSpecificValue {
            command_id: command_id.to_owned(),
            field,
        });
    }
    Ok(value)
}

fn looks_host_specific(value: &str) -> bool {
    absolute_path_payload(value)
        || value.contains("/Users/")
        || value.contains("/home/")
        || value.contains("\\Users\\")
        || value.contains("$HOME")
        || value.contains("${HOME}")
        || value.contains("%USERPROFILE%")
        || value.strip_prefix('@').is_some_and(absolute_path_payload)
        || value
            .split_once('=')
            .is_some_and(|(_, payload)| absolute_path_payload(payload))
        || ["-I", "-L", "-F"].iter().any(|prefix| {
            value
                .strip_prefix(prefix)
                .is_some_and(absolute_path_payload)
        })
}

fn absolute_path_payload(value: &str) -> bool {
    let value = value.strip_prefix('@').unwrap_or(value);
    let bytes = value.as_bytes();
    value.starts_with('~')
        || value.starts_with('/')
        || value
            .get(..5)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("file:"))
        || (bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes[2], b'/' | b'\\'))
}

fn shell_word(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn yaml_string(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

const fn publishable(confidence: Confidence) -> bool {
    matches!(confidence, Confidence::Medium | Confidence::High)
}

fn runner_provenance(runner: RunnerTarget, detail: &str) -> Provenance {
    Provenance {
        rule_id: String::from("init.runner.explicit-opt-in.v1"),
        source_path: Some(Path::new(runner.path()).into()),
        source_range: None,
        detail: detail.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::error::Error;
    use std::ffi::OsString;
    use std::io;
    use std::path::{Path, PathBuf};

    use forge_core::domain::{
        AdapterInventory, AssetInventory, CommandSource, CommandSpec, Confidence, EffectivePolicy,
        Intent, ProjectModel, ProjectModelInputs, RepoFacts, WorkState,
    };
    use forge_core::{RepoId, RepoRelativePath, ResolvedCommandSet};

    use super::{
        RunnerRenderError, RunnerTarget, project_runner_model, render_runner_body,
        runner_provenance, safe_text,
    };

    #[cfg(not(windows))]
    const SUPPORTED_RUNNERS: [RunnerTarget; 3] =
        [RunnerTarget::Make, RunnerTarget::Just, RunnerTarget::Task];
    #[cfg(windows)]
    const SUPPORTED_RUNNERS: [RunnerTarget; 1] = [RunnerTarget::Task];

    fn model() -> Result<ProjectModel, Box<dyn Error>> {
        let repository = RepoFacts {
            id: RepoId::from("local:runner"),
            root: PathBuf::from("/repo"),
            git_dir: PathBuf::from("/repo/.git"),
            git_common_dir: PathBuf::from("/repo/.git"),
            is_linked_worktree: false,
            head: None,
            branch: None,
            upstream: None,
            work_state: WorkState::Clean,
        };
        let provenance = vec![runner_provenance(RunnerTarget::Make, "fixture")];
        let mut model = ProjectModel::new(ProjectModelInputs {
            repository,
            repository_provenance: provenance.clone(),
            repository_confidence: Confidence::High,
            unit_inventory_provenance: provenance.clone(),
            unit_inventory_confidence: Confidence::High,
            assets: AssetInventory::new(Vec::new(), provenance.clone(), Confidence::High),
            adapters: AdapterInventory::new(Vec::new(), provenance.clone(), Confidence::High),
            policy: EffectivePolicy::new(None, provenance.clone(), Confidence::High),
        });
        for intent in Intent::ALL {
            model.commands.insert(
                intent,
                ResolvedCommandSet::absent(provenance.clone(), Confidence::High),
            );
        }
        let mut check = CommandSpec::new(
            "rust.check",
            Intent::Check,
            "cargo",
            RepoRelativePath::new("workspace")?,
            CommandSource::LanguageDefault {
                provider: String::from("rust"),
                rule: String::from("fixture"),
            },
        )
        .with_args(["check", "--workspace"]);
        check.confidence = Confidence::High;
        check.env = BTreeMap::from([(OsString::from("RUSTUP_AUTO_INSTALL"), OsString::from("0"))]);
        model.commands.insert(
            Intent::Check,
            ResolvedCommandSet::resolved(
                vec![check],
                provenance,
                Confidence::High,
                Confidence::High,
            )?,
        );
        Ok(model.finalize()?)
    }

    #[test]
    fn supported_runner_bodies_are_deterministic_and_contain_no_forge_invocation()
    -> Result<(), Box<dyn Error>> {
        let model = model()?;
        for runner in SUPPORTED_RUNNERS {
            let first = render_runner_body(&model, runner)?;
            let second = render_runner_body(&model, runner)?;
            assert_eq!(first, second);
            assert!(first.contains("verify"));
            assert!(first.contains("cargo"));
            assert!(!first.contains("forge evidence"));
        }
        Ok(())
    }

    #[test]
    fn runner_values_cannot_inject_managed_marker_tokens() {
        for value in ["prefix forge:begin suffix", "prefix forge:end suffix"] {
            assert!(matches!(
                safe_text(
                    "fixture.command",
                    Some(value),
                    RunnerTarget::Make,
                    "argument"
                ),
                Err(RunnerRenderError::UnsafeText { .. })
            ));
        }
    }

    #[test]
    fn projection_matches_the_public_runner_entry() -> Result<(), Box<dyn Error>> {
        let projected = project_runner_model(&model()?, RunnerTarget::Task)?;
        let verify = projected
            .commands
            .get(&Intent::Verify)
            .and_then(ResolvedCommandSet::executable_commands)
            .ok_or("verify projection is missing")?;
        assert_eq!(verify[0].program, OsString::from("task"));
        assert_eq!(
            verify[0].args,
            ["--taskfile", "Taskfile.yml", "verify"].map(OsString::from)
        );
        assert!(
            projected
                .assets
                .entries
                .iter()
                .any(|asset| asset.path.as_path() == Path::new("Taskfile.yml"))
        );
        Ok(())
    }

    #[test]
    fn unsupported_platform_error_names_the_selected_runner() {
        for runner in [RunnerTarget::Make, RunnerTarget::Just] {
            assert_eq!(
                RunnerRenderError::UnsupportedPlatform { runner }.to_string(),
                format!(
                    "the explicit `{}` runner recipe is not portable on this platform",
                    runner.program()
                )
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn shell_dependent_runners_are_rejected_by_render_and_projection() -> Result<(), Box<dyn Error>>
    {
        let model = model()?;
        for runner in [RunnerTarget::Make, RunnerTarget::Just] {
            let expected = RunnerRenderError::UnsupportedPlatform { runner };
            assert_eq!(render_runner_body(&model, runner), Err(expected.clone()));
            assert_eq!(project_runner_model(&model, runner), Err(expected.clone()));
            assert_eq!(
                expected.to_string(),
                format!(
                    "the explicit `{}` runner recipe is not portable on this platform",
                    runner.program()
                )
            );
        }
        Ok(())
    }

    #[test]
    fn secret_like_environment_is_rejected_before_it_can_enter_a_runner()
    -> Result<(), Box<dyn Error>> {
        let mut model = model()?;
        let mut command = model
            .commands
            .get(&Intent::Check)
            .and_then(ResolvedCommandSet::executable_commands)
            .and_then(|commands| commands.first())
            .cloned()
            .ok_or("fixture check command is missing")?;
        command.env.insert(
            OsString::from("API_TOKEN"),
            OsString::from("must-not-render"),
        );
        model.commands.insert(
            Intent::Check,
            ResolvedCommandSet::resolved(
                vec![command],
                vec![runner_provenance(RunnerTarget::Make, "secret fixture")],
                Confidence::High,
                Confidence::Unknown,
            )?,
        );
        model = model.finalize()?;

        assert!(matches!(
            render_runner_body(&model, RunnerTarget::Task),
            Err(RunnerRenderError::SecretLikeEnvironment { .. })
        ));
        Ok(())
    }

    #[test]
    fn secret_like_argv_is_rejected_before_it_can_enter_a_runner() -> Result<(), Box<dyn Error>> {
        let mut model = model()?;
        let mut command = model
            .commands
            .get(&Intent::Check)
            .and_then(ResolvedCommandSet::executable_commands)
            .and_then(|commands| commands.first())
            .cloned()
            .ok_or("fixture check command is missing")?;
        command
            .args
            .push(OsString::from("--access-key=literal-must-not-render"));
        model.commands.insert(
            Intent::Check,
            ResolvedCommandSet::resolved(
                vec![command],
                vec![runner_provenance(RunnerTarget::Make, "secret argv fixture")],
                Confidence::High,
                Confidence::Unknown,
            )?,
        );
        model = model.finalize()?;

        let error = match render_runner_body(&model, RunnerTarget::Task) {
            Err(error) => error,
            Ok(_) => {
                return Err(io::Error::other("secret-like argv was rendered into a runner").into());
            }
        };
        assert!(matches!(
            error,
            RunnerRenderError::SecretLikeArgument { .. }
        ));
        assert!(!error.to_string().contains("literal-must-not-render"));
        Ok(())
    }

    #[test]
    fn embedded_absolute_paths_are_rejected_before_runner_rendering() -> Result<(), Box<dyn Error>>
    {
        for argument in ["--cache-dir=/opt/team/cache", "@/private/tmp/response"] {
            let mut model = model()?;
            let mut command = model
                .commands
                .get(&Intent::Check)
                .and_then(ResolvedCommandSet::executable_commands)
                .and_then(|commands| commands.first())
                .cloned()
                .ok_or("fixture check command is missing")?;
            command.args.push(OsString::from(argument));
            model.commands.insert(
                Intent::Check,
                ResolvedCommandSet::resolved(
                    vec![command],
                    vec![runner_provenance(
                        RunnerTarget::Make,
                        "absolute path fixture",
                    )],
                    Confidence::High,
                    Confidence::Unknown,
                )?,
            );
            model = model.finalize()?;

            assert!(matches!(
                render_runner_body(&model, RunnerTarget::Task),
                Err(RunnerRenderError::HostSpecificValue { .. })
            ));
        }
        Ok(())
    }
}
