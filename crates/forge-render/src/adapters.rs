//! Deterministic, repository-derived host adapter bodies.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::path::Path;

use forge_core::domain::{
    CommandEnforcement, CommandResolution, CommandSpec, Confidence, Intent, Mutability,
    ProjectModel,
};

pub const AGENTS_MAX_LINES: usize = 120;
pub const AGENTS_MAX_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AdapterRenderError {
    LimitExceeded { lines: usize, bytes: usize },
}

pub(crate) fn render_agents_body(model: &ProjectModel) -> Result<String, AdapterRenderError> {
    let mut lines = vec![String::from("## Authoritative paths")];
    let paths = authoritative_paths(model);
    if paths.is_empty() {
        lines.push(String::from(
            "- No high- or medium-confidence authoritative path was detected; stop before guessing one.",
        ));
    } else {
        lines.extend(paths.into_iter().map(|path| format!("- `{path}`")));
    }

    lines.push(String::new());
    lines.push(String::from("## Project-native commands"));
    let commands = renderable_commands(model);
    if commands.is_empty() {
        lines.push(String::from(
            "- No resolved command is safe to reproduce here; stop before guessing argv.",
        ));
    } else {
        lines.extend(commands);
    }

    lines.push(String::new());
    lines.push(String::from("## Completion evidence"));
    lines.push(String::from(
        "- Applicable required commands above must pass; advisory commands are informative only.",
    ));
    lines.push(String::from(
        "- Local command success does not prove CI, review, release, signing, or authorization.",
    ));

    lines.push(String::new());
    lines.push(String::from("## Stop boundaries"));
    lines.push(String::from(
        "- Stop rather than guessing when an applicable intent is absent, ambiguous, or unknown.",
    ));
    lines.push(String::from(
        "- Stop before changing CI, release, signing, ownership, migrations, or destructive/external state unless explicitly authorized.",
    ));

    let body = lines.join("\n");
    enforce_limit(&body)?;
    Ok(body)
}

pub(crate) const fn render_claude_pointer() -> &'static str {
    "@AGENTS.md"
}

fn authoritative_paths(model: &ProjectModel) -> BTreeSet<String> {
    let mut paths = BTreeSet::new();
    for unit in &model.units {
        if is_publishable(unit.confidence) {
            insert_safe_path(&mut paths, unit.manifest.as_path());
        }
    }
    for asset in &model.assets.entries {
        if is_publishable(asset.confidence) && !asset.kind.starts_with("adapter.") {
            insert_safe_path(&mut paths, asset.path.as_path());
        }
    }
    paths
}

fn renderable_commands(model: &ProjectModel) -> Vec<String> {
    let mut rendered = Vec::new();
    for intent in Intent::ALL {
        let Some(command_set) = model.commands.get(&intent) else {
            continue;
        };
        if command_set.resolution() != CommandResolution::Resolved
            || !is_publishable(command_set.resolution_confidence)
        {
            continue;
        }
        let Some(commands) = command_set.executable_commands() else {
            continue;
        };
        for (index, command) in commands.iter().enumerate() {
            if let Some(line) = render_command(
                intent,
                index,
                commands.len(),
                command,
                &model.repository.root,
            ) {
                rendered.push(line);
            }
        }
    }
    rendered
}

fn render_command(
    intent: Intent,
    index: usize,
    count: usize,
    command: &CommandSpec,
    repository_root: &Path,
) -> Option<String> {
    if !is_publishable(command.confidence) {
        return None;
    }
    let mut tokens = Vec::with_capacity(command.args.len() + 1);
    tokens.push(render_token(&command.program)?);
    for argument in &command.args {
        tokens.push(render_token(argument)?);
    }
    let environment = render_environment(command, repository_root)?;
    let cwd = safe_relative_text(command.cwd.as_path())?;
    let step = (count > 1).then(|| format!(" step {}/{}", index + 1, count));
    let enforcement = match command.enforcement {
        CommandEnforcement::Required => "required",
        CommandEnforcement::Advisory => "advisory",
    };
    let authorization = (command.mutability == Mutability::ExternalSideEffect)
        .then_some("; explicit authorization required");
    let environment = if environment.is_empty() {
        String::new()
    } else {
        format!("env {}; ", environment.join(" "))
    };
    Some(format!(
        "- {}{} ({enforcement}): {environment}argv {}; cwd `{cwd}`{}.",
        intent_name(intent),
        step.unwrap_or_default(),
        tokens.join(" "),
        authorization.unwrap_or_default(),
    ))
}

fn render_environment(command: &CommandSpec, repository_root: &Path) -> Option<Vec<String>> {
    let mut rendered = Vec::with_capacity(command.env.len());
    for (name, value) in &command.env {
        let name = name.to_str()?;
        let value = value.to_str()?;
        if !valid_environment_name(name)
            || suspected_secret_name(name)
            || value.chars().any(char::is_control)
            || value.contains('`')
        {
            return None;
        }
        let value = if name == "GOWORK" {
            render_gowork(value, repository_root)?
        } else {
            if looks_host_specific(value) {
                return None;
            }
            value.to_owned()
        };
        rendered.push(format!("`{name}={value}`"));
    }
    Some(rendered)
}

fn render_gowork(value: &str, repository_root: &Path) -> Option<String> {
    if matches!(value, "auto" | "off") {
        return Some(value.to_owned());
    }
    let path = Path::new(value);
    if path.is_absolute() {
        let relative = path.strip_prefix(repository_root).ok()?;
        let relative = safe_relative_text(relative)?;
        return Some(if relative == "." {
            String::from("<repo>")
        } else {
            format!("<repo>/{relative}")
        });
    }
    safe_relative_text(path).map(str::to_owned)
}

fn valid_environment_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

fn suspected_secret_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    [
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "CREDENTIAL",
        "AUTH",
        "COOKIE",
        "SESSION",
        "PRIVATE_KEY",
        "ACCESS_KEY",
    ]
    .iter()
    .any(|marker| upper.contains(marker))
}

fn render_token(value: &OsStr) -> Option<String> {
    let value = value.to_str()?;
    if value.is_empty()
        || value.chars().any(char::is_control)
        || value.contains('`')
        || looks_host_specific(value)
    {
        return None;
    }
    Some(format!("`{value}`"))
}

fn insert_safe_path(paths: &mut BTreeSet<String>, path: &Path) {
    if let Some(path) = safe_relative_text(path) {
        paths.insert(path.to_owned());
    }
}

fn safe_relative_text(path: &Path) -> Option<&str> {
    let value = path.to_str()?;
    (!path.is_absolute() && !looks_host_specific(value) && !value.contains('`')).then_some(value)
}

fn looks_host_specific(value: &str) -> bool {
    let bytes = value.as_bytes();
    value.starts_with('~')
        || value.starts_with('/')
        || value.contains("/Users/")
        || value.contains("/home/")
        || value.contains("\\Users\\")
        || value.contains("$HOME")
        || value.contains("${HOME}")
        || value.contains("%USERPROFILE%")
        || (bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes[2], b'/' | b'\\'))
}

const fn is_publishable(confidence: Confidence) -> bool {
    matches!(confidence, Confidence::Medium | Confidence::High)
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

fn enforce_limit(body: &str) -> Result<(), AdapterRenderError> {
    let lines = body.lines().count();
    let bytes = body.len();
    if lines > AGENTS_MAX_LINES || bytes > AGENTS_MAX_BYTES {
        Err(AdapterRenderError::LimitExceeded { lines, bytes })
    } else {
        Ok(())
    }
}
