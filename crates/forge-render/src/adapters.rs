//! Deterministic, repository-derived host adapter bodies.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use forge_core::domain::{
    CommandEnforcement, CommandResolution, CommandSpec, Confidence, Intent, Mutability,
    ProjectModel,
};
use forge_core::fingerprint::{is_secret_like_name, validate_argv_privacy};

pub const AGENTS_MAX_LINES: usize = 120;
pub const AGENTS_MAX_BYTES: usize = 8 * 1024;
const AUTHORITATIVE_DIRECTORY_MIN_FILES: usize = 8;

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
    if commands.lines.is_empty() {
        lines.push(String::from(
            "- No resolved command is safe to reproduce here; stop before guessing argv.",
        ));
    } else {
        lines.extend(commands.lines);
    }

    if !commands.receipt_intents.is_empty() {
        lines.push(String::new());
        lines.push(String::from("## Optional local Receipts"));
        lines.extend(commands.receipt_intents.into_iter().map(|intent| {
            format!(
                "- `forge evidence run {intent}` executes the same resolved `{intent}` command set and records a scope-bound local Receipt."
            )
        }));
        lines.push(String::from(
            "- A local Receipt is optional evidence, never CI, review, release, or approval authority.",
        ));
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
    compact_authoritative_paths(paths)
}

/// Replaces a large family of exact files with its deepest shared directory entry.
///
/// The exact model remains available through `forge explain`; AGENTS is a bounded navigation
/// index. Keeping small groups exact while collapsing eight or more descendants avoids spending
/// most of the adapter budget on generated fixtures, ADR series, or large monorepo manifests.
fn compact_authoritative_paths(paths: BTreeSet<PathBuf>) -> BTreeSet<String> {
    let mut candidates = BTreeMap::<PathBuf, BTreeSet<PathBuf>>::new();
    for path in &paths {
        let mut ancestor = path.parent();
        while let Some(directory) = ancestor {
            if directory.as_os_str().is_empty() {
                break;
            }
            candidates
                .entry(directory.to_path_buf())
                .or_default()
                .insert(path.clone());
            ancestor = directory.parent();
        }
    }

    let mut candidates = candidates.into_iter().collect::<Vec<_>>();
    candidates.sort_by(|(left_path, _), (right_path, _)| {
        right_path
            .components()
            .count()
            .cmp(&left_path.components().count())
            .then_with(|| left_path.cmp(right_path))
    });

    let mut covered = BTreeSet::new();
    let mut directories = BTreeSet::new();
    for (directory, descendants) in candidates {
        let uncovered = descendants
            .iter()
            .filter(|path| !covered.contains(*path))
            .count();
        if uncovered < AUTHORITATIVE_DIRECTORY_MIN_FILES {
            continue;
        }
        covered.extend(descendants);
        if let Some(directory) = safe_relative_text(&directory) {
            directories.insert(format!("{directory}/"));
        }
    }

    let mut compacted = paths
        .into_iter()
        .filter(|path| !covered.contains(path))
        .filter_map(|path| safe_relative_text(&path).map(str::to_owned))
        .collect::<BTreeSet<_>>();
    compacted.extend(directories);
    compacted
}

struct RenderedCommands {
    lines: Vec<String>,
    receipt_intents: Vec<&'static str>,
}

fn renderable_commands(model: &ProjectModel) -> RenderedCommands {
    let mut lines = Vec::new();
    let mut receipt_intents = Vec::new();
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
        let rendered = commands
            .iter()
            .enumerate()
            .map(|(index, command)| {
                render_command(
                    intent,
                    index,
                    commands.len(),
                    command,
                    &model.repository.root,
                )
            })
            .collect::<Option<Vec<_>>>();
        let Some(rendered) = rendered else {
            continue;
        };
        lines.extend(rendered);
        if commands.iter().all(|command| {
            matches!(
                command.mutability,
                Mutability::ReadOnly | Mutability::ExternalSideEffect
            )
        }) {
            receipt_intents.push(intent_name(intent));
        }
    }
    RenderedCommands {
        lines,
        receipt_intents,
    }
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
    validate_argv_privacy(std::iter::once(&command.program).chain(command.args.iter())).ok()?;
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
            || is_secret_like_name(name)
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

fn insert_safe_path(paths: &mut BTreeSet<PathBuf>, path: &Path) {
    if safe_relative_text(path).is_some() {
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    use forge_core::{CommandSource, CommandSpec, Confidence, Intent, RepoRelativePath};

    use super::{compact_authoritative_paths, render_command};

    #[test]
    fn large_path_families_collapse_to_the_deepest_useful_directory() {
        let mut paths = BTreeSet::from([PathBuf::from("README.md")]);
        for index in 0..8 {
            paths.insert(PathBuf::from(format!("docs/adr/{index:04}.md")));
        }

        assert_eq!(
            compact_authoritative_paths(paths),
            BTreeSet::from([String::from("README.md"), String::from("docs/adr/")])
        );
    }

    #[test]
    fn small_path_families_remain_exact() {
        let paths = (0..7)
            .map(|index| PathBuf::from(format!("crates/member-{index}/Cargo.toml")))
            .collect::<BTreeSet<_>>();
        let expected = paths
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect::<BTreeSet<_>>();

        assert_eq!(compact_authoritative_paths(paths), expected);
    }

    #[test]
    fn secret_like_argv_is_omitted_from_generated_adapter_guidance() {
        let mut command = CommandSpec::new(
            "private-argv",
            Intent::Check,
            "tool",
            RepoRelativePath::root(),
            CommandSource::ExplicitConfig,
        )
        .with_args(["--token=literal-must-not-render"]);
        command.confidence = Confidence::High;

        assert_eq!(
            render_command(Intent::Check, 0, 1, &command, Path::new("/repo")),
            None
        );
    }
}
