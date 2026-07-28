//! Conservative discovery of conventional project-owned script entrypoints.
//!
//! A filename identifies only an intent-shaped entrypoint. It does not prove coverage, safety, or
//! success, and Forge never executes the script during discovery. Invocation is retained as
//! `program + argv`: a supported shebang remains authoritative. An extension alone never proves
//! whether a project uses `python`, `uv`, `node`, `bun`, a shell dialect, or another launcher.

use std::ffi::OsString;
use std::path::{Component, Path};

use forge_core::fingerprint::validate_argv_privacy;
use forge_core::{
    BoundedText, CommandSource, CommandSpec, Confidence, Intent, Provenance, RepoRelativePath,
};

/// Whether a conventional script entrypoint could be represented without guessing shell text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptDiscoveryCompleteness {
    Complete,
    Unknown,
}

/// One conventional project-owned script candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptDiscovery {
    intent: Option<Intent>,
    completeness: ScriptDiscoveryCompleteness,
    command: Option<CommandSpec>,
    provenance: Vec<Provenance>,
}

impl ScriptDiscovery {
    fn unknown(
        path: &RepoRelativePath,
        intent: Option<Intent>,
        rule_suffix: &str,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            intent,
            completeness: ScriptDiscoveryCompleteness::Unknown,
            command: None,
            provenance: vec![provenance(path, rule_suffix, detail)],
        }
    }

    #[must_use]
    pub const fn completeness(&self) -> ScriptDiscoveryCompleteness {
        self.completeness
    }

    #[must_use]
    pub const fn intent(&self) -> Option<Intent> {
        self.intent
    }

    #[must_use]
    pub const fn command(&self) -> Option<&CommandSpec> {
        self.command.as_ref()
    }

    #[must_use]
    pub fn provenance(&self) -> &[Provenance] {
        &self.provenance
    }
}

/// Returns the intent for an exact root-level `scripts/`, `tools/`, or `hack/` entrypoint.
///
/// Similar names and nested paths are deliberately ignored. A supported script filename extension
/// is stripped only after the exact parent directory is established; it never selects a launcher.
#[must_use]
pub fn standard_script_intent(path: &Path) -> Option<Intent> {
    let mut components = path.components();
    let parent = match components.next()? {
        Component::Normal(parent) => parent.to_str()?,
        _ => return None,
    };
    if !matches!(parent, "scripts" | "tools" | "hack") {
        return None;
    }
    let file_name = match components.next()? {
        Component::Normal(file_name) if components.next().is_none() => file_name.to_str()?,
        _ => return None,
    };
    let (stem, extension) = split_supported_extension(file_name);
    if extension.is_none() && file_name.contains('.') {
        return None;
    }
    intent_for_stem(stem)
}

/// Discovers one already-classified script without interpreting its body.
#[must_use]
pub fn discover_standard_script(path: &RepoRelativePath, input: &BoundedText) -> ScriptDiscovery {
    let Some(intent) = standard_script_intent(path.as_path()) else {
        return ScriptDiscovery::unknown(
            path,
            None,
            "invalid-path",
            "script path is outside the exact conventional entrypoint surface",
        );
    };
    if input.truncated {
        return ScriptDiscovery::unknown(
            path,
            Some(intent),
            "input-truncated",
            "script input exceeded the bounded-read limit before its invocation contract was established",
        );
    }
    if input.binary || input.bytes.contains(&0) {
        return ScriptDiscovery::unknown(
            path,
            Some(intent),
            "input-binary",
            "script input is binary and was not treated as an interpreter script",
        );
    }

    let Some(shebang) = parse_shebang(&input.bytes) else {
        return ScriptDiscovery::unknown(
            path,
            Some(intent),
            "missing-or-unsupported-shebang",
            "script invocation is not represented by one absolute shebang loader and at most one argument",
        );
    };
    if validate_argv_privacy(std::iter::once(&shebang.program).chain(shebang.argument.iter()))
        .is_err()
    {
        return ScriptDiscovery::unknown(
            path,
            Some(intent),
            "private-invocation",
            "script invocation contains credential-like command metadata and was not retained",
        );
    }
    let Some(invocation) = portable_invocation(shebang) else {
        return ScriptDiscovery::unknown(
            path,
            Some(intent),
            "nonportable-shebang",
            "script invocation is not proven by an exact /usr/bin/env plus one portable program name",
        );
    };

    let mut args = invocation.prefix_args;
    args.push(path.as_path().as_os_str().to_os_string());
    let parent = path
        .as_path()
        .parent()
        .and_then(Path::file_name)
        .and_then(|value| value.to_str())
        .unwrap_or("project");
    let file_name = path
        .as_path()
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("script")
        .replace('.', "-");
    let mut command = CommandSpec::new(
        format!("script.{parent}.{file_name}"),
        intent,
        invocation.program,
        RepoRelativePath::root(),
        CommandSource::ExistingProjectTarget {
            path: path.clone(),
            target: String::from("script-entrypoint"),
        },
    )
    .with_args(args);
    command.confidence = Confidence::Medium;
    let provenance = vec![provenance(
        path,
        "exact-entrypoint",
        "exact conventional script name and argv-safe interpreter map to a project-owned intent; coverage remains unknown",
    )];
    ScriptDiscovery {
        intent: Some(intent),
        completeness: ScriptDiscoveryCompleteness::Complete,
        command: Some(command),
        provenance,
    }
}

#[derive(Debug)]
struct ScriptInvocation {
    program: OsString,
    prefix_args: Vec<OsString>,
}

#[derive(Debug)]
struct ParsedShebang {
    program: OsString,
    argument: Option<OsString>,
}

fn parse_shebang(bytes: &[u8]) -> Option<ParsedShebang> {
    if !bytes.starts_with(b"#!") {
        return None;
    }
    let line_end = bytes
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(bytes.len());
    let line = std::str::from_utf8(bytes.get(2..line_end)?)
        .ok()?
        .trim_end_matches('\r')
        .trim();
    let (program, argument) = line
        .find(char::is_whitespace)
        .map_or((line, None), |split| {
            let (program, remainder) = line.split_at(split);
            (program, Some(remainder.trim()))
        });
    // A shebang is a POSIX text protocol even when Forge inspects the repository on Windows.
    // Host-native path parsing would reject `/usr/bin/env` there before the portable-invocation
    // policy below can classify it.
    if !program.starts_with('/')
        || argument.is_some_and(|argument| {
            argument.is_empty()
                || argument.bytes().any(|byte| byte.is_ascii_control())
                || argument.split_ascii_whitespace().count() != 1
        })
    {
        return None;
    }
    Some(ParsedShebang {
        program: OsString::from(program),
        argument: argument.map(OsString::from),
    })
}

fn portable_invocation(shebang: ParsedShebang) -> Option<ScriptInvocation> {
    if shebang.program != "/usr/bin/env" {
        return None;
    }
    let argument = shebang.argument?.into_string().ok()?;
    if !portable_program_name(&argument) {
        return None;
    }
    Some(ScriptInvocation {
        // `/usr/bin/env name script` and `name script` both resolve `name` through PATH. Keeping
        // the portable program name avoids publishing a host-absolute loader in AGENTS.md.
        program: OsString::from(argument),
        prefix_args: Vec::new(),
    })
}

fn portable_program_name(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && !value
            .chars()
            .any(|character| matches!(character, '/' | '\\' | '='))
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'+' | b'.'))
}

fn split_supported_extension(file_name: &str) -> (&str, Option<&str>) {
    let Some((stem, extension)) = file_name.rsplit_once('.') else {
        return (file_name, None);
    };
    if supported_script_extension(extension) {
        (stem, Some(extension))
    } else {
        (file_name, None)
    }
}

const fn supported_script_extension(extension: &str) -> bool {
    matches!(
        extension.as_bytes(),
        b"sh"
            | b"bash"
            | b"zsh"
            | b"fish"
            | b"py"
            | b"rb"
            | b"pl"
            | b"js"
            | b"ps1"
            | b"cmd"
            | b"bat"
    )
}

fn intent_for_stem(stem: &str) -> Option<Intent> {
    match stem {
        "setup" | "bootstrap" => Some(Intent::Setup),
        "format-check" | "fmt-check" => Some(Intent::FormatCheck),
        "format" | "fmt" => Some(Intent::Format),
        "check" | "lint" => Some(Intent::Check),
        "fix" => Some(Intent::Fix),
        "test" => Some(Intent::Test),
        "verify" | "ci" => Some(Intent::Verify),
        "build" => Some(Intent::Build),
        _ => None,
    }
}

fn provenance(path: &RepoRelativePath, rule_suffix: &str, detail: impl Into<String>) -> Provenance {
    Provenance {
        rule_id: format!("script.{rule_suffix}.v1"),
        source_path: Some(path.as_path().into()),
        source_range: None,
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::path::Path;

    use forge_core::{BoundedText, CommandSource, Confidence, Intent, RepoRelativePath};

    use super::{ScriptDiscoveryCompleteness, discover_standard_script, standard_script_intent};

    fn text(bytes: impl Into<Vec<u8>>) -> BoundedText {
        BoundedText {
            bytes: bytes.into(),
            truncated: false,
            binary: false,
        }
    }

    fn path(value: &str) -> RepoRelativePath {
        RepoRelativePath::new(value).unwrap_or_else(|_| RepoRelativePath::root())
    }

    #[test]
    fn exact_conventional_paths_map_without_guessing_similar_names() {
        assert_eq!(
            standard_script_intent(Path::new("scripts/test")),
            Some(Intent::Test)
        );
        assert_eq!(
            standard_script_intent(Path::new("tools/fmt-check.sh")),
            Some(Intent::FormatCheck)
        );
        assert_eq!(
            standard_script_intent(Path::new("hack/bootstrap.py")),
            Some(Intent::Setup)
        );
        assert_eq!(
            standard_script_intent(Path::new("nested/scripts/test")),
            None
        );
        assert_eq!(
            standard_script_intent(Path::new("scripts/test-helper")),
            None
        );
        assert_eq!(standard_script_intent(Path::new("scripts/test.txt")), None);
    }

    #[test]
    fn env_shebang_is_normalized_to_the_same_path_resolved_program()
    -> Result<(), Box<dyn std::error::Error>> {
        let script_path = path("scripts/test");
        let script = discover_standard_script(
            &script_path,
            &text(b"#!/usr/bin/env bash\r\necho test\r\n".to_vec()),
        );

        assert_eq!(script.completeness(), ScriptDiscoveryCompleteness::Complete);
        let command = script.command().ok_or("complete script command missing")?;
        assert_eq!(command.intent, Intent::Test);
        assert_eq!(command.program, OsStr::new("bash"));
        assert_eq!(command.args, [script_path.as_path().as_os_str()]);
        assert_eq!(command.confidence, Confidence::Medium);
        assert!(command.coverage.is_empty());
        assert!(matches!(
            &command.source,
            CommandSource::ExistingProjectTarget { path, target }
                if path == &script_path && target == "script-entrypoint"
        ));
        Ok(())
    }

    #[test]
    fn extension_without_shebang_is_unknown_instead_of_guessing_a_launcher() {
        let script =
            discover_standard_script(&path("hack/verify.py"), &text(b"print('ok')\n".to_vec()));

        assert_eq!(script.completeness(), ScriptDiscoveryCompleteness::Unknown);
        assert!(script.command().is_none());
    }

    #[test]
    fn ambiguous_or_missing_interpreter_is_unknown() {
        for bytes in [
            b"echo test\n".as_slice(),
            b"#!/usr/bin/env -S python3 -u\n".as_slice(),
            b"#!/usr/bin/env\n".as_slice(),
            b"#!python3\n".as_slice(),
            b"#!/bin/zsh\n".as_slice(),
            b"#!/bin/sh -c\n".as_slice(),
            b"#!/custom/env bash\n".as_slice(),
        ] {
            let script = discover_standard_script(&path("scripts/test"), &text(bytes.to_vec()));
            assert_eq!(script.completeness(), ScriptDiscoveryCompleteness::Unknown);
            assert!(script.command().is_none());
        }
    }

    #[test]
    fn truncated_and_binary_scripts_are_intent_local_unknowns() {
        for input in [
            BoundedText {
                bytes: b"#!/usr/bin/env bash\n".to_vec(),
                truncated: true,
                binary: false,
            },
            BoundedText {
                bytes: b"#!/usr/bin/env bash\0".to_vec(),
                truncated: false,
                binary: true,
            },
        ] {
            let script = discover_standard_script(&path("scripts/test.sh"), &input);
            assert_eq!(script.intent(), Some(Intent::Test));
            assert_eq!(script.completeness(), ScriptDiscoveryCompleteness::Unknown);
            assert!(script.command().is_none());
        }
    }

    #[test]
    fn additional_conventional_names_are_classified_without_guessing_execution() {
        assert_eq!(
            standard_script_intent(Path::new("scripts/ci.fish")),
            Some(Intent::Verify)
        );
        assert_eq!(
            standard_script_intent(Path::new("tools/test.zsh")),
            Some(Intent::Test)
        );
        assert_eq!(
            standard_script_intent(Path::new("hack/build.cmd")),
            Some(Intent::Build)
        );
        assert_eq!(
            standard_script_intent(Path::new("hack/check.bat")),
            Some(Intent::Check)
        );

        let zsh = discover_standard_script(
            &path("tools/test.zsh"),
            &text(b"#!/bin/zsh\necho test\n".to_vec()),
        );
        assert_eq!(zsh.intent(), Some(Intent::Test));
        assert_eq!(zsh.completeness(), ScriptDiscoveryCompleteness::Unknown);
    }

    #[test]
    fn credential_like_shebang_argument_is_rejected_without_echoing_the_value() {
        let secret = "SUPERSECRET";
        let script = discover_standard_script(
            &path("scripts/test"),
            &text(format!("#!/usr/bin/tool --api-key={secret}\n").into_bytes()),
        );

        assert_eq!(script.completeness(), ScriptDiscoveryCompleteness::Unknown);
        assert!(script.command().is_none());
        assert!(script.provenance().iter().all(|source| {
            !source.detail.contains(secret) && source.rule_id == "script.private-invocation.v1"
        }));
    }
}
