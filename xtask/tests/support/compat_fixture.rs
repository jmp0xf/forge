//! Executable protocol fixture for `xtask diff-plans` integration tests.

#![forbid(unsafe_code)]

use std::env;
use std::ffi::OsString;
use std::io::{self, Write as _};
use std::path::Path;
use std::process::ExitCode;

use serde_json::{Value, json};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("fake Forge error: {error}");
            ExitCode::from(70)
        }
    }
}

fn run() -> Result<(), String> {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    let executable =
        env::current_exe().map_err(|error| format!("failed to locate fake executable: {error}"))?;
    let profile_from_environment = env::var("FORGE_XTASK_COMPAT_FIXTURE_PROFILE").ok();
    let profile = profile_from_environment.as_deref().unwrap_or_else(|| {
        executable
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("baseline")
    });
    let marker = Path::new("compat-subject-marker");
    if profile.contains("rejects-state") && marker.exists() {
        return Err(String::from(
            "comparison subject inherited filesystem state from the other binary",
        ));
    }
    if profile.contains("writes-state") {
        std::fs::write(marker, b"subject-local state\n")
            .map_err(|error| format!("failed to write fake subject state: {error}"))?;
    }
    if contains_argument(&arguments, "version") {
        return emit(&version_document(profile));
    }
    if let Some(schema_index) = argument_index(&arguments, "schema") {
        let schema = arguments
            .get(schema_index + 1)
            .and_then(|value| value.to_str())
            .ok_or_else(|| String::from("schema invocation omitted its identifier"))?;
        return emit(&schema_document(profile, schema));
    }
    if contains_argument(&arguments, "init") {
        let repository = option_value(&arguments, "-C")
            .map(|path| Path::new(path).to_string_lossy().into_owned())
            .unwrap_or_else(|| String::from("."));
        return emit(&init_document(profile, &repository));
    }
    Err(format!("unsupported invocation {arguments:?}"))
}

fn version_document(profile: &str) -> Value {
    let mut schemas = vec![String::from("forge.init-plan/v1")];
    if profile.contains("schema-added") {
        schemas.push(String::from("forge.example/v1"));
    }
    json!({
        "schema": "forge.version/v1",
        "tool_version": tool_version(profile),
        "ok": true,
        "data": {
            "name": "forge",
            "version": tool_version(profile),
            "supported_schemas": schemas,
            "capabilities": ["init", "schema", "version"]
        },
        "diagnostics": [],
        "truncated": false,
        "artifacts": []
    })
}

fn schema_document(profile: &str, schema: &str) -> Value {
    let marker = if profile.contains("schema-changed") {
        "candidate"
    } else {
        "stable"
    };
    json!({
        "$id": schema,
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "x-test-marker": marker
    })
}

fn init_document(profile: &str, repository: &str) -> Value {
    let plan = if profile.contains("plan-changed") {
        "candidate-plan"
    } else {
        "stable-plan"
    };
    json!({
        "schema": "forge.init-plan/v1",
        "tool_version": tool_version(profile),
        "ok": true,
        "data": {
            "repository_root": repository,
            "plan": plan
        },
        "diagnostics": [],
        "truncated": false,
        "artifacts": []
    })
}

fn tool_version(profile: &str) -> &'static str {
    if profile.contains("candidate") {
        "1.0.0"
    } else {
        "0.9.0"
    }
}

fn contains_argument(arguments: &[OsString], expected: &str) -> bool {
    argument_index(arguments, expected).is_some()
}

fn argument_index(arguments: &[OsString], expected: &str) -> Option<usize> {
    arguments.iter().position(|value| value == expected)
}

fn option_value<'a>(arguments: &'a [OsString], option: &str) -> Option<&'a OsString> {
    argument_index(arguments, option).and_then(|index| arguments.get(index + 1))
}

fn emit(value: &Value) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("failed to serialize fake result: {error}"))?;
    bytes.push(b'\n');
    io::stdout()
        .lock()
        .write_all(&bytes)
        .map_err(|error| format!("failed to write fake result: {error}"))
}
