//! Runs each declared project-native fixture command when its tool is installed.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

const COMMANDLESS_SCENARIO_FIXTURES: &[&str] = &[
    "empty-repo",
    "huge-output",
    "malicious-runner",
    "timeout-tree",
];

#[test]
fn generated_fixture_commands_run_independently_when_tools_are_available()
-> Result<(), Box<dyn std::error::Error>> {
    let repository = repository_root()?;
    let generated = repository.join("fixtures/generated");
    let manifest: Value = serde_json::from_slice(&fs::read(generated.join("manifest-v1.json"))?)?;
    let fixtures = manifest["fixtures"]
        .as_array()
        .ok_or("materialized fixture manifest omitted fixtures")?;
    let temporary = tempfile::tempdir()?;
    let copied = temporary.path().join("generated");
    copy_tree(&generated, &copied)?;

    let mut availability = BTreeMap::new();
    for fixture in fixtures {
        let id = fixture["id"]
            .as_str()
            .ok_or("materialized fixture omitted id")?;
        let commands = fixture["commands"]
            .as_array()
            .ok_or("materialized fixture omitted commands")?;
        if commands.is_empty() {
            assert!(
                COMMANDLESS_SCENARIO_FIXTURES.contains(&id),
                "fixture `{id}` has no native command without being an explicit synthetic scenario"
            );
        }
        for (index, command) in commands.iter().enumerate() {
            let program = command["program"]
                .as_str()
                .ok_or("fixture command omitted program")?;
            let available = match availability.get(program) {
                Some(available) => *available,
                None => {
                    let available = tool_is_available(program)?;
                    availability.insert(program.to_owned(), available);
                    available
                }
            };
            if !available {
                continue;
            }

            let cwd = command["cwd"]
                .as_str()
                .ok_or("fixture command omitted cwd")?;
            let arguments = command["args"]
                .as_array()
                .ok_or("fixture command omitted args")?
                .iter()
                .map(|argument| {
                    argument
                        .as_str()
                        .ok_or("fixture command argument is not a string")
                })
                .collect::<Result<Vec<_>, _>>()?;
            let working_directory = copied.join(id).join(cwd);
            let mut process = Command::new(program);
            process
                .args(arguments)
                .current_dir(&working_directory)
                .env_remove("GOWORK");
            isolate_tool_state(&mut process, temporary.path(), id, index, program);
            let output = process.output()?;
            assert_command_succeeded(id, index, program, &output);
        }
    }
    Ok(())
}

fn repository_root() -> Result<PathBuf, Box<dyn std::error::Error>> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "xtask manifest directory has no repository parent".into())
}

fn tool_is_available(program: &str) -> Result<bool, std::io::Error> {
    let version_argument = if program == "go" {
        "version"
    } else {
        "--version"
    };
    match Command::new(program).arg(version_argument).output() {
        Ok(output) if output.status.success() => Ok(true),
        Ok(output) => Err(std::io::Error::other(format!(
            "`{program} {version_argument}` failed with {}; stdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn isolate_tool_state(
    process: &mut Command,
    temporary: &Path,
    fixture_id: &str,
    command_index: usize,
    program: &str,
) {
    if program == "cargo" {
        process.env("RUSTUP_AUTO_INSTALL", "0").env(
            "CARGO_TARGET_DIR",
            temporary
                .join("cargo-targets")
                .join(format!("{fixture_id}-{command_index}")),
        );
    } else if program == "go" {
        process
            .env("GOPROXY", "off")
            .env("GOSUMDB", "off")
            .env("GOCACHE", temporary.join("go-cache"))
            .env("GOMODCACHE", temporary.join("go-module-cache"))
            .env("GOPATH", temporary.join("go-path"));
    }
}

fn assert_command_succeeded(id: &str, index: usize, program: &str, output: &Output) {
    assert!(
        output.status.success(),
        "fixture `{id}` command {index} (`{program}`) failed with {}; stdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn copy_tree(source: &Path, destination: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(destination)?;
    let mut entries = fs::read_dir(source)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let file_type = entry.file_type()?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if file_type.is_symlink() {
            return Err(format!(
                "fixture output contains a symlink: {}",
                source_path.display()
            )
            .into());
        }
        if file_type.is_dir() {
            copy_tree(&source_path, &destination_path)?;
        } else if file_type.is_file() {
            fs::copy(&source_path, &destination_path)?;
        } else {
            return Err(format!(
                "fixture output is not a regular file: {}",
                source_path.display()
            )
            .into());
        }
    }
    Ok(())
}
