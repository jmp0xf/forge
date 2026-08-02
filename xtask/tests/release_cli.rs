//! Public process contract for the local-only release-candidate commands.

#![forbid(unsafe_code)]

use std::path::Path;
use std::process::{Command, Output};

use tempfile::tempdir;

const EXIT_ENV_UNMET: i32 = 2;
const EXIT_USAGE: i32 = 64;

#[test]
fn release_subcommands_publish_help_on_stdout() -> std::io::Result<()> {
    for command in ["release-build", "release-finalize", "release-check"] {
        let output = run([command, "--help"])?;
        assert_eq!(output.status.code(), Some(0), "{command}");
        assert!(output.stderr.is_empty(), "{command}");
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .starts_with(&format!("usage: xtask {command} ")),
            "{command}"
        );
    }
    let build_help = run(["release-build", "--help"])?;
    assert!(
        String::from_utf8_lossy(&build_help.stdout)
            .contains("[--build-input-observation-dir <DIR>]")
    );
    assert!(String::from_utf8_lossy(&build_help.stdout).contains("must not be uploaded raw"));
    Ok(())
}

#[test]
fn release_subcommands_report_usage_on_stderr() -> std::io::Result<()> {
    for command in ["release-build", "release-finalize", "release-check"] {
        let output = run([command])?;
        assert_eq!(output.status.code(), Some(EXIT_USAGE), "{command}");
        assert!(output.stdout.is_empty(), "{command}");
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .starts_with("error: release command options must be explicit"),
            "{command}"
        );
    }
    Ok(())
}

#[test]
fn release_subcommands_classify_a_missing_output_directory_as_environment_unmet()
-> std::io::Result<()> {
    let temporary = tempdir()?;
    let missing = temporary.path().join("missing");

    let build =
        run_with_output_directory("release-build", Some("x86_64-unknown-linux-musl"), &missing)?;
    assert_environment_failure("release-build", &build);

    for command in ["release-finalize", "release-check"] {
        let output = run_with_output_directory(command, None, &missing)?;
        assert_environment_failure(command, &output);
    }
    Ok(())
}

#[test]
fn release_build_observation_destination_is_explicit_fresh_and_create_only() -> std::io::Result<()>
{
    let temporary = tempdir()?;
    let output = temporary.path().join("candidate");
    std::fs::create_dir(&output)?;
    let missing = temporary.path().join("missing-observation");

    let missing_output = run_build_with_observation(&output, &missing)?;
    assert_eq!(missing_output.status.code(), Some(EXIT_ENV_UNMET));
    assert!(missing_output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&missing_output.stderr).contains("build input observation output")
    );

    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| std::io::Error::other("xtask has no repository parent"))?;
    let source_container = repository
        .parent()
        .ok_or_else(|| std::io::Error::other("repository has no containing directory"))?;
    let containing_output = run_build_with_observation(&output, source_container)?;
    assert_eq!(containing_output.status.code(), Some(EXIT_ENV_UNMET));
    assert!(containing_output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&containing_output.stderr)
            .contains("observation output must not contain")
    );

    let observation = temporary.path().join("observation");
    std::fs::create_dir(&observation)?;
    let fixed = observation.join("release-build-input-observation-x86_64-unknown-linux-musl.json");
    std::fs::write(&fixed, b"pre-existing-private-record")?;
    let collision = run_build_with_observation(&output, &observation)?;
    assert_eq!(collision.status.code(), Some(EXIT_ENV_UNMET));
    assert!(collision.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&collision.stderr)
            .contains("build input observation already exists")
    );
    assert_eq!(std::fs::read(fixed)?, b"pre-existing-private-record");
    Ok(())
}

fn run<const N: usize>(arguments: [&str; N]) -> std::io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(arguments)
        .output()
}

fn run_with_output_directory(
    command: &str,
    target: Option<&str>,
    output: &Path,
) -> std::io::Result<Output> {
    let mut process = Command::new(env!("CARGO_BIN_EXE_xtask"));
    process.arg(command);
    if let Some(target) = target {
        process.args(["--target", target]);
    }
    process.arg("--output-dir").arg(output);
    process.output()
}

fn run_build_with_observation(output: &Path, observation: &Path) -> std::io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args([
            "release-build",
            "--target",
            "x86_64-unknown-linux-musl",
            "--output-dir",
        ])
        .arg(output)
        .arg("--build-input-observation-dir")
        .arg(observation)
        .output()
}

fn assert_environment_failure(command: &str, output: &Output) {
    assert_eq!(output.status.code(), Some(EXIT_ENV_UNMET), "{command}");
    assert!(output.stdout.is_empty(), "{command}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.starts_with("error: failed to pin the existing release output directory"),
        "{command}: {stderr}"
    );
}
