//! CLI-level checks for the public N-1 compatibility harness.

use std::path::Path;
use std::process::{Command, Output};

#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::path::PathBuf;

#[test]
fn diff_plans_requires_both_explicit_binaries() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["diff-plans", "--baseline", "forge-old"])
        .output()?;
    assert_eq!(output.status.code(), Some(64));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--candidate"));
    Ok(())
}

#[test]
fn missing_explicit_binary_is_an_environment_failure() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let missing = directory.path().join("missing-forge-binary");
    let output = run_xtask(&missing, &missing)?;
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot inspect baseline binary"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn equal_public_behavior_passes_while_ignoring_only_tool_version()
-> Result<(), Box<dyn std::error::Error>> {
    let binaries = NamedBinaries::new(
        "baseline-writes-state-forge",
        "candidate-rejects-state-forge",
    )?;
    let output = run_xtask(&binaries.baseline, &binaries.candidate)?;
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("28 fixtures, 1 shared schemas"));
    assert!(stdout.contains("not external authority"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn changed_plan_returns_a_reviewable_difference() -> Result<(), Box<dyn std::error::Error>> {
    let binaries = NamedBinaries::new("baseline-forge", "candidate-plan-changed-forge")?;
    let output = run_xtask(&binaries.baseline, &binaries.candidate)?;
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.contains("init plan differs"));
    assert!(stderr.contains("baseline=blake3:"));
    assert!(stderr.contains("candidate=blake3:"));
    assert!(stderr.contains("not external authority"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn schema_set_and_shared_document_changes_are_both_reported()
-> Result<(), Box<dyn std::error::Error>> {
    let binaries = NamedBinaries::new(
        "baseline-forge",
        "candidate-schema-added-schema-changed-forge",
    )?;
    let output = run_xtask(&binaries.baseline, &binaries.candidate)?;
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.contains("supported schema set"));
    assert!(stderr.contains("forge.example/v1"));
    assert!(stderr.contains("JSON Schema document differs"));
    Ok(())
}

fn run_xtask(baseline: &Path, candidate: &Path) -> std::io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["diff-plans", "--baseline"])
        .arg(baseline)
        .arg("--candidate")
        .arg(candidate)
        .output()
}

#[cfg(unix)]
struct NamedBinaries {
    _directory: tempfile::TempDir,
    baseline: PathBuf,
    candidate: PathBuf,
}

#[cfg(unix)]
impl NamedBinaries {
    fn new(baseline_name: &str, candidate_name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let source = Path::new(env!("CARGO_BIN_EXE_xtask-compat-fixture"));
        let baseline = directory.path().join(baseline_name);
        let candidate = directory.path().join(candidate_name);
        write_wrapper(&baseline, source, baseline_name)?;
        write_wrapper(&candidate, source, candidate_name)?;
        Ok(Self {
            _directory: directory,
            baseline,
            candidate,
        })
    }
}

#[cfg(unix)]
fn write_wrapper(path: &Path, target: &Path, profile: &str) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let source = shell_quote(&target.to_string_lossy());
    let profile = shell_quote(profile);
    fs::write(
        path,
        format!("#!/bin/sh\nFORGE_XTASK_COMPAT_FIXTURE_PROFILE={profile} exec {source} \"$@\"\n"),
    )?;
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions)
}

#[cfg(unix)]
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}
