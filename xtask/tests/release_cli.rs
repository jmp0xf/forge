//! Public process contract for the local-only release-candidate commands.

#![forbid(unsafe_code)]

use std::path::Path;
use std::process::{Command, Output};

use tempfile::tempdir;

const EXIT_ENV_UNMET: i32 = 2;
const EXIT_USAGE: i32 = 64;
const RELEASE_BUILD_HELP: &str = concat!(
    "usage: xtask release-build --target <TRIPLE> --output-dir <DIR> [--build-input-observation-dir <DIR>]\n\n",
    "Builds one accepted target from a clean Git checkout in a fresh temporary Cargo target directory, then stages the binary and its source-bound CycloneDX 1.6 SBOM. The optional observation is a private, diagnostic-only pre-build record that can contain local toolchain paths; it is not a release asset or evidence and must not be uploaded raw. Run the compiled xtask directly when a nested `cargo run` is unsuitable.\n",
);
const RELEASE_BUILD_PLAN_HELP: &str = "usage: xtask release-build-plan --target <TRIPLE> --output-dir <DIR>\n\nWrites exactly release-build-plan.json into an existing fresh empty directory outside the source repository. The canonical document binds the clean Git commit, Cargo.lock digest, target, and fixed release semantics without requesting Cargo or creating a binary, SBOM, or Cargo target directory. It is an untrusted candidate request, never builder evidence, qualification, approval, or release authority. This command does not establish a process sandbox or trust the Git found on PATH: formal qualification must invoke an already-built xtask directly while the external Authority pins the real Git executable and enforces its child-process allowlist; do not enter this phase through cargo run.\n";
const RELEASE_BUILD_APPLY_HELP: &str = "usage: xtask release-build-apply --input-dir <DIR> --output-dir <DIR>\n\nReads exactly release-build-plan.json, release-build-apply-descriptor.json, and release-build-bound-binary from one existing pinned input directory, then writes exactly the plan-derived binary and CycloneDX SBOM names into a disjoint existing fresh empty output directory. The command accepts no target, program, environment, or filename overrides and requests no Git, Cargo, compiler, metadata, tree, network, or other child process. Its outputs remain candidate-controlled and are never builder evidence, qualification, approval, or release authority. The external Authority must enforce a zero-child sandbox, read-only input, exclusive scratch output, and discard the entire output directory after any failure; invoke an already-built xtask directly, never cargo run.\n";
const APPLY_BINARY_NAME: &str = "forge-0.1.0-rc.2-x86_64-unknown-linux-musl";
const APPLY_SBOM_NAME: &str = "forge-0.1.0-rc.2-x86_64-unknown-linux-musl.cdx.json";
const RELEASE_BUILD_USAGE_ERROR: &[u8] =
    b"error: release command options must be explicit `--name value` pairs\n";

#[test]
fn release_subcommands_publish_help_on_stdout() -> std::io::Result<()> {
    for command in [
        "release-build",
        "release-build-plan",
        "release-build-apply",
        "release-finalize",
        "release-check",
    ] {
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
    assert_eq!(build_help.status.code(), Some(0));
    assert_eq!(build_help.stdout, RELEASE_BUILD_HELP.as_bytes());
    assert!(build_help.stderr.is_empty());
    let plan_help = run(["release-build-plan", "--help"])?;
    assert_eq!(plan_help.status.code(), Some(0));
    assert_eq!(plan_help.stdout, RELEASE_BUILD_PLAN_HELP.as_bytes());
    assert!(plan_help.stderr.is_empty());
    let apply_help = run(["release-build-apply", "--help"])?;
    assert_eq!(apply_help.status.code(), Some(0));
    assert_eq!(apply_help.stdout, RELEASE_BUILD_APPLY_HELP.as_bytes());
    assert!(apply_help.stderr.is_empty());

    let top_level_help = run(["help"])?;
    assert_eq!(top_level_help.status.code(), Some(0));
    assert!(top_level_help.stderr.is_empty());
    assert!(
        String::from_utf8_lossy(&top_level_help.stdout).contains("release-build-apply"),
        "top-level help omitted release-build-apply"
    );
    Ok(())
}

#[test]
fn release_subcommands_report_usage_on_stderr() -> std::io::Result<()> {
    for command in [
        "release-build",
        "release-build-plan",
        "release-build-apply",
        "release-finalize",
        "release-check",
    ] {
        let output = run([command])?;
        assert_eq!(output.status.code(), Some(EXIT_USAGE), "{command}");
        assert!(output.stdout.is_empty(), "{command}");
        if command == "release-build" {
            assert_eq!(output.stderr, RELEASE_BUILD_USAGE_ERROR, "{command}");
        } else {
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .starts_with("error: release command options must be explicit"),
                "{command}"
            );
        }
    }
    Ok(())
}

#[test]
fn release_subcommands_classify_missing_directories_as_environment_unmet() -> std::io::Result<()> {
    let temporary = tempdir()?;
    let missing = temporary.path().join("missing");

    let build =
        run_with_output_directory("release-build", Some("x86_64-unknown-linux-musl"), &missing)?;
    assert_environment_failure("release-build", "release output", &build);

    let plan = run_with_output_directory(
        "release-build-plan",
        Some("x86_64-unknown-linux-musl"),
        &missing,
    )?;
    assert_environment_failure("release-build-plan", "release-build plan output", &plan);

    let apply_input = temporary.path().join("apply-input");
    let apply_output = temporary.path().join("apply-output");
    std::fs::create_dir(&apply_input)?;
    std::fs::create_dir(&apply_output)?;
    let missing_input = run_apply(&missing, &apply_output)?;
    assert_environment_failure(
        "release-build-apply",
        "release-build apply input",
        &missing_input,
    );
    let missing_output = run_apply(&apply_input, &missing)?;
    assert_environment_failure(
        "release-build-apply",
        "release-build apply output",
        &missing_output,
    );

    for command in ["release-finalize", "release-check"] {
        let output = run_with_output_directory(command, None, &missing)?;
        assert_environment_failure(command, "release output", &output);
    }
    Ok(())
}

#[test]
fn release_build_plan_rejects_a_nonfresh_namespace_before_source_work() -> std::io::Result<()> {
    let temporary = tempdir()?;
    let output = temporary.path().join("plan");
    std::fs::create_dir(&output)?;
    let sentinel = output.join("sentinel.txt");
    std::fs::write(&sentinel, b"existing bytes")?;

    let result = run_with_output_directory(
        "release-build-plan",
        Some("x86_64-unknown-linux-musl"),
        &output,
    )?;
    assert_eq!(result.status.code(), Some(EXIT_ENV_UNMET));
    assert!(result.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&result.stderr)
            .contains("release-build plan output must be a fresh empty directory")
    );
    assert_eq!(std::fs::read(sentinel)?, b"existing bytes");
    assert!(!output.join("release-build-plan.json").exists());
    Ok(())
}

#[test]
fn release_build_apply_reproduces_the_golden_without_toolchain_lookup() -> std::io::Result<()> {
    const PLAN: &[u8] = include_bytes!("golden/release-build-apply/release-build-plan.json");
    const DESCRIPTOR: &[u8] =
        include_bytes!("golden/release-build-apply/release-build-apply-descriptor.json");
    const BINARY: &[u8] = include_bytes!("golden/release-build-apply/release-build-bound-binary");
    const SBOM: &[u8] = include_bytes!(concat!(
        "golden/release-build-apply/",
        "forge-0.1.0-rc.2-x86_64-unknown-linux-musl.cdx.json"
    ));

    let temporary = tempdir()?;
    let input = temporary.path().join("input");
    let output = temporary.path().join("output");
    std::fs::create_dir(&input)?;
    std::fs::create_dir(&output)?;
    std::fs::write(input.join("release-build-plan.json"), PLAN)?;
    std::fs::write(
        input.join("release-build-apply-descriptor.json"),
        DESCRIPTOR,
    )?;
    std::fs::write(input.join("release-build-bound-binary"), BINARY)?;

    let result = run_apply_with_tool_traps(&input, &output)?;
    assert_eq!(result.status.code(), Some(0));
    assert!(result.stderr.is_empty());
    assert_eq!(
        result.stdout,
        format!(
            "assembled {APPLY_BINARY_NAME} and {APPLY_SBOM_NAME} for x86_64-unknown-linux-musl; candidate output only, not builder evidence, qualification, approval, or release authority\n"
        )
        .as_bytes()
    );
    assert_eq!(std::fs::read(output.join(APPLY_BINARY_NAME))?, BINARY);
    assert_eq!(std::fs::read(output.join(APPLY_SBOM_NAME))?, SBOM);
    assert_eq!(std::fs::read(input.join("release-build-plan.json"))?, PLAN);
    assert_eq!(
        std::fs::read(input.join("release-build-apply-descriptor.json"))?,
        DESCRIPTOR
    );
    assert_eq!(
        std::fs::read(input.join("release-build-bound-binary"))?,
        BINARY
    );
    let mut output_names = std::fs::read_dir(&output)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<Vec<_>, _>>()?;
    output_names.sort();
    assert_eq!(
        output_names,
        [
            std::ffi::OsString::from(APPLY_BINARY_NAME),
            std::ffi::OsString::from(APPLY_SBOM_NAME),
        ]
    );
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

fn run_apply(input: &Path, output: &Path) -> std::io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("release-build-apply")
        .arg("--input-dir")
        .arg(input)
        .arg("--output-dir")
        .arg(output)
        .output()
}

fn run_apply_with_tool_traps(input: &Path, output: &Path) -> std::io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("release-build-apply")
        .arg("--input-dir")
        .arg(input)
        .arg("--output-dir")
        .arg(output)
        .env("PATH", "forge-release-build-apply-must-not-use-path")
        .env("CARGO", "forge-release-build-apply-must-not-use-cargo")
        .env("GIT", "forge-release-build-apply-must-not-use-git")
        .env("RUSTC", "forge-release-build-apply-must-not-use-rustc")
        .output()
}

fn assert_environment_failure(command: &str, label: &str, output: &Output) {
    assert_eq!(output.status.code(), Some(EXIT_ENV_UNMET), "{command}");
    assert!(output.stdout.is_empty(), "{command}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.starts_with(&format!(
            "error: failed to pin the existing {label} directory"
        )),
        "{command}: {stderr}"
    );
}
