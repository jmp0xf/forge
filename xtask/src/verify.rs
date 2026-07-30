//! One project-owned entry point for the complete local verification contract.

use std::ffi::OsString;
use std::fmt;
use std::io::{self, Write};
use std::path::Path;
#[cfg(any(windows, test))]
use std::path::PathBuf;
use std::time::{Duration, Instant};

use forge_core::domain::{Mutability, NetworkIntent};
use forge_core::path::RepoRelativePath;
use forge_core::ports::{EnvPolicy, ExecSpec, OutputPolicy, ProcessObservation, StdinPolicy};
use forge_runtime::process::SynchronousProcessRunner;

use crate::cargo_env::{CargoCompilationTarget, CargoNetworkMode, prepared_cargo_environment};

// The enclosing Forge command has a 45-minute project timeout. Reserve one minute for repository
// discovery, command setup, and Receipt persistence when this entry point is dogfooded through
// `forge evidence run verify`.
const OPERATION_TIMEOUT: Duration = Duration::from_secs(44 * 60);
const RETAINED_STREAM_BYTES: usize = 256 * 1024;
const FAILURE_DISPLAY_BYTES: usize = 16 * 1024;
const COMPLETE_OUTPUT_BYTES: u64 = 8 * 1024 * 1024;
// Windows cannot replace a running `xtask.exe`. Keep nested Cargo output in one reusable target
// directory, with a second stable candidate for an xtask that was itself built in the first.
#[cfg(any(windows, test))]
const WINDOWS_VERIFY_TARGET_PRIMARY: &str = "target/xtask-verify-a";
#[cfg(any(windows, test))]
const WINDOWS_VERIFY_TARGET_SECONDARY: &str = "target/xtask-verify-b";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Enforcement {
    Required,
    Advisory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct VerifyStep {
    label: &'static str,
    cwd: &'static str,
    args: &'static [&'static str],
    enforcement: Enforcement,
}

const VERIFY_STEPS: &[VerifyStep] = &[
    VerifyStep {
        label: "root format check",
        cwd: ".",
        args: &["fmt", "--all", "--", "--check"],
        enforcement: Enforcement::Required,
    },
    VerifyStep {
        label: "root workspace check",
        cwd: ".",
        args: &["check", "--locked", "--workspace", "--all-targets"],
        enforcement: Enforcement::Required,
    },
    VerifyStep {
        label: "root strict lint",
        cwd: ".",
        args: &[
            "clippy",
            "--locked",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
        enforcement: Enforcement::Required,
    },
    VerifyStep {
        label: "root workspace tests",
        cwd: ".",
        args: &["test", "--locked", "--workspace", "--no-fail-fast"],
        enforcement: Enforcement::Required,
    },
    VerifyStep {
        label: "fuzz format check",
        cwd: "fuzz",
        args: &["fmt", "--all", "--", "--check"],
        enforcement: Enforcement::Required,
    },
    VerifyStep {
        label: "fuzz workspace check",
        cwd: "fuzz",
        args: &["check", "--locked", "--all-targets"],
        enforcement: Enforcement::Required,
    },
    VerifyStep {
        label: "fuzz workspace tests",
        cwd: "fuzz",
        args: &["test", "--locked", "--no-fail-fast"],
        enforcement: Enforcement::Required,
    },
    VerifyStep {
        label: "bootstrap CLI",
        cwd: ".",
        args: &["run", "--locked", "-p", "forge-cli", "--", "version"],
        enforcement: Enforcement::Required,
    },
    // Keep advisory work last: it must never consume the remaining operation budget needed by a
    // required step.
    VerifyStep {
        label: "fuzz lint (advisory)",
        cwd: "fuzz",
        args: &["clippy", "--locked", "--all-targets"],
        enforcement: Enforcement::Advisory,
    },
];

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum VerifyErrorKind {
    Negative,
    Environment,
    Internal,
}

#[derive(Debug)]
pub(crate) struct VerifyError {
    kind: VerifyErrorKind,
    message: String,
}

impl VerifyError {
    #[must_use]
    pub(crate) const fn kind(&self) -> VerifyErrorKind {
        self.kind
    }

    fn negative(message: impl Into<String>) -> Self {
        Self {
            kind: VerifyErrorKind::Negative,
            message: message.into(),
        }
    }

    fn environment(message: impl Into<String>) -> Self {
        Self {
            kind: VerifyErrorKind::Environment,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            kind: VerifyErrorKind::Internal,
            message: message.into(),
        }
    }
}

impl fmt::Display for VerifyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for VerifyError {}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct VerifyReport {
    pub(crate) required_steps: usize,
    pub(crate) advisory_steps_passed: usize,
    pub(crate) advisory_steps_failed: usize,
}

pub(crate) fn run(repository: &Path) -> Result<VerifyReport, VerifyError> {
    let started = Instant::now();
    let runner = SynchronousProcessRunner::new(repository).map_err(|error| {
        VerifyError::environment(format!("failed to initialize verification runner: {error}"))
    })?;
    let cargo_env = prepared_cargo_environment(
        &runner,
        CargoNetworkMode::Inherit,
        CargoCompilationTarget::Host,
    )
    .map_err(|error| {
        VerifyError::environment(format!(
            "failed to prepare the verification Cargo environment: {error}"
        ))
    })?;
    let mut report = VerifyReport {
        required_steps: 0,
        advisory_steps_passed: 0,
        advisory_steps_failed: 0,
    };

    for step in VERIFY_STEPS {
        let Some(remaining) = OPERATION_TIMEOUT.checked_sub(started.elapsed()) else {
            if step.enforcement == Enforcement::Advisory {
                eprintln!(
                    "warning: skipped advisory step `{}` because the bounded verification budget was exhausted",
                    step.label
                );
                report.advisory_steps_failed += 1;
                continue;
            }
            return Err(VerifyError::negative(format!(
                "required step `{}` did not start before the bounded verification budget expired",
                step.label
            )));
        };
        if remaining.is_zero() {
            if step.enforcement == Enforcement::Advisory {
                eprintln!(
                    "warning: skipped advisory step `{}` because the bounded verification budget was exhausted",
                    step.label
                );
                report.advisory_steps_failed += 1;
                continue;
            }
            return Err(VerifyError::negative(format!(
                "required step `{}` did not start before the bounded verification budget expired",
                step.label
            )));
        }

        println!("verify: running {}", step.label);
        io::stdout().flush().map_err(|error| {
            VerifyError::environment(format!("failed to flush verification progress: {error}"))
        })?;

        let spec = step_spec(repository, step, remaining, &cargo_env)?;
        match runner.run_with_output_hard_limit(&spec, COMPLETE_OUTPUT_BYTES) {
            Ok(observation) if observation_passed(&observation) => {
                println!(
                    "verify: passed {} in {} ms",
                    step.label,
                    observation.duration.as_millis()
                );
                match step.enforcement {
                    Enforcement::Required => report.required_steps += 1,
                    Enforcement::Advisory => report.advisory_steps_passed += 1,
                }
            }
            Ok(observation) => {
                write_failure_output(step.label, &observation)?;
                let message = failed_observation_message(step.label, &observation);
                if step.enforcement == Enforcement::Required {
                    if observation.timed_out || observation.interrupted {
                        return Err(VerifyError::environment(message));
                    }
                    return Err(VerifyError::negative(message));
                }
                eprintln!("warning: {message}");
                report.advisory_steps_failed += 1;
            }
            Err(error) => {
                let message = format!("step `{}` could not complete: {error}", step.label);
                if step.enforcement == Enforcement::Advisory {
                    eprintln!("warning: {message}");
                    report.advisory_steps_failed += 1;
                } else {
                    return Err(VerifyError::environment(message));
                }
            }
        }
    }

    Ok(report)
}

fn step_spec(
    repository: &Path,
    step: &VerifyStep,
    timeout: Duration,
    cargo_env: &EnvPolicy,
) -> Result<ExecSpec, VerifyError> {
    let cwd = RepoRelativePath::new(step.cwd).map_err(|error| {
        VerifyError::internal(format!(
            "invalid built-in verification cwd `{}`: {error}",
            step.cwd
        ))
    })?;
    #[cfg(windows)]
    let env = {
        let mut env = cargo_env.clone();
        env.overrides.insert(
            OsString::from("CARGO_TARGET_DIR"),
            windows_verify_target_dir(repository)?.into_os_string(),
        );
        env
    };
    #[cfg(not(windows))]
    let env = {
        let _ = repository;
        cargo_env.clone()
    };
    Ok(ExecSpec {
        program: OsString::from("cargo"),
        args: step.args.iter().map(OsString::from).collect(),
        cwd,
        env,
        timeout,
        stdin: StdinPolicy::Closed,
        stdout: OutputPolicy::CaptureBounded {
            max_bytes: RETAINED_STREAM_BYTES,
        },
        stderr: OutputPolicy::CaptureBounded {
            max_bytes: RETAINED_STREAM_BYTES,
        },
        // Cargo build scripts and tests are project code and may write outside the worktree.
        mutability: Mutability::ExternalSideEffect,
        network: NetworkIntent::Inherit,
        concurrency_key: Some(String::from("xtask-verify")),
    })
}

#[cfg(windows)]
fn windows_verify_target_dir(repository: &Path) -> Result<PathBuf, VerifyError> {
    let repository = repository.canonicalize().map_err(|error| {
        VerifyError::environment(format!(
            "failed to resolve the repository before selecting a nested Cargo target directory: {error}"
        ))
    })?;
    let current_executable = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|error| {
            VerifyError::environment(format!(
                "failed to resolve the running xtask executable before selecting a nested Cargo target directory: {error}"
            ))
        })?;
    Ok(select_windows_verify_target_dir(
        &repository,
        &current_executable,
    ))
}

#[cfg(any(windows, test))]
fn select_windows_verify_target_dir(repository: &Path, current_executable: &Path) -> PathBuf {
    debug_assert!(repository.is_absolute());
    debug_assert!(current_executable.is_absolute());

    let primary = repository.join(WINDOWS_VERIFY_TARGET_PRIMARY);
    if current_executable.starts_with(&primary) {
        repository.join(WINDOWS_VERIFY_TARGET_SECONDARY)
    } else {
        primary
    }
}

fn observation_passed(observation: &ProcessObservation) -> bool {
    observation.exit_code == Some(0)
        && observation.signal.is_none()
        && !observation.timed_out
        && !observation.interrupted
}

fn failed_observation_message(label: &str, observation: &ProcessObservation) -> String {
    format!(
        "step `{label}` failed: exit_code={:?}, signal={:?}, timed_out={}, interrupted={}, stdout_bytes={}, stderr_bytes={}",
        observation.exit_code,
        observation.signal,
        observation.timed_out,
        observation.interrupted,
        observation.stdout_total_bytes,
        observation.stderr_total_bytes
    )
}

fn write_failure_output(label: &str, observation: &ProcessObservation) -> Result<(), VerifyError> {
    write_retained(
        &mut io::stdout().lock(),
        label,
        "stdout",
        &observation.stdout,
        observation.stdout_truncated,
    )?;
    write_retained(
        &mut io::stderr().lock(),
        label,
        "stderr",
        &observation.stderr,
        observation.stderr_truncated,
    )
}

fn write_retained(
    destination: &mut impl Write,
    label: &str,
    stream: &str,
    bytes: &[u8],
    truncated: bool,
) -> Result<(), VerifyError> {
    if bytes.is_empty() && !truncated {
        return Ok(());
    }
    let displayed = &bytes[..bytes.len().min(FAILURE_DISPLAY_BYTES)];
    let mut safe_display = String::with_capacity(displayed.len());
    for character in String::from_utf8_lossy(displayed).chars() {
        if character == '\n' || character == '\t' {
            safe_display.push(character);
        } else if character.is_control() {
            safe_display.extend(character.escape_default());
        } else {
            safe_display.push(character);
        }
    }
    writeln!(destination, "verify: retained {stream} for failed {label}:")
        .and_then(|()| destination.write_all(safe_display.as_bytes()))
        .and_then(|()| {
            if safe_display.ends_with('\n') {
                Ok(())
            } else {
                destination.write_all(b"\n")
            }
        })
        .and_then(|()| {
            if bytes.len() > FAILURE_DISPLAY_BYTES {
                writeln!(
                    destination,
                    "verify: {stream} display was limited to {FAILURE_DISPLAY_BYTES} retained bytes"
                )
            } else {
                Ok(())
            }
        })
        .and_then(|()| {
            if truncated {
                writeln!(
                    destination,
                    "verify: {stream} retention was truncated at {RETAINED_STREAM_BYTES} bytes"
                )
            } else {
                Ok(())
            }
        })
        .map_err(|error| {
            VerifyError::environment(format!("failed to write retained child output: {error}"))
        })
}

#[cfg(test)]
mod tests {
    use std::ffi::{OsStr, OsString};
    use std::path::Path;
    use std::time::Duration;

    use forge_core::domain::{Mutability, NetworkIntent};
    use forge_core::ports::{OutputPolicy, StdinPolicy};

    use crate::cargo_env::{CargoCompilationTarget, CargoNetworkMode, cargo_environment};

    use super::{
        COMPLETE_OUTPUT_BYTES, Enforcement, FAILURE_DISPLAY_BYTES, OPERATION_TIMEOUT,
        RETAINED_STREAM_BYTES, VERIFY_STEPS, WINDOWS_VERIFY_TARGET_PRIMARY,
        WINDOWS_VERIFY_TARGET_SECONDARY, select_windows_verify_target_dir, step_spec,
    };

    #[test]
    fn verification_plan_contains_all_required_contracts_before_advisory_work() {
        let plan: Vec<_> = VERIFY_STEPS
            .iter()
            .map(|step| (step.label, step.cwd, step.args))
            .collect();
        assert_eq!(
            plan,
            vec![
                (
                    "root format check",
                    ".",
                    &["fmt", "--all", "--", "--check"] as &[_]
                ),
                (
                    "root workspace check",
                    ".",
                    &["check", "--locked", "--workspace", "--all-targets"] as &[_],
                ),
                (
                    "root strict lint",
                    ".",
                    &[
                        "clippy",
                        "--locked",
                        "--workspace",
                        "--all-targets",
                        "--",
                        "-D",
                        "warnings",
                    ] as &[_],
                ),
                (
                    "root workspace tests",
                    ".",
                    &["test", "--locked", "--workspace", "--no-fail-fast"] as &[_],
                ),
                (
                    "fuzz format check",
                    "fuzz",
                    &["fmt", "--all", "--", "--check"] as &[_]
                ),
                (
                    "fuzz workspace check",
                    "fuzz",
                    &["check", "--locked", "--all-targets"] as &[_],
                ),
                (
                    "fuzz workspace tests",
                    "fuzz",
                    &["test", "--locked", "--no-fail-fast"] as &[_],
                ),
                (
                    "bootstrap CLI",
                    ".",
                    &["run", "--locked", "-p", "forge-cli", "--", "version"] as &[_],
                ),
                (
                    "fuzz lint (advisory)",
                    "fuzz",
                    &["clippy", "--locked", "--all-targets"] as &[_],
                ),
            ]
        );
        assert!(
            VERIFY_STEPS[..VERIFY_STEPS.len() - 1]
                .iter()
                .all(|step| step.enforcement == Enforcement::Required)
        );
        assert_eq!(
            VERIFY_STEPS.last().map(|step| step.enforcement),
            Some(Enforcement::Advisory)
        );
        assert_eq!(OPERATION_TIMEOUT, Duration::from_secs(44 * 60));
        assert_eq!(COMPLETE_OUTPUT_BYTES, 8 * 1024 * 1024);
        assert_eq!(FAILURE_DISPLAY_BYTES, 16 * 1024);
    }

    #[test]
    fn every_step_uses_argv_closed_stdin_and_a_bounded_process_contract()
    -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(windows)]
        let repository = std::env::current_dir()?.canonicalize()?;
        #[cfg(not(windows))]
        let repository = Path::new("/repository").to_path_buf();
        let cargo_env = cargo_environment(CargoNetworkMode::Inherit, CargoCompilationTarget::Host);
        for step in VERIFY_STEPS {
            let spec = step_spec(&repository, step, Duration::from_secs(7), &cargo_env)?;
            assert_eq!(spec.program, OsStr::new("cargo"));
            assert_eq!(spec.stdin, StdinPolicy::Closed);
            assert_eq!(spec.mutability, Mutability::ExternalSideEffect);
            assert_eq!(spec.network, NetworkIntent::Inherit);
            assert_eq!(spec.timeout, Duration::from_secs(7));
            assert_eq!(
                spec.stdout,
                OutputPolicy::CaptureBounded {
                    max_bytes: RETAINED_STREAM_BYTES
                }
            );
            assert_eq!(spec.stderr, spec.stdout);
            #[cfg(not(windows))]
            assert!(
                !spec
                    .env
                    .overrides
                    .contains_key(OsStr::new("CARGO_TARGET_DIR"))
            );
            #[cfg(windows)]
            {
                let target_dir = spec
                    .env
                    .overrides
                    .get(OsStr::new("CARGO_TARGET_DIR"))
                    .ok_or("Windows verify step must isolate its nested Cargo target")?;
                let target_dir = Path::new(target_dir);
                assert!(target_dir.is_absolute());
                assert!(target_dir.starts_with(&repository));
                assert!(
                    target_dir.ends_with(WINDOWS_VERIFY_TARGET_PRIMARY)
                        || target_dir.ends_with(WINDOWS_VERIFY_TARGET_SECONDARY)
                );
            }
            assert_eq!(
                spec.env
                    .overrides
                    .get(OsStr::new("RUSTUP_AUTO_INSTALL"))
                    .map(OsString::as_os_str),
                Some(OsStr::new("0"))
            );
        }
        Ok(())
    }

    #[test]
    fn windows_target_selection_is_stable_and_avoids_the_running_candidate() {
        #[cfg(windows)]
        let repository = Path::new(r"C:\repository");
        #[cfg(not(windows))]
        let repository = Path::new("/repository");
        #[cfg(windows)]
        let outside_executable = Path::new(r"C:\outside\target\debug\xtask.exe");
        #[cfg(not(windows))]
        let outside_executable = Path::new("/outside/target/debug/xtask");
        let primary = repository.join(WINDOWS_VERIFY_TARGET_PRIMARY);
        let secondary = repository.join(WINDOWS_VERIFY_TARGET_SECONDARY);

        assert_eq!(
            select_windows_verify_target_dir(repository, outside_executable),
            primary
        );
        assert_eq!(
            select_windows_verify_target_dir(repository, &primary.join("debug/xtask.exe")),
            secondary
        );
        assert_eq!(
            select_windows_verify_target_dir(repository, &secondary.join("debug/xtask.exe")),
            primary
        );
    }
}
