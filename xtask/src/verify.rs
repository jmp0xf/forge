//! One project-owned entry point for the complete local verification contract.

#[cfg(windows)]
use std::collections::BTreeMap;
#[cfg(any(windows, test))]
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fmt;
#[cfg(windows)]
use std::fs;
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
// Windows cannot replace a running `xtask.exe`. Derive two reusable candidates from Cargo's
// effective target directory so repository Cargo configuration remains authoritative.
#[cfg(any(windows, test))]
const WINDOWS_VERIFY_TARGET_PRIMARY: &str = "xtask-verify-a";
#[cfg(any(windows, test))]
const WINDOWS_VERIFY_TARGET_SECONDARY: &str = "xtask-verify-b";
#[cfg(any(windows, test))]
const CARGO_METADATA_OUTPUT_BYTES: usize = 1024 * 1024;

#[cfg(windows)]
#[derive(Debug)]
struct WindowsVerifyTargetDirectories {
    by_cwd: BTreeMap<&'static str, Option<WindowsVerifyTargetDirectory>>,
}

#[cfg(windows)]
impl WindowsVerifyTargetDirectories {
    fn for_cwd(
        &self,
        cwd: &'static str,
    ) -> Result<Option<&WindowsVerifyTargetDirectory>, VerifyError> {
        self.by_cwd.get(cwd).map(Option::as_ref).ok_or_else(|| {
            VerifyError::internal(
                "a built-in verification working directory has no prepared Cargo target",
            )
        })
    }
}

#[cfg(any(windows, test))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct WindowsVerifyTargetDirectory {
    target_spelling: PathBuf,
    target_identity: PathBuf,
    candidate_spelling: PathBuf,
    candidate_identity: PathBuf,
}

#[cfg(windows)]
impl WindowsVerifyTargetDirectory {
    fn revalidated_spelling(&self) -> Result<&Path, VerifyError> {
        let target_identity =
            existing_directory_identity(&self.target_spelling)?.ok_or_else(|| {
                VerifyError::environment(
                    "the prepared Cargo target directory disappeared before a verification step",
                )
            })?;
        let candidate_identity = existing_directory_identity(&self.candidate_spelling)?
            .ok_or_else(|| {
                VerifyError::environment(
                    "the prepared nested Cargo target disappeared before a verification step",
                )
            })?;
        revalidate_windows_verify_target_directory(self, &target_identity, &candidate_identity)?;
        Ok(&self.candidate_spelling)
    }
}

#[cfg(any(windows, test))]
#[derive(Debug, serde::Deserialize)]
struct CargoMetadataTargetDirectory {
    target_directory: PathBuf,
}

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
    #[cfg(windows)]
    let windows_target_directories =
        prepare_windows_verify_target_directories(&runner, &cargo_env, started)?;
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

        #[cfg(windows)]
        let cargo_target_directory = windows_target_directories
            .for_cwd(step.cwd)?
            .map(WindowsVerifyTargetDirectory::revalidated_spelling)
            .transpose()?;
        #[cfg(not(windows))]
        let cargo_target_directory = None;
        let spec = step_spec(step, remaining, &cargo_env, cargo_target_directory)?;
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
    step: &VerifyStep,
    timeout: Duration,
    cargo_env: &EnvPolicy,
    cargo_target_directory: Option<&Path>,
) -> Result<ExecSpec, VerifyError> {
    let cwd = RepoRelativePath::new(step.cwd).map_err(|error| {
        VerifyError::internal(format!(
            "invalid built-in verification cwd `{}`: {error}",
            step.cwd
        ))
    })?;
    let mut env = cargo_env.clone();
    if let Some(cargo_target_directory) = cargo_target_directory {
        // `CARGO_BUILD_TARGET_DIR` and `CARGO_TARGET_DIR` both project Cargo's effective
        // `build.target-dir`. Once the original value has been resolved through `cargo metadata`,
        // keep exactly one authority for the isolated nested build.
        remove_cargo_build_target_dir(&mut env);
        env.overrides.insert(
            OsString::from("CARGO_TARGET_DIR"),
            cargo_target_directory.as_os_str().to_owned(),
        );
    }
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

fn remove_cargo_build_target_dir(env: &mut EnvPolicy) {
    // Windows environment names are case-insensitive. Remove every spelling here as well as the
    // canonical spelling so an ambient mixed-case key cannot remain a second target authority.
    env.inherit.retain(|key| {
        !key.to_string_lossy()
            .eq_ignore_ascii_case("CARGO_BUILD_TARGET_DIR")
    });
    env.overrides.retain(|key, _| {
        !key.to_string_lossy()
            .eq_ignore_ascii_case("CARGO_BUILD_TARGET_DIR")
    });
}

#[cfg(windows)]
fn prepare_windows_verify_target_directories(
    runner: &SynchronousProcessRunner,
    cargo_env: &EnvPolicy,
    started: Instant,
) -> Result<WindowsVerifyTargetDirectories, VerifyError> {
    let current_executable = canonical_current_executable()?;
    let mut by_cwd = BTreeMap::new();

    for cwd in unique_verify_working_directories() {
        let remaining = OPERATION_TIMEOUT
            .checked_sub(started.elapsed())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| {
                VerifyError::negative(
                    "Cargo target-directory discovery did not complete before the bounded verification budget expired",
                )
            })?;
        let spec = cargo_metadata_spec(cwd, remaining, cargo_env)?;
        let observation = runner
            .run_with_output_hard_limit(&spec, CARGO_METADATA_OUTPUT_BYTES as u64)
            .map_err(|error| {
                let reason = error
                    .reason()
                    .map_or("unspecified", |reason| reason.as_str());
                VerifyError::environment(format!(
                    "Cargo target-directory discovery for `{cwd}` could not complete: kind={}, reason={reason}",
                    error.kind().as_str()
                ))
            })?;
        if !observation_passed(&observation) {
            let label = format!("Cargo target-directory discovery for `{cwd}`");
            let message = failed_observation_message(&label, &observation);
            if observation.timed_out || observation.interrupted {
                return Err(VerifyError::environment(message));
            }
            return Err(VerifyError::negative(message));
        }
        if observation.stdout_truncated
            || observation.stdout_total_bytes != observation.stdout.len() as u64
        {
            return Err(VerifyError::environment(format!(
                "Cargo target-directory discovery for `{cwd}` returned incomplete stdout"
            )));
        }

        let selected = with_cargo_target_discovery_context(
            cwd,
            (|| {
                let target_directory = parse_cargo_target_directory(&observation.stdout)?;
                let target_identity = existing_directory_identity(&target_directory)?;
                match target_identity {
                    Some(target_identity) => select_windows_verify_target_dir(
                        &target_directory,
                        &target_identity,
                        &current_executable,
                        prepare_candidate_identity,
                    ),
                    None => Ok(None),
                }
            })(),
        )?;
        by_cwd.insert(cwd, selected);
    }

    Ok(WindowsVerifyTargetDirectories { by_cwd })
}

#[cfg(any(windows, test))]
fn with_cargo_target_discovery_context<T>(
    cwd: &str,
    result: Result<T, VerifyError>,
) -> Result<T, VerifyError> {
    result.map_err(|error| VerifyError {
        kind: error.kind,
        message: format!(
            "Cargo target-directory discovery for `{cwd}` failed while validating its effective target: {}",
            error.message
        ),
    })
}

#[cfg(windows)]
fn canonical_current_executable() -> Result<PathBuf, VerifyError> {
    let executable = std::env::current_exe().map_err(|error| {
        VerifyError::environment(format!(
            "failed to identify the running xtask executable ({:?})",
            error.kind()
        ))
    })?;
    fs::canonicalize(executable).map_err(|error| {
        VerifyError::environment(format!(
            "failed to resolve the running xtask executable ({:?})",
            error.kind()
        ))
    })
}

#[cfg(windows)]
fn existing_directory_identity(path: &Path) -> Result<Option<PathBuf>, VerifyError> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(VerifyError::environment(format!(
                "failed to inspect a Cargo target directory ({:?})",
                error.kind()
            )));
        }
    };
    if !metadata.is_dir() {
        return Err(VerifyError::environment(
            "Cargo metadata identified a target directory that is not a directory",
        ));
    }
    fs::canonicalize(path).map(Some).map_err(|error| {
        VerifyError::environment(format!(
            "failed to resolve a Cargo target directory ({:?})",
            error.kind()
        ))
    })
}

#[cfg(windows)]
fn prepare_candidate_identity(candidate: &Path) -> Result<PathBuf, VerifyError> {
    match fs::create_dir(candidate) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(VerifyError::environment(format!(
                "failed to create a nested Cargo target candidate ({:?})",
                error.kind()
            )));
        }
    }
    let metadata = fs::metadata(candidate).map_err(|error| {
        VerifyError::environment(format!(
            "failed to inspect a nested Cargo target candidate ({:?})",
            error.kind()
        ))
    })?;
    if !metadata.is_dir() {
        return Err(VerifyError::environment(
            "a nested Cargo target candidate is not a directory",
        ));
    }
    fs::canonicalize(candidate).map_err(|error| {
        VerifyError::environment(format!(
            "failed to resolve a nested Cargo target candidate ({:?})",
            error.kind()
        ))
    })
}

#[cfg(any(windows, test))]
fn unique_verify_working_directories() -> Vec<&'static str> {
    VERIFY_STEPS
        .iter()
        .map(|step| step.cwd)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(any(windows, test))]
fn cargo_metadata_spec(
    cwd: &'static str,
    timeout: Duration,
    cargo_env: &EnvPolicy,
) -> Result<ExecSpec, VerifyError> {
    let cwd = RepoRelativePath::new(cwd).map_err(|error| {
        VerifyError::internal(format!("invalid built-in Cargo metadata cwd: {error}"))
    })?;
    Ok(ExecSpec {
        program: OsString::from("cargo"),
        args: ["metadata", "--format-version", "1", "--no-deps", "--locked"]
            .into_iter()
            .map(OsString::from)
            .collect(),
        cwd,
        env: cargo_env.clone(),
        timeout,
        stdin: StdinPolicy::Closed,
        stdout: OutputPolicy::CaptureBounded {
            max_bytes: CARGO_METADATA_OUTPUT_BYTES,
        },
        stderr: OutputPolicy::CaptureBounded {
            max_bytes: FAILURE_DISPLAY_BYTES,
        },
        mutability: Mutability::ExternalSideEffect,
        network: NetworkIntent::Inherit,
        concurrency_key: Some(String::from("xtask-verify-metadata")),
    })
}

#[cfg(any(windows, test))]
fn parse_cargo_target_directory(bytes: &[u8]) -> Result<PathBuf, VerifyError> {
    let metadata: CargoMetadataTargetDirectory =
        serde_json::from_slice(bytes).map_err(|error| {
            VerifyError::environment(format!(
                "Cargo metadata JSON could not be parsed (line={}, column={})",
                error.line(),
                error.column()
            ))
        })?;
    if !metadata.target_directory.is_absolute() {
        return Err(VerifyError::environment(
            "Cargo metadata returned a non-absolute target directory",
        ));
    }
    Ok(metadata.target_directory)
}

#[cfg(any(windows, test))]
fn select_windows_verify_target_dir<F>(
    target_spelling: &Path,
    target_identity: &Path,
    current_executable_identity: &Path,
    mut prepare_identity: F,
) -> Result<Option<WindowsVerifyTargetDirectory>, VerifyError>
where
    F: FnMut(&Path) -> Result<PathBuf, VerifyError>,
{
    if !target_spelling.is_absolute()
        || !target_identity.is_absolute()
        || !current_executable_identity.is_absolute()
    {
        return Err(VerifyError::internal(
            "Windows nested Cargo target selection requires absolute paths",
        ));
    }
    if !current_executable_identity.starts_with(target_identity) {
        return Ok(None);
    }

    for name in [
        WINDOWS_VERIFY_TARGET_PRIMARY,
        WINDOWS_VERIFY_TARGET_SECONDARY,
    ] {
        let candidate = target_spelling.join(name);
        let candidate_identity = prepare_identity(&candidate)?;
        if !candidate_identity.is_absolute() {
            return Err(VerifyError::internal(
                "a nested Cargo target candidate resolved to a non-absolute path",
            ));
        }
        if !is_fixed_windows_verify_target_child(&candidate_identity, target_identity, name) {
            return Err(VerifyError::environment(
                "a nested Cargo target candidate resolved through an unexpected filesystem alias",
            ));
        }
        if !current_executable_identity.starts_with(&candidate_identity) {
            return Ok(Some(WindowsVerifyTargetDirectory {
                target_spelling: target_spelling.to_path_buf(),
                target_identity: target_identity.to_path_buf(),
                candidate_spelling: candidate,
                candidate_identity,
            }));
        }
    }

    Err(VerifyError::environment(
        "both nested Cargo target candidates contain the running xtask executable",
    ))
}

#[cfg(any(windows, test))]
fn is_fixed_windows_verify_target_child(
    candidate_identity: &Path,
    target_identity: &Path,
    expected_name: &str,
) -> bool {
    candidate_identity.parent() == Some(target_identity)
        && candidate_identity
            .file_name()
            .and_then(|candidate_name| candidate_name.to_str())
            .is_some_and(|candidate_name| candidate_name.eq_ignore_ascii_case(expected_name))
}

#[cfg(any(windows, test))]
fn revalidate_windows_verify_target_directory(
    prepared: &WindowsVerifyTargetDirectory,
    current_target_identity: &Path,
    current_candidate_identity: &Path,
) -> Result<(), VerifyError> {
    let expected_name = prepared
        .candidate_spelling
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| VerifyError::internal("a prepared Cargo target has no fixed child name"))?;
    if current_target_identity != prepared.target_identity
        || current_candidate_identity != prepared.candidate_identity
        || !is_fixed_windows_verify_target_child(
            current_candidate_identity,
            current_target_identity,
            expected_name,
        )
    {
        return Err(VerifyError::environment(
            "a prepared nested Cargo target changed filesystem identity before a verification step",
        ));
    }
    Ok(())
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
    use std::collections::BTreeMap;
    use std::ffi::{OsStr, OsString};
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use forge_core::domain::{Mutability, NetworkIntent};
    use forge_core::ports::{OutputPolicy, StdinPolicy};

    use crate::cargo_env::{CargoCompilationTarget, CargoNetworkMode, cargo_environment};

    use super::{
        CARGO_METADATA_OUTPUT_BYTES, COMPLETE_OUTPUT_BYTES, Enforcement, FAILURE_DISPLAY_BYTES,
        OPERATION_TIMEOUT, RETAINED_STREAM_BYTES, VERIFY_STEPS, WINDOWS_VERIFY_TARGET_PRIMARY,
        WINDOWS_VERIFY_TARGET_SECONDARY, cargo_metadata_spec, parse_cargo_target_directory,
        revalidate_windows_verify_target_directory, select_windows_verify_target_dir, step_spec,
        unique_verify_working_directories, with_cargo_target_discovery_context,
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
        let cargo_env = cargo_environment(CargoNetworkMode::Inherit, CargoCompilationTarget::Host);
        for step in VERIFY_STEPS {
            let spec = step_spec(step, Duration::from_secs(7), &cargo_env, None)?;
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
            assert!(
                !spec
                    .env
                    .overrides
                    .contains_key(OsStr::new("CARGO_TARGET_DIR"))
            );
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
    fn cargo_metadata_specs_cover_each_distinct_working_directory_with_the_prepared_environment()
    -> Result<(), Box<dyn std::error::Error>> {
        let working_directories = unique_verify_working_directories();
        assert_eq!(working_directories, vec![".", "fuzz"]);

        let mut cargo_env =
            cargo_environment(CargoNetworkMode::Inherit, CargoCompilationTarget::Host);
        cargo_env.overrides.insert(
            OsString::from("FORGE_TEST_CARGO_ENV"),
            OsString::from("preserved"),
        );
        let specs = working_directories
            .iter()
            .map(|cwd| cargo_metadata_spec(cwd, Duration::from_secs(11), &cargo_env))
            .collect::<Result<Vec<_>, _>>()?;

        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].cwd.as_path(), Path::new("."));
        assert_eq!(specs[1].cwd.as_path(), Path::new("fuzz"));
        for spec in specs {
            assert_eq!(spec.program, OsStr::new("cargo"));
            assert_eq!(
                spec.args,
                ["metadata", "--format-version", "1", "--no-deps", "--locked",]
                    .into_iter()
                    .map(OsString::from)
                    .collect::<Vec<_>>()
            );
            assert_eq!(spec.env, cargo_env);
            assert_eq!(spec.timeout, Duration::from_secs(11));
            assert_eq!(spec.stdin, StdinPolicy::Closed);
            assert_eq!(
                spec.stdout,
                OutputPolicy::CaptureBounded {
                    max_bytes: CARGO_METADATA_OUTPUT_BYTES,
                }
            );
            assert_eq!(
                spec.stderr,
                OutputPolicy::CaptureBounded {
                    max_bytes: FAILURE_DISPLAY_BYTES,
                }
            );
            assert_eq!(spec.mutability, Mutability::ExternalSideEffect);
            assert_eq!(spec.network, NetworkIntent::Inherit);
            assert_eq!(
                spec.concurrency_key.as_deref(),
                Some("xtask-verify-metadata")
            );
        }
        Ok(())
    }

    #[test]
    fn cargo_metadata_parser_requires_an_absolute_target_directory()
    -> Result<(), Box<dyn std::error::Error>> {
        let absolute = std::env::current_dir()?.join("synthetic-cargo-target");
        let complete = serde_json::to_vec(&serde_json::json!({
            "packages": [],
            "target_directory": absolute,
        }))?;
        assert_eq!(parse_cargo_target_directory(&complete)?, absolute);

        let relative = br#"{"target_directory":"target"}"#;
        assert!(parse_cargo_target_directory(relative).is_err());
        let missing = br#"{"packages":[]}"#;
        assert!(parse_cargo_target_directory(missing).is_err());
        Ok(())
    }

    #[test]
    fn cargo_target_validation_errors_preserve_kind_and_identify_the_working_directory()
    -> Result<(), Box<dyn std::error::Error>> {
        let error = match with_cargo_target_discovery_context::<()>(
            "fuzz",
            Err(super::VerifyError::environment("synthetic target failure")),
        ) {
            Ok(()) => return Err("synthetic target failure unexpectedly succeeded".into()),
            Err(error) => error,
        };

        assert_eq!(error.kind(), super::VerifyErrorKind::Environment);
        assert!(error.to_string().contains("`fuzz`"));
        assert!(error.to_string().contains("synthetic target failure"));
        Ok(())
    }

    #[test]
    fn step_target_override_changes_only_the_effective_target_directory()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut cargo_env =
            cargo_environment(CargoNetworkMode::Inherit, CargoCompilationTarget::Host);
        cargo_env.overrides.insert(
            OsString::from("FORGE_TEST_CARGO_ENV"),
            OsString::from("preserved"),
        );
        cargo_env.overrides.insert(
            OsString::from("CARGO_TARGET_DIR"),
            OsString::from("previous"),
        );
        cargo_env
            .inherit
            .insert(OsString::from("CARGO_BUILD_TARGET_DIR"));
        cargo_env
            .inherit
            .insert(OsString::from("Cargo_Build_Target_Dir"));
        cargo_env.overrides.insert(
            OsString::from("CARGO_BUILD_TARGET_DIR"),
            OsString::from("previous-build"),
        );
        cargo_env.overrides.insert(
            OsString::from("cargo_build_target_dir"),
            OsString::from("previous-build-lowercase"),
        );
        #[cfg(windows)]
        let selected = Path::new(r"C:\target\xtask-verify-a");
        #[cfg(not(windows))]
        let selected = Path::new("/target/xtask-verify-a");

        let spec = step_spec(
            &VERIFY_STEPS[0],
            Duration::from_secs(7),
            &cargo_env,
            Some(selected),
        )?;
        let mut expected = cargo_env.clone();
        expected.overrides.insert(
            OsString::from("CARGO_TARGET_DIR"),
            selected.as_os_str().to_owned(),
        );
        expected
            .inherit
            .remove(OsStr::new("CARGO_BUILD_TARGET_DIR"));
        expected
            .inherit
            .remove(OsStr::new("Cargo_Build_Target_Dir"));
        expected
            .overrides
            .remove(OsStr::new("CARGO_BUILD_TARGET_DIR"));
        expected
            .overrides
            .remove(OsStr::new("cargo_build_target_dir"));
        assert_eq!(spec.env, expected);
        assert_eq!(
            spec.env
                .overrides
                .get(OsStr::new("FORGE_TEST_CARGO_ENV"))
                .map(OsString::as_os_str),
            Some(OsStr::new("preserved"))
        );
        Ok(())
    }

    #[test]
    fn windows_target_selection_is_stable_and_avoids_candidate_junctions()
    -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(windows)]
        let target_spelling = Path::new(r"C:\spelling\target");
        #[cfg(not(windows))]
        let target_spelling = Path::new("/spelling/target");
        #[cfg(windows)]
        let target_identity = Path::new(r"C:\identity\target");
        #[cfg(not(windows))]
        let target_identity = Path::new("/identity/target");
        let current_executable = target_identity.join("debug/xtask.exe");
        let primary = target_spelling.join(WINDOWS_VERIFY_TARGET_PRIMARY);
        let secondary = target_spelling.join(WINDOWS_VERIFY_TARGET_SECONDARY);

        let mut identities = BTreeMap::new();
        identities.insert(
            WINDOWS_VERIFY_TARGET_PRIMARY,
            target_identity.join(WINDOWS_VERIFY_TARGET_PRIMARY),
        );
        identities.insert(
            WINDOWS_VERIFY_TARGET_SECONDARY,
            target_identity.join(WINDOWS_VERIFY_TARGET_SECONDARY),
        );
        let selected = select_windows_verify_target_dir(
            target_spelling,
            target_identity,
            &current_executable,
            |candidate| candidate_identity(candidate, &identities),
        )?
        .ok_or("the primary nested target was not selected")?;
        assert_eq!(selected.candidate_spelling, primary.clone());
        revalidate_windows_verify_target_directory(
            &selected,
            target_identity,
            &target_identity.join(WINDOWS_VERIFY_TARGET_PRIMARY),
        )?;
        assert!(
            revalidate_windows_verify_target_directory(
                &selected,
                target_identity,
                &target_identity.join(WINDOWS_VERIFY_TARGET_SECONDARY),
            )
            .is_err()
        );
        #[cfg(windows)]
        let replaced_target = Path::new(r"C:\replacement\target");
        #[cfg(not(windows))]
        let replaced_target = Path::new("/replacement/target");
        assert!(
            revalidate_windows_verify_target_directory(
                &selected,
                replaced_target,
                &replaced_target.join(WINDOWS_VERIFY_TARGET_PRIMARY),
            )
            .is_err()
        );

        let primary_identity = target_identity.join(WINDOWS_VERIFY_TARGET_PRIMARY);
        let current_in_primary = primary_identity.join("debug/xtask.exe");
        let selected = select_windows_verify_target_dir(
            target_spelling,
            target_identity,
            &current_in_primary,
            |candidate| candidate_identity(candidate, &identities),
        )?
        .ok_or("the secondary nested target was not selected")?;
        assert_eq!(selected.candidate_spelling, secondary);

        identities.insert(WINDOWS_VERIFY_TARGET_PRIMARY, target_identity.to_path_buf());
        assert!(
            select_windows_verify_target_dir(
                target_spelling,
                target_identity,
                &current_executable,
                |candidate| candidate_identity(candidate, &identities),
            )
            .is_err()
        );

        #[cfg(windows)]
        let outside = Path::new(r"C:\outside\xtask.exe");
        #[cfg(not(windows))]
        let outside = Path::new("/outside/xtask");
        let mut calls = 0;
        assert_eq!(
            select_windows_verify_target_dir(target_spelling, target_identity, outside, |_| {
                calls += 1;
                Err(super::VerifyError::internal(
                    "candidate preparation must not run",
                ))
            },)
            .ok(),
            Some(None)
        );
        assert_eq!(calls, 0);

        fn candidate_identity(
            candidate: &Path,
            identities: &BTreeMap<&str, PathBuf>,
        ) -> Result<PathBuf, super::VerifyError> {
            let name = candidate
                .file_name()
                .and_then(OsStr::to_str)
                .ok_or_else(|| super::VerifyError::internal("invalid synthetic candidate"))?;
            identities
                .get(name)
                .cloned()
                .ok_or_else(|| super::VerifyError::internal("missing synthetic identity"))
        }

        assert!(primary.ends_with(WINDOWS_VERIFY_TARGET_PRIMARY));
        Ok(())
    }
}
