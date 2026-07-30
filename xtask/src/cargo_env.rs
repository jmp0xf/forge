#[cfg(any(all(windows, target_env = "msvc"), test))]
use std::collections::BTreeMap;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt;
#[cfg(any(all(windows, target_env = "msvc"), test))]
use std::path::{Path, PathBuf};
#[cfg(any(all(windows, target_env = "msvc"), test))]
use std::time::Duration;

#[cfg(any(all(windows, target_env = "msvc"), test))]
use forge_core::domain::{Mutability, NetworkIntent};
#[cfg(any(all(windows, target_env = "msvc"), test))]
use forge_core::path::RepoRelativePath;
use forge_core::ports::EnvPolicy;
#[cfg(all(windows, target_env = "msvc"))]
use forge_core::ports::ProcessError;
#[cfg(any(all(windows, target_env = "msvc"), test))]
use forge_core::ports::{ExecSpec, OutputPolicy, ProcessObservation, StdinPolicy};
use forge_runtime::process::SynchronousProcessRunner;

const MSVC_PROBE_COMMAND: &str = "__forge-msvc-environment-probe";
#[cfg(any(all(windows, target_env = "msvc"), test))]
const MSVC_PROBE_MAGIC: &[u8; 9] = b"FORGEMSV1";
#[cfg(any(all(windows, target_env = "msvc"), test))]
const MSVC_PROBE_NOT_FOUND_MAGIC: &[u8; 9] = b"FORGEMSN1";
#[cfg(any(all(windows, target_env = "msvc"), test))]
const MSVC_PROBE_HEADER_BYTES: usize = MSVC_PROBE_MAGIC.len() + 1;
#[cfg(any(all(windows, target_env = "msvc"), test))]
const MSVC_PROBE_MAX_FRAME_BYTES: usize = 1024 * 1024;
#[cfg(any(all(windows, target_env = "msvc"), test))]
// Reserve one code unit for the terminating NUL required by the Windows environment API.
const MSVC_PROBE_MAX_VALUE_UNITS: usize = 32_766;
#[cfg(any(all(windows, target_env = "msvc"), test))]
const MSVC_PROBE_MAX_DIAGNOSTIC_BYTES: usize = 16 * 1024;
#[cfg(any(all(windows, target_env = "msvc"), test))]
const MSVC_PROBE_OUTPUT_HARD_LIMIT: u64 =
    (MSVC_PROBE_MAX_FRAME_BYTES + MSVC_PROBE_MAX_DIAGNOSTIC_BYTES) as u64;
#[cfg(any(all(windows, target_env = "msvc"), test))]
const MSVC_PROBE_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(any(all(windows, target_env = "msvc"), test))]
const MSVC_VSWHERE_TIMEOUT: Duration = Duration::from_secs(15);
#[cfg(any(all(windows, target_env = "msvc"), test))]
const MSVC_VSWHERE_MAX_OUTPUT_BYTES: usize = 32 * 1024;
#[cfg(any(all(windows, target_env = "msvc"), test))]
const MSVC_VSWHERE_OUTPUT_HARD_LIMIT: u64 =
    (MSVC_VSWHERE_MAX_OUTPUT_BYTES + MSVC_PROBE_MAX_DIAGNOSTIC_BYTES) as u64;
#[cfg(any(all(windows, target_env = "msvc"), test))]
const MSVC_EXPLICIT_INSTALL_ROOT_ENV: &str = "XTASK_MSVC_INSTALL_ROOT";
#[cfg(all(windows, target_env = "msvc"))]
const MSVC_VSWHERE_RELATIVE_PATH: &str = r"Microsoft Visual Studio\Installer\vswhere.exe";
#[cfg(all(windows, target_env = "msvc"))]
const MSVC_VSWHERE_PROGRAM_FILES_KEYS: &[&str] = &["ProgramFiles(x86)", "ProgramFiles"];
#[cfg(any(all(windows, target_env = "msvc"), test))]
const MSVC_PROBE_BASE_INPUT_KEYS: &[&str] = &[
    "PATH",
    "LIB",
    "INCLUDE",
    "VCToolsVersion",
    "VSCMD_ARG_VCVARS_SPECTRE",
    "WindowsSdkDir",
    "WindowsSDKVersion",
];
#[cfg(any(all(windows, target_env = "msvc"), test))]
const MSVC_PROBE_DEVELOPER_INPUT_KEYS: &[&str] = &[
    "VCINSTALLDIR",
    "VSTEL_MSBuildProjectFullPath",
    "VSCMD_ARG_TGT_ARCH",
    "VSINSTALLDIR",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CargoNetworkMode {
    Inherit,
    Offline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CargoCompilationTarget<'a> {
    Host,
    Target(&'a str),
}

#[derive(Debug)]
pub(crate) struct CargoEnvironmentError(String);

impl fmt::Display for CargoEnvironmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for CargoEnvironmentError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
#[cfg(any(all(windows, target_env = "msvc"), test))]
enum MsvcEnvironmentKey {
    Path = 1,
    Lib = 2,
    Include = 3,
}

#[cfg(any(all(windows, target_env = "msvc"), test))]
impl MsvcEnvironmentKey {
    const COUNT: usize = 3;

    const fn name(self) -> &'static str {
        match self {
            Self::Path => "PATH",
            Self::Lib => "LIB",
            Self::Include => "INCLUDE",
        }
    }

    fn parse(value: u8) -> Result<Self, MsvcProbeProtocolError> {
        match value {
            1 => Ok(Self::Path),
            2 => Ok(Self::Lib),
            3 => Ok(Self::Include),
            _ => Err(MsvcProbeProtocolError::new(format!(
                "MSVC probe frame contains unknown environment key {value}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(any(all(windows, target_env = "msvc"), test))]
struct MsvcProbeProtocolError(String);

#[cfg(any(all(windows, target_env = "msvc"), test))]
impl MsvcProbeProtocolError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

#[cfg(any(all(windows, target_env = "msvc"), test))]
impl fmt::Display for MsvcProbeProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[cfg(any(all(windows, target_env = "msvc"), test))]
impl std::error::Error for MsvcProbeProtocolError {}

pub(crate) fn cargo_environment(
    network: CargoNetworkMode,
    _compilation_target: CargoCompilationTarget<'_>,
) -> EnvPolicy {
    let mut policy = EnvPolicy::minimal();
    policy.inherit.extend(
        env::vars_os()
            .map(|(key, _)| key)
            .filter(|key| is_cargo_build_environment_key(key)),
    );
    policy
        .overrides
        .insert(OsString::from("RUSTUP_AUTO_INSTALL"), OsString::from("0"));
    if network == CargoNetworkMode::Offline {
        policy
            .overrides
            .insert(OsString::from("CARGO_NET_OFFLINE"), OsString::from("true"));
    }
    policy
}

pub(crate) fn prepared_cargo_environment(
    runner: &SynchronousProcessRunner,
    network: CargoNetworkMode,
    compilation_target: CargoCompilationTarget<'_>,
) -> Result<EnvPolicy, CargoEnvironmentError> {
    let mut policy = cargo_environment(network, compilation_target);
    extend_windows_msvc_environment(runner, &mut policy, compilation_target)?;
    Ok(policy)
}

#[cfg(all(windows, target_env = "msvc"))]
fn extend_windows_msvc_environment(
    runner: &SynchronousProcessRunner,
    policy: &mut EnvPolicy,
    compilation_target: CargoCompilationTarget<'_>,
) -> Result<(), CargoEnvironmentError> {
    let Some(target) = windows_msvc_target(compilation_target) else {
        return Ok(());
    };
    let executable = env::current_exe().map_err(|error| {
        CargoEnvironmentError(format!(
            "failed to resolve xtask for the bounded MSVC environment probe ({:?})",
            error.kind()
        ))
    })?;
    let mut observation = run_msvc_probe(runner, &executable, target, None)?;
    if observation_reports_toolchain_not_found(&observation) {
        let installation_root = discover_msvc_installation_with_vswhere(runner)?;
        observation = run_msvc_probe(
            runner,
            &executable,
            target,
            Some(installation_root.as_os_str()),
        )?;
    }
    require_probe_success(&observation)?;
    let environment = decode_msvc_probe_frame(&observation.stdout)
        .map_err(|error| CargoEnvironmentError(format!("invalid MSVC probe output: {error}")))?;
    apply_msvc_probe_environment(policy, environment).map_err(|error| {
        CargoEnvironmentError(format!("invalid MSVC environment projection: {error}"))
    })
}

#[cfg(all(windows, target_env = "msvc"))]
fn run_msvc_probe(
    runner: &SynchronousProcessRunner,
    executable: &Path,
    target: &str,
    installation_root: Option<&OsStr>,
) -> Result<ProcessObservation, CargoEnvironmentError> {
    runner
        .run_with_output_hard_limit(
            &msvc_probe_spec(executable.as_os_str().to_owned(), target, installation_root),
            MSVC_PROBE_OUTPUT_HARD_LIMIT,
        )
        .map_err(|error| content_free_process_error("bounded MSVC environment probe", &error))
}

#[cfg(all(windows, target_env = "msvc"))]
fn discover_msvc_installation_with_vswhere(
    runner: &SynchronousProcessRunner,
) -> Result<PathBuf, CargoEnvironmentError> {
    let executable = trusted_vswhere_executable()?;
    let observation = runner
        .run_with_output_hard_limit(
            &msvc_vswhere_spec(executable.into_os_string()),
            MSVC_VSWHERE_OUTPUT_HARD_LIMIT,
        )
        .map_err(|error| content_free_process_error("bounded Visual Studio discovery", &error))?;
    require_vswhere_success(&observation)?;
    let installation_root = parse_vswhere_installation_path(&observation.stdout)?;
    canonical_installation_root(&installation_root)
}

#[cfg(all(windows, target_env = "msvc"))]
fn trusted_vswhere_executable() -> Result<PathBuf, CargoEnvironmentError> {
    for key in MSVC_VSWHERE_PROGRAM_FILES_KEYS {
        let Some(program_files) = env::var_os(key) else {
            continue;
        };
        let program_files = PathBuf::from(program_files);
        if !program_files.is_absolute() {
            return Err(CargoEnvironmentError(String::from(
                "a Program Files root for Visual Studio discovery was not absolute",
            )));
        }
        let canonical_root = std::fs::canonicalize(&program_files).map_err(|error| {
            CargoEnvironmentError(format!(
                "failed to resolve a Program Files root for Visual Studio discovery ({:?})",
                error.kind()
            ))
        })?;
        if !canonical_root.is_dir() {
            return Err(CargoEnvironmentError(String::from(
                "a Program Files root for Visual Studio discovery was not a directory",
            )));
        }

        let candidate = program_files.join(MSVC_VSWHERE_RELATIVE_PATH);
        let canonical_candidate = match std::fs::canonicalize(candidate) {
            Ok(candidate) => candidate,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(CargoEnvironmentError(format!(
                    "failed to resolve the Visual Studio discovery executable ({:?})",
                    error.kind()
                )));
            }
        };
        if !canonical_candidate.is_file()
            || !canonical_vswhere_is_confined(
                &canonical_root,
                &canonical_candidate,
                Path::new(MSVC_VSWHERE_RELATIVE_PATH),
            )
        {
            return Err(CargoEnvironmentError(String::from(
                "the Visual Studio discovery executable was outside its trusted Program Files location",
            )));
        }
        return Ok(canonical_candidate);
    }

    Err(CargoEnvironmentError(String::from(
        "a trusted Visual Studio discovery executable was not available",
    )))
}

#[cfg(any(all(windows, target_env = "msvc"), test))]
fn canonical_vswhere_is_confined(
    canonical_root: &Path,
    canonical_candidate: &Path,
    expected_relative_path: &Path,
) -> bool {
    canonical_candidate
        .strip_prefix(canonical_root)
        .is_ok_and(|relative| relative == expected_relative_path)
}

#[cfg(all(windows, target_env = "msvc"))]
fn canonical_installation_root(path: &Path) -> Result<PathBuf, CargoEnvironmentError> {
    if !path.is_absolute() {
        return Err(CargoEnvironmentError(String::from(
            "Visual Studio discovery returned a non-absolute installation root",
        )));
    }
    let root = std::fs::canonicalize(path).map_err(|error| {
        CargoEnvironmentError(format!(
            "failed to resolve the Visual Studio installation root ({:?})",
            error.kind()
        ))
    })?;
    if !root.is_dir() {
        return Err(CargoEnvironmentError(String::from(
            "Visual Studio discovery returned an installation root that was not a directory",
        )));
    }
    Ok(root)
}

#[cfg(all(windows, target_env = "msvc"))]
fn content_free_process_error(stage: &str, error: &ProcessError) -> CargoEnvironmentError {
    let reason = error
        .reason()
        .map_or("unspecified", |reason| reason.as_str());
    CargoEnvironmentError(format!(
        "{stage} failed: kind={}, reason={reason}, io_kind={:?}",
        error.kind().as_str(),
        error.io_kind()
    ))
}

#[cfg(not(all(windows, target_env = "msvc")))]
fn extend_windows_msvc_environment(
    _runner: &SynchronousProcessRunner,
    _policy: &mut EnvPolicy,
    _compilation_target: CargoCompilationTarget<'_>,
) -> Result<(), CargoEnvironmentError> {
    Ok(())
}

#[cfg(all(windows, target_env = "msvc"))]
fn windows_msvc_target(compilation_target: CargoCompilationTarget<'_>) -> Option<&str> {
    match compilation_target {
        CargoCompilationTarget::Host => match env::consts::ARCH {
            "x86_64" => Some("x86_64-pc-windows-msvc"),
            _ => None,
        },
        CargoCompilationTarget::Target(target) => supported_msvc_target(target).then_some(target),
    }
}

#[cfg(any(all(windows, target_env = "msvc"), test))]
fn supported_msvc_target(target: &str) -> bool {
    target == "x86_64-pc-windows-msvc"
}

#[cfg(all(windows, target_env = "msvc"))]
fn msvc_target_arch(target: &str) -> Option<&'static str> {
    match target {
        "x86_64-pc-windows-msvc" => Some("x86_64"),
        _ => None,
    }
}

#[cfg(test)]
fn is_msvc_probe_input_key(key: &str) -> bool {
    MSVC_PROBE_BASE_INPUT_KEYS.contains(&key) || MSVC_PROBE_DEVELOPER_INPUT_KEYS.contains(&key)
}

#[cfg(all(windows, target_env = "msvc"))]
struct MsvcProbeEnvironment {
    values: BTreeMap<&'static str, OsString>,
}

#[cfg(all(windows, target_env = "msvc"))]
impl MsvcProbeEnvironment {
    fn capture() -> Result<Self, CargoEnvironmentError> {
        let installation_root = env::var_os(MSVC_EXPLICIT_INSTALL_ROOT_ENV)
            .map(PathBuf::from)
            .map(|path| canonical_installation_root(&path))
            .transpose()?;
        Ok(Self {
            values: capture_msvc_probe_values(env::var_os, installation_root.as_deref()),
        })
    }
}

#[cfg(any(all(windows, target_env = "msvc"), test))]
fn capture_msvc_probe_values(
    mut get: impl FnMut(&'static str) -> Option<OsString>,
    installation_root: Option<&Path>,
) -> BTreeMap<&'static str, OsString> {
    let mut values = MSVC_PROBE_BASE_INPUT_KEYS
        .iter()
        .copied()
        .filter_map(|key| get(key).map(|value| (key, value)))
        .collect::<BTreeMap<_, _>>();
    if let Some(installation_root) = installation_root {
        // `find-msvc-tools` 0.1.9 treats a known-but-different Developer Prompt target as an
        // instruction to resolve the requested target directly under VSINSTALLDIR. The v0 probe
        // supports only x64, so x86 is a stable, explicit mismatch. That path-based branch runs
        // before COM and does not execute the crate's `cl.exe` or `vswhere.exe` fallbacks.
        values.insert(
            "VCINSTALLDIR",
            installation_root.join("VC").into_os_string(),
        );
        values.insert("VSINSTALLDIR", installation_root.as_os_str().to_owned());
        values.insert("VSCMD_ARG_TGT_ARCH", OsString::from("x86"));
    } else if let Some(architecture) = get("VSCMD_ARG_TGT_ARCH") {
        values.insert("VSCMD_ARG_TGT_ARCH", architecture);
        values.extend(
            MSVC_PROBE_DEVELOPER_INPUT_KEYS
                .iter()
                .copied()
                .filter(|key| *key != "VSCMD_ARG_TGT_ARCH")
                .filter_map(|key| get(key).map(|value| (key, value))),
        );
    }
    values
}

#[cfg(all(windows, target_env = "msvc"))]
impl find_msvc_tools::EnvGetter for MsvcProbeEnvironment {
    fn get_env(&self, name: &'static str) -> Option<find_msvc_tools::Env> {
        self.values
            .get(name)
            .cloned()
            .map(find_msvc_tools::Env::Owned)
    }
}

#[cfg(any(all(windows, target_env = "msvc"), test))]
fn msvc_probe_spec(
    executable: OsString,
    target: &str,
    installation_root: Option<&OsStr>,
) -> ExecSpec {
    ExecSpec {
        program: executable,
        args: vec![OsString::from(MSVC_PROBE_COMMAND), OsString::from(target)],
        cwd: RepoRelativePath::root(),
        env: msvc_probe_environment(installation_root),
        timeout: MSVC_PROBE_TIMEOUT,
        stdin: StdinPolicy::Closed,
        stdout: OutputPolicy::CaptureBounded {
            max_bytes: MSVC_PROBE_MAX_FRAME_BYTES,
        },
        stderr: OutputPolicy::CaptureBounded {
            max_bytes: MSVC_PROBE_MAX_DIAGNOSTIC_BYTES,
        },
        mutability: Mutability::ReadOnly,
        // This is intent metadata, not a sandbox claim. The probe only performs local toolchain
        // discovery and is requested to remain offline.
        network: NetworkIntent::OfflineRequested,
        concurrency_key: Some(String::from("xtask-msvc-environment-probe")),
    }
}

#[cfg(any(all(windows, target_env = "msvc"), test))]
fn msvc_vswhere_spec(executable: OsString) -> ExecSpec {
    ExecSpec {
        program: executable,
        args: [
            "-latest",
            "-products",
            "*",
            "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-property",
            "installationPath",
            "-utf8",
            "-nologo",
        ]
        .into_iter()
        .map(OsString::from)
        .collect(),
        cwd: RepoRelativePath::root(),
        env: EnvPolicy::minimal(),
        timeout: MSVC_VSWHERE_TIMEOUT,
        stdin: StdinPolicy::Closed,
        stdout: OutputPolicy::CaptureBounded {
            max_bytes: MSVC_VSWHERE_MAX_OUTPUT_BYTES,
        },
        stderr: OutputPolicy::CaptureBounded {
            max_bytes: MSVC_PROBE_MAX_DIAGNOSTIC_BYTES,
        },
        mutability: Mutability::ReadOnly,
        network: NetworkIntent::OfflineRequested,
        concurrency_key: Some(String::from("xtask-msvc-vswhere-probe")),
    }
}

#[cfg(any(all(windows, target_env = "msvc"), test))]
fn msvc_probe_environment(installation_root: Option<&OsStr>) -> EnvPolicy {
    msvc_probe_environment_for(
        env::var_os("VSCMD_ARG_TGT_ARCH").is_some(),
        installation_root,
    )
}

#[cfg(any(all(windows, target_env = "msvc"), test))]
fn msvc_probe_environment_for(
    developer_prompt_arch_is_explicit: bool,
    installation_root: Option<&OsStr>,
) -> EnvPolicy {
    let mut policy = EnvPolicy::minimal();
    policy.inherit.extend(
        MSVC_PROBE_BASE_INPUT_KEYS
            .iter()
            .copied()
            .map(OsString::from),
    );
    if let Some(installation_root) = installation_root {
        policy.overrides.insert(
            OsString::from(MSVC_EXPLICIT_INSTALL_ROOT_ENV),
            installation_root.to_owned(),
        );
    } else if developer_prompt_arch_is_explicit {
        // `find-msvc-tools` checks VSCMD_ARG_TGT_ARCH before its `cl.exe` fallback. Inheriting this
        // group atomically therefore preserves a builder-selected Developer Command Prompt while
        // keeping that fallback unreachable. ProgramFiles remains excluded, so COM failure cannot
        // activate the crate's `vswhere.exe` fallback either.
        policy.inherit.extend(
            MSVC_PROBE_DEVELOPER_INPUT_KEYS
                .iter()
                .copied()
                .map(OsString::from),
        );
    }
    policy
}

#[cfg(any(all(windows, target_env = "msvc"), test))]
fn parse_vswhere_installation_path(stdout: &[u8]) -> Result<PathBuf, CargoEnvironmentError> {
    if stdout.is_empty() || stdout.len() > MSVC_VSWHERE_MAX_OUTPUT_BYTES {
        return Err(CargoEnvironmentError(String::from(
            "Visual Studio discovery returned an empty or oversized installation root",
        )));
    }
    let output = std::str::from_utf8(stdout).map_err(|_| {
        CargoEnvironmentError(String::from(
            "Visual Studio discovery returned a non-UTF-8 installation root",
        ))
    })?;
    let mut lines = output.lines();
    let line = lines.next().ok_or_else(|| {
        CargoEnvironmentError(String::from(
            "Visual Studio discovery returned no installation root",
        ))
    })?;
    if line.is_empty() || line.trim() != line || line.contains('\0') || lines.next().is_some() {
        return Err(CargoEnvironmentError(String::from(
            "Visual Studio discovery returned an invalid installation root record",
        )));
    }
    let path = PathBuf::from(line);
    if !path.is_absolute() {
        return Err(CargoEnvironmentError(String::from(
            "Visual Studio discovery returned a non-absolute installation root",
        )));
    }
    Ok(path)
}

#[cfg(any(all(windows, target_env = "msvc"), test))]
fn require_vswhere_success(observation: &ProcessObservation) -> Result<(), CargoEnvironmentError> {
    if observation_completed_successfully(observation)
        && observation.stdout_total_bytes == observation.stdout.len() as u64
    {
        return Ok(());
    }
    Err(CargoEnvironmentError(format!(
        "Visual Studio discovery did not complete successfully: exit={:?}, signal={:?}, timed_out={}, interrupted={}, stdout_bytes={}, stdout_truncated={}, stderr_bytes={}, stderr_truncated={}",
        observation.exit_code,
        observation.signal,
        observation.timed_out,
        observation.interrupted,
        observation.stdout_total_bytes,
        observation.stdout_truncated,
        observation.stderr_total_bytes,
        observation.stderr_truncated
    )))
}

#[cfg(any(all(windows, target_env = "msvc"), test))]
fn observation_completed_successfully(observation: &ProcessObservation) -> bool {
    observation.exit_code == Some(0)
        && observation.signal.is_none()
        && !observation.timed_out
        && !observation.interrupted
        && !observation.stdout_truncated
        && !observation.stderr_truncated
}

#[cfg(any(all(windows, target_env = "msvc"), test))]
fn observation_reports_toolchain_not_found(observation: &ProcessObservation) -> bool {
    observation.exit_code == Some(2)
        && observation.signal.is_none()
        && !observation.timed_out
        && !observation.interrupted
        && !observation.stdout_truncated
        && !observation.stderr_truncated
        && observation.stdout_total_bytes == MSVC_PROBE_NOT_FOUND_MAGIC.len() as u64
        && observation.stdout == MSVC_PROBE_NOT_FOUND_MAGIC
}

#[cfg(any(all(windows, target_env = "msvc"), test))]
fn require_probe_success(observation: &ProcessObservation) -> Result<(), CargoEnvironmentError> {
    if observation_completed_successfully(observation) {
        return Ok(());
    }
    Err(CargoEnvironmentError(format!(
        "MSVC environment probe did not complete successfully: exit={:?}, signal={:?}, timed_out={}, interrupted={}, stdout_bytes={}, stdout_truncated={}, stderr_bytes={}, stderr_truncated={}",
        observation.exit_code,
        observation.signal,
        observation.timed_out,
        observation.interrupted,
        observation.stdout_total_bytes,
        observation.stdout_truncated,
        observation.stderr_total_bytes,
        observation.stderr_truncated
    )))
}

pub(crate) fn is_msvc_probe_command(command: &str) -> bool {
    command == MSVC_PROBE_COMMAND
}

#[cfg(all(windows, target_env = "msvc"))]
pub(crate) fn run_msvc_probe_helper(target: &str) -> Result<(), CargoEnvironmentError> {
    use std::os::windows::ffi::OsStrExt as _;

    if !supported_msvc_target(target) {
        return Err(CargoEnvironmentError(format!(
            "unsupported MSVC probe target `{target}`"
        )));
    }
    let architecture = msvc_target_arch(target).ok_or_else(|| {
        CargoEnvironmentError(format!("unsupported MSVC probe target `{target}`"))
    })?;
    // Capture the allowlist again inside the helper. This preserves the invariant even when the
    // hidden command is invoked directly instead of through its bounded parent: Developer Command
    // Prompt values exist only as a group containing VSCMD_ARG_TGT_ARCH, so the crate never needs
    // its `cl.exe` architecture probe. Program Files is always unavailable, preventing its
    // `vswhere.exe` fallback after COM failure.
    let probe_environment = MsvcProbeEnvironment::capture()?;
    let tool =
        match find_msvc_tools::find_tool_with_env(architecture, "link.exe", &probe_environment) {
            Some(tool) => tool,
            None => {
                write_msvc_probe_output(MSVC_PROBE_NOT_FOUND_MAGIC)?;
                return Err(CargoEnvironmentError(String::from(
                    "MSVC toolchain environment was not discoverable through bounded local sources",
                )));
            }
        };
    let environment = tool
        .env()
        .into_iter()
        .filter_map(|(key, value)| {
            canonical_msvc_tool_environment_key(key)
                .map(|key| (key, value.encode_wide().collect::<Vec<_>>()))
        })
        .collect::<Vec<_>>();
    let frame = encode_msvc_probe_frame(environment).map_err(|error| {
        CargoEnvironmentError(format!("failed to encode MSVC probe output: {error}"))
    })?;
    write_msvc_probe_output(&frame)
}

#[cfg(all(windows, target_env = "msvc"))]
fn write_msvc_probe_output(bytes: &[u8]) -> Result<(), CargoEnvironmentError> {
    use std::io::Write as _;

    let mut stdout = std::io::stdout().lock();
    stdout.write_all(bytes).map_err(|error| {
        CargoEnvironmentError(format!(
            "failed to write MSVC probe output ({:?})",
            error.kind()
        ))
    })?;
    stdout.flush().map_err(|error| {
        CargoEnvironmentError(format!(
            "failed to flush MSVC probe output ({:?})",
            error.kind()
        ))
    })
}

#[cfg(not(all(windows, target_env = "msvc")))]
pub(crate) fn run_msvc_probe_helper(_target: &str) -> Result<(), CargoEnvironmentError> {
    Err(CargoEnvironmentError(String::from(
        "MSVC environment probing is only available from a Windows MSVC xtask",
    )))
}

#[cfg(any(all(windows, target_env = "msvc"), test))]
fn encode_msvc_probe_frame<I>(entries: I) -> Result<Vec<u8>, MsvcProbeProtocolError>
where
    I: IntoIterator<Item = (MsvcEnvironmentKey, Vec<u16>)>,
{
    let mut unique_entries = BTreeMap::new();
    for (key, value) in entries {
        validate_msvc_value(key, &value)?;
        if unique_entries.insert(key, value).is_some() {
            return Err(MsvcProbeProtocolError::new(format!(
                "MSVC probe input repeats the {} record",
                key.name()
            )));
        }
    }
    let entries = unique_entries;
    if entries.len() > MsvcEnvironmentKey::COUNT {
        return Err(MsvcProbeProtocolError::new(
            "MSVC probe frame contains too many records",
        ));
    }
    let mut frame = Vec::with_capacity(MSVC_PROBE_HEADER_BYTES);
    frame.extend_from_slice(MSVC_PROBE_MAGIC);
    frame.push(u8::try_from(entries.len()).map_err(|_| {
        MsvcProbeProtocolError::new("MSVC probe record count does not fit the protocol")
    })?);
    for (key, value) in entries {
        let units = u32::try_from(value.len()).map_err(|_| {
            MsvcProbeProtocolError::new(format!("MSVC {} value is too long", key.name()))
        })?;
        let value_bytes = value.len().checked_mul(2).ok_or_else(|| {
            MsvcProbeProtocolError::new(format!("MSVC {} value length overflowed", key.name()))
        })?;
        let record_bytes = 1usize
            .checked_add(4)
            .and_then(|bytes| bytes.checked_add(value_bytes))
            .ok_or_else(|| MsvcProbeProtocolError::new("MSVC probe frame length overflowed"))?;
        if frame
            .len()
            .checked_add(record_bytes)
            .is_none_or(|length| length > MSVC_PROBE_MAX_FRAME_BYTES)
        {
            return Err(MsvcProbeProtocolError::new(format!(
                "MSVC {} value exceeds the probe frame limit",
                key.name()
            )));
        }
        frame.push(key as u8);
        frame.extend_from_slice(&units.to_le_bytes());
        for unit in value {
            frame.extend_from_slice(&unit.to_le_bytes());
        }
    }
    Ok(frame)
}

#[cfg(any(all(windows, target_env = "msvc"), test))]
fn decode_msvc_probe_frame(
    frame: &[u8],
) -> Result<BTreeMap<MsvcEnvironmentKey, Vec<u16>>, MsvcProbeProtocolError> {
    if frame.len() > MSVC_PROBE_MAX_FRAME_BYTES {
        return Err(MsvcProbeProtocolError::new(
            "MSVC probe frame exceeds its total byte limit",
        ));
    }
    if frame.len() < MSVC_PROBE_HEADER_BYTES {
        return Err(MsvcProbeProtocolError::new(
            "MSVC probe frame is truncated before its header",
        ));
    }
    if &frame[..MSVC_PROBE_MAGIC.len()] != MSVC_PROBE_MAGIC {
        return Err(MsvcProbeProtocolError::new(
            "MSVC probe frame has an invalid magic or version",
        ));
    }
    let record_count = usize::from(frame[MSVC_PROBE_MAGIC.len()]);
    if record_count > MsvcEnvironmentKey::COUNT {
        return Err(MsvcProbeProtocolError::new(
            "MSVC probe frame declares too many records",
        ));
    }

    let mut offset = MSVC_PROBE_HEADER_BYTES;
    let mut environment = BTreeMap::new();
    for _ in 0..record_count {
        let key = *frame.get(offset).ok_or_else(|| {
            MsvcProbeProtocolError::new("MSVC probe frame is truncated before a record key")
        })?;
        offset += 1;
        let length_end = offset.checked_add(4).ok_or_else(|| {
            MsvcProbeProtocolError::new("MSVC probe record length offset overflowed")
        })?;
        let encoded_length = frame.get(offset..length_end).ok_or_else(|| {
            MsvcProbeProtocolError::new("MSVC probe frame is truncated in a record length")
        })?;
        let units = u32::from_le_bytes(
            encoded_length
                .try_into()
                .map_err(|_| MsvcProbeProtocolError::new("invalid MSVC probe record length"))?,
        );
        offset = length_end;
        let units = usize::try_from(units)
            .map_err(|_| MsvcProbeProtocolError::new("MSVC probe value length overflowed"))?;
        if units > MSVC_PROBE_MAX_VALUE_UNITS {
            return Err(MsvcProbeProtocolError::new(
                "MSVC probe value exceeds the Windows environment value limit",
            ));
        }
        let value_bytes = units
            .checked_mul(2)
            .ok_or_else(|| MsvcProbeProtocolError::new("MSVC probe value length overflowed"))?;
        let value_end = offset
            .checked_add(value_bytes)
            .ok_or_else(|| MsvcProbeProtocolError::new("MSVC probe value offset overflowed"))?;
        let encoded_value = frame.get(offset..value_end).ok_or_else(|| {
            MsvcProbeProtocolError::new("MSVC probe frame is truncated in a record value")
        })?;
        offset = value_end;
        let key = MsvcEnvironmentKey::parse(key)?;
        let mut value = Vec::with_capacity(encoded_value.len() / 2);
        for bytes in encoded_value.chunks_exact(2) {
            value.push(u16::from_le_bytes([bytes[0], bytes[1]]));
        }
        validate_msvc_value(key, &value)?;
        if environment.insert(key, value).is_some() {
            return Err(MsvcProbeProtocolError::new(format!(
                "MSVC probe frame repeats the {} record",
                key.name()
            )));
        }
    }
    if offset != frame.len() {
        return Err(MsvcProbeProtocolError::new(
            "MSVC probe frame contains trailing bytes",
        ));
    }
    Ok(environment)
}

#[cfg(any(all(windows, target_env = "msvc"), test))]
fn validate_msvc_value(
    key: MsvcEnvironmentKey,
    value: &[u16],
) -> Result<(), MsvcProbeProtocolError> {
    if value.len() > MSVC_PROBE_MAX_VALUE_UNITS {
        return Err(MsvcProbeProtocolError::new(format!(
            "MSVC {} value exceeds the Windows environment value limit",
            key.name()
        )));
    }
    if value.contains(&0) {
        return Err(MsvcProbeProtocolError::new(format!(
            "MSVC {} value contains a NUL code unit",
            key.name()
        )));
    }
    Ok(())
}

#[cfg(any(all(windows, target_env = "msvc"), test))]
fn apply_msvc_probe_environment(
    policy: &mut EnvPolicy,
    environment: BTreeMap<MsvcEnvironmentKey, Vec<u16>>,
) -> Result<(), MsvcProbeProtocolError> {
    for (key, value) in environment {
        validate_msvc_value(key, &value)?;
        policy
            .overrides
            .insert(OsString::from(key.name()), os_string_from_utf16(&value)?);
    }
    Ok(())
}

#[cfg(all(windows, any(target_env = "msvc", test)))]
fn os_string_from_utf16(value: &[u16]) -> Result<OsString, MsvcProbeProtocolError> {
    use std::os::windows::ffi::OsStringExt as _;

    Ok(OsString::from_wide(value))
}

#[cfg(all(not(windows), test))]
fn os_string_from_utf16(value: &[u16]) -> Result<OsString, MsvcProbeProtocolError> {
    String::from_utf16(value).map(OsString::from).map_err(|_| {
        MsvcProbeProtocolError::new("test projection contains non-Unicode UTF-16 on this platform")
    })
}

#[cfg(all(windows, target_env = "msvc"))]
fn canonical_msvc_tool_environment_key(key: &OsStr) -> Option<MsvcEnvironmentKey> {
    let key = key.to_str()?;
    if key.eq_ignore_ascii_case("PATH") {
        Some(MsvcEnvironmentKey::Path)
    } else if key.eq_ignore_ascii_case("LIB") {
        Some(MsvcEnvironmentKey::Lib)
    } else if key.eq_ignore_ascii_case("INCLUDE") {
        Some(MsvcEnvironmentKey::Include)
    } else {
        None
    }
}

pub(crate) fn is_cargo_build_environment_key(key: &OsStr) -> bool {
    let Some(key) = key.to_str() else {
        return false;
    };
    if forge_core::fingerprint::is_secret_like_name(key) {
        return false;
    }
    let key = key.to_ascii_uppercase();
    matches!(
        key.as_str(),
        "AR" | "CC"
            | "CFLAGS"
            | "CPATH"
            | "CXX"
            | "CXXFLAGS"
            | "DEVELOPER_DIR"
            | "INCLUDE"
            | "LDFLAGS"
            | "LIB"
            | "LIBPATH"
            | "LIBRARY_PATH"
            | "MACOSX_DEPLOYMENT_TARGET"
            | "PKG_CONFIG_PATH"
            | "PROGRAMFILES"
            | "PROGRAMFILES(X86)"
            | "RANLIB"
            | "RUSTC"
            | "RUSTC_WRAPPER"
            | "RUSTC_WORKSPACE_WRAPPER"
            | "RUSTDOC"
            | "RUSTFLAGS"
            | "CARGO_BUILD_TARGET_DIR"
            | "CARGO_ENCODED_RUSTFLAGS"
            | "RUSTUP_TOOLCHAIN"
            | "SDKROOT"
            | "UNIVERSALCRTSDKDIR"
            | "UCRTVERSION"
            | "VCINSTALLDIR"
            | "VCTOOLSINSTALLDIR"
            | "WINDOWSSDKDIR"
            | "WINDOWSSDKVERSION"
    ) || [
        "AR_",
        "CC_",
        "CFLAGS_",
        "CXX_",
        "CXXFLAGS_",
        "PKG_CONFIG_",
        "RANLIB_",
        "CARGO_TARGET_",
    ]
    .iter()
    .any(|prefix| key.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::ffi::{OsStr, OsString};
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use forge_core::domain::{Mutability, NetworkIntent};
    use forge_core::ports::{EnvPolicy, OutputPolicy, ProcessObservation, StdinPolicy};
    use forge_runtime::process::empty_process_output_digests;

    use super::{
        MSVC_EXPLICIT_INSTALL_ROOT_ENV, MSVC_PROBE_HEADER_BYTES, MSVC_PROBE_MAGIC,
        MSVC_PROBE_MAX_DIAGNOSTIC_BYTES, MSVC_PROBE_MAX_FRAME_BYTES, MSVC_PROBE_MAX_VALUE_UNITS,
        MSVC_PROBE_NOT_FOUND_MAGIC, MSVC_PROBE_OUTPUT_HARD_LIMIT, MSVC_PROBE_TIMEOUT,
        MSVC_VSWHERE_MAX_OUTPUT_BYTES, MSVC_VSWHERE_OUTPUT_HARD_LIMIT, MSVC_VSWHERE_TIMEOUT,
        MsvcEnvironmentKey, apply_msvc_probe_environment, canonical_vswhere_is_confined,
        capture_msvc_probe_values, decode_msvc_probe_frame, encode_msvc_probe_frame,
        is_cargo_build_environment_key, is_msvc_probe_input_key, msvc_probe_environment_for,
        msvc_probe_spec, msvc_vswhere_spec, observation_reports_toolchain_not_found,
        parse_vswhere_installation_path, require_probe_success, require_vswhere_success,
        supported_msvc_target,
    };

    fn observation(exit_code: i32, stdout: &[u8], stderr: &[u8]) -> ProcessObservation {
        let (stdout_digest, stderr_digest) = empty_process_output_digests();
        ProcessObservation {
            exit_code: Some(exit_code),
            signal: None,
            stdout: stdout.to_vec(),
            stderr: stderr.to_vec(),
            stdout_digest,
            stderr_digest,
            stdout_total_bytes: stdout.len() as u64,
            stderr_total_bytes: stderr.len() as u64,
            stdout_truncated: false,
            stderr_truncated: false,
            duration: Duration::from_millis(1),
            timed_out: false,
            interrupted: false,
        }
    }

    #[test]
    fn build_environment_allows_toolchain_controls_but_not_registry_tokens() {
        assert!(is_cargo_build_environment_key(OsStr::new(
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER"
        )));
        assert!(is_cargo_build_environment_key(OsStr::new(
            "CARGO_BUILD_TARGET_DIR"
        )));
        assert!(is_cargo_build_environment_key(OsStr::new("RUSTC_WRAPPER")));
        assert!(is_cargo_build_environment_key(OsStr::new("ProgramFiles")));
        assert!(is_cargo_build_environment_key(OsStr::new(
            "ProgramFiles(x86)"
        )));
        assert!(!is_cargo_build_environment_key(OsStr::new(
            "CARGO_REGISTRIES_CRATES_IO_TOKEN"
        )));
        assert!(!is_cargo_build_environment_key(OsStr::new(
            "CARGO_TARGET_PRIVATE_TOKEN"
        )));
        assert!(is_cargo_build_environment_key(OsStr::new("LIB")));
    }

    #[test]
    fn msvc_targets_are_explicit_and_bounded() {
        assert!(supported_msvc_target("x86_64-pc-windows-msvc"));
        assert!(!supported_msvc_target("aarch64-pc-windows-msvc"));
        assert!(!supported_msvc_target("x86_64-pc-windows-gnu"));
    }

    #[test]
    fn msvc_probe_process_contract_is_bounded_noninteractive_and_local() {
        let spec = msvc_probe_spec(OsString::from("xtask.exe"), "x86_64-pc-windows-msvc", None);

        assert_eq!(
            spec.args,
            [
                OsString::from("__forge-msvc-environment-probe"),
                OsString::from("x86_64-pc-windows-msvc"),
            ]
        );
        assert_eq!(spec.stdin, StdinPolicy::Closed);
        assert_eq!(spec.timeout, MSVC_PROBE_TIMEOUT);
        assert_eq!(
            spec.stdout,
            OutputPolicy::CaptureBounded {
                max_bytes: MSVC_PROBE_MAX_FRAME_BYTES
            }
        );
        assert_eq!(
            spec.stderr,
            OutputPolicy::CaptureBounded {
                max_bytes: MSVC_PROBE_MAX_DIAGNOSTIC_BYTES
            }
        );
        assert_eq!(spec.mutability, Mutability::ReadOnly);
        assert_eq!(spec.network, NetworkIntent::OfflineRequested);
        assert_eq!(
            MSVC_PROBE_OUTPUT_HARD_LIMIT,
            (MSVC_PROBE_MAX_FRAME_BYTES + MSVC_PROBE_MAX_DIAGNOSTIC_BYTES) as u64
        );
    }

    #[test]
    fn msvc_vswhere_process_contract_is_bounded_noninteractive_and_local() {
        let spec = msvc_vswhere_spec(OsString::from("vswhere.exe"));

        assert_eq!(
            spec.args,
            [
                "-latest",
                "-products",
                "*",
                "-requires",
                "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                "-property",
                "installationPath",
                "-utf8",
                "-nologo",
            ]
            .map(OsString::from)
        );
        assert_eq!(spec.stdin, StdinPolicy::Closed);
        assert_eq!(spec.timeout, MSVC_VSWHERE_TIMEOUT);
        assert_eq!(
            spec.stdout,
            OutputPolicy::CaptureBounded {
                max_bytes: MSVC_VSWHERE_MAX_OUTPUT_BYTES
            }
        );
        assert_eq!(
            spec.stderr,
            OutputPolicy::CaptureBounded {
                max_bytes: MSVC_PROBE_MAX_DIAGNOSTIC_BYTES
            }
        );
        assert_eq!(spec.mutability, Mutability::ReadOnly);
        assert_eq!(spec.network, NetworkIntent::OfflineRequested);
        assert_eq!(
            MSVC_VSWHERE_OUTPUT_HARD_LIMIT,
            (MSVC_VSWHERE_MAX_OUTPUT_BYTES + MSVC_PROBE_MAX_DIAGNOSTIC_BYTES) as u64
        );
    }

    #[test]
    fn msvc_probe_input_blocks_subprocess_fallbacks_and_gates_developer_prompt() {
        let default_environment = msvc_probe_environment_for(false, None);
        for key in ["ProgramFiles", "ProgramFiles(x86)"] {
            assert!(
                !is_msvc_probe_input_key(key),
                "unexpected probe input {key}"
            );
            assert!(
                !default_environment.inherit.contains(OsStr::new(key)),
                "probe process unexpectedly inherits {key}"
            );
        }
        for key in [
            "PATH",
            "LIB",
            "INCLUDE",
            "VCToolsVersion",
            "VSCMD_ARG_VCVARS_SPECTRE",
            "WindowsSdkDir",
            "WindowsSDKVersion",
        ] {
            assert!(is_msvc_probe_input_key(key), "missing probe input {key}");
        }

        let developer_prompt_keys = [
            "VCINSTALLDIR",
            "VSTEL_MSBuildProjectFullPath",
            "VSCMD_ARG_TGT_ARCH",
            "VSINSTALLDIR",
        ];
        for key in developer_prompt_keys {
            assert!(is_msvc_probe_input_key(key), "missing probe input {key}");
            assert!(
                !default_environment.inherit.contains(OsStr::new(key)),
                "developer prompt input {key} was inherited without an explicit architecture"
            );
        }
        let developer_environment = msvc_probe_environment_for(true, None);
        for key in developer_prompt_keys {
            assert!(
                developer_environment.inherit.contains(OsStr::new(key)),
                "developer prompt input {key} was not inherited with the explicit architecture"
            );
        }

        let mut ambient = BTreeMap::from([
            ("PATH", OsString::from("ambient-path")),
            ("VCINSTALLDIR", OsString::from("vc-install")),
            ("VSTEL_MSBuildProjectFullPath", OsString::from("project")),
            ("VSINSTALLDIR", OsString::from("vs-install")),
        ]);
        let captured = capture_msvc_probe_values(|key| ambient.get(key).cloned(), None);
        assert_eq!(captured.len(), 1);
        assert_eq!(captured.get("PATH"), Some(&OsString::from("ambient-path")));

        ambient.insert("VSCMD_ARG_TGT_ARCH", OsString::from("x64"));
        let captured = capture_msvc_probe_values(|key| ambient.get(key).cloned(), None);
        for key in developer_prompt_keys {
            assert!(
                captured.contains_key(key),
                "helper snapshot did not atomically capture {key}"
            );
        }
    }

    #[test]
    fn explicit_install_root_uses_private_override_and_forces_path_based_lookup() {
        let installation_root = Path::new("trusted-visual-studio");
        let policy = msvc_probe_environment_for(true, Some(installation_root.as_os_str()));

        for key in [
            "VCINSTALLDIR",
            "VSTEL_MSBuildProjectFullPath",
            "VSCMD_ARG_TGT_ARCH",
            "VSINSTALLDIR",
            "ProgramFiles",
            "ProgramFiles(x86)",
        ] {
            assert!(
                !policy.inherit.contains(OsStr::new(key)),
                "explicit-root probe unexpectedly inherited {key}"
            );
        }
        assert_eq!(
            policy
                .overrides
                .get(OsStr::new(MSVC_EXPLICIT_INSTALL_ROOT_ENV)),
            Some(&installation_root.as_os_str().to_owned())
        );

        let ambient = BTreeMap::from([
            ("PATH", OsString::from("ambient-path")),
            ("VCINSTALLDIR", OsString::from("ambient-vc")),
            (
                "VSTEL_MSBuildProjectFullPath",
                OsString::from("ambient-project"),
            ),
            ("VSCMD_ARG_TGT_ARCH", OsString::from("x64")),
            ("VSINSTALLDIR", OsString::from("ambient-vs")),
            ("ProgramFiles", OsString::from("ambient-program-files")),
        ]);
        let captured =
            capture_msvc_probe_values(|key| ambient.get(key).cloned(), Some(installation_root));

        assert_eq!(captured.get("PATH"), Some(&OsString::from("ambient-path")));
        assert_eq!(
            captured.get("VCINSTALLDIR"),
            Some(&installation_root.join("VC").into_os_string())
        );
        assert_eq!(
            captured.get("VSINSTALLDIR"),
            Some(&installation_root.as_os_str().to_owned())
        );
        assert_eq!(
            captured.get("VSCMD_ARG_TGT_ARCH"),
            Some(&OsString::from("x86"))
        );
        assert!(!captured.contains_key("VSTEL_MSBuildProjectFullPath"));
        assert!(!captured.contains_key("ProgramFiles"));
    }

    #[test]
    fn vswhere_installation_path_parser_requires_one_absolute_utf8_record() {
        let absolute = std::env::temp_dir().join("Visual Studio");
        let mut valid = absolute.as_os_str().to_string_lossy().into_owned();
        valid.push_str("\r\n");
        assert_eq!(
            parse_vswhere_installation_path(valid.as_bytes()).ok(),
            Some(absolute)
        );

        for invalid in [
            Vec::new(),
            b"relative-installation\r\n".to_vec(),
            b"/first\n/second\n".to_vec(),
            b" /leading-space\n".to_vec(),
            b"/trailing-space \n".to_vec(),
            b"/embedded\0nul\n".to_vec(),
            vec![0xff],
        ] {
            assert!(parse_vswhere_installation_path(&invalid).is_err());
        }
        assert!(
            parse_vswhere_installation_path(&vec![b'a'; MSVC_VSWHERE_MAX_OUTPUT_BYTES + 1])
                .is_err()
        );
    }

    #[test]
    fn canonical_vswhere_confinement_requires_the_exact_relative_location() {
        let root = PathBuf::from("canonical-program-files");
        let expected = Path::new("installer").join("vswhere.exe");

        assert!(canonical_vswhere_is_confined(
            &root,
            &root.join(&expected),
            &expected
        ));
        assert!(!canonical_vswhere_is_confined(
            &root,
            &root.join("other").join("vswhere.exe"),
            &expected
        ));
        assert!(!canonical_vswhere_is_confined(
            &root,
            &PathBuf::from("outside").join(&expected),
            &expected
        ));
    }

    #[test]
    fn toolchain_not_found_fallback_requires_the_exact_bounded_marker() {
        let missing = observation(2, MSVC_PROBE_NOT_FOUND_MAGIC, b"private diagnostic");
        assert!(observation_reports_toolchain_not_found(&missing));

        let mut wrong_exit = observation(2, MSVC_PROBE_NOT_FOUND_MAGIC, b"private diagnostic");
        wrong_exit.exit_code = Some(1);
        assert!(!observation_reports_toolchain_not_found(&wrong_exit));

        let mut extra_output = observation(2, MSVC_PROBE_NOT_FOUND_MAGIC, b"private diagnostic");
        extra_output.stdout.push(0);
        extra_output.stdout_total_bytes += 1;
        assert!(!observation_reports_toolchain_not_found(&extra_output));

        let mut truncated = missing;
        truncated.stdout_truncated = true;
        assert!(!observation_reports_toolchain_not_found(&truncated));
    }

    #[test]
    fn vswhere_failure_diagnostic_does_not_replay_child_output() {
        let failed = observation(7, b"sensitive-install-root", b"sensitive-local-path");
        let error = require_vswhere_success(&failed)
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();

        assert!(error.contains("exit=Some(7)"));
        assert!(error.contains("stdout_bytes=22"));
        assert!(error.contains("stderr_bytes=20"));
        assert!(!error.contains("sensitive-install-root"));
        assert!(!error.contains("sensitive-local-path"));
    }

    #[test]
    fn msvc_probe_protocol_round_trips_utf16_code_units() -> Result<(), Box<dyn std::error::Error>>
    {
        let expected = BTreeMap::from([
            (
                MsvcEnvironmentKey::Path,
                vec![0x0043, 0x003a, 0xd83d, 0xde80],
            ),
            (MsvcEnvironmentKey::Lib, vec![0xd800, 0x0041]),
            (MsvcEnvironmentKey::Include, Vec::new()),
        ]);
        let frame = encode_msvc_probe_frame(expected.clone())?;

        assert_eq!(&frame[..MSVC_PROBE_MAGIC.len()], MSVC_PROBE_MAGIC);
        assert_eq!(decode_msvc_probe_frame(&frame)?, expected);
        Ok(())
    }

    #[test]
    fn msvc_probe_protocol_rejects_bad_duplicate_truncated_and_trailing_frames()
    -> Result<(), Box<dyn std::error::Error>> {
        let valid = encode_msvc_probe_frame([(MsvcEnvironmentKey::Path, vec![u16::from(b'C')])])?;

        let mut bad_magic = valid.clone();
        bad_magic[0] ^= 0xff;
        assert!(decode_msvc_probe_frame(&bad_magic).is_err());

        let mut unknown_key = valid.clone();
        unknown_key[MSVC_PROBE_HEADER_BYTES] = 99;
        assert!(decode_msvc_probe_frame(&unknown_key).is_err());

        let mut duplicate = valid.clone();
        duplicate[MSVC_PROBE_MAGIC.len()] = 2;
        duplicate.extend_from_slice(&valid[MSVC_PROBE_HEADER_BYTES..]);
        assert!(decode_msvc_probe_frame(&duplicate).is_err());

        assert!(decode_msvc_probe_frame(&valid[..valid.len() - 1]).is_err());

        let mut trailing = valid;
        trailing.push(0);
        assert!(decode_msvc_probe_frame(&trailing).is_err());
        Ok(())
    }

    #[test]
    fn msvc_probe_protocol_encoder_rejects_duplicate_input() {
        assert!(
            encode_msvc_probe_frame([
                (MsvcEnvironmentKey::Path, vec![1]),
                (MsvcEnvironmentKey::Path, vec![2]),
            ])
            .is_err()
        );
    }

    #[test]
    fn msvc_probe_protocol_enforces_the_total_frame_limit() {
        let oversized_units = vec![0; MSVC_PROBE_MAX_FRAME_BYTES / 2];
        assert!(encode_msvc_probe_frame([(MsvcEnvironmentKey::Path, oversized_units)]).is_err());
        assert!(decode_msvc_probe_frame(&vec![0; MSVC_PROBE_MAX_FRAME_BYTES + 1]).is_err());
    }

    #[test]
    fn msvc_probe_protocol_rejects_nul_and_oversized_environment_values()
    -> Result<(), Box<dyn std::error::Error>> {
        assert!(encode_msvc_probe_frame([(MsvcEnvironmentKey::Path, vec![0])]).is_err());
        assert!(
            encode_msvc_probe_frame([(
                MsvcEnvironmentKey::Path,
                vec![1; MSVC_PROBE_MAX_VALUE_UNITS + 1],
            )])
            .is_err()
        );

        let mut nul_frame = encode_msvc_probe_frame([(MsvcEnvironmentKey::Path, vec![1])])?;
        let last = nul_frame.len();
        nul_frame[last - 2..].copy_from_slice(&0_u16.to_le_bytes());
        assert!(decode_msvc_probe_frame(&nul_frame).is_err());

        let mut oversized_frame = Vec::from(MSVC_PROBE_MAGIC.as_slice());
        oversized_frame.push(1);
        oversized_frame.push(MsvcEnvironmentKey::Path as u8);
        oversized_frame
            .extend_from_slice(&u32::try_from(MSVC_PROBE_MAX_VALUE_UNITS + 1)?.to_le_bytes());
        assert!(decode_msvc_probe_frame(&oversized_frame).is_err());
        Ok(())
    }

    #[test]
    fn msvc_probe_failure_diagnostic_does_not_replay_child_output() {
        let (stdout_digest, stderr_digest) = empty_process_output_digests();
        let observation = ProcessObservation {
            exit_code: Some(7),
            signal: None,
            stdout: Vec::new(),
            stderr: b"sensitive-local-toolchain-path".to_vec(),
            stdout_digest,
            stderr_digest,
            stdout_total_bytes: 0,
            stderr_total_bytes: 30,
            stdout_truncated: false,
            stderr_truncated: false,
            duration: Duration::from_millis(1),
            timed_out: false,
            interrupted: false,
        };

        let error = require_probe_success(&observation)
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();
        assert!(error.contains("exit=Some(7)"));
        assert!(error.contains("stderr_bytes=30"));
        assert!(!error.contains("sensitive-local-toolchain-path"));
    }

    #[test]
    fn msvc_projection_is_three_keys_only_and_never_overrides_a_linker()
    -> Result<(), Box<dyn std::error::Error>> {
        let linker = OsString::from("repository-linker.exe");
        let linker_key = OsString::from("CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER");
        let mut policy = EnvPolicy::minimal();
        policy.overrides.insert(linker_key.clone(), linker.clone());
        let environment = BTreeMap::from([
            (
                MsvcEnvironmentKey::Path,
                "prepared-path".encode_utf16().collect(),
            ),
            (
                MsvcEnvironmentKey::Lib,
                "prepared-lib".encode_utf16().collect(),
            ),
            (
                MsvcEnvironmentKey::Include,
                "prepared-include".encode_utf16().collect(),
            ),
        ]);

        apply_msvc_probe_environment(&mut policy, environment)?;

        assert_eq!(policy.overrides.get(&linker_key), Some(&linker));
        assert_eq!(
            policy.overrides.get(OsStr::new("PATH")),
            Some(&OsString::from("prepared-path"))
        );
        assert_eq!(
            policy.overrides.get(OsStr::new("LIB")),
            Some(&OsString::from("prepared-lib"))
        );
        assert_eq!(
            policy.overrides.get(OsStr::new("INCLUDE")),
            Some(&OsString::from("prepared-include"))
        );
        assert_eq!(policy.overrides.len(), 4);
        Ok(())
    }
}
