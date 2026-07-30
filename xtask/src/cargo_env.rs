#[cfg(any(all(windows, target_env = "msvc"), test))]
use std::collections::BTreeMap;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt;
#[cfg(any(all(windows, target_env = "msvc"), test))]
use std::time::Duration;

#[cfg(any(all(windows, target_env = "msvc"), test))]
use forge_core::domain::{Mutability, NetworkIntent};
#[cfg(any(all(windows, target_env = "msvc"), test))]
use forge_core::path::RepoRelativePath;
use forge_core::ports::EnvPolicy;
#[cfg(any(all(windows, target_env = "msvc"), test))]
use forge_core::ports::{ExecSpec, OutputPolicy, ProcessObservation, StdinPolicy};
use forge_runtime::process::SynchronousProcessRunner;

const MSVC_PROBE_COMMAND: &str = "__forge-msvc-environment-probe";
#[cfg(any(all(windows, target_env = "msvc"), test))]
const MSVC_PROBE_MAGIC: &[u8; 9] = b"FORGEMSV1";
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
            "failed to resolve xtask for the bounded MSVC environment probe: {error}"
        ))
    })?;
    let observation = runner
        .run_with_output_hard_limit(
            &msvc_probe_spec(executable.into_os_string(), target),
            MSVC_PROBE_OUTPUT_HARD_LIMIT,
        )
        .map_err(|error| {
            CargoEnvironmentError(format!("bounded MSVC environment probe failed: {error}"))
        })?;
    require_probe_success(&observation)?;
    let environment = decode_msvc_probe_frame(&observation.stdout)
        .map_err(|error| CargoEnvironmentError(format!("invalid MSVC probe output: {error}")))?;
    apply_msvc_probe_environment(policy, environment).map_err(|error| {
        CargoEnvironmentError(format!("invalid MSVC environment projection: {error}"))
    })
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
    fn capture() -> Self {
        Self {
            values: capture_msvc_probe_values(env::var_os),
        }
    }
}

#[cfg(any(all(windows, target_env = "msvc"), test))]
fn capture_msvc_probe_values(
    mut get: impl FnMut(&'static str) -> Option<OsString>,
) -> BTreeMap<&'static str, OsString> {
    let explicit_architecture = get("VSCMD_ARG_TGT_ARCH");
    let mut values = MSVC_PROBE_BASE_INPUT_KEYS
        .iter()
        .copied()
        .filter_map(|key| get(key).map(|value| (key, value)))
        .collect::<BTreeMap<_, _>>();
    if let Some(architecture) = explicit_architecture {
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
fn msvc_probe_spec(executable: OsString, target: &str) -> ExecSpec {
    ExecSpec {
        program: executable,
        args: vec![OsString::from(MSVC_PROBE_COMMAND), OsString::from(target)],
        cwd: RepoRelativePath::root(),
        env: msvc_probe_environment(),
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
fn msvc_probe_environment() -> EnvPolicy {
    msvc_probe_environment_for(env::var_os("VSCMD_ARG_TGT_ARCH").is_some())
}

#[cfg(any(all(windows, target_env = "msvc"), test))]
fn msvc_probe_environment_for(developer_prompt_arch_is_explicit: bool) -> EnvPolicy {
    let mut policy = EnvPolicy::minimal();
    policy.inherit.extend(
        MSVC_PROBE_BASE_INPUT_KEYS
            .iter()
            .copied()
            .map(OsString::from),
    );
    if developer_prompt_arch_is_explicit {
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
fn require_probe_success(observation: &ProcessObservation) -> Result<(), CargoEnvironmentError> {
    if observation.exit_code == Some(0)
        && observation.signal.is_none()
        && !observation.timed_out
        && !observation.interrupted
        && !observation.stdout_truncated
        && !observation.stderr_truncated
    {
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
    use std::io::Write as _;
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
    let probe_environment = MsvcProbeEnvironment::capture();
    let tool = find_msvc_tools::find_tool_with_env(architecture, "link.exe", &probe_environment)
        .ok_or_else(|| {
            CargoEnvironmentError(String::from(
                "MSVC toolchain environment was not discoverable through bounded local sources",
            ))
        })?;
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
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&frame).map_err(|error| {
        CargoEnvironmentError(format!("failed to write MSVC probe output: {error}"))
    })?;
    stdout.flush().map_err(|error| {
        CargoEnvironmentError(format!("failed to flush MSVC probe output: {error}"))
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
    use std::time::Duration;

    use forge_core::domain::{Mutability, NetworkIntent};
    use forge_core::ports::{EnvPolicy, OutputPolicy, ProcessObservation, StdinPolicy};
    use forge_runtime::process::empty_process_output_digests;

    use super::{
        MSVC_PROBE_HEADER_BYTES, MSVC_PROBE_MAGIC, MSVC_PROBE_MAX_DIAGNOSTIC_BYTES,
        MSVC_PROBE_MAX_FRAME_BYTES, MSVC_PROBE_MAX_VALUE_UNITS, MSVC_PROBE_OUTPUT_HARD_LIMIT,
        MSVC_PROBE_TIMEOUT, MsvcEnvironmentKey, apply_msvc_probe_environment,
        capture_msvc_probe_values, decode_msvc_probe_frame, encode_msvc_probe_frame,
        is_cargo_build_environment_key, is_msvc_probe_input_key, msvc_probe_environment_for,
        msvc_probe_spec, require_probe_success, supported_msvc_target,
    };

    #[test]
    fn build_environment_allows_toolchain_controls_but_not_registry_tokens() {
        assert!(is_cargo_build_environment_key(OsStr::new(
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER"
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
        let spec = msvc_probe_spec(OsString::from("xtask.exe"), "x86_64-pc-windows-msvc");

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
    fn msvc_probe_input_blocks_subprocess_fallbacks_and_gates_developer_prompt() {
        let default_environment = msvc_probe_environment_for(false);
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
        let developer_environment = msvc_probe_environment_for(true);
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
        let captured = capture_msvc_probe_values(|key| ambient.get(key).cloned());
        assert_eq!(captured.len(), 1);
        assert_eq!(captured.get("PATH"), Some(&OsString::from("ambient-path")));

        ambient.insert("VSCMD_ARG_TGT_ARCH", OsString::from("x64"));
        let captured = capture_msvc_probe_values(|key| ambient.get(key).cloned());
        for key in developer_prompt_keys {
            assert!(
                captured.contains_key(key),
                "helper snapshot did not atomically capture {key}"
            );
        }
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
