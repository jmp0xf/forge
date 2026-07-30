//! Bounded toolchain probes for evidence dependency fingerprints.
//!
//! Probe output is untrusted and may contain host-specific data. This module validates the
//! observation and retains only the runner-computed stream digests; raw output never crosses the
//! public dependency boundary.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::time::{Duration, Instant};

use forge_core::evidence::DependencyValue;
use forge_core::fingerprint::toolchain_info_dependency_digest;
use forge_core::ports::{
    EnvPolicy, ExecSpec, Hasher, OutputPolicy, ProcessObservation, ProcessPort, StdinPolicy,
};
use forge_core::{
    CommandSpec, Confidence, Digest, Mutability, NetworkIntent, OperationControl,
    OperationControlError, Provenance, RepoRelativePath, ToolchainInfo, UnlimitedOperationControl,
};

use crate::process::SynchronousProcessRunner;

/// Behavior identifier included in every known toolchain dependency.
pub const TOOLCHAIN_PROBE_PROTOCOL_VERSION: &str = "forge.toolchain-probe/v1";

/// Maximum wall time for each version probe.
pub const TOOLCHAIN_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Default aggregate wall-time budget for one complete probe request.
pub const TOOLCHAIN_PROBE_TOTAL_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum retained bytes for each probe output stream.
pub const TOOLCHAIN_PROBE_OUTPUT_LIMIT_BYTES: usize = 64 * 1024;

/// A v0 toolchain family with an authoritative bounded probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ToolchainFamily {
    Rust,
    Go,
}

impl ToolchainFamily {
    /// Maps a detected language identifier to a supported v0 toolchain family.
    #[must_use]
    pub fn from_language_name(language: &str) -> Option<Self> {
        match language {
            "rust" => Some(Self::Rust),
            "go" => Some(Self::Go),
            _ => None,
        }
    }
}

/// A command dependency for which v0 has a fixed, read-only probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ToolchainProbeKind {
    Cargo,
    Rustc,
    CargoFmt,
    CargoClippy,
    Go,
    Gofmt,
}

impl ToolchainProbeKind {
    /// Stable name used by doctor diagnostics and completeness checks.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cargo => "cargo",
            Self::Rustc => "rustc",
            Self::CargoFmt => "cargo-fmt",
            Self::CargoClippy => "cargo-clippy",
            Self::Go => "go",
            Self::Gofmt => "gofmt",
        }
    }
}

/// Classifies the complete fixed probe set required by one supported project command.
///
/// The allowlist is intentionally exact. Wrapper commands, explicit executable paths, Cargo
/// toolchain selectors, plugins, and unknown subcommands return `None` rather than being guessed
/// from a program-name substring. Doctor and Evidence share this boundary so availability checks
/// and reusable dependency fingerprints cannot drift apart.
#[must_use]
pub fn required_probes_for_command(command: &CommandSpec) -> Option<BTreeSet<ToolchainProbeKind>> {
    if command.program == OsStr::new("rustc") {
        return Some(BTreeSet::from([ToolchainProbeKind::Rustc]));
    }
    if command.program == OsStr::new("gofmt") {
        return Some(BTreeSet::from([
            ToolchainProbeKind::Go,
            ToolchainProbeKind::Gofmt,
        ]));
    }
    let subcommand = command.args.first()?.to_str()?;
    if command.program == OsStr::new("cargo") {
        return match subcommand {
            "check" | "test" | "build" => Some(BTreeSet::from([
                ToolchainProbeKind::Cargo,
                ToolchainProbeKind::Rustc,
            ])),
            "fmt" => Some(BTreeSet::from([
                ToolchainProbeKind::Cargo,
                ToolchainProbeKind::CargoFmt,
            ])),
            "clippy" => Some(BTreeSet::from([
                ToolchainProbeKind::Cargo,
                ToolchainProbeKind::Rustc,
                ToolchainProbeKind::CargoClippy,
            ])),
            _ => None,
        };
    }
    if command.program == OsStr::new("go") {
        return matches!(subcommand, "test" | "build" | "vet")
            .then(|| BTreeSet::from([ToolchainProbeKind::Go]));
    }
    None
}

/// Stable failure classes for one bounded version probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ToolchainProbeFailure {
    ExecutableUnavailable,
    Failed,
    TimedOut,
    Interrupted,
    Truncated,
    Malformed,
    RuntimeUnavailable,
}

/// Sanitized tool versions and typed failures from one complete probe request.
///
/// Raw stdout, stderr, host triples, paths, and environment values never cross this boundary.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ToolchainVersionReport {
    versions: BTreeMap<String, String>,
    proven: BTreeSet<String>,
    failures: BTreeMap<String, ToolchainProbeFailure>,
}

impl ToolchainVersionReport {
    #[must_use]
    pub fn versions(&self) -> &BTreeMap<String, String> {
        &self.versions
    }

    /// Required executable capabilities proven by their fixed probes.
    #[must_use]
    pub fn proven(&self) -> &BTreeSet<String> {
        &self.proven
    }

    #[must_use]
    pub fn failures(&self) -> &BTreeMap<String, ToolchainProbeFailure> {
        &self.failures
    }
}

/// Complete, deterministic inputs to a toolchain dependency probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolchainProbeRequest {
    cwd: RepoRelativePath,
    environment: EnvPolicy,
    probes: BTreeSet<ToolchainProbeKind>,
    total_timeout: Duration,
}

impl ToolchainProbeRequest {
    /// Creates a request with the normal minimal inherited environment.
    #[must_use]
    pub fn new(cwd: RepoRelativePath, families: impl IntoIterator<Item = ToolchainFamily>) -> Self {
        let mut probes = BTreeSet::new();
        for family in families {
            match family {
                ToolchainFamily::Rust => {
                    probes.extend([ToolchainProbeKind::Cargo, ToolchainProbeKind::Rustc]);
                }
                ToolchainFamily::Go => {
                    probes.insert(ToolchainProbeKind::Go);
                }
            }
        }
        Self {
            cwd,
            environment: EnvPolicy::minimal(),
            probes,
            total_timeout: TOOLCHAIN_PROBE_TOTAL_TIMEOUT,
        }
    }

    /// Creates a request for an already classified set of safe v0 probes.
    #[must_use]
    pub fn for_probes(
        cwd: RepoRelativePath,
        environment: EnvPolicy,
        probes: impl IntoIterator<Item = ToolchainProbeKind>,
    ) -> Self {
        Self {
            cwd,
            environment,
            probes: probes.into_iter().collect(),
            total_timeout: TOOLCHAIN_PROBE_TOTAL_TIMEOUT,
        }
    }

    /// Creates a request matching one project's command cwd and explicit environment overrides.
    #[must_use]
    pub fn for_command(
        command: &CommandSpec,
        families: impl IntoIterator<Item = ToolchainFamily>,
    ) -> Self {
        Self::new(command.cwd.clone(), families)
            .with_environment(EnvPolicy::minimal_with_overrides(command.env.clone()))
    }

    /// Replaces the environment supplied to every probe.
    #[must_use]
    pub fn with_environment(mut self, environment: EnvPolicy) -> Self {
        self.environment = environment;
        self
    }

    /// Bounds the complete request; each individual probe remains capped at five seconds.
    #[must_use]
    pub fn with_total_timeout(mut self, timeout: Duration) -> Self {
        self.total_timeout = timeout;
        self
    }
}

/// Probes every requested family through the unified process runner and returns one dependency.
///
/// Every required probe must start, finish successfully, and produce complete bounded output.
/// Unsupported, missing, malformed, timed-out, interrupted, or failed probes conservatively
/// return [`DependencyValue::Unknown`].
#[must_use]
pub fn probe_toolchain_dependency_digest<H: Hasher + ?Sized>(
    runner: &SynchronousProcessRunner,
    request: &ToolchainProbeRequest,
    hasher: &H,
) -> DependencyValue<Digest> {
    probe_with_process_controlled(runner, request, hasher, &UnlimitedOperationControl)
}

/// Probes one dependency under the caller's shared command-wide deadline.
#[must_use]
pub fn probe_toolchain_dependency_digest_controlled<H: Hasher + ?Sized>(
    runner: &SynchronousProcessRunner,
    request: &ToolchainProbeRequest,
    hasher: &H,
    control: &dyn OperationControl,
) -> DependencyValue<Digest> {
    probe_with_process_controlled(runner, request, hasher, control)
}

/// Reads normalized versions for every required v0 toolchain through the bounded runner.
///
/// A capability is proven only after its complete fixed probe set succeeds. Version-bearing probes
/// additionally return a bounded normalized version; `gofmt` has no version interface and is
/// represented only in [`ToolchainVersionReport::proven`]. Arbitrary process text is never retained.
#[must_use]
pub fn probe_toolchain_versions(
    runner: &SynchronousProcessRunner,
    request: &ToolchainProbeRequest,
) -> ToolchainVersionReport {
    probe_versions_with_process_controlled(runner, request, &UnlimitedOperationControl)
}

/// Reads normalized versions under the caller's shared command-wide deadline.
#[must_use]
pub fn probe_toolchain_versions_controlled(
    runner: &SynchronousProcessRunner,
    request: &ToolchainProbeRequest,
    control: &dyn OperationControl,
) -> ToolchainVersionReport {
    probe_versions_with_process_controlled(runner, request, control)
}

#[cfg(test)]
fn probe_with_process<P, H>(
    process: &P,
    request: &ToolchainProbeRequest,
    hasher: &H,
) -> DependencyValue<Digest>
where
    P: ProcessPort + ?Sized,
    H: Hasher + ?Sized,
{
    probe_with_process_controlled(process, request, hasher, &UnlimitedOperationControl)
}

#[cfg(test)]
fn probe_versions_with_process<P>(
    process: &P,
    request: &ToolchainProbeRequest,
) -> ToolchainVersionReport
where
    P: ProcessPort + ?Sized,
{
    probe_versions_with_process_controlled(process, request, &UnlimitedOperationControl)
}

fn probe_with_process_controlled<P, H>(
    process: &P,
    request: &ToolchainProbeRequest,
    hasher: &H,
    control: &dyn OperationControl,
) -> DependencyValue<Digest>
where
    P: ProcessPort + ?Sized,
    H: Hasher + ?Sized,
{
    if request.probes.is_empty() {
        return DependencyValue::Unknown;
    }

    let mut values = std::collections::BTreeMap::from([(
        String::from("probe.protocol"),
        String::from(TOOLCHAIN_PROBE_PROTOCOL_VERSION),
    )]);
    let mut provenance = Vec::new();
    let started = Instant::now();
    for kind in &request.probes {
        for probe in probes_for(*kind) {
            let Some(request_timeout) = remaining_probe_timeout(request, started) else {
                return DependencyValue::Unknown;
            };
            let Ok(permit) = control.checkpoint() else {
                return DependencyValue::Unknown;
            };
            let timeout = permit.cap(request_timeout);
            let spec = probe.exec_spec(request, timeout);
            let observation = match process.run(&spec) {
                Ok(observation) if is_complete_success(&observation) => observation,
                Ok(_) | Err(_) => return DependencyValue::Unknown,
            };
            values.insert(
                format!("{}.stdout-digest", probe.id),
                observation.stdout_digest.as_str().to_owned(),
            );
            values.insert(
                format!("{}.stderr-digest", probe.id),
                observation.stderr_digest.as_str().to_owned(),
            );
            provenance.push(probe.provenance());
        }
    }

    let toolchain = ToolchainInfo::new(values, provenance, Confidence::High);
    match toolchain_info_dependency_digest(hasher, &toolchain) {
        Ok(dependency) => dependency,
        Err(_) => DependencyValue::Unknown,
    }
}

fn probe_versions_with_process_controlled<P>(
    process: &P,
    request: &ToolchainProbeRequest,
    control: &dyn OperationControl,
) -> ToolchainVersionReport
where
    P: ProcessPort + ?Sized,
{
    let mut report = ToolchainVersionReport::default();
    let started = Instant::now();
    for kind in &request.probes {
        let mut observations = BTreeMap::new();
        for probe in probes_for(*kind) {
            let Some(request_timeout) = remaining_probe_timeout(request, started) else {
                record_failure(&mut report, kind.as_str(), ToolchainProbeFailure::TimedOut);
                break;
            };
            let permit = match control.checkpoint() {
                Ok(permit) => permit,
                Err(error) => {
                    record_failure(&mut report, kind.as_str(), control_probe_failure(error));
                    break;
                }
            };
            let timeout = permit.cap(request_timeout);
            match process.run(&probe.exec_spec(request, timeout)) {
                Ok(observation) => match version_observation_failure(&observation) {
                    Some(failure) => {
                        record_failure(&mut report, kind.as_str(), failure);
                        break;
                    }
                    None => {
                        observations.insert(probe.id, observation);
                    }
                },
                Err(error) => {
                    let failure = match error.kind() {
                        forge_core::ports::ProcessErrorKind::ExecutableUnavailable
                        | forge_core::ports::ProcessErrorKind::PermissionDenied => {
                            ToolchainProbeFailure::ExecutableUnavailable
                        }
                        forge_core::ports::ProcessErrorKind::InvalidRepositoryRoot
                        | forge_core::ports::ProcessErrorKind::InvalidWorkingDirectory
                        | forge_core::ports::ProcessErrorKind::InvalidEnvironment
                        | forge_core::ports::ProcessErrorKind::UnsupportedProgram
                        | forge_core::ports::ProcessErrorKind::Spawn
                        | forge_core::ports::ProcessErrorKind::ProcessTree
                        | forge_core::ports::ProcessErrorKind::Output
                        | forge_core::ports::ProcessErrorKind::Wait => {
                            ToolchainProbeFailure::RuntimeUnavailable
                        }
                    };
                    record_failure(&mut report, kind.as_str(), failure);
                    break;
                }
            }
        }
        if report.failures.contains_key(kind.as_str()) {
            continue;
        }
        record_probe_success(&mut report, *kind, &observations);
    }

    report
}

const fn control_probe_failure(error: OperationControlError) -> ToolchainProbeFailure {
    match error {
        OperationControlError::TimedOut => ToolchainProbeFailure::TimedOut,
        OperationControlError::Interrupted => ToolchainProbeFailure::Interrupted,
    }
}

fn remaining_probe_timeout(request: &ToolchainProbeRequest, started: Instant) -> Option<Duration> {
    let remaining = request.total_timeout.checked_sub(started.elapsed())?;
    if remaining.is_zero() {
        None
    } else {
        Some(remaining.min(TOOLCHAIN_PROBE_TIMEOUT))
    }
}

fn record_probe_success(
    report: &mut ToolchainVersionReport,
    kind: ToolchainProbeKind,
    observations: &BTreeMap<&'static str, ProcessObservation>,
) {
    if kind == ToolchainProbeKind::Gofmt {
        if observations
            .get("go.gofmt-capability")
            .is_some_and(|observation| is_gofmt_help(&observation.stdout, &observation.stderr))
        {
            report.proven.insert(kind.as_str().to_owned());
        } else {
            record_failure(report, kind.as_str(), ToolchainProbeFailure::Malformed);
        }
        return;
    }
    let version = match kind {
        ToolchainProbeKind::Cargo => observations
            .get("rust.cargo-version")
            .and_then(|observation| parse_release_version(&observation.stdout))
            .map(|version| ("cargo", version)),
        ToolchainProbeKind::Rustc => observations
            .get("rust.rustc-version")
            .and_then(|observation| parse_release_version(&observation.stdout))
            .map(|version| ("rustc", version)),
        ToolchainProbeKind::CargoFmt => observations
            .get("rust.cargo-fmt-version")
            .and_then(|observation| parse_component_version(&observation.stdout, "rustfmt"))
            .map(|version| ("rustfmt", version)),
        ToolchainProbeKind::CargoClippy => observations
            .get("rust.cargo-clippy-version")
            .and_then(|observation| parse_component_version(&observation.stdout, "clippy"))
            .map(|version| ("clippy", version)),
        ToolchainProbeKind::Go => {
            let version = observations
                .get("go.version")
                .and_then(|observation| parse_go_version(&observation.stdout));
            let environment_version = observations
                .get("go.environment")
                .and_then(|observation| parse_go_environment_version(&observation.stdout));
            version
                .filter(|version| Some(version.as_str()) == environment_version.as_deref())
                .map(|version| ("go", version))
        }
        // The capability-only probe returns above. Keep this fallback fail-closed so a future
        // refactor cannot turn an internal branch mismatch into a process panic.
        ToolchainProbeKind::Gofmt => None,
    };
    match version {
        Some((version_name, version)) => {
            report.proven.insert(kind.as_str().to_owned());
            report.versions.insert(version_name.to_owned(), version);
        }
        None => record_failure(report, kind.as_str(), ToolchainProbeFailure::Malformed),
    }
}

fn version_observation_failure(observation: &ProcessObservation) -> Option<ToolchainProbeFailure> {
    if observation.interrupted {
        return Some(ToolchainProbeFailure::Interrupted);
    }
    if observation.timed_out {
        return Some(ToolchainProbeFailure::TimedOut);
    }
    if observation.exit_code != Some(0) || observation.signal.is_some() {
        return Some(ToolchainProbeFailure::Failed);
    }
    if observation.stdout_truncated
        || observation.stderr_truncated
        || observation.stdout_total_bytes > TOOLCHAIN_PROBE_OUTPUT_LIMIT_BYTES as u64
        || observation.stderr_total_bytes > TOOLCHAIN_PROBE_OUTPUT_LIMIT_BYTES as u64
        || observation.stdout_total_bytes != observation.stdout.len() as u64
        || observation.stderr_total_bytes != observation.stderr.len() as u64
    {
        return Some(ToolchainProbeFailure::Truncated);
    }
    None
}

fn record_failure(
    report: &mut ToolchainVersionReport,
    tool: &'static str,
    failure: ToolchainProbeFailure,
) {
    let should_replace = report
        .failures
        .get(tool)
        .is_none_or(|current| failure_priority(failure) > failure_priority(*current));
    if should_replace {
        report.failures.insert(tool.to_owned(), failure);
    }
    report.proven.remove(tool);
    report.versions.remove(tool);
}

const fn failure_priority(failure: ToolchainProbeFailure) -> u8 {
    match failure {
        ToolchainProbeFailure::Malformed => 1,
        ToolchainProbeFailure::Truncated => 2,
        ToolchainProbeFailure::Failed => 3,
        ToolchainProbeFailure::ExecutableUnavailable => 4,
        ToolchainProbeFailure::RuntimeUnavailable => 5,
        ToolchainProbeFailure::TimedOut => 6,
        ToolchainProbeFailure::Interrupted => 7,
    }
}

fn parse_release_version(output: &[u8]) -> Option<String> {
    let output = std::str::from_utf8(output).ok()?;
    let candidate = output
        .lines()
        .find_map(|line| line.strip_prefix("release: "))?;
    valid_version_token(candidate).then(|| candidate.to_owned())
}

fn parse_component_version(output: &[u8], component: &str) -> Option<String> {
    let output = std::str::from_utf8(output).ok()?;
    let mut fields = output.lines().next()?.split_ascii_whitespace();
    if fields.next()? != component {
        return None;
    }
    let candidate = fields.next()?;
    valid_version_token(candidate).then(|| candidate.to_owned())
}

fn parse_go_version(output: &[u8]) -> Option<String> {
    let output = std::str::from_utf8(output).ok()?;
    let mut lines = output.lines();
    let fields = lines.next()?.split_ascii_whitespace().collect::<Vec<_>>();
    if lines.next().is_some() || fields.len() < 4 || fields[0] != "go" || fields[1] != "version" {
        return None;
    }
    let (goos, goarch) = fields.last()?.split_once('/')?;
    if !valid_platform_token(goos) || !valid_platform_token(goarch) {
        return None;
    }
    normalize_go_version(&fields[2..fields.len() - 1].join(" "))
}

fn parse_go_environment_version(output: &[u8]) -> Option<String> {
    let output = std::str::from_utf8(output).ok()?;
    let mut lines = output.lines();
    let goos = lines.next()?;
    let goarch = lines.next()?;
    let version = lines.next()?;
    if lines.next().is_some() || !valid_platform_token(goos) || !valid_platform_token(goarch) {
        return None;
    }
    normalize_go_version(version)
}

fn normalize_go_version(candidate: &str) -> Option<String> {
    if candidate.len() > 160 || !candidate.is_ascii() {
        return None;
    }
    if !candidate.contains(' ') {
        return valid_go_revision(candidate).then(|| candidate.to_owned());
    }
    let mut fields = candidate.split_ascii_whitespace();
    if fields.next()? != "devel" {
        return None;
    }
    let revision = fields.next()?;
    if !valid_go_revision(revision) {
        return None;
    }
    if fields.any(|field| {
        field.is_empty()
            || field.len() > 32
            || !field.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'-' | b'+' | b'.')
            })
    }) {
        return None;
    }
    Some(format!("devel {revision}"))
}

fn valid_go_revision(candidate: &str) -> bool {
    candidate
        .strip_prefix("go")
        .and_then(|version| version.bytes().next())
        .is_some_and(|byte| byte.is_ascii_digit())
        && valid_version_token(candidate)
}

fn is_gofmt_help(stdout: &[u8], stderr: &[u8]) -> bool {
    [stdout, stderr].into_iter().any(|stream| {
        std::str::from_utf8(stream)
            .ok()
            .is_some_and(|text| text.lines().next() == Some("usage: gofmt [flags] [path ...]"))
    })
}

fn valid_platform_token(candidate: &str) -> bool {
    !candidate.is_empty()
        && candidate.len() <= 64
        && candidate
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn valid_version_token(candidate: &str) -> bool {
    !candidate.is_empty()
        && candidate.len() <= 64
        && candidate.bytes().any(|byte| byte.is_ascii_digit())
        && candidate
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'+'))
}

#[derive(Debug, Clone, Copy)]
struct Probe {
    id: &'static str,
    program: &'static str,
    args: &'static [&'static str],
    rule_id: &'static str,
    disable_rustup_auto_install: bool,
}

impl Probe {
    fn exec_spec(self, request: &ToolchainProbeRequest, timeout: Duration) -> ExecSpec {
        let mut environment = request.environment.clone();
        if self.disable_rustup_auto_install {
            environment
                .overrides
                .insert(OsString::from("RUSTUP_AUTO_INSTALL"), OsString::from("0"));
        }
        ExecSpec {
            program: OsString::from(self.program),
            args: self.args.iter().map(OsString::from).collect(),
            cwd: request.cwd.clone(),
            env: environment,
            timeout,
            stdin: StdinPolicy::Closed,
            stdout: OutputPolicy::CaptureBounded {
                max_bytes: TOOLCHAIN_PROBE_OUTPUT_LIMIT_BYTES,
            },
            stderr: OutputPolicy::CaptureBounded {
                max_bytes: TOOLCHAIN_PROBE_OUTPUT_LIMIT_BYTES,
            },
            mutability: Mutability::ReadOnly,
            network: NetworkIntent::OfflineRequested,
            concurrency_key: None,
        }
    }

    fn provenance(self) -> Provenance {
        Provenance {
            rule_id: String::from(self.rule_id),
            source_path: None,
            source_range: None,
            detail: format!(
                "Observed {} through the bounded argv-only process runner",
                self.id
            ),
        }
    }
}

const RUST_PROBES: &[Probe] = &[
    Probe {
        id: "rust.cargo-version",
        program: "cargo",
        args: &["--version", "--verbose"],
        rule_id: "runtime.toolchain.rust.cargo-version.v1",
        disable_rustup_auto_install: true,
    },
    Probe {
        id: "rust.rustc-version",
        program: "rustc",
        args: &["-vV"],
        rule_id: "runtime.toolchain.rust.rustc-version.v1",
        disable_rustup_auto_install: true,
    },
];

const CARGO_FMT_PROBES: &[Probe] = &[Probe {
    id: "rust.cargo-fmt-version",
    program: "cargo",
    args: &["fmt", "--version"],
    rule_id: "runtime.toolchain.rust.cargo-fmt-version.v1",
    disable_rustup_auto_install: true,
}];

const CARGO_CLIPPY_PROBES: &[Probe] = &[Probe {
    id: "rust.cargo-clippy-version",
    program: "cargo",
    args: &["clippy", "--version"],
    rule_id: "runtime.toolchain.rust.cargo-clippy-version.v1",
    disable_rustup_auto_install: true,
}];

const GO_PROBES: &[Probe] = &[
    Probe {
        id: "go.version",
        program: "go",
        args: &["version"],
        rule_id: "runtime.toolchain.go.version.v1",
        disable_rustup_auto_install: false,
    },
    Probe {
        id: "go.environment",
        program: "go",
        args: &["env", "GOOS", "GOARCH", "GOVERSION"],
        rule_id: "runtime.toolchain.go.environment.v1",
        disable_rustup_auto_install: false,
    },
];

const GOFMT_PROBES: &[Probe] = &[Probe {
    id: "go.gofmt-capability",
    program: "gofmt",
    args: &["-h"],
    rule_id: "runtime.toolchain.go.gofmt-capability.v1",
    disable_rustup_auto_install: false,
}];

fn probes_for(kind: ToolchainProbeKind) -> &'static [Probe] {
    match kind {
        ToolchainProbeKind::Cargo => &RUST_PROBES[..1],
        ToolchainProbeKind::Rustc => &RUST_PROBES[1..],
        ToolchainProbeKind::CargoFmt => CARGO_FMT_PROBES,
        ToolchainProbeKind::CargoClippy => CARGO_CLIPPY_PROBES,
        ToolchainProbeKind::Go => GO_PROBES,
        ToolchainProbeKind::Gofmt => GOFMT_PROBES,
    }
}

fn is_complete_success(observation: &ProcessObservation) -> bool {
    observation.exit_code == Some(0)
        && observation.signal.is_none()
        && !observation.timed_out
        && !observation.interrupted
        && !observation.stdout_truncated
        && !observation.stderr_truncated
        && (observation.stdout_total_bytes > 0 || observation.stderr_total_bytes > 0)
        && observation.stdout_total_bytes <= TOOLCHAIN_PROBE_OUTPUT_LIMIT_BYTES as u64
        && observation.stderr_total_bytes <= TOOLCHAIN_PROBE_OUTPUT_LIMIT_BYTES as u64
        && !observation.stdout_digest.as_str().is_empty()
        && !observation.stderr_digest.as_str().is_empty()
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::{BTreeMap, BTreeSet, VecDeque};
    use std::ffi::OsString;
    use std::io;
    use std::time::Duration;

    use forge_core::evidence::DependencyValue;
    use forge_core::ports::{
        EnvPolicy, ExecSpec, Hasher, ProcessError, ProcessErrorKind, ProcessObservation,
        ProcessPort, StdinPolicy,
    };
    use forge_core::{
        CommandSource, CommandSpec, Intent, OperationControl, OperationControlError,
        OperationPermit, RepoRelativePath,
    };

    use crate::hash::Blake3Hasher;

    use super::{
        TOOLCHAIN_PROBE_OUTPUT_LIMIT_BYTES, TOOLCHAIN_PROBE_TIMEOUT, ToolchainFamily,
        ToolchainProbeFailure, ToolchainProbeKind, ToolchainProbeRequest,
        probe_versions_with_process, probe_versions_with_process_controlled, probe_with_process,
        required_probes_for_command,
    };

    #[derive(Debug, Default)]
    struct FakeProcess {
        seen: RefCell<Vec<ExecSpec>>,
        responses: RefCell<VecDeque<Result<ProcessObservation, ProcessError>>>,
    }

    #[derive(Debug)]
    struct ScriptedControl {
        steps: RefCell<VecDeque<Result<OperationPermit, OperationControlError>>>,
    }

    impl ScriptedControl {
        fn new(
            steps: impl IntoIterator<Item = Result<OperationPermit, OperationControlError>>,
        ) -> Self {
            Self {
                steps: RefCell::new(steps.into_iter().collect()),
            }
        }
    }

    impl OperationControl for ScriptedControl {
        fn checkpoint(&self) -> Result<OperationPermit, OperationControlError> {
            self.steps
                .borrow_mut()
                .pop_front()
                .unwrap_or(Err(OperationControlError::TimedOut))
        }
    }

    impl FakeProcess {
        fn with_responses(
            responses: impl IntoIterator<Item = Result<ProcessObservation, ProcessError>>,
        ) -> Self {
            Self {
                seen: RefCell::new(Vec::new()),
                responses: RefCell::new(responses.into_iter().collect()),
            }
        }
    }

    impl ProcessPort for FakeProcess {
        fn run(&self, spec: &ExecSpec) -> Result<ProcessObservation, ProcessError> {
            self.seen.borrow_mut().push(spec.clone());
            self.responses.borrow_mut().pop_front().ok_or_else(|| {
                ProcessError::new(
                    ProcessErrorKind::Spawn,
                    "read fake toolchain response",
                    io::Error::other("missing fake toolchain response"),
                )
            })?
        }
    }

    fn observation(stdout: &[u8]) -> ProcessObservation {
        ProcessObservation {
            exit_code: Some(0),
            signal: None,
            stdout: stdout.to_vec(),
            stderr: Vec::new(),
            stdout_digest: Blake3Hasher.digest(&[b"fixture.stdout\0", stdout]),
            stderr_digest: Blake3Hasher.digest(&[b"fixture.stderr\0"]),
            stdout_total_bytes: stdout.len() as u64,
            stderr_total_bytes: 0,
            stdout_truncated: false,
            stderr_truncated: false,
            duration: Duration::from_millis(1),
            timed_out: false,
            interrupted: false,
        }
    }

    fn observation_with_stderr(stderr: &[u8]) -> ProcessObservation {
        let mut observation = observation(b"");
        observation.stderr = stderr.to_vec();
        observation.stderr_digest = Blake3Hasher.digest(&[b"fixture.stderr\0", stderr]);
        observation.stderr_total_bytes = stderr.len() as u64;
        observation
    }

    fn response_set() -> Vec<Result<ProcessObservation, ProcessError>> {
        vec![
            Ok(observation(b"cargo fixture\n")),
            Ok(observation(b"rustc fixture\n")),
            Ok(observation(b"go fixture\n")),
            Ok(observation(b"linux\namd64\ngo fixture\n")),
        ]
    }

    fn valid_version_response_set() -> Vec<Result<ProcessObservation, ProcessError>> {
        vec![
            Ok(observation(
                b"cargo 1.85.0 (fixture 2025-02-17)\nrelease: 1.85.0\nhost: fixture-host\n",
            )),
            Ok(observation(
                b"rustc 1.85.0 (fixture 2025-02-17)\nbinary: rustc\nrelease: 1.85.0\nhost: fixture-host\n",
            )),
            Ok(observation(b"go version go1.24.0 fixture/arch\n")),
            Ok(observation(b"fixtureos\nfixturearch\ngo1.24.0\n")),
        ]
    }

    #[test]
    fn supported_language_names_are_explicit() {
        assert_eq!(
            ToolchainFamily::from_language_name("rust"),
            Some(ToolchainFamily::Rust)
        );
        assert_eq!(
            ToolchainFamily::from_language_name("go"),
            Some(ToolchainFamily::Go)
        );
        assert_eq!(ToolchainFamily::from_language_name("python"), None);
    }

    #[test]
    fn command_probe_classification_is_exact_and_component_aware()
    -> Result<(), Box<dyn std::error::Error>> {
        let command = |program: &str, args: &[&str]| {
            CommandSpec::new(
                "fixture",
                Intent::Check,
                program,
                RepoRelativePath::root(),
                CommandSource::ExplicitConfig,
            )
            .with_args(args)
        };

        assert_eq!(
            required_probes_for_command(&command("cargo", &["fmt", "--all"])),
            Some(BTreeSet::from([
                ToolchainProbeKind::Cargo,
                ToolchainProbeKind::CargoFmt,
            ]))
        );
        assert_eq!(
            required_probes_for_command(&command("cargo", &["clippy", "--workspace"])),
            Some(BTreeSet::from([
                ToolchainProbeKind::Cargo,
                ToolchainProbeKind::Rustc,
                ToolchainProbeKind::CargoClippy,
            ]))
        );
        assert_eq!(
            required_probes_for_command(&command("gofmt", &["-l", "."])),
            Some(BTreeSet::from([
                ToolchainProbeKind::Go,
                ToolchainProbeKind::Gofmt,
            ]))
        );
        assert!(required_probes_for_command(&command("cargo", &["audit"])).is_none());
        assert!(required_probes_for_command(&command("cargo", &["+nightly", "test"])).is_none());
        assert!(required_probes_for_command(&command("./tools/cargo", &["test"])).is_none());
        Ok(())
    }

    #[test]
    fn version_report_retains_only_validated_versions_from_complete_probes() {
        let process = FakeProcess::with_responses(valid_version_response_set());
        let request = ToolchainProbeRequest::new(
            RepoRelativePath::root(),
            [ToolchainFamily::Go, ToolchainFamily::Rust],
        );

        let report = probe_versions_with_process(&process, &request);

        assert_eq!(
            report.versions(),
            &BTreeMap::from([
                (String::from("cargo"), String::from("1.85.0")),
                (String::from("go"), String::from("go1.24.0")),
                (String::from("rustc"), String::from("1.85.0")),
            ])
        );
        assert!(report.failures().is_empty());
        let serialized = format!("{report:?}");
        assert!(!serialized.contains("fixture-host"));
        assert!(!serialized.contains("fixtureos"));
    }

    #[test]
    fn version_report_classifies_missing_and_nonzero_failures() {
        let unavailable = ProcessError::new(
            ProcessErrorKind::ExecutableUnavailable,
            "start fixture probe",
            io::Error::new(io::ErrorKind::NotFound, "fixture unavailable"),
        );
        let mut nonzero = observation(b"rustc fixture\nrelease: 1.85.0\n");
        nonzero.exit_code = Some(1);
        let process = FakeProcess::with_responses([Err(unavailable), Ok(nonzero)]);
        let request = ToolchainProbeRequest::new(RepoRelativePath::root(), [ToolchainFamily::Rust]);

        let report = probe_versions_with_process(&process, &request);

        assert_eq!(
            report.failures().get("cargo"),
            Some(&ToolchainProbeFailure::ExecutableUnavailable)
        );
        assert_eq!(
            report.failures().get("rustc"),
            Some(&ToolchainProbeFailure::Failed)
        );
        assert!(report.versions().is_empty());
    }

    #[test]
    fn version_report_keeps_timeout_truncation_and_malformed_output_unknown() {
        let mut timed_out = observation(b"cargo fixture\nrelease: 1.85.0\n");
        timed_out.timed_out = true;
        let mut truncated = observation(b"rustc fixture\nrelease: 1.85.0\n");
        truncated.stdout_truncated = true;
        let process = FakeProcess::with_responses([Ok(timed_out), Ok(truncated)]);
        let request = ToolchainProbeRequest::new(RepoRelativePath::root(), [ToolchainFamily::Rust]);

        let report = probe_versions_with_process(&process, &request);

        assert_eq!(
            report.failures().get("cargo"),
            Some(&ToolchainProbeFailure::TimedOut)
        );
        assert_eq!(
            report.failures().get("rustc"),
            Some(&ToolchainProbeFailure::Truncated)
        );

        let malformed = FakeProcess::with_responses([
            Ok(observation(b"cargo output without a release field\n")),
            Ok(observation(b"rustc output without a release field\n")),
        ]);
        let malformed_report = probe_versions_with_process(&malformed, &request);
        assert_eq!(
            malformed_report.failures().get("cargo"),
            Some(&ToolchainProbeFailure::Malformed)
        );
        assert_eq!(
            malformed_report.failures().get("rustc"),
            Some(&ToolchainProbeFailure::Malformed)
        );
    }

    #[test]
    fn version_report_rejects_oversize_and_inconsistent_go_versions() {
        let mut oversize = observation(b"go version go1.24.0 fixture/arch\n");
        oversize.stdout_total_bytes = TOOLCHAIN_PROBE_OUTPUT_LIMIT_BYTES as u64 + 1;
        let oversize_process = FakeProcess::with_responses([
            Ok(oversize),
            Ok(observation(b"fixtureos\nfixturearch\ngo1.24.0\n")),
        ]);
        let request = ToolchainProbeRequest::new(RepoRelativePath::root(), [ToolchainFamily::Go]);

        let report = probe_versions_with_process(&oversize_process, &request);
        assert_eq!(
            report.failures().get("go"),
            Some(&ToolchainProbeFailure::Truncated)
        );

        let inconsistent = FakeProcess::with_responses([
            Ok(observation(b"go version go1.24.0 fixture/arch\n")),
            Ok(observation(b"fixtureos\nfixturearch\ngo1.24.1\n")),
        ]);
        let report = probe_versions_with_process(&inconsistent, &request);
        assert_eq!(
            report.failures().get("go"),
            Some(&ToolchainProbeFailure::Malformed)
        );
        assert!(report.versions().is_empty());
    }

    #[test]
    fn component_and_gofmt_probes_require_the_actual_command_capability() {
        let process = FakeProcess::with_responses([
            Ok(observation(b"rustfmt 1.8.0-stable (fixture 2025-02-17)\n")),
            Ok(observation(b"clippy 0.1.85 (fixture 2025-02-17)\n")),
            Ok(observation_with_stderr(
                b"usage: gofmt [flags] [path ...]\n  -w\twrite result\n",
            )),
        ]);
        let request = ToolchainProbeRequest::for_probes(
            RepoRelativePath::root(),
            EnvPolicy::minimal(),
            [
                ToolchainProbeKind::CargoFmt,
                ToolchainProbeKind::CargoClippy,
                ToolchainProbeKind::Gofmt,
            ],
        );

        let report = probe_versions_with_process(&process, &request);

        assert_eq!(
            report.proven(),
            &[
                "cargo-clippy".to_owned(),
                "cargo-fmt".to_owned(),
                "gofmt".to_owned(),
            ]
            .into_iter()
            .collect()
        );
        assert_eq!(
            report.versions().get("rustfmt"),
            Some(&"1.8.0-stable".to_owned())
        );
        assert_eq!(report.versions().get("clippy"), Some(&"0.1.85".to_owned()));
        assert!(report.failures().is_empty());
        assert_eq!(
            process
                .seen
                .borrow()
                .iter()
                .map(|spec| {
                    (
                        spec.program.to_string_lossy().into_owned(),
                        spec.args
                            .iter()
                            .map(|arg| arg.to_string_lossy().into_owned())
                            .collect::<Vec<_>>(),
                    )
                })
                .collect::<Vec<_>>(),
            vec![
                (
                    String::from("cargo"),
                    vec![String::from("fmt"), String::from("--version")],
                ),
                (
                    String::from("cargo"),
                    vec![String::from("clippy"), String::from("--version")],
                ),
                (String::from("gofmt"), vec![String::from("-h")]),
            ]
        );

        for kind in [ToolchainProbeKind::CargoFmt, ToolchainProbeKind::Gofmt] {
            let unavailable = ProcessError::new(
                ProcessErrorKind::ExecutableUnavailable,
                "start fixture probe",
                io::Error::new(io::ErrorKind::NotFound, "fixture unavailable"),
            );
            let failed = FakeProcess::with_responses([Err(unavailable)]);
            let request = ToolchainProbeRequest::for_probes(
                RepoRelativePath::root(),
                EnvPolicy::minimal(),
                [kind],
            );
            let report = probe_versions_with_process(&failed, &request);
            assert_eq!(
                report.failures().get(kind.as_str()),
                Some(&ToolchainProbeFailure::ExecutableUnavailable)
            );
            assert!(!report.proven().contains(kind.as_str()));
        }
    }

    #[test]
    fn go_development_versions_are_bounded_and_normalized() {
        let process = FakeProcess::with_responses([
            Ok(observation(
                b"go version devel go1.26-deadbeef Thu Jul 24 12:00:00 2026 +0000 darwin/arm64\n",
            )),
            Ok(observation(
                b"darwin\narm64\ndevel go1.26-deadbeef Thu Jul 24 12:00:00 2026 +0000\n",
            )),
        ]);
        let request = ToolchainProbeRequest::new(RepoRelativePath::root(), [ToolchainFamily::Go]);

        let report = probe_versions_with_process(&process, &request);

        assert_eq!(
            report.versions().get("go"),
            Some(&String::from("devel go1.26-deadbeef"))
        );
        assert!(report.failures().is_empty());
    }

    #[test]
    fn request_timeout_caps_each_probe_and_exhaustion_starts_nothing() {
        let process = FakeProcess::with_responses(valid_version_response_set());
        let request = ToolchainProbeRequest::new(
            RepoRelativePath::root(),
            [ToolchainFamily::Rust, ToolchainFamily::Go],
        )
        .with_total_timeout(Duration::from_millis(50));

        let _ = probe_versions_with_process(&process, &request);

        assert!(
            process.seen.borrow().iter().all(|spec| {
                !spec.timeout.is_zero() && spec.timeout <= Duration::from_millis(50)
            })
        );

        let exhausted = FakeProcess::default();
        let request = ToolchainProbeRequest::new(RepoRelativePath::root(), [ToolchainFamily::Rust])
            .with_total_timeout(Duration::ZERO);
        let report = probe_versions_with_process(&exhausted, &request);
        assert!(exhausted.seen.borrow().is_empty());
        assert_eq!(
            report.failures().get("cargo"),
            Some(&ToolchainProbeFailure::TimedOut)
        );
        assert_eq!(
            report.failures().get("rustc"),
            Some(&ToolchainProbeFailure::TimedOut)
        );
    }

    #[test]
    fn command_budget_preserves_completed_probe_prefix_and_starts_nothing_after_expiry() {
        let process = FakeProcess::with_responses([Ok(observation(
            b"cargo 1.96.0 (fixture 2026-07-28)\nrelease: 1.96.0\nhost: fixture-host\n",
        ))]);
        let request = ToolchainProbeRequest::new(
            RepoRelativePath::root(),
            [ToolchainFamily::Rust, ToolchainFamily::Go],
        );
        let control = ScriptedControl::new([
            Ok(OperationPermit::limited(Duration::from_millis(17))),
            Err(OperationControlError::TimedOut),
        ]);

        let report = probe_versions_with_process_controlled(&process, &request, &control);

        assert_eq!(process.seen.borrow().len(), 1);
        assert_eq!(process.seen.borrow()[0].timeout, Duration::from_millis(17));
        assert_eq!(
            report.versions().get("cargo"),
            Some(&String::from("1.96.0"))
        );
        assert_eq!(
            report.failures().get("rustc"),
            Some(&ToolchainProbeFailure::TimedOut)
        );
        assert_eq!(
            report.failures().get("go"),
            Some(&ToolchainProbeFailure::TimedOut)
        );
    }

    #[test]
    fn probes_rust_and_go_in_canonical_order_with_fixed_boundaries() {
        let process = FakeProcess::with_responses(response_set());
        let request = ToolchainProbeRequest::new(
            RepoRelativePath::root(),
            [
                ToolchainFamily::Go,
                ToolchainFamily::Rust,
                ToolchainFamily::Go,
            ],
        )
        .with_environment(EnvPolicy::minimal_with_overrides(BTreeMap::from([(
            OsString::from("GOWORK"),
            OsString::from("off"),
        )])));

        let dependency = probe_with_process(&process, &request, &Blake3Hasher);
        assert!(matches!(dependency, DependencyValue::Known(_)));
        let seen = process.seen.borrow();
        let programs_and_args: Vec<_> = seen
            .iter()
            .map(|spec| (spec.program.clone(), spec.args.clone()))
            .collect();
        assert_eq!(
            programs_and_args,
            vec![
                (
                    OsString::from("cargo"),
                    vec![OsString::from("--version"), OsString::from("--verbose")]
                ),
                (OsString::from("rustc"), vec![OsString::from("-vV")]),
                (OsString::from("go"), vec![OsString::from("version")]),
                (
                    OsString::from("go"),
                    vec![
                        OsString::from("env"),
                        OsString::from("GOOS"),
                        OsString::from("GOARCH"),
                        OsString::from("GOVERSION")
                    ]
                ),
            ]
        );
        for spec in seen.iter() {
            assert_eq!(spec.timeout, TOOLCHAIN_PROBE_TIMEOUT);
            assert_eq!(spec.stdin, StdinPolicy::Closed);
            assert_eq!(
                spec.stdout.retention_limit(),
                TOOLCHAIN_PROBE_OUTPUT_LIMIT_BYTES
            );
            assert_eq!(
                spec.stderr.retention_limit(),
                TOOLCHAIN_PROBE_OUTPUT_LIMIT_BYTES
            );
            assert_eq!(
                spec.env.overrides.get(&OsString::from("GOWORK")),
                Some(&OsString::from("off"))
            );
        }
        for spec in seen.iter().take(2) {
            assert_eq!(
                spec.env
                    .overrides
                    .get(&OsString::from("RUSTUP_AUTO_INSTALL")),
                Some(&OsString::from("0"))
            );
        }
        for spec in seen.iter().skip(2) {
            assert_eq!(
                spec.env
                    .overrides
                    .get(&OsString::from("RUSTUP_AUTO_INSTALL")),
                None
            );
        }
    }

    #[test]
    fn request_for_command_preserves_execution_environment() {
        use forge_core::{CommandSource, Intent};

        let mut command = forge_core::CommandSpec::new(
            "fixture",
            Intent::Check,
            "go",
            RepoRelativePath::root(),
            CommandSource::LanguageDefault {
                provider: String::from("go"),
                rule: String::from("fixture"),
            },
        );
        command
            .env
            .insert(OsString::from("GOWORK"), OsString::from("off"));
        let process = FakeProcess::with_responses([
            Ok(observation(b"go fixture\n")),
            Ok(observation(b"linux\namd64\ngo fixture\n")),
        ]);
        let request = ToolchainProbeRequest::for_command(&command, [ToolchainFamily::Go]);

        assert!(matches!(
            probe_with_process(&process, &request, &Blake3Hasher),
            DependencyValue::Known(_)
        ));
        assert!(process.seen.borrow().iter().all(|spec| {
            spec.cwd == command.cwd
                && spec.env.overrides.get(&OsString::from("GOWORK")) == Some(&OsString::from("off"))
        }));
    }

    #[test]
    fn reordered_and_duplicate_families_produce_the_same_dependency() {
        let first = FakeProcess::with_responses(response_set());
        let second = FakeProcess::with_responses(response_set());
        let first_request = ToolchainProbeRequest::new(
            RepoRelativePath::root(),
            [ToolchainFamily::Rust, ToolchainFamily::Go],
        );
        let second_request = ToolchainProbeRequest::new(
            RepoRelativePath::root(),
            [
                ToolchainFamily::Go,
                ToolchainFamily::Rust,
                ToolchainFamily::Go,
            ],
        );

        assert_eq!(
            probe_with_process(&first, &first_request, &Blake3Hasher),
            probe_with_process(&second, &second_request, &Blake3Hasher)
        );
    }

    #[test]
    fn changed_version_output_changes_only_the_dependency_digest() {
        let first = FakeProcess::with_responses([
            Ok(observation(b"go fixture one\n")),
            Ok(observation(b"linux\namd64\ngo fixture\n")),
        ]);
        let second = FakeProcess::with_responses([
            Ok(observation(b"go fixture two\n")),
            Ok(observation(b"linux\namd64\ngo fixture\n")),
        ]);
        let request = ToolchainProbeRequest::new(RepoRelativePath::root(), [ToolchainFamily::Go]);

        assert_ne!(
            probe_with_process(&first, &request, &Blake3Hasher),
            probe_with_process(&second, &request, &Blake3Hasher)
        );
    }

    #[test]
    fn no_supported_family_is_unknown_without_running_a_process() {
        let process = FakeProcess::default();
        let request = ToolchainProbeRequest::new(RepoRelativePath::root(), []);

        assert_eq!(
            probe_with_process(&process, &request, &Blake3Hasher),
            DependencyValue::Unknown
        );
        assert!(process.seen.borrow().is_empty());
    }

    #[test]
    fn every_incomplete_or_failed_observation_is_unknown() {
        let request = ToolchainProbeRequest::new(RepoRelativePath::root(), [ToolchainFamily::Go]);
        let mut cases = Vec::new();

        let mut nonzero = observation(b"go fixture\n");
        nonzero.exit_code = Some(1);
        cases.push(Ok(nonzero));
        let mut signaled = observation(b"go fixture\n");
        signaled.signal = Some(9);
        cases.push(Ok(signaled));
        let mut timed_out = observation(b"go fixture\n");
        timed_out.timed_out = true;
        cases.push(Ok(timed_out));
        let mut interrupted = observation(b"go fixture\n");
        interrupted.interrupted = true;
        cases.push(Ok(interrupted));
        let mut stdout_truncated = observation(b"go fixture\n");
        stdout_truncated.stdout_truncated = true;
        cases.push(Ok(stdout_truncated));
        let mut stderr_truncated = observation(b"go fixture\n");
        stderr_truncated.stderr_truncated = true;
        cases.push(Ok(stderr_truncated));
        cases.push(Ok(observation(b"")));
        cases.push(Err(ProcessError::new(
            ProcessErrorKind::ExecutableUnavailable,
            "start fixture probe",
            io::Error::new(io::ErrorKind::NotFound, "fixture unavailable"),
        )));

        for first_response in cases {
            let process = FakeProcess::with_responses([first_response]);
            assert_eq!(
                probe_with_process(&process, &request, &Blake3Hasher),
                DependencyValue::Unknown
            );
        }
    }

    #[test]
    fn digest_contract_does_not_return_raw_version_output() -> Result<(), Box<dyn std::error::Error>>
    {
        let raw = b"secret-looking-but-not-a-secret fixture version";
        let process = FakeProcess::with_responses([
            Ok(observation(raw)),
            Ok(observation(b"linux\namd64\ngo fixture\n")),
        ]);
        let request = ToolchainProbeRequest::new(RepoRelativePath::root(), [ToolchainFamily::Go]);

        let DependencyValue::Known(digest) = probe_with_process(&process, &request, &Blake3Hasher)
        else {
            return Err(io::Error::other("complete toolchain fixture became unknown").into());
        };
        assert!(!digest.as_str().contains("secret-looking"));
        assert!(digest.as_str().starts_with("blake3:"));
        Ok(())
    }
}
