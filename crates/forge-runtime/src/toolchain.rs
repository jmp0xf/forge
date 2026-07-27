//! Bounded toolchain probes for evidence dependency fingerprints.
//!
//! Probe output is untrusted and may contain host-specific data. This module validates the
//! observation and retains only the runner-computed stream digests; raw output never crosses the
//! public dependency boundary.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::time::Duration;

use forge_core::evidence::DependencyValue;
use forge_core::fingerprint::toolchain_info_dependency_digest;
use forge_core::ports::{
    EnvPolicy, ExecSpec, Hasher, OutputPolicy, ProcessObservation, ProcessPort, StdinPolicy,
};
use forge_core::{
    CommandSpec, Confidence, Digest, Mutability, NetworkIntent, Provenance, RepoRelativePath,
    ToolchainInfo,
};

use crate::process::SynchronousProcessRunner;

/// Behavior identifier included in every known toolchain dependency.
pub const TOOLCHAIN_PROBE_PROTOCOL_VERSION: &str = "forge.toolchain-probe/v1";

/// Maximum wall time for each version probe.
pub const TOOLCHAIN_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

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

/// Complete, deterministic inputs to a toolchain dependency probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolchainProbeRequest {
    cwd: RepoRelativePath,
    environment: EnvPolicy,
    families: BTreeSet<ToolchainFamily>,
}

impl ToolchainProbeRequest {
    /// Creates a request with the normal minimal inherited environment.
    #[must_use]
    pub fn new(cwd: RepoRelativePath, families: impl IntoIterator<Item = ToolchainFamily>) -> Self {
        Self {
            cwd,
            environment: EnvPolicy::minimal(),
            families: families.into_iter().collect(),
        }
    }

    /// Creates a request matching one project's command cwd and explicit environment overrides.
    #[must_use]
    pub fn for_command(
        command: &CommandSpec,
        families: impl IntoIterator<Item = ToolchainFamily>,
    ) -> Self {
        Self {
            cwd: command.cwd.clone(),
            environment: EnvPolicy::minimal_with_overrides(command.env.clone()),
            families: families.into_iter().collect(),
        }
    }

    /// Replaces the environment supplied to every probe.
    #[must_use]
    pub fn with_environment(mut self, environment: EnvPolicy) -> Self {
        self.environment = environment;
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
    probe_with_process(runner, request, hasher)
}

fn probe_with_process<P, H>(
    process: &P,
    request: &ToolchainProbeRequest,
    hasher: &H,
) -> DependencyValue<Digest>
where
    P: ProcessPort + ?Sized,
    H: Hasher + ?Sized,
{
    if request.families.is_empty() {
        return DependencyValue::Unknown;
    }

    let mut values = std::collections::BTreeMap::from([(
        String::from("probe.protocol"),
        String::from(TOOLCHAIN_PROBE_PROTOCOL_VERSION),
    )]);
    let mut provenance = Vec::new();
    for family in &request.families {
        for probe in probes_for(*family) {
            let spec = probe.exec_spec(request);
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

#[derive(Debug, Clone, Copy)]
struct Probe {
    id: &'static str,
    program: &'static str,
    args: &'static [&'static str],
    rule_id: &'static str,
    disable_rustup_auto_install: bool,
}

impl Probe {
    fn exec_spec(self, request: &ToolchainProbeRequest) -> ExecSpec {
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
            timeout: TOOLCHAIN_PROBE_TIMEOUT,
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

fn probes_for(family: ToolchainFamily) -> &'static [Probe] {
    match family {
        ToolchainFamily::Rust => RUST_PROBES,
        ToolchainFamily::Go => GO_PROBES,
    }
}

fn is_complete_success(observation: &ProcessObservation) -> bool {
    observation.exit_code == Some(0)
        && observation.signal.is_none()
        && !observation.timed_out
        && !observation.interrupted
        && !observation.stdout_truncated
        && !observation.stderr_truncated
        && observation.stdout_total_bytes > 0
        && observation.stdout_total_bytes <= TOOLCHAIN_PROBE_OUTPUT_LIMIT_BYTES as u64
        && observation.stderr_total_bytes <= TOOLCHAIN_PROBE_OUTPUT_LIMIT_BYTES as u64
        && !observation.stdout_digest.as_str().is_empty()
        && !observation.stderr_digest.as_str().is_empty()
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::{BTreeMap, VecDeque};
    use std::ffi::OsString;
    use std::io;
    use std::time::Duration;

    use forge_core::RepoRelativePath;
    use forge_core::evidence::DependencyValue;
    use forge_core::ports::{
        EnvPolicy, ExecSpec, Hasher, ProcessError, ProcessErrorKind, ProcessObservation,
        ProcessPort, StdinPolicy,
    };

    use crate::hash::Blake3Hasher;

    use super::{
        TOOLCHAIN_PROBE_OUTPUT_LIMIT_BYTES, TOOLCHAIN_PROBE_TIMEOUT, ToolchainFamily,
        ToolchainProbeRequest, probe_with_process,
    };

    #[derive(Debug, Default)]
    struct FakeProcess {
        seen: RefCell<Vec<ExecSpec>>,
        responses: RefCell<VecDeque<Result<ProcessObservation, ProcessError>>>,
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

    fn response_set() -> Vec<Result<ProcessObservation, ProcessError>> {
        vec![
            Ok(observation(b"cargo fixture\n")),
            Ok(observation(b"rustc fixture\n")),
            Ok(observation(b"go fixture\n")),
            Ok(observation(b"linux\namd64\ngo fixture\n")),
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
