//! Side-effect ports implemented by `forge-runtime`.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::domain::{CommandSpec, Mutability, NetworkIntent};
use crate::git::{GitError, GitFileSet, PorcelainV2Status};
use crate::inventory::{BoundedText, Inventory, InventoryError, InventoryOptions, PathKind};
use crate::path::RepoRelativePath;
use forge_schema::Digest;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessObservation {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_total_bytes: u64,
    pub stderr_total_bytes: u64,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub duration: Duration,
    pub timed_out: bool,
    pub interrupted: bool,
}

/// Environment variable names inherited by a normal project-command execution.
///
/// The set is deliberately small and contains locations or executable lookup state needed by the
/// supported toolchains. All other ambient values are removed before spawning the child.
pub const MINIMAL_INHERITED_ENVIRONMENT: &[&str] = &[
    "PATH",
    "HOME",
    "XDG_CONFIG_HOME",
    "USERPROFILE",
    "CARGO_HOME",
    "RUSTUP_HOME",
    "GOMODCACHE",
    "GOPATH",
    "GOROOT",
    "TMPDIR",
    "TEMP",
    "TMP",
    "SYSTEMROOT",
    "WINDIR",
    "PATHEXT",
    "LOCALAPPDATA",
    "APPDATA",
];

/// Explicit, allowlist-based environment policy for one child process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvPolicy {
    /// Ambient variable names that may be inherited from the Forge process.
    pub inherit: BTreeSet<OsString>,
    /// Explicit values applied after inheritance.
    pub overrides: BTreeMap<OsString, OsString>,
}

impl EnvPolicy {
    /// Inherits only the small cross-platform toolchain allowlist and applies no overrides.
    #[must_use]
    pub fn minimal() -> Self {
        Self {
            inherit: MINIMAL_INHERITED_ENVIRONMENT
                .iter()
                .map(OsString::from)
                .collect(),
            overrides: BTreeMap::new(),
        }
    }

    /// Applies explicit values to the minimal inherited environment.
    #[must_use]
    pub fn minimal_with_overrides(overrides: BTreeMap<OsString, OsString>) -> Self {
        Self {
            overrides,
            ..Self::minimal()
        }
    }
}

impl Default for EnvPolicy {
    fn default() -> Self {
        Self::minimal()
    }
}

/// How a child receives standard input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdinPolicy {
    /// Connect stdin to the null device. This is the safe default for automation.
    Closed,
    /// Explicitly inherit Forge's stdin for an interactive command.
    Inherit,
}

/// How much of one child output stream Forge retains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputPolicy {
    /// Drain the complete stream while retaining at most `max_bytes`.
    CaptureBounded { max_bytes: usize },
    /// Drain without retaining bytes.
    Discard,
}

impl OutputPolicy {
    #[must_use]
    pub const fn retention_limit(self) -> usize {
        match self {
            Self::CaptureBounded { max_bytes } => max_bytes,
            Self::Discard => 0,
        }
    }
}

/// Default in-memory retention bound for each project-command output stream.
pub const DEFAULT_CAPTURE_LIMIT_BYTES: usize = 256 * 1024;

/// Complete runtime policy for one argv-only child process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecSpec {
    pub program: OsString,
    pub args: Vec<OsString>,
    pub cwd: RepoRelativePath,
    pub env: EnvPolicy,
    pub timeout: Duration,
    pub stdin: StdinPolicy,
    pub stdout: OutputPolicy,
    pub stderr: OutputPolicy,
    pub mutability: Mutability,
    pub network: NetworkIntent,
    pub concurrency_key: Option<String>,
}

impl ExecSpec {
    /// Converts the executable fields of a detected project command without string conversion,
    /// shell interpolation, or loss of native argv/environment data.
    #[must_use]
    pub fn from_project_command(command: &CommandSpec) -> Self {
        Self {
            program: command.program.clone(),
            args: command.args.clone(),
            cwd: command.cwd.clone(),
            env: EnvPolicy::minimal_with_overrides(command.env.clone()),
            timeout: command.timeout,
            stdin: StdinPolicy::Closed,
            stdout: OutputPolicy::CaptureBounded {
                max_bytes: DEFAULT_CAPTURE_LIMIT_BYTES,
            },
            stderr: OutputPolicy::CaptureBounded {
                max_bytes: DEFAULT_CAPTURE_LIMIT_BYTES,
            },
            mutability: command.mutability,
            network: command.network,
            concurrency_key: None,
        }
    }
}

impl From<&CommandSpec> for ExecSpec {
    fn from(command: &CommandSpec) -> Self {
        Self::from_project_command(command)
    }
}

/// Stable process failure categories for failures that cannot be represented as observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessErrorKind {
    InvalidRepositoryRoot,
    InvalidWorkingDirectory,
    InvalidEnvironment,
    UnsupportedProgram,
    ExecutableUnavailable,
    PermissionDenied,
    Spawn,
    ProcessTree,
    Output,
    Wait,
}

/// A typed process-boundary failure with its original operating-system error retained.
#[derive(Debug)]
pub struct ProcessError {
    kind: ProcessErrorKind,
    action: &'static str,
    source: io::Error,
}

impl ProcessError {
    #[must_use]
    pub fn new(kind: ProcessErrorKind, action: &'static str, source: io::Error) -> Self {
        Self {
            kind,
            action,
            source,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> ProcessErrorKind {
        self.kind
    }

    #[must_use]
    pub fn io_kind(&self) -> io::ErrorKind {
        self.source.kind()
    }
}

impl fmt::Display for ProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.action, self.source)
    }
}

impl std::error::Error for ProcessError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

pub trait ProcessPort {
    fn run(&self, spec: &ExecSpec) -> Result<ProcessObservation, ProcessError>;
}

pub trait FileSystemPort {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>>;
    /// Inventories a repository using an explicit authority for candidate paths.
    ///
    /// `Some(file_set)` preserves every Git-tracked path, applies Git ignore semantics only to
    /// untracked candidates, and applies supplementary `.ignore` rules only to those untracked
    /// candidates. `None` selects the filesystem-walking fallback and must only be used after the
    /// caller has established that the root is not a Git repository.
    fn inventory(
        &self,
        root: &Path,
        file_set: Option<&GitFileSet>,
        options: InventoryOptions,
    ) -> Result<Inventory, InventoryError>;
    /// Reads a repository-relative text candidate up to the configured byte bound.
    fn read_bounded_text(
        &self,
        root: &Path,
        path: &RepoRelativePath,
        max_text_file_bytes: u64,
    ) -> Result<BoundedText, InventoryError>;
    /// Inspects one repository-relative path without following symbolic links.
    ///
    /// Missing paths are represented explicitly; permission and other I/O failures remain errors.
    fn path_kind(&self, root: &Path, path: &RepoRelativePath) -> io::Result<PathKind>;
    fn write_atomic(&self, path: &Path, bytes: &[u8]) -> io::Result<()>;
    fn exists(&self, path: &Path) -> bool;
}

/// Repository-confined file access used by reviewed working-tree change plans.
///
/// Implementations must reject absolute or parent-traversing paths, symbolic-link targets or
/// ancestors, non-regular targets, and repository-root changes. `write_atomic_confined` must write
/// through a same-directory temporary file and replace the target atomically at the single-file
/// boundary. Multi-file atomicity is deliberately not promised by this port.
pub trait RepositoryFilePort {
    /// Reads a safe repository-relative regular file, or returns `None` when it does not exist.
    fn read_confined(
        &self,
        repository_root: &Path,
        path: &RepoRelativePath,
    ) -> io::Result<Option<Vec<u8>>>;

    /// Atomically writes one safe repository-relative regular file.
    fn write_atomic_confined(
        &self,
        repository_root: &Path,
        path: &RepoRelativePath,
        bytes: &[u8],
    ) -> io::Result<()>;
}

pub trait GitPort {
    fn repository_root(&self, start: &Path) -> Result<PathBuf, GitError>;
    fn git_dir(&self, start: &Path) -> Result<PathBuf, GitError>;
    fn git_common_dir(&self, start: &Path) -> Result<PathBuf, GitError>;
    fn status(&self, root: &Path) -> Result<PorcelainV2Status, GitError>;
    fn file_set(&self, root: &Path) -> Result<GitFileSet, GitError>;
}

pub trait StateStore {
    fn load(&self, key: &str) -> io::Result<Option<Vec<u8>>>;
    fn store_atomic(&self, key: &str, bytes: &[u8]) -> io::Result<()>;
}

pub trait Clock {
    fn now(&self) -> SystemTime;
}

pub trait Hasher {
    fn digest(&self, chunks: &[&[u8]]) -> Digest;
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::ffi::OsString;
    use std::time::Duration;

    use crate::domain::{CommandSource, CommandSpec, Intent, Mutability, NetworkIntent};

    use super::{DEFAULT_CAPTURE_LIMIT_BYTES, EnvPolicy, ExecSpec, OutputPolicy, StdinPolicy};
    use crate::path::RepoRelativePath;

    #[test]
    fn project_command_adapter_preserves_every_executable_field() -> Result<(), Box<dyn Error>> {
        let mut command = CommandSpec::new(
            "ports.exec.adapter",
            Intent::Test,
            "tool",
            RepoRelativePath::new("member")?,
            CommandSource::LanguageDefault {
                provider: "test".into(),
                rule: "adapter".into(),
            },
        )
        .with_args(["--flag", "literal argument"]);
        command
            .env
            .insert(OsString::from("EXPLICIT"), OsString::from("value"));
        command.timeout = Duration::from_millis(1234);
        command.mutability = Mutability::WorkingTreeWrite;
        command.network = NetworkIntent::OfflineRequested;

        let execution = ExecSpec::from_project_command(&command);

        assert_eq!(execution.program, command.program);
        assert_eq!(execution.args, command.args);
        assert_eq!(execution.cwd, command.cwd);
        assert_eq!(execution.env.overrides, command.env);
        assert_eq!(
            execution.env,
            EnvPolicy::minimal_with_overrides(command.env)
        );
        assert_eq!(execution.timeout, Duration::from_millis(1234));
        assert_eq!(execution.stdin, StdinPolicy::Closed);
        assert_eq!(
            execution.stdout,
            OutputPolicy::CaptureBounded {
                max_bytes: DEFAULT_CAPTURE_LIMIT_BYTES
            }
        );
        assert_eq!(execution.stdout, execution.stderr);
        assert_eq!(execution.mutability, Mutability::WorkingTreeWrite);
        assert_eq!(execution.network, NetworkIntent::OfflineRequested);
        assert_eq!(execution.concurrency_key, None);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn project_command_adapter_preserves_non_utf8_argv_and_environment() {
        use std::os::unix::ffi::OsStringExt as _;

        let program = OsString::from_vec(b"tool-\xff".to_vec());
        let argument = OsString::from_vec(b"arg-\xfe".to_vec());
        let env_name = OsString::from_vec(b"NAME_\xfd".to_vec());
        let env_value = OsString::from_vec(b"value-\xfc".to_vec());
        let mut command = CommandSpec::new(
            "ports.exec.native",
            Intent::Check,
            &program,
            RepoRelativePath::root(),
            CommandSource::LanguageDefault {
                provider: "test".into(),
                rule: "native".into(),
            },
        )
        .with_args([&argument]);
        command.env.insert(env_name.clone(), env_value.clone());

        let execution = ExecSpec::from_project_command(&command);

        assert_eq!(execution.program, program);
        assert_eq!(execution.args, [argument]);
        assert_eq!(execution.env.overrides.get(&env_name), Some(&env_value));
    }

    #[test]
    fn discarded_output_has_a_zero_retention_bound() {
        assert_eq!(OutputPolicy::Discard.retention_limit(), 0);
    }
}
