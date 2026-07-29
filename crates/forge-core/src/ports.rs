//! Side-effect ports implemented by `forge-runtime`.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::control::OperationControl;
use crate::domain::{CommandSpec, Mutability, NetworkIntent};
use crate::git::{
    GitError, GitErrorKind, GitFileSet, GitIndexEntry, GitObjectId, PorcelainV2Status,
};
use crate::inventory::{
    BoundedText, Inventory, InventoryError, InventoryOptions, PathKind, PathMetadata,
};
use crate::path::RepoRelativePath;
use forge_schema::Digest;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessObservation {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// Digest of the complete stdout stream, including bytes not retained in `stdout`.
    ///
    /// A producer must give its algorithm a behavior version before receipts may reuse the value.
    pub stdout_digest: Digest,
    /// Digest of the complete stderr stream, including bytes not retained in `stderr`.
    ///
    /// A producer must give its algorithm a behavior version before receipts may reuse the value.
    pub stderr_digest: Digest,
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

impl ProcessErrorKind {
    /// Stable machine spelling used by typed Receipt projections and process-boundary markers.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRepositoryRoot => "invalid-repository-root",
            Self::InvalidWorkingDirectory => "invalid-working-directory",
            Self::InvalidEnvironment => "invalid-environment",
            Self::UnsupportedProgram => "unsupported-program",
            Self::ExecutableUnavailable => "executable-unavailable",
            Self::PermissionDenied => "permission-denied",
            Self::Spawn => "spawn",
            Self::ProcessTree => "process-tree",
            Self::Output => "output",
            Self::Wait => "wait",
        }
    }
}

/// Stable detail for process-boundary failures that share one wire-level category.
///
/// The v2 Receipt contract records [`ProcessErrorKind`]. Additive runtime details stay separate so
/// a caller can distinguish a local enforcement decision without changing that versioned wire
/// enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProcessErrorReason {
    /// The combined complete stdout and stderr streams crossed an execution-time hard limit.
    OutputLimitExceeded,
}

impl ProcessErrorReason {
    /// Stable machine spelling for content-free diagnostics outside versioned Receipt schemas.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OutputLimitExceeded => "output-limit-exceeded",
        }
    }
}

/// A typed process-boundary failure with its original operating-system error retained.
#[derive(Debug)]
pub struct ProcessError {
    kind: ProcessErrorKind,
    reason: Option<ProcessErrorReason>,
    action: &'static str,
    source: io::Error,
}

impl ProcessError {
    #[must_use]
    pub fn new(kind: ProcessErrorKind, action: &'static str, source: io::Error) -> Self {
        Self {
            kind,
            reason: None,
            action,
            source,
        }
    }

    /// Constructs the content-free failure returned after an output hard limit terminates a child
    /// process tree.
    #[must_use]
    pub fn output_limit_exceeded() -> Self {
        Self {
            kind: ProcessErrorKind::Output,
            reason: Some(ProcessErrorReason::OutputLimitExceeded),
            action: "enforce combined child output hard limit",
            source: io::Error::new(
                io::ErrorKind::InvalidData,
                "combined child output exceeded its hard limit",
            ),
        }
    }

    #[must_use]
    pub const fn kind(&self) -> ProcessErrorKind {
        self.kind
    }

    /// Returns an additive stable reason when the broad process category has one.
    #[must_use]
    pub const fn reason(&self) -> Option<ProcessErrorReason> {
        self.reason
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
    /// Inventories with one operation-wide deadline and cancellation source.
    ///
    /// Alternate ports retain source compatibility through this fail-safe default. Native runtime
    /// implementations override it to checkpoint every retained or skipped entry.
    fn inventory_controlled(
        &self,
        root: &Path,
        file_set: Option<&GitFileSet>,
        options: InventoryOptions,
        control: &dyn OperationControl,
    ) -> Result<Inventory, InventoryError> {
        control.checkpoint()?;
        self.inventory(root, file_set, options)
    }
    /// Reads a repository-relative text candidate up to the configured byte bound.
    fn read_bounded_text(
        &self,
        root: &Path,
        path: &RepoRelativePath,
        max_text_file_bytes: u64,
    ) -> Result<BoundedText, InventoryError>;
    /// Reads bounded text with cooperative checkpoints.
    fn read_bounded_text_controlled(
        &self,
        root: &Path,
        path: &RepoRelativePath,
        max_text_file_bytes: u64,
        control: &dyn OperationControl,
    ) -> Result<BoundedText, InventoryError> {
        control.checkpoint()?;
        self.read_bounded_text(root, path, max_text_file_bytes)
    }
    /// Inspects one repository-relative path without following symbolic links.
    ///
    /// Missing paths are represented explicitly; permission and other I/O failures remain errors.
    fn path_kind(&self, root: &Path, path: &RepoRelativePath) -> io::Result<PathKind>;
    /// Atomically observes path kind and size without following symbolic links.
    ///
    /// The default fails closed: a port that cannot provide both facts from one metadata snapshot
    /// must not silently make a shared-cache entry appear reusable.
    fn path_metadata(&self, _root: &Path, _path: &RepoRelativePath) -> io::Result<PathMetadata> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the filesystem port does not implement atomic path metadata observations",
        ))
    }
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

    /// Reads at most `max_bytes`; a larger target must be rejected without retaining it.
    ///
    /// Implementations report the size-bound rejection as [`io::ErrorKind::InvalidData`]. Other
    /// path-safety and I/O failures must retain their own error kinds so callers can distinguish
    /// an expected bound from an inaccessible or unsafe target.
    fn read_confined_bounded(
        &self,
        repository_root: &Path,
        path: &RepoRelativePath,
        max_bytes: usize,
    ) -> io::Result<Option<Vec<u8>>>;

    /// Atomically writes one safe repository-relative regular file.
    fn write_atomic_confined(
        &self,
        repository_root: &Path,
        path: &RepoRelativePath,
        bytes: &[u8],
    ) -> io::Result<()>;
}

/// Whether a failed repository write reached its single-file commit point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepositoryWriteCommit {
    /// The target name was not changed by the failed operation.
    NotCommitted,
    /// The target name was committed, but durability or post-write verification did not finish.
    CommittedUnverified,
}

/// A repository write failure that preserves whether the target was already committed.
#[derive(Debug)]
pub struct RepositoryWriteError {
    commit: RepositoryWriteCommit,
    source: io::Error,
}

impl RepositoryWriteError {
    #[must_use]
    pub const fn new(commit: RepositoryWriteCommit, source: io::Error) -> Self {
        Self { commit, source }
    }

    #[must_use]
    pub const fn commit(&self) -> RepositoryWriteCommit {
        self.commit
    }

    #[must_use]
    pub fn source_error(&self) -> &io::Error {
        &self.source
    }

    #[must_use]
    pub fn into_source(self) -> io::Error {
        self.source
    }
}

impl fmt::Display for RepositoryWriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.commit {
            RepositoryWriteCommit::NotCommitted => {
                write!(
                    formatter,
                    "repository write failed before commit: {}",
                    self.source
                )
            }
            RepositoryWriteCommit::CommittedUnverified => write!(
                formatter,
                "repository target was committed but could not be fully synchronized or verified: {}",
                self.source
            ),
        }
    }
}

impl Error for RepositoryWriteError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

/// Result of one compare-and-write operation through a pinned repository root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepositoryWriteOutcome {
    /// The target no longer matched the reviewed preimage, so nothing was committed.
    PreconditionMismatch,
    /// The target was committed and reread through the same pinned parent capability.
    Written { observed: Option<Vec<u8>> },
}

/// One apply-scoped repository capability.
///
/// Implementations pin one repository root for the lifetime of the value. Reads and writes are
/// handle-relative. A write must pin the target parent before its prewrite read and retain that
/// same parent through commit and post-write read. A missing expected preimage is a no-clobber
/// create; an existing expected preimage is rechecked after the temporary file is synchronized
/// and immediately before an atomic replacement. Portable filesystems do not provide one syscall
/// that compares arbitrary file bytes and renames, so a same-parent actor can still race the final
/// recheck and replacement; callers must not treat replacement as cross-process compare-and-swap.
pub trait RepositoryApplyPort {
    /// Reads a safe repository-relative regular file through the pinned root.
    fn read_confined_bounded(
        &self,
        path: &RepoRelativePath,
        max_bytes: usize,
    ) -> io::Result<Option<Vec<u8>>>;

    /// Commits `bytes` only when the parent-relative target still equals `expected`.
    fn write_atomic_if_unchanged(
        &self,
        path: &RepoRelativePath,
        expected: Option<&[u8]>,
        bytes: &[u8],
        max_postimage_bytes: usize,
    ) -> Result<RepositoryWriteOutcome, RepositoryWriteError>;
}

pub trait GitPort {
    fn repository_root(&self, start: &Path) -> Result<PathBuf, GitError>;
    fn git_dir(&self, start: &Path) -> Result<PathBuf, GitError>;
    fn git_common_dir(&self, start: &Path) -> Result<PathBuf, GitError>;
    fn status(&self, root: &Path) -> Result<PorcelainV2Status, GitError>;
    fn file_set(&self, root: &Path) -> Result<GitFileSet, GitError>;

    /// Reads the exact raw Git index file through one bounded, no-follow file snapshot.
    ///
    /// The bytes are opaque input for a cryptographic cache identity; callers must not interpret
    /// them as a Git object ID or rely on Git's SHA-1/SHA-256 object format. Implementations must
    /// reject symbolic links, non-regular files, files larger than `max_bytes`, split indexes whose
    /// shared dependency is not included, and any present sibling `index.lock`.
    ///
    /// The default fails closed so alternate ports cannot silently build a reusable cache identity
    /// from an incomplete or path-derived approximation of the index.
    fn index_snapshot_bytes(&self, _root: &Path, _max_bytes: usize) -> Result<Vec<u8>, GitError> {
        Err(GitError::new(
            GitErrorKind::InvalidData,
            "index-snapshot",
            "the Git port does not implement bounded raw-index snapshot reads",
        ))
    }

    /// Reads the complete bounded index representation used by reusable cache identities.
    ///
    /// The default fails closed so alternate ports cannot claim a complete index basis from only
    /// a path list.
    fn index_entries(&self, _root: &Path) -> Result<Vec<GitIndexEntry>, GitError> {
        Err(GitError::new(
            GitErrorKind::InvalidData,
            "index-entries",
            "the Git port does not implement complete index entry reads",
        ))
    }

    /// Reads one regular file from an exact immutable commit object.
    ///
    /// `Ok(None)` means that the path is absent from that commit. Implementations must not follow
    /// worktree paths, invoke content filters, or resolve a symbolic ref in place of `commit`.
    /// The default fails closed so a partial test or alternate port cannot silently claim that an
    /// accepted policy file was absent.
    fn read_commit_file_bounded(
        &self,
        _root: &Path,
        _commit: &GitObjectId,
        _path: &RepoRelativePath,
        _max_bytes: u64,
    ) -> Result<Option<Vec<u8>>, GitError> {
        Err(GitError::new(
            GitErrorKind::InvalidData,
            "read-commit-file",
            "the Git port does not implement bounded immutable commit-file reads",
        ))
    }
}

pub trait StateStore {
    fn load(&self, key: &str) -> io::Result<Option<Vec<u8>>>;

    /// Loads at most `max_bytes`; implementations must reject a larger value without retaining it.
    ///
    /// Implementations report the size-bound rejection as [`io::ErrorKind::InvalidData`]. Other
    /// storage failures must retain their own error kinds.
    fn load_bounded(&self, key: &str, max_bytes: usize) -> io::Result<Option<Vec<u8>>>;

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
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use crate::domain::{CommandSource, CommandSpec, Intent, Mutability, NetworkIntent};
    use crate::{GitError, GitErrorKind, GitFileSet, PorcelainV2Status};

    use super::{
        DEFAULT_CAPTURE_LIMIT_BYTES, EnvPolicy, ExecSpec, GitPort, OutputPolicy, ProcessError,
        ProcessErrorKind, ProcessErrorReason, StdinPolicy,
    };
    use crate::path::RepoRelativePath;

    #[derive(Debug)]
    struct GitPortWithoutIndexSnapshot;

    impl GitPort for GitPortWithoutIndexSnapshot {
        fn repository_root(&self, _start: &Path) -> Result<PathBuf, GitError> {
            unavailable_git_operation()
        }

        fn git_dir(&self, _start: &Path) -> Result<PathBuf, GitError> {
            unavailable_git_operation()
        }

        fn git_common_dir(&self, _start: &Path) -> Result<PathBuf, GitError> {
            unavailable_git_operation()
        }

        fn status(&self, _root: &Path) -> Result<PorcelainV2Status, GitError> {
            unavailable_git_operation()
        }

        fn file_set(&self, _root: &Path) -> Result<GitFileSet, GitError> {
            unavailable_git_operation()
        }
    }

    fn unavailable_git_operation<T>() -> Result<T, GitError> {
        Err(GitError::new(
            GitErrorKind::InvalidData,
            "test",
            "operation is intentionally unavailable",
        ))
    }

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

    #[test]
    fn output_limit_failure_is_typed_stable_and_content_free() {
        let error = ProcessError::output_limit_exceeded();

        assert_eq!(error.kind(), ProcessErrorKind::Output);
        assert_eq!(
            error.reason(),
            Some(ProcessErrorReason::OutputLimitExceeded)
        );
        assert_eq!(
            error.reason().map(ProcessErrorReason::as_str),
            Some("output-limit-exceeded")
        );
        assert_eq!(error.io_kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(
            crate::wire::process_error_kind_to_wire(error.kind()),
            forge_schema::ProcessErrorKindV2Data::Output
        );
        assert_eq!(
            error.to_string(),
            "enforce combined child output hard limit: combined child output exceeded its hard limit"
        );
    }

    #[test]
    fn raw_index_snapshot_defaults_to_fail_closed() {
        let error = GitPortWithoutIndexSnapshot
            .index_snapshot_bytes(Path::new("."), 1024)
            .err();

        assert_eq!(
            error.as_ref().map(GitError::kind),
            Some(GitErrorKind::InvalidData)
        );
        assert_eq!(
            error.as_ref().map(GitError::operation),
            Some("index-snapshot")
        );
    }
}
