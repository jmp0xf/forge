//! Hardened Git CLI implementation of the typed core port.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[cfg(all(test, unix))]
use forge_core::UnlimitedOperationControl;
use forge_core::domain::{
    CommandSource, CommandSpec, Confidence, Intent, Mutability, NetworkIntent,
};
use forge_core::git::{GitIndexEntry, GitIndexReadError, parse_git_index_reader_controlled};
use forge_core::ports::{
    ExecSpec, GitPort, OutputPolicy, ProcessError, ProcessErrorKind, ProcessObservation,
    ProcessPort as _,
};
use forge_core::{
    GitError, GitErrorKind, GitFileSet, GitObjectFormat, GitObjectId, GitPathListReadError,
    OperationControl as _, OperationControlError, PorcelainV2ReadError, PorcelainV2Status,
    RepoRelativePath, parse_git_path_list_reader_controlled,
    parse_status_porcelain_v2_reader_controlled,
};

use crate::control::OperationBudget;
use crate::process::{
    DEFAULT_SPOOLED_STDOUT_LIMIT_BYTES, SpooledProcessObservation, SynchronousProcessRunner,
};

/// Maximum wall-clock duration for one Git inspection.
pub const DEFAULT_GIT_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum Git status bytes retained in an anonymous disk spool.
pub const DEFAULT_GIT_STATUS_SPOOL_LIMIT_BYTES: usize = DEFAULT_SPOOLED_STDOUT_LIMIT_BYTES;

/// Maximum bytes retained in memory for one NUL-delimited porcelain v2 record.
pub const DEFAULT_GIT_STATUS_RECORD_LIMIT_BYTES: usize = 1024 * 1024;

/// Maximum typed worktree entries accepted from one porcelain v2 status.
///
/// This supports repositories with at least 100,000 entries while bounding typed allocation.
pub const DEFAULT_GIT_STATUS_ENTRY_LIMIT: usize = 200_000;

/// Typed wrapper around the installed `git` executable and unified process runner.
#[derive(Debug, Clone)]
pub struct GitCli {
    timeout: Duration,
    status_spool_limit_bytes: usize,
    status_record_limit_bytes: usize,
    status_entry_limit: usize,
    cancellation: Arc<AtomicBool>,
    operation_budget: OperationBudget,
}

impl Default for GitCli {
    fn default() -> Self {
        let cancellation = Arc::new(AtomicBool::new(false));
        Self {
            timeout: DEFAULT_GIT_TIMEOUT,
            status_spool_limit_bytes: DEFAULT_GIT_STATUS_SPOOL_LIMIT_BYTES,
            status_record_limit_bytes: DEFAULT_GIT_STATUS_RECORD_LIMIT_BYTES,
            status_entry_limit: DEFAULT_GIT_STATUS_ENTRY_LIMIT,
            cancellation: Arc::clone(&cancellation),
            operation_budget: OperationBudget::unlimited(cancellation),
        }
    }
}

/// The status command fixed by the design contract and ADR-0007.
pub const STATUS_PORCELAIN_V2_ARGS: &[&str] = &[
    "status",
    "--porcelain=v2",
    "-z",
    "--branch",
    "--untracked-files=all",
];

/// Enumerate every path represented by the index, including tracked paths ignored later.
pub const TRACKED_FILES_ARGS: &[&str] = &["ls-files", "--cached", "-z", "--"];

/// Enumerate the exact mode, object identity, stage, and native path represented by the index.
pub const INDEX_ENTRIES_ARGS: &[&str] = &["ls-files", "--stage", "-v", "-z", "--"];

/// Enumerate untracked paths using Git's repository, info, and global exclude semantics.
pub const UNTRACKED_FILES_ARGS: &[&str] =
    &["ls-files", "--others", "--exclude-standard", "-z", "--"];

/// Resolve the repository root as an absolute native path.
pub const REPOSITORY_ROOT_ARGS: &[&str] = &["rev-parse", "--show-toplevel"];

/// Resolve the worktree-specific Git directory as an absolute native path.
pub const GIT_DIR_ARGS: &[&str] = &["rev-parse", "--path-format=absolute", "--git-dir"];

/// Resolve the shared Git directory as an absolute native path.
pub const GIT_COMMON_DIR_ARGS: &[&str] =
    &["rev-parse", "--path-format=absolute", "--git-common-dir"];

/// Resolve the exact worktree-specific index and report any split-index dependency.
pub const INDEX_PATH_ARGS: &[&str] = &[
    "rev-parse",
    "--path-format=absolute",
    "--git-path",
    "index",
    "--shared-index-path",
];

/// Resolve the object format used by Git command output.
pub const OBJECT_FORMAT_ARGS: &[&str] = &["rev-parse", "--show-object-format=output"];

/// Global Git arguments used before every non-interactive Forge operation.
pub const HARDENED_GIT_GLOBAL_ARGS: &[&str] = &[
    "--no-pager",
    "--no-optional-locks",
    "--no-replace-objects",
    "--literal-pathspecs",
    "-c",
    "core.fsmonitor=false",
];

/// Environment overrides required for non-interactive Git operations.
pub const HARDENED_GIT_ENV: &[(&str, &str)] = &[
    ("GIT_TERMINAL_PROMPT", "0"),
    ("GIT_OPTIONAL_LOCKS", "0"),
    ("GIT_NO_LAZY_FETCH", "1"),
    ("GCM_INTERACTIVE", "Never"),
    ("LC_ALL", "C"),
];

/// Ambient Git settings whose semantics must match the invoking user's Git discovery/configuration.
const PRESERVED_GIT_ENV: &[&str] = &[
    "GIT_CEILING_DIRECTORIES",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_NOSYSTEM",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_PARAMETERS",
    "GIT_ATTR_NOSYSTEM",
];

/// Ambient overrides that could silently redirect Forge to a different repository or executable.
const REJECTED_GIT_ENV: &[&str] = &[
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_NAMESPACE",
    "GIT_SHALLOW_FILE",
    "GIT_REPLACE_REF_BASE",
    "GIT_EXEC_PATH",
];

impl GitCli {
    /// Creates a Git CLI with the default bounded timeout and status capacity.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Overrides the per-operation timeout, primarily for bounded integration contexts.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Replaces the independent default cancellation flag with one shared by the caller.
    ///
    /// The flag is sticky: setting it to `true` interrupts all current and later Git operations
    /// performed by this value or any of its clones until the caller resets it.
    #[must_use]
    pub fn with_cancellation_flag(mut self, cancellation: Arc<AtomicBool>) -> Self {
        self.cancellation = Arc::clone(&cancellation);
        self.operation_budget = self.operation_budget.with_cancellation_flag(cancellation);
        self
    }

    /// Shares one command-wide absolute deadline and cancellation source with every Git child.
    #[must_use]
    pub fn with_operation_budget(mut self, operation_budget: OperationBudget) -> Self {
        self.cancellation = operation_budget.cancellation_flag();
        self.operation_budget = operation_budget;
        self
    }

    /// Overrides the anonymous status spool bound.
    #[must_use]
    pub fn with_status_spool_limit_bytes(mut self, limit: usize) -> Self {
        self.status_spool_limit_bytes = limit;
        self
    }

    /// Backward-compatible spelling for [`Self::with_status_spool_limit_bytes`].
    #[must_use]
    pub fn with_status_output_limit_bytes(self, limit: usize) -> Self {
        self.with_status_spool_limit_bytes(limit)
    }

    fn command_spec(&self, operation: GitOperation) -> Result<CommandSpec, GitError> {
        let args = operation.static_args().ok_or_else(|| {
            GitError::new(
                GitErrorKind::InvalidData,
                operation.name(),
                "operation requires explicit bounded arguments",
            )
        })?;
        self.command_spec_with_args(operation, args.iter().map(OsString::from).collect())
    }

    fn command_spec_with_args(
        &self,
        operation: GitOperation,
        args: Vec<OsString>,
    ) -> Result<CommandSpec, GitError> {
        let mut hardened_args: Vec<OsString> = HARDENED_GIT_GLOBAL_ARGS
            .iter()
            .map(OsString::from)
            .collect();
        hardened_args.extend(args);
        let mut spec = CommandSpec::new(
            operation.command_id(),
            Intent::Check,
            "git",
            RepoRelativePath::root(),
            CommandSource::LanguageDefault {
                provider: "git".into(),
                rule: "forge-runtime-inspection".into(),
            },
        )
        .with_args(hardened_args);
        spec.timeout = self
            .operation_budget
            .checkpoint()
            .map_err(|error| operation_control_git_error(operation, error))?
            .cap(self.timeout);
        spec.mutability = Mutability::ReadOnly;
        // These commands are local-only, but NetworkIntent has no `None` variant. Do not claim
        // ecosystem offline flags were requested when Git has no such flag for these operations.
        spec.network = NetworkIntent::Unknown;
        spec.confidence = Confidence::High;
        spec.env = hardened_git_environment(std::env::vars_os()).map_err(|error| {
            GitError::new(
                GitErrorKind::UnsafeEnvironment,
                operation.name(),
                error.to_string(),
            )
        })?;
        Ok(spec)
    }

    fn run_with_args(
        &self,
        start: &Path,
        operation: GitOperation,
        args: Vec<OsString>,
        stdout_limit: usize,
    ) -> Result<ProcessObservation, GitError> {
        self.fail_if_cancelled(operation)?;
        let mut spec =
            ExecSpec::from_project_command(&self.command_spec_with_args(operation, args)?);
        spec.stdout = OutputPolicy::CaptureBounded {
            max_bytes: stdout_limit,
        };
        let runner = SynchronousProcessRunner::new(start)
            .map_err(|error| map_execution_error(operation, error))?
            .with_cancellation_flag(Arc::clone(&self.cancellation));
        runner
            .run(&spec)
            .map_err(|error| map_execution_error(operation, error))
    }

    fn exec_spec(&self, operation: GitOperation) -> Result<ExecSpec, GitError> {
        let mut spec = ExecSpec::from_project_command(&self.command_spec(operation)?);
        if operation.uses_spool() {
            spec.stdout = OutputPolicy::CaptureBounded {
                max_bytes: self.status_spool_limit_bytes,
            };
        }
        Ok(spec)
    }

    fn run(&self, start: &Path, operation: GitOperation) -> Result<Vec<u8>, GitError> {
        if operation.uses_spool() {
            return Err(GitError::new(
                GitErrorKind::InvalidData,
                operation.name(),
                format!(
                    "operation {} must use the bounded anonymous spool path",
                    operation.name()
                ),
            ));
        }
        self.fail_if_cancelled(operation)?;
        let runner = SynchronousProcessRunner::new(start)
            .map_err(|error| map_execution_error(operation, error))?
            .with_cancellation_flag(Arc::clone(&self.cancellation));
        let observation = runner
            .run(&self.exec_spec(operation)?)
            .map_err(|error| map_execution_error(operation, error))?;
        checked_stdout(operation, observation)
    }

    fn run_spooled(
        &self,
        root: &Path,
        operation: GitOperation,
    ) -> Result<SpooledProcessObservation, GitError> {
        if !operation.uses_spool() {
            return Err(GitError::new(
                GitErrorKind::InvalidData,
                operation.name(),
                format!(
                    "operation {} does not use the bounded spool path",
                    operation.name()
                ),
            ));
        }
        self.fail_if_cancelled(operation)?;
        SynchronousProcessRunner::new(root)
            .map_err(|error| map_execution_error(operation, error))?
            .with_cancellation_flag(Arc::clone(&self.cancellation))
            .run_spooled_stdout(&self.exec_spec(operation)?)
            .map_err(|error| map_execution_error(operation, error))
    }

    fn fail_if_cancelled(&self, operation: GitOperation) -> Result<(), GitError> {
        if self.cancellation.load(Ordering::Acquire) {
            return Err(GitError::new(
                GitErrorKind::Interrupted,
                operation.name(),
                "operation was interrupted before Git started",
            ));
        }
        Ok(())
    }

    fn resolve_path(&self, start: &Path, operation: GitOperation) -> Result<PathBuf, GitError> {
        let bytes = self.run(start, operation)?;
        parse_absolute_git_path(bytes, operation.name()).map_err(|error| {
            GitError::new(
                GitErrorKind::InvalidData,
                operation.name(),
                error.to_string(),
            )
        })
    }

    fn object_format(&self, root: &Path) -> Result<GitObjectFormat, GitError> {
        parse_object_format(self.run(root, GitOperation::ObjectFormat)?).map_err(|error| {
            GitError::new(
                GitErrorKind::InvalidData,
                GitOperation::ObjectFormat.name(),
                error.to_string(),
            )
        })
    }

    fn spooled_paths(
        &self,
        root: &Path,
        operation: GitOperation,
        max_paths: usize,
    ) -> Result<Vec<RepoRelativePath>, GitError> {
        let mut spooled = self.run_spooled(root, operation)?;
        check_spooled_observation(operation, &mut spooled, self.status_spool_limit_bytes)?;
        parse_git_path_list_reader_controlled(
            BufReader::new(spooled.stdout_file),
            self.status_record_limit_bytes,
            max_paths,
            &self.operation_budget,
        )
        .map_err(|error| map_path_list_read_error(operation, error))
    }

    /// Reads the complete bounded index representation required for scope acquisition.
    pub fn index_entries(&self, root: &Path) -> Result<Vec<GitIndexEntry>, GitError> {
        let object_format = self.object_format(root)?;
        let mut spooled = self.run_spooled(root, GitOperation::IndexEntries)?;
        check_spooled_observation(
            GitOperation::IndexEntries,
            &mut spooled,
            self.status_spool_limit_bytes,
        )?;
        parse_git_index_reader_controlled(
            BufReader::new(spooled.stdout_file),
            object_format,
            self.status_record_limit_bytes,
            self.status_entry_limit,
            &self.operation_budget,
        )
        .map_err(|error| map_index_read_error(GitOperation::IndexEntries, error))
    }

    /// Reads the exact raw index through one bounded, no-follow file descriptor.
    pub fn index_snapshot_bytes(&self, root: &Path, max_bytes: usize) -> Result<Vec<u8>, GitError> {
        let index_path = parse_index_snapshot_path(self.run(root, GitOperation::IndexPath)?)?;
        read_index_snapshot_file_controlled(&index_path, max_bytes, &self.operation_budget)
    }
}

fn operation_control_git_error(operation: GitOperation, error: OperationControlError) -> GitError {
    let kind = match error {
        OperationControlError::TimedOut => GitErrorKind::TimedOut,
        OperationControlError::Interrupted => GitErrorKind::Interrupted,
    };
    GitError::new(kind, operation.name(), error.to_string())
}

fn hardened_git_environment<I>(ambient: I) -> io::Result<BTreeMap<OsString, OsString>>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    let mut environment = BTreeMap::new();
    for (key, value) in ambient {
        if let Some(rejected) = REJECTED_GIT_ENV
            .iter()
            .find(|candidate| git_environment_key_eq(&key, candidate))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "ambient Git environment variable `{rejected}` would override Forge's resolved repository or Git executable; unset it and use `forge -C <path>`"
                ),
            ));
        }
        if PRESERVED_GIT_ENV
            .iter()
            .any(|candidate| git_environment_key_eq(&key, candidate))
            || indexed_git_config_key(&key, "GIT_CONFIG_KEY_")
            || indexed_git_config_key(&key, "GIT_CONFIG_VALUE_")
        {
            environment.insert(key, value);
        }
    }
    for (key, value) in HARDENED_GIT_ENV {
        environment.insert(OsString::from(key), OsString::from(value));
    }
    Ok(environment)
}

#[cfg(windows)]
fn git_environment_key_eq(key: &OsStr, expected: &str) -> bool {
    key.to_string_lossy().eq_ignore_ascii_case(expected)
}

#[cfg(not(windows))]
fn git_environment_key_eq(key: &OsStr, expected: &str) -> bool {
    key == OsStr::new(expected)
}

fn indexed_git_config_key(key: &OsStr, prefix: &str) -> bool {
    let Some(key) = key.to_str() else {
        return false;
    };
    let suffix = if cfg!(windows) {
        key.get(..prefix.len())
            .filter(|candidate| candidate.eq_ignore_ascii_case(prefix))
            .map(|_| &key[prefix.len()..])
    } else {
        key.strip_prefix(prefix)
    };
    suffix.is_some_and(|suffix| {
        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
    })
}

impl GitPort for GitCli {
    fn repository_root(&self, start: &Path) -> Result<PathBuf, GitError> {
        self.resolve_path(start, GitOperation::RepositoryRoot)
    }

    fn git_dir(&self, start: &Path) -> Result<PathBuf, GitError> {
        self.resolve_path(start, GitOperation::GitDir)
    }

    fn git_common_dir(&self, start: &Path) -> Result<PathBuf, GitError> {
        self.resolve_path(start, GitOperation::GitCommonDir)
    }

    fn status(&self, root: &Path) -> Result<PorcelainV2Status, GitError> {
        let object_format = self.object_format(root)?;
        let mut spooled = self.run_spooled(root, GitOperation::Status)?;
        check_spooled_observation(
            GitOperation::Status,
            &mut spooled,
            self.status_spool_limit_bytes,
        )?;
        let status = parse_status_porcelain_v2_reader_controlled(
            BufReader::new(spooled.stdout_file),
            object_format,
            self.status_record_limit_bytes,
            self.status_entry_limit,
            &self.operation_budget,
        )
        .map_err(|error| map_status_read_error(GitOperation::Status, error))?;
        if status.branch.oid.is_none() || status.branch.head.is_none() {
            return Err(GitError::new(
                GitErrorKind::InvalidData,
                GitOperation::Status.name(),
                "Git porcelain v2 status omitted required branch.oid or branch.head headers",
            ));
        }
        Ok(status)
    }

    fn file_set(&self, root: &Path) -> Result<GitFileSet, GitError> {
        let tracked =
            self.spooled_paths(root, GitOperation::TrackedFiles, self.status_entry_limit)?;
        let remaining = self.status_entry_limit.saturating_sub(tracked.len());
        let untracked = self.spooled_paths(root, GitOperation::UntrackedFiles, remaining)?;
        Ok(GitFileSet::new(tracked, untracked))
    }

    fn index_snapshot_bytes(&self, root: &Path, max_bytes: usize) -> Result<Vec<u8>, GitError> {
        GitCli::index_snapshot_bytes(self, root, max_bytes)
    }

    fn index_entries(&self, root: &Path) -> Result<Vec<GitIndexEntry>, GitError> {
        GitCli::index_entries(self, root)
    }

    fn read_commit_file_bounded(
        &self,
        root: &Path,
        commit: &GitObjectId,
        path: &RepoRelativePath,
        max_bytes: u64,
    ) -> Result<Option<Vec<u8>>, GitError> {
        let object_id_width = commit.as_bytes().len();
        let commit = object_id_argument(commit, GitOperation::CommitTreeEntry)?;
        let tree_args = vec![
            OsString::from("ls-tree"),
            OsString::from("-z"),
            OsString::from("--full-tree"),
            commit,
            OsString::from("--"),
            path.as_path().as_os_str().to_os_string(),
        ];
        let tree = checked_stdout(
            GitOperation::CommitTreeEntry,
            self.run_with_args(
                root,
                GitOperation::CommitTreeEntry,
                tree_args,
                self.status_record_limit_bytes,
            )?,
        )?;
        let Some(blob_oid) = parse_exact_tree_blob(&tree, path, object_id_width)? else {
            return Ok(None);
        };

        let size_args = vec![
            OsString::from("cat-file"),
            OsString::from("-s"),
            blob_oid.clone(),
        ];
        let size = checked_stdout(
            GitOperation::BlobSize,
            self.run_with_args(root, GitOperation::BlobSize, size_args, 128)?,
        )?;
        let size = parse_blob_size(size)?;
        if size > max_bytes {
            return Err(GitError::new(
                GitErrorKind::OutputLimit,
                GitOperation::BlobContents.name(),
                format!("blob size {size} bytes exceeds the configured bound of {max_bytes} bytes"),
            ));
        }
        let stdout_limit = usize::try_from(max_bytes).map_err(|_| {
            GitError::new(
                GitErrorKind::OutputLimit,
                GitOperation::BlobContents.name(),
                "the configured blob bound exceeds this platform's addressable memory",
            )
        })?;
        let blob_args = vec![OsString::from("cat-file"), OsString::from("blob"), blob_oid];
        let bytes = checked_stdout(
            GitOperation::BlobContents,
            self.run_with_args(root, GitOperation::BlobContents, blob_args, stdout_limit)?,
        )?;
        if bytes.len() as u64 != size {
            return Err(GitError::new(
                GitErrorKind::InvalidData,
                GitOperation::BlobContents.name(),
                format!(
                    "Git returned {} blob bytes after reporting a size of {size}",
                    bytes.len()
                ),
            ));
        }
        Ok(Some(bytes))
    }
}

#[derive(Debug, Clone, Copy)]
enum GitOperation {
    RepositoryRoot,
    GitDir,
    GitCommonDir,
    IndexPath,
    IndexSnapshot,
    ObjectFormat,
    Status,
    IndexEntries,
    TrackedFiles,
    UntrackedFiles,
    CommitTreeEntry,
    BlobSize,
    BlobContents,
}

impl GitOperation {
    fn name(self) -> &'static str {
        match self {
            Self::RepositoryRoot => "repository-root",
            Self::GitDir => "git-dir",
            Self::GitCommonDir => "git-common-dir",
            Self::IndexPath => "index-path",
            Self::IndexSnapshot => "index-snapshot",
            Self::ObjectFormat => "object-format",
            Self::Status => "status",
            Self::IndexEntries => "index-entries",
            Self::TrackedFiles => "tracked-files",
            Self::UntrackedFiles => "untracked-files",
            Self::CommitTreeEntry => "commit-tree-entry",
            Self::BlobSize => "blob-size",
            Self::BlobContents => "blob-contents",
        }
    }

    fn command_id(self) -> &'static str {
        match self {
            Self::RepositoryRoot => "runtime.git.repository-root",
            Self::GitDir => "runtime.git.git-dir",
            Self::GitCommonDir => "runtime.git.git-common-dir",
            Self::IndexPath => "runtime.git.index-path",
            Self::IndexSnapshot => "runtime.git.index-snapshot",
            Self::ObjectFormat => "runtime.git.object-format",
            Self::Status => "runtime.git.status",
            Self::IndexEntries => "runtime.git.index-entries",
            Self::TrackedFiles => "runtime.git.tracked-files",
            Self::UntrackedFiles => "runtime.git.untracked-files",
            Self::CommitTreeEntry => "runtime.git.commit-tree-entry",
            Self::BlobSize => "runtime.git.blob-size",
            Self::BlobContents => "runtime.git.blob-contents",
        }
    }

    fn static_args(self) -> Option<&'static [&'static str]> {
        Some(match self {
            Self::RepositoryRoot => REPOSITORY_ROOT_ARGS,
            Self::GitDir => GIT_DIR_ARGS,
            Self::GitCommonDir => GIT_COMMON_DIR_ARGS,
            Self::IndexPath => INDEX_PATH_ARGS,
            Self::ObjectFormat => OBJECT_FORMAT_ARGS,
            Self::Status => STATUS_PORCELAIN_V2_ARGS,
            Self::IndexEntries => INDEX_ENTRIES_ARGS,
            Self::TrackedFiles => TRACKED_FILES_ARGS,
            Self::UntrackedFiles => UNTRACKED_FILES_ARGS,
            Self::IndexSnapshot | Self::CommitTreeEntry | Self::BlobSize | Self::BlobContents => {
                return None;
            }
        })
    }

    fn uses_spool(self) -> bool {
        matches!(
            self,
            Self::Status | Self::IndexEntries | Self::TrackedFiles | Self::UntrackedFiles
        )
    }
}

fn check_spooled_observation(
    operation: GitOperation,
    spooled: &mut SpooledProcessObservation,
    spool_limit_bytes: usize,
) -> Result<(), GitError> {
    check_observation(operation, &spooled.observation)?;
    spooled
        .stdout_file
        .flush()
        .map_err(|error| map_io_error(operation, "flush bounded stdout spool", error))?;
    let spool_length = spooled
        .stdout_file
        .metadata()
        .map_err(|error| map_io_error(operation, "inspect bounded stdout spool", error))?
        .len();
    let spool_limit = u64::try_from(spool_limit_bytes).unwrap_or(u64::MAX);
    let expected_length = spooled.observation.stdout_total_bytes.min(spool_limit);
    if spool_length != expected_length {
        return Err(GitError::new(
            GitErrorKind::InvalidData,
            operation.name(),
            format!(
                "bounded stdout spool retained {spool_length} bytes, expected {expected_length} from {} total bytes",
                spooled.observation.stdout_total_bytes
            ),
        ));
    }
    spooled
        .stdout_file
        .seek(SeekFrom::Start(0))
        .map_err(|error| map_io_error(operation, "rewind bounded stdout spool", error))?;
    Ok(())
}

fn checked_stdout(
    operation: GitOperation,
    observation: ProcessObservation,
) -> Result<Vec<u8>, GitError> {
    check_observation(operation, &observation)?;
    Ok(observation.stdout)
}

fn check_observation(
    operation: GitOperation,
    observation: &ProcessObservation,
) -> Result<(), GitError> {
    if observation.timed_out {
        return Err(GitError::new(
            GitErrorKind::TimedOut,
            operation.name(),
            "operation exceeded its timeout",
        ));
    }
    if observation.interrupted {
        return Err(GitError::new(
            GitErrorKind::Interrupted,
            operation.name(),
            "operation was interrupted",
        ));
    }
    if observation.stdout_truncated || observation.stderr_truncated {
        return Err(GitError::new(
            GitErrorKind::OutputLimit,
            operation.name(),
            format!(
                "output exceeded the configured bound (stdout total {} bytes, stderr total {} bytes)",
                observation.stdout_total_bytes, observation.stderr_total_bytes,
            ),
        ));
    }
    if observation.exit_code != Some(0) {
        let stderr = bounded_stderr_context(&observation.stderr);
        return Err(GitError::new(
            classify_command_failure(&observation.stderr),
            operation.name(),
            format!(
                "exit code {:?}, signal {:?}{stderr}",
                observation.exit_code, observation.signal,
            ),
        ));
    }
    Ok(())
}

fn map_status_read_error(operation: GitOperation, error: PorcelainV2ReadError) -> GitError {
    match error {
        PorcelainV2ReadError::Control(error) => operation_control_git_error(operation, error),
        PorcelainV2ReadError::Input {
            offset,
            record,
            source,
        } => GitError::new(
            GitErrorKind::Io,
            operation.name(),
            format!(
                "failed to read Git porcelain v2 status at byte {offset}, record {record}: {source}"
            ),
        ),
        PorcelainV2ReadError::Parse(error) => GitError::new(
            GitErrorKind::InvalidData,
            operation.name(),
            format!("Git returned malformed porcelain v2 status: {error}"),
        ),
    }
}

fn map_path_list_read_error(operation: GitOperation, error: GitPathListReadError) -> GitError {
    match error {
        GitPathListReadError::Control(error) => operation_control_git_error(operation, error),
        GitPathListReadError::Input { source, .. } => GitError::new(
            GitErrorKind::Io,
            operation.name(),
            format!("failed to read Git path list: {source}"),
        ),
        error => GitError::new(
            GitErrorKind::InvalidData,
            operation.name(),
            format!("Git returned a malformed path list: {error}"),
        ),
    }
}

fn map_index_read_error(operation: GitOperation, error: GitIndexReadError) -> GitError {
    match error {
        GitIndexReadError::Control(error) => operation_control_git_error(operation, error),
        GitIndexReadError::Input { source, .. } => GitError::new(
            GitErrorKind::Io,
            operation.name(),
            format!("failed to read Git index entries: {source}"),
        ),
        error => GitError::new(
            GitErrorKind::InvalidData,
            operation.name(),
            format!("Git returned malformed index entries: {error}"),
        ),
    }
}

#[cfg(all(test, unix))]
fn read_index_snapshot_file(path: &Path, max_bytes: usize) -> Result<Vec<u8>, GitError> {
    read_index_snapshot_file_controlled(path, max_bytes, &UnlimitedOperationControl)
}

fn read_index_snapshot_file_controlled(
    path: &Path,
    max_bytes: usize,
    control: &dyn forge_core::OperationControl,
) -> Result<Vec<u8>, GitError> {
    read_index_snapshot_file_after_inspection_controlled(path, max_bytes, control, || Ok(()))
}

#[cfg(all(test, unix))]
fn read_index_snapshot_file_after_inspection<F>(
    path: &Path,
    max_bytes: usize,
    after_path_inspection: F,
) -> Result<Vec<u8>, GitError>
where
    F: FnOnce() -> io::Result<()>,
{
    read_index_snapshot_file_after_inspection_controlled(
        path,
        max_bytes,
        &UnlimitedOperationControl,
        after_path_inspection,
    )
}

fn read_index_snapshot_file_after_inspection_controlled<F>(
    path: &Path,
    max_bytes: usize,
    control: &dyn forge_core::OperationControl,
    after_path_inspection: F,
) -> Result<Vec<u8>, GitError>
where
    F: FnOnce() -> io::Result<()>,
{
    control
        .checkpoint()
        .map_err(|error| operation_control_git_error(GitOperation::IndexSnapshot, error))?;
    let lock_path = index_lock_path(path)?;
    ensure_index_lock_absent(&lock_path, "before reading the index")?;

    let path_metadata = fs::symlink_metadata(path).map_err(|error| {
        map_io_error(
            GitOperation::IndexSnapshot,
            "inspect resolved index path without following links",
            error,
        )
    })?;
    validate_index_snapshot_metadata(&path_metadata, "resolved index path")?;
    after_path_inspection().map_err(|error| {
        map_io_error(
            GitOperation::IndexSnapshot,
            "complete the index inspection boundary",
            error,
        )
    })?;

    let mut file = open_index_file_no_follow(path).map_err(|error| {
        if no_follow_open_rejected_link(&error) {
            invalid_index_snapshot("resolved index path became a symbolic link before it opened")
        } else {
            map_io_error(
                GitOperation::IndexSnapshot,
                "open resolved index path without following links",
                error,
            )
        }
    })?;
    let initial_metadata = file.metadata().map_err(|error| {
        map_io_error(
            GitOperation::IndexSnapshot,
            "inspect opened index file",
            error,
        )
    })?;
    validate_index_snapshot_metadata(&initial_metadata, "opened index file")?;

    let max_bytes_u64 = u64::try_from(max_bytes).unwrap_or(u64::MAX);
    if initial_metadata.len() > max_bytes_u64 {
        return Err(index_snapshot_too_large(initial_metadata.len(), max_bytes));
    }

    let capacity = usize::try_from(initial_metadata.len())
        .unwrap_or(max_bytes)
        .min(max_bytes);
    let mut bytes = Vec::with_capacity(capacity);
    let mut bounded = std::io::Read::by_ref(&mut file).take(max_bytes_u64.saturating_add(1));
    let mut chunk = [0_u8; 64 * 1024];
    loop {
        control
            .checkpoint()
            .map_err(|error| operation_control_git_error(GitOperation::IndexSnapshot, error))?;
        let read = bounded.read(&mut chunk).map_err(|error| {
            map_io_error(
                GitOperation::IndexSnapshot,
                "read opened index file within its byte bound",
                error,
            )
        })?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    if bytes.len() > max_bytes {
        return Err(index_snapshot_too_large(bytes.len() as u64, max_bytes));
    }

    control
        .checkpoint()
        .map_err(|error| operation_control_git_error(GitOperation::IndexSnapshot, error))?;

    let final_metadata = file.metadata().map_err(|error| {
        map_io_error(
            GitOperation::IndexSnapshot,
            "reinspect opened index file after reading",
            error,
        )
    })?;
    validate_index_snapshot_metadata(&final_metadata, "reinspected index file")?;
    let observed_length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if initial_metadata.len() != final_metadata.len()
        || observed_length != final_metadata.len()
        || metadata_modified_changed(&initial_metadata, &final_metadata)
    {
        return Err(invalid_index_snapshot(
            "index file changed while its bounded snapshot was being read",
        ));
    }
    ensure_index_lock_absent(&lock_path, "after reading the index")?;

    Ok(bytes)
}

fn parse_index_snapshot_path(mut bytes: Vec<u8>) -> Result<PathBuf, GitError> {
    trim_one_line_ending(&mut bytes);
    if bytes.contains(&b'\n') {
        return Err(invalid_index_snapshot(
            "split indexes are not a complete single-file snapshot",
        ));
    }
    parse_absolute_git_path(bytes, GitOperation::IndexPath.name()).map_err(|error| {
        GitError::new(
            GitErrorKind::InvalidData,
            GitOperation::IndexPath.name(),
            error.to_string(),
        )
    })
}

fn index_lock_path(index_path: &Path) -> Result<PathBuf, GitError> {
    let Some(file_name) = index_path.file_name() else {
        return Err(invalid_index_snapshot(
            "resolved index path does not name a file",
        ));
    };
    let mut lock_name = file_name.to_os_string();
    lock_name.push(".lock");
    Ok(index_path.with_file_name(lock_name))
}

fn ensure_index_lock_absent(lock_path: &Path, phase: &str) -> Result<(), GitError> {
    match fs::symlink_metadata(lock_path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(invalid_index_snapshot(format!(
            "index.lock exists {phase}; the index may be changing"
        ))),
        Err(error) => Err(map_io_error(
            GitOperation::IndexSnapshot,
            "inspect index.lock without following links",
            error,
        )),
    }
}

fn validate_index_snapshot_metadata(
    metadata: &fs::Metadata,
    subject: &str,
) -> Result<(), GitError> {
    if metadata_is_link_or_reparse(metadata) {
        return Err(invalid_index_snapshot(format!(
            "{subject} is a symbolic link or reparse point"
        )));
    }
    if !metadata.is_file() {
        return Err(invalid_index_snapshot(format!(
            "{subject} is not a regular file"
        )));
    }
    Ok(())
}

fn index_snapshot_too_large(observed_bytes: u64, max_bytes: usize) -> GitError {
    GitError::new(
        GitErrorKind::OutputLimit,
        GitOperation::IndexSnapshot.name(),
        format!(
            "raw index size {observed_bytes} bytes exceeds the configured bound of {max_bytes} bytes"
        ),
    )
}

fn invalid_index_snapshot(detail: impl Into<String>) -> GitError {
    GitError::new(
        GitErrorKind::InvalidData,
        GitOperation::IndexSnapshot.name(),
        detail,
    )
}

fn metadata_modified_changed(initial: &fs::Metadata, final_metadata: &fs::Metadata) -> bool {
    modification_times_differ_or_are_unobservable(initial.modified(), final_metadata.modified())
}

fn modification_times_differ_or_are_unobservable(
    initial: io::Result<std::time::SystemTime>,
    final_time: io::Result<std::time::SystemTime>,
) -> bool {
    match (initial, final_time) {
        (Ok(initial), Ok(final_metadata)) => initial != final_metadata,
        // Snapshot stability is a proof obligation. If either timestamp cannot be observed, the
        // reader cannot establish that the file stayed unchanged and must fail closed.
        _ => true,
    }
}

#[cfg(unix)]
fn open_index_file_no_follow(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    OpenOptions::new()
        .read(true)
        // A path can become a FIFO after the no-follow metadata probe. Nonblocking open lets the
        // descriptor metadata check reject it instead of waiting forever for an attacker-supplied
        // writer. O_NONBLOCK has no effect on ordinary index files.
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK)
        .open(path)
}

#[cfg(windows)]
fn open_index_file_no_follow(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(not(any(unix, windows)))]
fn open_index_file_no_follow(_path: &Path) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "bounded raw-index snapshots require a no-follow file-open primitive",
    ))
}

#[cfg(windows)]
fn metadata_is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn metadata_is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(unix)]
fn no_follow_open_rejected_link(error: &io::Error) -> bool {
    error.raw_os_error() == Some(nix::libc::ELOOP)
}

#[cfg(not(unix))]
fn no_follow_open_rejected_link(_error: &io::Error) -> bool {
    false
}

fn map_io_error(operation: GitOperation, action: &str, error: io::Error) -> GitError {
    GitError::new(
        GitErrorKind::Io,
        operation.name(),
        format!("{action}: {error}"),
    )
}

fn map_execution_error(operation: GitOperation, error: ProcessError) -> GitError {
    let kind = match error.kind() {
        ProcessErrorKind::ExecutableUnavailable => GitErrorKind::ExecutableUnavailable,
        _ => GitErrorKind::Io,
    };
    GitError::new(kind, operation.name(), error.to_string())
}

fn classify_command_failure(stderr: &[u8]) -> GitErrorKind {
    let stderr = String::from_utf8_lossy(stderr).to_ascii_lowercase();
    if stderr.contains("not a git repository") {
        GitErrorKind::NotRepository
    } else if [
        "corrupt",
        "bad object",
        "bad signature",
        "invalid object",
        "index file smaller than expected",
        "unable to map index file",
    ]
    .iter()
    .any(|marker| stderr.contains(marker))
    {
        GitErrorKind::CorruptRepository
    } else {
        GitErrorKind::CommandFailed
    }
}

fn bounded_stderr_context(stderr: &[u8]) -> String {
    const LIMIT: usize = 4 * 1024;
    if stderr.is_empty() {
        return String::new();
    }
    let retained = &stderr[..stderr.len().min(LIMIT)];
    let suffix = if stderr.len() > LIMIT {
        " [truncated]"
    } else {
        ""
    };
    format!(": {}{suffix}", String::from_utf8_lossy(retained).trim_end())
}

fn parse_object_format(mut bytes: Vec<u8>) -> io::Result<GitObjectFormat> {
    trim_one_line_ending(&mut bytes);
    match bytes.as_slice() {
        b"sha1" => Ok(GitObjectFormat::Sha1),
        b"sha256" => Ok(GitObjectFormat::Sha256),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "git object-format returned an unsupported or malformed value",
        )),
    }
}

fn object_id_argument(
    object_id: &GitObjectId,
    operation: GitOperation,
) -> Result<OsString, GitError> {
    object_id_bytes_argument(object_id.as_bytes(), object_id.as_bytes().len())
        .map_err(|detail| GitError::new(GitErrorKind::InvalidData, operation.name(), detail))
}

fn object_id_bytes_argument(bytes: &[u8], expected_width: usize) -> Result<OsString, &'static str> {
    if !matches!(expected_width, 40 | 64)
        || bytes.len() != expected_width
        || !bytes.iter().all(u8::is_ascii_hexdigit)
    {
        return Err("Git returned an invalid full object ID");
    }
    let value = std::str::from_utf8(bytes).map_err(|_| "Git returned a non-ASCII object ID")?;
    Ok(OsString::from(value))
}

fn parse_exact_tree_blob(
    bytes: &[u8],
    requested_path: &RepoRelativePath,
    object_id_width: usize,
) -> Result<Option<OsString>, GitError> {
    if bytes.is_empty() {
        return Ok(None);
    }
    let Some(record) = bytes.strip_suffix(&[0]) else {
        return Err(invalid_tree_entry("tree entry was not NUL terminated"));
    };
    if record.contains(&0) {
        return Err(invalid_tree_entry(
            "an exact literal path query returned multiple tree entries",
        ));
    }
    let Some(tab) = record.iter().position(|byte| *byte == b'\t') else {
        return Err(invalid_tree_entry("tree entry omitted the path delimiter"));
    };
    let metadata = &record[..tab];
    let path = path_buf_from_git_bytes(record[tab + 1..].to_vec())
        .map_err(|error| invalid_tree_entry(format!("tree entry path was invalid: {error}")))?;
    if path != requested_path.as_path() {
        return Err(invalid_tree_entry(
            "literal path query returned a different repository path",
        ));
    }
    let mut fields = metadata.split(|byte| *byte == b' ');
    let (Some(mode), Some(kind), Some(object_id), None) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return Err(invalid_tree_entry("tree entry metadata was malformed"));
    };
    if !matches!(mode, b"100644" | b"100755") || kind != b"blob" {
        return Err(invalid_tree_entry(
            "the selected commit path is not a regular file blob",
        ));
    }
    object_id_bytes_argument(object_id, object_id_width)
        .map(Some)
        .map_err(invalid_tree_entry)
}

fn invalid_tree_entry(detail: impl Into<String>) -> GitError {
    GitError::new(
        GitErrorKind::InvalidData,
        GitOperation::CommitTreeEntry.name(),
        detail,
    )
}

fn parse_blob_size(mut bytes: Vec<u8>) -> Result<u64, GitError> {
    trim_one_line_ending(&mut bytes);
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(GitError::new(
            GitErrorKind::InvalidData,
            GitOperation::BlobSize.name(),
            "Git returned a malformed blob size",
        ));
    }
    std::str::from_utf8(&bytes)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| {
            GitError::new(
                GitErrorKind::InvalidData,
                GitOperation::BlobSize.name(),
                "Git returned a blob size outside the supported range",
            )
        })
}

fn parse_absolute_git_path(mut bytes: Vec<u8>, operation: &str) -> io::Result<PathBuf> {
    trim_one_line_ending(&mut bytes);
    if bytes.is_empty() || bytes.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("git {operation} returned an empty or NUL-containing path"),
        ));
    }

    let path = path_buf_from_git_bytes(bytes)?;
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("git {operation} did not return an absolute path"),
        ));
    }
    Ok(path)
}

#[cfg(windows)]
fn trim_one_line_ending(bytes: &mut Vec<u8>) {
    if bytes.ends_with(b"\r\n") {
        bytes.truncate(bytes.len() - 2);
    } else if bytes.ends_with(b"\n") {
        bytes.truncate(bytes.len() - 1);
    }
}

#[cfg(not(windows))]
fn trim_one_line_ending(bytes: &mut Vec<u8>) {
    if bytes.ends_with(b"\n") {
        bytes.truncate(bytes.len() - 1);
    }
}

#[cfg(unix)]
fn path_buf_from_git_bytes(bytes: Vec<u8>) -> io::Result<PathBuf> {
    use std::os::unix::ffi::OsStringExt as _;

    Ok(PathBuf::from(OsString::from_vec(bytes)))
}

#[cfg(not(unix))]
fn path_buf_from_git_bytes(bytes: Vec<u8>) -> io::Result<PathBuf> {
    String::from_utf8(bytes).map(PathBuf::from).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Git returned a path that is not valid UTF-8 on this platform",
        )
    })
}

#[cfg(test)]
mod tests {
    use std::ffi::{OsStr, OsString};
    #[cfg(unix)]
    use std::fs;
    use std::io;
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    use forge_core::ports::{
        GitPort as _, OutputPolicy, ProcessError, ProcessErrorKind, ProcessObservation, StdinPolicy,
    };
    use forge_core::{BranchOid, Digest, GitErrorKind, GitObjectFormat, RepoRelativePath};

    use crate::control::OperationBudget;

    use super::{
        GitCli, GitOperation, HARDENED_GIT_ENV, HARDENED_GIT_GLOBAL_ARGS, INDEX_ENTRIES_ARGS,
        INDEX_PATH_ARGS, OBJECT_FORMAT_ARGS, STATUS_PORCELAIN_V2_ARGS, TRACKED_FILES_ARGS,
        UNTRACKED_FILES_ARGS, checked_stdout, classify_command_failure, hardened_git_environment,
        indexed_git_config_key, modification_times_differ_or_are_unobservable,
        parse_absolute_git_path, parse_blob_size, parse_exact_tree_blob, parse_object_format,
    };
    #[cfg(unix)]
    use super::{
        parse_index_snapshot_path, read_index_snapshot_file,
        read_index_snapshot_file_after_inspection,
    };

    #[test]
    fn git_execution_uses_the_shared_bounded_noninteractive_policy()
    -> Result<(), Box<dyn std::error::Error>> {
        let git = GitCli::new().with_status_spool_limit_bytes(1234);
        let status = git.exec_spec(GitOperation::Status)?;
        let root = git.exec_spec(GitOperation::RepositoryRoot)?;

        assert_eq!(status.stdin, StdinPolicy::Closed);
        assert_eq!(
            status.stdout,
            OutputPolicy::CaptureBounded { max_bytes: 1234 }
        );
        assert_eq!(
            root.stdout,
            OutputPolicy::CaptureBounded {
                max_bytes: forge_core::ports::DEFAULT_CAPTURE_LIMIT_BYTES
            }
        );
        assert_eq!(
            status.env.overrides.get(OsStr::new("GIT_TERMINAL_PROMPT")),
            Some(&OsString::from("0"))
        );
        Ok(())
    }

    #[test]
    fn expired_command_budget_prevents_git_from_starting() {
        let git = GitCli::new().with_operation_budget(OperationBudget::until(
            Instant::now(),
            Arc::new(AtomicBool::new(false)),
        ));

        let result = git.exec_spec(GitOperation::RepositoryRoot);

        assert!(matches!(
            result,
            Err(ref error) if error.kind() == GitErrorKind::TimedOut
        ));
    }

    #[test]
    fn git_maps_typed_missing_executable_without_parsing_text() {
        let process_error = ProcessError::new(
            ProcessErrorKind::ExecutableUnavailable,
            "spawn child process",
            io::Error::new(io::ErrorKind::NotFound, "localized diagnostic"),
        );

        assert_eq!(
            super::map_execution_error(GitOperation::Status, process_error).kind(),
            GitErrorKind::ExecutableUnavailable
        );
    }

    #[test]
    fn hardened_status_is_argv_only_and_non_interactive() {
        assert!(HARDENED_GIT_GLOBAL_ARGS.contains(&"--no-pager"));
        assert!(HARDENED_GIT_GLOBAL_ARGS.contains(&"--no-optional-locks"));
        assert!(HARDENED_GIT_GLOBAL_ARGS.contains(&"--no-replace-objects"));
        assert!(HARDENED_GIT_GLOBAL_ARGS.contains(&"--literal-pathspecs"));
        assert!(
            HARDENED_GIT_GLOBAL_ARGS
                .windows(2)
                .any(|args| args == ["-c", "core.fsmonitor=false"])
        );
        assert!(STATUS_PORCELAIN_V2_ARGS.contains(&"--porcelain=v2"));
        assert!(STATUS_PORCELAIN_V2_ARGS.contains(&"-z"));
        assert_eq!(
            OBJECT_FORMAT_ARGS,
            ["rev-parse", "--show-object-format=output"]
        );
        assert_eq!(
            INDEX_PATH_ARGS,
            [
                "rev-parse",
                "--path-format=absolute",
                "--git-path",
                "index",
                "--shared-index-path"
            ]
        );
        assert_eq!(TRACKED_FILES_ARGS, ["ls-files", "--cached", "-z", "--"]);
        assert_eq!(
            INDEX_ENTRIES_ARGS,
            ["ls-files", "--stage", "-v", "-z", "--"]
        );
        assert_eq!(
            UNTRACKED_FILES_ARGS,
            ["ls-files", "--others", "--exclude-standard", "-z", "--"]
        );
        assert!(HARDENED_GIT_ENV.contains(&("GIT_TERMINAL_PROMPT", "0")));
        assert!(HARDENED_GIT_ENV.contains(&("GIT_OPTIONAL_LOCKS", "0")));
        assert!(HARDENED_GIT_ENV.contains(&("GIT_NO_LAZY_FETCH", "1")));
        assert!(HARDENED_GIT_ENV.contains(&("GCM_INTERACTIVE", "Never")));
        assert!(HARDENED_GIT_ENV.contains(&("LC_ALL", "C")));
    }

    #[test]
    fn git_environment_preserves_discovery_and_config_without_unrelated_values()
    -> Result<(), Box<dyn std::error::Error>> {
        let environment = hardened_git_environment([
            (
                OsString::from("GIT_CEILING_DIRECTORIES"),
                OsString::from("/workspace"),
            ),
            (
                OsString::from("GIT_CONFIG_GLOBAL"),
                OsString::from("/config/git/config"),
            ),
            (OsString::from("GIT_CONFIG_COUNT"), OsString::from("1")),
            (
                OsString::from("GIT_CONFIG_KEY_0"),
                OsString::from("safe.directory"),
            ),
            (
                OsString::from("GIT_CONFIG_VALUE_0"),
                OsString::from("/workspace"),
            ),
            (
                OsString::from("FORGE_SECRET_TEST_VALUE"),
                OsString::from("must-not-leak"),
            ),
        ])?;

        assert_eq!(
            environment.get(OsStr::new("GIT_CEILING_DIRECTORIES")),
            Some(&OsString::from("/workspace"))
        );
        assert_eq!(
            environment.get(OsStr::new("GIT_CONFIG_GLOBAL")),
            Some(&OsString::from("/config/git/config"))
        );
        assert_eq!(
            environment.get(OsStr::new("GIT_CONFIG_KEY_0")),
            Some(&OsString::from("safe.directory"))
        );
        assert_eq!(
            environment.get(OsStr::new("GIT_CONFIG_VALUE_0")),
            Some(&OsString::from("/workspace"))
        );
        assert!(!environment.contains_key(OsStr::new("FORGE_SECRET_TEST_VALUE")));
        Ok(())
    }

    #[test]
    fn git_environment_overrides_interactive_and_locale_controls()
    -> Result<(), Box<dyn std::error::Error>> {
        let environment = hardened_git_environment([
            (OsString::from("GIT_TERMINAL_PROMPT"), OsString::from("1")),
            (OsString::from("GIT_OPTIONAL_LOCKS"), OsString::from("1")),
            (OsString::from("GCM_INTERACTIVE"), OsString::from("Always")),
            (OsString::from("LC_ALL"), OsString::from("fr_FR.UTF-8")),
        ])?;

        for (key, expected) in HARDENED_GIT_ENV {
            assert_eq!(
                environment.get(OsStr::new(key)),
                Some(&OsString::from(expected))
            );
        }
        Ok(())
    }

    #[test]
    fn git_environment_rejects_repository_redirection_without_echoing_values()
    -> Result<(), Box<dyn std::error::Error>> {
        for key in ["GIT_DIR", "GIT_WORK_TREE", "GIT_EXEC_PATH"] {
            let result = hardened_git_environment([(
                OsString::from(key),
                OsString::from("sensitive-value-must-not-leak"),
            )]);
            let error = result
                .err()
                .ok_or("repository redirection was not rejected")?;

            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(error.to_string().contains(key));
            assert!(!error.to_string().contains("sensitive-value-must-not-leak"));
        }
        Ok(())
    }

    #[test]
    fn indexed_git_config_names_require_a_decimal_index() {
        assert!(indexed_git_config_key(
            OsStr::new("GIT_CONFIG_KEY_0"),
            "GIT_CONFIG_KEY_"
        ));
        assert!(indexed_git_config_key(
            OsStr::new("GIT_CONFIG_VALUE_123"),
            "GIT_CONFIG_VALUE_"
        ));
        for invalid in [
            "GIT_CONFIG_KEY_",
            "GIT_CONFIG_KEY_-1",
            "GIT_CONFIG_KEY_NAME",
            "XGIT_CONFIG_KEY_0",
        ] {
            assert!(!indexed_git_config_key(
                OsStr::new(invalid),
                "GIT_CONFIG_KEY_"
            ));
        }
    }

    #[cfg(unix)]
    #[test]
    fn raw_index_path_parser_rejects_split_index_dependencies()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            parse_index_snapshot_path(b"/repo/.git/index\n".to_vec())?,
            Path::new("/repo/.git/index")
        );
        let error = parse_index_snapshot_path(
            b"/repo/.git/index\n/repo/.git/sharedindex.0123456789abcdef\n".to_vec(),
        )
        .err()
        .ok_or("split index paths unexpectedly produced a single-file snapshot path")?;
        assert_eq!(error.kind(), GitErrorKind::InvalidData);
        assert_eq!(error.operation(), "index-snapshot");
        assert!(error.detail().contains("split indexes"));
        Ok(())
    }

    #[test]
    fn raw_index_timestamp_observation_fails_closed() {
        let now = std::time::SystemTime::now();
        assert!(!modification_times_differ_or_are_unobservable(
            Ok(now),
            Ok(now)
        ));
        assert!(modification_times_differ_or_are_unobservable(
            Ok(now),
            Err(io::Error::other("final timestamp unavailable"))
        ));
        assert!(modification_times_differ_or_are_unobservable(
            Err(io::Error::other("initial timestamp unavailable")),
            Ok(now)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn raw_index_file_reader_does_not_follow_a_symbolic_link()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir()?;
        let real_index = directory.path().join("index.real");
        let linked_index = directory.path().join("index");
        fs::write(&real_index, b"DIRCopaque-index-bytes")?;
        symlink("index.real", &linked_index)?;

        let error = read_index_snapshot_file(&linked_index, 1024)
            .err()
            .ok_or("symbolic-link index unexpectedly produced a raw snapshot")?;
        assert_eq!(error.kind(), GitErrorKind::InvalidData);
        assert_eq!(error.operation(), "index-snapshot");
        assert!(error.detail().contains("symbolic link"));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn raw_index_file_reader_does_not_block_when_the_path_becomes_a_fifo()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let index = directory.path().join("index");
        let original = directory.path().join("index.original");
        let fifo = directory.path().join("index.fifo");
        fs::write(&index, b"DIRCopaque-index-bytes")?;
        let created = std::process::Command::new("mkfifo").arg(&fifo).output()?;
        if !created.status.success() {
            return Err(io::Error::other(format!(
                "mkfifo failed: {}",
                String::from_utf8_lossy(&created.stderr)
            ))
            .into());
        }

        let error = read_index_snapshot_file_after_inspection(&index, 1024, || {
            fs::rename(&index, &original)?;
            fs::rename(&fifo, &index)
        })
        .err()
        .ok_or("FIFO replacement unexpectedly produced a raw snapshot")?;

        assert_eq!(error.kind(), GitErrorKind::InvalidData);
        assert_eq!(error.operation(), "index-snapshot");
        assert!(error.detail().contains("not a regular file"));
        Ok(())
    }

    #[test]
    fn git_port_dogfoods_the_current_worktree() -> Result<(), Box<dyn std::error::Error>> {
        let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let expected_root = crate_dir.join("../..").canonicalize()?;
        let git = GitCli::new();

        let root = git.repository_root(crate_dir)?;
        let git_dir = git.git_dir(&root)?;
        let git_common_dir = git.git_common_dir(&root)?;
        let status = git.status(&root)?;
        let file_set = git.file_set(&root)?;
        let index_snapshot = git.index_snapshot_bytes(&root, 64 * 1024 * 1024)?;
        let index_entries = git.index_entries(&root)?;

        assert_eq!(root, expected_root);
        assert!(git_dir.is_absolute());
        assert!(git_dir.is_dir());
        assert!(git_common_dir.is_absolute());
        assert!(git_common_dir.is_dir());
        assert!(status.branch.oid.is_some());
        assert!(status.branch.head.is_some());
        assert!(
            file_set
                .tracked
                .iter()
                .any(|path| path.as_path() == Path::new("Cargo.toml"))
        );
        assert!(
            index_entries
                .iter()
                .any(|entry| entry.path.as_path() == Path::new("Cargo.toml") && entry.stage == 0)
        );
        assert!(index_snapshot.starts_with(b"DIRC"));
        let head = match status.branch.oid {
            Some(BranchOid::Commit(head)) => head,
            _ => return Err("dogfood repository did not have a commit".into()),
        };
        let committed_manifest = git
            .read_commit_file_bounded(
                &root,
                &head,
                &RepoRelativePath::new("Cargo.toml")?,
                1024 * 1024,
            )?
            .ok_or("committed Cargo.toml was absent")?;
        assert!(
            committed_manifest
                .windows(b"[workspace]".len())
                .any(|window| window == b"[workspace]")
        );
        let committed_forge_config = git
            .read_commit_file_bounded(
                &root,
                &head,
                &RepoRelativePath::new("forge.toml")?,
                1024 * 1024,
            )?
            .ok_or("dogfood forge.toml was absent from the committed tree")?;
        assert!(
            committed_forge_config
                .windows(b"schema = 1".len())
                .any(|window| window == b"schema = 1")
        );
        assert!(
            committed_forge_config
                .windows(b"exclude = [\"fixtures/**\"]".len())
                .any(|window| window == b"exclude = [\"fixtures/**\"]")
        );
        assert_eq!(
            git.read_commit_file_bounded(&root, &head, &RepoRelativePath::new("Cargo.toml")?, 1,)
                .err()
                .map(|error| error.kind()),
            Some(GitErrorKind::OutputLimit)
        );
        Ok(())
    }

    #[test]
    fn preset_cancellation_interrupts_in_memory_and_spooled_git_before_spawn()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let missing_root = root.path().join("must-not-be-inspected");
        let cancellation = Arc::new(AtomicBool::new(true));
        let git = GitCli::new().with_cancellation_flag(cancellation);

        let in_memory_error = git
            .repository_root(&missing_root)
            .err()
            .ok_or("pre-cancelled repository-root unexpectedly completed")?;
        let spooled_error = git
            .file_set(&missing_root)
            .err()
            .ok_or("pre-cancelled file-set unexpectedly completed")?;

        assert_eq!(in_memory_error.kind(), GitErrorKind::Interrupted);
        assert_eq!(spooled_error.kind(), GitErrorKind::Interrupted);
        Ok(())
    }

    #[test]
    fn cloned_git_clients_share_only_their_explicit_cancellation_flag()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let cancellation = Arc::new(AtomicBool::new(false));
        let git = GitCli::new().with_cancellation_flag(Arc::clone(&cancellation));
        let cloned = git.clone();
        let independent = GitCli::new();

        assert!(Arc::ptr_eq(&git.cancellation, &cancellation));
        assert!(Arc::ptr_eq(&git.cancellation, &cloned.cancellation));
        assert!(!Arc::ptr_eq(&git.cancellation, &independent.cancellation));
        assert!(!independent.cancellation.load(Ordering::Acquire));

        cancellation.store(true, Ordering::Release);
        let error = cloned
            .repository_root(root.path())
            .err()
            .ok_or("clone did not observe the shared cancellation flag")?;
        assert_eq!(error.kind(), GitErrorKind::Interrupted);
        Ok(())
    }

    #[test]
    fn status_bound_never_returns_a_partial_typed_result() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let error = GitCli::new()
            .with_status_output_limit_bytes(1)
            .status(&root)
            .err()
            .ok_or("one-byte status bound unexpectedly produced a typed result")?;

        assert_eq!(error.kind(), GitErrorKind::OutputLimit);
        assert!(error.to_string().contains("stdout total"));
        Ok(())
    }

    /// Opaque placeholder: these Git classification tests do not consume process-output digests.
    fn ignored_process_digest(stream: &str) -> Digest {
        Digest::new(format!("fixture:non-canonical-git-{stream}"))
    }

    fn successful_observation() -> ProcessObservation {
        ProcessObservation {
            exit_code: Some(0),
            signal: None,
            stdout: b"output".to_vec(),
            stderr: Vec::new(),
            stdout_digest: ignored_process_digest("stdout"),
            stderr_digest: ignored_process_digest("stderr"),
            stdout_total_bytes: 6,
            stderr_total_bytes: 0,
            stdout_truncated: false,
            stderr_truncated: false,
            duration: Duration::from_millis(1),
            timed_out: false,
            interrupted: false,
        }
    }

    #[test]
    fn git_observation_failures_are_closed_with_totals() {
        let mut timed_out = successful_observation();
        timed_out.timed_out = true;
        assert_eq!(
            checked_stdout(GitOperation::Status, timed_out)
                .err()
                .map(|error| error.kind()),
            Some(GitErrorKind::TimedOut)
        );

        let mut interrupted = successful_observation();
        interrupted.interrupted = true;
        assert_eq!(
            checked_stdout(GitOperation::Status, interrupted)
                .err()
                .map(|error| error.kind()),
            Some(GitErrorKind::Interrupted)
        );

        let mut truncated = successful_observation();
        truncated.stdout_truncated = true;
        truncated.stdout_total_bytes = 123_456;
        let error = checked_stdout(GitOperation::Status, truncated).err();
        assert_eq!(
            error.as_ref().map(|error| error.kind()),
            Some(GitErrorKind::OutputLimit)
        );
        assert!(
            error
                .as_ref()
                .is_some_and(|error| error.to_string().contains("123456 bytes"))
        );

        let mut failed = successful_observation();
        failed.exit_code = Some(1);
        assert_eq!(
            checked_stdout(GitOperation::Status, failed)
                .err()
                .map(|error| error.kind()),
            Some(GitErrorKind::CommandFailed)
        );
    }

    #[test]
    fn command_failure_categories_do_not_require_callers_to_parse_diagnostics() {
        assert_eq!(
            classify_command_failure(b"fatal: not a git repository (or any parent)"),
            GitErrorKind::NotRepository
        );
        assert_eq!(
            classify_command_failure(b"fatal: index file corrupt"),
            GitErrorKind::CorruptRepository
        );
        assert_eq!(
            classify_command_failure(b"fatal: unrelated failure"),
            GitErrorKind::CommandFailed
        );
    }

    #[test]
    fn parses_only_supported_object_format_values() {
        assert_eq!(
            parse_object_format(b"sha1\n".to_vec()).ok(),
            Some(GitObjectFormat::Sha1)
        );
        assert_eq!(
            parse_object_format(b"sha256\n".to_vec()).ok(),
            Some(GitObjectFormat::Sha256)
        );
        assert!(parse_object_format(b"sha1 sha256\n".to_vec()).is_err());
    }

    #[test]
    fn exact_tree_blob_parser_rejects_ambiguous_or_non_regular_results()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = RepoRelativePath::new("forge.toml")?;
        let oid = b"0123456789012345678901234567890123456789";
        let mut regular = b"100644 blob ".to_vec();
        regular.extend_from_slice(oid);
        regular.extend_from_slice(b"\tforge.toml\0");
        assert_eq!(
            parse_exact_tree_blob(&regular, &path, 40)?,
            Some(OsString::from(std::str::from_utf8(oid)?))
        );
        assert!(parse_exact_tree_blob(b"", &path, 40)?.is_none());

        let mut symlink = b"120000 blob ".to_vec();
        symlink.extend_from_slice(oid);
        symlink.extend_from_slice(b"\tforge.toml\0");
        assert_eq!(
            parse_exact_tree_blob(&symlink, &path, 40)
                .err()
                .map(|error| error.kind()),
            Some(GitErrorKind::InvalidData)
        );

        let mut multiple = regular.clone();
        multiple.extend_from_slice(&regular);
        assert!(parse_exact_tree_blob(&multiple, &path, 40).is_err());
        assert!(parse_exact_tree_blob(&regular, &RepoRelativePath::new("other")?, 40).is_err());
        assert_eq!(parse_blob_size(b"42\n".to_vec())?, 42);
        assert!(parse_blob_size(b"-1\n".to_vec()).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rev_parse_removes_exactly_one_lf_and_preserves_native_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::ffi::OsStrExt as _;

        let path = parse_absolute_git_path(b"/tmp/non-utf8-\xff-and-newline\n\n".to_vec(), "test")?;
        assert_eq!(
            path.as_os_str().as_bytes(),
            b"/tmp/non-utf8-\xff-and-newline\n"
        );
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn rev_parse_accepts_one_lf_or_crlf() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            parse_absolute_git_path(b"C:\\repo\r\n".to_vec(), "test")?,
            Path::new("C:\\repo")
        );
        assert_eq!(
            parse_absolute_git_path(b"C:\\repo\n".to_vec(), "test")?,
            Path::new("C:\\repo")
        );
        Ok(())
    }
}
