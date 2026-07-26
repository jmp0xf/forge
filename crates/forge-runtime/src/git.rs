//! Hardened Git CLI implementation of the typed core port.

use std::ffi::OsString;
use std::io::{self, BufReader, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use forge_core::domain::{
    CommandSource, CommandSpec, Confidence, Intent, Mutability, NetworkIntent,
};
use forge_core::ports::{GitPort, ProcessObservation, ProcessPort as _};
use forge_core::{
    GitObjectFormat, PorcelainV2ReadError, PorcelainV2Status, RepoRelativePath,
    parse_status_porcelain_v2_reader,
};

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
#[derive(Debug, Clone, Copy)]
pub struct GitCli {
    timeout: Duration,
    status_spool_limit_bytes: usize,
    status_record_limit_bytes: usize,
    status_entry_limit: usize,
}

impl Default for GitCli {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_GIT_TIMEOUT,
            status_spool_limit_bytes: DEFAULT_GIT_STATUS_SPOOL_LIMIT_BYTES,
            status_record_limit_bytes: DEFAULT_GIT_STATUS_RECORD_LIMIT_BYTES,
            status_entry_limit: DEFAULT_GIT_STATUS_ENTRY_LIMIT,
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

/// Resolve the repository root as an absolute native path.
pub const REPOSITORY_ROOT_ARGS: &[&str] = &["rev-parse", "--show-toplevel"];

/// Resolve the worktree-specific Git directory as an absolute native path.
pub const GIT_DIR_ARGS: &[&str] = &["rev-parse", "--path-format=absolute", "--git-dir"];

/// Resolve the shared Git directory as an absolute native path.
pub const GIT_COMMON_DIR_ARGS: &[&str] =
    &["rev-parse", "--path-format=absolute", "--git-common-dir"];

/// Resolve the object format used by Git command output.
pub const OBJECT_FORMAT_ARGS: &[&str] = &["rev-parse", "--show-object-format=output"];

/// Global Git arguments used before every non-interactive Forge operation.
pub const HARDENED_GIT_GLOBAL_ARGS: &[&str] = &[
    "--no-pager",
    "--no-optional-locks",
    "-c",
    "core.fsmonitor=false",
];

/// Environment overrides required for non-interactive Git operations.
pub const HARDENED_GIT_ENV: &[(&str, &str)] =
    &[("GIT_TERMINAL_PROMPT", "0"), ("GIT_OPTIONAL_LOCKS", "0")];

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

    fn command_spec(&self, operation: GitOperation) -> CommandSpec {
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
        .with_args(
            HARDENED_GIT_GLOBAL_ARGS
                .iter()
                .chain(operation.args())
                .copied(),
        );
        spec.timeout = self.timeout;
        spec.mutability = Mutability::ReadOnly;
        // These commands are local-only, but NetworkIntent has no `None` variant. Do not claim
        // ecosystem offline flags were requested when Git has no such flag for these operations.
        spec.network = NetworkIntent::Unknown;
        spec.confidence = Confidence::High;
        for (key, value) in HARDENED_GIT_ENV {
            spec.env.insert(OsString::from(key), OsString::from(value));
        }
        spec
    }

    fn run(&self, start: &Path, operation: GitOperation) -> io::Result<Vec<u8>> {
        if matches!(operation, GitOperation::Status) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Git status must use the bounded anonymous spool path",
            ));
        }
        let runner = SynchronousProcessRunner::new(start)?;
        let observation = runner.run(&self.command_spec(operation)).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("failed to execute git {}: {error}", operation.name()),
            )
        })?;
        checked_stdout(operation.name(), observation)
    }

    fn run_spooled_status(&self, root: &Path) -> io::Result<SpooledProcessObservation> {
        let operation = GitOperation::Status;
        SynchronousProcessRunner::new(root)?
            .run_spooled_stdout(&self.command_spec(operation), self.status_spool_limit_bytes)
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("failed to execute git {}: {error}", operation.name()),
                )
            })
    }

    fn resolve_path(&self, start: &Path, operation: GitOperation) -> io::Result<PathBuf> {
        let bytes = self.run(start, operation)?;
        parse_absolute_git_path(bytes, operation.name())
    }

    fn object_format(&self, root: &Path) -> io::Result<GitObjectFormat> {
        parse_object_format(self.run(root, GitOperation::ObjectFormat)?)
    }
}

impl GitPort for GitCli {
    fn repository_root(&self, start: &Path) -> io::Result<PathBuf> {
        self.resolve_path(start, GitOperation::RepositoryRoot)
    }

    fn git_dir(&self, start: &Path) -> io::Result<PathBuf> {
        self.resolve_path(start, GitOperation::GitDir)
    }

    fn git_common_dir(&self, start: &Path) -> io::Result<PathBuf> {
        self.resolve_path(start, GitOperation::GitCommonDir)
    }

    fn status(&self, root: &Path) -> io::Result<PorcelainV2Status> {
        let object_format = self.object_format(root)?;
        let mut spooled = self.run_spooled_status(root)?;
        check_observation(GitOperation::Status.name(), &spooled.observation)?;
        spooled.stdout_file.flush()?;
        let spool_length = spooled.stdout_file.metadata()?.len();
        let spool_limit = u64::try_from(self.status_spool_limit_bytes).unwrap_or(u64::MAX);
        let expected_length = spooled.observation.stdout_total_bytes.min(spool_limit);
        if spool_length != expected_length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Git status spool length mismatch: retained {spool_length} bytes, expected {expected_length} from {} total bytes",
                    spooled.observation.stdout_total_bytes
                ),
            ));
        }
        spooled.stdout_file.seek(SeekFrom::Start(0))?;
        let status = parse_status_porcelain_v2_reader(
            BufReader::new(spooled.stdout_file),
            object_format,
            self.status_record_limit_bytes,
            self.status_entry_limit,
        )
        .map_err(map_status_read_error)?;
        if status.branch.oid.is_none() || status.branch.head.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Git porcelain v2 status omitted required branch.oid or branch.head headers",
            ));
        }
        Ok(status)
    }
}

#[derive(Debug, Clone, Copy)]
enum GitOperation {
    RepositoryRoot,
    GitDir,
    GitCommonDir,
    ObjectFormat,
    Status,
}

impl GitOperation {
    fn name(self) -> &'static str {
        match self {
            Self::RepositoryRoot => "repository-root",
            Self::GitDir => "git-dir",
            Self::GitCommonDir => "git-common-dir",
            Self::ObjectFormat => "object-format",
            Self::Status => "status",
        }
    }

    fn command_id(self) -> &'static str {
        match self {
            Self::RepositoryRoot => "runtime.git.repository-root",
            Self::GitDir => "runtime.git.git-dir",
            Self::GitCommonDir => "runtime.git.git-common-dir",
            Self::ObjectFormat => "runtime.git.object-format",
            Self::Status => "runtime.git.status",
        }
    }

    fn args(self) -> &'static [&'static str] {
        match self {
            Self::RepositoryRoot => REPOSITORY_ROOT_ARGS,
            Self::GitDir => GIT_DIR_ARGS,
            Self::GitCommonDir => GIT_COMMON_DIR_ARGS,
            Self::ObjectFormat => OBJECT_FORMAT_ARGS,
            Self::Status => STATUS_PORCELAIN_V2_ARGS,
        }
    }
}

fn checked_stdout(operation: &str, observation: ProcessObservation) -> io::Result<Vec<u8>> {
    check_observation(operation, &observation)?;
    Ok(observation.stdout)
}

fn check_observation(operation: &str, observation: &ProcessObservation) -> io::Result<()> {
    if observation.timed_out {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("git {operation} exceeded its timeout"),
        ));
    }
    if observation.interrupted {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            format!("git {operation} was interrupted"),
        ));
    }
    if observation.stdout_truncated || observation.stderr_truncated {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "git {operation} output exceeded the configured bound (stdout total {} bytes, stderr total {} bytes)",
                observation.stdout_total_bytes, observation.stderr_total_bytes,
            ),
        ));
    }
    if observation.exit_code != Some(0) {
        let stderr = bounded_stderr_context(&observation.stderr);
        return Err(io::Error::other(format!(
            "git {operation} failed (exit code {:?}, signal {:?}){stderr}",
            observation.exit_code, observation.signal,
        )));
    }
    Ok(())
}

fn map_status_read_error(error: PorcelainV2ReadError) -> io::Error {
    match error {
        PorcelainV2ReadError::Input {
            offset,
            record,
            source,
        } => io::Error::new(
            source.kind(),
            format!(
                "failed to read Git porcelain v2 status at byte {offset}, record {record}: {source}"
            ),
        ),
        PorcelainV2ReadError::Parse(error) => io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Git returned malformed porcelain v2 status: {error}"),
        ),
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
    use std::io;
    use std::path::Path;
    use std::time::Duration;

    use forge_core::GitObjectFormat;
    use forge_core::ports::{GitPort as _, ProcessObservation};

    use super::{
        GitCli, HARDENED_GIT_ENV, HARDENED_GIT_GLOBAL_ARGS, OBJECT_FORMAT_ARGS,
        STATUS_PORCELAIN_V2_ARGS, checked_stdout, parse_absolute_git_path, parse_object_format,
    };

    #[test]
    fn hardened_status_is_argv_only_and_non_interactive() {
        assert!(HARDENED_GIT_GLOBAL_ARGS.contains(&"--no-pager"));
        assert!(HARDENED_GIT_GLOBAL_ARGS.contains(&"--no-optional-locks"));
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
        assert!(HARDENED_GIT_ENV.contains(&("GIT_TERMINAL_PROMPT", "0")));
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

        assert_eq!(root, expected_root);
        assert!(git_dir.is_absolute());
        assert!(git_dir.is_dir());
        assert!(git_common_dir.is_absolute());
        assert!(git_common_dir.is_dir());
        assert!(status.branch.oid.is_some());
        assert!(status.branch.head.is_some());
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

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("stdout total"));
        Ok(())
    }

    fn successful_observation() -> ProcessObservation {
        ProcessObservation {
            exit_code: Some(0),
            signal: None,
            stdout: b"output".to_vec(),
            stderr: Vec::new(),
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
            checked_stdout("test", timed_out)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::TimedOut)
        );

        let mut interrupted = successful_observation();
        interrupted.interrupted = true;
        assert_eq!(
            checked_stdout("test", interrupted)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::Interrupted)
        );

        let mut truncated = successful_observation();
        truncated.stdout_truncated = true;
        truncated.stdout_total_bytes = 123_456;
        let error = checked_stdout("test", truncated).err();
        assert_eq!(
            error.as_ref().map(io::Error::kind),
            Some(io::ErrorKind::InvalidData)
        );
        assert!(
            error
                .as_ref()
                .is_some_and(|error| error.to_string().contains("123456 bytes"))
        );

        let mut failed = successful_observation();
        failed.exit_code = Some(1);
        assert_eq!(
            checked_stdout("test", failed)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::Other)
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
