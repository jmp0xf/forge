//! Synchronous, argv-only subprocess execution.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use forge_core::Digest;
use forge_core::evidence::DependencyValue;
use forge_core::fingerprint::environment_dependency_digest;
use forge_core::ports::{
    DEFAULT_CAPTURE_LIMIT_BYTES, EnvPolicy, ExecSpec, Hasher, ProcessError, ProcessErrorKind,
    ProcessObservation, ProcessPort, StdinPolicy,
};

/// Default maximum number of bytes retained in memory for each output stream.
pub const DEFAULT_OUTPUT_LIMIT_BYTES: usize = DEFAULT_CAPTURE_LIMIT_BYTES;

/// Default maximum number of stdout bytes retained in an anonymous temporary file.
///
/// The spool keeps large machine-readable output off the heap, but remains explicitly bounded so
/// an unexpectedly large child cannot consume unbounded local disk space.
pub const DEFAULT_SPOOLED_STDOUT_LIMIT_BYTES: usize = 256 * 1024 * 1024;

/// Process-tree isolation backend compiled for the current target.
///
/// This is a build-time capability fact, not evidence that any particular command completed or
/// that an external CI host preserves the same runtime boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessTreeCapability {
    /// A dedicated Unix process group plus a non-reaping exit observer are available.
    UnixProcessGroup,
    /// A Windows Job Object is assigned before user code is resumed.
    WindowsJobObject,
    /// The current target has no complete process-tree isolation backend.
    Unsupported,
}

/// Conservative result of resolving one command executable without running repository code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutableAvailability {
    /// The current platform lookup rules found an executable regular file.
    Available,
    /// Every safely inspected lookup candidate was absent or non-executable.
    Unavailable,
    /// The lookup could not be reproduced safely or completely on this platform.
    Unknown,
}

/// Returns the process-tree isolation backend compiled for the current target.
#[must_use]
pub const fn process_tree_capability() -> ProcessTreeCapability {
    #[cfg(windows)]
    {
        ProcessTreeCapability::WindowsJobObject
    }
    #[cfg(all(
        unix,
        any(
            target_os = "android",
            all(target_os = "linux", not(target_env = "uclibc")),
            target_vendor = "apple",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly"
        )
    ))]
    {
        ProcessTreeCapability::UnixProcessGroup
    }
    #[cfg(not(any(
        windows,
        all(
            unix,
            any(
                target_os = "android",
                all(target_os = "linux", not(target_env = "uclibc")),
                target_vendor = "apple",
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd",
                target_os = "dragonfly"
            )
        )
    )))]
    {
        ProcessTreeCapability::Unsupported
    }
}

/// Fingerprints the exact sanitized environment that the runner would supply to `spec`.
///
/// Raw values never leave this boundary. Privacy-unsafe names and invalid process environment
/// entries become a typed process error, so callers can record an unknown dependency while still
/// deciding separately whether executing the observation is allowed.
pub fn process_environment_dependency_digest<H: Hasher + ?Sized>(
    spec: &ExecSpec,
    hasher: &H,
) -> Result<DependencyValue<Digest>, ProcessError> {
    let environment = sanitized_environment(std::env::vars_os(), &spec.env).map_err(|error| {
        ProcessError::new(
            ProcessErrorKind::InvalidEnvironment,
            "build command environment fingerprint",
            error,
        )
    })?;
    environment_dependency_digest(hasher, &environment).map_err(|error| {
        ProcessError::new(
            ProcessErrorKind::InvalidEnvironment,
            "fingerprint command environment",
            io::Error::new(io::ErrorKind::InvalidInput, error),
        )
    })
}

const TERMINATION_GRACE: Duration = Duration::from_millis(250);
const WAIT_POLL_INTERVAL: Duration = Duration::from_millis(25);
const RESTRICTED_ENVIRONMENT: &[&str] = &[
    "PAGER",
    "GIT_PAGER",
    "MANPAGER",
    "SYSTEMD_PAGER",
    "LESS",
    "LV",
    "GIT_TERMINAL_PROMPT",
    "GIT_ASKPASS",
    "SSH_ASKPASS",
    "SSH_ASKPASS_REQUIRE",
    "SUDO_ASKPASS",
    "GCM_INTERACTIVE",
    "GIT_OPTIONAL_LOCKS",
    "GIT_TRACE",
    "GIT_TRACE2",
    "RUST_LOG",
    "RUST_BACKTRACE",
    "RUST_LIB_BACKTRACE",
    "RUSTC_LOG",
    "CARGO_LOG",
];
/// An argv-only runner bound to one canonical repository root.
#[derive(Debug, Clone)]
pub struct SynchronousProcessRunner {
    repository_root: PathBuf,
    termination_grace: Duration,
    cancellation: Arc<AtomicBool>,
}

impl SynchronousProcessRunner {
    /// Binds a runner to `repository_root` after resolving symlinks.
    pub fn new(repository_root: impl AsRef<Path>) -> Result<Self, ProcessError> {
        let repository_root = repository_root.as_ref().canonicalize().map_err(|error| {
            ProcessError::new(
                ProcessErrorKind::InvalidRepositoryRoot,
                "resolve process runner repository root",
                error,
            )
        })?;
        if !repository_root.is_dir() {
            return Err(ProcessError::new(
                ProcessErrorKind::InvalidRepositoryRoot,
                "validate process runner repository root",
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "process runner repository root is not a directory",
                ),
            ));
        }

        Ok(Self {
            repository_root,
            termination_grace: TERMINATION_GRACE,
            cancellation: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Replaces the default cancellation flag with one shared by the caller.
    ///
    /// Setting the flag to `true` interrupts every in-flight run that shares it. Callers own
    /// resetting a sticky flag before starting later commands.
    #[must_use]
    pub fn with_cancellation_flag(mut self, cancellation: Arc<AtomicBool>) -> Self {
        self.cancellation = cancellation;
        self
    }

    /// Returns the canonical root to which command working directories are bound.
    #[must_use]
    pub fn repository_root(&self) -> &Path {
        &self.repository_root
    }

    /// Resolves the executable selected by `spec` without starting it.
    ///
    /// Unix PATH lookup is reproduced conservatively. Other targets return `Unknown` until their
    /// native search order can be matched without executing untrusted project code.
    pub fn executable_availability(
        &self,
        spec: &ExecSpec,
    ) -> Result<ExecutableAvailability, ProcessError> {
        let cwd = self.resolve_cwd(spec.cwd.as_path())?;
        let environment =
            sanitized_environment(std::env::vars_os(), &spec.env).map_err(|error| {
                ProcessError::new(
                    ProcessErrorKind::InvalidEnvironment,
                    "build executable lookup environment",
                    error,
                )
            })?;
        reject_implicit_shell_program(&spec.program).map_err(|error| {
            ProcessError::new(
                ProcessErrorKind::UnsupportedProgram,
                "validate executable lookup program",
                error,
            )
        })?;
        Ok(platform_executable_availability(
            &spec.program,
            &cwd,
            &environment,
        ))
    }

    /// Runs one command with stdout retained in a private anonymous temporary file.
    ///
    /// This runtime-only path shares the same process-tree, timeout, cancellation, environment,
    /// and pipe-draining lifecycle as [`ProcessPort::run`]. Stderr remains an in-memory diagnostic
    /// capped at [`DEFAULT_OUTPUT_LIMIT_BYTES`]. The temporary file has no caller-visible path and
    /// is removed by the operating system after its last handle closes.
    pub(crate) fn run_spooled_stdout(
        &self,
        spec: &ExecSpec,
    ) -> Result<SpooledProcessObservation, ProcessError> {
        let spool = private_anonymous_tempfile().map_err(|error| {
            ProcessError::new(
                ProcessErrorKind::Output,
                "create private stdout spool",
                error,
            )
        })?;
        let execution = self.execute(
            spec,
            spool,
            spec.stdout.retention_limit(),
            spec.stderr.retention_limit(),
        )?;
        let (observation, stdout_file) = execution.into_spooled_observation();
        Ok(SpooledProcessObservation {
            observation,
            stdout_file,
        })
    }

    fn resolve_cwd(&self, relative: &Path) -> Result<PathBuf, ProcessError> {
        let resolved = self
            .repository_root
            .join(relative)
            .canonicalize()
            .map_err(|error| {
                ProcessError::new(
                    ProcessErrorKind::InvalidWorkingDirectory,
                    "resolve command working directory",
                    error,
                )
            })?;
        if !resolved.starts_with(&self.repository_root) {
            return Err(ProcessError::new(
                ProcessErrorKind::InvalidWorkingDirectory,
                "confine command working directory",
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "command working directory resolves outside the repository",
                ),
            ));
        }
        if !resolved.is_dir() {
            return Err(ProcessError::new(
                ProcessErrorKind::InvalidWorkingDirectory,
                "validate command working directory",
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "command working directory is not a directory",
                ),
            ));
        }
        Ok(resolved)
    }

    fn execute<W>(
        &self,
        spec: &ExecSpec,
        stdout_sink: W,
        stdout_limit_bytes: usize,
        stderr_limit_bytes: usize,
    ) -> Result<ExecutionObservation<W>, ProcessError>
    where
        W: Write + Send + 'static,
    {
        let cwd = self.resolve_cwd(spec.cwd.as_path())?;
        let environment =
            sanitized_environment(std::env::vars_os(), &spec.env).map_err(|error| {
                ProcessError::new(
                    ProcessErrorKind::InvalidEnvironment,
                    "build command environment",
                    error,
                )
            })?;
        reject_implicit_shell_program(&spec.program).map_err(|error| {
            ProcessError::new(
                ProcessErrorKind::UnsupportedProgram,
                "validate command program",
                error,
            )
        })?;
        if self.cancellation.load(Ordering::Acquire) {
            return Ok(ExecutionObservation::interrupted_before_spawn(stdout_sink));
        }

        let mut command = Command::new(&spec.program);
        command
            .args(&spec.args)
            .current_dir(cwd)
            .env_clear()
            .envs(environment)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        match spec.stdin {
            StdinPolicy::Closed => {
                command.stdin(Stdio::null());
            }
            StdinPolicy::Inherit => {
                command.stdin(Stdio::inherit());
            }
        }

        let prepared_tree = platform::PreparedTree::prepare(&mut command).map_err(|error| {
            ProcessError::new(
                ProcessErrorKind::ProcessTree,
                "prepare child process tree",
                error,
            )
        })?;
        let started_at = Instant::now();
        let mut child = command.spawn().map_err(map_spawn_error)?;
        let mut tree = match prepared_tree.attach(&child) {
            Ok(tree) => tree,
            Err(error) => {
                reap_direct_child(&mut child);
                return Err(ProcessError::new(
                    ProcessErrorKind::ProcessTree,
                    "attach child process tree",
                    error,
                ));
            }
        };

        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                abort_child(&mut child, &tree);
                return Err(ProcessError::new(
                    ProcessErrorKind::Output,
                    "open child stdout pipe",
                    io::Error::other("child stdout pipe was not created"),
                ));
            }
        };
        let stderr = match child.stderr.take() {
            Some(stderr) => stderr,
            None => {
                abort_child(&mut child, &tree);
                return Err(ProcessError::new(
                    ProcessErrorKind::Output,
                    "open child stderr pipe",
                    io::Error::other("child stderr pipe was not created"),
                ));
            }
        };

        let stdout_reader = match spawn_reader(
            "forge-stdout-drain",
            OutputStream::Stdout,
            stdout,
            stdout_sink,
            stdout_limit_bytes,
        ) {
            Ok(reader) => reader,
            Err(error) => {
                abort_child(&mut child, &tree);
                return Err(ProcessError::new(
                    ProcessErrorKind::Output,
                    "start child stdout drain",
                    error,
                ));
            }
        };
        let stderr_reader = match spawn_reader(
            "forge-stderr-drain",
            OutputStream::Stderr,
            stderr,
            Vec::with_capacity(stderr_limit_bytes.min(8 * 1024)),
            stderr_limit_bytes,
        ) {
            Ok(reader) => reader,
            Err(error) => {
                abort_child(&mut child, &tree);
                let _ = join_reader(stdout_reader);
                return Err(ProcessError::new(
                    ProcessErrorKind::Output,
                    "start child stderr drain",
                    error,
                ));
            }
        };

        let wait_result = wait_for_child(
            &mut child,
            &mut tree,
            spec.timeout,
            self.termination_grace,
            &self.cancellation,
        );
        let stdout_result = join_reader(stdout_reader);
        let stderr_result = join_reader(stderr_reader);
        let (status, timed_out, interrupted) = wait_result.map_err(|error| {
            ProcessError::new(ProcessErrorKind::Wait, "wait for child process tree", error)
        })?;
        let mut stdout = stdout_result.map_err(|error| {
            ProcessError::new(ProcessErrorKind::Output, "drain child stdout", error)
        })?;
        let mut stderr = stderr_result.map_err(|error| {
            ProcessError::new(ProcessErrorKind::Output, "drain child stderr", error)
        })?;
        reject_sink_error("stdout", &mut stdout).map_err(|error| {
            ProcessError::new(ProcessErrorKind::Output, "retain child stdout", error)
        })?;
        reject_sink_error("stderr", &mut stderr).map_err(|error| {
            ProcessError::new(ProcessErrorKind::Output, "retain child stderr", error)
        })?;

        Ok(ExecutionObservation {
            exit_code: status.code(),
            signal: platform::exit_signal(&status),
            stdout,
            stderr,
            duration: started_at.elapsed(),
            timed_out,
            interrupted,
        })
    }
}

fn private_anonymous_tempfile() -> io::Result<File> {
    let file = tempfile::tempfile()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

#[cfg(unix)]
fn platform_executable_availability(
    program: &OsStr,
    cwd: &Path,
    environment: &BTreeMap<OsString, OsString>,
) -> ExecutableAvailability {
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::PermissionsExt as _;

    fn candidate_availability(path: &Path) -> io::Result<bool> {
        match std::fs::metadata(path) {
            Ok(metadata) => Ok(metadata.is_file() && metadata.permissions().mode() & 0o111 != 0),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) =>
            {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    if program.as_bytes().contains(&b'/') {
        let path = Path::new(program);
        let candidate = if path.is_absolute() {
            path.to_path_buf()
        } else {
            cwd.join(path)
        };
        return match candidate_availability(&candidate) {
            Ok(true) => ExecutableAvailability::Available,
            Ok(false) => ExecutableAvailability::Unavailable,
            Err(_) => ExecutableAvailability::Unknown,
        };
    }

    let Some(path) = environment.get(OsStr::new("PATH")) else {
        return ExecutableAvailability::Unknown;
    };
    let mut incomplete = false;
    for directory in std::env::split_paths(path) {
        let directory = if directory.as_os_str().is_empty() {
            cwd.to_path_buf()
        } else {
            directory
        };
        match candidate_availability(&directory.join(program)) {
            Ok(true) => return ExecutableAvailability::Available,
            Ok(false) => {}
            Err(_) => incomplete = true,
        }
    }
    if incomplete {
        ExecutableAvailability::Unknown
    } else {
        ExecutableAvailability::Unavailable
    }
}

#[cfg(not(unix))]
fn platform_executable_availability(
    _program: &OsStr,
    _cwd: &Path,
    _environment: &BTreeMap<OsString, OsString>,
) -> ExecutableAvailability {
    ExecutableAvailability::Unknown
}

#[cfg(windows)]
fn reject_implicit_shell_program(program: &OsStr) -> io::Result<()> {
    if is_windows_batch_program(program) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Windows .bat/.cmd programs are unsupported because they require implicit cmd.exe shell execution: {program:?}"
            ),
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn reject_implicit_shell_program(_program: &OsStr) -> io::Result<()> {
    Ok(())
}

#[cfg(any(windows, test))]
fn is_windows_batch_program(program: &OsStr) -> bool {
    // Windows only adds `.exe` when an extension is omitted. A batch program found through PATH
    // must therefore still be named with `.bat` or `.cmd`, so this lexical gate also covers PATH
    // resolution without reproducing the operating system's executable-search algorithm.
    Path::new(program).extension().is_some_and(|extension| {
        let extension = extension.to_string_lossy();
        extension.eq_ignore_ascii_case("bat") || extension.eq_ignore_ascii_case("cmd")
    })
}

impl ProcessPort for SynchronousProcessRunner {
    fn run(&self, spec: &ExecSpec) -> Result<ProcessObservation, ProcessError> {
        self.execute(
            spec,
            Vec::with_capacity(spec.stdout.retention_limit().min(8 * 1024)),
            spec.stdout.retention_limit(),
            spec.stderr.retention_limit(),
        )
        .map(ExecutionObservation::into_process_observation)
    }
}

fn map_spawn_error(error: io::Error) -> ProcessError {
    let kind = match error.kind() {
        io::ErrorKind::NotFound => ProcessErrorKind::ExecutableUnavailable,
        io::ErrorKind::PermissionDenied => ProcessErrorKind::PermissionDenied,
        _ => ProcessErrorKind::Spawn,
    };
    ProcessError::new(kind, "spawn child process", error)
}

/// Process metadata plus stdout held outside the heap in an anonymous temporary file.
#[derive(Debug)]
pub(crate) struct SpooledProcessObservation {
    /// `stdout` is intentionally empty; its totals and truncation flag describe `stdout_file`.
    pub(crate) observation: ProcessObservation,
    pub(crate) stdout_file: File,
}

#[derive(Debug)]
struct ExecutionObservation<W> {
    exit_code: Option<i32>,
    signal: Option<i32>,
    stdout: DrainedOutput<W>,
    stderr: DrainedOutput<Vec<u8>>,
    duration: Duration,
    timed_out: bool,
    interrupted: bool,
}

impl<W> ExecutionObservation<W> {
    fn interrupted_before_spawn(stdout_sink: W) -> Self {
        Self {
            exit_code: None,
            signal: None,
            stdout: DrainedOutput::empty(OutputStream::Stdout, stdout_sink),
            stderr: DrainedOutput::empty(OutputStream::Stderr, Vec::new()),
            duration: Duration::ZERO,
            timed_out: false,
            interrupted: true,
        }
    }

    fn into_parts(self) -> (ProcessObservation, W) {
        let stdout_total_bytes = self.stdout.total_bytes;
        let stdout_truncated = self.stdout.truncated;
        let stdout_sink = self.stdout.sink;
        let observation = ProcessObservation {
            exit_code: self.exit_code,
            signal: self.signal,
            stdout: Vec::new(),
            stderr: self.stderr.sink,
            stdout_digest: self.stdout.digest,
            stderr_digest: self.stderr.digest,
            stdout_total_bytes,
            stderr_total_bytes: self.stderr.total_bytes,
            stdout_truncated,
            stderr_truncated: self.stderr.truncated,
            duration: self.duration,
            timed_out: self.timed_out,
            interrupted: self.interrupted,
        };
        (observation, stdout_sink)
    }

    fn into_spooled_observation(self) -> (ProcessObservation, W) {
        self.into_parts()
    }
}

impl ExecutionObservation<Vec<u8>> {
    fn into_process_observation(self) -> ProcessObservation {
        let (mut observation, stdout) = self.into_parts();
        observation.stdout = stdout;
        observation
    }
}

fn wait_for_child(
    child: &mut Child,
    tree: &mut platform::ChildTree,
    timeout: Duration,
    termination_grace: Duration,
    cancellation: &AtomicBool,
) -> io::Result<(ExitStatus, bool, bool)> {
    let wait_started = Instant::now();
    loop {
        let exited = match platform::wait_for_exit(tree, Duration::ZERO) {
            Ok(exited) => exited,
            Err(error) => {
                abort_child(child, tree);
                return Err(error);
            }
        };
        if exited {
            let status = kill_tree_and_reap(child, tree)?;
            return Ok((status, false, false));
        }

        if cancellation.load(Ordering::Acquire) {
            let status = terminate_and_reap(child, tree, termination_grace)?;
            return Ok((status, false, true));
        }

        let elapsed = wait_started.elapsed();
        if elapsed >= timeout {
            let status = terminate_and_reap(child, tree, termination_grace)?;
            return Ok((status, true, false));
        }

        let poll_duration = timeout.saturating_sub(elapsed).min(WAIT_POLL_INTERVAL);
        match platform::wait_for_exit(tree, poll_duration) {
            Ok(true) => {
                let status = kill_tree_and_reap(child, tree)?;
                return Ok((status, false, false));
            }
            Ok(false) => {}
            Err(error) => {
                abort_child(child, tree);
                return Err(error);
            }
        }
    }
}

fn terminate_and_reap(
    child: &mut Child,
    tree: &platform::ChildTree,
    termination_grace: Duration,
) -> io::Result<ExitStatus> {
    let termination = platform::terminate_tree(tree);

    if termination
        .as_ref()
        .is_ok_and(|mode| !mode.requires_grace())
    {
        // Windows Job Objects have no generic graceful signal. The platform has already atomically
        // requested forced tree termination, so sleeping and issuing the same kill twice only
        // delays timeout/cancellation reporting.
        return child.wait();
    }

    if termination.as_ref().is_ok_and(|mode| mode.requires_grace()) {
        // Do not call `wait`, `try_wait`, or `wait_timeout` during this grace period. On Unix those
        // calls reap an exited group leader. Keeping the leader as a zombie reserves its PID/PGID,
        // so the force-kill below cannot race with PGID reuse and signal an unrelated process
        // group.
        thread::sleep(termination_grace);
    }

    let kill_result = platform::kill_tree(tree);
    if kill_result.is_err() {
        // Killing by the still-owned child handle/PID is the safest fallback when group/job
        // termination fails. It cannot target a reused PID because the child remains unreaped.
        let _ = child.kill();
    }
    let status_result = child.wait();

    termination.map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("failed to request process-tree termination: {error}"),
        )
    })?;
    kill_result.map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("failed to force process-tree termination: {error}"),
        )
    })?;
    status_result
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminationMode {
    #[cfg(any(unix, test))]
    Graceful,
    #[cfg(any(windows, test))]
    Forced,
}

impl TerminationMode {
    fn requires_grace(self) -> bool {
        match self {
            #[cfg(any(unix, test))]
            Self::Graceful => true,
            #[cfg(any(windows, test))]
            Self::Forced => false,
        }
    }
}

fn kill_tree_and_reap(child: &mut Child, tree: &platform::ChildTree) -> io::Result<ExitStatus> {
    // The platform observer reports exit without reaping the direct child. On Unix, that zombie
    // pins the numeric PID/PGID while the remaining group is killed; on Windows, the Job Object
    // itself is a stable tree identity. Reap only after tree cleanup completes.
    let kill_result = platform::kill_tree(tree);
    if kill_result.is_err() {
        let _ = child.kill();
    }
    let status_result = child.wait();

    kill_result.map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("failed to clean up process tree after leader exit: {error}"),
        )
    })?;
    status_result
}

fn abort_child(child: &mut Child, tree: &platform::ChildTree) {
    let _ = platform::kill_tree(tree);
    let _ = child.kill();
    let _ = child.wait();
}

fn reap_direct_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[derive(Debug)]
struct DrainedOutput<W> {
    sink: W,
    digest: Digest,
    total_bytes: u64,
    truncated: bool,
    sink_error: Option<io::Error>,
}

impl<W> DrainedOutput<W> {
    fn empty(stream: OutputStream, sink: W) -> Self {
        Self {
            sink,
            digest: stream.empty_digest(),
            total_bytes: 0,
            truncated: false,
            sink_error: None,
        }
    }
}

/// Identifies one subprocess pipe in the process-output digest domain.
///
/// The `forge.process-output/v1\0` preimage is, in order: the domain/version bytes; the stream
/// label length as an eight-byte little-endian unsigned integer; the raw `stdout` or `stderr`
/// label; the `\0stream-bytes\0` separator; and every raw pipe byte in read order through EOF.
/// Read chunk boundaries and retained-output bounds are not encoded. This keeps the digest stable
/// across buffering policies while making identical stdout and stderr byte streams distinct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputStream {
    Stdout,
    Stderr,
}

impl OutputStream {
    const DOMAIN: &'static [u8] = b"forge.process-output/v1\0";

    const fn label(self) -> &'static [u8] {
        match self {
            Self::Stdout => b"stdout",
            Self::Stderr => b"stderr",
        }
    }

    fn hasher(self) -> blake3::Hasher {
        let label = self.label();
        let mut hasher = blake3::Hasher::new();
        hasher.update(Self::DOMAIN);
        hasher.update(&(label.len() as u64).to_le_bytes());
        hasher.update(label);
        hasher.update(b"\0stream-bytes\0");
        hasher
    }

    fn empty_digest(self) -> Digest {
        finish_output_digest(self.hasher())
    }
}

fn finish_output_digest(hasher: blake3::Hasher) -> Digest {
    Digest::new(format!("blake3:{}", hasher.finalize().to_hex()))
}

/// Returns normal empty-stream digests for a command that was deliberately not spawned.
///
/// These are complete observations of zero bytes, not infrastructure-unavailable sentinels.
#[must_use]
pub fn empty_process_output_digests() -> (Digest, Digest) {
    (
        OutputStream::Stdout.empty_digest(),
        OutputStream::Stderr.empty_digest(),
    )
}

fn spawn_reader<R, W>(
    name: &'static str,
    stream: OutputStream,
    reader: R,
    sink: W,
    limit: usize,
) -> io::Result<JoinHandle<io::Result<DrainedOutput<W>>>>
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    thread::Builder::new()
        .name(name.into())
        .spawn(move || drain_bounded(stream, reader, sink, limit))
}

fn join_reader<W>(
    reader: JoinHandle<io::Result<DrainedOutput<W>>>,
) -> io::Result<DrainedOutput<W>> {
    match reader.join() {
        Ok(result) => result,
        Err(_) => Err(io::Error::other("subprocess output drain thread failed")),
    }
}

fn drain_bounded<W>(
    stream: OutputStream,
    mut reader: impl Read,
    mut sink: W,
    limit: usize,
) -> io::Result<DrainedOutput<W>>
where
    W: Write,
{
    let mut total_bytes = 0_u64;
    let mut retained_bytes = 0_usize;
    let mut truncated = false;
    let mut sink_error = None;
    let mut buffer = [0_u8; 8 * 1024];
    let mut hasher = stream.hasher();

    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }

        hasher.update(&buffer[..read]);
        total_bytes = total_bytes.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        let remaining = limit.saturating_sub(retained_bytes);
        let retained = remaining.min(read);
        retained_bytes += retained;
        if retained > 0 && sink_error.is_none() {
            if let Err(error) = sink.write_all(&buffer[..retained]) {
                // Closing the pipe here could block the child or turn a recoverable local sink
                // error into SIGPIPE. Remember the first write failure, then continue
                // draining/discarding until the process lifecycle has completed.
                sink_error = Some(error);
                truncated = true;
            }
        }
        truncated |= retained < read;
    }

    Ok(DrainedOutput {
        sink,
        digest: finish_output_digest(hasher),
        total_bytes,
        truncated,
        sink_error,
    })
}

fn reject_sink_error<W>(stream: &str, output: &mut DrainedOutput<W>) -> io::Result<()> {
    let Some(error) = output.sink_error.take() else {
        return Ok(());
    };
    Err(io::Error::new(
        error.kind(),
        format!(
            "failed to retain {stream} after draining {} total bytes: {error}",
            output.total_bytes
        ),
    ))
}

fn sanitized_environment<I>(
    inherited: I,
    policy: &EnvPolicy,
) -> io::Result<BTreeMap<OsString, OsString>>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    let mut environment = BTreeMap::new();
    for (key, value) in inherited {
        if policy
            .inherit
            .iter()
            .any(|candidate| environment_policy_key_eq(&key, candidate))
        {
            validate_environment_entry(&key, &value)?;
            if is_restricted_environment_key(&key) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "command environment policy inherits a restricted pager, prompt, or trace setting",
                ));
            }
            environment.insert(key, value);
        }
    }

    for (key, value) in &policy.overrides {
        validate_environment_entry(key, value)?;
        if is_restricted_environment_key(key) && !is_safe_disabled_control(key, value) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "command environment contains a restricted pager, prompt, or trace setting",
            ));
        }
        environment.insert(key.clone(), value.clone());
    }
    Ok(environment)
}

#[cfg(windows)]
fn environment_policy_key_eq(key: &OsStr, candidate: &OsStr) -> bool {
    key.to_string_lossy()
        .eq_ignore_ascii_case(&candidate.to_string_lossy())
}

#[cfg(not(windows))]
fn environment_policy_key_eq(key: &OsStr, candidate: &OsStr) -> bool {
    key == candidate
}

fn is_restricted_environment_key(key: &OsStr) -> bool {
    RESTRICTED_ENVIRONMENT
        .iter()
        .any(|candidate| environment_key_eq(key, candidate))
        || environment_key_starts_with(key, "GIT_TRACE_")
        || environment_key_starts_with(key, "GIT_TRACE2_")
}

fn is_safe_disabled_control(key: &OsStr, value: &OsStr) -> bool {
    (environment_key_eq(key, "GIT_TERMINAL_PROMPT") && value == OsStr::new("0"))
        || (environment_key_eq(key, "GIT_OPTIONAL_LOCKS") && value == OsStr::new("0"))
        || (environment_key_eq(key, "GCM_INTERACTIVE") && value == OsStr::new("Never"))
}

#[cfg(windows)]
fn environment_key_eq(key: &OsStr, candidate: &str) -> bool {
    key.to_string_lossy().eq_ignore_ascii_case(candidate)
}

#[cfg(not(windows))]
fn environment_key_eq(key: &OsStr, candidate: &str) -> bool {
    key == OsStr::new(candidate)
}

#[cfg(windows)]
fn environment_key_starts_with(key: &OsStr, prefix: &str) -> bool {
    key.to_string_lossy()
        .get(..prefix.len())
        .is_some_and(|start| start.eq_ignore_ascii_case(prefix))
}

#[cfg(not(windows))]
fn environment_key_starts_with(key: &OsStr, prefix: &str) -> bool {
    key.to_str().is_some_and(|key| key.starts_with(prefix))
}

#[cfg(unix)]
fn validate_environment_entry(key: &OsStr, value: &OsStr) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt as _;

    if key.as_bytes().is_empty()
        || key.as_bytes().contains(&b'=')
        || key.as_bytes().contains(&0)
        || value.as_bytes().contains(&0)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "command environment contains an invalid name or value",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn validate_environment_entry(key: &OsStr, value: &OsStr) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt as _;

    let invalid_key = key.encode_wide().next().is_none()
        || key
            .encode_wide()
            .any(|unit| unit == u16::from(b'=') || unit == 0);
    if invalid_key || value.encode_wide().any(|unit| unit == 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "command environment contains an invalid name or value",
        ));
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn validate_environment_entry(key: &OsStr, value: &OsStr) -> io::Result<()> {
    if key.is_empty()
        || key.to_string_lossy().contains(['=', '\0'])
        || value.to_string_lossy().contains('\0')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "command environment contains an invalid name or value",
        ));
    }
    Ok(())
}

#[cfg(unix)]
mod platform {
    use std::io;
    use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
    use std::process::{Child, Command, ExitStatus};
    use std::time::Duration;

    use nix::errno::Errno;
    use nix::sys::signal::{Signal, killpg};
    use nix::unistd::Pid;

    #[derive(Debug)]
    pub(super) struct PreparedTree;

    #[derive(Debug)]
    pub(super) struct ChildTree {
        process_group: Pid,
        exit_observer: ExitObserver,
    }

    impl PreparedTree {
        pub(super) fn prepare(command: &mut Command) -> io::Result<Self> {
            command.process_group(0);
            Ok(Self)
        }

        pub(super) fn attach(self, child: &Child) -> io::Result<ChildTree> {
            let pid = i32::try_from(child.id()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "child process id is out of range",
                )
            })?;
            let process_group = Pid::from_raw(pid);
            let exit_observer = match ExitObserver::new(process_group) {
                Ok(observer) => observer,
                Err(error) => {
                    // The child has already been spawned, so an observer setup failure must not
                    // leave it free to create orphaned descendants. The unreaped leader still
                    // pins this freshly created process-group identity during cleanup.
                    let cleanup_result = signal_process_group(process_group, Signal::SIGKILL);
                    return Err(match cleanup_result {
                        Ok(()) => error,
                        Err(cleanup_error) => io::Error::new(
                            cleanup_error.kind(),
                            format!(
                                "failed to establish exit observer ({error}) and clean up the process group: {cleanup_error}"
                            ),
                        ),
                    });
                }
            };
            Ok(ChildTree {
                process_group,
                exit_observer,
            })
        }
    }

    pub(super) fn wait_for_exit(tree: &mut ChildTree, timeout: Duration) -> io::Result<bool> {
        tree.exit_observer.wait_for_exit(timeout)
    }

    pub(super) fn terminate_tree(tree: &ChildTree) -> io::Result<super::TerminationMode> {
        signal_tree(tree, Signal::SIGTERM).map(|()| super::TerminationMode::Graceful)
    }

    pub(super) fn kill_tree(tree: &ChildTree) -> io::Result<()> {
        signal_tree(tree, Signal::SIGKILL)
    }

    #[cfg(target_vendor = "apple")]
    fn signal_tree(tree: &ChildTree, signal: Signal) -> io::Result<()> {
        signal_process_group(tree.process_group, signal)
    }

    #[cfg(target_vendor = "apple")]
    fn signal_process_group(process_group: Pid, signal: Signal) -> io::Result<()> {
        match killpg(process_group, signal) {
            Ok(()) | Err(Errno::ESRCH) => Ok(()),
            Err(Errno::EPERM) => {
                // XNU's killpg implementation filters zombies from the process-group walk and
                // returns EPERM when no live member remains. The unreaped leader still pins this
                // PGID, so a same-session SIGCONT probe cannot target a reused group. SIGCONT is
                // permitted across credential changes within a session: success proves a live
                // member remains and the original signal failure must be reported; EPERM/ESRCH
                // means the group contains only exited members and is already terminated.
                match killpg(process_group, Signal::SIGCONT) {
                    Ok(()) => Err(Errno::EPERM.into()),
                    Err(Errno::EPERM | Errno::ESRCH) => Ok(()),
                    Err(error) => {
                        let error = io::Error::from(error);
                        Err(io::Error::new(
                            error.kind(),
                            format!(
                                "failed to probe Darwin process-group liveness after {signal:?}: {error}"
                            ),
                        ))
                    }
                }
            }
            Err(error) => Err(error.into()),
        }
    }

    #[cfg(not(target_vendor = "apple"))]
    fn signal_tree(tree: &ChildTree, signal: Signal) -> io::Result<()> {
        signal_process_group(tree.process_group, signal)
    }

    #[cfg(not(target_vendor = "apple"))]
    fn signal_process_group(process_group: Pid, signal: Signal) -> io::Result<()> {
        match killpg(process_group, signal) {
            Ok(()) | Err(Errno::ESRCH) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    pub(super) fn exit_signal(status: &ExitStatus) -> Option<i32> {
        status.signal()
    }

    #[cfg(any(
        target_os = "android",
        all(target_os = "linux", not(target_env = "uclibc"))
    ))]
    #[derive(Debug)]
    struct ExitObserver(Pid);

    #[cfg(any(
        target_os = "android",
        all(target_os = "linux", not(target_env = "uclibc"))
    ))]
    impl ExitObserver {
        fn new(pid: Pid) -> io::Result<Self> {
            Ok(Self(pid))
        }

        fn wait_for_exit(&mut self, timeout: Duration) -> io::Result<bool> {
            use nix::sys::wait::{Id, WaitPidFlag, WaitStatus, waitid};

            let observe = || {
                let flags = WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT;
                match waitid(Id::Pid(self.0), flags)? {
                    WaitStatus::StillAlive => Ok(false),
                    WaitStatus::Exited(..) | WaitStatus::Signaled(..) => Ok(true),
                    status => Err(io::Error::other(format!(
                        "waitid returned an unexpected child status: {status:?}"
                    ))),
                }
            };

            if observe()? {
                return Ok(true);
            }
            if timeout.is_zero() {
                return Ok(false);
            }
            std::thread::sleep(timeout);
            observe()
        }
    }

    #[cfg(any(
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    #[derive(Debug)]
    struct ExitObserver {
        queue: nix::sys::event::Kqueue,
        exited: bool,
    }

    #[cfg(any(
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    impl ExitObserver {
        fn new(pid: Pid) -> io::Result<Self> {
            use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent, Kqueue};

            let queue = Kqueue::new()?;
            let change = KEvent::new(
                usize::try_from(pid.as_raw()).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "negative child process id")
                })?,
                EventFilter::EVFILT_PROC,
                EvFlags::EV_ADD | EvFlags::EV_ONESHOT,
                FilterFlag::NOTE_EXIT,
                0,
                0,
            );
            let mut events = [change];
            // XNU can report ESRCH either as the `kevent` error or through an EV_ERROR event when
            // this freshly spawned child reaches exit before registration. This runtime
            // exclusively owns the `Child` and does not reap via a SIGCHLD handler, so the child
            // remains a zombie that pins the same PID/PGID. Retaining the exited state lets the
            // caller kill that still-pinned process group before reaping instead of turning a
            // successful short command into a setup failure.
            let count = match queue.kevent(
                &[change],
                &mut events,
                Some(nix::libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                }),
            ) {
                Ok(count) => count,
                #[cfg(target_vendor = "apple")]
                Err(Errno::ESRCH) => {
                    return Ok(Self {
                        queue,
                        exited: true,
                    });
                }
                Err(error) => return Err(error.into()),
            };
            let exited = match first_event_reports_exit(&events, count) {
                Ok(exited) => exited,
                #[cfg(target_vendor = "apple")]
                Err(error) if error.raw_os_error() == Some(nix::libc::ESRCH) => true,
                Err(error) => return Err(error),
            };
            Ok(Self { queue, exited })
        }

        fn wait_for_exit(&mut self, timeout: Duration) -> io::Result<bool> {
            use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent};

            if self.exited {
                return Ok(true);
            }

            let mut events = [KEvent::new(
                0,
                EventFilter::EVFILT_PROC,
                EvFlags::empty(),
                FilterFlag::empty(),
                0,
                0,
            )];
            let count =
                self.queue
                    .kevent(&[], &mut events, Some(duration_to_timespec(timeout)?))?;
            self.exited = first_event_reports_exit(&events, count)?;
            Ok(self.exited)
        }
    }

    #[cfg(any(
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    fn first_event_reports_exit(
        events: &[nix::sys::event::KEvent; 1],
        count: usize,
    ) -> io::Result<bool> {
        use nix::sys::event::{EvFlags, FilterFlag};

        if count == 0 {
            return Ok(false);
        }
        let event = &events[0];
        if event.flags().contains(EvFlags::EV_ERROR) {
            let raw_error = i32::try_from(event.data()).map_err(|_| {
                io::Error::other("kqueue returned an out-of-range registration error")
            })?;
            if raw_error != 0 {
                return Err(io::Error::from_raw_os_error(raw_error));
            }
        }
        Ok(event.fflags().contains(FilterFlag::NOTE_EXIT))
    }

    #[cfg(any(
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    fn duration_to_timespec(duration: Duration) -> io::Result<nix::libc::timespec> {
        let tv_sec = duration.as_secs().try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "process wait duration is too large for kqueue",
            )
        })?;
        Ok(nix::libc::timespec {
            tv_sec,
            tv_nsec: duration.subsec_nanos().into(),
        })
    }

    #[cfg(not(any(
        target_os = "android",
        all(target_os = "linux", not(target_env = "uclibc")),
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )))]
    #[derive(Debug)]
    struct ExitObserver;

    #[cfg(not(any(
        target_os = "android",
        all(target_os = "linux", not(target_env = "uclibc")),
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )))]
    impl ExitObserver {
        fn new(_pid: Pid) -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "non-reaping process exit observation is unsupported on this Unix platform",
            ))
        }

        fn wait_for_exit(&mut self, _timeout: Duration) -> io::Result<bool> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "non-reaping process exit observation is unsupported on this Unix platform",
            ))
        }
    }
}

#[cfg(windows)]
mod platform {
    #![allow(unsafe_code)]

    use std::io;
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle as _;
    use std::os::windows::process::CommandExt as _;
    use std::process::{Child, Command, ExitStatus};
    use std::time::Duration;

    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_NO_MORE_FILES, HANDLE, INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0,
        WAIT_TIMEOUT,
    };
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject, TerminateJobObject,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_SUSPENDED, OpenThread, ResumeThread, THREAD_SUSPEND_RESUME, WaitForSingleObject,
    };

    #[derive(Debug)]
    struct OwnedJob(HANDLE);

    impl OwnedJob {
        fn create() -> io::Result<Self> {
            // SAFETY: Null security attributes and name request an unnamed job with default
            // security. The returned handle is checked and exclusively owned by `OwnedJob`.
            let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if handle.is_null() {
                return Err(io::Error::last_os_error());
            }

            let job = Self(handle);
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let byte_len = u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                .map_err(|_| io::Error::other("Windows Job Object limits are too large"))?;
            // SAFETY: `job.0` is a live Job Object handle. `limits` is the exact structure
            // selected by `JobObjectExtendedLimitInformation` and remains valid for the call.
            let configured = unsafe {
                SetInformationJobObject(
                    job.0,
                    JobObjectExtendedLimitInformation,
                    std::ptr::from_ref(&limits).cast(),
                    byte_len,
                )
            };
            if configured == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(job)
        }
    }

    impl Drop for OwnedJob {
        fn drop(&mut self) {
            // SAFETY: `self.0` is exclusively owned and closed exactly once here. The
            // kill-on-close limit intentionally terminates any remaining descendants.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }

    #[derive(Debug)]
    pub(super) struct PreparedTree(OwnedJob);

    #[derive(Debug)]
    pub(super) struct ChildTree {
        job: OwnedJob,
        process: HANDLE,
    }

    impl PreparedTree {
        pub(super) fn prepare(command: &mut Command) -> io::Result<Self> {
            command.creation_flags(CREATE_SUSPENDED);
            OwnedJob::create().map(Self)
        }

        pub(super) fn attach(self, child: &Child) -> io::Result<ChildTree> {
            // SAFETY: Both handles are live for this call; ownership is retained by `Child` and
            // `OwnedJob`, respectively, and the API does not take ownership of either handle.
            let assigned = unsafe { AssignProcessToJobObject(self.0.0, child.as_raw_handle()) };
            if assigned == 0 {
                return Err(io::Error::last_os_error());
            }

            // CREATE_SUSPENDED prevents user code from running before Job assignment. With the
            // process now contained, enumerate and resume every initial thread. Even if a resume
            // fails after another thread starts, dropping the kill-on-close Job prevents escape.
            resume_initial_threads(child.id())?;
            Ok(ChildTree {
                job: self.0,
                process: child.as_raw_handle(),
            })
        }
    }

    pub(super) fn wait_for_exit(tree: &mut ChildTree, timeout: Duration) -> io::Result<bool> {
        let millis = if timeout.is_zero() {
            0
        } else {
            u32::try_from(timeout.as_millis().max(1)).unwrap_or(u32::MAX - 1)
        };
        // SAFETY: The borrowed process handle remains owned by `Child` until the caller reaps it.
        match unsafe { WaitForSingleObject(tree.process, millis) } {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            WAIT_FAILED => Err(io::Error::last_os_error()),
            result => Err(io::Error::other(format!(
                "WaitForSingleObject returned unexpected result {result}"
            ))),
        }
    }

    pub(super) fn terminate_tree(tree: &ChildTree) -> io::Result<super::TerminationMode> {
        // Windows has no generic SIGTERM equivalent for non-console subprocesses. A Job Object is
        // already the stable tree identity, so request atomic forced termination immediately.
        kill_tree(tree).map(|()| super::TerminationMode::Forced)
    }

    pub(super) fn kill_tree(tree: &ChildTree) -> io::Result<()> {
        // SAFETY: `tree.job.0` remains a live Job Object handle for the duration of the call.
        let terminated = unsafe { TerminateJobObject(tree.job.0, 1) };
        if terminated == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(super) fn exit_signal(_status: &ExitStatus) -> Option<i32> {
        None
    }

    #[derive(Debug)]
    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            // SAFETY: `self.0` is exclusively owned and closed exactly once here.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }

    fn resume_initial_threads(process_id: u32) -> io::Result<()> {
        let threads = initial_process_threads(process_id)?;
        if threads.is_empty() {
            return Err(io::Error::other(
                "suspended child has no discoverable initial thread",
            ));
        }

        for thread in threads {
            // SAFETY: Each handle was opened with THREAD_SUSPEND_RESUME and remains live. A newly
            // CREATE_SUSPENDED process has one suspend count owned by this runner.
            let previous_count = unsafe { ResumeThread(thread.0) };
            if previous_count == u32::MAX {
                return Err(io::Error::last_os_error());
            }
            if previous_count != 1 {
                return Err(io::Error::other(format!(
                    "suspended child thread had unexpected suspend count {previous_count}"
                )));
            }
        }
        Ok(())
    }

    fn initial_process_threads(process_id: u32) -> io::Result<Vec<OwnedHandle>> {
        // SAFETY: The flags request a system thread snapshot and do not consume caller-owned data.
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let snapshot = OwnedHandle(snapshot);
        let mut entry = THREADENTRY32 {
            dwSize: u32::try_from(size_of::<THREADENTRY32>())
                .map_err(|_| io::Error::other("THREADENTRY32 is too large"))?,
            ..THREADENTRY32::default()
        };
        let mut threads = Vec::new();

        // SAFETY: `snapshot` is a valid ToolHelp snapshot and `entry` has the required size.
        let mut has_entry = unsafe { Thread32First(snapshot.0, &mut entry) };
        while has_entry != 0 {
            if entry.th32OwnerProcessID == process_id {
                // SAFETY: The snapshot supplied this thread ID. The returned handle is checked and
                // owned by `OwnedHandle`; inheritance is deliberately disabled.
                let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
                if thread.is_null() {
                    return Err(io::Error::last_os_error());
                }
                threads.push(OwnedHandle(thread));
            }

            // SAFETY: The same valid snapshot and initialized output structure remain live.
            has_entry = unsafe { Thread32Next(snapshot.0, &mut entry) };
        }

        let iteration_error = io::Error::last_os_error();
        if iteration_error.raw_os_error() != Some(ERROR_NO_MORE_FILES as i32) {
            return Err(iteration_error);
        }
        Ok(threads)
    }
}

#[cfg(not(any(unix, windows)))]
mod platform {
    use std::io;
    use std::process::{Child, Command, ExitStatus};
    use std::time::Duration;

    #[derive(Debug)]
    pub(super) struct PreparedTree;

    #[derive(Debug)]
    pub(super) struct ChildTree;

    impl PreparedTree {
        pub(super) fn prepare(_command: &mut Command) -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "process-tree isolation is unsupported on this platform",
            ))
        }

        pub(super) fn attach(self, _child: &Child) -> io::Result<ChildTree> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "process-tree isolation is unsupported on this platform",
            ))
        }
    }

    pub(super) fn terminate_tree(_tree: &ChildTree) -> io::Result<super::TerminationMode> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "process-tree termination is unsupported on this platform",
        ))
    }

    pub(super) fn kill_tree(_tree: &ChildTree) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "process-tree termination is unsupported on this platform",
        ))
    }

    pub(super) fn wait_for_exit(_tree: &mut ChildTree, _timeout: Duration) -> io::Result<bool> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "non-reaping process exit observation is unsupported on this platform",
        ))
    }

    pub(super) fn exit_signal(_status: &ExitStatus) -> Option<i32> {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::error::Error;
    use std::ffi::{OsStr, OsString};
    use std::fs::{self, OpenOptions};
    use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
    use std::process::Command as ProcessCommand;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::thread;
    use std::time::{Duration, Instant};

    use forge_core::RepoRelativePath;
    use forge_core::domain::{CommandSource, CommandSpec, Intent};
    use forge_core::evidence::DependencyValue;
    use forge_core::ports::{
        EnvPolicy, ExecSpec, OutputPolicy, ProcessErrorKind, ProcessPort as _,
    };
    use tempfile::tempdir;

    #[cfg(target_vendor = "apple")]
    use super::platform;
    use super::{
        DEFAULT_OUTPUT_LIMIT_BYTES, OutputStream, SynchronousProcessRunner, TerminationMode,
        drain_bounded, is_windows_batch_program, private_anonymous_tempfile,
        process_environment_dependency_digest, sanitized_environment,
    };
    use crate::hash::Blake3Hasher;

    const PROCESS_TREE_FIXTURE_MODE: &str = "FORGE_PROCESS_FIXTURE_MODE";
    const PROCESS_TREE_FIXTURE_HEARTBEAT: &str = "FORGE_PROCESS_FIXTURE_HEARTBEAT";
    const PROCESS_TREE_FIXTURE_OUTPUT_BYTES: &str = "FORGE_PROCESS_FIXTURE_OUTPUT_BYTES";
    const PROCESS_TREE_FIXTURE_TEST: &str = "process::tests::process_tree_fixture_helper";

    fn spec(program: impl AsRef<OsStr>, args: &[&str]) -> ExecSpec {
        ExecSpec::from_project_command(
            &CommandSpec::new(
                "runtime.process.test",
                Intent::Test,
                program,
                RepoRelativePath::root(),
                CommandSource::LanguageDefault {
                    provider: "test".into(),
                    rule: "runtime-process".into(),
                },
            )
            .with_args(args),
        )
    }

    #[cfg(unix)]
    #[test]
    fn executable_lookup_checks_path_without_running_repository_code() -> Result<(), Box<dyn Error>>
    {
        use std::os::unix::fs::PermissionsExt as _;

        use super::ExecutableAvailability;

        let root = tempdir()?;
        let bin = root.path().join("bin");
        fs::create_dir(&bin)?;
        let executable = bin.join("forge-availability-fixture");
        fs::write(&executable, b"this must never be executed\n")?;
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))?;
        let runner = SynchronousProcessRunner::new(root.path())?;
        let mut available = spec("forge-availability-fixture", &[]);
        available.env = EnvPolicy::minimal_with_overrides(BTreeMap::from([(
            OsString::from("PATH"),
            bin.as_os_str().to_owned(),
        )]));

        assert_eq!(
            runner.executable_availability(&available)?,
            ExecutableAvailability::Available
        );
        assert_eq!(fs::read(&executable)?, b"this must never be executed\n");

        let mut unavailable = spec("forge-missing-availability-fixture", &[]);
        unavailable.env = available.env;
        assert_eq!(
            runner.executable_availability(&unavailable)?,
            ExecutableAvailability::Unavailable
        );
        Ok(())
    }

    #[test]
    fn process_tree_fixture_helper() -> Result<(), Box<dyn Error>> {
        let Some(mode) = std::env::var_os(PROCESS_TREE_FIXTURE_MODE) else {
            return Ok(());
        };

        if mode == OsStr::new("output") {
            let requested = std::env::var(PROCESS_TREE_FIXTURE_OUTPUT_BYTES)?.parse::<usize>()?;
            let chunk = [b'x'; 8 * 1024];
            let mut remaining = requested;
            let mut stdout = io::stdout().lock();
            while remaining > 0 {
                let write = remaining.min(chunk.len());
                stdout.write_all(&chunk[..write])?;
                remaining -= write;
            }
            stdout.flush()?;
            return Ok(());
        }

        let heartbeat = std::env::var_os(PROCESS_TREE_FIXTURE_HEARTBEAT)
            .ok_or_else(|| io::Error::other("process-tree fixture heartbeat is missing"))?;

        if mode == OsStr::new("parent") || mode == OsStr::new("orphan-parent") {
            let executable = std::env::current_exe()?;
            let mut child = ProcessCommand::new(executable)
                .args(["--exact", PROCESS_TREE_FIXTURE_TEST, "--nocapture"])
                .env(PROCESS_TREE_FIXTURE_MODE, "child")
                .env(PROCESS_TREE_FIXTURE_HEARTBEAT, &heartbeat)
                .spawn()?;

            if mode == OsStr::new("orphan-parent") {
                let heartbeat_deadline = Instant::now() + Duration::from_secs(2);
                loop {
                    match fs::metadata(&heartbeat) {
                        Ok(metadata) if metadata.len() > 0 => return Ok(()),
                        Ok(_) => {}
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                        Err(error) => return Err(error.into()),
                    }
                    if Instant::now() >= heartbeat_deadline {
                        return Err(io::Error::other(
                            "fixture descendant did not start before parent exit",
                        )
                        .into());
                    }
                    thread::sleep(Duration::from_millis(10));
                }
            }

            let status = child.wait()?;
            return Err(io::Error::other(format!(
                "process-tree fixture child exited before termination: {status}"
            ))
            .into());
        }

        if mode == OsStr::new("child") {
            let mut heartbeat = OpenOptions::new()
                .create(true)
                .append(true)
                .open(heartbeat)?;
            loop {
                heartbeat.write_all(b"x")?;
                heartbeat.flush()?;
                thread::sleep(Duration::from_millis(25));
            }
        }

        Err(io::Error::other("unknown process-tree fixture mode").into())
    }

    fn output_fixture_command(bytes: usize) -> Result<ExecSpec, Box<dyn Error>> {
        let executable = std::env::current_exe()?;
        let mut command = spec(
            executable,
            &["--exact", PROCESS_TREE_FIXTURE_TEST, "--nocapture"],
        );
        command.env.overrides.insert(
            OsString::from(PROCESS_TREE_FIXTURE_MODE),
            OsString::from("output"),
        );
        command.env.overrides.insert(
            OsString::from(PROCESS_TREE_FIXTURE_OUTPUT_BYTES),
            OsString::from(bytes.to_string()),
        );
        command.timeout = Duration::from_secs(5);
        Ok(command)
    }

    #[test]
    fn spooled_stdout_retains_more_than_the_in_memory_diagnostic_cap() -> Result<(), Box<dyn Error>>
    {
        let root = tempdir()?;
        let runner = SynchronousProcessRunner::new(root.path())?;
        let payload_bytes = DEFAULT_OUTPUT_LIMIT_BYTES + 64 * 1024;
        let mut command = output_fixture_command(payload_bytes)?;
        command.stdout = OutputPolicy::CaptureBounded {
            max_bytes: 2 * 1024 * 1024,
        };
        let mut spooled = runner.run_spooled_stdout(&command)?;

        assert_eq!(spooled.observation.exit_code, Some(0));
        assert!(!spooled.observation.timed_out);
        assert!(!spooled.observation.interrupted);
        assert!(!spooled.observation.stdout_truncated);
        assert!(spooled.observation.stdout.is_empty());
        assert!(spooled.observation.stdout_total_bytes > DEFAULT_OUTPUT_LIMIT_BYTES as u64);
        assert_eq!(
            spooled.stdout_file.metadata()?.len(),
            spooled.observation.stdout_total_bytes
        );
        assert!(fs::read_dir(root.path())?.next().is_none());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            assert_eq!(
                spooled.stdout_file.metadata()?.permissions().mode() & 0o777,
                0o600
            );
        }
        spooled.stdout_file.seek(SeekFrom::Start(0))?;
        let mut first_byte = [0_u8; 1];
        spooled.stdout_file.read_exact(&mut first_byte)?;
        assert_ne!(first_byte, [0]);
        Ok(())
    }

    #[test]
    fn termination_modes_keep_graceful_and_forced_paths_distinct() {
        assert!(TerminationMode::Graceful.requires_grace());
        assert!(!TerminationMode::Forced.requires_grace());
    }

    #[test]
    fn spooled_stdout_drains_and_counts_bytes_beyond_its_disk_cap() -> Result<(), Box<dyn Error>> {
        const SPOOL_LIMIT: usize = 32 * 1024;
        let root = tempdir()?;
        let runner = SynchronousProcessRunner::new(root.path())?;
        let payload_bytes = DEFAULT_OUTPUT_LIMIT_BYTES + 64 * 1024;
        let mut command = output_fixture_command(payload_bytes)?;
        command.stdout = OutputPolicy::CaptureBounded {
            max_bytes: SPOOL_LIMIT,
        };
        let spooled = runner.run_spooled_stdout(&command)?;

        assert_eq!(spooled.observation.exit_code, Some(0));
        assert!(spooled.observation.stdout_truncated);
        assert!(spooled.observation.stdout_total_bytes > DEFAULT_OUTPUT_LIMIT_BYTES as u64);
        assert_eq!(spooled.stdout_file.metadata()?.len(), SPOOL_LIMIT as u64);
        Ok(())
    }

    #[derive(Debug, Default)]
    struct FailingSink;

    impl io::Write for FailingSink {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("synthetic sink failure"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn sink_failure_is_remembered_after_the_input_is_fully_drained() -> Result<(), Box<dyn Error>> {
        let input = vec![b'x'; 128 * 1024];
        let drained = drain_bounded(
            OutputStream::Stdout,
            io::Cursor::new(&input),
            FailingSink,
            input.len(),
        )?;

        assert_eq!(drained.total_bytes, input.len() as u64);
        assert!(drained.truncated);
        assert!(drained.sink_error.is_some());
        Ok(())
    }

    #[test]
    fn bounded_drain_digest_covers_bytes_beyond_the_retained_prefix() -> Result<(), Box<dyn Error>>
    {
        let mut input = vec![b'a'; 16 * 1024];
        input.extend(vec![b'b'; 16 * 1024]);
        let bounded = drain_bounded(
            OutputStream::Stdout,
            io::Cursor::new(&input),
            Vec::new(),
            17,
        )?;
        let complete = drain_bounded(
            OutputStream::Stdout,
            io::Cursor::new(&input),
            io::sink(),
            input.len(),
        )?;
        let prefix = drain_bounded(
            OutputStream::Stdout,
            io::Cursor::new(&input[..17]),
            io::sink(),
            17,
        )?;

        assert_eq!(bounded.sink, input[..17]);
        assert_eq!(bounded.total_bytes, input.len() as u64);
        assert!(bounded.truncated);
        assert_eq!(bounded.digest, complete.digest);
        assert_ne!(bounded.digest, prefix.digest);
        Ok(())
    }

    #[test]
    fn process_output_digest_separates_stream_and_content() -> Result<(), Box<dyn Error>> {
        let stdout = drain_bounded(
            OutputStream::Stdout,
            io::Cursor::new(b"same"),
            io::sink(),
            0,
        )?;
        let stderr = drain_bounded(
            OutputStream::Stderr,
            io::Cursor::new(b"same"),
            io::sink(),
            0,
        )?;
        let changed = drain_bounded(
            OutputStream::Stdout,
            io::Cursor::new(b"different"),
            io::sink(),
            0,
        )?;

        assert_ne!(stdout.digest, stderr.digest);
        assert_ne!(stdout.digest, changed.digest);
        Ok(())
    }

    #[test]
    fn process_output_digest_has_fixed_vectors() -> Result<(), Box<dyn Error>> {
        let empty_stdout =
            drain_bounded(OutputStream::Stdout, io::Cursor::new(b""), io::sink(), 0)?;
        let empty_stderr =
            drain_bounded(OutputStream::Stderr, io::Cursor::new(b""), io::sink(), 0)?;
        let raw_stdout = drain_bounded(
            OutputStream::Stdout,
            io::Cursor::new(b"raw\0bytes\xff\n"),
            io::sink(),
            0,
        )?;

        assert_eq!(
            empty_stdout.digest.as_str(),
            "blake3:9aa4ab96d0ae1f71c26db70c010010a28f44bf36091b92500c6ac152af8d71fe"
        );
        assert_eq!(
            empty_stderr.digest.as_str(),
            "blake3:dd372cad62e2ad3de5ea9ffdd82b6ab63d7a5c787aefd40e3a2878bc4741cfe9"
        );
        assert_eq!(
            raw_stdout.digest.as_str(),
            "blake3:4d70b2b7e18af8e9543e8555740968433713c232fe75747101cae8156adb9304"
        );
        Ok(())
    }

    #[test]
    fn anonymous_spool_digest_covers_bytes_beyond_its_bound() -> Result<(), Box<dyn Error>> {
        let input = vec![b'x'; 64 * 1024];
        let spooled = drain_bounded(
            OutputStream::Stdout,
            io::Cursor::new(&input),
            private_anonymous_tempfile()?,
            31,
        )?;
        let complete = drain_bounded(
            OutputStream::Stdout,
            io::Cursor::new(&input),
            io::sink(),
            input.len(),
        )?;

        assert_eq!(spooled.sink.metadata()?.len(), 31);
        assert!(spooled.truncated);
        assert_eq!(spooled.digest, complete.digest);
        Ok(())
    }

    #[test]
    fn process_sink_failure_returns_only_after_the_pipe_is_drained() -> Result<(), Box<dyn Error>> {
        let root = tempdir()?;
        let runner = SynchronousProcessRunner::new(root.path())?;
        let payload_bytes = DEFAULT_OUTPUT_LIMIT_BYTES + 64 * 1024;
        let started_at = Instant::now();
        let error = runner
            .execute(
                &output_fixture_command(payload_bytes)?,
                FailingSink,
                2 * 1024 * 1024,
                DEFAULT_OUTPUT_LIMIT_BYTES,
            )
            .err()
            .ok_or("failing process sink unexpectedly succeeded")?;

        assert!(started_at.elapsed() < Duration::from_secs(4));
        assert!(error.to_string().contains("after draining"));
        assert!(error.to_string().contains("total bytes"));
        Ok(())
    }

    #[test]
    fn windows_batch_extensions_are_identified_case_insensitively() {
        for program in [
            "build.cmd",
            "BUILD.BAT",
            r"C:\tools\run.CmD",
            "relative/run.bAt",
        ] {
            assert!(is_windows_batch_program(OsStr::new(program)));
        }
        for program in ["cmd.exe", "script", "archive.cmd.exe", "command"] {
            assert!(!is_windows_batch_program(OsStr::new(program)));
        }
    }

    #[test]
    fn startup_failures_have_stable_typed_categories() -> Result<(), Box<dyn Error>> {
        let root = tempdir()?;
        let runner = SynchronousProcessRunner::new(root.path())?;

        let missing = runner
            .run(&spec("forge-test-program-that-does-not-exist", &[]))
            .err()
            .ok_or("missing executable unexpectedly started")?;
        assert_eq!(missing.kind(), ProcessErrorKind::ExecutableUnavailable);
        assert_eq!(missing.io_kind(), io::ErrorKind::NotFound);

        let mut invalid_environment = spec("forge-test-program-that-is-not-reached", &[]);
        invalid_environment.env.overrides.insert(
            OsString::from("INVALID=NAME"),
            OsString::from("must-not-be-read"),
        );
        let invalid_environment = runner
            .run(&invalid_environment)
            .err()
            .ok_or("invalid environment unexpectedly reached process creation")?;
        assert_eq!(
            invalid_environment.kind(),
            ProcessErrorKind::InvalidEnvironment
        );

        let mut missing_cwd = spec("forge-test-program-that-is-not-reached", &[]);
        missing_cwd.cwd = RepoRelativePath::new("missing-directory")?;
        let missing_cwd = runner
            .run(&missing_cwd)
            .err()
            .ok_or("missing working directory unexpectedly reached process creation")?;
        assert_eq!(
            missing_cwd.kind(),
            ProcessErrorKind::InvalidWorkingDirectory
        );
        Ok(())
    }

    #[test]
    fn cancellation_before_spawn_remains_an_observation() -> Result<(), Box<dyn Error>> {
        let root = tempdir()?;
        let cancellation = Arc::new(AtomicBool::new(true));
        let runner =
            SynchronousProcessRunner::new(root.path())?.with_cancellation_flag(cancellation);

        let observation = runner.run(&spec("forge-test-program-that-is-not-reached", &[]))?;

        assert!(observation.interrupted);
        assert!(!observation.timed_out);
        assert_eq!(observation.exit_code, None);
        assert_eq!(observation.duration, Duration::ZERO);
        assert_eq!(
            observation.stdout_digest.as_str(),
            "blake3:9aa4ab96d0ae1f71c26db70c010010a28f44bf36091b92500c6ac152af8d71fe"
        );
        assert_eq!(
            observation.stderr_digest.as_str(),
            "blake3:dd372cad62e2ad3de5ea9ffdd82b6ab63d7a5c787aefd40e3a2878bc4741cfe9"
        );
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn windows_batch_program_is_rejected_before_path_resolution() -> Result<(), Box<dyn Error>> {
        let root = tempdir()?;
        let runner = SynchronousProcessRunner::new(root.path())?;
        let error = runner
            .run(&spec("missing-tool.CmD", &["untrusted & argument"]))
            .err()
            .ok_or("Windows batch program unexpectedly reached process creation")?;

        assert_eq!(error.kind(), ProcessErrorKind::UnsupportedProgram);
        assert!(error.to_string().contains("implicit cmd.exe"));
        Ok(())
    }

    #[test]
    fn timeout_stops_descendants_in_platform_process_tree() -> Result<(), Box<dyn Error>> {
        let root = tempdir()?;
        let heartbeat = root.path().join("portable-tree-heartbeat");
        let executable = std::env::current_exe()?;
        let runner = SynchronousProcessRunner::new(root.path())?;
        let mut command = spec(
            executable,
            &["--exact", PROCESS_TREE_FIXTURE_TEST, "--nocapture"],
        );
        command.env.overrides.insert(
            OsString::from(PROCESS_TREE_FIXTURE_MODE),
            OsString::from("parent"),
        );
        command.env.overrides.insert(
            OsString::from(PROCESS_TREE_FIXTURE_HEARTBEAT),
            heartbeat.as_os_str().to_os_string(),
        );
        command.timeout = Duration::from_secs(2);

        let observation = runner.run(&command)?;

        assert!(observation.timed_out);
        assert!(!observation.interrupted);
        assert!(observation.stdout_digest.as_str().starts_with("blake3:"));
        assert!(observation.stderr_digest.as_str().starts_with("blake3:"));
        let stopped_at = fs::metadata(&heartbeat)?.len();
        assert!(stopped_at > 0, "the fixture descendant never ran");
        thread::sleep(Duration::from_millis(300));
        let after = fs::metadata(&heartbeat)?.len();
        assert_eq!(
            stopped_at, after,
            "a fixture descendant survived process-tree timeout"
        );
        Ok(())
    }

    #[test]
    fn normal_exit_stops_background_descendants_before_pipe_drain() -> Result<(), Box<dyn Error>> {
        let root = tempdir()?;
        let heartbeat = root.path().join("normal-exit-tree-heartbeat");
        let executable = std::env::current_exe()?;
        let runner = SynchronousProcessRunner::new(root.path())?;
        let mut command = spec(
            executable,
            &["--exact", PROCESS_TREE_FIXTURE_TEST, "--nocapture"],
        );
        command.env.overrides.insert(
            OsString::from(PROCESS_TREE_FIXTURE_MODE),
            OsString::from("orphan-parent"),
        );
        command.env.overrides.insert(
            OsString::from(PROCESS_TREE_FIXTURE_HEARTBEAT),
            heartbeat.as_os_str().to_os_string(),
        );
        command.timeout = Duration::from_secs(3);

        let started_at = Instant::now();
        let observation = runner.run(&command)?;

        assert_eq!(observation.exit_code, Some(0));
        assert!(!observation.timed_out);
        assert!(!observation.interrupted);
        assert!(
            started_at.elapsed() < Duration::from_secs(2),
            "runner waited for a background descendant to close inherited pipes"
        );
        let stopped_at = fs::metadata(&heartbeat)?.len();
        assert!(stopped_at > 0, "the fixture descendant never ran");
        thread::sleep(Duration::from_millis(300));
        let after = fs::metadata(&heartbeat)?.len();
        assert_eq!(
            stopped_at, after,
            "a fixture descendant survived normal leader exit"
        );
        Ok(())
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn darwin_timeout_boundary_accepts_a_zombie_only_process_group() -> Result<(), Box<dyn Error>> {
        let mut command = ProcessCommand::new("/bin/sh");
        command.args(["-c", "sleep 0.2"]);
        let prepared_tree = platform::PreparedTree::prepare(&mut command)?;
        let mut child = command.spawn()?;
        let mut tree = match prepared_tree.attach(&child) {
            Ok(tree) => tree,
            Err(error) => {
                super::reap_direct_child(&mut child);
                return Err(error.into());
            }
        };

        // Model the timeout race: the last watcher poll sees a live leader, then the leader exits
        // before the timeout branch sends TERM. XNU reports EPERM for this zombie-only group even
        // though no live member remains; both graceful and force termination must accept it.
        assert!(!platform::wait_for_exit(&mut tree, Duration::ZERO)?);
        thread::sleep(Duration::from_millis(300));
        assert!(platform::wait_for_exit(&mut tree, Duration::ZERO)?);

        let terminate_result = platform::terminate_tree(&tree);
        let kill_result = platform::kill_tree(&tree);
        let status_result = child.wait();
        terminate_result?;
        kill_result?;
        assert!(status_result?.success());
        Ok(())
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn darwin_attach_accepts_a_child_that_exited_before_registration() -> Result<(), Box<dyn Error>>
    {
        let mut command = ProcessCommand::new("/usr/bin/true");
        let prepared_tree = platform::PreparedTree::prepare(&mut command)?;
        let mut child = command.spawn()?;

        // Force the same ordering as a heavily loaded caller: the direct child exits before the
        // parent reaches EVFILT_PROC registration, but remains unreaped and therefore still owns
        // its PID/PGID identity.
        thread::sleep(Duration::from_millis(100));
        let mut tree = match prepared_tree.attach(&child) {
            Ok(tree) => tree,
            Err(error) => {
                super::reap_direct_child(&mut child);
                return Err(error.into());
            }
        };

        assert!(platform::wait_for_exit(&mut tree, Duration::ZERO)?);
        assert!(super::kill_tree_and_reap(&mut child, &tree)?.success());
        Ok(())
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn darwin_parallel_quick_exits_remain_observable() -> Result<(), Box<dyn Error>> {
        const THREADS: usize = 8;
        const RUNS_PER_THREAD: usize = 128;

        let root = tempdir()?;
        let runner = Arc::new(SynchronousProcessRunner::new(root.path())?);
        let workers = (0..THREADS)
            .map(|_| {
                let runner = Arc::clone(&runner);
                thread::spawn(move || -> Result<(), String> {
                    for run in 0..RUNS_PER_THREAD {
                        let observation = runner
                            .run(&spec("/usr/bin/true", &[]))
                            .map_err(|error| format!("quick-exit run {run} failed: {error}"))?;
                        if observation.exit_code != Some(0)
                            || observation.signal.is_some()
                            || observation.timed_out
                            || observation.interrupted
                        {
                            return Err(format!(
                                "quick-exit run {run} returned an invalid observation: {observation:?}"
                            ));
                        }
                    }
                    Ok(())
                })
            })
            .collect::<Vec<_>>();

        for worker in workers {
            worker
                .join()
                .map_err(|_| io::Error::other("quick-exit worker panicked"))?
                .map_err(io::Error::other)?;
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn arguments_are_not_interpreted_by_a_shell() -> Result<(), Box<dyn Error>> {
        let root = tempdir()?;
        let runner = SynchronousProcessRunner::new(root.path())?;
        let observation = runner.run(&spec("/bin/echo", &["$(printf injected); *"]))?;

        assert_eq!(observation.stdout, b"$(printf injected); *\n");
        assert!(observation.stderr.is_empty());
        assert_eq!(observation.exit_code, Some(0));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn child_stdin_is_closed() -> Result<(), Box<dyn Error>> {
        let root = tempdir()?;
        let runner = SynchronousProcessRunner::new(root.path())?;
        let mut command = spec("/bin/cat", &[]);
        command.timeout = Duration::from_secs(1);
        let observation = runner.run(&command)?;

        assert_eq!(observation.exit_code, Some(0));
        assert!(!observation.timed_out);
        assert!(observation.stdout.is_empty());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlink_working_directory_escape_is_rejected() -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::symlink;

        let root = tempdir()?;
        let outside = tempdir()?;
        symlink(outside.path(), root.path().join("escape"))?;
        let runner = SynchronousProcessRunner::new(root.path())?;
        let mut command = spec("/bin/pwd", &[]);
        command.cwd = RepoRelativePath::new("escape")?;

        let error = runner
            .run(&command)
            .err()
            .ok_or_else(|| io::Error::other("symlink escape unexpectedly executed the command"))?;
        assert_eq!(error.kind(), ProcessErrorKind::InvalidWorkingDirectory);
        Ok(())
    }

    #[test]
    fn environment_is_allowlisted_and_only_explicit_controls_survive() -> Result<(), Box<dyn Error>>
    {
        let inherited = [
            (OsString::from("PATH"), OsString::from("/safe/bin")),
            (OsString::from("HOME"), OsString::from("/safe/home")),
            (
                OsString::from("XDG_CONFIG_HOME"),
                OsString::from("/safe/config"),
            ),
            (OsString::from("PAGER"), OsString::from("less")),
            (
                OsString::from("GIT_TRACE2_EVENT"),
                OsString::from("/secret"),
            ),
            (
                OsString::from("SSH_AUTH_SOCK"),
                OsString::from("/secret/socket"),
            ),
        ];
        let mut explicit = BTreeMap::new();
        explicit.insert(OsString::from("FORGE_TEST"), OsString::from("visible"));
        explicit.insert(OsString::from("GIT_TERMINAL_PROMPT"), OsString::from("0"));
        explicit.insert(OsString::from("GIT_OPTIONAL_LOCKS"), OsString::from("0"));
        explicit.insert(OsString::from("GCM_INTERACTIVE"), OsString::from("Never"));
        let policy = EnvPolicy::minimal_with_overrides(explicit);
        let environment = sanitized_environment(inherited, &policy)?;

        assert_eq!(
            environment.get(OsStr::new("PATH")),
            Some(&OsString::from("/safe/bin"))
        );
        assert_eq!(
            environment.get(OsStr::new("HOME")),
            Some(&OsString::from("/safe/home"))
        );
        assert_eq!(
            environment.get(OsStr::new("XDG_CONFIG_HOME")),
            Some(&OsString::from("/safe/config"))
        );
        assert_eq!(
            environment.get(OsStr::new("FORGE_TEST")),
            Some(&OsString::from("visible"))
        );
        assert_eq!(
            environment.get(OsStr::new("GIT_TERMINAL_PROMPT")),
            Some(&OsString::from("0"))
        );
        assert_eq!(
            environment.get(OsStr::new("GIT_OPTIONAL_LOCKS")),
            Some(&OsString::from("0"))
        );
        assert_eq!(
            environment.get(OsStr::new("GCM_INTERACTIVE")),
            Some(&OsString::from("Never"))
        );
        assert!(!environment.contains_key(OsStr::new("PAGER")));
        assert!(!environment.contains_key(OsStr::new("GIT_TRACE2_EVENT")));
        assert!(!environment.contains_key(OsStr::new("SSH_AUTH_SOCK")));

        for (key, value) in [
            ("GIT_TERMINAL_PROMPT", "1"),
            ("GIT_OPTIONAL_LOCKS", "1"),
            ("GCM_INTERACTIVE", "Always"),
            ("GIT_PAGER", "cat"),
            ("GIT_TRACE2_EVENT", "/tmp/trace"),
        ] {
            let mut restricted = BTreeMap::new();
            restricted.insert(OsString::from(key), OsString::from(value));
            let policy = EnvPolicy::minimal_with_overrides(restricted);
            assert!(sanitized_environment([], &policy).is_err());
        }
        Ok(())
    }

    #[test]
    fn environment_fingerprint_uses_the_same_sanitized_process_map() -> Result<(), Box<dyn Error>> {
        let mut first = spec("tool", &[]);
        first.env = EnvPolicy {
            inherit: BTreeSet::new(),
            overrides: BTreeMap::from([(OsString::from("SAFE_FLAG"), OsString::from("first"))]),
        };
        let mut second = first.clone();
        second
            .env
            .overrides
            .insert(OsString::from("SAFE_FLAG"), OsString::from("second"));

        let first = process_environment_dependency_digest(&first, &Blake3Hasher)?;
        let second = process_environment_dependency_digest(&second, &Blake3Hasher)?;

        assert!(matches!(first, DependencyValue::Known(_)));
        assert_ne!(first, second);
        Ok(())
    }

    #[test]
    fn environment_fingerprint_rejects_secret_like_overrides_without_values_in_errors()
    -> Result<(), Box<dyn Error>> {
        let mut command = spec("tool", &[]);
        command.env = EnvPolicy {
            inherit: BTreeSet::new(),
            overrides: BTreeMap::from([(
                OsString::from("API_TOKEN"),
                OsString::from("must-not-leak"),
            )]),
        };

        let Err(error) = process_environment_dependency_digest(&command, &Blake3Hasher) else {
            return Err("secret-like environment unexpectedly fingerprinted".into());
        };
        assert_eq!(error.kind(), ProcessErrorKind::InvalidEnvironment);
        assert!(!error.to_string().contains("API_TOKEN"));
        assert!(!error.to_string().contains("must-not-leak"));
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn restricted_environment_keys_are_case_insensitive_on_windows() -> Result<(), Box<dyn Error>> {
        let mut explicit = BTreeMap::new();
        explicit.insert(OsString::from("git_terminal_prompt"), OsString::from("0"));
        let mut policy = EnvPolicy::minimal_with_overrides(explicit);
        assert!(sanitized_environment([], &policy).is_ok());

        policy
            .overrides
            .insert(OsString::from("git_terminal_prompt"), OsString::from("1"));
        assert!(sanitized_environment([], &policy).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn stdout_and_stderr_remain_separate() -> Result<(), Box<dyn Error>> {
        let root = tempdir()?;
        let runner = SynchronousProcessRunner::new(root.path())?;
        let observation = runner.run(&spec(
            "/bin/sh",
            &["-c", "printf 'stdout-only'; printf 'stderr-only' >&2"],
        ))?;

        assert_eq!(observation.stdout, b"stdout-only");
        assert_eq!(observation.stderr, b"stderr-only");
        assert_eq!(observation.stdout_total_bytes, 11);
        assert_eq!(observation.stderr_total_bytes, 11);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn discarded_output_still_has_complete_stream_digests() -> Result<(), Box<dyn Error>> {
        let root = tempdir()?;
        let runner = SynchronousProcessRunner::new(root.path())?;
        let mut discarded = spec(
            "/bin/sh",
            &["-c", "printf 'same-output'; printf 'same-output' >&2"],
        );
        discarded.stdout = OutputPolicy::Discard;
        discarded.stderr = OutputPolicy::Discard;
        let captured = runner.run(&spec(
            "/bin/sh",
            &["-c", "printf 'same-output'; printf 'same-output' >&2"],
        ))?;
        let discarded = runner.run(&discarded)?;

        assert!(discarded.stdout.is_empty());
        assert!(discarded.stderr.is_empty());
        assert!(discarded.stdout_truncated);
        assert!(discarded.stderr_truncated);
        assert_eq!(discarded.stdout_total_bytes, 11);
        assert_eq!(discarded.stderr_total_bytes, 11);
        assert_eq!(discarded.stdout_digest, captured.stdout_digest);
        assert_eq!(discarded.stderr_digest, captured.stderr_digest);
        assert_ne!(discarded.stdout_digest, discarded.stderr_digest);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn huge_output_is_drained_but_retained_within_each_limit() -> Result<(), Box<dyn Error>> {
        let root = tempdir()?;
        let runner = SynchronousProcessRunner::new(root.path())?;
        let script = concat!(
            "i=0; ",
            "while [ \"$i\" -lt 20000 ]; do ",
            "printf '0123456789abcdef0123456789abcdef\\n'; ",
            "i=$((i + 1)); ",
            "done"
        );
        let mut command = spec("/bin/sh", &["-c", script]);
        command.stdout = OutputPolicy::CaptureBounded {
            max_bytes: 4 * 1024,
        };
        command.stderr = OutputPolicy::CaptureBounded {
            max_bytes: 4 * 1024,
        };
        let observation = runner.run(&command)?;

        assert_eq!(observation.stdout.len(), 4 * 1024);
        assert_eq!(observation.stdout_total_bytes, 660_000);
        assert!(observation.stdout_truncated);
        assert!(!observation.stderr_truncated);
        assert_eq!(observation.exit_code, Some(0));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn timeout_kills_descendants_that_ignore_term() -> Result<(), Box<dyn Error>> {
        let root = tempdir()?;
        let heartbeat = root.path().join("heartbeat");
        let runner = SynchronousProcessRunner::new(root.path())?;
        let mut command = spec(
            "/bin/sh",
            &[
                "-c",
                concat!(
                    "trap '' TERM; ",
                    "(trap '' TERM; while :; do printf x >> \"$1\"; sleep 0.05; done) & ",
                    "printf '%s\\n' \"$!\"; wait"
                ),
                "forge-process-test",
                heartbeat
                    .to_str()
                    .ok_or_else(|| io::Error::other("non-UTF-8 test path"))?,
            ],
        );
        command.timeout = Duration::from_millis(300);
        let observation = runner.run(&command)?;

        assert!(observation.timed_out);
        assert!(observation.signal.is_some());
        let before = fs::metadata(&heartbeat)?.len();
        assert!(before > 0);
        thread::sleep(Duration::from_millis(250));
        let after = fs::metadata(&heartbeat)?.len();
        assert_eq!(
            before, after,
            "a descendant continued writing after timeout"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn cancellation_kills_descendants_without_reporting_timeout() -> Result<(), Box<dyn Error>> {
        use std::sync::atomic::Ordering;

        let root = tempdir()?;
        let heartbeat = root.path().join("cancel-heartbeat");
        let cancellation = Arc::new(AtomicBool::new(false));
        let runner = SynchronousProcessRunner::new(root.path())?
            .with_cancellation_flag(Arc::clone(&cancellation));
        let mut command = spec(
            "/bin/sh",
            &[
                "-c",
                concat!(
                    "trap '' TERM; ",
                    "(trap '' TERM; while :; do printf x >> \"$1\"; sleep 0.05; done) & ",
                    "wait"
                ),
                "forge-process-cancel-test",
                heartbeat
                    .to_str()
                    .ok_or_else(|| io::Error::other("non-UTF-8 test path"))?,
            ],
        );
        command.timeout = Duration::from_secs(30);

        let worker = thread::spawn(move || runner.run(&command));
        let heartbeat_deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match fs::metadata(&heartbeat) {
                Ok(metadata) if metadata.len() > 0 => break,
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    cancellation.store(true, Ordering::Release);
                    let _ = worker.join();
                    return Err(error.into());
                }
            }
            if Instant::now() >= heartbeat_deadline {
                cancellation.store(true, Ordering::Release);
                let _ = worker.join();
                return Err(
                    io::Error::other("descendant did not start before cancellation").into(),
                );
            }
            thread::sleep(Duration::from_millis(10));
        }

        cancellation.store(true, Ordering::Release);
        let observation = worker
            .join()
            .map_err(|_| io::Error::other("process runner thread failed"))??;

        assert!(observation.interrupted);
        assert!(!observation.timed_out);
        assert!(observation.signal.is_some());
        assert!(observation.stdout_digest.as_str().starts_with("blake3:"));
        assert!(observation.stderr_digest.as_str().starts_with("blake3:"));
        let stopped_at = fs::metadata(&heartbeat)?.len();
        thread::sleep(Duration::from_millis(250));
        let after = fs::metadata(&heartbeat)?.len();
        assert_eq!(
            stopped_at, after,
            "a descendant continued writing after cancellation"
        );
        Ok(())
    }
}
