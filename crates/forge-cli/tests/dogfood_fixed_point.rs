//! Repository-level dogfood invariant: the checked-in adapter projection is a fixed point.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use forge_core::domain::{Mutability, NetworkIntent};
use forge_core::path::RepoRelativePath;
use forge_core::ports::{
    EnvPolicy, ExecSpec, OutputPolicy, ProcessError, ProcessObservation, ProcessPort as _,
    StdinPolicy,
};
use forge_runtime::git::{HARDENED_GIT_ENV, HARDENED_GIT_GLOBAL_ARGS};
use forge_runtime::process::SynchronousProcessRunner;
use serde_json::Value;

const PRIVATE_TREE_MAX_ENTRIES: usize = 32_768;
const PRIVATE_TREE_MAX_BYTES: u64 = 512 * 1024 * 1024;
const SNAPSHOT_READ_BUFFER_BYTES: usize = 64 * 1024;
const GIT_SNAPSHOT_OUTPUT_MAX_BYTES: u64 = 512 * 1024 * 1024;
const GIT_PATH_OUTPUT_MAX_BYTES: u64 = 64 * 1024;
const GIT_COMMAND_TIMEOUT: Duration = Duration::from_secs(60);

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

#[derive(Debug, PartialEq, Eq)]
struct GitSemanticSnapshot {
    head: GitCommandSnapshot,
    status: GitCommandSnapshot,
    index_entries: GitCommandSnapshot,
    index_diff: GitCommandSnapshot,
    worktree_diff: GitCommandSnapshot,
    untracked_paths: GitCommandSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GitStreamSnapshot {
    bytes: u64,
    digest: [u8; 32],
}

#[derive(Debug, PartialEq, Eq)]
struct GitCommandSnapshot {
    exit_code: Option<i32>,
    signal: Option<i32>,
    stdout: GitStreamSnapshot,
}

struct GitOutputBudget {
    observed: u64,
    max_bytes: u64,
}

#[derive(Debug, PartialEq, Eq)]
struct FileTreeSnapshot {
    exists: bool,
    directories: usize,
    files: usize,
    total_bytes: u64,
    digest: [u8; 32],
}

#[derive(Debug, PartialEq, Eq)]
struct RepositorySnapshot {
    git: GitSemanticSnapshot,
    forge_private_state: FileTreeSnapshot,
    forge_shared_cache: FileTreeSnapshot,
}

fn configure_repository_environment(command: &mut Command) {
    for name in [
        "GIT_CONFIG",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_PARAMETERS",
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_NAMESPACE",
        "GIT_EXEC_PATH",
        "GIT_EXTERNAL_DIFF",
    ] {
        command.env_remove(name);
    }
    command
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_PAGER", "cat")
        .env("LC_ALL", "C");
}

impl GitOutputBudget {
    fn new(max_bytes: u64) -> Self {
        Self {
            observed: 0,
            max_bytes,
        }
    }

    fn charge(&mut self, label: &str, observation: &ProcessObservation) -> io::Result<()> {
        // The process runner has already drained both streams without retaining their bytes. This
        // is an acceptance bound over the completed semantic snapshot; the runner's timeout is the
        // independent bound for a child that does not finish.
        let command_bytes = observation
            .stdout_total_bytes
            .checked_add(observation.stderr_total_bytes)
            .ok_or_else(|| {
                io::Error::other(format!(
                    "Git command `{label}` output byte count overflowed"
                ))
            })?;
        let observed = self.observed.checked_add(command_bytes).ok_or_else(|| {
            io::Error::other(format!(
                "Git command `{label}` cumulative output byte count overflowed"
            ))
        })?;
        if observed > self.max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Git command `{label}` exceeded the bounded Git snapshot output budget"),
            ));
        }
        self.observed = observed;
        Ok(())
    }
}

fn git_environment() -> EnvPolicy {
    let mut overrides = HARDENED_GIT_ENV
        .iter()
        .map(|(name, value)| (OsString::from(name), OsString::from(value)))
        .collect::<BTreeMap<_, _>>();
    overrides.insert(OsString::from("GIT_CONFIG_NOSYSTEM"), OsString::from("1"));
    overrides.insert(
        OsString::from("GIT_CONFIG_GLOBAL"),
        OsString::from(git_null_device()),
    );
    overrides.insert(OsString::from("GIT_ATTR_NOSYSTEM"), OsString::from("1"));
    EnvPolicy::minimal_with_overrides(overrides)
}

#[cfg(windows)]
fn git_null_device() -> &'static str {
    "NUL"
}

#[cfg(not(windows))]
fn git_null_device() -> &'static str {
    "/dev/null"
}

fn git_exec_spec(arguments: &[&str], stdout: OutputPolicy) -> ExecSpec {
    let args = HARDENED_GIT_GLOBAL_ARGS
        .iter()
        .copied()
        .chain(["-c", "core.autocrlf=false"])
        .chain(arguments.iter().copied())
        .map(OsString::from)
        .collect();
    ExecSpec {
        program: OsString::from("git"),
        args,
        cwd: RepoRelativePath::root(),
        env: git_environment(),
        timeout: GIT_COMMAND_TIMEOUT,
        stdin: StdinPolicy::Closed,
        stdout,
        stderr: OutputPolicy::Discard,
        mutability: Mutability::ReadOnly,
        network: NetworkIntent::OfflineRequested,
        concurrency_key: None,
    }
}

fn git_process_error(label: &str, error: &ProcessError) -> io::Error {
    io::Error::new(
        error.io_kind(),
        format!(
            "Git command `{label}` execution failed: category={} io={:?}",
            error.kind().as_str(),
            error.io_kind()
        ),
    )
}

fn git_failure_message(label: &str, observation: &ProcessObservation) -> String {
    format!(
        "Git command `{label}` failed: exit_code={:?} signal={:?} timed_out={} interrupted={} stdout_bytes={} stdout_digest={} stderr_bytes={} stderr_digest={}",
        observation.exit_code,
        observation.signal,
        observation.timed_out,
        observation.interrupted,
        observation.stdout_total_bytes,
        observation.stdout_digest,
        observation.stderr_total_bytes,
        observation.stderr_digest,
    )
}

fn successful_git_observation(
    runner: &SynchronousProcessRunner,
    label: &str,
    arguments: &[&str],
    stdout: OutputPolicy,
) -> io::Result<ProcessObservation> {
    let observation = runner
        .run(&git_exec_spec(arguments, stdout))
        .map_err(|error| git_process_error(label, &error))?;
    let succeeded = observation.exit_code == Some(0)
        && observation.signal.is_none()
        && !observation.timed_out
        && !observation.interrupted;
    if !succeeded {
        return Err(io::Error::other(git_failure_message(label, &observation)));
    }
    Ok(observation)
}

fn git_stream_snapshot(
    label: &str,
    stream_name: &str,
    total_bytes: u64,
    digest: &forge_schema::Digest,
) -> GitStreamSnapshot {
    fn update_framed(hasher: &mut blake3::Hasher, value: &[u8]) {
        hasher.update(&(value.len() as u64).to_le_bytes());
        hasher.update(value);
    }

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"forge.dogfood-git-stream/v1\0");
    update_framed(&mut hasher, label.as_bytes());
    update_framed(&mut hasher, stream_name.as_bytes());
    hasher.update(&total_bytes.to_le_bytes());
    update_framed(&mut hasher, digest.as_str().as_bytes());
    GitStreamSnapshot {
        bytes: total_bytes,
        digest: *hasher.finalize().as_bytes(),
    }
}

fn git_command_snapshot(label: &str, observation: &ProcessObservation) -> GitCommandSnapshot {
    GitCommandSnapshot {
        exit_code: observation.exit_code,
        signal: observation.signal,
        stdout: git_stream_snapshot(
            label,
            "stdout",
            observation.stdout_total_bytes,
            &observation.stdout_digest,
        ),
    }
}

fn successful_git_snapshot(
    runner: &SynchronousProcessRunner,
    label: &str,
    arguments: &[&str],
    budget: &mut GitOutputBudget,
) -> io::Result<GitCommandSnapshot> {
    let observation = successful_git_observation(runner, label, arguments, OutputPolicy::Discard)?;
    budget.charge(label, &observation)?;
    Ok(git_command_snapshot(label, &observation))
}

fn successful_git_stdout_bounded(
    runner: &SynchronousProcessRunner,
    label: &str,
    arguments: &[&str],
) -> io::Result<Vec<u8>> {
    let observation = successful_git_observation(
        runner,
        label,
        arguments,
        OutputPolicy::CaptureBounded {
            max_bytes: GIT_PATH_OUTPUT_MAX_BYTES as usize,
        },
    )?;
    let mut budget = GitOutputBudget::new(GIT_PATH_OUTPUT_MAX_BYTES);
    budget.charge(label, &observation)?;
    if observation.stdout_truncated
        || observation.stdout.len() as u64 != observation.stdout_total_bytes
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Git command `{label}` exceeded its bounded stdout capture"),
        ));
    }
    Ok(observation.stdout)
}

fn absolute_git_path(
    runner: &SynchronousProcessRunner,
    selector: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let label = match selector {
        "--git-dir" => "resolve absolute Git directory",
        "--git-common-dir" => "resolve absolute Git common directory",
        _ => "resolve absolute Git path",
    };
    let output = successful_git_stdout_bounded(
        runner,
        label,
        &["rev-parse", "--path-format=absolute", selector],
    )?;
    let output = String::from_utf8(output).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "absolute Git path is not valid UTF-8",
        )
    })?;
    let output = output
        .strip_suffix("\r\n")
        .or_else(|| output.strip_suffix('\n'))
        .unwrap_or(&output);
    Ok(PathBuf::from(output))
}

fn git_semantic_snapshot(runner: &SynchronousProcessRunner) -> io::Result<GitSemanticSnapshot> {
    let mut budget = GitOutputBudget::new(GIT_SNAPSHOT_OUTPUT_MAX_BYTES);
    Ok(GitSemanticSnapshot {
        head: successful_git_snapshot(
            runner,
            "resolve HEAD",
            &["rev-parse", "--verify", "HEAD"],
            &mut budget,
        )?,
        status: successful_git_snapshot(
            runner,
            "snapshot porcelain status",
            &[
                "status",
                "--porcelain=v2",
                "-z",
                "--branch",
                "--untracked-files=all",
            ],
            &mut budget,
        )?,
        index_entries: successful_git_snapshot(
            runner,
            "snapshot index entries",
            &["ls-files", "--stage", "-v", "-z", "--"],
            &mut budget,
        )?,
        index_diff: successful_git_snapshot(
            runner,
            "snapshot index diff",
            &[
                "diff",
                "--cached",
                "--no-ext-diff",
                "--no-textconv",
                "--binary",
                "--",
            ],
            &mut budget,
        )?,
        worktree_diff: successful_git_snapshot(
            runner,
            "snapshot worktree diff",
            &["diff", "--no-ext-diff", "--no-textconv", "--binary", "--"],
            &mut budget,
        )?,
        untracked_paths: successful_git_snapshot(
            runner,
            "snapshot untracked paths",
            &["ls-files", "--others", "--exclude-standard", "-z", "--"],
            &mut budget,
        )?,
    })
}

fn file_tree_snapshot(root: &Path) -> io::Result<FileTreeSnapshot> {
    fn visit(
        root: &Path,
        current: &Path,
        snapshot: &mut FileTreeSnapshot,
        hasher: &mut blake3::Hasher,
        discovered_entries: &mut usize,
    ) -> io::Result<()> {
        let mut children = Vec::new();
        for child in current.read_dir()? {
            charge_private_tree_entry(discovered_entries)?;
            children.push(child?);
        }
        children.sort_by_key(fs::DirEntry::file_name);
        for child in children {
            let entries = snapshot
                .directories
                .checked_add(snapshot.files)
                .and_then(|entries| entries.checked_add(1))
                .ok_or_else(|| io::Error::other("Forge private-state entry count overflowed"))?;
            if entries > PRIVATE_TREE_MAX_ENTRIES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Forge private state exceeds the bounded dogfood snapshot entry count",
                ));
            }
            let path = child.path();
            let relative = path
                .strip_prefix(root)
                .map_err(io::Error::other)?
                .to_path_buf();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.is_dir() {
                snapshot.directories += 1;
                update_snapshot_path(hasher, b"directory", &relative)?;
                visit(root, &path, snapshot, hasher, discovered_entries)?;
            } else if metadata.is_file() {
                snapshot.files += 1;
                snapshot.total_bytes = snapshot
                    .total_bytes
                    .checked_add(metadata.len())
                    .ok_or_else(|| io::Error::other("Forge private-state byte count overflowed"))?;
                if snapshot.total_bytes > PRIVATE_TREE_MAX_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Forge private state exceeds the bounded dogfood snapshot byte count",
                    ));
                }
                update_snapshot_path(hasher, b"file", &relative)?;
                hasher.update(&metadata.len().to_le_bytes());
                let mut file = File::open(&path)?;
                let mut observed = 0_u64;
                let mut buffer = [0_u8; SNAPSHOT_READ_BUFFER_BYTES];
                loop {
                    let read = file.read(&mut buffer)?;
                    if read == 0 {
                        break;
                    }
                    observed = observed
                        .checked_add(read as u64)
                        .ok_or_else(|| io::Error::other("private-state read size overflowed"))?;
                    if observed > metadata.len() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Forge private-state file grew during dogfood snapshot",
                        ));
                    }
                    hasher.update(&buffer[..read]);
                }
                if observed != metadata.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Forge private-state file changed during dogfood snapshot",
                    ));
                }
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Forge private state contains a symlink or special file: {}",
                        path.display()
                    ),
                ));
            }
        }
        Ok(())
    }

    match fs::symlink_metadata(root) {
        Ok(metadata) if metadata.is_dir() => {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"forge.dogfood-private-tree/v1\0");
            let mut discovered_entries = 0;
            let mut snapshot = FileTreeSnapshot {
                exists: true,
                directories: 0,
                files: 0,
                total_bytes: 0,
                digest: [0; 32],
            };
            visit(
                root,
                root,
                &mut snapshot,
                &mut hasher,
                &mut discovered_entries,
            )?;
            snapshot.digest = *hasher.finalize().as_bytes();
            Ok(snapshot)
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Forge private state root is not a real directory: {}",
                root.display()
            ),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(FileTreeSnapshot {
            exists: false,
            directories: 0,
            files: 0,
            total_bytes: 0,
            digest: [0; 32],
        }),
        Err(error) => Err(error),
    }
}

fn charge_private_tree_entry(discovered_entries: &mut usize) -> io::Result<()> {
    *discovered_entries = discovered_entries
        .checked_add(1)
        .ok_or_else(|| io::Error::other("Forge private-state entry count overflowed"))?;
    if *discovered_entries > PRIVATE_TREE_MAX_ENTRIES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Forge private state exceeds the bounded dogfood snapshot entry count",
        ));
    }
    Ok(())
}

fn update_snapshot_path(
    hasher: &mut blake3::Hasher,
    kind: &[u8],
    relative: &Path,
) -> io::Result<()> {
    let path = native_path_bytes(relative)?;
    hasher.update(&(kind.len() as u64).to_le_bytes());
    hasher.update(kind);
    hasher.update(&(path.len() as u64).to_le_bytes());
    hasher.update(&path);
    Ok(())
}

#[cfg(unix)]
fn native_path_bytes(path: &Path) -> io::Result<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt as _;

    Ok(path.as_os_str().as_bytes().to_vec())
}

#[cfg(windows)]
fn native_path_bytes(path: &Path) -> io::Result<Vec<u8>> {
    use std::os::windows::ffi::OsStrExt as _;

    let mut bytes = Vec::new();
    for unit in path.as_os_str().encode_wide() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    Ok(bytes)
}

#[cfg(not(any(unix, windows)))]
fn native_path_bytes(path: &Path) -> io::Result<Vec<u8>> {
    path.to_str()
        .map(|path| path.as_bytes().to_vec())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Forge private-state path is not representable on this platform",
            )
        })
}

fn repository_snapshot(root: &Path) -> Result<RepositorySnapshot, Box<dyn std::error::Error>> {
    let runner = SynchronousProcessRunner::new(root)
        .map_err(|error| git_process_error("initialize Git snapshot runner", &error))?;
    let git_dir = absolute_git_path(&runner, "--git-dir")?;
    let common_dir = absolute_git_path(&runner, "--git-common-dir")?;
    Ok(RepositorySnapshot {
        git: git_semantic_snapshot(&runner)?,
        forge_private_state: file_tree_snapshot(&git_dir.join("forge"))?,
        forge_shared_cache: file_tree_snapshot(&common_dir.join("forge/cache"))?,
    })
}

#[test]
fn git_snapshot_and_failure_diagnostic_do_not_retain_output() {
    let stdout_secret = b"private-source-token\n";
    let stderr_secret = b"stderr-private-token";
    let observation = process_observation(7, stdout_secret, stderr_secret);
    let snapshot = git_command_snapshot("large-output fixture", &observation);
    let debug = format!("{snapshot:?}");
    let diagnostic = git_failure_message("large-output fixture", &observation);
    for forbidden in [
        String::from_utf8_lossy(stdout_secret),
        String::from_utf8_lossy(stderr_secret),
    ] {
        assert!(!debug.contains(forbidden.as_ref()));
        assert!(!diagnostic.contains(forbidden.as_ref()));
    }
    assert_eq!(snapshot.exit_code, Some(7));
    assert_eq!(snapshot.stdout.bytes, stdout_secret.len() as u64);
    assert!(diagnostic.contains("exit_code=Some(7)"));
    assert!(diagnostic.contains("stdout_bytes="));
    assert!(diagnostic.contains("stdout_digest="));
    assert!(diagnostic.contains("stderr_bytes="));
    assert!(diagnostic.contains("stderr_digest="));
}

#[test]
fn successful_git_snapshot_ignores_stderr_and_duration() {
    let first = process_observation(0, b"stable-stdout", b"first-trace");
    let mut second = process_observation(0, b"stable-stdout", b"second-trace");
    second.stderr_digest = forge_schema::Digest::new("blake3:different-stderr-fixture");
    second.duration = Duration::from_secs(2);

    assert_eq!(
        git_command_snapshot("success fixture", &first),
        git_command_snapshot("success fixture", &second),
        "successful stderr diagnostics and timing are not repository semantics"
    );
}

#[test]
fn git_snapshot_environment_does_not_inherit_trace_controls() {
    let environment = git_environment();
    assert!(
        environment
            .inherit
            .iter()
            .chain(environment.overrides.keys())
            .all(|name| !name.to_string_lossy().starts_with("GIT_TRACE"))
    );
    assert_eq!(
        environment
            .overrides
            .get(&OsString::from("GIT_TERMINAL_PROMPT")),
        Some(&OsString::from("0"))
    );
    assert_eq!(
        environment
            .overrides
            .get(&OsString::from("GIT_CONFIG_NOSYSTEM")),
        Some(&OsString::from("1"))
    );
}

#[test]
fn git_commands_share_one_stdout_and_stderr_budget() -> Result<(), Box<dyn std::error::Error>> {
    let mut budget = GitOutputBudget::new(8);
    budget.charge("first command", &process_observation(0, b"123", b"45"))?;
    assert_eq!(budget.observed, 5);

    let error = match budget.charge("second command", &process_observation(0, b"6789", b"")) {
        Err(error) => error,
        Ok(()) => return Err(io::Error::other("combined Git output exceeded its budget").into()),
    };
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        budget.observed, 5,
        "a rejected charge must not be committed"
    );
    assert!(
        error
            .to_string()
            .contains("bounded Git snapshot output budget")
    );
    Ok(())
}

#[test]
fn git_output_budget_rejects_byte_count_overflow() -> Result<(), Box<dyn std::error::Error>> {
    let mut budget = GitOutputBudget::new(u64::MAX);
    let error = match budget.charge(
        "overflow fixture",
        &process_observation_with_sizes(u64::MAX, 1),
    ) {
        Err(error) => error,
        Ok(()) => return Err(io::Error::other("Git output byte count overflowed").into()),
    };

    assert_eq!(error.kind(), io::ErrorKind::Other);
    assert!(error.to_string().contains("byte count overflowed"));
    Ok(())
}

fn process_observation(exit_code: i32, stdout: &[u8], stderr: &[u8]) -> ProcessObservation {
    ProcessObservation {
        exit_code: Some(exit_code),
        signal: None,
        stdout: stdout.to_vec(),
        stderr: stderr.to_vec(),
        stdout_digest: forge_schema::Digest::new("blake3:stdout-fixture"),
        stderr_digest: forge_schema::Digest::new("blake3:stderr-fixture"),
        stdout_total_bytes: stdout.len() as u64,
        stderr_total_bytes: stderr.len() as u64,
        stdout_truncated: false,
        stderr_truncated: false,
        duration: Duration::from_millis(1),
        timed_out: false,
        interrupted: false,
    }
}

fn process_observation_with_sizes(stdout: u64, stderr: u64) -> ProcessObservation {
    let mut observation = process_observation(0, b"", b"");
    observation.stdout_total_bytes = stdout;
    observation.stderr_total_bytes = stderr;
    observation
}

#[test]
fn private_tree_entry_budget_counts_discovered_siblings_before_recursion() {
    let mut discovered_entries = PRIVATE_TREE_MAX_ENTRIES - 1;
    assert!(charge_private_tree_entry(&mut discovered_entries).is_ok());
    assert_eq!(discovered_entries, PRIVATE_TREE_MAX_ENTRIES);
    assert!(charge_private_tree_entry(&mut discovered_entries).is_err());
}

#[test]
fn forge_init_dry_run_is_a_zero_diff_on_its_own_repository()
-> Result<(), Box<dyn std::error::Error>> {
    let root = repository_root();
    let before = repository_snapshot(&root)?;
    let mut command = Command::new(env!("CARGO_BIN_EXE_forge"));
    command
        .current_dir(&root)
        .args(["init", "--dry-run", "--json"]);
    configure_repository_environment(&mut command);

    let output = command.output()?;
    let after = repository_snapshot(&root)?;
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let envelope: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(envelope["schema"], "forge.init-plan/v1");
    assert_eq!(
        envelope["data"]["edits"],
        Value::Array(Vec::new()),
        "run `cargo run -p forge-cli -- init --apply --allow-dirty` after reviewing the dogfood diff"
    );
    assert_eq!(after.git, before.git, "dry-run changed Git semantic state");
    assert_eq!(
        after.forge_private_state, before.forge_private_state,
        "dry-run changed Forge private-state paths or bytes"
    );
    assert_eq!(
        after.forge_shared_cache, before.forge_shared_cache,
        "dry-run changed Forge shared-cache paths or bytes"
    );
    Ok(())
}
