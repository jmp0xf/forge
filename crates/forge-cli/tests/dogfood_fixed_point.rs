//! Repository-level dogfood invariant: the checked-in adapter projection is a fixed point.

use std::fs::{self, File};
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

const PRIVATE_TREE_MAX_ENTRIES: usize = 32_768;
const PRIVATE_TREE_MAX_BYTES: u64 = 512 * 1024 * 1024;
const SNAPSHOT_READ_BUFFER_BYTES: usize = 64 * 1024;

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

#[derive(Debug, PartialEq, Eq)]
struct GitSemanticSnapshot {
    head: Vec<u8>,
    status: Vec<u8>,
    index_entries: Vec<u8>,
    index_diff: Vec<u8>,
    worktree_diff: Vec<u8>,
    untracked_paths: Vec<u8>,
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

fn successful_git_stdout(root: &Path, arguments: &[&str]) -> io::Result<Vec<u8>> {
    let mut command = Command::new("git");
    command
        .current_dir(root)
        .arg("--no-optional-locks")
        .arg("-c")
        .arg("core.fsmonitor=false")
        .arg("-c")
        .arg("core.autocrlf=false")
        .args(arguments);
    configure_repository_environment(&mut command);
    let output = command.output()?;
    if output.status.success() {
        return Ok(output.stdout);
    }
    Err(io::Error::other(format!(
        "git {arguments:?} failed with status {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).trim_end()
    )))
}

fn absolute_git_path(root: &Path, selector: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let output = successful_git_stdout(root, &["rev-parse", "--path-format=absolute", selector])?;
    Ok(PathBuf::from(String::from_utf8(output)?.trim_end()))
}

fn git_semantic_snapshot(root: &Path) -> io::Result<GitSemanticSnapshot> {
    Ok(GitSemanticSnapshot {
        head: successful_git_stdout(root, &["rev-parse", "--verify", "HEAD"])?,
        status: successful_git_stdout(
            root,
            &[
                "status",
                "--porcelain=v2",
                "-z",
                "--branch",
                "--untracked-files=all",
            ],
        )?,
        index_entries: successful_git_stdout(root, &["ls-files", "--stage", "-v", "-z", "--"])?,
        index_diff: successful_git_stdout(
            root,
            &["diff", "--cached", "--no-ext-diff", "--binary", "--"],
        )?,
        worktree_diff: successful_git_stdout(root, &["diff", "--no-ext-diff", "--binary", "--"])?,
        untracked_paths: successful_git_stdout(
            root,
            &["ls-files", "--others", "--exclude-standard", "-z", "--"],
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
    let git_dir = absolute_git_path(root, "--git-dir")?;
    let common_dir = absolute_git_path(root, "--git-common-dir")?;
    Ok(RepositorySnapshot {
        git: git_semantic_snapshot(root)?,
        forge_private_state: file_tree_snapshot(&git_dir.join("forge"))?,
        forge_shared_cache: file_tree_snapshot(&common_dir.join("forge/cache"))?,
    })
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
