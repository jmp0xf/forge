//! Repository-level dogfood invariant: the checked-in adapter projection is a fixed point.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

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
    directories: Vec<PathBuf>,
    files: Vec<(PathBuf, Vec<u8>)>,
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
    fn visit(root: &Path, current: &Path, snapshot: &mut FileTreeSnapshot) -> io::Result<()> {
        let mut children = current.read_dir()?.collect::<Result<Vec<_>, _>>()?;
        children.sort_by_key(fs::DirEntry::file_name);
        for child in children {
            let path = child.path();
            let relative = path
                .strip_prefix(root)
                .map_err(io::Error::other)?
                .to_path_buf();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.is_dir() {
                snapshot.directories.push(relative);
                visit(root, &path, snapshot)?;
            } else if metadata.is_file() {
                snapshot.files.push((relative, fs::read(&path)?));
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
            let mut snapshot = FileTreeSnapshot {
                exists: true,
                directories: Vec::new(),
                files: Vec::new(),
            };
            visit(root, root, &mut snapshot)?;
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
            directories: Vec::new(),
            files: Vec::new(),
        }),
        Err(error) => Err(error),
    }
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
