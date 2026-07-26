use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(target_os = "linux")]
use forge_core::StatusEntry;
use forge_core::ports::GitPort as _;
use forge_runtime::git::GitCli;

fn run_git<I, S>(cwd: &Path, args: I) -> io::Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .output()?;
    if output.status.success() {
        return Ok(());
    }
    Err(io::Error::other(format!(
        "Git fixture setup failed (status {:?}): {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).trim_end(),
    )))
}

fn committed_repository() -> Result<(tempfile::TempDir, PathBuf), Box<dyn std::error::Error>> {
    let target_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
    fs::create_dir_all(&target_dir)?;
    let root = tempfile::tempdir_in(target_dir)?;
    let repository = root.path().join("repository");
    fs::create_dir(&repository)?;
    run_git(&repository, ["init"])?;
    run_git(&repository, ["config", "user.name", "Forge Tests"])?;
    run_git(
        &repository,
        ["config", "user.email", "forge-tests@example.invalid"],
    )?;
    fs::write(repository.join("tracked.txt"), b"tracked\n")?;
    run_git(&repository, ["add", "--", "tracked.txt"])?;
    run_git(&repository, ["commit", "-m", "fixture"])?;
    Ok((root, repository))
}

fn add_linked_worktree(repository: &Path, linked: &Path) -> io::Result<()> {
    let args = vec![
        OsString::from("worktree"),
        OsString::from("add"),
        OsString::from("--detach"),
        linked.as_os_str().to_os_string(),
    ];
    run_git(repository, args)
}

#[test]
fn linked_worktree_has_distinct_typed_git_dir_and_shared_common_dir()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, repository) = committed_repository()?;
    let linked = root.path().join("linked");
    add_linked_worktree(&repository, &linked)?;

    let git = GitCli::new();
    let repository_root = repository.canonicalize()?;
    let linked_root = linked.canonicalize()?;
    assert_eq!(git.repository_root(&repository)?, repository_root);
    assert_eq!(git.repository_root(&linked)?, linked_root);

    let repository_git_dir = git.git_dir(&repository)?;
    let linked_git_dir = git.git_dir(&linked)?;
    assert_ne!(repository_git_dir, linked_git_dir);
    assert_eq!(
        git.git_common_dir(&repository)?,
        git.git_common_dir(&linked)?
    );
    assert!(git.status(&repository)?.branch.oid.is_some());
    assert!(git.status(&linked)?.branch.oid.is_some());
    Ok(())
}

// Darwin filesystems reject this deliberately invalid UTF-8 filename before Git can observe it.
// Linux CI provides the byte-native filesystem integration leg; core parser tests remain portable.
#[cfg(target_os = "linux")]
#[test]
fn status_preserves_a_non_utf8_worktree_path() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};

    let (_root, repository) = committed_repository()?;
    let filename = OsString::from_vec(b"non-utf8-\xff".to_vec());
    fs::write(repository.join(&filename), b"untracked\n").map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("failed to create non-UTF-8 fixture path: {error}"),
        )
    })?;

    let status = GitCli::new().status(&repository).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("failed to read typed status for non-UTF-8 fixture: {error}"),
        )
    })?;
    let found = status.entries.iter().any(|entry| match entry {
        StatusEntry::Untracked(path) => {
            path.as_path().as_os_str().as_bytes() == filename.as_bytes()
        }
        _ => false,
    });
    assert!(
        found,
        "typed status did not preserve the native filename bytes"
    );
    Ok(())
}
