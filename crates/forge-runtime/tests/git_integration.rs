use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use forge_core::ports::GitPort as _;
use forge_core::{
    BranchHead, BranchOid, Digest, GitErrorKind, GitObjectFormat, RepoRelativePath, StatusEntry,
};
use forge_runtime::git::GitCli;
use forge_runtime::inventory::{InventoryOptions, build_git_inventory};
use forge_runtime::state::{
    AtomicStateStore, GitStateLayout, SharedCacheKind, SharedCacheStore, SharedCacheWrite,
};

#[derive(Debug)]
struct GitFixture {
    _root: tempfile::TempDir,
    repository: PathBuf,
    support: PathBuf,
}

impl GitFixture {
    fn init(object_format: GitObjectFormat) -> Result<Self, Box<dyn std::error::Error>> {
        let target_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
        fs::create_dir_all(&target_dir)?;
        let root = tempfile::tempdir_in(target_dir)?;
        let repository = root.path().join("repository");
        let support = root.path().join("git-fixture-support");
        fs::create_dir(&repository)?;
        fs::create_dir(&support)?;
        fs::create_dir(support.join("empty-hooks"))?;
        fs::create_dir(support.join("empty-template"))?;
        fs::create_dir(support.join("xdg"))?;
        fs::write(support.join("global-config"), b"")?;
        fs::write(support.join("attributes"), b"")?;
        fs::write(support.join("excludes"), b"")?;

        let fixture = Self {
            _root: root,
            repository,
            support,
        };
        let mut object_format_arg = OsString::from("--object-format=");
        object_format_arg.push(match object_format {
            GitObjectFormat::Sha1 => "sha1",
            GitObjectFormat::Sha256 => "sha256",
        });
        let mut template_arg = OsString::from("--template=");
        template_arg.push(fixture.support.join("empty-template"));
        let output =
            fixture.git_output([OsString::from("init"), object_format_arg, template_arg])?;
        if !output.status.success() {
            let message = fixture.git_failure("init", &output);
            if object_format == GitObjectFormat::Sha256 {
                let version = fixture
                    .git_output([OsString::from("--version")])
                    .ok()
                    .filter(|version| version.status.success())
                    .map(|version| String::from_utf8_lossy(&version.stdout).trim().to_owned())
                    .unwrap_or_else(|| "unknown Git version".to_owned());
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!(
                        "the M1 integration contract requires Git SHA-256 repositories, but {version} rejected `git init --object-format=sha256`: {message}"
                    ),
                )
                .into());
            }
            return Err(io::Error::other(message).into());
        }
        fixture.run_git(["config", "user.name", "Forge Tests"])?;
        fixture.run_git(["config", "user.email", "forge-tests@example.invalid"])?;
        Ok(fixture)
    }

    fn committed(object_format: GitObjectFormat) -> Result<Self, Box<dyn std::error::Error>> {
        let fixture = Self::init(object_format)?;
        fs::write(fixture.repository.join("tracked.txt"), b"tracked\n")?;
        fixture.run_git(["add", "--", "tracked.txt"])?;
        fixture.run_git(["commit", "-m", "fixture"])?;
        Ok(fixture)
    }

    fn git_command(&self) -> Command {
        let mut command = Command::new("git");
        command
            .current_dir(&self.repository)
            .arg("--no-pager")
            .arg("--no-optional-locks")
            .arg("-c")
            .arg(path_config(
                "core.hooksPath",
                &self.support.join("empty-hooks"),
            ))
            .arg("-c")
            .arg(path_config(
                "core.attributesFile",
                &self.support.join("attributes"),
            ))
            .arg("-c")
            .arg(path_config(
                "core.excludesFile",
                &self.support.join("excludes"),
            ))
            .arg("-c")
            .arg("core.fsmonitor=false")
            .arg("-c")
            .arg("core.autocrlf=false")
            .arg("-c")
            .arg("commit.gpgSign=false")
            .arg("-c")
            .arg("tag.gpgSign=false")
            .env_remove("GIT_CONFIG")
            .env_remove("GIT_CONFIG_COUNT")
            .env_remove("GIT_CONFIG_PARAMETERS")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_COMMON_DIR")
            .env_remove("GIT_INDEX_FILE")
            .env_remove("GIT_OBJECT_DIRECTORY")
            .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
            .env_remove("GIT_NAMESPACE")
            .env_remove("GIT_EXEC_PATH")
            .env_remove("GIT_EXTERNAL_DIFF")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", self.support.join("global-config"))
            .env("GIT_ATTR_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_PAGER", "cat")
            .env("XDG_CONFIG_HOME", self.support.join("xdg"))
            .env("LC_ALL", "C")
            .env("GIT_AUTHOR_DATE", "2000-01-01T00:00:00Z")
            .env("GIT_COMMITTER_DATE", "2000-01-01T00:00:00Z");
        command
    }

    fn git_output<I, S>(&self, args: I) -> io::Result<Output>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.git_command().args(args).output()
    }

    fn run_git<I, S>(&self, args: I) -> io::Result<()>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.run_git_at(&self.repository, args)
    }

    fn run_git_at<I, S>(&self, worktree: &Path, args: I) -> io::Result<()>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let output = self
            .git_command()
            .current_dir(worktree)
            .args(args)
            .output()?;
        if output.status.success() {
            return Ok(());
        }
        Err(io::Error::other(
            self.git_failure("fixture command", &output),
        ))
    }

    fn git_failure(&self, operation: &str, output: &Output) -> String {
        format!(
            "Git {operation} failed (status {:?}): {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim_end(),
        )
    }
}

fn path_config(key: &str, value: &Path) -> OsString {
    let mut argument = OsString::from(key);
    argument.push("=");
    argument.push(value);
    argument
}

fn add_linked_worktree(fixture: &GitFixture, linked: &Path) -> io::Result<()> {
    let args = vec![
        OsString::from("worktree"),
        OsString::from("add"),
        OsString::from("--detach"),
        linked.as_os_str().to_os_string(),
    ];
    fixture.run_git(args)
}

#[test]
fn linked_worktrees_isolate_mutable_state_and_share_cache_layout()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = GitFixture::committed(GitObjectFormat::Sha1)?;
    let linked = fixture._root.path().join("linked");
    add_linked_worktree(&fixture, &linked)?;

    let git = GitCli::new();
    let repository_root = fixture.repository.canonicalize()?;
    let linked_root = linked.canonicalize()?;
    assert_eq!(git.repository_root(&fixture.repository)?, repository_root);
    assert_eq!(git.repository_root(&linked)?, linked_root);

    let repository_git_dir = git.git_dir(&fixture.repository)?;
    let linked_git_dir = git.git_dir(&linked)?;
    assert_ne!(repository_git_dir, linked_git_dir);
    let repository_common_dir = git.git_common_dir(&fixture.repository)?;
    let linked_common_dir = git.git_common_dir(&linked)?;
    assert_eq!(repository_common_dir, linked_common_dir);

    let repository_layout = GitStateLayout::new(repository_git_dir, repository_common_dir);
    let linked_layout = GitStateLayout::new(linked_git_dir, linked_common_dir);
    assert_ne!(
        repository_layout.worktree_dir(),
        linked_layout.worktree_dir()
    );
    assert_eq!(
        repository_layout.shared_cache_dir(),
        linked_layout.shared_cache_dir()
    );

    let repository_store = AtomicStateStore::new(repository_layout.clone())?;
    let linked_store = AtomicStateStore::new(linked_layout.clone())?;
    let state_key = "mutable/current.json";
    let repository_value = br#"{"worktree":"repository"}"#;
    let linked_value = br#"{"worktree":"linked"}"#;

    repository_store.store_atomic(state_key, repository_value)?;
    assert_eq!(linked_store.load(state_key)?, None);
    linked_store.store_atomic(state_key, linked_value)?;
    assert_eq!(
        repository_store.load(state_key)?,
        Some(repository_value.to_vec())
    );
    assert_eq!(linked_store.load(state_key)?, Some(linked_value.to_vec()));

    let repository_cache = SharedCacheStore::new(&repository_layout)?;
    let linked_cache = SharedCacheStore::new(&linked_layout)?;
    assert_eq!(repository_cache.root(), linked_cache.root());
    let cache_key = Digest::new(format!("blake3:{}", "a".repeat(64)));
    assert_eq!(
        repository_cache.store_immutable(
            SharedCacheKind::Inventory,
            &cache_key,
            b"shared immutable inventory",
        )?,
        SharedCacheWrite::Created
    );
    assert_eq!(
        linked_cache.load(SharedCacheKind::Inventory, &cache_key, 1024)?,
        Some(b"shared immutable inventory".to_vec())
    );
    assert_eq!(
        linked_cache.store_immutable(
            SharedCacheKind::Inventory,
            &cache_key,
            b"shared immutable inventory",
        )?,
        SharedCacheWrite::AlreadyPresent
    );

    assert!(git.status(&fixture.repository)?.branch.oid.is_some());
    assert!(git.status(&linked)?.branch.oid.is_some());

    let repository_index_before = git.index_snapshot_bytes(&fixture.repository, 1024 * 1024)?;
    let linked_index_before = git.index_snapshot_bytes(&linked, 1024 * 1024)?;
    fs::write(linked.join("tracked.txt"), b"linked index change\n")?;
    fixture.run_git_at(&linked, ["add", "--", "tracked.txt"])?;
    assert_eq!(
        git.index_snapshot_bytes(&fixture.repository, 1024 * 1024)?,
        repository_index_before
    );
    assert_ne!(
        git.index_snapshot_bytes(&linked, 1024 * 1024)?,
        linked_index_before
    );
    Ok(())
}

#[test]
fn raw_index_snapshot_is_exact_bounded_and_changes_after_git_add()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = GitFixture::init(GitObjectFormat::Sha1)?;
    fs::write(fixture.repository.join("tracked.txt"), b"first\n")?;
    fixture.run_git(["add", "--", "tracked.txt"])?;

    let git = GitCli::new();
    let first = git.index_snapshot_bytes(&fixture.repository, 1024 * 1024)?;
    assert!(first.starts_with(b"DIRC"));
    assert_eq!(
        git.index_snapshot_bytes(&fixture.repository, first.len())?,
        first
    );
    assert_eq!(
        git.index_snapshot_bytes(&fixture.repository, first.len().saturating_sub(1))
            .err()
            .map(|error| error.kind()),
        Some(GitErrorKind::OutputLimit)
    );

    fs::write(fixture.repository.join("tracked.txt"), b"second\n")?;
    fixture.run_git(["add", "--", "tracked.txt"])?;
    let second = git.index_snapshot_bytes(&fixture.repository, 1024 * 1024)?;
    assert!(second.starts_with(b"DIRC"));
    assert_ne!(second, first);

    fs::write(fixture.repository.join(".git").join("index.lock"), b"")?;
    let locked = git
        .index_snapshot_bytes(&fixture.repository, 1024 * 1024)
        .err()
        .ok_or("locked index unexpectedly produced a raw snapshot")?;
    assert_eq!(locked.kind(), GitErrorKind::InvalidData);
    assert_eq!(locked.operation(), "index-snapshot");
    assert!(locked.detail().contains("index.lock"));
    Ok(())
}

#[test]
fn raw_index_snapshot_fails_closed_for_a_split_index() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = GitFixture::init(GitObjectFormat::Sha1)?;
    fs::write(fixture.repository.join("tracked.txt"), b"tracked\n")?;
    fixture.run_git(["add", "--", "tracked.txt"])?;
    fixture.run_git(["update-index", "--split-index"])?;

    let error = GitCli::new()
        .index_snapshot_bytes(&fixture.repository, 1024 * 1024)
        .err()
        .ok_or("split index unexpectedly produced a single-file raw snapshot")?;
    assert_eq!(error.kind(), GitErrorKind::InvalidData);
    assert_eq!(error.operation(), "index-snapshot");
    assert!(error.detail().contains("split indexes"));
    Ok(())
}

#[test]
fn raw_index_snapshot_rejects_a_non_regular_index() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = GitFixture::init(GitObjectFormat::Sha1)?;
    fs::write(fixture.repository.join("tracked.txt"), b"tracked\n")?;
    fixture.run_git(["add", "--", "tracked.txt"])?;
    let index_path = fixture.repository.join(".git").join("index");
    fs::rename(
        &index_path,
        fixture.repository.join(".git").join("index.real"),
    )?;
    fs::create_dir(&index_path)?;

    let error = GitCli::new()
        .index_snapshot_bytes(&fixture.repository, 1024 * 1024)
        .err()
        .ok_or("directory index unexpectedly produced a raw snapshot")?;
    assert_eq!(error.kind(), GitErrorKind::CorruptRepository);
    assert_eq!(error.operation(), "index-path");
    assert!(error.detail().contains("unable to map index file"));
    Ok(())
}

#[test]
fn sha256_repository_status_uses_full_width_object_ids() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = GitFixture::committed(GitObjectFormat::Sha256)?;
    fs::write(fixture.repository.join("tracked.txt"), b"modified\n")?;
    fs::write(fixture.repository.join("untracked.txt"), b"untracked\n")?;

    let status = GitCli::new().status(&fixture.repository)?;
    assert_eq!(status.object_format, GitObjectFormat::Sha256);
    let Some(BranchOid::Commit(branch_oid)) = status.branch.oid.as_ref() else {
        return Err("SHA-256 repository did not report a committed branch OID".into());
    };
    assert_eq!(branch_oid.as_bytes().len(), 64);

    let tracked = status.entries.iter().find_map(|entry| match entry {
        StatusEntry::Ordinary(entry) if entry.path.as_path() == Path::new("tracked.txt") => {
            Some(entry)
        }
        _ => None,
    });
    let Some(tracked) = tracked else {
        return Err("SHA-256 status omitted the modified tracked file".into());
    };
    assert_eq!(tracked.head_oid.as_bytes().len(), 64);
    assert_eq!(tracked.index_oid.as_bytes().len(), 64);
    assert!(status.entries.iter().any(|entry| {
        matches!(entry, StatusEntry::Untracked(path) if path.as_path() == Path::new("untracked.txt"))
    }));
    Ok(())
}

#[test]
fn commit_file_reads_are_immutable_literal_and_bounded() -> Result<(), Box<dyn std::error::Error>> {
    for object_format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let fixture = GitFixture::init(object_format)?;
        let accepted = b"schema = 1\n# accepted baseline\n";
        let literal_path_content = b"literal pathspec bytes\n";
        fs::write(fixture.repository.join("forge.toml"), accepted)?;
        fs::write(
            fixture.repository.join("[policy].toml"),
            literal_path_content,
        )?;
        fixture.run_git(["add", "--all"])?;
        fixture.run_git(["commit", "-m", "policy baseline"])?;

        let git = GitCli::new();
        let status = git.status(&fixture.repository)?;
        let head = match status.branch.oid {
            Some(BranchOid::Commit(head)) => head,
            _ => return Err("committed fixture did not report an immutable HEAD".into()),
        };
        fs::write(fixture.repository.join("forge.toml"), b"schema = 1\n")?;
        let path = RepoRelativePath::new("forge.toml")?;

        assert_eq!(
            git.read_commit_file_bounded(
                &fixture.repository,
                &head,
                &path,
                accepted.len() as u64,
            )?,
            Some(accepted.to_vec())
        );
        assert_eq!(
            git.read_commit_file_bounded(
                &fixture.repository,
                &head,
                &RepoRelativePath::new("absent.toml")?,
                1024,
            )?,
            None
        );
        assert_eq!(
            git.read_commit_file_bounded(
                &fixture.repository,
                &head,
                &RepoRelativePath::new("[policy].toml")?,
                1024,
            )?,
            Some(literal_path_content.to_vec())
        );
        assert_eq!(
            git.read_commit_file_bounded(
                &fixture.repository,
                &head,
                &path,
                accepted.len() as u64 - 1,
            )
            .err()
            .map(|error| error.kind()),
            Some(GitErrorKind::OutputLimit)
        );
    }
    Ok(())
}

#[test]
fn unborn_repository_status_is_typed_without_a_commit() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = GitFixture::init(GitObjectFormat::Sha1)?;
    fs::write(fixture.repository.join("untracked.txt"), b"untracked\n")?;

    let status = GitCli::new().status(&fixture.repository)?;
    assert_eq!(status.object_format, GitObjectFormat::Sha1);
    assert_eq!(status.branch.oid, Some(BranchOid::Unborn));
    assert!(matches!(status.branch.head, Some(BranchHead::Named(_))));
    assert!(status.entries.iter().any(|entry| {
        matches!(entry, StatusEntry::Untracked(path) if path.as_path() == Path::new("untracked.txt"))
    }));
    Ok(())
}

#[test]
fn git_inventory_keeps_tracked_ignored_paths_and_filters_only_untracked_candidates()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = GitFixture::committed(GitObjectFormat::Sha1)?;
    fs::write(
        fixture.repository.join(".gitignore"),
        b"tracked.txt\ngit-ignored.txt\n",
    )?;
    fs::write(
        fixture.repository.join(".ignore"),
        b"tracked.txt\ndot-ignore-ignored.txt\n",
    )?;
    fs::write(fixture.repository.join("git-ignored.txt"), b"ignored\n")?;
    fs::write(
        fixture.repository.join("dot-ignore-ignored.txt"),
        b"ignored\n",
    )?;
    fs::write(fixture.repository.join("kept-untracked.txt"), b"kept\n")?;

    let git = GitCli::new();
    let file_set = git.file_set(&fixture.repository)?;
    assert!(
        file_set
            .tracked
            .iter()
            .any(|path| path.as_path() == Path::new("tracked.txt"))
    );
    assert!(
        !file_set
            .untracked
            .iter()
            .any(|path| path.as_path() == Path::new("git-ignored.txt"))
    );
    assert!(
        file_set
            .untracked
            .iter()
            .any(|path| path.as_path() == Path::new("dot-ignore-ignored.txt"))
    );

    let inventory = build_git_inventory(&fixture.repository, &git, InventoryOptions::default())?;
    let contains = |expected: &Path| inventory.entries.iter().any(|entry| entry.path == expected);
    assert!(contains(Path::new("tracked.txt")));
    assert!(contains(Path::new("kept-untracked.txt")));
    assert!(!contains(Path::new("git-ignored.txt")));
    assert!(!contains(Path::new("dot-ignore-ignored.txt")));
    Ok(())
}

#[test]
fn non_repository_fails_closed_with_operation_context() -> Result<(), Box<dyn std::error::Error>> {
    // This fixture must live outside the Forge checkout or Git would intentionally discover the
    // checkout's parent repository while walking upward.
    let directory = tempfile::tempdir()?;

    let error = GitCli::new()
        .repository_root(directory.path())
        .err()
        .ok_or("non-repository path unexpectedly resolved to a repository")?;
    assert_eq!(error.kind(), GitErrorKind::NotRepository);
    assert!(error.to_string().contains("repository-root"));
    Ok(())
}

// Darwin filesystems reject this deliberately invalid UTF-8 filename before Git can observe it.
// Linux CI provides the byte-native filesystem integration leg; core parser tests remain portable.
#[cfg(target_os = "linux")]
#[test]
fn status_preserves_a_non_utf8_worktree_path() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};

    let fixture = GitFixture::committed(GitObjectFormat::Sha1)?;
    let filename = OsString::from_vec(b"non-utf8-\xff".to_vec());
    fs::write(fixture.repository.join(&filename), b"untracked\n").map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("failed to create non-UTF-8 fixture path: {error}"),
        )
    })?;

    let git = GitCli::new();
    let status = git.status(&fixture.repository).map_err(|error| {
        io::Error::other(format!(
            "failed to read typed status for non-UTF-8 fixture: {error}"
        ))
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

    let file_set = git.file_set(&fixture.repository)?;
    assert!(
        file_set
            .untracked
            .iter()
            .any(|path| { path.as_path().as_os_str().as_bytes() == filename.as_bytes() })
    );
    let inventory = build_git_inventory(&fixture.repository, &git, InventoryOptions::default())?;
    assert!(
        inventory
            .entries
            .iter()
            .any(|entry| { entry.path.as_os_str().as_bytes() == filename.as_bytes() })
    );

    fixture.run_git(["add", "--all"])?;
    fixture.run_git(["commit", "-m", "native path"])?;
    let status = git.status(&fixture.repository)?;
    let head = match status.branch.oid {
        Some(BranchOid::Commit(head)) => head,
        _ => return Err("native-path fixture did not report a commit".into()),
    };
    let native_path = RepoRelativePath::new(Path::new(&filename))?;
    assert_eq!(
        git.read_commit_file_bounded(&fixture.repository, &head, &native_path, 1024)?,
        Some(b"untracked\n".to_vec())
    );
    Ok(())
}
