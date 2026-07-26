//! Per-worktree state layout, atomic storage, and process locking.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Component, Path, PathBuf};

use forge_core::ports::StateStore;
use thiserror::Error;

use crate::fs::{FileSystemError, RepositoryWriter};

/// Schema version for mutable, per-worktree state.
pub const STATE_LAYOUT_VERSION: u16 = 1;

/// Schema version for immutable, content-addressed shared cache entries.
pub const SHARED_CACHE_LAYOUT_VERSION: u16 = 1;

/// State paths derived from Git's already-resolved `git-dir` and
/// `git-common-dir` values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitStateLayout {
    git_dir: PathBuf,
    common_dir: PathBuf,
    worktree_dir: PathBuf,
    shared_cache_dir: PathBuf,
}

impl GitStateLayout {
    #[must_use]
    pub fn new(git_dir: impl Into<PathBuf>, common_dir: impl Into<PathBuf>) -> Self {
        let git_dir = git_dir.into();
        let common_dir = common_dir.into();
        let worktree_dir = git_dir.join("forge");
        let shared_cache_dir = common_dir.join("forge").join("cache");
        Self {
            git_dir,
            common_dir,
            worktree_dir,
            shared_cache_dir,
        }
    }

    #[must_use]
    pub fn git_dir(&self) -> &Path {
        &self.git_dir
    }

    #[must_use]
    pub fn common_dir(&self) -> &Path {
        &self.common_dir
    }

    #[must_use]
    pub fn worktree_dir(&self) -> &Path {
        &self.worktree_dir
    }

    #[must_use]
    pub fn shared_cache_dir(&self) -> &Path {
        &self.shared_cache_dir
    }

    #[must_use]
    pub fn lock_file(&self) -> PathBuf {
        self.worktree_dir.join("lock")
    }
}

/// Atomic byte storage confined to one worktree's private Git directory.
#[derive(Debug, Clone)]
pub struct AtomicStateStore {
    layout: GitStateLayout,
    writer: RepositoryWriter,
}

impl AtomicStateStore {
    /// Validates the resolved Git roots and creates the private state/cache
    /// directories. Mutable values are always rooted at `worktree_dir`.
    pub fn new(layout: GitStateLayout) -> Result<Self, StateError> {
        validate_resolved_directory(layout.git_dir())?;
        validate_resolved_directory(layout.common_dir())?;
        ensure_private_directory(layout.worktree_dir())?;

        let shared_parent =
            layout
                .shared_cache_dir()
                .parent()
                .ok_or_else(|| StateError::InvalidLayout {
                    path: layout.shared_cache_dir().to_path_buf(),
                    reason: "shared cache path has no parent".to_owned(),
                })?;
        ensure_private_directory(shared_parent)?;
        ensure_private_directory(layout.shared_cache_dir())?;

        let writer = RepositoryWriter::new(layout.worktree_dir())?;
        Ok(Self { layout, writer })
    }

    /// Opens an existing per-worktree state store without changing the
    /// filesystem.
    ///
    /// This validates both resolved Git roots and the private state directory,
    /// but deliberately does not create the state directory, shared cache, or
    /// lock file. An absent state directory is reported as `Ok(None)`; an
    /// existing unsafe path fails closed.
    pub fn open_existing_read_only(layout: GitStateLayout) -> Result<Option<Self>, StateError> {
        validate_resolved_directory(layout.git_dir())?;
        validate_resolved_directory(layout.common_dir())?;
        if !validate_existing_private_directory(layout.worktree_dir())? {
            return Ok(None);
        }

        let writer = RepositoryWriter::new(layout.worktree_dir())?;
        Ok(Some(Self { layout, writer }))
    }

    #[must_use]
    pub fn layout(&self) -> &GitStateLayout {
        &self.layout
    }

    /// Loads exactly the schema bytes stored for `key`.
    pub fn load(&self, key: &str) -> Result<Option<Vec<u8>>, StateError> {
        let relative = validate_state_key(key)?;
        match self.writer.read(&relative) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.io_kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(StateError::PathSafety(error)),
        }
    }

    /// Atomically stores exactly the supplied schema bytes for `key`.
    pub fn store_atomic(&self, key: &str, bytes: &[u8]) -> Result<(), StateError> {
        let relative = validate_state_key(key)?;
        if relative == Path::new("lock") {
            return Err(StateError::UnsafeKey {
                key: key.to_owned(),
                reason: "`lock` is reserved for the state lock".to_owned(),
            });
        }

        if let Some(parent) = relative.parent() {
            ensure_private_relative_directories(self.layout.worktree_dir(), parent)?;
        }
        self.writer
            .write_atomic_private(relative, bytes)
            .map_err(StateError::PathSafety)
    }

    /// Attempts to acquire the per-worktree exclusive lock.
    ///
    /// The returned guard owns the locked file descriptor, so dropping it
    /// releases the lock. Contention is reported with `WouldBlock` semantics.
    pub fn try_lock(&self) -> Result<StateLock, StateError> {
        let lock_path = self.layout.lock_file();
        let file = open_private_lock_file(&lock_path)?;
        match fs2::FileExt::try_lock_exclusive(&file) {
            Ok(()) => Ok(StateLock {
                _file: file,
                path: lock_path,
            }),
            Err(source) if is_lock_contention(&source) => {
                Err(StateError::LockBusy { path: lock_path })
            }
            Err(source) => Err(StateError::io("acquire state lock", lock_path, source)),
        }
    }
}

impl StateStore for AtomicStateStore {
    fn load(&self, key: &str) -> io::Result<Option<Vec<u8>>> {
        AtomicStateStore::load(self, key).map_err(StateError::into_io_error)
    }

    fn store_atomic(&self, key: &str, bytes: &[u8]) -> io::Result<()> {
        AtomicStateStore::store_atomic(self, key, bytes).map_err(StateError::into_io_error)
    }
}

/// An exclusive state lock released when the value is dropped.
#[derive(Debug)]
pub struct StateLock {
    _file: File,
    path: PathBuf,
}

impl StateLock {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// A state layout, path-safety, persistence, or locking failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StateError {
    #[error("invalid Git state layout path `{path}`: {reason}")]
    InvalidLayout { path: PathBuf, reason: String },
    #[error("unsafe state key `{key}`: {reason}")]
    UnsafeKey { key: String, reason: String },
    #[error("state path safety check failed: {0}")]
    PathSafety(#[from] FileSystemError),
    #[error("state lock is already held: `{path}`")]
    LockBusy { path: PathBuf },
    #[error("state operation `{operation}` failed for `{path}`: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

impl StateError {
    fn io(operation: &'static str, path: impl AsRef<Path>, source: io::Error) -> Self {
        Self::Io {
            operation,
            path: path.as_ref().to_path_buf(),
            source,
        }
    }

    #[must_use]
    pub fn io_kind(&self) -> io::ErrorKind {
        match self {
            Self::InvalidLayout { .. } | Self::UnsafeKey { .. } => io::ErrorKind::InvalidInput,
            Self::PathSafety(error) => error.io_kind(),
            Self::LockBusy { .. } => io::ErrorKind::WouldBlock,
            Self::Io { source, .. } => source.kind(),
        }
    }

    pub fn into_io_error(self) -> io::Error {
        io::Error::new(self.io_kind(), self)
    }
}

fn validate_resolved_directory(path: &Path) -> Result<(), StateError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(StateError::InvalidLayout {
            path: path.to_path_buf(),
            reason: "Git directory must be an absolute, resolved path".to_owned(),
        });
    }

    let metadata = fs::symlink_metadata(path)
        .map_err(|source| StateError::io("inspect Git state root", path, source))?;
    if metadata.file_type().is_symlink() {
        return Err(StateError::PathSafety(FileSystemError::SymlinkComponent {
            path: path.to_path_buf(),
        }));
    }
    if !metadata.is_dir() {
        return Err(StateError::InvalidLayout {
            path: path.to_path_buf(),
            reason: "Git state root is not a directory".to_owned(),
        });
    }
    Ok(())
}

fn ensure_private_directory(path: &Path) -> Result<(), StateError> {
    match create_private_directory(path) {
        Ok(()) => {}
        Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
        Err(source) => {
            return Err(StateError::io(
                "create private state directory",
                path,
                source,
            ));
        }
    }

    let metadata = fs::symlink_metadata(path)
        .map_err(|source| StateError::io("verify private state directory", path, source))?;
    validate_private_directory(path, &metadata)
}

fn validate_existing_private_directory(path: &Path) -> Result<bool, StateError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(source) => {
            return Err(StateError::io(
                "inspect private state directory",
                path,
                source,
            ));
        }
    };
    validate_private_directory(path, &metadata)?;
    Ok(true)
}

fn validate_private_directory(path: &Path, metadata: &fs::Metadata) -> Result<(), StateError> {
    if metadata.file_type().is_symlink() {
        return Err(StateError::PathSafety(FileSystemError::SymlinkComponent {
            path: path.to_path_buf(),
        }));
    }
    if !metadata.is_dir() {
        return Err(StateError::InvalidLayout {
            path: path.to_path_buf(),
            reason: "state layout conflicts with an existing non-directory".to_owned(),
        });
    }

    validate_private_directory_permissions(path, metadata)?;
    Ok(())
}

fn ensure_private_relative_directories(root: &Path, relative: &Path) -> Result<(), StateError> {
    let mut candidate = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(segment) = component else {
            return Err(StateError::UnsafeKey {
                key: relative.to_string_lossy().into_owned(),
                reason: "state hierarchy is not normalized".to_owned(),
            });
        };
        candidate.push(segment);
        ensure_private_directory(&candidate)?;
    }
    Ok(())
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;

    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> io::Result<()> {
    fs::create_dir(path)
}

#[cfg(unix)]
fn validate_private_directory_permissions(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), StateError> {
    use std::os::unix::fs::PermissionsExt as _;

    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(StateError::InvalidLayout {
            path: path.to_path_buf(),
            reason: format!(
                "private state directory mode {mode:o} grants group or other access; expected 0700 or stricter"
            ),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_directory_permissions(
    _path: &Path,
    _metadata: &fs::Metadata,
) -> Result<(), StateError> {
    Ok(())
}

fn validate_state_key(key: &str) -> Result<PathBuf, StateError> {
    if key.is_empty() {
        return Err(StateError::UnsafeKey {
            key: key.to_owned(),
            reason: "key must name a file".to_owned(),
        });
    }
    if key.starts_with('/') || key.ends_with('/') || key.contains('\\') {
        return Err(StateError::UnsafeKey {
            key: key.to_owned(),
            reason: "key must use a portable relative `/` hierarchy".to_owned(),
        });
    }

    for segment in key.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(StateError::UnsafeKey {
                key: key.to_owned(),
                reason: "empty, `.` and `..` path segments are forbidden".to_owned(),
            });
        }
        if !segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(StateError::UnsafeKey {
                key: key.to_owned(),
                reason: "segments may contain only ASCII letters, digits, `.`, `_`, or `-`"
                    .to_owned(),
            });
        }
    }

    let path = PathBuf::from(key);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(StateError::UnsafeKey {
            key: key.to_owned(),
            reason: "key is not a normalized relative path".to_owned(),
        });
    }
    Ok(path)
}

fn open_private_lock_file(path: &Path) -> Result<File, StateError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_lock_metadata(path, &metadata)?,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            match create_new_lock_file(path) {
                Ok(file) => {
                    return Ok(file);
                }
                Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
                    let metadata = fs::symlink_metadata(path).map_err(|inspect_source| {
                        StateError::io("inspect raced state lock", path, inspect_source)
                    })?;
                    validate_lock_metadata(path, &metadata)?;
                }
                Err(source) => {
                    return Err(StateError::io("create state lock", path, source));
                }
            }
        }
        Err(source) => return Err(StateError::io("inspect state lock", path, source)),
    }

    let file = open_existing_lock_file(path).map_err(|source| {
        StateError::io("open state lock without following links", path, source)
    })?;
    if !file
        .metadata()
        .map_err(|source| StateError::io("verify opened state lock", path, source))?
        .is_file()
    {
        return Err(StateError::InvalidLayout {
            path: path.to_path_buf(),
            reason: "state lock is not a regular file".to_owned(),
        });
    }
    Ok(file)
}

fn validate_lock_metadata(path: &Path, metadata: &fs::Metadata) -> Result<(), StateError> {
    if metadata.file_type().is_symlink() {
        return Err(StateError::PathSafety(FileSystemError::SymlinkComponent {
            path: path.to_path_buf(),
        }));
    }
    if !metadata.is_file() {
        return Err(StateError::InvalidLayout {
            path: path.to_path_buf(),
            reason: "state lock conflicts with an existing non-regular file".to_owned(),
        });
    }
    Ok(())
}

fn create_new_lock_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    configure_lock_open_options(&mut options);
    options.open(path)
}

fn open_existing_lock_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    configure_lock_open_options(&mut options);
    options.open(path)
}

#[cfg(unix)]
fn configure_lock_open_options(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt as _;

    options.mode(0o600).custom_flags(nix::libc::O_NOFOLLOW);
}

#[cfg(windows)]
fn configure_lock_open_options(options: &mut OpenOptions) {
    use std::os::windows::fs::OpenOptionsExt as _;

    // FILE_FLAG_OPEN_REPARSE_POINT opens the link itself instead of its target.
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
}

#[cfg(not(any(unix, windows)))]
fn configure_lock_open_options(_options: &mut OpenOptions) {}

fn is_lock_contention(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::WouldBlock
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fs;
    use std::io;
    use std::path::{Path, PathBuf};

    use tempfile::tempdir;

    use super::{AtomicStateStore, GitStateLayout, StateError};

    type FileSystemSnapshot = Vec<(PathBuf, u32, Option<Vec<u8>>)>;

    #[test]
    fn read_only_open_leaves_absent_state_and_filesystem_unchanged() -> Result<(), Box<dyn Error>> {
        let temporary = tempdir()?;
        let git_dir = temporary.path().join("git");
        let common_dir = temporary.path().join("common");
        fs::create_dir(&git_dir)?;
        fs::create_dir(&common_dir)?;
        let layout = GitStateLayout::new(&git_dir, &common_dir);
        let before = filesystem_snapshot(temporary.path())?;

        let result = AtomicStateStore::open_existing_read_only(layout.clone())?;

        assert!(result.is_none());
        assert_eq!(filesystem_snapshot(temporary.path())?, before);
        assert!(!layout.worktree_dir().exists());
        assert!(!layout.shared_cache_dir().exists());
        assert!(!layout.lock_file().exists());
        Ok(())
    }

    #[test]
    fn read_only_open_reads_existing_state_without_writing() -> Result<(), Box<dyn Error>> {
        let temporary = tempdir()?;
        let git_dir = temporary.path().join("git");
        let common_dir = temporary.path().join("common");
        fs::create_dir(&git_dir)?;
        fs::create_dir(&common_dir)?;
        let layout = GitStateLayout::new(&git_dir, &common_dir);
        let store = AtomicStateStore::new(layout.clone())?;
        store.store_atomic("evidence/current.json", br#"{"schema":1}"#)?;
        let before = filesystem_snapshot(temporary.path())?;

        let read_only = AtomicStateStore::open_existing_read_only(layout.clone())?
            .ok_or_else(|| io::Error::other("existing state store was not opened"))?;

        assert_eq!(
            read_only.load("evidence/current.json")?,
            Some(br#"{"schema":1}"#.to_vec())
        );
        assert_eq!(filesystem_snapshot(temporary.path())?, before);
        assert!(!layout.lock_file().exists());
        Ok(())
    }

    fn filesystem_snapshot(root: &Path) -> io::Result<FileSystemSnapshot> {
        let mut snapshot = Vec::new();
        let mut directories = vec![root.to_path_buf()];
        while let Some(directory) = directories.pop() {
            for entry in fs::read_dir(directory)? {
                let path = entry?.path();
                let metadata = fs::symlink_metadata(&path)?;
                let contents = if metadata.is_file() {
                    Some(fs::read(&path)?)
                } else {
                    None
                };
                snapshot.push((
                    path.strip_prefix(root)
                        .map_err(|error| io::Error::other(error.to_string()))?
                        .to_path_buf(),
                    permission_mode(&metadata),
                    contents,
                ));
                if metadata.is_dir() {
                    directories.push(path);
                }
            }
        }
        snapshot.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(snapshot)
    }

    #[cfg(unix)]
    fn permission_mode(metadata: &fs::Metadata) -> u32 {
        use std::os::unix::fs::PermissionsExt as _;

        metadata.permissions().mode() & 0o777
    }

    #[cfg(not(unix))]
    fn permission_mode(_metadata: &fs::Metadata) -> u32 {
        0
    }

    #[test]
    fn worktree_state_is_isolated_while_cache_is_shared() -> Result<(), Box<dyn Error>> {
        let temporary = tempdir()?;
        let common = temporary.path().join("common");
        let worktree_a = temporary.path().join("worktree-a-git");
        let worktree_b = temporary.path().join("worktree-b-git");
        fs::create_dir(&common)?;
        fs::create_dir(&worktree_a)?;
        fs::create_dir(&worktree_b)?;

        let layout_a = GitStateLayout::new(&worktree_a, &common);
        let layout_b = GitStateLayout::new(&worktree_b, &common);
        assert_ne!(layout_a.worktree_dir(), layout_b.worktree_dir());
        assert_eq!(layout_a.shared_cache_dir(), layout_b.shared_cache_dir());

        let store_a = AtomicStateStore::new(layout_a)?;
        let store_b = AtomicStateStore::new(layout_b)?;
        store_a.store_atomic("model-v1.json", br#"{"schema":1}"#)?;

        assert_eq!(store_b.load("model-v1.json")?, None);
        assert_eq!(
            store_a.load("model-v1.json")?,
            Some(br#"{"schema":1}"#.to_vec())
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn preexisting_symlink_state_directory_fails_closed() -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::symlink;

        let temporary = tempdir()?;
        let git_dir = temporary.path().join("git");
        let outside = temporary.path().join("outside");
        fs::create_dir(&git_dir)?;
        fs::create_dir(&outside)?;
        symlink(&outside, git_dir.join("forge"))?;

        let layout = GitStateLayout::new(&git_dir, &git_dir);
        let create_result = AtomicStateStore::new(layout.clone());
        let read_only_result = AtomicStateStore::open_existing_read_only(layout);

        assert!(matches!(
            create_result,
            Err(StateError::PathSafety(
                crate::fs::FileSystemError::SymlinkComponent { .. }
            ))
        ));
        assert!(matches!(
            read_only_result,
            Err(StateError::PathSafety(
                crate::fs::FileSystemError::SymlinkComponent { .. }
            ))
        ));
        Ok(())
    }

    #[test]
    fn preexisting_regular_file_state_directory_fails_closed() -> Result<(), Box<dyn Error>> {
        let temporary = tempdir()?;
        let git_dir = temporary.path().join("git");
        fs::create_dir(&git_dir)?;
        fs::write(git_dir.join("forge"), b"conflict")?;

        let layout = GitStateLayout::new(&git_dir, &git_dir);

        assert!(matches!(
            AtomicStateStore::new(layout.clone()),
            Err(StateError::InvalidLayout { .. })
        ));
        assert!(matches!(
            AtomicStateStore::open_existing_read_only(layout),
            Err(StateError::InvalidLayout { .. })
        ));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn preexisting_public_state_directory_fails_closed() -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = tempdir()?;
        let git_dir = temporary.path().join("git");
        let state_dir = git_dir.join("forge");
        fs::create_dir(&git_dir)?;
        fs::create_dir(&state_dir)?;
        fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o777))?;

        let layout = GitStateLayout::new(&git_dir, &git_dir);

        assert_insecure_state_error(AtomicStateStore::new(layout.clone()))?;
        assert_insecure_state_error(AtomicStateStore::open_existing_read_only(layout))?;
        Ok(())
    }

    #[cfg(unix)]
    fn assert_insecure_state_error<T>(result: Result<T, StateError>) -> io::Result<()> {
        match result {
            Err(StateError::InvalidLayout { reason, .. })
                if reason.contains("group or other access") =>
            {
                Ok(())
            }
            Err(other) => Err(io::Error::other(format!("unexpected error: {other}"))),
            Ok(_) => Err(io::Error::other("public state directory was accepted")),
        }
    }

    #[cfg(unix)]
    #[test]
    fn private_state_directories_and_files_use_private_modes() -> Result<(), Box<dyn Error>> {
        let temporary = tempdir()?;
        let git_dir = temporary.path().join("git");
        let common_dir = temporary.path().join("common");
        fs::create_dir(&git_dir)?;
        fs::create_dir(&common_dir)?;
        let layout = GitStateLayout::new(&git_dir, &common_dir);
        let store = AtomicStateStore::new(layout.clone())?;

        store.store_atomic("receipts/one.json", br#"{"schema":1}"#)?;
        let _lock = store.try_lock()?;

        assert_private_mode(layout.worktree_dir(), 0o700)?;
        assert_private_mode(&layout.worktree_dir().join("receipts"), 0o700)?;
        assert_private_mode(layout.shared_cache_dir(), 0o700)?;
        assert_private_mode(&layout.worktree_dir().join("receipts/one.json"), 0o600)?;
        assert_private_mode(&layout.lock_file(), 0o600)?;
        Ok(())
    }

    #[cfg(unix)]
    fn assert_private_mode(path: &std::path::Path, maximum: u32) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        let actual = fs::metadata(path)?.permissions().mode() & 0o777;
        if actual & !maximum != 0 {
            return Err(io::Error::other(format!(
                "mode {actual:o} for `{}` is wider than {maximum:o}",
                path.display()
            )));
        }
        Ok(())
    }

    #[test]
    fn exclusive_lock_conflict_is_would_block_and_drop_releases_it() -> Result<(), Box<dyn Error>> {
        let temporary = tempdir()?;
        let git_dir = temporary.path().join("git");
        fs::create_dir(&git_dir)?;
        let layout = GitStateLayout::new(&git_dir, &git_dir);
        let first_store = AtomicStateStore::new(layout.clone())?;
        let second_store = AtomicStateStore::new(layout)?;

        let first_lock = first_store.try_lock()?;
        let conflict = second_store.try_lock();
        match conflict {
            Err(error) => assert_eq!(error.io_kind(), io::ErrorKind::WouldBlock),
            Ok(_unexpected_lock) => {
                return Err(io::Error::other("second lock unexpectedly succeeded").into());
            }
        }

        drop(first_lock);
        let _second_lock = second_store.try_lock()?;
        Ok(())
    }

    #[test]
    fn state_keys_are_portable_relative_hierarchies() -> Result<(), Box<dyn Error>> {
        let temporary = tempdir()?;
        let git_dir = temporary.path().join("git");
        fs::create_dir(&git_dir)?;
        let store = AtomicStateStore::new(GitStateLayout::new(&git_dir, &git_dir))?;

        store.store_atomic("receipts/01ABC.json", b"schema bytes")?;
        assert_eq!(
            store.load("receipts/01ABC.json")?,
            Some(b"schema bytes".to_vec())
        );
        for unsafe_key in ["", "/absolute", "../escape", "a/../escape", "a//b", "a\\b"] {
            assert!(matches!(
                store.store_atomic(unsafe_key, b"unsafe"),
                Err(StateError::UnsafeKey { .. })
            ));
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn state_store_rejects_symlink_target() -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::symlink;

        let temporary = tempdir()?;
        let git_dir = temporary.path().join("git");
        fs::create_dir(&git_dir)?;
        let layout = GitStateLayout::new(&git_dir, &git_dir);
        let store = AtomicStateStore::new(layout.clone())?;
        store.store_atomic("receipts/bootstrap.json", b"schema bytes")?;
        let outside = temporary.path().join("outside.json");
        fs::write(&outside, b"outside")?;
        symlink(&outside, layout.worktree_dir().join("receipts/linked.json"))?;

        let result = store.store_atomic("receipts/linked.json", b"unsafe");

        assert!(matches!(
            result,
            Err(StateError::PathSafety(
                crate::fs::FileSystemError::SymlinkComponent { .. }
            ))
        ));
        assert_eq!(fs::read(&outside)?, b"outside");
        Ok(())
    }
}
