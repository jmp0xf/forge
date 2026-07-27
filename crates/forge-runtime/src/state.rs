//! Per-worktree state layout, atomic storage, and process locking.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

use forge_core::ports::StateStore;
use thiserror::Error;

use crate::fs::{FileSystemError, RepositoryWriter};

mod evidence;
pub use evidence::*;
mod shared_cache;
pub use shared_cache::*;
#[cfg(windows)]
mod windows;
#[cfg(any(windows, test))]
mod windows_acl_policy;

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
    evidence_security: bool,
}

impl AtomicStateStore {
    /// Validates the resolved Git roots and creates an owner-private per-worktree state directory.
    ///
    /// Receipt, Evidence, and log callers must still use [`Self::new_evidence`] for their typed,
    /// versioned, and retention-aware storage contract.
    pub fn new(layout: GitStateLayout) -> Result<Self, StateError> {
        validate_resolved_directory(layout.git_dir())?;
        validate_resolved_directory(layout.common_dir())?;
        let _created = ensure_private_directory(layout.worktree_dir())?;

        let writer = RepositoryWriter::new(layout.worktree_dir())?;
        Ok(Self {
            layout,
            writer,
            evidence_security: false,
        })
    }

    /// Opens an existing generic per-worktree state store without changing the filesystem.
    ///
    /// This validates both resolved Git roots and the private state directory,
    /// but deliberately does not create the state directory, shared cache, or
    /// lock file. An absent state directory is reported as `Ok(None)`; an
    /// existing unsafe path fails closed. Evidence readers must use
    /// [`Self::open_existing_evidence_read_only`] for the additional typed Evidence contract.
    /// Forge performs no application-level write here; the host filesystem may still update
    /// implementation-managed access timestamps when later reads occur.
    pub fn open_existing_read_only(layout: GitStateLayout) -> Result<Option<Self>, StateError> {
        validate_resolved_directory(layout.git_dir())?;
        validate_resolved_directory(layout.common_dir())?;
        if !validate_existing_private_directory(layout.worktree_dir())? {
            return Ok(None);
        }

        let writer = RepositoryWriter::new(layout.worktree_dir())?;
        Ok(Some(Self {
            layout,
            writer,
            evidence_security: false,
        }))
    }

    #[must_use]
    pub fn layout(&self) -> &GitStateLayout {
        &self.layout
    }

    /// Loads exactly the schema bytes stored for `key`.
    pub fn load(&self, key: &str) -> Result<Option<Vec<u8>>, StateError> {
        let relative = validate_state_key(key)?;
        reject_reserved_state_access(key, &relative)?;
        self.load_inner(&relative)
    }

    fn load_inner(&self, relative: &Path) -> Result<Option<Vec<u8>>, StateError> {
        read_private_state_file(self.layout.worktree_dir(), relative, None)
    }

    /// Loads one state value with a hard retention bound.
    pub fn load_bounded(&self, key: &str, max_bytes: usize) -> Result<Option<Vec<u8>>, StateError> {
        let relative = validate_state_key(key)?;
        reject_reserved_state_access(key, &relative)?;
        self.load_bounded_inner(&relative, max_bytes)
    }

    fn load_bounded_inner(
        &self,
        relative: &Path,
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, StateError> {
        read_private_state_file(self.layout.worktree_dir(), relative, Some(max_bytes))
    }

    /// Atomically stores exactly the supplied schema bytes for `key`.
    pub fn store_atomic(&self, key: &str, bytes: &[u8]) -> Result<(), StateError> {
        let relative = validate_state_key(key)?;
        reject_reserved_state_access(key, &relative)?;

        validate_required_private_state_directory(self.layout.worktree_dir())?;
        if let Some(parent) = relative.parent() {
            ensure_private_relative_directories(self.layout.worktree_dir(), parent)?;
        }
        let _existing = resolve_existing_private_state_file(self.layout.worktree_dir(), &relative)?;
        self.writer
            .write_atomic_private(&relative, bytes)
            .map_err(StateError::PathSafety)?;
        validate_required_private_state_file(self.layout.worktree_dir(), &relative)
    }

    /// Atomically stores a new immutable value and refuses to replace an existing key.
    pub fn store_new_atomic(&self, key: &str, bytes: &[u8]) -> Result<(), StateError> {
        let relative = validate_state_key(key)?;
        reject_reserved_state_access(key, &relative)?;
        self.store_new_atomic_inner(&relative, bytes)
    }

    fn store_new_atomic_inner(&self, relative: &Path, bytes: &[u8]) -> Result<(), StateError> {
        validate_required_private_state_directory(self.layout.worktree_dir())?;
        if let Some(parent) = relative.parent() {
            ensure_private_relative_directories(self.layout.worktree_dir(), parent)?;
        }
        let _existing = resolve_existing_private_state_file(self.layout.worktree_dir(), relative)?;
        match self.writer.write_atomic_private_new(relative, bytes) {
            Ok(()) => validate_required_private_state_file(self.layout.worktree_dir(), relative),
            Err(error) if error.io_kind() == io::ErrorKind::AlreadyExists => {
                // A raced or pre-existing target is still part of the private state boundary.
                // Validate it before preserving the no-clobber result so permissive state never
                // hides behind an ordinary identity collision.
                validate_required_private_state_file(self.layout.worktree_dir(), relative)?;
                Err(StateError::PathSafety(error))
            }
            Err(error) => Err(StateError::PathSafety(error)),
        }
    }

    /// Lists direct regular-file keys under one existing private state directory.
    ///
    /// Results use the portable state-key syntax and stable byte ordering. Missing directories
    /// are empty; symlinks, nested directories, non-regular entries, and over-limit results fail
    /// closed. This generic primitive validates private storage permissions but does not validate
    /// the Evidence version hierarchy, content identities, or references; Evidence readers must use
    /// [`Self::visit_evidence_state_snapshot`].
    pub fn list_regular_keys_bounded(
        &self,
        directory: &str,
        max_entries: usize,
    ) -> Result<Vec<String>, StateError> {
        let relative = validate_state_key(directory)?;
        reject_reserved_state_access(directory, &relative)?;
        self.list_regular_keys_bounded_inner(directory, &relative, max_entries)
    }

    fn list_regular_keys_bounded_inner(
        &self,
        directory: &str,
        relative: &Path,
        max_entries: usize,
    ) -> Result<Vec<String>, StateError> {
        let Some(path) = validate_existing_state_directory(self.layout.worktree_dir(), relative)?
        else {
            return Ok(Vec::new());
        };
        let mut keys = Vec::new();
        for entry in fs::read_dir(&path)
            .map_err(|source| StateError::io("list private state directory", &path, source))?
        {
            let entry = entry
                .map_err(|source| StateError::io("read private state entry", &path, source))?;
            let entry_path = entry.path();
            let metadata = fs::symlink_metadata(&entry_path).map_err(|source| {
                StateError::io("inspect private state entry", &entry_path, source)
            })?;
            if metadata_is_link_or_reparse(&metadata) {
                return Err(StateError::PathSafety(FileSystemError::SymlinkComponent {
                    path: entry_path,
                }));
            }
            if !metadata.is_file() {
                let reason = if metadata.is_dir()
                    && evidence::is_evidence_gc_quarantine_name(&entry.file_name())
                {
                    "immutable evidence GC residue requires held-lock recovery"
                } else {
                    "listed state directory contains a non-regular entry"
                };
                return Err(StateError::InvalidLayout {
                    path: entry_path,
                    reason: reason.to_owned(),
                });
            }
            validate_private_state_file(&entry_path, &metadata)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| StateError::InvalidLayout {
                    path: entry.path(),
                    reason: "state keys must use portable ASCII names".to_owned(),
                })?;
            let key = format!("{directory}/{name}");
            validate_state_key(&key)?;
            keys.push(key);
            if keys.len() > max_entries {
                return Err(StateError::EntryLimit {
                    directory: directory.to_owned(),
                    max_entries,
                });
            }
        }
        keys.sort();
        Ok(keys)
    }

    /// Attempts to acquire the per-worktree exclusive lock.
    ///
    /// The returned guard owns the locked file descriptor, so dropping it
    /// releases the lock. Contention is reported with `WouldBlock` semantics.
    pub fn try_lock(&self) -> Result<StateLock, StateError> {
        validate_required_private_state_directory(self.layout.worktree_dir())?;
        let lock_path = self.layout.lock_file();
        let file = open_private_lock_file(&lock_path)?;
        if self.evidence_security {
            evidence::validate_evidence_lock_acl(&file, &lock_path)?;
        }
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

    fn ensure_matching_lock(&self, lock: &StateLock) -> Result<(), StateError> {
        if lock.path == self.layout.lock_file() && lock_file_still_names_path(lock)? {
            evidence::validate_evidence_lock_acl(&lock._file, &lock.path)?;
            if lock_file_still_names_path(lock)? {
                return Ok(());
            }
        }
        Err(StateError::WrongLock {
            expected: self.layout.lock_file(),
            actual: lock.path.clone(),
        })
    }
}

impl StateStore for AtomicStateStore {
    fn load(&self, key: &str) -> io::Result<Option<Vec<u8>>> {
        AtomicStateStore::load(self, key).map_err(StateError::into_io_error)
    }

    fn load_bounded(&self, key: &str, max_bytes: usize) -> io::Result<Option<Vec<u8>>> {
        AtomicStateStore::load_bounded(self, key, max_bytes).map_err(StateError::into_io_error)
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
    #[error("private Evidence state uses an unsupported or future layout version at `{path}`")]
    UnsupportedEvidenceStateVersion { path: PathBuf },
    #[error("unsafe state key `{key}`: {reason}")]
    UnsafeKey { key: String, reason: String },
    #[error("generic state access cannot use reserved state path `{key}`")]
    ReservedStatePath { key: String },
    #[error("state path safety check failed: {0}")]
    PathSafety(#[from] FileSystemError),
    #[error("state lock is already held: `{path}`")]
    LockBusy { path: PathBuf },
    #[error(
        "state directory `{directory}` contains more than the configured {max_entries} entries"
    )]
    EntryLimit {
        directory: String,
        max_entries: usize,
    },
    #[error(
        "retained state directory `{directory}` requires {retained_entries} entries, above the {max_entries}-entry scan-safe limit"
    )]
    RetainedObjectCountExceeded {
        directory: String,
        retained_entries: usize,
        max_entries: usize,
    },
    #[error("state lock `{actual}` does not protect expected worktree state `{expected}`")]
    WrongLock { expected: PathBuf, actual: PathBuf },
    #[error("immutable state object `{key}` exceeds its {max_bytes}-byte bound")]
    ObjectTooLarge { key: String, max_bytes: usize },
    #[error("immutable state object `{key}` cannot be decoded: {reason}")]
    ObjectDecode {
        key: String,
        reason: EvidenceStateDecodeError,
    },
    #[error("immutable state object `{key}` declares identity `{declared}`")]
    ObjectIdentityMismatch { key: String, declared: String },
    #[error("immutable state object `{key}` does not match its content-addressed filename")]
    ObjectContentAddressMismatch { key: String },
    #[error("retained state object `{owner}` references missing object `{referenced}`")]
    MissingReference { owner: String, referenced: String },
    #[error(
        "retained immutable evidence state uses {retained_bytes} bytes, above the {max_bytes}-byte budget"
    )]
    RetainedBudgetExceeded { retained_bytes: u64, max_bytes: u64 },
    #[error(
        "immutable evidence scan reached {scanned_bytes} bytes at `{key}`, above the {max_bytes}-byte bound"
    )]
    ScanByteLimit {
        key: String,
        scanned_bytes: u64,
        max_bytes: u64,
    },
    #[error(
        "immutable evidence scan reached {references} references at `{key}`, above the {max_references}-reference bound"
    )]
    ReferenceLimit {
        key: String,
        references: usize,
        max_references: usize,
    },
    #[error("immutable evidence state byte accounting overflowed")]
    StateSizeOverflow,
    #[error("immutable state object `{key}` changed during garbage collection")]
    StateChanged { key: String },
    #[error(
        "immutable state object `{key}` could not be verified after quarantine ({verification}); replacement could not be restored from `{quarantine}`: {source}"
    )]
    QuarantineRestore {
        key: String,
        quarantine: PathBuf,
        verification: String,
        #[source]
        source: io::Error,
    },
    #[error("immutable state identity collision for `{key}`")]
    ImmutableCollision { key: String },
    #[error("private evidence-state mutation is unsupported on `{platform}`: {reason}")]
    EvidenceStateMutationUnsupported {
        platform: &'static str,
        reason: &'static str,
    },
    #[error("private evidence-state reads are unsupported on `{platform}`: {reason}")]
    EvidenceStateReadUnsupported {
        platform: &'static str,
        reason: &'static str,
    },
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
            Self::InvalidLayout { .. }
            | Self::UnsupportedEvidenceStateVersion { .. }
            | Self::UnsafeKey { .. }
            | Self::ReservedStatePath { .. }
            | Self::WrongLock { .. } => io::ErrorKind::InvalidInput,
            Self::PathSafety(error) => error.io_kind(),
            Self::LockBusy { .. } => io::ErrorKind::WouldBlock,
            Self::EntryLimit { .. }
            | Self::RetainedObjectCountExceeded { .. }
            | Self::ObjectTooLarge { .. }
            | Self::ObjectDecode { .. }
            | Self::ObjectIdentityMismatch { .. }
            | Self::ObjectContentAddressMismatch { .. }
            | Self::MissingReference { .. }
            | Self::RetainedBudgetExceeded { .. }
            | Self::ScanByteLimit { .. }
            | Self::ReferenceLimit { .. }
            | Self::StateSizeOverflow
            | Self::StateChanged { .. }
            | Self::QuarantineRestore { .. } => io::ErrorKind::InvalidData,
            Self::ImmutableCollision { .. } => io::ErrorKind::AlreadyExists,
            Self::EvidenceStateMutationUnsupported { .. }
            | Self::EvidenceStateReadUnsupported { .. } => io::ErrorKind::Unsupported,
            Self::Io { source, .. } => source.kind(),
        }
    }

    pub fn into_io_error(self) -> io::Error {
        io::Error::new(self.io_kind(), self)
    }
}

#[cfg(unix)]
fn validate_private_file_permissions(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), StateError> {
    use std::os::unix::fs::PermissionsExt as _;

    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(StateError::InvalidLayout {
            path: path.to_path_buf(),
            reason: format!(
                "private state object mode {mode:o} grants group or other access; expected 0600 or stricter"
            ),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_file_permissions(
    _path: &Path,
    _metadata: &fs::Metadata,
) -> Result<(), StateError> {
    Ok(())
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
    if metadata_is_link_or_reparse(&metadata) {
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

fn ensure_private_directory(path: &Path) -> Result<bool, StateError> {
    let created = match create_private_directory(path) {
        Ok(()) => true,
        Err(source) if source.kind() == io::ErrorKind::AlreadyExists => false,
        Err(source) => {
            return Err(StateError::io(
                "create private state directory",
                path,
                source,
            ));
        }
    };

    let metadata = fs::symlink_metadata(path)
        .map_err(|source| StateError::io("verify private state directory", path, source))?;
    validate_private_directory(path, &metadata)?;
    if created {
        #[cfg(not(windows))]
        evidence::clear_inherited_extended_acl(path)?;
        #[cfg(windows)]
        if let Err(error) = evidence::clear_inherited_extended_acl(path) {
            let _cleanup = fs::remove_dir(path);
            return Err(error);
        }
        sync_directory(path)?;
        let parent = path.parent().ok_or_else(|| StateError::InvalidLayout {
            path: path.to_path_buf(),
            reason: "private state directory has no parent".to_owned(),
        })?;
        sync_directory(parent)?;
    }
    evidence::validate_private_directory_acl(path, &metadata)?;
    Ok(created)
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
    validate_private_state_directory(path, &metadata)?;
    Ok(true)
}

fn validate_existing_state_directory(
    root: &Path,
    relative: &Path,
) -> Result<Option<PathBuf>, StateError> {
    validate_required_private_state_directory(root)?;
    let mut candidate = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(segment) = component else {
            return Err(StateError::UnsafeKey {
                key: relative.to_string_lossy().into_owned(),
                reason: "state hierarchy is not normalized".to_owned(),
            });
        };
        candidate.push(segment);
        let metadata = match fs::symlink_metadata(&candidate) {
            Ok(metadata) => metadata,
            Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(StateError::io(
                    "inspect private state directory",
                    &candidate,
                    source,
                ));
            }
        };
        validate_private_state_directory(&candidate, &metadata)?;
    }
    Ok(Some(candidate))
}

fn validate_required_private_state_directory(path: &Path) -> Result<(), StateError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| StateError::io("inspect private state directory", path, source))?;
    validate_private_state_directory(path, &metadata)
}

fn validate_private_state_directory(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), StateError> {
    validate_private_directory(path, metadata)?;
    evidence::validate_private_directory_acl(path, metadata)
}

fn validate_private_directory(path: &Path, metadata: &fs::Metadata) -> Result<(), StateError> {
    if metadata_is_link_or_reparse(metadata) {
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
        let _created = ensure_private_directory(&candidate)?;
    }
    Ok(())
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;

    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(path)
}

#[cfg(windows)]
fn create_private_directory(path: &Path) -> io::Result<()> {
    windows::create_private_directory(path)
}

#[cfg(windows)]
pub(crate) fn create_private_atomic_file(path: &Path) -> io::Result<File> {
    windows::create_private_file_new(path)
}

#[cfg(not(any(unix, windows)))]
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

fn read_private_state_file(
    root: &Path,
    relative: &Path,
    max_bytes: Option<usize>,
) -> Result<Option<Vec<u8>>, StateError> {
    let Some((path, _path_metadata)) = resolve_existing_private_state_file(root, relative)? else {
        return Ok(None);
    };
    let mut file = match open_private_state_file(&path) {
        Ok(file) => file,
        Err(error) if error.io_kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let metadata = file
        .metadata()
        .map_err(|source| StateError::io("inspect opened private state file", &path, source))?;
    validate_opened_private_state_file(&file, &path, &metadata)?;

    let mut bytes = Vec::new();
    if let Some(max_bytes) = max_bytes {
        if metadata.len() > max_bytes as u64 {
            return Err(StateError::io(
                "read bounded private state file",
                &path,
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "file exceeds its bounded regular-file contract",
                ),
            ));
        }
        Read::by_ref(&mut file)
            .take((max_bytes as u64).saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|source| StateError::io("read bounded private state file", &path, source))?;
        if bytes.len() > max_bytes {
            return Err(StateError::io(
                "read bounded private state file",
                &path,
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "file grew beyond its read limit",
                ),
            ));
        }
    } else {
        file.read_to_end(&mut bytes)
            .map_err(|source| StateError::io("read private state file", &path, source))?;
    }
    let final_metadata = file
        .metadata()
        .map_err(|source| StateError::io("reinspect opened private state file", &path, source))?;
    validate_opened_private_state_file(&file, &path, &final_metadata)?;
    Ok(Some(bytes))
}

fn resolve_existing_private_state_file(
    root: &Path,
    relative: &Path,
) -> Result<Option<(PathBuf, fs::Metadata)>, StateError> {
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));
    if validate_existing_state_directory(root, parent)?.is_none() {
        return Ok(None);
    }
    let path = root.join(relative);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(StateError::io("inspect private state file", &path, source));
        }
    };
    validate_private_state_file(&path, &metadata)?;
    Ok(Some((path, metadata)))
}

fn validate_required_private_state_file(root: &Path, relative: &Path) -> Result<(), StateError> {
    if resolve_existing_private_state_file(root, relative)?.is_some() {
        return Ok(());
    }
    Err(StateError::InvalidLayout {
        path: root.join(relative),
        reason: "private state file disappeared during the operation".to_owned(),
    })
}

fn validate_private_state_file(path: &Path, metadata: &fs::Metadata) -> Result<(), StateError> {
    if metadata_is_link_or_reparse(metadata) {
        return Err(StateError::PathSafety(FileSystemError::SymlinkComponent {
            path: path.to_path_buf(),
        }));
    }
    if !metadata.is_file() {
        return Err(StateError::InvalidLayout {
            path: path.to_path_buf(),
            reason: "private state object is not a regular file".to_owned(),
        });
    }
    validate_private_file_permissions(path, metadata)?;
    evidence::validate_private_file_acl(path, metadata)
}

fn validate_opened_private_state_file(
    file: &File,
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), StateError> {
    if !metadata.is_file() {
        return Err(StateError::InvalidLayout {
            path: path.to_path_buf(),
            reason: "opened private state object is not a regular file".to_owned(),
        });
    }
    validate_private_file_permissions(path, metadata)?;
    evidence::validate_evidence_lock_acl(file, path)
}

#[cfg(unix)]
fn open_private_state_file(path: &Path) -> Result<File, StateError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| {
            StateError::io(
                "open private state file without following links",
                path,
                source,
            )
        })
}

#[cfg(windows)]
fn open_private_state_file(path: &Path) -> Result<File, StateError> {
    windows::open_private_file_read(path).map_err(|source| {
        StateError::io(
            "open private state file without following Windows reparse points",
            path,
            source,
        )
    })
}

#[cfg(not(any(unix, windows)))]
fn open_private_state_file(path: &Path) -> Result<File, StateError> {
    File::open(path).map_err(|source| StateError::io("open private state file", path, source))
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
        if segment.ends_with('.') {
            return Err(StateError::UnsafeKey {
                key: key.to_owned(),
                reason: "segments ending in `.` are forbidden because Win32 aliases them to the name without trailing dots"
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

fn reject_reserved_state_access(key: &str, relative: &Path) -> Result<(), StateError> {
    if !is_reserved_state_path(relative) {
        return Ok(());
    }
    Err(StateError::ReservedStatePath {
        key: key.to_owned(),
    })
}

fn is_reserved_state_path(relative: &Path) -> bool {
    relative.components().next().is_some_and(|component| {
        component.as_os_str().to_str().is_some_and(|segment| {
            ["lock", "receipts", "evidence", "logs"]
                .iter()
                .any(|reserved| segment.eq_ignore_ascii_case(reserved))
        })
    })
}

fn open_private_lock_file(path: &Path) -> Result<File, StateError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_lock_metadata(path, &metadata)?,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            match create_new_lock_file(path) {
                Ok(file) => {
                    evidence::clear_inherited_extended_acl_file(&file, path)?;
                    validate_opened_private_lock_file(&file, path)?;
                    file.sync_all().map_err(|source| {
                        StateError::io("synchronize new state lock", path, source)
                    })?;
                    let parent = path.parent().ok_or_else(|| StateError::InvalidLayout {
                        path: path.to_path_buf(),
                        reason: "state lock has no parent directory".to_owned(),
                    })?;
                    sync_directory(parent)?;
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
    validate_opened_private_lock_file(&file, path)?;
    Ok(file)
}

fn validate_lock_metadata(path: &Path, metadata: &fs::Metadata) -> Result<(), StateError> {
    if metadata_is_link_or_reparse(metadata) {
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
    validate_private_file_permissions(path, metadata)?;
    evidence::validate_private_file_acl(path, metadata)
}

fn validate_opened_private_lock_file(file: &File, path: &Path) -> Result<(), StateError> {
    let metadata = file
        .metadata()
        .map_err(|source| StateError::io("inspect opened state lock", path, source))?;
    if !metadata.is_file() {
        return Err(StateError::InvalidLayout {
            path: path.to_path_buf(),
            reason: "state lock is not a regular file".to_owned(),
        });
    }
    validate_private_file_permissions(path, &metadata)?;
    evidence::validate_evidence_lock_acl(file, path)
}

#[cfg(unix)]
fn lock_file_still_names_path(lock: &StateLock) -> Result<bool, StateError> {
    use std::os::unix::fs::MetadataExt as _;

    let opened = lock
        ._file
        .metadata()
        .map_err(|source| StateError::io("inspect held state lock", &lock.path, source))?;
    let current = match fs::symlink_metadata(&lock.path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(source) => {
            return Err(StateError::io(
                "reinspect held state lock path",
                &lock.path,
                source,
            ));
        }
    };
    validate_lock_metadata(&lock.path, &current)?;
    Ok(opened.dev() == current.dev() && opened.ino() == current.ino())
}

#[cfg(windows)]
fn lock_file_still_names_path(lock: &StateLock) -> Result<bool, StateError> {
    let current = match fs::symlink_metadata(&lock.path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(source) => {
            return Err(StateError::io(
                "reinspect held state lock path",
                &lock.path,
                source,
            ));
        }
    };
    validate_lock_metadata(&lock.path, &current)?;
    windows::file_handle_still_names_path(
        &lock._file,
        &lock.path,
        windows_acl_policy::PrivateWindowsObjectKind::File,
    )
}

#[cfg(not(any(unix, windows)))]
fn lock_file_still_names_path(_lock: &StateLock) -> Result<bool, StateError> {
    Ok(false)
}

#[cfg(unix)]
pub(super) fn sync_directory(path: &Path) -> Result<(), StateError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| StateError::io("synchronize private state directory", path, source))
}

#[cfg(windows)]
pub(super) fn sync_directory(_path: &Path) -> Result<(), StateError> {
    // Windows does not expose a portable directory-fsync equivalent for ordinary directory
    // handles. Immutable Evidence publication separately uses MoveFileExW with
    // MOVEFILE_WRITE_THROUGH after syncing the temporary file; GC remains recoverable by design.
    Ok(())
}

#[cfg(not(any(unix, windows)))]
pub(super) fn sync_directory(_path: &Path) -> Result<(), StateError> {
    Ok(())
}

#[cfg(not(windows))]
fn create_new_lock_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    configure_lock_open_options(&mut options);
    options.open(path)
}

#[cfg(windows)]
fn create_new_lock_file(path: &Path) -> io::Result<File> {
    windows::create_private_file_new(path)
}

#[cfg(not(windows))]
fn open_existing_lock_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    configure_lock_open_options(&mut options);
    options.open(path)
}

#[cfg(windows)]
fn open_existing_lock_file(path: &Path) -> io::Result<File> {
    windows::open_private_file_read_write(path)
}

#[cfg(unix)]
fn configure_lock_open_options(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt as _;

    options.mode(0o600).custom_flags(nix::libc::O_NOFOLLOW);
}

#[cfg(not(any(unix, windows)))]
fn configure_lock_open_options(_options: &mut OpenOptions) {}

fn is_lock_contention(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::WouldBlock
}

#[cfg(windows)]
pub(super) fn metadata_is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;

    metadata.file_type().is_symlink()
        || metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
}

#[cfg(not(windows))]
pub(super) fn metadata_is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fs;
    use std::io;

    use tempfile::tempdir;

    use super::{AtomicStateStore, GitStateLayout, StateError};

    #[cfg(unix)]
    #[test]
    fn generic_operations_reject_a_permissive_state_file_without_repair()
    -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = tempdir()?;
        let git_dir = temporary.path().join("git");
        fs::create_dir(&git_dir)?;
        let layout = GitStateLayout::new(&git_dir, &git_dir);
        let store = AtomicStateStore::new(layout.clone())?;
        let key = "mutable/current.json";
        let path = layout.worktree_dir().join(key);
        store.store_atomic(key, b"private")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;

        assert_private_boundary_error(store.load(key))?;
        assert_private_boundary_error(store.load_bounded(key, 64))?;
        assert_private_boundary_error(store.store_atomic(key, b"replacement"))?;
        assert_private_boundary_error(store.store_new_atomic(key, b"replacement"))?;
        assert_private_boundary_error(store.list_regular_keys_bounded("mutable", 8))?;
        let read_only = AtomicStateStore::open_existing_read_only(layout.clone())?
            .ok_or_else(|| io::Error::other("existing private state root was not opened"))?;
        assert_private_boundary_error(read_only.load(key))?;

        assert_eq!(fs::read(&path)?, b"private");
        assert_eq!(fs::metadata(path)?.permissions().mode() & 0o777, 0o644);

        let directory = layout.worktree_dir().join("mutable");
        let path = directory.join("current.json");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755))?;
        assert_private_boundary_error(store.load(key))?;
        assert_private_boundary_error(store.store_atomic(key, b"replacement"))?;
        assert_private_boundary_error(store.list_regular_keys_bounded("mutable", 8))?;
        assert_eq!(fs::read(path)?, b"private");
        assert_eq!(fs::metadata(directory)?.permissions().mode() & 0o777, 0o755);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn generic_operations_revalidate_the_private_state_root() -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = tempdir()?;
        let git_dir = temporary.path().join("git");
        fs::create_dir(&git_dir)?;
        let layout = GitStateLayout::new(&git_dir, &git_dir);
        let store = AtomicStateStore::new(layout.clone())?;
        store.store_atomic("mutable/current.json", b"private")?;
        fs::set_permissions(layout.worktree_dir(), fs::Permissions::from_mode(0o755))?;

        assert_private_boundary_error(store.load("mutable/current.json"))?;
        assert_private_boundary_error(store.store_atomic("mutable/next.json", b"next"))?;
        assert_private_boundary_error(store.list_regular_keys_bounded("mutable", 8))?;
        assert_private_boundary_error(store.try_lock())?;
        assert!(!layout.worktree_dir().join("mutable/next.json").exists());
        assert!(!layout.lock_file().exists());
        assert_eq!(
            fs::metadata(layout.worktree_dir())?.permissions().mode() & 0o777,
            0o755
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn generic_lock_rejects_a_permissive_existing_file_without_repair() -> Result<(), Box<dyn Error>>
    {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = tempdir()?;
        let git_dir = temporary.path().join("git");
        fs::create_dir(&git_dir)?;
        let layout = GitStateLayout::new(&git_dir, &git_dir);
        let store = AtomicStateStore::new(layout.clone())?;
        drop(store.try_lock()?);
        fs::set_permissions(layout.lock_file(), fs::Permissions::from_mode(0o644))?;

        assert_private_boundary_error(store.try_lock())?;
        assert_eq!(
            fs::metadata(layout.lock_file())?.permissions().mode() & 0o777,
            0o644
        );
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn generic_state_rejects_extended_acls_on_root_file_and_lock_without_repair()
    -> Result<(), Box<dyn Error>> {
        let temporary = tempdir()?;
        let git_dir = temporary.path().join("git");
        fs::create_dir(&git_dir)?;
        let layout = GitStateLayout::new(&git_dir, &git_dir);
        let store = AtomicStateStore::new(layout.clone())?;
        let key = "mutable/current.json";
        let state_path = layout.worktree_dir().join(key);
        store.store_atomic(key, b"private")?;
        drop(store.try_lock()?);

        add_everyone_read_acl(&state_path)?;
        assert_private_boundary_error(store.load(key))?;
        assert_private_boundary_error(store.store_atomic(key, b"replacement"))?;
        assert_private_boundary_error(store.list_regular_keys_bounded("mutable", 8))?;
        assert_eq!(fs::read(&state_path)?, b"private");

        add_everyone_read_acl(&layout.lock_file())?;
        assert_private_boundary_error(store.try_lock())?;

        add_everyone_read_acl(layout.worktree_dir())?;
        assert_private_boundary_error(AtomicStateStore::new(layout.clone()))?;
        assert_private_boundary_error(AtomicStateStore::open_existing_read_only(layout))?;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn add_everyone_read_acl(path: &std::path::Path) -> io::Result<()> {
        let status = std::process::Command::new("/bin/chmod")
            .arg("+a")
            .arg("everyone allow read")
            .arg(path)
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other("failed to install macOS ACL fixture"))
        }
    }

    #[cfg(windows)]
    #[test]
    fn generic_state_rejects_a_null_dacl_without_repair() -> Result<(), Box<dyn Error>> {
        let temporary = tempdir()?;
        let git_dir = temporary.path().join("git");
        fs::create_dir(&git_dir)?;
        let layout = GitStateLayout::new(&git_dir, &git_dir);
        let store = AtomicStateStore::new(layout.clone())?;
        let key = "mutable/current.json";
        let path = layout.worktree_dir().join(key);
        store.store_atomic(key, b"private")?;
        super::windows::set_null_dacl_for_test(&path)?;

        assert_private_boundary_error(store.load(key))?;
        assert_private_boundary_error(store.store_atomic(key, b"replacement"))?;
        assert_private_boundary_error(store.list_regular_keys_bounded("mutable", 8))?;
        assert_eq!(fs::read(path)?, b"private");
        Ok(())
    }

    fn assert_private_boundary_error<T>(result: Result<T, StateError>) -> io::Result<()> {
        match result {
            Err(StateError::InvalidLayout { reason, .. })
                if reason.contains("group or other access")
                    || reason.contains("extended ACL")
                    || reason.contains("DACL") =>
            {
                Ok(())
            }
            Err(other) => Err(io::Error::other(format!("unexpected error: {other}"))),
            Ok(_) => Err(io::Error::other("permissive private state was accepted")),
        }
    }
}
