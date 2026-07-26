//! Native filesystem primitives and repository-confined writes.

use std::fs::{self, File};
use std::io::{self, Write as _};
use std::path::{Component, Path, PathBuf};

use forge_core::ports::FileSystemPort;
use tempfile::NamedTempFile;
use thiserror::Error;

/// The native implementation of [`FileSystemPort`].
///
/// [`NativeFileSystem::write_atomic`] is deliberately a low-level, single-file
/// primitive. Repository targets must go through [`RepositoryWriter`] so path
/// confinement and symlink checks cannot be skipped accidentally.
#[derive(Debug, Default, Clone, Copy)]
pub struct NativeFileSystem;

impl NativeFileSystem {
    pub fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        fs::read(path)
    }

    #[must_use]
    pub fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    /// Replaces one file through a temporary file in the target directory.
    ///
    /// Existing permissions are copied to the replacement. The temporary file
    /// is flushed and synced before the atomic rename. This function does not
    /// provide a multi-file transaction.
    pub fn write_atomic(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        write_atomic_impl(path, bytes, NewFileMode::Default)
    }
}

impl FileSystemPort for NativeFileSystem {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        NativeFileSystem::read(self, path)
    }

    fn write_atomic(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        NativeFileSystem::write_atomic(self, path, bytes)
    }

    fn exists(&self, path: &Path) -> bool {
        NativeFileSystem::exists(self, path)
    }
}

/// A repository-rooted writer that rejects path traversal and symlink writes.
#[derive(Debug, Clone)]
pub struct RepositoryWriter {
    root: PathBuf,
    filesystem: NativeFileSystem,
}

impl RepositoryWriter {
    /// Creates a writer rooted at an existing, real directory.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, FileSystemError> {
        let supplied_root = root.as_ref();
        let metadata = fs::symlink_metadata(supplied_root).map_err(|source| {
            FileSystemError::io("inspect repository root", supplied_root, source)
        })?;
        if metadata.file_type().is_symlink() {
            return Err(FileSystemError::SymlinkComponent {
                path: supplied_root.to_path_buf(),
            });
        }
        if !metadata.is_dir() {
            return Err(FileSystemError::RootNotDirectory {
                path: supplied_root.to_path_buf(),
            });
        }

        let root = fs::canonicalize(supplied_root).map_err(|source| {
            FileSystemError::io("canonicalize repository root", supplied_root, source)
        })?;
        Ok(Self {
            root,
            filesystem: NativeFileSystem,
        })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn read(&self, relative_path: impl AsRef<Path>) -> Result<Vec<u8>, FileSystemError> {
        let target = self.checked_target(relative_path.as_ref())?;
        self.filesystem
            .read(&target)
            .map_err(|source| FileSystemError::io("read repository file", &target, source))
    }

    pub fn exists(&self, relative_path: impl AsRef<Path>) -> Result<bool, FileSystemError> {
        let target = self.checked_target(relative_path.as_ref())?;
        match fs::symlink_metadata(&target) {
            Ok(_) => Ok(true),
            Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(source) => Err(FileSystemError::io(
                "inspect repository target",
                &target,
                source,
            )),
        }
    }

    /// Atomically writes one repository-relative file after validating the path
    /// both before parent creation and immediately before the write.
    pub fn write_atomic(
        &self,
        relative_path: impl AsRef<Path>,
        bytes: &[u8],
    ) -> Result<(), FileSystemError> {
        self.write_atomic_with_mode(relative_path.as_ref(), bytes, NewFileMode::Default)
    }

    pub(crate) fn write_atomic_private(
        &self,
        relative_path: impl AsRef<Path>,
        bytes: &[u8],
    ) -> Result<(), FileSystemError> {
        self.write_atomic_with_mode(relative_path.as_ref(), bytes, NewFileMode::Private)
    }

    fn write_atomic_with_mode(
        &self,
        relative_path: &Path,
        bytes: &[u8],
        new_file_mode: NewFileMode,
    ) -> Result<(), FileSystemError> {
        let normalized = normalize_relative_path(relative_path)?;
        self.validate_target(&normalized)?;
        self.create_parent_directories(&normalized)?;

        // Recheck after directory creation and immediately before the write so
        // a pre-existing path conflict cannot be hidden by the create phase.
        let target = self.validate_target(&normalized)?;
        write_atomic_impl_with_recheck(&target, bytes, new_file_mode, || {
            self.validate_target(&normalized)
                .map(|_| ())
                .map_err(FileSystemError::into_io_error)
        })
        .map_err(|source| FileSystemError::io("atomically write repository file", target, source))
    }

    fn checked_target(&self, relative_path: &Path) -> Result<PathBuf, FileSystemError> {
        let normalized = normalize_relative_path(relative_path)?;
        self.validate_target(&normalized)
    }

    fn validate_target(&self, normalized: &Path) -> Result<PathBuf, FileSystemError> {
        self.validate_root_is_unchanged()?;

        let target = self.root.join(normalized);
        if !target.starts_with(&self.root) {
            return Err(FileSystemError::OutsideRoot {
                root: self.root.clone(),
                path: target,
            });
        }

        let mut candidate = self.root.clone();
        let component_count = normalized.components().count();
        for (index, component) in normalized.components().enumerate() {
            let Component::Normal(segment) = component else {
                return Err(FileSystemError::InvalidRelativePath {
                    path: normalized.to_path_buf(),
                    reason: "path was not normalized".to_owned(),
                });
            };
            candidate.push(segment);
            let is_target = index + 1 == component_count;
            match fs::symlink_metadata(&candidate) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink() {
                        return Err(FileSystemError::SymlinkComponent { path: candidate });
                    }
                    if is_target && !metadata.is_file() {
                        return Err(FileSystemError::TargetNotRegular { path: candidate });
                    }
                    if !is_target && !metadata.is_dir() {
                        return Err(FileSystemError::AncestorNotDirectory { path: candidate });
                    }
                }
                Err(source) if source.kind() == io::ErrorKind::NotFound => break,
                Err(source) => {
                    return Err(FileSystemError::io(
                        "inspect repository path component",
                        candidate,
                        source,
                    ));
                }
            }
        }

        self.validate_canonical_confinement(&target)?;
        Ok(target)
    }

    fn validate_root_is_unchanged(&self) -> Result<(), FileSystemError> {
        let metadata = fs::symlink_metadata(&self.root)
            .map_err(|source| FileSystemError::io("recheck repository root", &self.root, source))?;
        if metadata.file_type().is_symlink() {
            return Err(FileSystemError::SymlinkComponent {
                path: self.root.clone(),
            });
        }
        if !metadata.is_dir() {
            return Err(FileSystemError::RootNotDirectory {
                path: self.root.clone(),
            });
        }

        let current = fs::canonicalize(&self.root).map_err(|source| {
            FileSystemError::io("re-canonicalize repository root", &self.root, source)
        })?;
        if current != self.root {
            return Err(FileSystemError::OutsideRoot {
                root: self.root.clone(),
                path: current,
            });
        }
        Ok(())
    }

    fn validate_canonical_confinement(&self, target: &Path) -> Result<(), FileSystemError> {
        let mut existing = target;
        loop {
            match fs::canonicalize(existing) {
                Ok(canonical) => {
                    if canonical.starts_with(&self.root) {
                        return Ok(());
                    }
                    return Err(FileSystemError::OutsideRoot {
                        root: self.root.clone(),
                        path: canonical,
                    });
                }
                Err(source) if source.kind() == io::ErrorKind::NotFound => {
                    existing = existing
                        .parent()
                        .ok_or_else(|| FileSystemError::OutsideRoot {
                            root: self.root.clone(),
                            path: target.to_path_buf(),
                        })?;
                }
                Err(source) => {
                    return Err(FileSystemError::io(
                        "canonicalize repository target",
                        existing,
                        source,
                    ));
                }
            }
        }
    }

    fn create_parent_directories(&self, normalized: &Path) -> Result<(), FileSystemError> {
        let Some(parent) = normalized.parent() else {
            return Ok(());
        };
        let mut candidate = self.root.clone();
        for component in parent.components() {
            let Component::Normal(segment) = component else {
                return Err(FileSystemError::InvalidRelativePath {
                    path: normalized.to_path_buf(),
                    reason: "parent path was not normalized".to_owned(),
                });
            };
            candidate.push(segment);
            match fs::create_dir(&candidate) {
                Ok(()) => {}
                Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => {
                    return Err(FileSystemError::io(
                        "create repository directory",
                        candidate,
                        source,
                    ));
                }
            }

            let metadata = fs::symlink_metadata(&candidate).map_err(|source| {
                FileSystemError::io("verify repository directory", &candidate, source)
            })?;
            if metadata.file_type().is_symlink() {
                return Err(FileSystemError::SymlinkComponent { path: candidate });
            }
            if !metadata.is_dir() {
                return Err(FileSystemError::AncestorNotDirectory { path: candidate });
            }
        }
        Ok(())
    }
}

/// A failure to confine a filesystem operation to its intended root.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FileSystemError {
    #[error("filesystem operation `{operation}` failed for `{path}`: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("repository root is not a directory: `{path}`")]
    RootNotDirectory { path: PathBuf },
    #[error("repository-relative path `{path}` is unsafe: {reason}")]
    InvalidRelativePath { path: PathBuf, reason: String },
    #[error("path component is a symbolic link: `{path}`")]
    SymlinkComponent { path: PathBuf },
    #[error("path ancestor is not a directory: `{path}`")]
    AncestorNotDirectory { path: PathBuf },
    #[error("existing write target is not a regular file: `{path}`")]
    TargetNotRegular { path: PathBuf },
    #[error("path `{path}` escapes repository root `{root}`")]
    OutsideRoot { root: PathBuf, path: PathBuf },
}

impl FileSystemError {
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
            Self::Io { source, .. } => source.kind(),
            Self::InvalidRelativePath { .. } => io::ErrorKind::InvalidInput,
            Self::RootNotDirectory { .. }
            | Self::SymlinkComponent { .. }
            | Self::AncestorNotDirectory { .. }
            | Self::TargetNotRegular { .. }
            | Self::OutsideRoot { .. } => io::ErrorKind::PermissionDenied,
        }
    }

    pub fn into_io_error(self) -> io::Error {
        io::Error::new(self.io_kind(), self)
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum NewFileMode {
    Default,
    Private,
}

fn normalize_relative_path(path: &Path) -> Result<PathBuf, FileSystemError> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(segment) => normalized.push(segment),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(FileSystemError::InvalidRelativePath {
                    path: path.to_path_buf(),
                    reason: "parent traversal (`..`) is forbidden".to_owned(),
                });
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(FileSystemError::InvalidRelativePath {
                    path: path.to_path_buf(),
                    reason: "absolute paths are forbidden".to_owned(),
                });
            }
        }
    }
    if normalized.as_os_str().is_empty() {
        return Err(FileSystemError::InvalidRelativePath {
            path: path.to_path_buf(),
            reason: "a file path is required".to_owned(),
        });
    }
    Ok(normalized)
}

fn write_atomic_impl(path: &Path, bytes: &[u8], new_file_mode: NewFileMode) -> io::Result<()> {
    write_atomic_impl_with_recheck(path, bytes, new_file_mode, || Ok(()))
}

fn write_atomic_impl_with_recheck(
    path: &Path,
    bytes: &[u8],
    new_file_mode: NewFileMode,
    recheck_before_rename: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("atomic write target has no parent: `{}`", path.display()),
        )
    })?;
    let existing_permissions = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => Some(metadata.permissions()),
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "atomic write target is not a regular file: `{}`",
                    path.display()
                ),
            ));
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => None,
        Err(source) => return Err(source),
    };

    let mut temporary = new_atomic_temporary_file(parent, new_file_mode)?;
    temporary.as_file_mut().write_all(bytes)?;
    temporary.as_file_mut().flush()?;

    if let Some(permissions) = existing_permissions {
        temporary.as_file().set_permissions(permissions)?;
    }
    temporary.as_file().sync_all()?;

    recheck_before_rename()?;
    temporary
        .persist(path)
        .map(|_| ())
        .map_err(|error| error.error)?;
    sync_parent_directory(parent)
}

#[cfg(unix)]
fn new_atomic_temporary_file(parent: &Path, mode: NewFileMode) -> io::Result<NamedTempFile> {
    use std::os::unix::fs::PermissionsExt as _;

    let mode = match mode {
        // 0666 lets the caller's umask choose stricter ordinary-file
        // permissions while ensuring generated files are never executable.
        NewFileMode::Default => 0o666,
        NewFileMode::Private => 0o600,
    };
    tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(mode))
        .tempfile_in(parent)
}

#[cfg(not(unix))]
fn new_atomic_temporary_file(parent: &Path, _mode: NewFileMode) -> io::Result<NamedTempFile> {
    NamedTempFile::new_in(parent)
}

#[cfg(unix)]
fn sync_parent_directory(parent: &Path) -> io::Result<()> {
    File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent_directory(_parent: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fs;
    use std::path::Path;

    use tempfile::tempdir;

    use super::{FileSystemError, NativeFileSystem, RepositoryWriter};

    #[test]
    fn native_filesystem_reads_and_replaces_atomically() -> Result<(), Box<dyn Error>> {
        let temporary = tempdir()?;
        let target = temporary.path().join("model.json");
        fs::write(&target, b"old")?;

        let filesystem = NativeFileSystem;
        filesystem.write_atomic(&target, b"new")?;

        assert!(filesystem.exists(&target));
        assert_eq!(filesystem.read(&target)?, b"new");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn atomic_replace_preserves_existing_permissions() -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = tempdir()?;
        let target = temporary.path().join("executable.sh");
        fs::write(&target, b"old")?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o750))?;

        NativeFileSystem.write_atomic(&target, b"new")?;

        assert_eq!(fs::metadata(&target)?.permissions().mode() & 0o777, 0o750);
        assert_eq!(fs::read(&target)?, b"new");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn new_repository_file_uses_normal_project_permissions() -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::PermissionsExt as _;

        let repository = tempdir()?;
        let writer = RepositoryWriter::new(repository.path())?;

        writer.write_atomic("AGENTS.md", b"project guidance")?;

        let mode = fs::metadata(repository.path().join("AGENTS.md"))?
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode & 0o111, 0);
        assert_eq!(mode & !0o644, 0);
        Ok(())
    }

    #[test]
    fn repository_writer_rejects_lexical_escapes() -> Result<(), Box<dyn Error>> {
        let temporary = tempdir()?;
        let writer = RepositoryWriter::new(temporary.path())?;

        let parent_error = writer.write_atomic(Path::new("../outside"), b"unsafe");
        assert!(matches!(
            parent_error,
            Err(FileSystemError::InvalidRelativePath { .. })
        ));

        let absolute_error = writer.write_atomic(temporary.path().join("absolute"), b"unsafe");
        assert!(matches!(
            absolute_error,
            Err(FileSystemError::InvalidRelativePath { .. })
        ));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn repository_writer_rejects_symlink_escape() -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::symlink;

        let repository = tempdir()?;
        let outside = tempdir()?;
        symlink(outside.path(), repository.path().join("linked"))?;
        let writer = RepositoryWriter::new(repository.path())?;

        let result = writer.write_atomic("linked/escape.txt", b"unsafe");

        assert!(matches!(
            result,
            Err(FileSystemError::SymlinkComponent { .. })
        ));
        assert!(!outside.path().join("escape.txt").exists());
        Ok(())
    }

    #[test]
    fn repository_writer_rejects_non_regular_existing_target() -> Result<(), Box<dyn Error>> {
        let repository = tempdir()?;
        fs::create_dir(repository.path().join("target"))?;
        let writer = RepositoryWriter::new(repository.path())?;

        let result = writer.write_atomic("target", b"unsafe");

        assert!(matches!(
            result,
            Err(FileSystemError::TargetNotRegular { .. })
        ));
        Ok(())
    }
}
