//! Native filesystem primitives and repository-confined writes.

use std::fs::{self, File};
use std::io::{self, Read as _, Write as _};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use forge_core::ports::{
    FileSystemPort, RepositoryApplyPort, RepositoryFilePort, RepositoryWriteError,
    RepositoryWriteOutcome,
};
use forge_core::{
    BoundedText, GitFileSet, Inventory, InventoryError, InventoryOptions, OperationControl,
    PathKind, PathMetadata, RepoRelativePath, UnlimitedOperationControl,
};
use tempfile::NamedTempFile;
use thiserror::Error;

use crate::inventory::{
    build_inventory_from_git_file_set_controlled, build_non_git_filesystem_inventory_controlled,
    read_bounded_text_controlled as read_repository_bounded_text_controlled,
};
use crate::repository_write::{CommitMode, RootHandle};

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

    pub fn inventory(
        &self,
        root: &Path,
        file_set: Option<&GitFileSet>,
        options: InventoryOptions,
    ) -> Result<Inventory, InventoryError> {
        self.inventory_controlled(root, file_set, options, &UnlimitedOperationControl)
    }

    pub fn inventory_controlled(
        &self,
        root: &Path,
        file_set: Option<&GitFileSet>,
        options: InventoryOptions,
        control: &dyn OperationControl,
    ) -> Result<Inventory, InventoryError> {
        match file_set {
            Some(file_set) => {
                build_inventory_from_git_file_set_controlled(root, file_set, options, control)
            }
            None => build_non_git_filesystem_inventory_controlled(root, options, control),
        }
    }

    pub fn read_bounded_text(
        &self,
        root: &Path,
        path: &RepoRelativePath,
        max_text_file_bytes: u64,
    ) -> Result<BoundedText, InventoryError> {
        self.read_bounded_text_controlled(
            root,
            path,
            max_text_file_bytes,
            &UnlimitedOperationControl,
        )
    }

    pub fn read_bounded_text_controlled(
        &self,
        root: &Path,
        path: &RepoRelativePath,
        max_text_file_bytes: u64,
        control: &dyn OperationControl,
    ) -> Result<BoundedText, InventoryError> {
        read_repository_bounded_text_controlled(root, path, max_text_file_bytes, control)
    }

    /// Inspects one path without following the target or any symbolic-link ancestor.
    pub fn path_kind(&self, root: &Path, path: &RepoRelativePath) -> io::Result<PathKind> {
        self.path_metadata(root, path).map(|metadata| metadata.kind)
    }

    /// Atomically inspects one path's kind and size without following symbolic links.
    pub fn path_metadata(&self, root: &Path, path: &RepoRelativePath) -> io::Result<PathMetadata> {
        path_metadata(root, path)
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

    fn inventory(
        &self,
        root: &Path,
        file_set: Option<&GitFileSet>,
        options: InventoryOptions,
    ) -> Result<Inventory, InventoryError> {
        NativeFileSystem::inventory(self, root, file_set, options)
    }

    fn inventory_controlled(
        &self,
        root: &Path,
        file_set: Option<&GitFileSet>,
        options: InventoryOptions,
        control: &dyn OperationControl,
    ) -> Result<Inventory, InventoryError> {
        NativeFileSystem::inventory_controlled(self, root, file_set, options, control)
    }

    fn read_bounded_text(
        &self,
        root: &Path,
        path: &RepoRelativePath,
        max_text_file_bytes: u64,
    ) -> Result<BoundedText, InventoryError> {
        NativeFileSystem::read_bounded_text(self, root, path, max_text_file_bytes)
    }

    fn read_bounded_text_controlled(
        &self,
        root: &Path,
        path: &RepoRelativePath,
        max_text_file_bytes: u64,
        control: &dyn OperationControl,
    ) -> Result<BoundedText, InventoryError> {
        NativeFileSystem::read_bounded_text_controlled(
            self,
            root,
            path,
            max_text_file_bytes,
            control,
        )
    }

    fn path_kind(&self, root: &Path, path: &RepoRelativePath) -> io::Result<PathKind> {
        NativeFileSystem::path_kind(self, root, path)
    }

    fn path_metadata(&self, root: &Path, path: &RepoRelativePath) -> io::Result<PathMetadata> {
        NativeFileSystem::path_metadata(self, root, path)
    }

    fn write_atomic(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        NativeFileSystem::write_atomic(self, path, bytes)
    }

    fn exists(&self, path: &Path) -> bool {
        NativeFileSystem::exists(self, path)
    }
}

impl RepositoryFilePort for NativeFileSystem {
    fn read_confined(
        &self,
        repository_root: &Path,
        path: &RepoRelativePath,
    ) -> io::Result<Option<Vec<u8>>> {
        let writer =
            RepositoryWriter::new(repository_root).map_err(FileSystemError::into_io_error)?;
        match writer.read(path.as_path()) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(FileSystemError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                Ok(None)
            }
            Err(error) => Err(error.into_io_error()),
        }
    }

    fn read_confined_bounded(
        &self,
        repository_root: &Path,
        path: &RepoRelativePath,
        max_bytes: usize,
    ) -> io::Result<Option<Vec<u8>>> {
        let writer =
            RepositoryWriter::new(repository_root).map_err(FileSystemError::into_io_error)?;
        match writer.read_bounded(path.as_path(), max_bytes) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(FileSystemError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                Ok(None)
            }
            Err(error) => Err(error.into_io_error()),
        }
    }

    fn write_atomic_confined(
        &self,
        repository_root: &Path,
        path: &RepoRelativePath,
        bytes: &[u8],
    ) -> io::Result<()> {
        RepositoryWriter::new(repository_root)
            .map_err(FileSystemError::into_io_error)?
            .write_atomic(path.as_path(), bytes)
            .map_err(FileSystemError::into_io_error)
    }
}

fn path_metadata(root: &Path, relative: &RepoRelativePath) -> io::Result<PathMetadata> {
    let root_metadata = fs::symlink_metadata(root).map_err(|source| {
        FileSystemError::io("inspect repository root", root, source).into_io_error()
    })?;
    if root_metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("repository root is a symbolic link: `{}`", root.display()),
        ));
    }
    if !root_metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            format!("repository root is not a directory: `{}`", root.display()),
        ));
    }

    let mut current = root.to_path_buf();
    let mut components = relative.as_path().components().peekable();
    while let Some(component) = components.next() {
        if component == Component::CurDir {
            continue;
        }
        current.push(component.as_os_str());
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                return Ok(PathMetadata::missing());
            }
            Err(source) => {
                return Err(
                    FileSystemError::io("inspect repository path", &current, source)
                        .into_io_error(),
                );
            }
        };
        let is_target = components.peek().is_none();
        if metadata.file_type().is_symlink() {
            if is_target {
                return Ok(PathMetadata::present(PathKind::Symlink, metadata.len()));
            }
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "repository-relative path points through a symbolic link: `{}`",
                    current.display()
                ),
            ));
        }
        if !is_target && !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                format!(
                    "repository-relative path ancestor is not a directory: `{}`",
                    current.display()
                ),
            ));
        }
        if is_target {
            return Ok(PathMetadata::present(
                metadata_path_kind(&metadata),
                metadata.len(),
            ));
        }
    }

    Ok(PathMetadata::present(
        PathKind::Directory,
        root_metadata.len(),
    ))
}

fn metadata_path_kind(metadata: &fs::Metadata) -> PathKind {
    let file_type = metadata.file_type();
    if file_type.is_dir() {
        PathKind::Directory
    } else if file_type.is_file() {
        PathKind::File
    } else if file_type.is_symlink() {
        PathKind::Symlink
    } else {
        PathKind::Other
    }
}

/// A repository-rooted writer that rejects path traversal and symlink writes.
#[derive(Debug, Clone)]
pub struct RepositoryWriter {
    root: PathBuf,
    filesystem: NativeFileSystem,
    write_root: Arc<RootHandle>,
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
        let write_root = RootHandle::open(&root)
            .map_err(|source| FileSystemError::io("open repository root handle", &root, source))?;
        Ok(Self {
            root,
            filesystem: NativeFileSystem,
            write_root: Arc::new(write_root),
        })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Verifies that the visible root path still names the pinned directory identity.
    pub fn validate_visible_root(&self) -> Result<(), FileSystemError> {
        self.write_root.validate_visible_root().map_err(|source| {
            FileSystemError::io(
                "validate visible repository root identity",
                &self.root,
                source,
            )
        })
    }

    pub fn read(&self, relative_path: impl AsRef<Path>) -> Result<Vec<u8>, FileSystemError> {
        let target = self.checked_target(relative_path.as_ref())?;
        self.filesystem
            .read(&target)
            .map_err(|source| FileSystemError::io("read repository file", &target, source))
    }

    /// Reads a confined regular file while retaining at most `max_bytes`.
    pub fn read_bounded(
        &self,
        relative_path: impl AsRef<Path>,
        max_bytes: usize,
    ) -> Result<Vec<u8>, FileSystemError> {
        let target = self.checked_target(relative_path.as_ref())?;
        read_file_bounded(&target, max_bytes)
            .map_err(|source| FileSystemError::io("read bounded repository file", &target, source))
    }

    /// Reads an optional regular file through this writer's pinned root handle.
    pub fn read_optional_bounded(
        &self,
        relative_path: impl AsRef<Path>,
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, FileSystemError> {
        let normalized = normalize_relative_path(relative_path.as_ref())?;
        let target = self.root.join(&normalized);
        self.write_root
            .read_bounded(&normalized, max_bytes)
            .map_err(|source| {
                FileSystemError::io(
                    "read bounded repository file through root handle",
                    target,
                    source,
                )
            })
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

    /// Atomically creates one ordinary repository file without replacing an existing target.
    pub fn write_atomic_new(
        &self,
        relative_path: impl AsRef<Path>,
        bytes: &[u8],
    ) -> Result<(), FileSystemError> {
        self.write_atomic_new_with_mode(relative_path.as_ref(), bytes, NewFileMode::Default)
    }

    pub(crate) fn write_atomic_private(
        &self,
        relative_path: impl AsRef<Path>,
        bytes: &[u8],
    ) -> Result<(), FileSystemError> {
        self.write_atomic_with_mode(relative_path.as_ref(), bytes, NewFileMode::Private)
    }

    /// Atomically creates one private file without replacing an existing identity.
    pub(crate) fn write_atomic_private_new(
        &self,
        relative_path: impl AsRef<Path>,
        bytes: &[u8],
    ) -> Result<(), FileSystemError> {
        self.write_atomic_new_with_mode(relative_path.as_ref(), bytes, NewFileMode::Private)
    }

    fn write_atomic_new_with_mode(
        &self,
        relative_path: &Path,
        bytes: &[u8],
        new_file_mode: NewFileMode,
    ) -> Result<(), FileSystemError> {
        let normalized = normalize_relative_path(relative_path)?;
        let target = self.root.join(&normalized);
        self.write_root
            .write_atomic(
                &normalized,
                bytes,
                new_file_mode,
                CommitMode::CreateNew,
                || Ok(()),
            )
            .map_err(|source| {
                FileSystemError::io("atomically create repository file", target, source)
            })
    }

    fn write_atomic_with_mode(
        &self,
        relative_path: &Path,
        bytes: &[u8],
        new_file_mode: NewFileMode,
    ) -> Result<(), FileSystemError> {
        self.write_atomic_with_mode_and_hook(relative_path, bytes, new_file_mode, || Ok(()))
    }

    fn write_atomic_with_mode_and_hook(
        &self,
        relative_path: &Path,
        bytes: &[u8],
        new_file_mode: NewFileMode,
        before_commit: impl FnOnce() -> io::Result<()>,
    ) -> Result<(), FileSystemError> {
        let normalized = normalize_relative_path(relative_path)?;
        let target = self.root.join(&normalized);
        self.write_root
            .write_atomic(
                &normalized,
                bytes,
                new_file_mode,
                CommitMode::Replace,
                before_commit,
            )
            .map_err(|source| {
                FileSystemError::io("atomically write repository file", target, source)
            })
    }

    #[cfg(test)]
    fn write_atomic_with_before_commit(
        &self,
        relative_path: &Path,
        bytes: &[u8],
        before_commit: impl FnOnce() -> io::Result<()>,
    ) -> Result<(), FileSystemError> {
        self.write_atomic_with_mode_and_hook(
            relative_path,
            bytes,
            NewFileMode::Default,
            before_commit,
        )
    }

    #[cfg(test)]
    fn write_atomic_if_unchanged_with_hook(
        &self,
        relative_path: &Path,
        expected: Option<&[u8]>,
        bytes: &[u8],
        max_postimage_bytes: usize,
        hook: impl FnMut(crate::repository_write::WriteEvent) -> io::Result<()>,
    ) -> Result<RepositoryWriteOutcome, RepositoryWriteError> {
        let normalized = normalize_relative_path(relative_path).map_err(|error| {
            RepositoryWriteError::new(
                forge_core::ports::RepositoryWriteCommit::NotCommitted,
                error.into_io_error(),
            )
        })?;
        self.write_root.write_atomic_if_unchanged_with_hook(
            &normalized,
            expected,
            bytes,
            max_postimage_bytes,
            hook,
        )
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
}

impl RepositoryApplyPort for RepositoryWriter {
    fn read_confined_bounded(
        &self,
        path: &RepoRelativePath,
        max_bytes: usize,
    ) -> io::Result<Option<Vec<u8>>> {
        self.read_optional_bounded(path.as_path(), max_bytes)
            .map_err(FileSystemError::into_io_error)
    }

    fn write_atomic_if_unchanged(
        &self,
        path: &RepoRelativePath,
        expected: Option<&[u8]>,
        bytes: &[u8],
        max_postimage_bytes: usize,
    ) -> Result<RepositoryWriteOutcome, RepositoryWriteError> {
        let normalized = normalize_relative_path(path.as_path()).map_err(|error| {
            RepositoryWriteError::new(
                forge_core::ports::RepositoryWriteCommit::NotCommitted,
                error.into_io_error(),
            )
        })?;
        self.write_root
            .write_atomic_if_unchanged(&normalized, expected, bytes, max_postimage_bytes)
    }
}

fn read_file_bounded(path: &Path, max_bytes: usize) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > max_bytes as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file exceeds its bounded regular-file contract",
        ));
    }
    let capacity = usize::try_from(metadata.len()).map_or(max_bytes, |bytes| bytes.min(max_bytes));
    let mut bytes = Vec::with_capacity(capacity);
    file.take((max_bytes as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file grew beyond its read limit",
        ));
    }
    Ok(bytes)
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
        Ok(metadata) if metadata.is_file() => match new_file_mode {
            NewFileMode::Default => Some(metadata.permissions()),
            // Private replacements must be newly owner-private. Inheriting the target's mode
            // would preserve a pre-existing disclosure boundary even though the bytes were
            // written through a private API.
            NewFileMode::Private => None,
        },
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

#[cfg(windows)]
fn new_atomic_temporary_file(parent: &Path, mode: NewFileMode) -> io::Result<NamedTempFile> {
    match mode {
        NewFileMode::Default => NamedTempFile::new_in(parent),
        NewFileMode::Private => tempfile::Builder::new()
            .prefix(".forge-private-")
            .make_in(parent, crate::state::create_private_atomic_file),
    }
}

#[cfg(not(any(unix, windows)))]
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
    use std::io;
    use std::path::Path;

    use forge_core::ports::{
        FileSystemPort, RepositoryFilePort, RepositoryWriteCommit, RepositoryWriteOutcome,
    };
    use forge_core::{GitFileSet, InventoryOptions, PathKind, PathMetadata, RepoRelativePath};
    use tempfile::tempdir;

    use super::{FileSystemError, NativeFileSystem, RepositoryWriter};
    use crate::repository_write::WriteEvent;

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

    #[test]
    fn repository_file_port_distinguishes_missing_and_round_trips_content()
    -> Result<(), Box<dyn Error>> {
        let repository = tempdir()?;
        let filesystem = NativeFileSystem;
        let path = RepoRelativePath::new("nested/AGENTS.md")?;

        assert_eq!(
            RepositoryFilePort::read_confined(&filesystem, repository.path(), &path)?,
            None
        );
        RepositoryFilePort::write_atomic_confined(
            &filesystem,
            repository.path(),
            &path,
            b"project guidance",
        )?;
        assert_eq!(
            RepositoryFilePort::read_confined(&filesystem, repository.path(), &path)?,
            Some(b"project guidance".to_vec())
        );
        Ok(())
    }

    #[test]
    fn repository_file_port_enforces_the_bounded_read_contract() -> Result<(), Box<dyn Error>> {
        let repository = tempdir()?;
        let filesystem = NativeFileSystem;
        let path = RepoRelativePath::new("AGENTS.md")?;
        fs::write(repository.path().join("AGENTS.md"), b"12345")?;

        assert_eq!(
            RepositoryFilePort::read_confined_bounded(&filesystem, repository.path(), &path, 5,)?,
            Some(b"12345".to_vec())
        );
        let oversized =
            RepositoryFilePort::read_confined_bounded(&filesystem, repository.path(), &path, 4);
        assert!(matches!(
            oversized,
            Err(ref error) if error.kind() == io::ErrorKind::InvalidData
        ));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn repository_file_port_rejects_symlink_reads_and_writes() -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::symlink;

        let repository = tempdir()?;
        let outside = tempdir()?;
        fs::write(outside.path().join("secret"), b"secret")?;
        symlink(outside.path(), repository.path().join("linked"))?;
        let filesystem = NativeFileSystem;
        let path = RepoRelativePath::new("linked/secret")?;

        let read = RepositoryFilePort::read_confined(&filesystem, repository.path(), &path);
        let write = RepositoryFilePort::write_atomic_confined(
            &filesystem,
            repository.path(),
            &path,
            b"replacement",
        );

        assert!(matches!(
            read,
            Err(ref error) if error.kind() == io::ErrorKind::PermissionDenied
        ));
        assert!(matches!(
            write,
            Err(ref error) if error.kind() == io::ErrorKind::PermissionDenied
        ));
        assert_eq!(fs::read(outside.path().join("secret"))?, b"secret");
        Ok(())
    }

    #[test]
    fn filesystem_port_exposes_git_authoritative_inventory_and_bounded_text()
    -> Result<(), Box<dyn Error>> {
        let repository = tempdir()?;
        fs::create_dir(repository.path().join("target"))?;
        fs::write(repository.path().join("target/tracked.txt"), "tracked")?;
        fs::write(repository.path().join(".ignore"), "ignored.txt\n")?;
        fs::write(repository.path().join("ignored.txt"), "ignored")?;
        let file_set = GitFileSet::new(
            vec![
                RepoRelativePath::new(".ignore")?,
                RepoRelativePath::new("target/tracked.txt")?,
            ],
            vec![RepoRelativePath::new("ignored.txt")?],
        );
        let filesystem = NativeFileSystem;

        let inventory = FileSystemPort::inventory(
            &filesystem,
            repository.path(),
            Some(&file_set),
            InventoryOptions::default(),
        )?;
        let paths: Vec<_> = inventory
            .entries
            .iter()
            .map(|entry| entry.path.as_path())
            .collect();
        assert!(paths.contains(&Path::new("target/tracked.txt")));
        assert!(!paths.contains(&Path::new("ignored.txt")));

        let non_git_inventory = FileSystemPort::inventory(
            &filesystem,
            repository.path(),
            None,
            InventoryOptions::default(),
        )?;
        assert!(
            !non_git_inventory
                .entries
                .iter()
                .any(|entry| entry.path.starts_with("target"))
        );

        let text = FileSystemPort::read_bounded_text(
            &filesystem,
            repository.path(),
            &RepoRelativePath::new(".ignore")?,
            7,
        )?;
        assert_eq!(text.bytes, b"ignored");
        assert!(text.truncated);
        assert!(!text.binary);
        Ok(())
    }

    #[test]
    fn path_kind_distinguishes_missing_from_probe_failures() -> Result<(), Box<dyn Error>> {
        let repository = tempdir()?;
        fs::write(repository.path().join("file"), "contents")?;
        fs::create_dir(repository.path().join("directory"))?;
        let filesystem = NativeFileSystem;

        assert_eq!(
            FileSystemPort::path_kind(
                &filesystem,
                repository.path(),
                &RepoRelativePath::new("missing")?,
            )?,
            PathKind::Missing
        );
        assert_eq!(
            FileSystemPort::path_kind(
                &filesystem,
                repository.path(),
                &RepoRelativePath::new("file")?,
            )?,
            PathKind::File
        );
        assert_eq!(
            FileSystemPort::path_kind(
                &filesystem,
                repository.path(),
                &RepoRelativePath::new("directory")?,
            )?,
            PathKind::Directory
        );
        assert_eq!(
            FileSystemPort::path_metadata(
                &filesystem,
                repository.path(),
                &RepoRelativePath::new("missing")?,
            )?,
            PathMetadata::missing()
        );
        assert_eq!(
            FileSystemPort::path_metadata(
                &filesystem,
                repository.path(),
                &RepoRelativePath::new("file")?,
            )?,
            PathMetadata::present(PathKind::File, 8)
        );

        let invalid_ancestor = FileSystemPort::path_kind(
            &filesystem,
            repository.path(),
            &RepoRelativePath::new("file/child")?,
        );
        assert!(matches!(
            invalid_ancestor,
            Err(ref error) if error.kind() == std::io::ErrorKind::NotADirectory
        ));

        let missing_root = FileSystemPort::path_kind(
            &filesystem,
            &repository.path().join("missing-root"),
            &RepoRelativePath::new("marker")?,
        );
        assert!(matches!(
            missing_root,
            Err(ref error) if error.kind() == std::io::ErrorKind::NotFound
        ));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn path_kind_reports_a_target_symlink_but_rejects_a_symlink_ancestor()
    -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::symlink;

        let repository = tempdir()?;
        let outside = tempdir()?;
        fs::write(outside.path().join("secret"), "secret")?;
        symlink(outside.path(), repository.path().join("link"))?;
        let filesystem = NativeFileSystem;

        assert_eq!(
            FileSystemPort::path_kind(
                &filesystem,
                repository.path(),
                &RepoRelativePath::new("link")?,
            )?,
            PathKind::Symlink
        );
        let through_link = FileSystemPort::path_kind(
            &filesystem,
            repository.path(),
            &RepoRelativePath::new("link/secret")?,
        );
        assert!(matches!(
            through_link,
            Err(ref error) if error.kind() == std::io::ErrorKind::PermissionDenied
        ));
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
    fn repository_writer_replace_preserves_existing_permissions() -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::PermissionsExt as _;

        let repository = tempdir()?;
        let target = repository.path().join("executable.sh");
        fs::write(&target, b"old")?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o750))?;
        let writer = RepositoryWriter::new(repository.path())?;

        writer.write_atomic("executable.sh", b"new")?;

        assert_eq!(fs::read(&target)?, b"new");
        assert_eq!(fs::metadata(&target)?.permissions().mode() & 0o777, 0o750);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn private_atomic_replace_does_not_inherit_permissive_permissions() -> Result<(), Box<dyn Error>>
    {
        use std::os::unix::fs::PermissionsExt as _;

        let repository = tempdir()?;
        let target = repository.path().join("state.json");
        fs::write(&target, b"old")?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o666))?;
        let writer = RepositoryWriter::new(repository.path())?;

        writer.write_atomic_private("state.json", b"new")?;

        assert_eq!(fs::read(&target)?, b"new");
        assert_eq!(fs::metadata(&target)?.permissions().mode() & 0o777, 0o600);
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

        assert!(matches!(result, Err(FileSystemError::Io { .. })));
        assert!(!outside.path().join("escape.txt").exists());
        Ok(())
    }

    #[test]
    fn repository_writer_rejects_non_regular_existing_target() -> Result<(), Box<dyn Error>> {
        let repository = tempdir()?;
        fs::create_dir(repository.path().join("target"))?;
        let writer = RepositoryWriter::new(repository.path())?;

        let result = writer.write_atomic("target", b"unsafe");

        assert!(matches!(result, Err(FileSystemError::Io { .. })));
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn repository_writer_rejects_ambiguous_windows_leaf_names() -> Result<(), Box<dyn Error>> {
        let repository = tempdir()?;
        let writer = RepositoryWriter::new(repository.path())?;

        for unsafe_name in ["target.txt:stream", "trailing.", "trailing "] {
            let result = writer.write_atomic(unsafe_name, b"unsafe");
            assert!(matches!(result, Err(FileSystemError::Io { .. })));
        }
        assert!(fs::read_dir(repository.path())?.next().is_none());
        Ok(())
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn create_new_collision_preserves_target_and_removes_temporary_file()
    -> Result<(), Box<dyn Error>> {
        let repository = tempdir()?;
        let target = repository.path().join("target.txt");
        fs::write(&target, b"owned")?;
        let writer = RepositoryWriter::new(repository.path())?;

        let error = match writer.write_atomic_new("target.txt", b"intruder") {
            Ok(()) => return Err(io::Error::other("create-new replaced an existing target").into()),
            Err(error) => error,
        };

        assert_eq!(error.io_kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&target)?, b"owned");
        let temporary_count = fs::read_dir(repository.path())?
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".forge-tmp-")
            })
            .count();
        assert_eq!(temporary_count, 0);
        Ok(())
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn visible_root_identity_validation_rejects_a_replacement() -> Result<(), Box<dyn Error>> {
        let container = tempdir()?;
        let repository = container.path().join("repository");
        let displaced = container.path().join("displaced");
        fs::create_dir(&repository)?;
        let writer = RepositoryWriter::new(&repository)?;
        writer.validate_visible_root()?;

        fs::rename(&repository, &displaced)?;
        fs::create_dir(&repository)?;

        assert!(writer.validate_visible_root().is_err());
        Ok(())
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn preflight_to_before_parent_open_swap_is_detected_without_writing_replacement()
    -> Result<(), Box<dyn Error>> {
        let repository = tempdir()?;
        let parent = repository.path().join("parent");
        let saved_parent = repository.path().join("saved-parent");
        fs::create_dir(&parent)?;
        fs::write(parent.join("target.txt"), b"reviewed")?;
        let writer = RepositoryWriter::new(repository.path())?;
        assert_eq!(
            writer.read_optional_bounded("parent/target.txt", 64)?,
            Some(b"reviewed".to_vec())
        );

        let outcome = writer.write_atomic_if_unchanged_with_hook(
            Path::new("parent/target.txt"),
            Some(b"reviewed"),
            b"forge",
            64,
            |event| {
                if event == WriteEvent::BeforeParentOpen {
                    fs::rename(&parent, &saved_parent)?;
                    fs::create_dir(&parent)?;
                    fs::write(parent.join("target.txt"), b"replacement")?;
                }
                Ok(())
            },
        )?;

        assert_eq!(outcome, RepositoryWriteOutcome::PreconditionMismatch);
        assert_eq!(fs::read(parent.join("target.txt"))?, b"replacement");
        assert_eq!(fs::read(saved_parent.join("target.txt"))?, b"reviewed");
        Ok(())
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn final_parent_swap_after_prewrite_commits_only_through_pinned_parent()
    -> Result<(), Box<dyn Error>> {
        let repository = tempdir()?;
        let parent = repository.path().join("parent");
        let saved_parent = repository.path().join("saved-parent");
        fs::create_dir(&parent)?;
        fs::write(parent.join("target.txt"), b"reviewed")?;
        let writer = RepositoryWriter::new(repository.path())?;

        let error = match writer.write_atomic_if_unchanged_with_hook(
            Path::new("parent/target.txt"),
            Some(b"reviewed"),
            b"forge",
            64,
            |event| {
                if event == WriteEvent::AfterPrewriteRead {
                    fs::rename(&parent, &saved_parent)?;
                    fs::create_dir(&parent)?;
                    fs::write(parent.join("target.txt"), b"replacement")?;
                }
                Ok(())
            },
        ) {
            Ok(_) => {
                return Err(io::Error::other(
                    "final parent identity change was reported as verified",
                )
                .into());
            }
            Err(error) => error,
        };

        assert_eq!(error.commit(), RepositoryWriteCommit::CommittedUnverified);
        assert_eq!(fs::read(parent.join("target.txt"))?, b"replacement");
        assert_eq!(fs::read(saved_parent.join("target.txt"))?, b"forge");
        Ok(())
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn leaf_change_after_prewrite_is_rechecked_and_never_overwritten() -> Result<(), Box<dyn Error>>
    {
        let repository = tempdir()?;
        let target = repository.path().join("target.txt");
        fs::write(&target, b"reviewed")?;
        let writer = RepositoryWriter::new(repository.path())?;

        let outcome = writer.write_atomic_if_unchanged_with_hook(
            Path::new("target.txt"),
            Some(b"reviewed"),
            b"forge",
            64,
            |event| {
                if event == WriteEvent::AfterPrewriteRead {
                    fs::write(&target, b"concurrent")?;
                }
                Ok(())
            },
        )?;

        assert_eq!(outcome, RepositoryWriteOutcome::PreconditionMismatch);
        assert_eq!(fs::read(&target)?, b"concurrent");
        let temporary_count = fs::read_dir(repository.path())?
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".forge-tmp-")
            })
            .count();
        assert_eq!(temporary_count, 0);
        Ok(())
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn intermediate_parent_swap_after_prewrite_uses_pinned_descendant() -> Result<(), Box<dyn Error>>
    {
        let repository = tempdir()?;
        let intermediate = repository.path().join("a");
        let saved_intermediate = repository.path().join("saved-a");
        fs::create_dir_all(intermediate.join("b"))?;
        fs::write(intermediate.join("b/target.txt"), b"reviewed")?;
        let writer = RepositoryWriter::new(repository.path())?;

        let error = match writer.write_atomic_if_unchanged_with_hook(
            Path::new("a/b/target.txt"),
            Some(b"reviewed"),
            b"forge",
            64,
            |event| {
                if event == WriteEvent::AfterPrewriteRead {
                    fs::rename(&intermediate, &saved_intermediate)?;
                    fs::create_dir_all(intermediate.join("b"))?;
                    fs::write(intermediate.join("b/target.txt"), b"replacement")?;
                }
                Ok(())
            },
        ) {
            Ok(_) => {
                return Err(io::Error::other(
                    "intermediate identity change was reported as verified",
                )
                .into());
            }
            Err(error) => error,
        };

        assert_eq!(error.commit(), RepositoryWriteCommit::CommittedUnverified);
        assert_eq!(fs::read(intermediate.join("b/target.txt"))?, b"replacement");
        assert_eq!(fs::read(saved_intermediate.join("b/target.txt"))?, b"forge");
        Ok(())
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn root_swap_after_prewrite_uses_pinned_root_and_reports_commit() -> Result<(), Box<dyn Error>>
    {
        let container = tempdir()?;
        let repository = container.path().join("repository");
        let saved_repository = container.path().join("saved-repository");
        fs::create_dir(&repository)?;
        fs::write(repository.join("target.txt"), b"reviewed")?;
        let writer = RepositoryWriter::new(&repository)?;

        let error = match writer.write_atomic_if_unchanged_with_hook(
            Path::new("target.txt"),
            Some(b"reviewed"),
            b"forge",
            64,
            |event| {
                if event == WriteEvent::AfterPrewriteRead {
                    fs::rename(&repository, &saved_repository)?;
                    fs::create_dir(&repository)?;
                    fs::write(repository.join("target.txt"), b"replacement")?;
                }
                Ok(())
            },
        ) {
            Ok(_) => {
                return Err(
                    io::Error::other("root identity change was reported as verified").into(),
                );
            }
            Err(error) => error,
        };

        assert_eq!(error.commit(), RepositoryWriteCommit::CommittedUnverified);
        assert_eq!(fs::read(repository.join("target.txt"))?, b"replacement");
        assert_eq!(fs::read(saved_repository.join("target.txt"))?, b"forge");
        Ok(())
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn repository_writer_does_not_follow_a_swapped_ancestor() -> Result<(), Box<dyn Error>> {
        let container = tempdir()?;
        let repository = container.path().join("repository");
        let parent = repository.join("parent");
        let saved_parent = repository.join("saved-parent");
        fs::create_dir(&repository)?;
        fs::create_dir(&parent)?;
        let writer = RepositoryWriter::new(&repository)?;

        let result = writer.write_atomic_with_before_commit(
            Path::new("parent/target.txt"),
            b"pinned parent",
            || {
                fs::rename(&parent, &saved_parent)?;
                fs::create_dir(&parent)
            },
        );

        assert!(matches!(result, Err(FileSystemError::Io { .. })));
        assert!(!parent.join("target.txt").exists());
        assert_eq!(fs::read(saved_parent.join("target.txt"))?, b"pinned parent");
        Ok(())
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn repository_writer_does_not_follow_a_swapped_root() -> Result<(), Box<dyn Error>> {
        let container = tempdir()?;
        let repository = container.path().join("repository");
        let saved_repository = container.path().join("saved-repository");
        fs::create_dir(&repository)?;
        let writer = RepositoryWriter::new(&repository)?;

        let result =
            writer.write_atomic_with_before_commit(Path::new("target.txt"), b"pinned root", || {
                fs::rename(&repository, &saved_repository)?;
                fs::create_dir(&repository)
            });

        assert!(matches!(result, Err(FileSystemError::Io { .. })));
        assert!(!repository.join("target.txt").exists());
        assert_eq!(
            fs::read(saved_repository.join("target.txt"))?,
            b"pinned root"
        );
        Ok(())
    }
}
