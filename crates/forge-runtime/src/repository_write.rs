//! Handle-relative repository writes.
//!
//! The path-oriented validation in `fs` is useful for diagnostics, but it cannot make the
//! interval between the last check and the final rename safe. This module pins the repository
//! root and every target ancestor with directory handles. Temporary-file creation and commit are
//! then relative to the pinned target parent, so replacing a visible ancestor cannot redirect the
//! write to the replacement tree.

use std::ffi::OsString;
use std::fmt;
use std::fs::File;
use std::io;

use crate::fs::NewFileMode;

#[cfg(unix)]
type RepositoryDirectoryEntryIdentity = (u64, u64);
#[cfg(windows)]
type RepositoryDirectoryEntryIdentity = (u64, [u8; 16]);
#[cfg(not(any(unix, windows)))]
type RepositoryDirectoryEntryIdentity = ();

/// One direct child observed relative to a pinned repository directory.
#[derive(Debug)]
pub(crate) struct RepositoryDirectoryEntry {
    name: OsString,
    kind: RepositoryDirectoryEntryKind,
    identity: RepositoryDirectoryEntryIdentity,
}

/// One bounded directory observation rooted in a live directory handle.
#[derive(Debug)]
pub(crate) struct RepositoryDirectoryListing {
    root: File,
    ancestors: Vec<File>,
    directory: File,
    entries: Vec<RepositoryDirectoryEntry>,
    opened_components: usize,
    target_present: bool,
}

impl RepositoryDirectoryListing {
    pub(crate) fn directory_chain(&self) -> impl Iterator<Item = &File> {
        std::iter::once(&self.root)
            .chain(self.ancestors.iter())
            .chain((self.opened_components != 0).then_some(&self.directory))
    }

    pub(crate) const fn target_present(&self) -> bool {
        self.target_present
    }

    pub(crate) fn into_directory_and_entries(
        self,
    ) -> Option<(File, Vec<RepositoryDirectoryEntry>)> {
        self.target_present
            .then_some((self.directory, self.entries))
    }
}

impl RepositoryDirectoryEntry {
    pub(crate) fn name(&self) -> &std::ffi::OsStr {
        &self.name
    }

    pub(crate) fn kind(&self) -> RepositoryDirectoryEntryKind {
        self.kind
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RepositoryDirectoryEntryKind {
    Directory,
    RegularFile,
}

#[derive(Debug)]
struct DirectoryEntryLimitExceeded;

impl fmt::Display for DirectoryEntryLimitExceeded {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("repository directory exceeds its bounded entry contract")
    }
}

impl std::error::Error for DirectoryEntryLimitExceeded {}

pub(crate) fn is_directory_entry_limit(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|source| source.is::<DirectoryEntryLimitExceeded>())
}

fn directory_entry_limit_error() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, DirectoryEntryLimitExceeded)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnsupportedDirectoryEntryKind {
    LinkOrReparse,
    Other,
}

#[derive(Debug)]
struct UnsupportedDirectoryEntry {
    name: OsString,
    kind: UnsupportedDirectoryEntryKind,
}

impl fmt::Display for UnsupportedDirectoryEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("repository directory contains an unsupported entry kind")
    }
}

impl std::error::Error for UnsupportedDirectoryEntry {}

pub(crate) fn unsupported_directory_entry(
    error: &io::Error,
) -> Option<(&std::ffi::OsStr, UnsupportedDirectoryEntryKind)> {
    let entry = error
        .get_ref()?
        .downcast_ref::<UnsupportedDirectoryEntry>()?;
    Some((&entry.name, entry.kind))
}

fn unsupported_directory_entry_error(
    name: OsString,
    kind: UnsupportedDirectoryEntryKind,
) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        UnsupportedDirectoryEntry { name, kind },
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommitMode {
    Replace,
    CreateNew,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WriteEvent {
    BeforeParentOpen,
    AfterPrewriteRead,
    BeforeCommit,
    AfterCommit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadEvent {
    AfterObservation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GcEvent {
    BeforeBeginRename,
    AfterBeginRename,
    #[cfg(unix)]
    AfterDeleteSync,
}

#[derive(Debug, Clone, Copy)]
enum ExpectedPreimage<'a> {
    Any,
    Exact(Option<&'a [u8]>),
}

/// The last namespace transition known to have completed during a repository-confined GC action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RepositoryGcCommit {
    /// Neither the source nor its quarantine name was changed by Forge.
    NotChanged,
    /// The source was moved to its quarantine name but was not finalized.
    Quarantined,
    /// A quarantined source was moved back to its original name.
    Restored,
    /// The verified quarantine name was removed.
    Deleted,
    /// Concurrent namespace changes prevented Forge from proving the final state.
    Indeterminate,
}

/// A GC namespace failure that preserves the last known transition.
#[derive(Debug)]
pub(crate) struct RepositoryGcError {
    commit: RepositoryGcCommit,
    source: io::Error,
}

impl RepositoryGcError {
    fn new(commit: RepositoryGcCommit, source: io::Error) -> Self {
        Self { commit, source }
    }

    pub(crate) fn not_changed(source: io::Error) -> Self {
        Self::new(RepositoryGcCommit::NotChanged, source)
    }

    #[must_use]
    pub(crate) const fn commit(&self) -> RepositoryGcCommit {
        self.commit
    }

    #[must_use]
    pub(crate) fn io_kind(&self) -> io::ErrorKind {
        self.source.kind()
    }

    pub(crate) fn into_source(self) -> io::Error {
        self.source
    }
}

impl fmt::Display for RepositoryGcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "repository GC operation failed after {:?}: {}",
            self.commit, self.source
        )
    }
}

impl std::error::Error for RepositoryGcError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

#[cfg(unix)]
mod platform {
    use std::ffi::{OsStr, OsString};
    use std::fs::File;
    use std::io::{self, Read as _, Write as _};
    use std::os::fd::AsRawFd as _;
    use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Component, Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use nix::dir::Dir;
    use nix::errno::Errno;
    use nix::fcntl::{AtFlags, OFlag, open, openat, renameat};
    use nix::sys::stat::{Mode, SFlag, fstatat, mkdirat};
    use nix::unistd::{UnlinkatFlags, linkat, unlinkat};

    use forge_core::branding::CLI_NAME;

    use super::GcEvent;
    use super::{
        BeginPrivateQuarantine, CommitMode, ExpectedPreimage, NewFileMode, ReadEvent,
        RepositoryDirectoryEntry, RepositoryDirectoryEntryKind, RepositoryDirectoryListing,
        RepositoryGcCommit, RepositoryGcError, WriteEvent, directory_entry_limit_error,
    };
    use forge_core::ports::{RepositoryWriteCommit, RepositoryWriteError, RepositoryWriteOutcome};

    const TEMPORARY_NAME_ATTEMPTS: u64 = 128;
    static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[derive(Debug)]
    pub(crate) struct RootHandle {
        directory: File,
        path: PathBuf,
        identity: (u64, u64),
    }

    /// One private file moved to a sibling quarantine name under a pinned parent directory.
    #[derive(Debug)]
    pub(crate) struct PrivateQuarantine {
        parent: File,
        parent_path: PathBuf,
        parent_identity: (u64, u64),
        root_path: PathBuf,
        root_identity: (u64, u64),
        original_leaf: OsString,
        quarantine_leaf: OsString,
        duplicate_original: bool,
        object: File,
    }

    struct ReadParentObservation {
        directory: File,
        _ancestors: Vec<File>,
        identities: Vec<(u64, u64)>,
        complete: bool,
    }

    enum ReadTargetObservation {
        Missing,
        Present {
            bytes: Vec<u8>,
            identity: (u64, u64),
            _object: File,
        },
    }

    impl RootHandle {
        pub(crate) fn open(path: &Path) -> io::Result<Self> {
            let descriptor = open(
                path,
                OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(errno_to_io)?;
            let directory = File::from(descriptor);
            if !directory.metadata()?.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::NotADirectory,
                    "repository root handle is not a directory",
                ));
            }
            let identity = directory_identity(&directory)?;
            Ok(Self {
                directory,
                path: path.to_path_buf(),
                identity,
            })
        }

        pub(crate) fn validate_visible_root(&self) -> io::Result<()> {
            let visible = open_root_directory(&self.path)?;
            if directory_identity(&visible)? == self.identity {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "visible repository root no longer matches the pinned directory handle",
                ))
            }
        }

        pub(crate) fn write_atomic(
            &self,
            relative: &Path,
            bytes: &[u8],
            file_mode: NewFileMode,
            commit_mode: CommitMode,
            before_commit: impl FnOnce() -> io::Result<()>,
        ) -> io::Result<()> {
            let mut before_commit = Some(before_commit);
            self.write_atomic_inner(
                relative,
                bytes,
                file_mode,
                commit_mode,
                ExpectedPreimage::Any,
                0,
                |event| {
                    if event == WriteEvent::BeforeCommit {
                        return before_commit.take().map_or_else(
                            || {
                                Err(io::Error::other(
                                    "before-commit callback ran more than once",
                                ))
                            },
                            |callback| callback(),
                        );
                    }
                    Ok(())
                },
            )
            .map(|_| ())
            .map_err(RepositoryWriteError::into_source)
        }

        pub(crate) fn read_bounded(
            &self,
            relative: &Path,
            max_bytes: usize,
        ) -> io::Result<Option<Vec<u8>>> {
            self.read_bounded_inner(relative, max_bytes, |_| Ok(()))
        }

        pub(crate) fn validate_regular_from(
            &self,
            relative: &Path,
            expected_parent: &File,
            object: &File,
        ) -> io::Result<()> {
            let (parent_path, leaf) = split_target(relative)?;
            if !expected_parent.metadata()?.is_dir() {
                return Err(read_namespace_changed(
                    "repository expected parent handle is not a directory",
                ));
            }
            let parent_identity = directory_identity(expected_parent)?;
            validate_visible_root_and_parent(
                &self.path,
                self.identity,
                parent_path,
                parent_identity,
            )?;
            let current = open_regular_leaf(expected_parent, leaf)?;
            if file_identity(&current)? != file_identity(object)? {
                return Err(read_namespace_changed(
                    "repository target identity changed under its pinned parent",
                ));
            }
            validate_visible_root_and_parent(
                &self.path,
                self.identity,
                parent_path,
                parent_identity,
            )
        }

        pub(crate) fn open_regular_from(
            &self,
            relative: &Path,
            expected_parent: &File,
        ) -> io::Result<Option<File>> {
            let (parent_path, leaf) = split_target(relative)?;
            if !expected_parent.metadata()?.is_dir() {
                return Err(read_namespace_changed(
                    "repository expected parent handle is not a directory",
                ));
            }
            let parent_identity = directory_identity(expected_parent)?;
            validate_visible_root_and_parent(
                &self.path,
                self.identity,
                parent_path,
                parent_identity,
            )?;
            let current = open_read_leaf(expected_parent, leaf)?;
            validate_visible_root_and_parent(
                &self.path,
                self.identity,
                parent_path,
                parent_identity,
            )?;
            Ok(current)
        }

        pub(crate) fn open_listed_entry_from(
            &self,
            relative: &Path,
            expected_directory: &File,
            entry: &RepositoryDirectoryEntry,
        ) -> io::Result<File> {
            if !expected_directory.metadata()?.is_dir() {
                return Err(read_namespace_changed(
                    "repository expected listing handle is not a directory",
                ));
            }
            let expected_identity = directory_identity(expected_directory)?;
            validate_visible_root_and_parent(
                &self.path,
                self.identity,
                relative,
                expected_identity,
            )?;
            let current = match entry.kind {
                RepositoryDirectoryEntryKind::Directory => {
                    open_listing_directory(expected_directory, &entry.name)
                }
                RepositoryDirectoryEntryKind::RegularFile => {
                    open_read_leaf(expected_directory, &entry.name)?.ok_or_else(|| {
                        read_namespace_changed(
                            "repository listed entry disappeared under its pinned parent",
                        )
                    })
                }
            }?;
            if file_identity(&current)? != entry.identity {
                return Err(read_namespace_changed(
                    "repository listed entry identity changed under its pinned parent",
                ));
            }
            validate_visible_root_and_parent(
                &self.path,
                self.identity,
                relative,
                expected_identity,
            )?;
            Ok(current)
        }

        pub(crate) fn list_directory(
            &self,
            relative: &Path,
            max_entries: usize,
        ) -> io::Result<Option<RepositoryDirectoryListing>> {
            self.list_directory_inner(relative, None, max_entries, || Ok(()))
        }

        pub(crate) fn list_directory_from(
            &self,
            relative: &Path,
            expected: &File,
            max_entries: usize,
        ) -> io::Result<RepositoryDirectoryListing> {
            self.list_directory_inner(relative, Some(expected), max_entries, || Ok(()))?
                .ok_or_else(|| {
                    read_namespace_changed(
                        "repository directory disappeared after its pinned parent listing",
                    )
                })
        }

        #[cfg(test)]
        pub(super) fn list_directory_with_hook(
            &self,
            relative: &Path,
            max_entries: usize,
            hook: impl FnOnce() -> io::Result<()>,
        ) -> io::Result<Option<RepositoryDirectoryListing>> {
            self.list_directory_inner(relative, None, max_entries, hook)
        }

        fn list_directory_inner(
            &self,
            relative: &Path,
            expected: Option<&File>,
            max_entries: usize,
            hook: impl FnOnce() -> io::Result<()>,
        ) -> io::Result<Option<RepositoryDirectoryListing>> {
            let observation = open_directory_for_listing(&self.directory, relative)?;
            if !observation.complete {
                validate_directory_observation(
                    &self.directory,
                    &self.path,
                    self.identity,
                    relative,
                    &observation.identities,
                )?;
                if expected.is_some() {
                    return Err(read_namespace_changed(
                        "repository directory disappeared after its pinned parent listing",
                    ));
                }
                return Ok(Some(RepositoryDirectoryListing {
                    root: reopen_listing_root(&self.directory)?,
                    ancestors: observation._ancestors,
                    directory: observation.directory,
                    entries: Vec::new(),
                    opened_components: observation.identities.len(),
                    target_present: false,
                }));
            }
            let opened_components = observation.identities.len();
            let ancestors = observation._ancestors;
            let visible_identity = directory_identity(&observation.directory)?;
            let directory = if let Some(expected) = expected {
                if directory_identity(expected)? != visible_identity {
                    return Err(read_namespace_changed(
                        "repository directory identity changed after its parent listing",
                    ));
                }
                expected.try_clone()?
            } else {
                observation.directory
            };
            if !directory.metadata()?.is_dir() {
                return Err(read_namespace_changed(
                    "repository listing handle is not a directory",
                ));
            }
            let expected_directory = directory_identity(&directory)?;
            let mut iterator = Dir::from_fd(directory.try_clone()?.into())?;
            let mut entries = Vec::new();
            for entry in iterator.iter() {
                let entry = entry.map_err(errno_to_io)?;
                let name = entry.file_name().to_bytes();
                if matches!(name, b"." | b"..") {
                    continue;
                }
                if entries.len() == max_entries {
                    return Err(directory_entry_limit_error());
                }
                let name = OsString::from_vec(name.to_vec());
                let metadata = fstatat(&directory, Path::new(&name), AtFlags::AT_SYMLINK_NOFOLLOW)
                    .map_err(errno_to_io)?;
                let file_type = SFlag::from_bits_truncate(metadata.st_mode);
                let (kind, object) = if file_type == SFlag::S_IFREG {
                    (
                        RepositoryDirectoryEntryKind::RegularFile,
                        open_regular_leaf(&directory, &name)?,
                    )
                } else if file_type == SFlag::S_IFDIR {
                    (
                        RepositoryDirectoryEntryKind::Directory,
                        open_listing_directory(&directory, &name)?,
                    )
                } else {
                    let kind = if file_type == SFlag::S_IFLNK {
                        super::UnsupportedDirectoryEntryKind::LinkOrReparse
                    } else {
                        super::UnsupportedDirectoryEntryKind::Other
                    };
                    return Err(super::unsupported_directory_entry_error(name, kind));
                };
                let identity = file_identity(&object)?;
                entries.push(RepositoryDirectoryEntry {
                    name,
                    kind,
                    identity,
                });
            }
            hook()?;
            validate_visible_root_and_parent(
                &self.path,
                self.identity,
                relative,
                expected_directory,
            )?;
            validate_listed_entries(&directory, &entries)?;
            validate_visible_root_and_parent(
                &self.path,
                self.identity,
                relative,
                expected_directory,
            )?;
            Ok(Some(RepositoryDirectoryListing {
                root: reopen_listing_root(&self.directory)?,
                ancestors,
                directory,
                entries,
                opened_components,
                target_present: true,
            }))
        }

        #[cfg(test)]
        pub(super) fn read_bounded_with_hook(
            &self,
            relative: &Path,
            max_bytes: usize,
            hook: impl FnOnce(ReadEvent) -> io::Result<()>,
        ) -> io::Result<Option<Vec<u8>>> {
            self.read_bounded_inner(relative, max_bytes, hook)
        }

        fn read_bounded_inner(
            &self,
            relative: &Path,
            max_bytes: usize,
            hook: impl FnOnce(ReadEvent) -> io::Result<()>,
        ) -> io::Result<Option<Vec<u8>>> {
            let (parent_path, leaf) = split_target(relative)?;
            let parent = open_parent_for_read(&self.directory, parent_path)?;
            if !parent.complete {
                hook(ReadEvent::AfterObservation)?;
                validate_read_observation(
                    &self.directory,
                    &self.path,
                    self.identity,
                    parent_path,
                    &parent.identities,
                    leaf,
                    None,
                )?;
                return Ok(None);
            }
            let target = read_target_bounded_with_identity(&parent.directory, leaf, max_bytes)?;
            hook(ReadEvent::AfterObservation)?;
            let expected_leaf = match &target {
                ReadTargetObservation::Missing => None,
                ReadTargetObservation::Present { identity, .. } => Some(*identity),
            };
            validate_read_observation(
                &self.directory,
                &self.path,
                self.identity,
                parent_path,
                &parent.identities,
                leaf,
                expected_leaf,
            )?;
            Ok(match target {
                ReadTargetObservation::Missing => None,
                ReadTargetObservation::Present { bytes, .. } => Some(bytes),
            })
        }

        #[cfg(test)]
        pub(crate) fn begin_private_quarantine(
            &self,
            relative: &Path,
            quarantine_leaf: &OsStr,
        ) -> Result<BeginPrivateQuarantine, RepositoryGcError> {
            self.begin_private_quarantine_inner(relative, quarantine_leaf, None, |_| Ok(()))
        }

        pub(crate) fn begin_private_quarantine_from(
            &self,
            relative: &Path,
            expected_parent: &File,
            quarantine_leaf: &OsStr,
        ) -> Result<BeginPrivateQuarantine, RepositoryGcError> {
            self.begin_private_quarantine_inner(
                relative,
                quarantine_leaf,
                Some(expected_parent),
                |_| Ok(()),
            )
        }

        #[cfg(test)]
        pub(super) fn begin_private_quarantine_with_hook(
            &self,
            relative: &Path,
            quarantine_leaf: &OsStr,
            hook: impl FnMut(GcEvent) -> io::Result<()>,
        ) -> Result<BeginPrivateQuarantine, RepositoryGcError> {
            self.begin_private_quarantine_inner(relative, quarantine_leaf, None, hook)
        }

        fn begin_private_quarantine_inner(
            &self,
            relative: &Path,
            quarantine_leaf: &OsStr,
            expected_parent: Option<&File>,
            mut hook: impl FnMut(GcEvent) -> io::Result<()>,
        ) -> Result<BeginPrivateQuarantine, RepositoryGcError> {
            let (parent_path, original_leaf) = split_target(relative)
                .and_then(|parts| {
                    validate_quarantine_names(parts.1, quarantine_leaf).map(|()| parts)
                })
                .map_err(not_changed_gc)?;
            let parent = if let Some(expected_parent) = expected_parent {
                if !expected_parent.metadata().map_err(not_changed_gc)?.is_dir() {
                    return Err(not_changed_gc(read_namespace_changed(
                        "repository GC expected parent handle is not a directory",
                    )));
                }
                let expected_identity =
                    directory_identity(expected_parent).map_err(not_changed_gc)?;
                validate_visible_root_and_parent(
                    &self.path,
                    self.identity,
                    parent_path,
                    expected_identity,
                )
                .map_err(not_changed_gc)?;
                expected_parent.try_clone().map_err(not_changed_gc)?
            } else {
                match self.open_parent(parent_path, NewFileMode::Private, false) {
                    Ok(parent) => parent,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        return Ok(BeginPrivateQuarantine::Missing);
                    }
                    Err(error) => return Err(not_changed_gc(error)),
                }
            };
            let parent_identity = directory_identity(&parent).map_err(not_changed_gc)?;
            let object = match open_regular_leaf(&parent, original_leaf) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    return Ok(BeginPrivateQuarantine::Missing);
                }
                Err(error) => return Err(not_changed_gc(error)),
            };
            let object_identity = file_identity(&object).map_err(not_changed_gc)?;

            hook(GcEvent::BeforeBeginRename).map_err(not_changed_gc)?;
            validate_visible_root_and_parent(
                &self.path,
                self.identity,
                parent_path,
                parent_identity,
            )
            .map_err(not_changed_gc)?;
            rename_leaf_noreplace(&parent, original_leaf, quarantine_leaf)
                .map_err(not_changed_gc)?;
            let post_rename = (|| {
                hook(GcEvent::AfterBeginRename)?;
                let reopened = open_regular_leaf(&parent, quarantine_leaf)?;
                if file_identity(&reopened)? != object_identity {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "repository GC source changed during quarantine rename",
                    ));
                }
                drop(reopened);
                parent.sync_all()?;
                validate_visible_root_and_parent(
                    &self.path,
                    self.identity,
                    parent_path,
                    parent_identity,
                )
            })();
            if let Err(source) = post_rename {
                return Err(recover_failed_begin_quarantine(
                    &parent,
                    quarantine_leaf,
                    original_leaf,
                    object_identity,
                    source,
                ));
            }

            Ok(BeginPrivateQuarantine::Quarantined(PrivateQuarantine {
                parent,
                parent_path: parent_path.to_path_buf(),
                parent_identity,
                root_path: self.path.clone(),
                root_identity: self.identity,
                original_leaf: original_leaf.to_os_string(),
                quarantine_leaf: quarantine_leaf.to_os_string(),
                duplicate_original: false,
                object,
            }))
        }

        #[cfg(test)]
        pub(crate) fn open_private_quarantine(
            &self,
            directory: &Path,
            original_leaf: &OsStr,
            quarantine_leaf: &OsStr,
        ) -> Result<super::OpenPrivateQuarantine, RepositoryGcError> {
            self.open_private_quarantine_inner(directory, original_leaf, quarantine_leaf, None)
        }

        pub(crate) fn open_private_quarantine_from(
            &self,
            directory: &Path,
            expected_parent: &File,
            original_leaf: &OsStr,
            quarantine_leaf: &OsStr,
        ) -> Result<super::OpenPrivateQuarantine, RepositoryGcError> {
            self.open_private_quarantine_inner(
                directory,
                original_leaf,
                quarantine_leaf,
                Some(expected_parent),
            )
        }

        fn open_private_quarantine_inner(
            &self,
            directory: &Path,
            original_leaf: &OsStr,
            quarantine_leaf: &OsStr,
            expected_parent: Option<&File>,
        ) -> Result<super::OpenPrivateQuarantine, RepositoryGcError> {
            validate_parent_path(directory).map_err(not_changed_gc)?;
            validate_quarantine_names(original_leaf, quarantine_leaf).map_err(not_changed_gc)?;
            let parent = if let Some(expected_parent) = expected_parent {
                if !expected_parent.metadata().map_err(not_changed_gc)?.is_dir() {
                    return Err(not_changed_gc(read_namespace_changed(
                        "repository GC recovery parent handle is not a directory",
                    )));
                }
                let expected_identity =
                    directory_identity(expected_parent).map_err(not_changed_gc)?;
                validate_visible_root_and_parent(
                    &self.path,
                    self.identity,
                    directory,
                    expected_identity,
                )
                .map_err(not_changed_gc)?;
                expected_parent.try_clone().map_err(not_changed_gc)?
            } else {
                match self.open_parent(directory, NewFileMode::Private, false) {
                    Ok(parent) => parent,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        return Ok(super::OpenPrivateQuarantine::Missing);
                    }
                    Err(error) => return Err(not_changed_gc(error)),
                }
            };
            let parent_identity = directory_identity(&parent).map_err(not_changed_gc)?;
            let object = match open_regular_leaf(&parent, quarantine_leaf) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    return Ok(super::OpenPrivateQuarantine::Missing);
                }
                Err(error) => return Err(not_changed_gc(error)),
            };
            let object_identity = file_identity(&object).map_err(not_changed_gc)?;
            let duplicate_original = match open_regular_leaf(&parent, original_leaf) {
                Ok(original) => {
                    if file_identity(&original).map_err(not_changed_gc)? != object_identity {
                        return Err(not_changed_gc(io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            "repository GC recovery found different objects at the original and quarantine names",
                        )));
                    }
                    true
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => false,
                Err(error) => return Err(not_changed_gc(error)),
            };

            let quarantine = PrivateQuarantine {
                parent,
                parent_path: directory.to_path_buf(),
                parent_identity,
                root_path: self.path.clone(),
                root_identity: self.identity,
                original_leaf: original_leaf.to_os_string(),
                quarantine_leaf: quarantine_leaf.to_os_string(),
                duplicate_original,
                object,
            };
            Ok(if duplicate_original {
                super::OpenPrivateQuarantine::DuplicateSameIdentity(quarantine)
            } else {
                super::OpenPrivateQuarantine::QuarantineOnly(quarantine)
            })
        }

        pub(crate) fn write_atomic_if_unchanged(
            &self,
            relative: &Path,
            expected: Option<&[u8]>,
            bytes: &[u8],
            max_postimage_bytes: usize,
        ) -> Result<RepositoryWriteOutcome, RepositoryWriteError> {
            let commit_mode = if expected.is_some() {
                CommitMode::Replace
            } else {
                CommitMode::CreateNew
            };
            self.write_atomic_inner(
                relative,
                bytes,
                NewFileMode::Default,
                commit_mode,
                ExpectedPreimage::Exact(expected),
                max_postimage_bytes,
                |_| Ok(()),
            )
        }

        #[cfg(test)]
        pub(crate) fn write_atomic_if_unchanged_with_hook(
            &self,
            relative: &Path,
            expected: Option<&[u8]>,
            bytes: &[u8],
            max_postimage_bytes: usize,
            mut hook: impl FnMut(WriteEvent) -> io::Result<()>,
        ) -> Result<RepositoryWriteOutcome, RepositoryWriteError> {
            let commit_mode = if expected.is_some() {
                CommitMode::Replace
            } else {
                CommitMode::CreateNew
            };
            self.write_atomic_inner(
                relative,
                bytes,
                NewFileMode::Default,
                commit_mode,
                ExpectedPreimage::Exact(expected),
                max_postimage_bytes,
                &mut hook,
            )
        }

        #[allow(clippy::too_many_arguments)]
        fn write_atomic_inner(
            &self,
            relative: &Path,
            bytes: &[u8],
            file_mode: NewFileMode,
            commit_mode: CommitMode,
            expected: ExpectedPreimage<'_>,
            max_postimage_bytes: usize,
            mut hook: impl FnMut(WriteEvent) -> io::Result<()>,
        ) -> Result<RepositoryWriteOutcome, RepositoryWriteError> {
            hook(WriteEvent::BeforeParentOpen).map_err(not_committed)?;
            let (parent_path, leaf) = split_target(relative).map_err(not_committed)?;
            let parent = self
                .open_parent(parent_path, file_mode, true)
                .map_err(not_committed)?;
            let original_parent_identity = directory_identity(&parent).map_err(not_committed)?;
            if let ExpectedPreimage::Exact(expected) = expected {
                let observed = read_target_bounded(&parent, leaf, max_postimage_bytes)
                    .map_err(not_committed)?;
                if observed.as_deref() != expected {
                    return Ok(RepositoryWriteOutcome::PreconditionMismatch);
                }
            }
            hook(WriteEvent::AfterPrewriteRead).map_err(not_committed)?;
            let existing_mode =
                existing_target_mode(&parent, leaf, file_mode).map_err(not_committed)?;
            let (mut temporary, temporary_name) =
                create_temporary(&parent, file_mode).map_err(not_committed)?;
            let mut committed = false;

            let result = (|| {
                temporary.write_all(bytes)?;
                temporary.flush()?;
                if let Some(mode) = existing_mode {
                    temporary.set_permissions(std::fs::Permissions::from_mode(mode))?;
                }
                temporary.sync_all()?;
                if let ExpectedPreimage::Exact(expected) = expected {
                    let observed = read_target_bounded(&parent, leaf, max_postimage_bytes)?;
                    if observed.as_deref() != expected {
                        return Ok(RepositoryWriteOutcome::PreconditionMismatch);
                    }
                }
                hook(WriteEvent::BeforeCommit)?;

                match commit_mode {
                    CommitMode::Replace => renameat(
                        &parent,
                        Path::new(&temporary_name),
                        &parent,
                        Path::new(leaf),
                    )
                    .map_err(errno_to_io)?,
                    CommitMode::CreateNew => {
                        linkat(
                            &parent,
                            Path::new(&temporary_name),
                            &parent,
                            Path::new(leaf),
                            AtFlags::empty(),
                        )
                        .map_err(errno_to_io)?;
                        committed = true;
                        unlinkat(
                            &parent,
                            Path::new(&temporary_name),
                            UnlinkatFlags::NoRemoveDir,
                        )
                        .map_err(errno_to_io)?;
                    }
                }
                committed = true;
                hook(WriteEvent::AfterCommit)?;
                parent.sync_all()?;

                let visible_parent = self.open_parent(parent_path, file_mode, false)?;
                if directory_identity(&visible_parent)? != original_parent_identity {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "repository target parent changed during atomic write",
                    ));
                }
                let visible_root = open_root_directory(&self.path)?;
                if directory_identity(&visible_root)? != self.identity {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "repository root changed during atomic write",
                    ));
                }
                let observed = match expected {
                    ExpectedPreimage::Any => None,
                    ExpectedPreimage::Exact(_) => {
                        read_target_bounded(&parent, leaf, max_postimage_bytes)?
                    }
                };
                Ok(RepositoryWriteOutcome::Written { observed })
            })();

            if !committed && !matches!(&result, Ok(RepositoryWriteOutcome::Written { .. })) {
                let cleanup = unlinkat(
                    &parent,
                    Path::new(&temporary_name),
                    UnlinkatFlags::NoRemoveDir,
                );
                if let Err(error) = cleanup {
                    if error != Errno::ENOENT {
                        return Err(RepositoryWriteError::new(
                            commit_state(committed),
                            io::Error::other(format!(
                                "atomic repository write failed and its temporary file could not be removed: {}",
                                errno_to_io(error)
                            )),
                        ));
                    }
                }
            }
            result.map_err(|source| RepositoryWriteError::new(commit_state(committed), source))
        }

        fn open_parent(
            &self,
            relative: &Path,
            mode: NewFileMode,
            create: bool,
        ) -> io::Result<File> {
            open_parent_from(&self.directory, relative, mode, create)
        }
    }

    impl PrivateQuarantine {
        pub(crate) fn object_file(&mut self) -> &mut File {
            &mut self.object
        }

        pub(crate) fn validate_visible_root_and_parent(&self) -> io::Result<()> {
            validate_visible_root_and_parent(
                &self.root_path,
                self.root_identity,
                &self.parent_path,
                self.parent_identity,
            )
        }

        pub(crate) fn restore(self) -> Result<(), RepositoryGcError> {
            let expected = file_identity(&self.object)
                .map_err(|error| RepositoryGcError::new(RepositoryGcCommit::Quarantined, error))?;
            let current =
                open_regular_leaf(&self.parent, &self.quarantine_leaf).map_err(|error| {
                    RepositoryGcError::new(RepositoryGcCommit::Indeterminate, error)
                })?;
            if file_identity(&current)
                .map_err(|error| RepositoryGcError::new(RepositoryGcCommit::Indeterminate, error))?
                != expected
            {
                return Err(RepositoryGcError::new(
                    RepositoryGcCommit::Indeterminate,
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "repository GC quarantine changed before restoration",
                    ),
                ));
            }
            drop(current);
            restore_leaf(&self.parent, &self.quarantine_leaf, &self.original_leaf)
                .map_err(|error| RepositoryGcError::new(RepositoryGcCommit::Quarantined, error))?;
            let restored = open_regular_leaf(&self.parent, &self.original_leaf)
                .map_err(|error| RepositoryGcError::new(RepositoryGcCommit::Restored, error))?;
            if file_identity(&restored)
                .map_err(|error| RepositoryGcError::new(RepositoryGcCommit::Restored, error))?
                != expected
            {
                return Err(RepositoryGcError::new(
                    RepositoryGcCommit::Indeterminate,
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "repository GC restored name does not identify the quarantined object",
                    ),
                ));
            }
            self.parent
                .sync_all()
                .map_err(|error| RepositoryGcError::new(RepositoryGcCommit::Restored, error))?;
            self.validate_visible_root_and_parent()
                .map_err(|error| RepositoryGcError::new(RepositoryGcCommit::Restored, error))
        }

        pub(crate) fn delete(self) -> Result<(), RepositoryGcError> {
            self.delete_inner(|_| Ok(()))
        }

        #[cfg(test)]
        pub(super) fn delete_with_hook(
            self,
            hook: impl FnMut(GcEvent) -> io::Result<()>,
        ) -> Result<(), RepositoryGcError> {
            self.delete_inner(hook)
        }

        fn delete_inner(
            self,
            mut hook: impl FnMut(GcEvent) -> io::Result<()>,
        ) -> Result<(), RepositoryGcError> {
            if let Err(validation) = self.validate_visible_root_and_parent() {
                if self.duplicate_original {
                    return Err(RepositoryGcError::new(
                        RepositoryGcCommit::Indeterminate,
                        validation,
                    ));
                }
                return restore_after_delete_precondition_failure(self, validation);
            }
            let expected = file_identity(&self.object)
                .map_err(|error| RepositoryGcError::new(RepositoryGcCommit::Quarantined, error))?;
            let current =
                open_regular_leaf(&self.parent, &self.quarantine_leaf).map_err(|error| {
                    RepositoryGcError::new(RepositoryGcCommit::Indeterminate, error)
                })?;
            if file_identity(&current)
                .map_err(|error| RepositoryGcError::new(RepositoryGcCommit::Indeterminate, error))?
                != expected
            {
                return Err(RepositoryGcError::new(
                    RepositoryGcCommit::Indeterminate,
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "repository GC quarantine changed before deletion",
                    ),
                ));
            }
            if self.duplicate_original {
                let original =
                    open_regular_leaf(&self.parent, &self.original_leaf).map_err(|error| {
                        RepositoryGcError::new(RepositoryGcCommit::Indeterminate, error)
                    })?;
                if file_identity(&original).map_err(|error| {
                    RepositoryGcError::new(RepositoryGcCommit::Indeterminate, error)
                })? != expected
                {
                    return Err(RepositoryGcError::new(
                        RepositoryGcCommit::Indeterminate,
                        io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "repository GC duplicate original changed before quarantine cleanup",
                        ),
                    ));
                }
            }
            drop(current);
            unlinkat(
                &self.parent,
                Path::new(&self.quarantine_leaf),
                UnlinkatFlags::NoRemoveDir,
            )
            .map_err(errno_to_io)
            .map_err(|error| RepositoryGcError::new(RepositoryGcCommit::Quarantined, error))?;
            self.parent
                .sync_all()
                .map_err(|error| RepositoryGcError::new(RepositoryGcCommit::Deleted, error))?;
            hook(GcEvent::AfterDeleteSync)
                .map_err(|error| RepositoryGcError::new(RepositoryGcCommit::Deleted, error))?;
            match open_regular_leaf(&self.parent, &self.quarantine_leaf) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Ok(remaining) => {
                    drop(remaining);
                    return Err(RepositoryGcError::new(
                        RepositoryGcCommit::Indeterminate,
                        io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "repository GC quarantine name reappeared after deletion",
                        ),
                    ));
                }
                Err(error) => {
                    return Err(RepositoryGcError::new(
                        RepositoryGcCommit::Indeterminate,
                        error,
                    ));
                }
            }
            self.validate_visible_root_and_parent()
                .map_err(|error| RepositoryGcError::new(RepositoryGcCommit::Deleted, error))
        }
    }

    fn open_parent_from(
        root: &File,
        relative: &Path,
        mode: NewFileMode,
        create: bool,
    ) -> io::Result<File> {
        validate_parent_path(relative)?;
        let mut current = root.try_clone()?;
        for component in relative.components() {
            let Component::Normal(segment) = component else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "repository parent path was not normalized",
                ));
            };
            current = match open_directory(&current, segment) {
                Ok(directory) => directory,
                Err(error) if create && error.kind() == io::ErrorKind::NotFound => {
                    let directory_mode = match mode {
                        NewFileMode::Default => Mode::from_bits_truncate(0o777),
                        NewFileMode::Private => Mode::from_bits_truncate(0o700),
                    };
                    let created = match mkdirat(&current, Path::new(segment), directory_mode) {
                        Ok(()) => true,
                        Err(Errno::EEXIST) => false,
                        Err(error) => return Err(errno_to_io(error)),
                    };
                    let directory = open_directory(&current, segment)?;
                    if created {
                        directory.sync_all()?;
                        current.sync_all()?;
                    }
                    directory
                }
                Err(error) => return Err(error),
            };
        }
        Ok(current)
    }

    fn open_parent_for_read(root: &File, relative: &Path) -> io::Result<ReadParentObservation> {
        validate_parent_path(relative)?;
        let mut chain = Vec::new();
        let mut identities = Vec::new();
        for component in relative.components() {
            let Component::Normal(segment) = component else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "repository parent path was not normalized",
                ));
            };
            let current = chain.last().unwrap_or(root);
            match open_directory(current, segment) {
                Ok(directory) => {
                    identities.push(directory_identity(&directory)?);
                    chain.push(directory);
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    return finish_read_parent_observation(root, chain, identities, false);
                }
                Err(error) => return Err(error),
            }
        }
        finish_read_parent_observation(root, chain, identities, true)
    }

    fn open_directory_for_listing(
        root: &File,
        relative: &Path,
    ) -> io::Result<ReadParentObservation> {
        validate_parent_path(relative)?;
        if relative.as_os_str().is_empty() {
            return finish_read_parent_observation(root, Vec::new(), Vec::new(), true);
        }
        let mut chain = Vec::new();
        let mut identities = Vec::new();
        let mut components = relative.components().peekable();
        while let Some(component) = components.next() {
            let Component::Normal(segment) = component else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "repository directory path was not normalized",
                ));
            };
            let current = chain.last().unwrap_or(root);
            let opened = if components.peek().is_none() {
                open_listing_directory(current, segment)
            } else {
                open_directory(current, segment)
            };
            match opened {
                Ok(directory) => {
                    identities.push(directory_identity(&directory)?);
                    chain.push(directory);
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    return finish_read_parent_observation(root, chain, identities, false);
                }
                Err(error) => return Err(error),
            }
        }
        finish_read_parent_observation(root, chain, identities, true)
    }

    fn finish_read_parent_observation(
        root: &File,
        mut chain: Vec<File>,
        identities: Vec<(u64, u64)>,
        complete: bool,
    ) -> io::Result<ReadParentObservation> {
        let directory = match chain.pop() {
            Some(directory) => directory,
            None => root.try_clone()?,
        };
        Ok(ReadParentObservation {
            directory,
            _ancestors: chain,
            identities,
            complete,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_read_observation(
        pinned_root: &File,
        root_path: &Path,
        root_identity: (u64, u64),
        parent_path: &Path,
        parent_identities: &[(u64, u64)],
        leaf: &OsStr,
        expected_leaf: Option<(u64, u64)>,
    ) -> io::Result<()> {
        validate_pinned_read_root(pinned_root, root_identity)?;
        let visible_root = open_visible_read_root(root_path, root_identity)?;
        let mut chain = Vec::new();
        for (index, component) in parent_path.components().enumerate() {
            let Component::Normal(segment) = component else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "repository parent path was not normalized",
                ));
            };
            let current = chain.last().unwrap_or(&visible_root);
            let directory = match open_directory(current, segment) {
                Ok(directory) => directory,
                Err(error)
                    if index == parent_identities.len()
                        && error.kind() == io::ErrorKind::NotFound =>
                {
                    validate_pinned_read_root(pinned_root, root_identity)?;
                    open_visible_read_root(root_path, root_identity)?;
                    return Ok(());
                }
                Err(error) => {
                    return Err(read_namespace_changed(format!(
                        "repository parent changed during bounded read: {error}"
                    )));
                }
            };
            let Some(expected) = parent_identities.get(index) else {
                return Err(read_namespace_changed(
                    "a previously missing repository parent appeared during bounded read",
                ));
            };
            if directory_identity(&directory)? != *expected {
                return Err(read_namespace_changed(
                    "repository parent identity changed during bounded read",
                ));
            }
            chain.push(directory);
        }

        if chain.len() != parent_identities.len() {
            return Err(read_namespace_changed(
                "repository parent observation was inconsistent during bounded read",
            ));
        }
        let visible_parent = chain.last().unwrap_or(&visible_root);
        validate_read_leaf(visible_parent, leaf, expected_leaf)?;
        validate_pinned_read_root(pinned_root, root_identity)?;
        open_visible_read_root(root_path, root_identity)?;
        Ok(())
    }

    fn validate_directory_observation(
        pinned_root: &File,
        root_path: &Path,
        root_identity: (u64, u64),
        relative: &Path,
        identities: &[(u64, u64)],
    ) -> io::Result<()> {
        validate_pinned_read_root(pinned_root, root_identity)?;
        let visible_root = open_visible_read_root(root_path, root_identity)?;
        let mut chain = Vec::new();
        for (index, component) in relative.components().enumerate() {
            let Component::Normal(segment) = component else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "repository directory path was not normalized",
                ));
            };
            let current = chain.last().unwrap_or(&visible_root);
            let directory = match open_directory(current, segment) {
                Ok(directory) => directory,
                Err(error)
                    if index == identities.len() && error.kind() == io::ErrorKind::NotFound =>
                {
                    validate_pinned_read_root(pinned_root, root_identity)?;
                    open_visible_read_root(root_path, root_identity)?;
                    return Ok(());
                }
                Err(error) => {
                    return Err(read_namespace_changed(format!(
                        "repository directory changed during listing: {error}"
                    )));
                }
            };
            let Some(expected) = identities.get(index) else {
                return Err(read_namespace_changed(
                    "a previously missing repository directory appeared during listing",
                ));
            };
            if directory_identity(&directory)? != *expected {
                return Err(read_namespace_changed(
                    "repository directory identity changed during listing",
                ));
            }
            chain.push(directory);
        }
        if chain.len() != identities.len() {
            return Err(read_namespace_changed(
                "repository directory observation was inconsistent during listing",
            ));
        }
        validate_pinned_read_root(pinned_root, root_identity)?;
        open_visible_read_root(root_path, root_identity)?;
        Ok(())
    }

    fn validate_pinned_read_root(root: &File, expected: (u64, u64)) -> io::Result<()> {
        if directory_identity(root)? == expected {
            Ok(())
        } else {
            Err(read_namespace_changed(
                "pinned repository root identity changed during bounded read",
            ))
        }
    }

    fn open_visible_read_root(path: &Path, expected: (u64, u64)) -> io::Result<File> {
        let visible = open_root_directory(path).map_err(|error| {
            read_namespace_changed(format!(
                "visible repository root changed during bounded read: {error}"
            ))
        })?;
        if directory_identity(&visible)? == expected {
            Ok(visible)
        } else {
            Err(read_namespace_changed(
                "visible repository root identity changed during bounded read",
            ))
        }
    }

    fn validate_read_leaf(
        parent: &File,
        leaf: &OsStr,
        expected: Option<(u64, u64)>,
    ) -> io::Result<()> {
        let observed = open_read_leaf(parent, leaf).map_err(|error| {
            read_namespace_changed(format!(
                "repository target changed during bounded read: {error}"
            ))
        })?;
        match (expected, observed) {
            (None, None) => Ok(()),
            (Some(expected), Some(file)) if file_identity(&file)? == expected => Ok(()),
            _ => Err(read_namespace_changed(
                "repository target identity changed during bounded read",
            )),
        }
    }

    fn validate_listed_entries(
        parent: &File,
        entries: &[RepositoryDirectoryEntry],
    ) -> io::Result<()> {
        for entry in entries {
            let current = match entry.kind {
                RepositoryDirectoryEntryKind::Directory => open_directory(parent, &entry.name),
                RepositoryDirectoryEntryKind::RegularFile => open_regular_leaf(parent, &entry.name),
            }
            .map_err(|error| {
                read_namespace_changed(format!(
                    "repository directory entry changed during listing: {error}"
                ))
            })?;
            if file_identity(&current)? != entry.identity {
                return Err(read_namespace_changed(
                    "repository directory entry identity changed during listing",
                ));
            }
        }
        Ok(())
    }

    fn read_namespace_changed(message: impl Into<String>) -> io::Error {
        io::Error::new(io::ErrorKind::PermissionDenied, message.into())
    }

    fn validate_parent_path(relative: &Path) -> io::Result<()> {
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "repository parent path was not normalized",
            ));
        }
        Ok(())
    }

    fn validate_quarantine_names(original: &OsStr, quarantine: &OsStr) -> io::Result<()> {
        validate_leaf(original)?;
        validate_leaf(quarantine)?;
        if original == quarantine {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "repository GC original and quarantine names must differ",
            ));
        }
        Ok(())
    }

    fn validate_leaf(leaf: &OsStr) -> io::Result<()> {
        let path = Path::new(leaf);
        if leaf.is_empty()
            || path.is_absolute()
            || path.components().count() != 1
            || !matches!(path.components().next(), Some(Component::Normal(_)))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "repository GC name must be one normalized leaf",
            ));
        }
        Ok(())
    }

    fn open_regular_leaf(parent: &File, leaf: &OsStr) -> io::Result<File> {
        validate_leaf(leaf)?;
        let descriptor = openat(
            parent,
            Path::new(leaf),
            OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| match error {
            Errno::ELOOP => io::Error::new(
                io::ErrorKind::PermissionDenied,
                "repository GC object is a symbolic link",
            ),
            error => errno_to_io(error),
        })?;
        let file = File::from(descriptor);
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "repository GC object is not a regular file",
            ));
        }
        Ok(file)
    }

    fn validate_visible_root_and_parent(
        root_path: &Path,
        root_identity: (u64, u64),
        parent_path: &Path,
        parent_identity: (u64, u64),
    ) -> io::Result<()> {
        let visible_root = open_root_directory(root_path)?;
        if directory_identity(&visible_root)? != root_identity {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "visible repository root no longer matches the pinned GC root",
            ));
        }
        let visible_parent =
            open_parent_from(&visible_root, parent_path, NewFileMode::Private, false)?;
        if directory_identity(&visible_parent)? != parent_identity {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "visible repository GC parent no longer matches the pinned directory",
            ));
        }
        Ok(())
    }

    fn file_identity(file: &File) -> io::Result<(u64, u64)> {
        let metadata = file.metadata()?;
        Ok((metadata.dev(), metadata.ino()))
    }

    fn restore_leaf(parent: &File, quarantine: &OsStr, original: &OsStr) -> io::Result<()> {
        rename_leaf_noreplace(parent, quarantine, original)
    }

    fn recover_failed_begin_quarantine(
        parent: &File,
        quarantine: &OsStr,
        original: &OsStr,
        expected: (u64, u64),
        source: io::Error,
    ) -> RepositoryGcError {
        let mut restored = false;
        let recovery = (|| {
            let current = open_regular_leaf(parent, quarantine)?;
            if file_identity(&current)? != expected {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "repository GC quarantine changed before failed-begin recovery",
                ));
            }
            drop(current);
            restore_leaf(parent, quarantine, original)?;
            restored = true;
            let original = open_regular_leaf(parent, original)?;
            if file_identity(&original)? != expected {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "repository GC original changed during failed-begin recovery",
                ));
            }
            parent.sync_all()
        })();
        match recovery {
            Ok(()) => RepositoryGcError::new(RepositoryGcCommit::Restored, source),
            Err(recovery) => {
                let commit = if restored {
                    RepositoryGcCommit::Restored
                } else {
                    RepositoryGcCommit::Indeterminate
                };
                let source_kind = source.kind();
                RepositoryGcError::new(
                    commit,
                    io::Error::new(
                        source_kind,
                        format!(
                            "repository GC begin failed after quarantine ({source}); recovery failed: {recovery}"
                        ),
                    ),
                )
            }
        }
    }

    fn restore_after_delete_precondition_failure(
        quarantine: PrivateQuarantine,
        validation: io::Error,
    ) -> Result<(), RepositoryGcError> {
        match quarantine.restore() {
            Ok(()) => Err(RepositoryGcError::new(
                RepositoryGcCommit::Restored,
                validation,
            )),
            Err(restore) => {
                let commit = restore.commit();
                let restore = restore.into_source();
                let validation_kind = validation.kind();
                Err(RepositoryGcError::new(
                    commit,
                    io::Error::new(
                        validation_kind,
                        format!(
                            "repository GC delete precondition failed ({validation}); recovery failed: {restore}"
                        ),
                    ),
                ))
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[allow(unsafe_code)]
    fn rename_leaf_noreplace(parent: &File, source: &OsStr, target: &OsStr) -> io::Result<()> {
        use std::ffi::CString;

        validate_quarantine_names(source, target)?;
        let source = CString::new(source.as_bytes()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "repository GC source contains a NUL byte",
            )
        })?;
        let target = CString::new(target.as_bytes()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "repository GC target contains a NUL byte",
            )
        })?;
        // `nix::renameat2` is intentionally unavailable on musl even though the Linux syscall is
        // part of the supported kernel ABI. Calling that ABI directly preserves the same atomic
        // RENAME_NOREPLACE contract on glibc and musl without a check-then-rename fallback.
        const LINUX_RENAME_NOREPLACE: nix::libc::c_uint = 1;
        // SAFETY: both names are NUL-terminated single leaves, the same live directory descriptor
        // is used on each side, and SYS_renameat2 has the documented five-argument Linux ABI.
        let status = unsafe {
            nix::libc::syscall(
                nix::libc::SYS_renameat2,
                parent.as_raw_fd(),
                source.as_ptr(),
                parent.as_raw_fd(),
                target.as_ptr(),
                LINUX_RENAME_NOREPLACE,
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(exclusive_rename_io_error(io::Error::last_os_error()))
        }
    }

    #[cfg(target_os = "macos")]
    #[allow(unsafe_code)]
    fn rename_leaf_noreplace(parent: &File, source: &OsStr, target: &OsStr) -> io::Result<()> {
        use std::ffi::CString;

        validate_quarantine_names(source, target)?;
        let source = CString::new(source.as_bytes()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "repository GC source contains a NUL byte",
            )
        })?;
        let target = CString::new(target.as_bytes()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "repository GC target contains a NUL byte",
            )
        })?;
        // SAFETY: both names are NUL-terminated single leaves and the same live directory
        // descriptor is used for source and destination.
        let status = unsafe {
            nix::libc::renameatx_np(
                parent.as_raw_fd(),
                source.as_ptr(),
                parent.as_raw_fd(),
                target.as_ptr(),
                nix::libc::RENAME_EXCL,
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(exclusive_rename_io_error(io::Error::last_os_error()))
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn rename_leaf_noreplace(_parent: &File, _source: &OsStr, _target: &OsStr) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "repository GC requires an atomic no-replace rename primitive on this Unix platform",
        ))
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn exclusive_rename_io_error(error: io::Error) -> io::Error {
        match error.raw_os_error() {
            Some(code)
                if code == nix::libc::ENOSYS
                    || code == nix::libc::ENOTSUP
                    || code == nix::libc::EOPNOTSUPP
                    || code == nix::libc::EINVAL =>
            {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "the filesystem does not support atomic exclusive repository GC renames",
                )
            }
            _ => error,
        }
    }

    fn not_changed_gc(source: io::Error) -> RepositoryGcError {
        RepositoryGcError::new(RepositoryGcCommit::NotChanged, source)
    }

    fn not_committed(source: io::Error) -> RepositoryWriteError {
        RepositoryWriteError::new(RepositoryWriteCommit::NotCommitted, source)
    }

    const fn commit_state(committed: bool) -> RepositoryWriteCommit {
        if committed {
            RepositoryWriteCommit::CommittedUnverified
        } else {
            RepositoryWriteCommit::NotCommitted
        }
    }

    fn split_target(relative: &Path) -> io::Result<(&Path, &OsStr)> {
        let parent = relative.parent().unwrap_or_else(|| Path::new(""));
        let leaf = relative.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "repository write target has no file name",
            )
        })?;
        Ok((parent, leaf))
    }

    fn open_directory(parent: &File, segment: &OsStr) -> io::Result<File> {
        openat(
            parent,
            Path::new(segment),
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| match error {
            Errno::ELOOP | Errno::ENOTDIR => io::Error::new(
                io::ErrorKind::PermissionDenied,
                "repository path ancestor is a symbolic link or not a directory",
            ),
            error => errno_to_io(error),
        })
    }

    fn open_listing_directory(parent: &File, segment: &OsStr) -> io::Result<File> {
        open_directory(parent, segment)
    }

    fn reopen_listing_root(directory: &File) -> io::Result<File> {
        directory.try_clone()
    }

    fn open_root_directory(path: &Path) -> io::Result<File> {
        open(
            path,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(errno_to_io)
    }

    fn read_target_bounded(
        parent: &File,
        leaf: &OsStr,
        max_bytes: usize,
    ) -> io::Result<Option<Vec<u8>>> {
        Ok(
            match read_target_bounded_with_identity(parent, leaf, max_bytes)? {
                ReadTargetObservation::Missing => None,
                ReadTargetObservation::Present { bytes, .. } => Some(bytes),
            },
        )
    }

    fn open_read_leaf(parent: &File, leaf: &OsStr) -> io::Result<Option<File>> {
        let descriptor = match openat(
            parent,
            Path::new(leaf),
            OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        ) {
            Ok(descriptor) => descriptor,
            Err(Errno::ENOENT) => return Ok(None),
            Err(Errno::ELOOP | Errno::ENOTDIR) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "repository target is a symbolic link or has an invalid file kind",
                ));
            }
            Err(error) => return Err(errno_to_io(error)),
        };
        let file = File::from(descriptor);
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "repository target is not a regular file",
            ));
        }
        Ok(Some(file))
    }

    fn read_target_bounded_with_identity(
        parent: &File,
        leaf: &OsStr,
        max_bytes: usize,
    ) -> io::Result<ReadTargetObservation> {
        let Some(mut file) = open_read_leaf(parent, leaf)? else {
            return Ok(ReadTargetObservation::Missing);
        };
        let metadata = file.metadata()?;
        let max_bytes_u64 = u64::try_from(max_bytes).unwrap_or(u64::MAX);
        if metadata.len() > max_bytes_u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "repository target exceeds its bounded regular-file contract",
            ));
        }
        let capacity =
            usize::try_from(metadata.len()).map_or(max_bytes, |size| size.min(max_bytes));
        let mut bytes = Vec::with_capacity(capacity);
        std::io::Read::by_ref(&mut file)
            .take(max_bytes_u64.saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() > max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "repository target grew beyond its bounded read limit",
            ));
        }
        Ok(ReadTargetObservation::Present {
            bytes,
            identity: (metadata.dev(), metadata.ino()),
            _object: file,
        })
    }

    fn existing_target_mode(
        parent: &File,
        leaf: &OsStr,
        file_mode: NewFileMode,
    ) -> io::Result<Option<u32>> {
        match fstatat(parent, Path::new(leaf), AtFlags::AT_SYMLINK_NOFOLLOW) {
            Ok(status) => {
                let kind = SFlag::from_bits_truncate(status.st_mode);
                if kind != SFlag::S_IFREG {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "atomic repository write target is not a regular file",
                    ));
                }
                Ok(match file_mode {
                    NewFileMode::Default => Some((u64::from(status.st_mode) & 0o7777) as u32),
                    NewFileMode::Private => None,
                })
            }
            Err(Errno::ENOENT) => Ok(None),
            Err(error) => Err(errno_to_io(error)),
        }
    }

    fn create_temporary(parent: &File, mode: NewFileMode) -> io::Result<(File, OsString)> {
        let permissions = match mode {
            NewFileMode::Default => Mode::from_bits_truncate(0o666),
            NewFileMode::Private => Mode::from_bits_truncate(0o600),
        };
        for _ in 0..TEMPORARY_NAME_ATTEMPTS {
            let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let name = OsString::from(format!(
                ".{CLI_NAME}-tmp-{}-{sequence:016x}",
                std::process::id()
            ));
            match openat(
                parent,
                Path::new(&name),
                OFlag::O_WRONLY
                    | OFlag::O_CREAT
                    | OFlag::O_EXCL
                    | OFlag::O_NOFOLLOW
                    | OFlag::O_CLOEXEC,
                permissions,
            ) {
                Ok(descriptor) => return Ok((File::from(descriptor), name)),
                Err(Errno::EEXIST) => {}
                Err(error) => return Err(errno_to_io(error)),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique repository temporary file",
        ))
    }

    fn directory_identity(directory: &File) -> io::Result<(u64, u64)> {
        let metadata = directory.metadata()?;
        Ok((metadata.dev(), metadata.ino()))
    }

    fn errno_to_io(error: Errno) -> io::Error {
        io::Error::from_raw_os_error(error as i32)
    }
}

#[cfg(windows)]
mod platform {
    #![allow(unsafe_code)]

    use std::ffi::{OsStr, OsString, c_void};
    use std::fs::File;
    use std::io::{self, Read as _, Write as _};
    use std::mem::{offset_of, size_of, size_of_val};
    use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
    use std::path::{Component, Path, PathBuf};
    use std::ptr;
    use std::sync::atomic::{AtomicU64, Ordering};

    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
        FILE_OPEN_REPARSE_POINT, FILE_RENAME_INFORMATION, FILE_SYNCHRONOUS_IO_NONALERT,
        FileRenameInformation, NtCreateFile, NtSetInformationFile,
    };
    use windows_sys::Win32::Foundation::{
        ERROR_NO_MORE_FILES, HANDLE, INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE,
        RtlNtStatusToDosError, UNICODE_STRING,
    };
    use windows_sys::Win32::Security::SECURITY_DESCRIPTOR;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateFileW, DELETE, FILE_ATTRIBUTE_DEVICE,
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_ID_BOTH_DIR_INFO, FILE_ID_INFO,
        FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_TRAVERSE, FileDispositionInfo, FileIdBothDirectoryInfo,
        FileIdBothDirectoryRestartInfo, FileIdInfo, GetFileInformationByHandle,
        GetFileInformationByHandleEx, OPEN_EXISTING, READ_CONTROL, ReOpenFile, SYNCHRONIZE,
        SetFileInformationByHandle, WRITE_DAC,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    use forge_core::branding::CLI_NAME;

    use super::GcEvent;
    use super::{
        BeginPrivateQuarantine, CommitMode, ExpectedPreimage, NewFileMode, ReadEvent,
        RepositoryDirectoryEntry, RepositoryDirectoryEntryKind, RepositoryDirectoryListing,
        RepositoryGcCommit, RepositoryGcError, WriteEvent, directory_entry_limit_error,
    };
    use forge_core::ports::{RepositoryWriteCommit, RepositoryWriteError, RepositoryWriteOutcome};

    const TEMPORARY_NAME_ATTEMPTS: u64 = 128;
    static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[derive(Debug)]
    pub(crate) struct RootHandle {
        directory: File,
        path: PathBuf,
        identity: (u64, [u8; 16]),
    }

    /// One private file moved to a sibling quarantine name under a pinned parent directory.
    #[derive(Debug)]
    pub(crate) struct PrivateQuarantine {
        parent: File,
        parent_path: PathBuf,
        parent_identity: (u64, [u8; 16]),
        root_path: PathBuf,
        root_identity: (u64, [u8; 16]),
        original_leaf: OsString,
        quarantine_leaf: OsString,
        duplicate_original: bool,
        object: File,
    }

    struct ReadParentObservation {
        directory: File,
        _ancestors: Vec<File>,
        identities: Vec<(u64, [u8; 16])>,
        complete: bool,
    }

    enum ReadTargetObservation {
        Missing,
        Present {
            bytes: Vec<u8>,
            identity: (u64, [u8; 16]),
            _object: File,
        },
    }

    impl RootHandle {
        pub(crate) fn open(path: &Path) -> io::Result<Self> {
            let wide = nul_terminated(path.as_os_str())?;
            // SAFETY: the path is NUL-terminated and the returned handle is checked before its
            // ownership is transferred to `File`.
            let handle = unsafe {
                CreateFileW(
                    wide.as_ptr(),
                    FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    ptr::null(),
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                    ptr::null_mut(),
                )
            };
            if handle == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `handle` is a newly returned owned Win32 handle.
            let directory = unsafe { File::from_raw_handle(handle) };
            validate_kind(&directory, true)?;
            let identity = directory_identity(&directory)?;
            Ok(Self {
                directory,
                path: path.to_path_buf(),
                identity,
            })
        }

        pub(crate) fn validate_visible_root(&self) -> io::Result<()> {
            let visible = open_root_directory(&self.path)?;
            if directory_identity(&visible)? == self.identity {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "visible repository root no longer matches the pinned directory handle",
                ))
            }
        }

        pub(crate) fn write_atomic(
            &self,
            relative: &Path,
            bytes: &[u8],
            file_mode: NewFileMode,
            commit_mode: CommitMode,
            before_commit: impl FnOnce() -> io::Result<()>,
        ) -> io::Result<()> {
            let mut before_commit = Some(before_commit);
            self.write_atomic_inner(
                relative,
                bytes,
                file_mode,
                commit_mode,
                ExpectedPreimage::Any,
                0,
                |event| {
                    if event == WriteEvent::BeforeCommit {
                        return before_commit.take().map_or_else(
                            || {
                                Err(io::Error::other(
                                    "before-commit callback ran more than once",
                                ))
                            },
                            |callback| callback(),
                        );
                    }
                    Ok(())
                },
            )
            .map(|_| ())
            .map_err(RepositoryWriteError::into_source)
        }

        pub(crate) fn read_bounded(
            &self,
            relative: &Path,
            max_bytes: usize,
        ) -> io::Result<Option<Vec<u8>>> {
            self.read_bounded_inner(relative, max_bytes, |_| Ok(()))
        }

        pub(crate) fn validate_regular_from(
            &self,
            relative: &Path,
            expected_parent: &File,
            object: &File,
        ) -> io::Result<()> {
            let (parent_path, leaf) = split_target(relative)?;
            validate_kind(expected_parent, true)?;
            let parent_identity = directory_identity(expected_parent)?;
            validate_visible_root_and_parent(
                &self.path,
                self.identity,
                parent_path,
                parent_identity,
            )?;
            let current = open_read_leaf(expected_parent, leaf)?.ok_or_else(|| {
                read_namespace_changed("repository target disappeared under its pinned parent")
            })?;
            if file_identity(&current)? != file_identity(object)? {
                return Err(read_namespace_changed(
                    "repository target identity changed under its pinned parent",
                ));
            }
            validate_visible_root_and_parent(
                &self.path,
                self.identity,
                parent_path,
                parent_identity,
            )
        }

        pub(crate) fn open_regular_from(
            &self,
            relative: &Path,
            expected_parent: &File,
        ) -> io::Result<Option<File>> {
            let (parent_path, leaf) = split_target(relative)?;
            validate_kind(expected_parent, true)?;
            let parent_identity = directory_identity(expected_parent)?;
            validate_visible_root_and_parent(
                &self.path,
                self.identity,
                parent_path,
                parent_identity,
            )?;
            let current = open_read_leaf(expected_parent, leaf)?;
            validate_visible_root_and_parent(
                &self.path,
                self.identity,
                parent_path,
                parent_identity,
            )?;
            Ok(current)
        }

        pub(crate) fn open_listed_entry_from(
            &self,
            relative: &Path,
            expected_directory: &File,
            entry: &RepositoryDirectoryEntry,
        ) -> io::Result<File> {
            validate_kind(expected_directory, true)?;
            let expected_identity = directory_identity(expected_directory)?;
            validate_visible_root_and_parent(
                &self.path,
                self.identity,
                relative,
                expected_identity,
            )?;
            let current = match entry.kind {
                RepositoryDirectoryEntryKind::Directory => {
                    open_listing_directory(expected_directory, &entry.name)
                }
                RepositoryDirectoryEntryKind::RegularFile => {
                    open_read_leaf(expected_directory, &entry.name)?.ok_or_else(|| {
                        read_namespace_changed(
                            "repository listed entry disappeared under its pinned parent",
                        )
                    })
                }
            }?;
            if file_identity(&current)? != entry.identity {
                return Err(read_namespace_changed(
                    "repository listed entry identity changed under its pinned parent",
                ));
            }
            validate_visible_root_and_parent(
                &self.path,
                self.identity,
                relative,
                expected_identity,
            )?;
            Ok(current)
        }

        pub(crate) fn list_directory(
            &self,
            relative: &Path,
            max_entries: usize,
        ) -> io::Result<Option<RepositoryDirectoryListing>> {
            self.list_directory_inner(relative, None, max_entries, || Ok(()))
        }

        pub(crate) fn list_directory_from(
            &self,
            relative: &Path,
            expected: &File,
            max_entries: usize,
        ) -> io::Result<RepositoryDirectoryListing> {
            self.list_directory_inner(relative, Some(expected), max_entries, || Ok(()))?
                .ok_or_else(|| {
                    read_namespace_changed(
                        "repository directory disappeared after its pinned parent listing",
                    )
                })
        }

        fn list_directory_inner(
            &self,
            relative: &Path,
            expected: Option<&File>,
            max_entries: usize,
            hook: impl FnOnce() -> io::Result<()>,
        ) -> io::Result<Option<RepositoryDirectoryListing>> {
            let observation = open_directory_for_listing(&self.directory, relative)?;
            if !observation.complete {
                validate_directory_observation(
                    &self.directory,
                    &self.path,
                    self.identity,
                    relative,
                    &observation.identities,
                )?;
                if expected.is_some() {
                    return Err(read_namespace_changed(
                        "repository directory disappeared after its pinned parent listing",
                    ));
                }
                return Ok(Some(RepositoryDirectoryListing {
                    root: reopen_listing_root(&self.directory)?,
                    ancestors: observation._ancestors,
                    directory: observation.directory,
                    entries: Vec::new(),
                    opened_components: observation.identities.len(),
                    target_present: false,
                }));
            }
            let opened_components = observation.identities.len();
            let ancestors = observation._ancestors;
            let visible_identity = directory_identity(&observation.directory)?;
            let directory = if let Some(expected) = expected {
                if directory_identity(expected)? != visible_identity {
                    return Err(read_namespace_changed(
                        "repository directory identity changed after its parent listing",
                    ));
                }
                expected.try_clone()?
            } else {
                observation.directory
            };
            validate_kind(&directory, true)?;
            let expected_directory = directory_identity(&directory)?;
            let mut entries = Vec::new();
            let mut restart = true;
            loop {
                let mut buffer = [0_u64; 8_192];
                let information_class = if restart {
                    FileIdBothDirectoryRestartInfo
                } else {
                    FileIdBothDirectoryInfo
                };
                // SAFETY: the directory handle is live and `buffer` is aligned writable storage of
                // exactly the supplied byte length for this variable-size information class.
                let success = unsafe {
                    GetFileInformationByHandleEx(
                        directory.as_raw_handle(),
                        information_class,
                        buffer.as_mut_ptr().cast(),
                        size_of_val(&buffer) as u32,
                    )
                };
                if success == 0 {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
                        break;
                    }
                    return Err(error);
                }
                restart = false;
                let bytes = size_of_val(&buffer);
                let mut offset = 0_usize;
                loop {
                    let header = offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);
                    if offset.checked_add(header).is_none_or(|end| end > bytes) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Windows returned a truncated repository directory entry",
                        ));
                    }
                    // SAFETY: `offset` and the fixed header were bounds-checked above; the buffer
                    // has alignment suitable for this structure.
                    let information = unsafe {
                        &*buffer
                            .as_ptr()
                            .cast::<u8>()
                            .add(offset)
                            .cast::<FILE_ID_BOTH_DIR_INFO>()
                    };
                    let name_bytes = information.FileNameLength as usize;
                    if name_bytes % size_of::<u16>() != 0
                        || offset
                            .checked_add(header)
                            .and_then(|start| start.checked_add(name_bytes))
                            .is_none_or(|end| end > bytes)
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Windows returned an invalid repository directory filename",
                        ));
                    }
                    // SAFETY: the UTF-16 filename range was validated inside `buffer` above.
                    let name = unsafe {
                        std::slice::from_raw_parts(
                            buffer
                                .as_ptr()
                                .cast::<u8>()
                                .add(offset + header)
                                .cast::<u16>(),
                            name_bytes / size_of::<u16>(),
                        )
                    };
                    if name != [u16::from(b'.')].as_slice()
                        && name != [u16::from(b'.'), u16::from(b'.')].as_slice()
                    {
                        if entries.len() == max_entries {
                            return Err(directory_entry_limit_error());
                        }
                        let name = OsString::from_wide(name);
                        let attributes = information.FileAttributes;
                        if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                            return Err(super::unsupported_directory_entry_error(
                                name,
                                super::UnsupportedDirectoryEntryKind::LinkOrReparse,
                            ));
                        }
                        if attributes & FILE_ATTRIBUTE_DEVICE != 0 {
                            return Err(super::unsupported_directory_entry_error(
                                name,
                                super::UnsupportedDirectoryEntryKind::Other,
                            ));
                        }
                        let (kind, object) = if attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                            (
                                RepositoryDirectoryEntryKind::Directory,
                                open_listing_directory(&directory, &name)?,
                            )
                        } else {
                            let object = open_read_leaf(&directory, &name)?.ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::NotFound,
                                    "repository directory entry disappeared during listing",
                                )
                            })?;
                            (RepositoryDirectoryEntryKind::RegularFile, object)
                        };
                        let identity = file_identity(&object)?;
                        entries.push(RepositoryDirectoryEntry {
                            name,
                            kind,
                            identity,
                        });
                    }
                    if information.NextEntryOffset == 0 {
                        break;
                    }
                    let next = information.NextEntryOffset as usize;
                    offset = offset.checked_add(next).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Windows repository directory offset overflowed",
                        )
                    })?;
                    if offset >= bytes {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Windows returned an out-of-range repository directory offset",
                        ));
                    }
                }
            }
            hook()?;
            validate_visible_root_and_parent(
                &self.path,
                self.identity,
                relative,
                expected_directory,
            )?;
            validate_listed_entries(&directory, &entries)?;
            validate_visible_root_and_parent(
                &self.path,
                self.identity,
                relative,
                expected_directory,
            )?;
            Ok(Some(RepositoryDirectoryListing {
                root: reopen_listing_root(&self.directory)?,
                ancestors,
                directory,
                entries,
                opened_components,
                target_present: true,
            }))
        }

        #[cfg(test)]
        pub(super) fn read_bounded_with_hook(
            &self,
            relative: &Path,
            max_bytes: usize,
            hook: impl FnOnce(ReadEvent) -> io::Result<()>,
        ) -> io::Result<Option<Vec<u8>>> {
            self.read_bounded_inner(relative, max_bytes, hook)
        }

        fn read_bounded_inner(
            &self,
            relative: &Path,
            max_bytes: usize,
            hook: impl FnOnce(ReadEvent) -> io::Result<()>,
        ) -> io::Result<Option<Vec<u8>>> {
            let (parent_path, leaf) = split_target(relative)?;
            let parent = open_parent_for_read(&self.directory, parent_path)?;
            if !parent.complete {
                hook(ReadEvent::AfterObservation)?;
                validate_read_observation(
                    &self.directory,
                    &self.path,
                    self.identity,
                    parent_path,
                    &parent.identities,
                    leaf,
                    None,
                )?;
                return Ok(None);
            }
            let target = read_target_bounded_with_identity(&parent.directory, leaf, max_bytes)?;
            hook(ReadEvent::AfterObservation)?;
            let expected_leaf = match &target {
                ReadTargetObservation::Missing => None,
                ReadTargetObservation::Present { identity, .. } => Some(*identity),
            };
            validate_read_observation(
                &self.directory,
                &self.path,
                self.identity,
                parent_path,
                &parent.identities,
                leaf,
                expected_leaf,
            )?;
            Ok(match target {
                ReadTargetObservation::Missing => None,
                ReadTargetObservation::Present { bytes, .. } => Some(bytes),
            })
        }

        #[cfg(test)]
        pub(crate) fn begin_private_quarantine(
            &self,
            relative: &Path,
            quarantine_leaf: &OsStr,
        ) -> Result<BeginPrivateQuarantine, RepositoryGcError> {
            self.begin_private_quarantine_inner(relative, quarantine_leaf, None, |_| Ok(()))
        }

        pub(crate) fn begin_private_quarantine_from(
            &self,
            relative: &Path,
            expected_parent: &File,
            quarantine_leaf: &OsStr,
        ) -> Result<BeginPrivateQuarantine, RepositoryGcError> {
            self.begin_private_quarantine_inner(
                relative,
                quarantine_leaf,
                Some(expected_parent),
                |_| Ok(()),
            )
        }

        #[cfg(test)]
        pub(super) fn begin_private_quarantine_with_hook(
            &self,
            relative: &Path,
            quarantine_leaf: &OsStr,
            hook: impl FnMut(GcEvent) -> io::Result<()>,
        ) -> Result<BeginPrivateQuarantine, RepositoryGcError> {
            self.begin_private_quarantine_inner(relative, quarantine_leaf, None, hook)
        }

        fn begin_private_quarantine_inner(
            &self,
            relative: &Path,
            quarantine_leaf: &OsStr,
            expected_parent: Option<&File>,
            mut hook: impl FnMut(GcEvent) -> io::Result<()>,
        ) -> Result<BeginPrivateQuarantine, RepositoryGcError> {
            let (parent_path, original_leaf) = split_target(relative)
                .and_then(|parts| {
                    validate_quarantine_names(parts.1, quarantine_leaf).map(|()| parts)
                })
                .map_err(not_changed_gc)?;
            let parent = if let Some(expected_parent) = expected_parent {
                validate_kind(expected_parent, true).map_err(not_changed_gc)?;
                let expected_identity =
                    directory_identity(expected_parent).map_err(not_changed_gc)?;
                validate_visible_root_and_parent(
                    &self.path,
                    self.identity,
                    parent_path,
                    expected_identity,
                )
                .map_err(not_changed_gc)?;
                expected_parent.try_clone().map_err(not_changed_gc)?
            } else {
                match self.open_parent(parent_path, NewFileMode::Private, false) {
                    Ok(parent) => parent,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        return Ok(BeginPrivateQuarantine::Missing);
                    }
                    Err(error) => return Err(not_changed_gc(error)),
                }
            };
            let parent_identity = directory_identity(&parent).map_err(not_changed_gc)?;
            let object = match open_gc_regular_leaf(&parent, original_leaf) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    return Ok(BeginPrivateQuarantine::Missing);
                }
                Err(error) => return Err(not_changed_gc(error)),
            };
            let object_identity = file_identity(&object).map_err(not_changed_gc)?;

            hook(GcEvent::BeforeBeginRename).map_err(not_changed_gc)?;
            validate_visible_root_and_parent(
                &self.path,
                self.identity,
                parent_path,
                parent_identity,
            )
            .map_err(not_changed_gc)?;
            rename_handle_relative(&object, quarantine_leaf, false).map_err(not_changed_gc)?;
            let post_rename = (|| {
                hook(GcEvent::AfterBeginRename)?;
                let reopened = open_gc_regular_leaf(&parent, quarantine_leaf)?;
                if file_identity(&reopened)? != object_identity {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "repository GC source changed during quarantine rename",
                    ));
                }
                drop(reopened);
                validate_visible_root_and_parent(
                    &self.path,
                    self.identity,
                    parent_path,
                    parent_identity,
                )
            })();
            if let Err(source) = post_rename {
                return Err(recover_failed_begin_quarantine(
                    &parent,
                    &object,
                    quarantine_leaf,
                    original_leaf,
                    object_identity,
                    source,
                ));
            }

            Ok(BeginPrivateQuarantine::Quarantined(PrivateQuarantine {
                parent,
                parent_path: parent_path.to_path_buf(),
                parent_identity,
                root_path: self.path.clone(),
                root_identity: self.identity,
                original_leaf: original_leaf.to_os_string(),
                quarantine_leaf: quarantine_leaf.to_os_string(),
                duplicate_original: false,
                object,
            }))
        }

        #[cfg(test)]
        pub(crate) fn open_private_quarantine(
            &self,
            directory: &Path,
            original_leaf: &OsStr,
            quarantine_leaf: &OsStr,
        ) -> Result<super::OpenPrivateQuarantine, RepositoryGcError> {
            self.open_private_quarantine_inner(directory, original_leaf, quarantine_leaf, None)
        }

        pub(crate) fn open_private_quarantine_from(
            &self,
            directory: &Path,
            expected_parent: &File,
            original_leaf: &OsStr,
            quarantine_leaf: &OsStr,
        ) -> Result<super::OpenPrivateQuarantine, RepositoryGcError> {
            self.open_private_quarantine_inner(
                directory,
                original_leaf,
                quarantine_leaf,
                Some(expected_parent),
            )
        }

        fn open_private_quarantine_inner(
            &self,
            directory: &Path,
            original_leaf: &OsStr,
            quarantine_leaf: &OsStr,
            expected_parent: Option<&File>,
        ) -> Result<super::OpenPrivateQuarantine, RepositoryGcError> {
            validate_parent_path(directory).map_err(not_changed_gc)?;
            validate_quarantine_names(original_leaf, quarantine_leaf).map_err(not_changed_gc)?;
            let parent = if let Some(expected_parent) = expected_parent {
                validate_kind(expected_parent, true).map_err(not_changed_gc)?;
                let expected_identity =
                    directory_identity(expected_parent).map_err(not_changed_gc)?;
                validate_visible_root_and_parent(
                    &self.path,
                    self.identity,
                    directory,
                    expected_identity,
                )
                .map_err(not_changed_gc)?;
                expected_parent.try_clone().map_err(not_changed_gc)?
            } else {
                match self.open_parent(directory, NewFileMode::Private, false) {
                    Ok(parent) => parent,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        return Ok(super::OpenPrivateQuarantine::Missing);
                    }
                    Err(error) => return Err(not_changed_gc(error)),
                }
            };
            let parent_identity = directory_identity(&parent).map_err(not_changed_gc)?;
            let object = match open_gc_regular_leaf(&parent, quarantine_leaf) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    return Ok(super::OpenPrivateQuarantine::Missing);
                }
                Err(error) => return Err(not_changed_gc(error)),
            };
            let object_identity = file_identity(&object).map_err(not_changed_gc)?;
            let duplicate_original = match open_gc_regular_leaf(&parent, original_leaf) {
                Ok(original) => {
                    if file_identity(&original).map_err(not_changed_gc)? != object_identity {
                        return Err(not_changed_gc(io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            "repository GC recovery found different objects at the original and quarantine names",
                        )));
                    }
                    true
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => false,
                Err(error) => return Err(not_changed_gc(error)),
            };

            let quarantine = PrivateQuarantine {
                parent,
                parent_path: directory.to_path_buf(),
                parent_identity,
                root_path: self.path.clone(),
                root_identity: self.identity,
                original_leaf: original_leaf.to_os_string(),
                quarantine_leaf: quarantine_leaf.to_os_string(),
                duplicate_original,
                object,
            };
            Ok(if duplicate_original {
                super::OpenPrivateQuarantine::DuplicateSameIdentity(quarantine)
            } else {
                super::OpenPrivateQuarantine::QuarantineOnly(quarantine)
            })
        }

        pub(crate) fn write_atomic_if_unchanged(
            &self,
            relative: &Path,
            expected: Option<&[u8]>,
            bytes: &[u8],
            max_postimage_bytes: usize,
        ) -> Result<RepositoryWriteOutcome, RepositoryWriteError> {
            let commit_mode = if expected.is_some() {
                CommitMode::Replace
            } else {
                CommitMode::CreateNew
            };
            self.write_atomic_inner(
                relative,
                bytes,
                NewFileMode::Default,
                commit_mode,
                ExpectedPreimage::Exact(expected),
                max_postimage_bytes,
                |_| Ok(()),
            )
        }

        #[cfg(test)]
        pub(crate) fn write_atomic_if_unchanged_with_hook(
            &self,
            relative: &Path,
            expected: Option<&[u8]>,
            bytes: &[u8],
            max_postimage_bytes: usize,
            mut hook: impl FnMut(WriteEvent) -> io::Result<()>,
        ) -> Result<RepositoryWriteOutcome, RepositoryWriteError> {
            let commit_mode = if expected.is_some() {
                CommitMode::Replace
            } else {
                CommitMode::CreateNew
            };
            self.write_atomic_inner(
                relative,
                bytes,
                NewFileMode::Default,
                commit_mode,
                ExpectedPreimage::Exact(expected),
                max_postimage_bytes,
                &mut hook,
            )
        }

        #[allow(clippy::too_many_arguments)]
        fn write_atomic_inner(
            &self,
            relative: &Path,
            bytes: &[u8],
            file_mode: NewFileMode,
            commit_mode: CommitMode,
            expected: ExpectedPreimage<'_>,
            max_postimage_bytes: usize,
            mut hook: impl FnMut(WriteEvent) -> io::Result<()>,
        ) -> Result<RepositoryWriteOutcome, RepositoryWriteError> {
            hook(WriteEvent::BeforeParentOpen).map_err(not_committed)?;
            let (parent_path, leaf) = split_target(relative).map_err(not_committed)?;
            let parent = self
                .open_parent(parent_path, file_mode, true)
                .map_err(not_committed)?;
            let original_parent_identity = directory_identity(&parent).map_err(not_committed)?;
            if let ExpectedPreimage::Exact(expected) = expected {
                let observed = read_target_bounded(&parent, leaf, max_postimage_bytes)
                    .map_err(not_committed)?;
                if observed.as_deref() != expected {
                    return Ok(RepositoryWriteOutcome::PreconditionMismatch);
                }
            }
            hook(WriteEvent::AfterPrewriteRead).map_err(not_committed)?;
            let existing_permissions =
                existing_target_permissions(&parent, leaf, file_mode).map_err(not_committed)?;
            let (mut temporary, _temporary_name) =
                create_temporary(&parent, file_mode).map_err(not_committed)?;
            let diagnostic_path = relative.to_path_buf();
            let mut committed = false;

            let result = (|| {
                temporary.write_all(bytes)?;
                temporary.flush()?;
                if let Some(permissions) = existing_permissions {
                    temporary.set_permissions(permissions)?;
                }
                if matches!(file_mode, NewFileMode::Private) {
                    crate::state::harden_private_repository_file(&temporary, &diagnostic_path)?;
                }
                temporary.sync_all()?;
                if let ExpectedPreimage::Exact(expected) = expected {
                    let observed = read_target_bounded(&parent, leaf, max_postimage_bytes)?;
                    if observed.as_deref() != expected {
                        return Ok(RepositoryWriteOutcome::PreconditionMismatch);
                    }
                }
                hook(WriteEvent::BeforeCommit)?;
                rename_handle_relative(
                    &temporary,
                    leaf,
                    matches!(commit_mode, CommitMode::Replace),
                )?;
                committed = true;
                hook(WriteEvent::AfterCommit)?;

                let visible_parent = self.open_parent(parent_path, file_mode, false)?;
                if directory_identity(&visible_parent)? != original_parent_identity {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "repository target parent changed during atomic write",
                    ));
                }
                let visible_root = open_root_directory(&self.path)?;
                if directory_identity(&visible_root)? != self.identity {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "repository root changed during atomic write",
                    ));
                }
                let observed = match expected {
                    ExpectedPreimage::Any => None,
                    ExpectedPreimage::Exact(_) => {
                        read_target_bounded(&parent, leaf, max_postimage_bytes)?
                    }
                };
                Ok(RepositoryWriteOutcome::Written { observed })
            })();

            if !committed && !matches!(&result, Ok(RepositoryWriteOutcome::Written { .. })) {
                if let Err(cleanup) = mark_delete_on_close(&temporary) {
                    return Err(RepositoryWriteError::new(
                        commit_state(committed),
                        io::Error::other(format!(
                            "atomic repository write failed and its Windows temporary file could not be removed: {cleanup}"
                        )),
                    ));
                }
            }
            result.map_err(|source| RepositoryWriteError::new(commit_state(committed), source))
        }

        fn open_parent(
            &self,
            relative: &Path,
            mode: NewFileMode,
            create: bool,
        ) -> io::Result<File> {
            open_parent_from(&self.directory, relative, mode, create)
        }
    }

    impl PrivateQuarantine {
        pub(crate) fn object_file(&mut self) -> &mut File {
            &mut self.object
        }

        pub(crate) fn validate_visible_root_and_parent(&self) -> io::Result<()> {
            validate_visible_root_and_parent(
                &self.root_path,
                self.root_identity,
                &self.parent_path,
                self.parent_identity,
            )
        }

        pub(crate) fn restore(self) -> Result<(), RepositoryGcError> {
            let expected = file_identity(&self.object)
                .map_err(|error| RepositoryGcError::new(RepositoryGcCommit::Quarantined, error))?;
            let current =
                open_gc_regular_leaf(&self.parent, &self.quarantine_leaf).map_err(|error| {
                    RepositoryGcError::new(RepositoryGcCommit::Indeterminate, error)
                })?;
            if file_identity(&current)
                .map_err(|error| RepositoryGcError::new(RepositoryGcCommit::Indeterminate, error))?
                != expected
            {
                return Err(RepositoryGcError::new(
                    RepositoryGcCommit::Indeterminate,
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "repository GC quarantine changed before restoration",
                    ),
                ));
            }
            drop(current);
            rename_handle_relative(&self.object, &self.original_leaf, false)
                .map_err(|error| RepositoryGcError::new(RepositoryGcCommit::Quarantined, error))?;
            let restored = open_gc_regular_leaf(&self.parent, &self.original_leaf)
                .map_err(|error| RepositoryGcError::new(RepositoryGcCommit::Restored, error))?;
            if file_identity(&restored)
                .map_err(|error| RepositoryGcError::new(RepositoryGcCommit::Restored, error))?
                != expected
            {
                return Err(RepositoryGcError::new(
                    RepositoryGcCommit::Indeterminate,
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "repository GC restored name does not identify the quarantined object",
                    ),
                ));
            }
            self.validate_visible_root_and_parent()
                .map_err(|error| RepositoryGcError::new(RepositoryGcCommit::Restored, error))
        }

        pub(crate) fn delete(self) -> Result<(), RepositoryGcError> {
            if let Err(validation) = self.validate_visible_root_and_parent() {
                if self.duplicate_original {
                    return Err(RepositoryGcError::new(
                        RepositoryGcCommit::Indeterminate,
                        validation,
                    ));
                }
                return restore_after_delete_precondition_failure(self, validation);
            }
            let expected = file_identity(&self.object)
                .map_err(|error| RepositoryGcError::new(RepositoryGcCommit::Quarantined, error))?;
            let current =
                open_gc_regular_leaf(&self.parent, &self.quarantine_leaf).map_err(|error| {
                    RepositoryGcError::new(RepositoryGcCommit::Indeterminate, error)
                })?;
            if file_identity(&current)
                .map_err(|error| RepositoryGcError::new(RepositoryGcCommit::Indeterminate, error))?
                != expected
            {
                return Err(RepositoryGcError::new(
                    RepositoryGcCommit::Indeterminate,
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "repository GC quarantine changed before deletion",
                    ),
                ));
            }
            if self.duplicate_original {
                let original =
                    open_gc_regular_leaf(&self.parent, &self.original_leaf).map_err(|error| {
                        RepositoryGcError::new(RepositoryGcCommit::Indeterminate, error)
                    })?;
                if file_identity(&original).map_err(|error| {
                    RepositoryGcError::new(RepositoryGcCommit::Indeterminate, error)
                })? != expected
                {
                    return Err(RepositoryGcError::new(
                        RepositoryGcCommit::Indeterminate,
                        io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "repository GC duplicate original changed before quarantine cleanup",
                        ),
                    ));
                }
            }
            drop(current);

            let PrivateQuarantine {
                parent,
                parent_path,
                parent_identity,
                root_path,
                root_identity,
                original_leaf: _,
                quarantine_leaf,
                duplicate_original: _,
                object,
            } = self;
            mark_delete_on_close(&object)
                .map_err(|error| RepositoryGcError::new(RepositoryGcCommit::Quarantined, error))?;
            drop(object);
            match open_gc_regular_leaf(&parent, &quarantine_leaf) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Ok(remaining) => {
                    drop(remaining);
                    return Err(RepositoryGcError::new(
                        RepositoryGcCommit::Indeterminate,
                        io::Error::other(
                            "Windows repository GC quarantine remained visible after deletion",
                        ),
                    ));
                }
                Err(error) => {
                    return Err(RepositoryGcError::new(
                        RepositoryGcCommit::Indeterminate,
                        error,
                    ));
                }
            }
            validate_visible_root_and_parent(
                &root_path,
                root_identity,
                &parent_path,
                parent_identity,
            )
            .map_err(|error| RepositoryGcError::new(RepositoryGcCommit::Deleted, error))
        }
    }

    fn open_parent_from(
        root: &File,
        relative: &Path,
        mode: NewFileMode,
        create: bool,
    ) -> io::Result<File> {
        validate_parent_path(relative)?;
        let mut current = root.try_clone()?;
        for component in relative.components() {
            let Component::Normal(segment) = component else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "repository parent path was not normalized",
                ));
            };
            current = match open_directory(&current, segment, FILE_OPEN, false) {
                Ok(directory) => directory,
                Err(error) if create && error.kind() == io::ErrorKind::NotFound => {
                    match open_directory(
                        &current,
                        segment,
                        FILE_CREATE,
                        matches!(mode, NewFileMode::Private),
                    ) {
                        Ok(directory) => {
                            if matches!(mode, NewFileMode::Private) {
                                if let Err(error) =
                                    crate::state::harden_private_repository_directory(
                                        &directory,
                                        Path::new(segment),
                                    )
                                {
                                    let _cleanup = mark_delete_on_close(&directory);
                                    return Err(error);
                                }
                            }
                            directory
                        }
                        Err(create_error)
                            if create_error.kind() == io::ErrorKind::AlreadyExists =>
                        {
                            open_directory(&current, segment, FILE_OPEN, false)?
                        }
                        Err(create_error) => return Err(create_error),
                    }
                }
                Err(error) => return Err(error),
            };
        }
        Ok(current)
    }

    fn open_parent_for_read(root: &File, relative: &Path) -> io::Result<ReadParentObservation> {
        validate_parent_path(relative)?;
        let mut chain = Vec::new();
        let mut identities = Vec::new();
        for component in relative.components() {
            let Component::Normal(segment) = component else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "repository parent path was not normalized",
                ));
            };
            let current = chain.last().unwrap_or(root);
            match open_directory(current, segment, FILE_OPEN, false) {
                Ok(directory) => {
                    identities.push(directory_identity(&directory)?);
                    chain.push(directory);
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    return finish_read_parent_observation(root, chain, identities, false);
                }
                Err(error) => return Err(error),
            }
        }
        finish_read_parent_observation(root, chain, identities, true)
    }

    fn open_directory_for_listing(
        root: &File,
        relative: &Path,
    ) -> io::Result<ReadParentObservation> {
        validate_parent_path(relative)?;
        if relative.as_os_str().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Windows confined directory listing requires a named directory",
            ));
        }
        let mut chain = Vec::new();
        let mut identities = Vec::new();
        let mut components = relative.components().peekable();
        while let Some(component) = components.next() {
            let Component::Normal(segment) = component else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "repository directory path was not normalized",
                ));
            };
            let current = chain.last().unwrap_or(root);
            let opened = if components.peek().is_none() {
                open_listing_directory(current, segment)
            } else {
                open_listing_ancestor_directory(current, segment)
            };
            match opened {
                Ok(directory) => {
                    identities.push(directory_identity(&directory)?);
                    chain.push(directory);
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    return finish_read_parent_observation(root, chain, identities, false);
                }
                Err(error) => return Err(error),
            }
        }
        finish_read_parent_observation(root, chain, identities, true)
    }

    fn finish_read_parent_observation(
        root: &File,
        mut chain: Vec<File>,
        identities: Vec<(u64, [u8; 16])>,
        complete: bool,
    ) -> io::Result<ReadParentObservation> {
        let directory = match chain.pop() {
            Some(directory) => directory,
            None => root.try_clone()?,
        };
        Ok(ReadParentObservation {
            directory,
            _ancestors: chain,
            identities,
            complete,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_read_observation(
        pinned_root: &File,
        root_path: &Path,
        root_identity: (u64, [u8; 16]),
        parent_path: &Path,
        parent_identities: &[(u64, [u8; 16])],
        leaf: &OsStr,
        expected_leaf: Option<(u64, [u8; 16])>,
    ) -> io::Result<()> {
        validate_pinned_read_root(pinned_root, root_identity)?;
        let visible_root = open_visible_read_root(root_path, root_identity)?;
        let mut chain = Vec::new();
        for (index, component) in parent_path.components().enumerate() {
            let Component::Normal(segment) = component else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "repository parent path was not normalized",
                ));
            };
            let current = chain.last().unwrap_or(&visible_root);
            let directory = match open_directory(current, segment, FILE_OPEN, false) {
                Ok(directory) => directory,
                Err(error)
                    if index == parent_identities.len()
                        && error.kind() == io::ErrorKind::NotFound =>
                {
                    validate_pinned_read_root(pinned_root, root_identity)?;
                    open_visible_read_root(root_path, root_identity)?;
                    return Ok(());
                }
                Err(error) => {
                    return Err(read_namespace_changed(format!(
                        "repository parent changed during bounded read: {error}"
                    )));
                }
            };
            let Some(expected) = parent_identities.get(index) else {
                return Err(read_namespace_changed(
                    "a previously missing repository parent appeared during bounded read",
                ));
            };
            if directory_identity(&directory)? != *expected {
                return Err(read_namespace_changed(
                    "repository parent identity changed during bounded read",
                ));
            }
            chain.push(directory);
        }

        if chain.len() != parent_identities.len() {
            return Err(read_namespace_changed(
                "repository parent observation was inconsistent during bounded read",
            ));
        }
        let visible_parent = chain.last().unwrap_or(&visible_root);
        validate_read_leaf(visible_parent, leaf, expected_leaf)?;
        validate_pinned_read_root(pinned_root, root_identity)?;
        open_visible_read_root(root_path, root_identity)?;
        Ok(())
    }

    fn validate_directory_observation(
        pinned_root: &File,
        root_path: &Path,
        root_identity: (u64, [u8; 16]),
        relative: &Path,
        identities: &[(u64, [u8; 16])],
    ) -> io::Result<()> {
        validate_pinned_read_root(pinned_root, root_identity)?;
        let visible_root = open_visible_read_root(root_path, root_identity)?;
        let mut chain = Vec::new();
        for (index, component) in relative.components().enumerate() {
            let Component::Normal(segment) = component else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "repository directory path was not normalized",
                ));
            };
            let current = chain.last().unwrap_or(&visible_root);
            let directory = match open_directory(current, segment, FILE_OPEN, false) {
                Ok(directory) => directory,
                Err(error)
                    if index == identities.len() && error.kind() == io::ErrorKind::NotFound =>
                {
                    validate_pinned_read_root(pinned_root, root_identity)?;
                    open_visible_read_root(root_path, root_identity)?;
                    return Ok(());
                }
                Err(error) => {
                    return Err(read_namespace_changed(format!(
                        "repository directory changed during listing: {error}"
                    )));
                }
            };
            let Some(expected) = identities.get(index) else {
                return Err(read_namespace_changed(
                    "a previously missing repository directory appeared during listing",
                ));
            };
            if directory_identity(&directory)? != *expected {
                return Err(read_namespace_changed(
                    "repository directory identity changed during listing",
                ));
            }
            chain.push(directory);
        }
        if chain.len() != identities.len() {
            return Err(read_namespace_changed(
                "repository directory observation was inconsistent during listing",
            ));
        }
        validate_pinned_read_root(pinned_root, root_identity)?;
        open_visible_read_root(root_path, root_identity)?;
        Ok(())
    }

    fn validate_pinned_read_root(root: &File, expected: (u64, [u8; 16])) -> io::Result<()> {
        if directory_identity(root)? == expected {
            Ok(())
        } else {
            Err(read_namespace_changed(
                "pinned repository root identity changed during bounded read",
            ))
        }
    }

    fn open_visible_read_root(path: &Path, expected: (u64, [u8; 16])) -> io::Result<File> {
        let visible = open_root_directory(path).map_err(|error| {
            read_namespace_changed(format!(
                "visible repository root changed during bounded read: {error}"
            ))
        })?;
        if directory_identity(&visible)? == expected {
            Ok(visible)
        } else {
            Err(read_namespace_changed(
                "visible repository root identity changed during bounded read",
            ))
        }
    }

    fn validate_read_leaf(
        parent: &File,
        leaf: &OsStr,
        expected: Option<(u64, [u8; 16])>,
    ) -> io::Result<()> {
        let observed = open_read_leaf(parent, leaf).map_err(|error| {
            read_namespace_changed(format!(
                "repository target changed during bounded read: {error}"
            ))
        })?;
        match (expected, observed) {
            (None, None) => Ok(()),
            (Some(expected), Some(file)) if file_identity(&file)? == expected => Ok(()),
            _ => Err(read_namespace_changed(
                "repository target identity changed during bounded read",
            )),
        }
    }

    fn validate_listed_entries(
        parent: &File,
        entries: &[RepositoryDirectoryEntry],
    ) -> io::Result<()> {
        for entry in entries {
            let current = match entry.kind {
                RepositoryDirectoryEntryKind::Directory => {
                    open_directory(parent, &entry.name, FILE_OPEN, false)
                }
                RepositoryDirectoryEntryKind::RegularFile => open_read_leaf(parent, &entry.name)?
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotFound,
                            "repository directory entry disappeared during listing",
                        )
                    }),
            }
            .map_err(|error| {
                read_namespace_changed(format!(
                    "repository directory entry changed during listing: {error}"
                ))
            })?;
            if file_identity(&current)? != entry.identity {
                return Err(read_namespace_changed(
                    "repository directory entry identity changed during listing",
                ));
            }
        }
        Ok(())
    }

    fn read_namespace_changed(message: impl Into<String>) -> io::Error {
        io::Error::new(io::ErrorKind::PermissionDenied, message.into())
    }

    fn validate_parent_path(relative: &Path) -> io::Result<()> {
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "repository parent path was not normalized",
            ));
        }
        Ok(())
    }

    fn validate_quarantine_names(original: &OsStr, quarantine: &OsStr) -> io::Result<()> {
        validate_leaf(original)?;
        validate_leaf(quarantine)?;
        if original == quarantine {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "repository GC original and quarantine names must differ",
            ));
        }
        Ok(())
    }

    fn validate_leaf(leaf: &OsStr) -> io::Result<()> {
        let path = Path::new(leaf);
        if leaf.is_empty()
            || path.is_absolute()
            || path.components().count() != 1
            || !matches!(path.components().next(), Some(Component::Normal(_)))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "repository GC name must be one normalized leaf",
            ));
        }
        let wide: Vec<u16> = leaf.encode_wide().collect();
        if wide.contains(&0)
            || wide
                .last()
                .is_some_and(|unit| *unit == b'.' as u16 || *unit == b' ' as u16)
            || wide.contains(&(b':' as u16))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "repository GC name has ambiguous Windows spelling",
            ));
        }
        Ok(())
    }

    fn split_target(relative: &Path) -> io::Result<(&Path, &OsStr)> {
        let parent = relative.parent().unwrap_or_else(|| Path::new(""));
        let leaf = relative.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "repository write target has no file name",
            )
        })?;
        Ok((parent, leaf))
    }

    fn open_root_directory(path: &Path) -> io::Result<File> {
        let wide = nul_terminated(path.as_os_str())?;
        // SAFETY: the path is NUL-terminated and the returned handle is checked before ownership
        // transfer.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `handle` is one newly returned owned handle.
        let directory = unsafe { File::from_raw_handle(handle) };
        validate_kind(&directory, true)?;
        Ok(directory)
    }

    fn open_gc_regular_leaf(parent: &File, leaf: &OsStr) -> io::Result<File> {
        validate_leaf(leaf)?;
        let file = nt_open_relative(
            parent,
            leaf,
            FILE_GENERIC_READ | FILE_READ_ATTRIBUTES | READ_CONTROL | DELETE | SYNCHRONIZE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )?;
        validate_kind(&file, false)?;
        Ok(file)
    }

    fn validate_visible_root_and_parent(
        root_path: &Path,
        root_identity: (u64, [u8; 16]),
        parent_path: &Path,
        parent_identity: (u64, [u8; 16]),
    ) -> io::Result<()> {
        let visible_root = open_root_directory(root_path)?;
        if directory_identity(&visible_root)? != root_identity {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "visible repository root no longer matches the pinned GC root",
            ));
        }
        let visible_parent =
            open_parent_from(&visible_root, parent_path, NewFileMode::Private, false)?;
        if directory_identity(&visible_parent)? != parent_identity {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "visible repository GC parent no longer matches the pinned directory",
            ));
        }
        Ok(())
    }

    fn file_identity(file: &File) -> io::Result<(u64, [u8; 16])> {
        directory_identity(file)
    }

    fn recover_failed_begin_quarantine(
        parent: &File,
        object: &File,
        quarantine: &OsStr,
        original: &OsStr,
        expected: (u64, [u8; 16]),
        source: io::Error,
    ) -> RepositoryGcError {
        let mut restored = false;
        let recovery = (|| {
            let current = open_gc_regular_leaf(parent, quarantine)?;
            if file_identity(&current)? != expected {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "repository GC quarantine changed before failed-begin recovery",
                ));
            }
            drop(current);
            rename_handle_relative(object, original, false)?;
            restored = true;
            let original = open_gc_regular_leaf(parent, original)?;
            if file_identity(&original)? != expected {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "repository GC original changed during failed-begin recovery",
                ));
            }
            Ok(())
        })();
        match recovery {
            Ok(()) => RepositoryGcError::new(RepositoryGcCommit::Restored, source),
            Err(recovery) => {
                let commit = if restored {
                    RepositoryGcCommit::Restored
                } else {
                    RepositoryGcCommit::Indeterminate
                };
                let source_kind = source.kind();
                RepositoryGcError::new(
                    commit,
                    io::Error::new(
                        source_kind,
                        format!(
                            "repository GC begin failed after quarantine ({source}); recovery failed: {recovery}"
                        ),
                    ),
                )
            }
        }
    }

    fn restore_after_delete_precondition_failure(
        quarantine: PrivateQuarantine,
        validation: io::Error,
    ) -> Result<(), RepositoryGcError> {
        match quarantine.restore() {
            Ok(()) => Err(RepositoryGcError::new(
                RepositoryGcCommit::Restored,
                validation,
            )),
            Err(restore) => {
                let commit = restore.commit();
                let restore = restore.into_source();
                let validation_kind = validation.kind();
                Err(RepositoryGcError::new(
                    commit,
                    io::Error::new(
                        validation_kind,
                        format!(
                            "repository GC delete precondition failed ({validation}); recovery failed: {restore}"
                        ),
                    ),
                ))
            }
        }
    }

    fn read_target_bounded(
        parent: &File,
        leaf: &OsStr,
        max_bytes: usize,
    ) -> io::Result<Option<Vec<u8>>> {
        Ok(
            match read_target_bounded_with_identity(parent, leaf, max_bytes)? {
                ReadTargetObservation::Missing => None,
                ReadTargetObservation::Present { bytes, .. } => Some(bytes),
            },
        )
    }

    fn open_read_leaf(parent: &File, leaf: &OsStr) -> io::Result<Option<File>> {
        let file = match nt_open_relative(
            parent,
            leaf,
            FILE_GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            FILE_ATTRIBUTE_NORMAL,
            None,
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::PermissionDenied
                        | io::ErrorKind::NotADirectory
                        | io::ErrorKind::IsADirectory
                        | io::ErrorKind::InvalidInput
                ) =>
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("repository target has an unsafe file kind: {error}"),
                ));
            }
            Err(error) => return Err(error),
        };
        validate_kind(&file, false).map_err(|error| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("repository target has an unsafe file kind: {error}"),
            )
        })?;
        Ok(Some(file))
    }

    fn read_target_bounded_with_identity(
        parent: &File,
        leaf: &OsStr,
        max_bytes: usize,
    ) -> io::Result<ReadTargetObservation> {
        let Some(mut file) = open_read_leaf(parent, leaf)? else {
            return Ok(ReadTargetObservation::Missing);
        };
        let metadata = file.metadata()?;
        let max_bytes_u64 = u64::try_from(max_bytes).unwrap_or(u64::MAX);
        if metadata.len() > max_bytes_u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "repository target exceeds its bounded regular-file contract",
            ));
        }
        let capacity =
            usize::try_from(metadata.len()).map_or(max_bytes, |size| size.min(max_bytes));
        let mut bytes = Vec::with_capacity(capacity);
        std::io::Read::by_ref(&mut file)
            .take(max_bytes_u64.saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() > max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "repository target grew beyond its bounded read limit",
            ));
        }
        let identity = file_identity(&file)?;
        Ok(ReadTargetObservation::Present {
            bytes,
            identity,
            _object: file,
        })
    }

    fn open_directory(
        parent: &File,
        segment: &OsStr,
        disposition: u32,
        private_create: bool,
    ) -> io::Result<File> {
        let mut desired_access = FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
        if private_create {
            desired_access |= READ_CONTROL | WRITE_DAC | DELETE;
        }
        let mut descriptor = private_create
            .then(crate::state::PrivateSecurityDescriptor::repository_directory)
            .transpose()?;
        let file = nt_open_relative(
            parent,
            segment,
            desired_access,
            disposition,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            FILE_ATTRIBUTE_DIRECTORY,
            descriptor.as_mut(),
        )?;
        validate_kind(&file, true)?;
        Ok(file)
    }

    fn open_listing_directory(parent: &File, segment: &OsStr) -> io::Result<File> {
        let file = nt_open_relative(
            parent,
            segment,
            FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            FILE_OPEN,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            FILE_ATTRIBUTE_DIRECTORY,
            None,
        )?;
        validate_kind(&file, true)?;
        Ok(file)
    }

    fn open_listing_ancestor_directory(parent: &File, segment: &OsStr) -> io::Result<File> {
        let file = nt_open_relative(
            parent,
            segment,
            FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            FILE_OPEN,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            FILE_ATTRIBUTE_DIRECTORY,
            None,
        )?;
        validate_kind(&file, true)?;
        Ok(file)
    }

    fn reopen_listing_root(directory: &File) -> io::Result<File> {
        // ReOpenFile derives a new access mask from the already pinned root object; it does not
        // resolve the visible root path again and therefore cannot cross a root-replacement race.
        // SAFETY: the source handle is live and the returned owned handle is checked below.
        let handle = unsafe {
            ReOpenFile(
                directory.as_raw_handle(),
                FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `handle` is a newly returned owned Win32 handle.
        let reopened = unsafe { File::from_raw_handle(handle) };
        validate_kind(&reopened, true)?;
        Ok(reopened)
    }

    fn existing_target_permissions(
        parent: &File,
        leaf: &OsStr,
        mode: NewFileMode,
    ) -> io::Result<Option<std::fs::Permissions>> {
        let opened = nt_open_relative(
            parent,
            leaf,
            FILE_READ_ATTRIBUTES | DELETE | SYNCHRONIZE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            FILE_ATTRIBUTE_NORMAL,
            None,
        );
        match opened {
            Ok(file) => {
                validate_kind(&file, false)?;
                Ok(match mode {
                    NewFileMode::Default => Some(file.metadata()?.permissions()),
                    NewFileMode::Private => None,
                })
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn create_temporary(parent: &File, mode: NewFileMode) -> io::Result<(File, OsString)> {
        let mut desired_access = FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE | SYNCHRONIZE;
        if matches!(mode, NewFileMode::Private) {
            desired_access |= READ_CONTROL | WRITE_DAC;
        }
        for _ in 0..TEMPORARY_NAME_ATTEMPTS {
            let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let name = OsString::from(format!(
                ".{CLI_NAME}-tmp-{}-{sequence:016x}",
                std::process::id()
            ));
            let mut descriptor = matches!(mode, NewFileMode::Private)
                .then(crate::state::PrivateSecurityDescriptor::repository_file)
                .transpose()?;
            match nt_open_relative(
                parent,
                &name,
                desired_access,
                FILE_CREATE,
                FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                FILE_ATTRIBUTE_NORMAL,
                descriptor.as_mut(),
            ) {
                Ok(file) => {
                    let validation = (|| {
                        validate_kind(&file, false)?;
                        if matches!(mode, NewFileMode::Private) {
                            crate::state::harden_private_repository_file(&file, Path::new(&name))?;
                        }
                        Ok(())
                    })();
                    if let Err(error) = validation {
                        if let Err(cleanup) = mark_delete_on_close(&file) {
                            return Err(io::Error::other(format!(
                                "validate Windows repository temporary file failed ({error}) and cleanup failed: {cleanup}"
                            )));
                        }
                        return Err(error);
                    }
                    return Ok((file, name));
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique repository temporary file",
        ))
    }

    fn nt_open_relative(
        parent: &File,
        name: &OsStr,
        desired_access: u32,
        disposition: u32,
        options: u32,
        attributes: u32,
        security_descriptor: Option<&mut crate::state::PrivateSecurityDescriptor>,
    ) -> io::Result<File> {
        let mut wide: Vec<u16> = name.encode_wide().collect();
        if wide.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Windows repository path contains a NUL code unit",
            ));
        }
        if wide
            .last()
            .is_some_and(|unit| *unit == b'.' as u16 || *unit == b' ' as u16)
            || wide.contains(&(b':' as u16))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Windows repository path component has ambiguous Win32 spelling",
            ));
        }
        let byte_len = wide
            .len()
            .checked_mul(size_of::<u16>())
            .and_then(|bytes| u16::try_from(bytes).ok())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Windows repository path component exceeds UNICODE_STRING limits",
                )
            })?;
        let unicode = UNICODE_STRING {
            Length: byte_len,
            MaximumLength: byte_len,
            Buffer: wide.as_mut_ptr(),
        };
        let security_descriptor = security_descriptor.map_or(ptr::null(), |descriptor| {
            descriptor
                .as_mut_ptr()
                .cast::<SECURITY_DESCRIPTOR>()
                .cast_const()
        });
        let object = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: parent.as_raw_handle(),
            ObjectName: ptr::from_ref(&unicode),
            Attributes: OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: security_descriptor,
            SecurityQualityOfService: ptr::null(),
        };
        let mut status_block = IO_STATUS_BLOCK::default();
        let mut handle: HANDLE = INVALID_HANDLE_VALUE;
        // SAFETY: all counted strings and structures remain live for this synchronous call; the
        // parent handle is valid; the result handle is checked before ownership transfer.
        let status = unsafe {
            NtCreateFile(
                &mut handle,
                desired_access,
                &object,
                &mut status_block,
                ptr::null(),
                attributes,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                disposition,
                options,
                ptr::null(),
                0,
            )
        };
        if status < 0 {
            // SAFETY: conversion is pure for the returned NTSTATUS.
            let code = unsafe { RtlNtStatusToDosError(status) };
            return Err(io::Error::from_raw_os_error(code as i32));
        }
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::other(
                "NtCreateFile succeeded without returning a valid handle",
            ));
        }
        // SAFETY: the successful call returned one owned handle.
        Ok(unsafe { File::from_raw_handle(handle) })
    }

    fn rename_handle_relative(source: &File, target: &OsStr, replace: bool) -> io::Result<()> {
        validate_leaf(target)?;
        let name: Vec<u16> = target.encode_wide().collect();
        if name.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Windows repository target contains a NUL code unit",
            ));
        }
        let name_bytes = name
            .len()
            .checked_mul(size_of::<u16>())
            .ok_or_else(|| io::Error::other("Windows rename buffer length overflowed"))?;
        // FILE_RENAME_INFORMATION has a variable-width trailing name. Windows requires the
        // complete fixed structure in addition to the counted UTF-16 bytes; using
        // `offset_of!(..., FileName)` leaves the buffer short because of the tail
        // member and its alignment padding.
        let total = size_of::<FILE_RENAME_INFORMATION>()
            .checked_add(name_bytes)
            .ok_or_else(|| io::Error::other("Windows rename buffer length overflowed"))?;
        let words = total.div_ceil(size_of::<usize>());
        let mut storage = vec![0usize; words];
        let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
        // SAFETY: `storage` is suitably aligned and sized for the fixed header plus counted UTF-16
        // name. The temporary handle uses synchronous I/O, and every pointer remains live for the
        // NtSetInformationFile call.
        unsafe {
            // `storage` is zero-filled, so the reserved union bytes remain zero while
            // FileRenameInformation reads the boolean member. Microsoft defines a NULL
            // RootDirectory plus a simple leaf as a same-directory rename, so the source
            // temporary file's directory remains the destination without resolving a visible
            // path.
            (*info).Anonymous.ReplaceIfExists = replace;
            (*info).RootDirectory = ptr::null_mut();
            (*info).FileNameLength = u32::try_from(name_bytes).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Windows repository target exceeds rename limits",
                )
            })?;
            ptr::copy_nonoverlapping(
                name.as_ptr().cast::<u8>(),
                storage
                    .as_mut_ptr()
                    .cast::<u8>()
                    .add(offset_of!(FILE_RENAME_INFORMATION, FileName)),
                name_bytes,
            );
            let mut status_block = IO_STATUS_BLOCK::default();
            let status = NtSetInformationFile(
                source.as_raw_handle(),
                &mut status_block,
                storage.as_ptr().cast::<c_void>(),
                u32::try_from(total).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Windows rename buffer exceeds API limits",
                    )
                })?,
                FileRenameInformation,
            );
            if status < 0 {
                let code = RtlNtStatusToDosError(status);
                return Err(io::Error::from_raw_os_error(code as i32));
            }
        }
        Ok(())
    }

    fn mark_delete_on_close(file: &File) -> io::Result<()> {
        let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
        // SAFETY: the file handle and fixed-size disposition structure are live for the call.
        if unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle(),
                FileDispositionInfo,
                ptr::from_ref(&disposition).cast(),
                size_of::<FILE_DISPOSITION_INFO>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn not_committed(source: io::Error) -> RepositoryWriteError {
        RepositoryWriteError::new(RepositoryWriteCommit::NotCommitted, source)
    }

    fn not_changed_gc(source: io::Error) -> RepositoryGcError {
        RepositoryGcError::new(RepositoryGcCommit::NotChanged, source)
    }

    const fn commit_state(committed: bool) -> RepositoryWriteCommit {
        if committed {
            RepositoryWriteCommit::CommittedUnverified
        } else {
            RepositoryWriteCommit::NotCommitted
        }
    }

    fn validate_kind(file: &File, expected_directory: bool) -> io::Result<()> {
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: the handle and writable output structure are live for this call.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "repository handle is a Windows reparse point",
            ));
        }
        let is_directory = information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        if is_directory != expected_directory {
            return Err(io::Error::new(
                if expected_directory {
                    io::ErrorKind::NotADirectory
                } else {
                    io::ErrorKind::InvalidInput
                },
                "repository handle has an unexpected file kind",
            ));
        }
        Ok(())
    }

    fn directory_identity(directory: &File) -> io::Result<(u64, [u8; 16])> {
        let mut information = FILE_ID_INFO::default();
        // SAFETY: the handle and exactly-sized writable output structure are live for this call.
        if unsafe {
            GetFileInformationByHandleEx(
                directory.as_raw_handle(),
                FileIdInfo,
                ptr::from_mut(&mut information).cast(),
                size_of::<FILE_ID_INFO>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok((
            information.VolumeSerialNumber,
            information.FileId.Identifier,
        ))
    }

    fn nul_terminated(value: &OsStr) -> io::Result<Vec<u16>> {
        let mut wide: Vec<u16> = value.encode_wide().collect();
        if wide.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Windows path contains a NUL code unit",
            ));
        }
        wide.push(0);
        Ok(wide)
    }
}

#[cfg(not(any(unix, windows)))]
mod platform {
    use std::ffi::OsStr;
    use std::fs::File;
    use std::io;
    use std::path::Path;

    use super::{
        BeginPrivateQuarantine, CommitMode, NewFileMode, RepositoryDirectoryEntry,
        RepositoryDirectoryListing, RepositoryGcCommit, RepositoryGcError,
    };
    use forge_core::ports::{RepositoryWriteError, RepositoryWriteOutcome};

    #[derive(Debug)]
    pub(crate) struct RootHandle;

    #[derive(Debug)]
    pub(crate) struct PrivateQuarantine {
        object: File,
    }

    impl RootHandle {
        pub(crate) fn open(_path: &Path) -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "confined repository writes require Unix or Windows directory handles",
            ))
        }

        pub(crate) fn validate_visible_root(&self) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "confined repository root identity checks require Unix or Windows directory handles",
            ))
        }

        pub(crate) fn write_atomic(
            &self,
            relative: &Path,
            bytes: &[u8],
            _file_mode: NewFileMode,
            commit_mode: CommitMode,
            before_commit: impl FnOnce() -> io::Result<()>,
        ) -> io::Result<()> {
            let _ = (self, relative, bytes, commit_mode, before_commit);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "confined repository writes require Unix or Windows directory handles",
            ))
        }

        pub(crate) fn read_bounded(
            &self,
            relative: &Path,
            max_bytes: usize,
        ) -> io::Result<Option<Vec<u8>>> {
            let _ = (self, relative, max_bytes);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "confined repository reads require Unix or Windows directory handles",
            ))
        }

        pub(crate) fn validate_regular_from(
            &self,
            relative: &Path,
            expected_parent: &File,
            object: &File,
        ) -> io::Result<()> {
            let _ = (self, relative, expected_parent, object);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "confined repository reads require Unix or Windows directory handles",
            ))
        }

        pub(crate) fn open_regular_from(
            &self,
            relative: &Path,
            expected_parent: &File,
        ) -> io::Result<Option<File>> {
            let _ = (self, relative, expected_parent);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "confined repository reads require Unix or Windows directory handles",
            ))
        }

        pub(crate) fn open_listed_entry_from(
            &self,
            relative: &Path,
            expected_directory: &File,
            entry: &RepositoryDirectoryEntry,
        ) -> io::Result<File> {
            let _ = (self, relative, expected_directory, entry);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "confined repository listings require Unix or Windows directory handles",
            ))
        }

        pub(crate) fn list_directory(
            &self,
            relative: &Path,
            max_entries: usize,
        ) -> io::Result<Option<RepositoryDirectoryListing>> {
            let _ = (self, relative, max_entries);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "confined repository listings require Unix or Windows directory handles",
            ))
        }

        pub(crate) fn list_directory_from(
            &self,
            relative: &Path,
            expected: &File,
            max_entries: usize,
        ) -> io::Result<RepositoryDirectoryListing> {
            let _ = (self, relative, expected, max_entries);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "confined repository listings require Unix or Windows directory handles",
            ))
        }

        pub(crate) fn begin_private_quarantine(
            &self,
            relative: &Path,
            quarantine_leaf: &OsStr,
        ) -> Result<BeginPrivateQuarantine, RepositoryGcError> {
            let _ = (self, relative, quarantine_leaf);
            Err(unsupported_gc())
        }

        pub(crate) fn begin_private_quarantine_from(
            &self,
            relative: &Path,
            expected_parent: &File,
            quarantine_leaf: &OsStr,
        ) -> Result<BeginPrivateQuarantine, RepositoryGcError> {
            let _ = (self, relative, expected_parent, quarantine_leaf);
            Err(unsupported_gc())
        }

        pub(crate) fn open_private_quarantine(
            &self,
            directory: &Path,
            original_leaf: &OsStr,
            quarantine_leaf: &OsStr,
        ) -> Result<super::OpenPrivateQuarantine, RepositoryGcError> {
            let _ = (self, directory, original_leaf, quarantine_leaf);
            Err(unsupported_gc())
        }

        pub(crate) fn open_private_quarantine_from(
            &self,
            directory: &Path,
            expected_parent: &File,
            original_leaf: &OsStr,
            quarantine_leaf: &OsStr,
        ) -> Result<super::OpenPrivateQuarantine, RepositoryGcError> {
            let _ = (
                self,
                directory,
                expected_parent,
                original_leaf,
                quarantine_leaf,
            );
            Err(unsupported_gc())
        }

        pub(crate) fn write_atomic_if_unchanged(
            &self,
            relative: &Path,
            expected: Option<&[u8]>,
            bytes: &[u8],
            max_postimage_bytes: usize,
        ) -> Result<RepositoryWriteOutcome, RepositoryWriteError> {
            let _ = (self, relative, expected, bytes, max_postimage_bytes);
            Err(RepositoryWriteError::new(
                forge_core::ports::RepositoryWriteCommit::NotCommitted,
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "confined repository writes require Unix or Windows directory handles",
                ),
            ))
        }
    }

    impl PrivateQuarantine {
        pub(crate) fn object_file(&mut self) -> &mut File {
            &mut self.object
        }

        pub(crate) fn validate_visible_root_and_parent(&self) -> io::Result<()> {
            let _ = self;
            Err(unsupported_gc().into_source())
        }

        pub(crate) fn restore(self) -> Result<(), RepositoryGcError> {
            let _ = self;
            Err(unsupported_gc())
        }

        pub(crate) fn delete(self) -> Result<(), RepositoryGcError> {
            let _ = self;
            Err(unsupported_gc())
        }
    }

    fn unsupported_gc() -> RepositoryGcError {
        RepositoryGcError::new(
            RepositoryGcCommit::NotChanged,
            io::Error::new(
                io::ErrorKind::Unsupported,
                "confined repository GC requires Unix or Windows directory handles",
            ),
        )
    }
}

pub(crate) use platform::{PrivateQuarantine, RootHandle};

#[derive(Debug)]
pub(crate) enum BeginPrivateQuarantine {
    Missing,
    Quarantined(PrivateQuarantine),
}

#[derive(Debug)]
pub(crate) enum OpenPrivateQuarantine {
    Missing,
    QuarantineOnly(PrivateQuarantine),
    DuplicateSameIdentity(PrivateQuarantine),
}

#[cfg(all(test, any(unix, windows)))]
mod tests {
    use std::error::Error;
    use std::ffi::OsStr;
    use std::fs;
    use std::io::{self, Read as _};
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    use std::path::Path;

    use tempfile::tempdir;

    use super::{
        BeginPrivateQuarantine, GcEvent, OpenPrivateQuarantine, ReadEvent, RepositoryGcCommit,
        RootHandle,
    };

    const DIRECTORY: &str = "objects";
    const ORIGINAL: &str = "receipt.json";
    const QUARANTINE: &str = ".forge-gc-quarantine-receipt";
    const CONTENT: &[u8] = b"verified receipt";

    fn create_source(root: &Path) -> io::Result<()> {
        fs::create_dir(root.join(DIRECTORY))?;
        fs::write(root.join(DIRECTORY).join(ORIGINAL), CONTENT)
    }

    fn begin(root: &RootHandle) -> Result<super::PrivateQuarantine, Box<dyn Error>> {
        let result = root.begin_private_quarantine(
            Path::new(DIRECTORY).join(ORIGINAL).as_path(),
            OsStr::new(QUARANTINE),
        )?;
        let BeginPrivateQuarantine::Quarantined(quarantine) = result else {
            return Err(io::Error::other("expected a quarantined repository object").into());
        };
        Ok(quarantine)
    }

    fn require_read_failure(
        result: io::Result<Option<Vec<u8>>>,
        changed: &str,
    ) -> Result<(), Box<dyn Error>> {
        let error = result
            .err()
            .ok_or_else(|| io::Error::other(format!("{changed} replacement was not rejected")))?;
        if error.kind() != io::ErrorKind::PermissionDenied {
            return Err(io::Error::other(format!(
                "{changed} replacement returned {:?}: {error}",
                error.kind()
            ))
            .into());
        }
        Ok(())
    }

    fn rename_for_read_swap(source: &Path, destination: &Path) -> io::Result<bool> {
        match fs::rename(source, destination) {
            Ok(()) => Ok(true),
            #[cfg(windows)]
            Err(error)
                if matches!(error.raw_os_error(), Some(5 | 32 | 33))
                    || error.kind() == io::ErrorKind::PermissionDenied =>
            {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    #[test]
    fn bounded_read_preserves_missing_and_limit_semantics() -> Result<(), Box<dyn Error>> {
        let repository = tempdir()?;
        fs::create_dir(repository.path().join(DIRECTORY))?;
        let root = RootHandle::open(repository.path())?;

        assert_eq!(root.read_bounded(Path::new("missing/file"), 8)?, None);
        assert_eq!(
            root.read_bounded(Path::new(DIRECTORY).join(ORIGINAL).as_path(), 8,)?,
            None
        );
        fs::write(repository.path().join(DIRECTORY).join(ORIGINAL), b"12345")?;
        assert_eq!(
            root.read_bounded(Path::new(DIRECTORY).join(ORIGINAL).as_path(), 5,)?,
            Some(b"12345".to_vec())
        );
        let oversized = root.read_bounded(Path::new(DIRECTORY).join(ORIGINAL).as_path(), 4);
        assert!(matches!(
            oversized,
            Err(ref error) if error.kind() == io::ErrorKind::InvalidData
        ));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn directory_listing_rejects_visible_root_replacement() -> Result<(), Box<dyn Error>> {
        let container = tempdir()?;
        let repository = container.path().join("repository");
        let displaced = container.path().join("displaced-repository");
        fs::create_dir(&repository)?;
        fs::create_dir(repository.join(DIRECTORY))?;
        fs::write(repository.join(DIRECTORY).join(ORIGINAL), CONTENT)?;
        let root = RootHandle::open(&repository)?;

        let result = root.list_directory_with_hook(Path::new(DIRECTORY), 8, || {
            fs::rename(&repository, &displaced)?;
            fs::create_dir(&repository)?;
            fs::create_dir(repository.join(DIRECTORY))?;
            fs::write(repository.join(DIRECTORY).join(ORIGINAL), b"replacement")
        });

        assert!(matches!(
            result,
            Err(ref error) if error.kind() == io::ErrorKind::PermissionDenied
        ));
        assert_eq!(fs::read(displaced.join(DIRECTORY).join(ORIGINAL))?, CONTENT);
        assert_eq!(
            fs::read(repository.join(DIRECTORY).join(ORIGINAL))?,
            b"replacement"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn directory_listing_rejects_target_directory_replacement() -> Result<(), Box<dyn Error>> {
        let repository = tempdir()?;
        let target = repository.path().join(DIRECTORY);
        let displaced = repository.path().join("displaced-objects");
        fs::create_dir(&target)?;
        fs::write(target.join(ORIGINAL), CONTENT)?;
        let root = RootHandle::open(repository.path())?;

        let result = root.list_directory_with_hook(Path::new(DIRECTORY), 8, || {
            fs::rename(&target, &displaced)?;
            fs::create_dir(&target)?;
            fs::write(target.join(ORIGINAL), b"replacement")
        });

        assert!(matches!(
            result,
            Err(ref error) if error.kind() == io::ErrorKind::PermissionDenied
        ));
        assert_eq!(fs::read(displaced.join(ORIGINAL))?, CONTENT);
        assert_eq!(fs::read(target.join(ORIGINAL))?, b"replacement");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn recursive_listing_rejects_a_replaced_child_directory() -> Result<(), Box<dyn Error>> {
        let repository = tempdir()?;
        let parent = repository.path().join("kind");
        let child = parent.join("v1");
        let displaced = parent.join("displaced-v1");
        fs::create_dir_all(&child)?;
        fs::write(child.join(ORIGINAL), CONTENT)?;
        let root = RootHandle::open(repository.path())?;
        let listing = root
            .list_directory(Path::new("kind"), 8)?
            .ok_or_else(|| io::Error::other("parent directory unexpectedly missing"))?;
        let (parent_handle, entries) = listing
            .into_directory_and_entries()
            .ok_or_else(|| io::Error::other("parent directory listing was incomplete"))?;
        let child_entry = entries
            .into_iter()
            .find(|entry| entry.name == OsStr::new("v1"))
            .ok_or_else(|| io::Error::other("child directory was not listed"))?;
        let child_handle =
            root.open_listed_entry_from(Path::new("kind"), &parent_handle, &child_entry)?;

        fs::rename(&child, &displaced)?;
        fs::create_dir(&child)?;
        fs::write(child.join(ORIGINAL), b"replacement")?;
        let result = root.list_directory_from(Path::new("kind/v1"), &child_handle, 8);

        assert!(matches!(
            result,
            Err(ref error) if error.kind() == io::ErrorKind::PermissionDenied
        ));
        assert_eq!(fs::read(displaced.join(ORIGINAL))?, CONTENT);
        assert_eq!(fs::read(child.join(ORIGINAL))?, b"replacement");
        Ok(())
    }

    #[test]
    fn bounded_read_rejects_visible_root_replacement_after_observation()
    -> Result<(), Box<dyn Error>> {
        let container = tempdir()?;
        let repository = container.path().join("repository");
        let displaced = container.path().join("displaced-repository");
        fs::create_dir(&repository)?;
        create_source(&repository)?;
        let root = RootHandle::open(&repository)?;
        let mut swapped = false;

        let result = root.read_bounded_with_hook(
            Path::new(DIRECTORY).join(ORIGINAL).as_path(),
            CONTENT.len(),
            |event| {
                if event != ReadEvent::AfterObservation {
                    return Err(io::Error::other("unexpected bounded-read hook event"));
                }
                if !rename_for_read_swap(&repository, &displaced)? {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "Windows safely refused the repository root swap",
                    ));
                }
                swapped = true;
                fs::create_dir(&repository)?;
                fs::create_dir(repository.join(DIRECTORY))?;
                fs::write(repository.join(DIRECTORY).join(ORIGINAL), b"replacement")
            },
        );

        require_read_failure(result, "visible root")?;
        if swapped {
            assert_eq!(fs::read(displaced.join(DIRECTORY).join(ORIGINAL))?, CONTENT);
            assert_eq!(
                fs::read(repository.join(DIRECTORY).join(ORIGINAL))?,
                b"replacement"
            );
        } else {
            assert_eq!(
                fs::read(repository.join(DIRECTORY).join(ORIGINAL))?,
                CONTENT
            );
        }
        Ok(())
    }

    #[test]
    fn bounded_read_rejects_intermediate_ancestor_replacement_after_observation()
    -> Result<(), Box<dyn Error>> {
        let repository = tempdir()?;
        let ancestor = repository.path().join("level");
        let displaced = repository.path().join("displaced-level");
        fs::create_dir(&ancestor)?;
        create_source(&ancestor)?;
        let root = RootHandle::open(repository.path())?;
        let relative = Path::new("level").join(DIRECTORY).join(ORIGINAL);
        let mut swapped = false;

        let result = root.read_bounded_with_hook(&relative, CONTENT.len(), |event| {
            if event != ReadEvent::AfterObservation {
                return Err(io::Error::other("unexpected bounded-read hook event"));
            }
            if !rename_for_read_swap(&ancestor, &displaced)? {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Windows safely refused the repository ancestor swap",
                ));
            }
            swapped = true;
            fs::create_dir(&ancestor)?;
            fs::create_dir(ancestor.join(DIRECTORY))?;
            fs::write(ancestor.join(DIRECTORY).join(ORIGINAL), b"replacement")
        });

        require_read_failure(result, "intermediate ancestor")?;
        if swapped {
            assert_eq!(fs::read(displaced.join(DIRECTORY).join(ORIGINAL))?, CONTENT);
            assert_eq!(
                fs::read(ancestor.join(DIRECTORY).join(ORIGINAL))?,
                b"replacement"
            );
        } else {
            assert_eq!(fs::read(ancestor.join(DIRECTORY).join(ORIGINAL))?, CONTENT);
        }
        Ok(())
    }

    #[test]
    fn bounded_read_rejects_final_leaf_replacement_after_observation() -> Result<(), Box<dyn Error>>
    {
        let repository = tempdir()?;
        create_source(repository.path())?;
        let original = repository.path().join(DIRECTORY).join(ORIGINAL);
        let displaced = repository.path().join(DIRECTORY).join("displaced.json");
        let root = RootHandle::open(repository.path())?;
        let mut swapped = false;

        let result = root.read_bounded_with_hook(
            Path::new(DIRECTORY).join(ORIGINAL).as_path(),
            CONTENT.len(),
            |event| {
                if event != ReadEvent::AfterObservation {
                    return Err(io::Error::other("unexpected bounded-read hook event"));
                }
                if !rename_for_read_swap(&original, &displaced)? {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "Windows safely refused the repository leaf swap",
                    ));
                }
                swapped = true;
                fs::write(&original, b"replacement")
            },
        );

        require_read_failure(result, "final leaf")?;
        if swapped {
            assert_eq!(fs::read(displaced)?, CONTENT);
            assert_eq!(fs::read(original)?, b"replacement");
        } else {
            assert_eq!(fs::read(original)?, CONTENT);
        }
        Ok(())
    }

    #[test]
    fn quarantine_begin_precheck_rejects_visible_root_replacement() -> Result<(), Box<dyn Error>> {
        let container = tempdir()?;
        let repository = container.path().join("repository");
        let displaced = container.path().join("displaced-repository");
        fs::create_dir(&repository)?;
        create_source(&repository)?;
        let root = RootHandle::open(&repository)?;
        let mut swapped = false;

        let error = root
            .begin_private_quarantine_with_hook(
                Path::new(DIRECTORY).join(ORIGINAL).as_path(),
                OsStr::new(QUARANTINE),
                |event| {
                    if event != GcEvent::BeforeBeginRename {
                        return Err(io::Error::other("unexpected quarantine hook event"));
                    }
                    if !rename_for_read_swap(&repository, &displaced)? {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "Windows safely refused the repository root swap",
                        ));
                    }
                    swapped = true;
                    fs::create_dir(&repository)?;
                    fs::create_dir(repository.join(DIRECTORY))?;
                    fs::write(repository.join(DIRECTORY).join(ORIGINAL), b"replacement")
                },
            )
            .err()
            .ok_or_else(|| io::Error::other("root replacement quarantine unexpectedly began"))?;

        assert_eq!(error.commit(), RepositoryGcCommit::NotChanged);
        if swapped {
            assert_eq!(fs::read(displaced.join(DIRECTORY).join(ORIGINAL))?, CONTENT);
            assert!(!displaced.join(DIRECTORY).join(QUARANTINE).exists());
            assert_eq!(
                fs::read(repository.join(DIRECTORY).join(ORIGINAL))?,
                b"replacement"
            );
        } else {
            assert_eq!(
                fs::read(repository.join(DIRECTORY).join(ORIGINAL))?,
                CONTENT
            );
        }
        Ok(())
    }

    #[test]
    fn quarantine_begin_postcheck_restores_after_parent_replacement() -> Result<(), Box<dyn Error>>
    {
        let repository = tempdir()?;
        create_source(repository.path())?;
        let parent = repository.path().join(DIRECTORY);
        let displaced = repository.path().join("displaced-objects");
        let root = RootHandle::open(repository.path())?;
        let mut swapped = false;

        let error = root
            .begin_private_quarantine_with_hook(
                Path::new(DIRECTORY).join(ORIGINAL).as_path(),
                OsStr::new(QUARANTINE),
                |event| match event {
                    GcEvent::BeforeBeginRename => Ok(()),
                    GcEvent::AfterBeginRename => {
                        if !rename_for_read_swap(&parent, &displaced)? {
                            return Err(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                "Windows safely refused the repository parent swap",
                            ));
                        }
                        swapped = true;
                        fs::create_dir(&parent)?;
                        fs::write(parent.join(ORIGINAL), b"replacement original")?;
                        fs::write(parent.join(QUARANTINE), b"replacement quarantine")
                    }
                    #[cfg(unix)]
                    GcEvent::AfterDeleteSync => {
                        Err(io::Error::other("unexpected quarantine delete hook event"))
                    }
                },
            )
            .err()
            .ok_or_else(|| io::Error::other("parent replacement quarantine unexpectedly began"))?;

        assert_eq!(error.commit(), RepositoryGcCommit::Restored);
        if swapped {
            assert_eq!(fs::read(displaced.join(ORIGINAL))?, CONTENT);
            assert!(!displaced.join(QUARANTINE).exists());
            assert_eq!(fs::read(parent.join(ORIGINAL))?, b"replacement original");
            assert_eq!(
                fs::read(parent.join(QUARANTINE))?,
                b"replacement quarantine"
            );
        } else {
            assert_eq!(fs::read(parent.join(ORIGINAL))?, CONTENT);
            assert!(!parent.join(QUARANTINE).exists());
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn quarantine_restore_rechecks_the_quarantine_identity_before_rename()
    -> Result<(), Box<dyn Error>> {
        let repository = tempdir()?;
        create_source(repository.path())?;
        let root = RootHandle::open(repository.path())?;
        let quarantine = begin(&root)?;
        let original_path = repository.path().join(DIRECTORY).join(ORIGINAL);
        let quarantine_path = repository.path().join(DIRECTORY).join(QUARANTINE);
        fs::remove_file(&quarantine_path)?;
        fs::write(&quarantine_path, b"replacement quarantine")?;

        let error = quarantine
            .restore()
            .err()
            .ok_or_else(|| io::Error::other("changed quarantine was restored"))?;

        assert_eq!(error.commit(), RepositoryGcCommit::Indeterminate);
        assert!(!original_path.exists());
        assert_eq!(fs::read(quarantine_path)?, b"replacement quarantine");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn quarantine_delete_confirms_the_name_remains_absent_after_sync() -> Result<(), Box<dyn Error>>
    {
        let repository = tempdir()?;
        create_source(repository.path())?;
        let root = RootHandle::open(repository.path())?;
        let quarantine = begin(&root)?;
        let original_path = repository.path().join(DIRECTORY).join(ORIGINAL);
        let quarantine_path = repository.path().join(DIRECTORY).join(QUARANTINE);

        let error = quarantine
            .delete_with_hook(|event| {
                if event != GcEvent::AfterDeleteSync {
                    return Err(io::Error::other("unexpected quarantine hook event"));
                }
                fs::write(&quarantine_path, b"replacement quarantine")
            })
            .err()
            .ok_or_else(|| io::Error::other("reappearing quarantine name was not detected"))?;

        assert_eq!(error.commit(), RepositoryGcCommit::Indeterminate);
        assert!(!original_path.exists());
        assert_eq!(fs::read(quarantine_path)?, b"replacement quarantine");
        Ok(())
    }

    #[test]
    fn bounded_read_rejects_directory_leaf_as_permission_denied() -> Result<(), Box<dyn Error>> {
        let repository = tempdir()?;
        fs::create_dir(repository.path().join(DIRECTORY))?;
        fs::create_dir(repository.path().join(DIRECTORY).join(ORIGINAL))?;
        let root = RootHandle::open(repository.path())?;

        let error = root
            .read_bounded(Path::new(DIRECTORY).join(ORIGINAL).as_path(), CONTENT.len())
            .err()
            .ok_or_else(|| io::Error::other("directory leaf was read as a regular file"))?;

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn bounded_read_rejects_symbolic_link_leaf_as_permission_denied() -> Result<(), Box<dyn Error>>
    {
        let repository = tempdir()?;
        fs::create_dir(repository.path().join(DIRECTORY))?;
        fs::write(repository.path().join("outside"), CONTENT)?;
        symlink(
            repository.path().join("outside"),
            repository.path().join(DIRECTORY).join(ORIGINAL),
        )?;
        let root = RootHandle::open(repository.path())?;

        let error = root
            .read_bounded(Path::new(DIRECTORY).join(ORIGINAL).as_path(), CONTENT.len())
            .err()
            .ok_or_else(|| io::Error::other("symbolic-link leaf was followed"))?;

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        Ok(())
    }

    #[test]
    fn private_quarantine_restores_the_opened_object() -> Result<(), Box<dyn Error>> {
        let repository = tempdir()?;
        create_source(repository.path())?;
        let root = RootHandle::open(repository.path())?;

        let mut quarantine = begin(&root)?;
        let mut observed = Vec::new();
        quarantine.object_file().read_to_end(&mut observed)?;
        assert_eq!(observed, CONTENT);
        assert!(!repository.path().join(DIRECTORY).join(ORIGINAL).exists());
        assert!(repository.path().join(DIRECTORY).join(QUARANTINE).exists());

        quarantine.restore()?;
        assert_eq!(
            fs::read(repository.path().join(DIRECTORY).join(ORIGINAL))?,
            CONTENT
        );
        assert!(!repository.path().join(DIRECTORY).join(QUARANTINE).exists());
        Ok(())
    }

    #[test]
    fn private_quarantine_deletes_only_the_verified_quarantine_name() -> Result<(), Box<dyn Error>>
    {
        let repository = tempdir()?;
        create_source(repository.path())?;
        let root = RootHandle::open(repository.path())?;

        begin(&root)?.delete()?;

        assert!(!repository.path().join(DIRECTORY).join(ORIGINAL).exists());
        assert!(!repository.path().join(DIRECTORY).join(QUARANTINE).exists());
        Ok(())
    }

    #[test]
    fn private_quarantine_never_overwrites_an_existing_quarantine() -> Result<(), Box<dyn Error>> {
        let repository = tempdir()?;
        create_source(repository.path())?;
        let quarantine_path = repository.path().join(DIRECTORY).join(QUARANTINE);
        fs::write(&quarantine_path, b"crash residue")?;
        let root = RootHandle::open(repository.path())?;

        let error = root
            .begin_private_quarantine(
                Path::new(DIRECTORY).join(ORIGINAL).as_path(),
                OsStr::new(QUARANTINE),
            )
            .err()
            .ok_or_else(|| io::Error::other("quarantine collision unexpectedly succeeded"))?;

        assert_eq!(error.commit(), RepositoryGcCommit::NotChanged);
        assert_eq!(error.into_source().kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            fs::read(repository.path().join(DIRECTORY).join(ORIGINAL))?,
            CONTENT
        );
        assert_eq!(fs::read(quarantine_path)?, b"crash residue");
        Ok(())
    }

    #[test]
    fn recovery_open_rejects_original_quarantine_conflicts_without_mutation()
    -> Result<(), Box<dyn Error>> {
        let repository = tempdir()?;
        create_source(repository.path())?;
        let quarantine_path = repository.path().join(DIRECTORY).join(QUARANTINE);
        fs::write(&quarantine_path, b"different object")?;
        let root = RootHandle::open(repository.path())?;

        let error = root
            .open_private_quarantine(
                Path::new(DIRECTORY),
                OsStr::new(ORIGINAL),
                OsStr::new(QUARANTINE),
            )
            .err()
            .ok_or_else(|| io::Error::other("recovery conflict unexpectedly succeeded"))?;

        assert_eq!(error.commit(), RepositoryGcCommit::NotChanged);
        assert_eq!(error.into_source().kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            fs::read(repository.path().join(DIRECTORY).join(ORIGINAL))?,
            CONTENT
        );
        assert_eq!(fs::read(quarantine_path)?, b"different object");
        Ok(())
    }

    #[test]
    fn recovery_open_restores_a_quarantine_when_original_is_missing() -> Result<(), Box<dyn Error>>
    {
        let repository = tempdir()?;
        fs::create_dir(repository.path().join(DIRECTORY))?;
        fs::write(repository.path().join(DIRECTORY).join(QUARANTINE), CONTENT)?;
        let root = RootHandle::open(repository.path())?;

        let opened = root.open_private_quarantine(
            Path::new(DIRECTORY),
            OsStr::new(ORIGINAL),
            OsStr::new(QUARANTINE),
        )?;
        let OpenPrivateQuarantine::QuarantineOnly(quarantine) = opened else {
            return Err(io::Error::other("existing quarantine was not opened alone").into());
        };
        quarantine.restore()?;

        assert_eq!(
            fs::read(repository.path().join(DIRECTORY).join(ORIGINAL))?,
            CONTENT
        );
        assert!(!repository.path().join(DIRECTORY).join(QUARANTINE).exists());
        Ok(())
    }

    #[test]
    fn recovery_open_removes_only_a_same_identity_duplicate_quarantine()
    -> Result<(), Box<dyn Error>> {
        let repository = tempdir()?;
        create_source(repository.path())?;
        let original_path = repository.path().join(DIRECTORY).join(ORIGINAL);
        let quarantine_path = repository.path().join(DIRECTORY).join(QUARANTINE);
        fs::hard_link(&original_path, &quarantine_path)?;
        let root = RootHandle::open(repository.path())?;

        let opened = root.open_private_quarantine(
            Path::new(DIRECTORY),
            OsStr::new(ORIGINAL),
            OsStr::new(QUARANTINE),
        )?;
        let OpenPrivateQuarantine::DuplicateSameIdentity(quarantine) = opened else {
            return Err(io::Error::other("same-identity duplicate was not classified").into());
        };
        quarantine.delete()?;

        assert_eq!(fs::read(original_path)?, CONTENT);
        assert!(!quarantine_path.exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn duplicate_cleanup_rechecks_original_identity_before_deletion() -> Result<(), Box<dyn Error>>
    {
        let repository = tempdir()?;
        create_source(repository.path())?;
        let original_path = repository.path().join(DIRECTORY).join(ORIGINAL);
        let quarantine_path = repository.path().join(DIRECTORY).join(QUARANTINE);
        fs::hard_link(&original_path, &quarantine_path)?;
        let root = RootHandle::open(repository.path())?;
        let opened = root.open_private_quarantine(
            Path::new(DIRECTORY),
            OsStr::new(ORIGINAL),
            OsStr::new(QUARANTINE),
        )?;
        let OpenPrivateQuarantine::DuplicateSameIdentity(quarantine) = opened else {
            return Err(io::Error::other("same-identity duplicate was not classified").into());
        };

        fs::remove_file(&original_path)?;
        fs::write(&original_path, b"replacement")?;
        let error = quarantine
            .delete()
            .err()
            .ok_or_else(|| io::Error::other("changed duplicate original was deleted"))?;

        assert_eq!(error.commit(), RepositoryGcCommit::Indeterminate);
        assert_eq!(fs::read(original_path)?, b"replacement");
        assert_eq!(fs::read(quarantine_path)?, CONTENT);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn delete_precondition_failure_restores_without_touching_replacement_tree()
    -> Result<(), Box<dyn Error>> {
        let container = tempdir()?;
        let repository = container.path().join("repository");
        let displaced = container.path().join("displaced");
        fs::create_dir(&repository)?;
        create_source(&repository)?;
        let root = RootHandle::open(&repository)?;
        let quarantine = begin(&root)?;

        fs::rename(&repository, &displaced)?;
        fs::create_dir(&repository)?;
        fs::create_dir(repository.join(DIRECTORY))?;
        fs::write(
            repository.join(DIRECTORY).join(ORIGINAL),
            b"replacement original",
        )?;
        fs::write(
            repository.join(DIRECTORY).join(QUARANTINE),
            b"replacement quarantine",
        )?;

        let error = quarantine
            .delete()
            .err()
            .ok_or_else(|| io::Error::other("delete ignored a replaced visible root"))?;
        assert_eq!(error.commit(), RepositoryGcCommit::Restored);
        assert_eq!(fs::read(displaced.join(DIRECTORY).join(ORIGINAL))?, CONTENT);
        assert!(!displaced.join(DIRECTORY).join(QUARANTINE).exists());
        assert_eq!(
            fs::read(repository.join(DIRECTORY).join(ORIGINAL))?,
            b"replacement original"
        );
        assert_eq!(
            fs::read(repository.join(DIRECTORY).join(QUARANTINE))?,
            b"replacement quarantine"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn private_quarantine_rejects_symbolic_link_sources() -> Result<(), Box<dyn Error>> {
        let repository = tempdir()?;
        fs::create_dir(repository.path().join(DIRECTORY))?;
        fs::write(repository.path().join("outside"), CONTENT)?;
        symlink(
            repository.path().join("outside"),
            repository.path().join(DIRECTORY).join(ORIGINAL),
        )?;
        let root = RootHandle::open(repository.path())?;

        let error = root
            .begin_private_quarantine(
                Path::new(DIRECTORY).join(ORIGINAL).as_path(),
                OsStr::new(QUARANTINE),
            )
            .err()
            .ok_or_else(|| io::Error::other("symbolic-link quarantine unexpectedly succeeded"))?;

        assert_eq!(error.commit(), RepositoryGcCommit::NotChanged);
        assert_eq!(error.into_source().kind(), io::ErrorKind::PermissionDenied);
        assert!(
            repository
                .path()
                .join(DIRECTORY)
                .join(ORIGINAL)
                .is_symlink()
        );
        assert!(!repository.path().join(DIRECTORY).join(QUARANTINE).exists());
        Ok(())
    }
}
