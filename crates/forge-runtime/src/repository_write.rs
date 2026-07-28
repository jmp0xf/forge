//! Handle-relative repository writes.
//!
//! The path-oriented validation in `fs` is useful for diagnostics, but it cannot make the
//! interval between the last check and the final rename safe. This module pins the repository
//! root and every target ancestor with directory handles. Temporary-file creation and commit are
//! then relative to the pinned target parent, so replacing a visible ancestor cannot redirect the
//! write to the replacement tree.

use crate::fs::NewFileMode;

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

#[derive(Debug, Clone, Copy)]
enum ExpectedPreimage<'a> {
    Any,
    Exact(Option<&'a [u8]>),
}

#[cfg(unix)]
mod platform {
    use std::ffi::{OsStr, OsString};
    use std::fs::File;
    use std::io::{self, Read as _, Write as _};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Component, Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use nix::errno::Errno;
    use nix::fcntl::{AtFlags, OFlag, open, openat, renameat};
    use nix::sys::stat::{Mode, SFlag, fstatat, mkdirat};
    use nix::unistd::{UnlinkatFlags, linkat, unlinkat};

    use forge_core::branding::CLI_NAME;

    use super::{CommitMode, ExpectedPreimage, NewFileMode, WriteEvent};
    use forge_core::ports::{RepositoryWriteCommit, RepositoryWriteError, RepositoryWriteOutcome};

    const TEMPORARY_NAME_ATTEMPTS: u64 = 128;
    static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[derive(Debug)]
    pub(crate) struct RootHandle {
        directory: File,
        path: PathBuf,
        identity: (u64, u64),
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
            let (parent_path, leaf) = split_target(relative)?;
            let parent = match self.open_parent(parent_path, NewFileMode::Default, false) {
                Ok(parent) => parent,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error),
            };
            read_target_bounded(&parent, leaf, max_bytes)
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
            let mut current = self.directory.try_clone()?;
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
        let descriptor = match openat(
            parent,
            Path::new(leaf),
            OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        ) {
            Ok(descriptor) => descriptor,
            Err(Errno::ENOENT) => return Ok(None),
            Err(error) => return Err(errno_to_io(error)),
        };
        let file = File::from(descriptor);
        let metadata = file.metadata()?;
        let max_bytes_u64 = u64::try_from(max_bytes).unwrap_or(u64::MAX);
        if !metadata.is_file() || metadata.len() > max_bytes_u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "repository target exceeds its bounded regular-file contract",
            ));
        }
        let capacity =
            usize::try_from(metadata.len()).map_or(max_bytes, |size| size.min(max_bytes));
        let mut bytes = Vec::with_capacity(capacity);
        file.take(max_bytes_u64.saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() > max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "repository target grew beyond its bounded read limit",
            ));
        }
        Ok(Some(bytes))
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
    use std::mem::{offset_of, size_of};
    use std::os::windows::ffi::OsStrExt as _;
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
        HANDLE, INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError, UNICODE_STRING,
    };
    use windows_sys::Win32::Security::SECURITY_DESCRIPTOR;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateFileW, DELETE, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_INFO,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
        FILE_GENERIC_WRITE, FILE_ID_INFO, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_TRAVERSE, FileDispositionInfo, FileIdInfo,
        GetFileInformationByHandle, GetFileInformationByHandleEx, OPEN_EXISTING, READ_CONTROL,
        SYNCHRONIZE, SetFileInformationByHandle, WRITE_DAC,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    use forge_core::branding::CLI_NAME;

    use super::{CommitMode, ExpectedPreimage, NewFileMode, WriteEvent};
    use forge_core::ports::{RepositoryWriteCommit, RepositoryWriteError, RepositoryWriteOutcome};

    const TEMPORARY_NAME_ATTEMPTS: u64 = 128;
    static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[derive(Debug)]
    pub(crate) struct RootHandle {
        directory: File,
        path: PathBuf,
        identity: (u64, [u8; 16]),
    }

    impl RootHandle {
        pub(crate) fn open(path: &Path) -> io::Result<Self> {
            let wide = nul_terminated(path.as_os_str())?;
            // SAFETY: the path is NUL-terminated and the returned handle is checked before its
            // ownership is transferred to `File`.
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
            let (parent_path, leaf) = split_target(relative)?;
            let parent = match self.open_parent(parent_path, NewFileMode::Default, false) {
                Ok(parent) => parent,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error),
            };
            read_target_bounded(&parent, leaf, max_bytes)
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
            let mut current = self.directory.try_clone()?;
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

    fn read_target_bounded(
        parent: &File,
        leaf: &OsStr,
        max_bytes: usize,
    ) -> io::Result<Option<Vec<u8>>> {
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
            Err(error) => return Err(error),
        };
        validate_kind(&file, false)?;
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
        file.take(max_bytes_u64.saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() > max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "repository target grew beyond its bounded read limit",
            ));
        }
        Ok(Some(bytes))
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
    use std::io;
    use std::path::Path;

    use super::{CommitMode, NewFileMode};
    use forge_core::ports::{RepositoryWriteError, RepositoryWriteOutcome};

    #[derive(Debug)]
    pub(crate) struct RootHandle;

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
}

pub(crate) use platform::RootHandle;
