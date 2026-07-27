//! Authoritative acquisition of the current HEAD-to-worktree repository scope.
//!
//! Clean tracked entries reuse Git's index object identity. Every staged, unstaged, or untracked
//! file is read completely and hashed with BLAKE3; symlinks bind their link content. Acquisition
//! fails closed for conflicts, dirty Gitlinks, opaque index flags, unsafe paths, partial reads, or
//! a repository snapshot that changes while it is being prepared.

use std::collections::BTreeMap;
use std::fs::{self, File, Metadata};
use std::io::{self, BufReader, Read as _};
use std::path::{Path, PathBuf};

use forge_core::git::{
    BranchOid, ChangeKind, GitIndexEntry, GitIndexTag, PorcelainV2Status, StatusEntry,
    SubmoduleState, XyStatus,
};
use forge_core::ports::GitPort as _;
use forge_core::scope::{
    GitlinkDirtyState, PreparedScope, PreparedScopeEntry, ScopeContentIdentity, ScopeDigestError,
    ScopeHead, ScopeMode, ScopeObjectId,
};
use forge_core::{
    GitError, OperationControl, OperationControlError, RepoRelativePath, UnlimitedOperationControl,
};
use thiserror::Error;

use crate::fs::NativeFileSystem;
use crate::git::GitCli;

/// Behavior identifier bound into Forge's evidence-behavior digest.
pub const SCOPE_ACQUISITION_PROTOCOL: &str = "forge.scope-acquisition/v1";

/// A complete scope could not be acquired without guessing or accepting a partial snapshot.
#[derive(Debug, Error)]
pub enum ScopeAcquisitionError {
    #[error(transparent)]
    Control(#[from] OperationControlError),
    #[error(transparent)]
    Git(#[from] GitError),
    #[error(transparent)]
    InvalidScope(#[from] ScopeDigestError),
    #[error("Git status did not report a HEAD or unborn-repository identity")]
    MissingHead,
    #[error("Git index contains an unmerged stage for {path:?}")]
    UnmergedIndex { path: RepoRelativePath },
    #[error("Git status contains an unmerged entry for {path:?}")]
    UnmergedStatus { path: RepoRelativePath },
    #[error("Git index state {tag:?} makes {path:?} content opaque")]
    OpaqueIndexState {
        path: RepoRelativePath,
        tag: GitIndexTag,
    },
    #[error("Git reported incompatible or duplicate state for {path:?}")]
    InconsistentGitState { path: RepoRelativePath },
    #[error("repository path {path:?} disappeared while its content was required")]
    MissingWorktreePath { path: RepoRelativePath },
    #[error("repository path {path:?} has unsupported kind `{kind}`")]
    UnsupportedPathKind {
        path: RepoRelativePath,
        kind: &'static str,
    },
    #[error("repository path {path:?} changed while Forge acquired its content")]
    WorktreePathChanged { path: RepoRelativePath },
    #[error("repository status or index changed while Forge acquired the scope")]
    RepositoryChanged,
    #[error("failed to {operation} repository path `{path}`: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// A prepared scope tied to one exact retained status/index observation.
///
/// The candidate is not current evidence until [`Self::confirm`] succeeds. Keeping the initial
/// observations borrowed lets a cache-hit caller reuse the live detection snapshot without cloning
/// a large index or weakening the final repository/worktree check.
#[derive(Debug)]
pub struct RepositoryScopeCandidate<'a> {
    root: &'a Path,
    status: &'a PorcelainV2Status,
    index_entries: &'a [GitIndexEntry],
    scope: PreparedScope,
    worktree_snapshots: BTreeMap<RepoRelativePath, WorktreeSnapshot>,
}

impl RepositoryScopeCandidate<'_> {
    /// Returns the exact prepared scope for dependency evaluation before final confirmation.
    #[must_use]
    pub const fn prepared_scope(&self) -> &PreparedScope {
        &self.scope
    }

    /// Confirms that HEAD/index/status and every dirty path still match the retained candidate.
    pub fn confirm(self, git: &GitCli) -> Result<PreparedScope, ScopeAcquisitionError> {
        self.confirm_controlled(git, &UnlimitedOperationControl)
    }

    /// Confirms the complete candidate with one shared operation-wide control.
    pub fn confirm_controlled(
        self,
        git: &GitCli,
        control: &dyn OperationControl,
    ) -> Result<PreparedScope, ScopeAcquisitionError> {
        control.checkpoint()?;
        let status_after = git.status(self.root)?;
        control.checkpoint()?;
        let index_after = git.index_entries(self.root)?;
        control.checkpoint()?;
        if self.status != &status_after || self.index_entries != index_after {
            return Err(ScopeAcquisitionError::RepositoryChanged);
        }

        confirm_worktree_snapshots(self.root, self.worktree_snapshots, control)?;
        control.checkpoint()?;
        Ok(self.scope)
    }
}

/// Prepares a scope from one already-proven coherent status/index snapshot without new Git I/O.
///
/// This is intended for a process-local detection seed, not persisted state. The caller must have
/// acquired both inputs from the same stable repository observation and must call
/// [`RepositoryScopeCandidate::confirm`] after all dependent reads.
pub fn prepare_repository_scope_candidate<'a>(
    root: &'a Path,
    status: &'a PorcelainV2Status,
    index_entries: &'a [GitIndexEntry],
) -> Result<RepositoryScopeCandidate<'a>, ScopeAcquisitionError> {
    prepare_repository_scope_candidate_controlled(
        root,
        status,
        index_entries,
        &UnlimitedOperationControl,
    )
}

/// Prepares a scope candidate with cooperative checkpoints over every retained path.
pub fn prepare_repository_scope_candidate_controlled<'a>(
    root: &'a Path,
    status: &'a PorcelainV2Status,
    index_entries: &'a [GitIndexEntry],
    control: &dyn OperationControl,
) -> Result<RepositoryScopeCandidate<'a>, ScopeAcquisitionError> {
    let (scope, worktree_snapshots) = prepare_scope(root, status, index_entries, control)?;
    Ok(RepositoryScopeCandidate {
        root,
        status,
        index_entries,
        scope,
        worktree_snapshots,
    })
}

/// Acquires one complete, stable repository scope using fresh Git and filesystem observations.
pub fn acquire_repository_scope(
    git: &GitCli,
    root: &Path,
) -> Result<PreparedScope, ScopeAcquisitionError> {
    acquire_repository_scope_controlled(git, root, &UnlimitedOperationControl)
}

/// Acquires one complete scope under an operation-wide deadline and cancellation source.
///
/// A timeout or interruption returns a typed error and never exposes the partially prepared scope.
pub fn acquire_repository_scope_controlled(
    git: &GitCli,
    root: &Path,
    control: &dyn OperationControl,
) -> Result<PreparedScope, ScopeAcquisitionError> {
    control.checkpoint()?;
    let status_before = git.status(root)?;
    control.checkpoint()?;
    let index_before = git.index_entries(root)?;
    control.checkpoint()?;
    prepare_repository_scope_candidate_controlled(root, &status_before, &index_before, control)?
        .confirm_controlled(git, control)
}

fn confirm_worktree_snapshots(
    root: &Path,
    worktree_snapshots: BTreeMap<RepoRelativePath, WorktreeSnapshot>,
    control: &dyn OperationControl,
) -> Result<(), ScopeAcquisitionError> {
    // A dirty or untracked path can change without altering its porcelain status. Re-hash every
    // such path and require the exact same mode/content identity before returning the scope.
    for (path, expected) in worktree_snapshots {
        control.checkpoint()?;
        let actual = snapshot_worktree_path(root, &path, expected.tracked_mode, control)?
            .ok_or_else(|| ScopeAcquisitionError::MissingWorktreePath { path: path.clone() })?;
        if actual.mode != expected.mode || actual.digest != expected.digest {
            return Err(ScopeAcquisitionError::WorktreePathChanged { path });
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WorktreeSnapshot {
    mode: ScopeMode,
    digest: [u8; 32],
    tracked_mode: Option<ScopeMode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathStatus {
    Tracked {
        xy: XyStatus,
        submodule: SubmoduleState,
    },
    Untracked,
}

fn prepare_scope(
    root: &Path,
    status: &PorcelainV2Status,
    index_entries: &[GitIndexEntry],
    control: &dyn OperationControl,
) -> Result<(PreparedScope, BTreeMap<RepoRelativePath, WorktreeSnapshot>), ScopeAcquisitionError> {
    control.checkpoint()?;
    let head = match status.branch.oid.as_ref() {
        Some(BranchOid::Commit(object_id)) => ScopeHead::Commit(ScopeObjectId::new(
            status.object_format,
            object_id.as_bytes(),
        )?),
        Some(BranchOid::Unborn) => ScopeHead::Unborn(status.object_format),
        None => return Err(ScopeAcquisitionError::MissingHead),
    };
    let mut statuses = collect_path_statuses(status, control)?;
    let mut prepared = Vec::with_capacity(index_entries.len().saturating_add(statuses.len()));
    let mut worktree_snapshots = BTreeMap::new();

    for index_entry in index_entries {
        control.checkpoint()?;
        if index_entry.stage != 0 {
            return Err(ScopeAcquisitionError::UnmergedIndex {
                path: index_entry.path.clone(),
            });
        }
        if !index_entry.tag.is_ordinary_cached() {
            return Err(ScopeAcquisitionError::OpaqueIndexState {
                path: index_entry.path.clone(),
                tag: index_entry.tag,
            });
        }

        let index_mode = ScopeMode::try_from(index_entry.mode)?;
        let path_status = statuses.remove(&index_entry.path);
        if path_status.is_some_and(|state| state.worktree_deleted()) {
            continue;
        }

        if index_mode == ScopeMode::Gitlink {
            if let Some(PathStatus::Tracked { xy, .. }) = path_status
                && xy.worktree == ChangeKind::TypeChanged
            {
                append_worktree_entry(
                    root,
                    &index_entry.path,
                    Some(index_mode),
                    &mut prepared,
                    &mut worktree_snapshots,
                    control,
                )?;
                continue;
            }
            let dirty = match path_status {
                None => GitlinkDirtyState::new(false, false, false),
                Some(PathStatus::Tracked {
                    submodule:
                        SubmoduleState::Submodule {
                            commit_changed,
                            tracked_changes,
                            untracked_changes,
                        },
                    ..
                }) => GitlinkDirtyState::new(commit_changed, tracked_changes, untracked_changes),
                Some(_) => {
                    return Err(ScopeAcquisitionError::InconsistentGitState {
                        path: index_entry.path.clone(),
                    });
                }
            };
            prepared.push(PreparedScopeEntry::new(
                index_entry.path.clone(),
                ScopeMode::Gitlink,
                ScopeContentIdentity::Gitlink {
                    object_id: ScopeObjectId::new(
                        status.object_format,
                        index_entry.object_id.as_bytes(),
                    )?,
                    dirty,
                },
            )?);
            continue;
        }

        if path_status.is_some() {
            append_worktree_entry(
                root,
                &index_entry.path,
                Some(index_mode),
                &mut prepared,
                &mut worktree_snapshots,
                control,
            )?;
        } else {
            prepared.push(PreparedScopeEntry::new(
                index_entry.path.clone(),
                index_mode,
                ScopeContentIdentity::IndexBlob(ScopeObjectId::new(
                    status.object_format,
                    index_entry.object_id.as_bytes(),
                )?),
            )?);
        }
    }

    // Remaining entries are untracked paths or index deletions. A deleted path contributes no
    // candidate entry; any file that still exists is bound by its complete worktree bytes.
    for (path, path_status) in statuses {
        control.checkpoint()?;
        if matches!(
            path_status,
            PathStatus::Tracked {
                xy: XyStatus {
                    index: ChangeKind::Deleted,
                    worktree: ChangeKind::Deleted,
                },
                ..
            }
        ) {
            continue;
        }
        match snapshot_worktree_path(root, &path, None, control)? {
            Some(snapshot) => {
                prepared.push(PreparedScopeEntry::new(
                    path.clone(),
                    snapshot.mode,
                    ScopeContentIdentity::WorktreeBlake3(snapshot.digest),
                )?);
                worktree_snapshots.insert(path, snapshot);
            }
            None if matches!(
                path_status,
                PathStatus::Tracked {
                    xy: XyStatus {
                        index: ChangeKind::Deleted,
                        ..
                    },
                    ..
                }
            ) => {}
            None => return Err(ScopeAcquisitionError::MissingWorktreePath { path }),
        }
    }

    control.checkpoint()?;
    Ok((PreparedScope::new(head, prepared)?, worktree_snapshots))
}

impl PathStatus {
    const fn worktree_deleted(self) -> bool {
        matches!(
            self,
            Self::Tracked {
                xy: XyStatus {
                    worktree: ChangeKind::Deleted,
                    ..
                },
                ..
            }
        )
    }
}

fn collect_path_statuses(
    status: &PorcelainV2Status,
    control: &dyn OperationControl,
) -> Result<BTreeMap<RepoRelativePath, PathStatus>, ScopeAcquisitionError> {
    let mut paths = BTreeMap::new();
    for entry in &status.entries {
        control.checkpoint()?;
        let candidate = match entry {
            StatusEntry::Ordinary(entry) => Some((
                entry.path.clone(),
                PathStatus::Tracked {
                    xy: entry.status,
                    submodule: entry.submodule,
                },
            )),
            StatusEntry::RenamedOrCopied(entry) => Some((
                entry.path.clone(),
                PathStatus::Tracked {
                    xy: entry.status,
                    submodule: entry.submodule,
                },
            )),
            StatusEntry::Unmerged(entry) => {
                return Err(ScopeAcquisitionError::UnmergedStatus {
                    path: entry.path.clone(),
                });
            }
            StatusEntry::Untracked(path) => Some((path.clone(), PathStatus::Untracked)),
            StatusEntry::Ignored(_) => None,
        };
        if let Some((path, state)) = candidate
            && paths.insert(path.clone(), state).is_some()
        {
            return Err(ScopeAcquisitionError::InconsistentGitState { path });
        }
    }
    Ok(paths)
}

fn append_worktree_entry(
    root: &Path,
    path: &RepoRelativePath,
    tracked_mode: Option<ScopeMode>,
    prepared: &mut Vec<PreparedScopeEntry>,
    worktree_snapshots: &mut BTreeMap<RepoRelativePath, WorktreeSnapshot>,
    control: &dyn OperationControl,
) -> Result<(), ScopeAcquisitionError> {
    let snapshot = snapshot_worktree_path(root, path, tracked_mode, control)?
        .ok_or_else(|| ScopeAcquisitionError::MissingWorktreePath { path: path.clone() })?;
    prepared.push(PreparedScopeEntry::new(
        path.clone(),
        snapshot.mode,
        ScopeContentIdentity::WorktreeBlake3(snapshot.digest),
    )?);
    worktree_snapshots.insert(path.clone(), snapshot);
    Ok(())
}

fn snapshot_worktree_path(
    root: &Path,
    path: &RepoRelativePath,
    tracked_mode: Option<ScopeMode>,
    control: &dyn OperationControl,
) -> Result<Option<WorktreeSnapshot>, ScopeAcquisitionError> {
    control.checkpoint()?;
    let filesystem = NativeFileSystem;
    let kind = filesystem
        .path_kind(root, path)
        .map_err(|source| path_io("inspect", root, path, source))?;
    let target = root.join(path.as_path());
    let (mode, digest) = match kind {
        forge_core::PathKind::Missing => return Ok(None),
        forge_core::PathKind::File => {
            let metadata = fs::symlink_metadata(&target)
                .map_err(|source| path_io("inspect", root, path, source))?;
            let mode = regular_scope_mode(&metadata, tracked_mode);
            let digest = hash_regular_file(&target, path, control)?;
            (mode, digest)
        }
        forge_core::PathKind::Symlink => {
            let target_value = fs::read_link(&target)
                .map_err(|source| path_io("read symlink", root, path, source))?;
            (
                ScopeMode::Symlink,
                hash_symlink_target(&target_value, path)?,
            )
        }
        forge_core::PathKind::Directory => {
            return Err(ScopeAcquisitionError::UnsupportedPathKind {
                path: path.clone(),
                kind: "directory",
            });
        }
        forge_core::PathKind::Other => {
            return Err(ScopeAcquisitionError::UnsupportedPathKind {
                path: path.clone(),
                kind: "special",
            });
        }
    };

    let final_kind = filesystem
        .path_kind(root, path)
        .map_err(|source| path_io("recheck", root, path, source))?;
    control.checkpoint()?;
    let expected_kind = if mode == ScopeMode::Symlink {
        forge_core::PathKind::Symlink
    } else {
        forge_core::PathKind::File
    };
    if final_kind != expected_kind {
        return Err(ScopeAcquisitionError::WorktreePathChanged { path: path.clone() });
    }
    Ok(Some(WorktreeSnapshot {
        mode,
        digest,
        tracked_mode,
    }))
}

fn hash_regular_file(
    target: &Path,
    path: &RepoRelativePath,
    control: &dyn OperationControl,
) -> Result<[u8; 32], ScopeAcquisitionError> {
    control.checkpoint()?;
    let file = File::open(target).map_err(|source| ScopeAcquisitionError::Io {
        operation: "open",
        path: path.as_path().to_path_buf(),
        source,
    })?;
    let metadata_before = file
        .metadata()
        .map_err(|source| ScopeAcquisitionError::Io {
            operation: "inspect open",
            path: path.as_path().to_path_buf(),
            source,
        })?;
    let mut reader = BufReader::new(file);
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        control.checkpoint()?;
        let count = reader
            .read(&mut buffer)
            .map_err(|source| ScopeAcquisitionError::Io {
                operation: "read",
                path: path.as_path().to_path_buf(),
                source,
            })?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    control.checkpoint()?;
    let metadata_after =
        reader
            .get_ref()
            .metadata()
            .map_err(|source| ScopeAcquisitionError::Io {
                operation: "reinspect open",
                path: path.as_path().to_path_buf(),
                source,
            })?;
    if !same_open_file_snapshot(&metadata_before, &metadata_after) {
        return Err(ScopeAcquisitionError::WorktreePathChanged { path: path.clone() });
    }
    control.checkpoint()?;
    Ok(*hasher.finalize().as_bytes())
}

fn same_open_file_snapshot(before: &Metadata, after: &Metadata) -> bool {
    before.len() == after.len()
        && before.modified().ok() == after.modified().ok()
        && before.file_type() == after.file_type()
}

#[cfg(unix)]
fn regular_scope_mode(metadata: &Metadata, _tracked_mode: Option<ScopeMode>) -> ScopeMode {
    use std::os::unix::fs::PermissionsExt as _;

    if metadata.permissions().mode() & 0o111 == 0 {
        ScopeMode::Regular
    } else {
        ScopeMode::Executable
    }
}

#[cfg(not(unix))]
fn regular_scope_mode(_metadata: &Metadata, tracked_mode: Option<ScopeMode>) -> ScopeMode {
    match tracked_mode {
        Some(ScopeMode::Executable) => ScopeMode::Executable,
        _ => ScopeMode::Regular,
    }
}

#[cfg(unix)]
fn hash_symlink_target(
    target: &Path,
    _path: &RepoRelativePath,
) -> Result<[u8; 32], ScopeAcquisitionError> {
    use std::os::unix::ffi::OsStrExt as _;

    Ok(*blake3::hash(target.as_os_str().as_bytes()).as_bytes())
}

#[cfg(not(unix))]
fn hash_symlink_target(
    target: &Path,
    path: &RepoRelativePath,
) -> Result<[u8; 32], ScopeAcquisitionError> {
    let bytes = target
        .as_os_str()
        .to_str()
        .ok_or_else(|| ScopeAcquisitionError::Io {
            operation: "encode symlink",
            path: path.as_path().to_path_buf(),
            source: io::Error::new(
                io::ErrorKind::InvalidData,
                "symlink target is not representable as UTF-8 on this platform",
            ),
        })?
        .as_bytes();
    Ok(*blake3::hash(bytes).as_bytes())
}

fn path_io(
    operation: &'static str,
    root: &Path,
    path: &RepoRelativePath,
    source: io::Error,
) -> ScopeAcquisitionError {
    ScopeAcquisitionError::Io {
        operation,
        path: root.join(path.as_path()),
        source,
    }
}
