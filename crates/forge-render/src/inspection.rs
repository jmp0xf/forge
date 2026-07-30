//! Read-only, per-target inspection of repository host adapters.

use std::error::Error;
use std::fmt;
use std::io;
use std::path::Path;

use forge_core::ports::{Hasher, RepositoryFilePort};
use forge_core::{Digest, RepoRelativePath};

use crate::managed_block::{
    LineEnding, ManagedBlock, ManagedBlockError, ManagedBlockSyntax, MergeAction,
    merge_managed_block_with_line_ending,
};
use crate::repository_file_digest;

/// Maximum accepted size for an existing or resulting adapter file.
///
/// Managed bodies have their own tighter limits. This complete-file limit bounds brownfield
/// reads retained for review and prevents a small generated block from causing huge postimages.
pub const ADAPTER_FILE_MAX_BYTES: usize = 1024 * 1024;

/// One desired managed target. Inspection never interprets this as write authorization.
#[derive(Debug, Clone, Copy)]
pub struct AdapterInspectionRequest<'a> {
    pub path: &'a RepoRelativePath,
    pub block_id: &'a str,
    pub desired_body: &'a str,
    pub syntax: ManagedBlockSyntax,
    /// Explicit fallback for a new file or an existing file with no reliable uniform style.
    pub fallback_line_ending: LineEnding,
    /// Optional unmanaged text accepted as semantically equivalent after trailing line endings.
    pub equivalent_unmanaged: Option<&'a str>,
}

/// Repository fact explaining why an edit would be needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FileEditReason {
    MissingFile,
    MissingManagedBlock,
    AssetChanged,
    UserEdited,
}

/// Complete six-state classification exposed by the read-only inspector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdapterInspectionKind {
    Satisfied,
    MissingFile,
    MissingManagedBlock,
    AssetChanged,
    UserEdited,
    EquivalentUnmanaged,
}

/// A bounded postimage derived without writing. `UserEdited` uses a forced merge only for review.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectedFileEdit {
    pub reason: FileEditReason,
    /// Reviewed fallback used when the target itself has no reliable line-ending style.
    pub fallback_line_ending: LineEnding,
    pub expected_preimage: Option<Digest>,
    pub preview_postimage: Vec<u8>,
    /// Digest of the complete resulting file, including preserved user-owned bytes.
    pub full_postimage_digest: Digest,
}

/// Read-only state of one requested adapter target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdapterInspectionState {
    Satisfied {
        /// Digest of the complete satisfied file, not only the managed block body.
        full_postimage_digest: Digest,
    },
    EquivalentUnmanaged {
        /// Digest of the complete equivalent unmanaged file.
        full_file_digest: Digest,
    },
    Edit(InspectedFileEdit),
}

impl AdapterInspectionState {
    #[must_use]
    pub const fn kind(&self) -> AdapterInspectionKind {
        match self {
            Self::Satisfied { .. } => AdapterInspectionKind::Satisfied,
            Self::EquivalentUnmanaged { .. } => AdapterInspectionKind::EquivalentUnmanaged,
            Self::Edit(edit) => match edit.reason {
                FileEditReason::MissingFile => AdapterInspectionKind::MissingFile,
                FileEditReason::MissingManagedBlock => AdapterInspectionKind::MissingManagedBlock,
                FileEditReason::AssetChanged => AdapterInspectionKind::AssetChanged,
                FileEditReason::UserEdited => AdapterInspectionKind::UserEdited,
            },
        }
    }
}

/// One canonical target observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterTargetInspection {
    pub path: RepoRelativePath,
    pub block_id: String,
    pub state: AdapterInspectionState,
}

impl AdapterTargetInspection {
    #[must_use]
    pub const fn kind(&self) -> AdapterInspectionKind {
        self.state.kind()
    }
}

/// Canonically ordered observations for every requested init adapter target.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AdapterInspectionReport {
    pub targets: Vec<AdapterTargetInspection>,
}

/// A bounded inspection failure. User-edited content is an observation, not an error here.
#[derive(Debug)]
pub enum AdapterInspectionError {
    DuplicateTarget(RepoRelativePath),
    Read {
        path: RepoRelativePath,
        source: io::Error,
    },
    ExistingFileTooLarge {
        path: RepoRelativePath,
        max_bytes: usize,
    },
    ResultingFileTooLarge {
        path: RepoRelativePath,
        bytes: usize,
        max_bytes: usize,
    },
    ManagedBlock {
        path: RepoRelativePath,
        source: ManagedBlockError,
    },
    InconsistentMergeAction {
        path: RepoRelativePath,
        action: MergeAction,
        existing: bool,
    },
}

impl fmt::Display for AdapterInspectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateTarget(path) => write!(
                formatter,
                "adapter target `{}` was requested more than once",
                path.as_path().display()
            ),
            Self::Read { path, source } => write!(
                formatter,
                "cannot read adapter target `{}`: {source}",
                path.as_path().display()
            ),
            Self::ExistingFileTooLarge { path, max_bytes } => write!(
                formatter,
                "existing adapter target `{}` exceeds the {max_bytes}-byte read limit",
                path.as_path().display()
            ),
            Self::ResultingFileTooLarge {
                path,
                bytes,
                max_bytes,
            } => write!(
                formatter,
                "resulting adapter target `{}` is {bytes} bytes, above the {max_bytes}-byte limit",
                path.as_path().display()
            ),
            Self::ManagedBlock { path, source } => write!(
                formatter,
                "cannot inspect managed block in `{}`: {source}",
                path.as_path().display()
            ),
            Self::InconsistentMergeAction {
                path,
                action,
                existing,
            } => write!(
                formatter,
                "managed merge for `{}` returned {action:?} with existing={existing}",
                path.as_path().display()
            ),
        }
    }
}

impl Error for AdapterInspectionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            Self::ManagedBlock { source, .. } => Some(source),
            Self::DuplicateTarget(_)
            | Self::ExistingFileTooLarge { .. }
            | Self::ResultingFileTooLarge { .. }
            | Self::InconsistentMergeAction { .. } => None,
        }
    }
}

/// Inspects every target in stable path order without writing repository state.
///
/// User-edited blocks are force-merged only into a bounded preview so callers can report all such
/// targets together. A later planner or apply boundary must still require explicit authorization.
pub fn inspect_adapter_targets<F, H>(
    repository_root: &Path,
    requests: &[AdapterInspectionRequest<'_>],
    filesystem: &F,
    hasher: &H,
) -> Result<AdapterInspectionReport, AdapterInspectionError>
where
    F: RepositoryFilePort + ?Sized,
    H: Hasher + ?Sized,
{
    let mut ordered = requests.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| {
        left.path
            .cmp(right.path)
            .then_with(|| left.block_id.cmp(right.block_id))
    });
    for pair in ordered.windows(2) {
        if pair[0].path == pair[1].path {
            return Err(AdapterInspectionError::DuplicateTarget(
                pair[0].path.clone(),
            ));
        }
    }

    let mut targets = Vec::with_capacity(ordered.len());
    for request in ordered {
        targets.push(inspect_one(repository_root, request, filesystem, hasher)?);
    }
    Ok(AdapterInspectionReport { targets })
}

fn inspect_one<F, H>(
    repository_root: &Path,
    request: &AdapterInspectionRequest<'_>,
    filesystem: &F,
    hasher: &H,
) -> Result<AdapterTargetInspection, AdapterInspectionError>
where
    F: RepositoryFilePort + ?Sized,
    H: Hasher + ?Sized,
{
    let existing = match filesystem.read_confined_bounded(
        repository_root,
        request.path,
        ADAPTER_FILE_MAX_BYTES,
    ) {
        Ok(existing) => existing,
        Err(source) if source.kind() == io::ErrorKind::InvalidData => {
            return Err(AdapterInspectionError::ExistingFileTooLarge {
                path: request.path.clone(),
                max_bytes: ADAPTER_FILE_MAX_BYTES,
            });
        }
        Err(source) => {
            return Err(AdapterInspectionError::Read {
                path: request.path.clone(),
                source,
            });
        }
    };
    if let Some(bytes) = &existing {
        if request
            .equivalent_unmanaged
            .is_some_and(|desired| equivalent_unmanaged(bytes, desired))
        {
            return Ok(AdapterTargetInspection {
                path: request.path.clone(),
                block_id: request.block_id.to_owned(),
                state: AdapterInspectionState::EquivalentUnmanaged {
                    full_file_digest: repository_file_digest(hasher, bytes),
                },
            });
        }
    }

    let block = ManagedBlock {
        id: request.block_id,
        body: request.desired_body,
    };
    let ordinary = merge_managed_block_with_line_ending(
        existing.as_deref(),
        &block,
        request.syntax,
        request.fallback_line_ending,
        hasher,
        false,
    );
    let (reason, merged) = match ordinary {
        Ok(merged) => (
            reason_from_action(request.path, merged.action, existing.is_some())?,
            merged,
        ),
        Err(ManagedBlockError::UserEdited { .. }) => {
            let preview = merge_managed_block_with_line_ending(
                existing.as_deref(),
                &block,
                request.syntax,
                request.fallback_line_ending,
                hasher,
                true,
            )
            .map_err(|source| AdapterInspectionError::ManagedBlock {
                path: request.path.clone(),
                source,
            })?;
            if preview.action != MergeAction::Replace {
                return Err(AdapterInspectionError::InconsistentMergeAction {
                    path: request.path.clone(),
                    action: preview.action,
                    existing: existing.is_some(),
                });
            }
            (Some(FileEditReason::UserEdited), preview)
        }
        Err(source) => {
            return Err(AdapterInspectionError::ManagedBlock {
                path: request.path.clone(),
                source,
            });
        }
    };
    enforce_resulting_limit(request.path, merged.content.len())?;
    let state = match reason {
        None => AdapterInspectionState::Satisfied {
            full_postimage_digest: repository_file_digest(hasher, &merged.content),
        },
        Some(reason) => AdapterInspectionState::Edit(InspectedFileEdit {
            reason,
            fallback_line_ending: request.fallback_line_ending,
            expected_preimage: existing
                .as_deref()
                .map(|bytes| repository_file_digest(hasher, bytes)),
            full_postimage_digest: repository_file_digest(hasher, &merged.content),
            preview_postimage: merged.content,
        }),
    };
    Ok(AdapterTargetInspection {
        path: request.path.clone(),
        block_id: request.block_id.to_owned(),
        state,
    })
}

fn reason_from_action(
    path: &RepoRelativePath,
    action: MergeAction,
    existing: bool,
) -> Result<Option<FileEditReason>, AdapterInspectionError> {
    match (action, existing) {
        (MergeAction::Create, false) => Ok(Some(FileEditReason::MissingFile)),
        (MergeAction::Append, true) => Ok(Some(FileEditReason::MissingManagedBlock)),
        (MergeAction::Replace, true) => Ok(Some(FileEditReason::AssetChanged)),
        (MergeAction::NoOp, true) => Ok(None),
        _ => Err(AdapterInspectionError::InconsistentMergeAction {
            path: path.clone(),
            action,
            existing,
        }),
    }
}

fn enforce_resulting_limit(
    path: &RepoRelativePath,
    bytes: usize,
) -> Result<(), AdapterInspectionError> {
    if bytes > ADAPTER_FILE_MAX_BYTES {
        Err(AdapterInspectionError::ResultingFileTooLarge {
            path: path.clone(),
            bytes,
            max_bytes: ADAPTER_FILE_MAX_BYTES,
        })
    } else {
        Ok(())
    }
}

fn equivalent_unmanaged(existing: &[u8], desired: &str) -> bool {
    let Ok(mut text) = std::str::from_utf8(existing) else {
        return false;
    };
    loop {
        if let Some(value) = text.strip_suffix("\r\n") {
            text = value;
        } else if let Some(value) = text.strip_suffix('\n') {
            text = value;
        } else {
            break;
        }
    }
    text == desired
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;
    use std::error::Error;
    use std::io;
    use std::path::{Path, PathBuf};

    use forge_core::ports::{Hasher, RepositoryFilePort};
    use forge_core::{Digest, RepoRelativePath};

    use crate::managed_block::{
        LineEnding, ManagedBlock, ManagedBlockError, ManagedBlockSyntax, merge_markdown_block,
    };
    use crate::repository_file_digest;

    use super::{
        ADAPTER_FILE_MAX_BYTES, AdapterInspectionError, AdapterInspectionKind,
        AdapterInspectionRequest, AdapterInspectionState, FileEditReason, inspect_adapter_targets,
    };

    #[derive(Debug, Default)]
    struct MemoryFiles {
        files: RefCell<BTreeMap<PathBuf, Vec<u8>>>,
        writes: Cell<usize>,
    }

    impl MemoryFiles {
        fn from_files(files: impl IntoIterator<Item = (PathBuf, Vec<u8>)>) -> Self {
            Self {
                files: RefCell::new(files.into_iter().collect()),
                writes: Cell::new(0),
            }
        }
    }

    impl RepositoryFilePort for MemoryFiles {
        fn read_confined(
            &self,
            _repository_root: &Path,
            _path: &RepoRelativePath,
        ) -> io::Result<Option<Vec<u8>>> {
            Err(io::Error::other(
                "inspection fixture forbids unbounded reads",
            ))
        }

        fn read_confined_bounded(
            &self,
            _repository_root: &Path,
            path: &RepoRelativePath,
            max_bytes: usize,
        ) -> io::Result<Option<Vec<u8>>> {
            let files = self.files.borrow();
            match files.get(path.as_path()) {
                Some(bytes) if bytes.len() > max_bytes => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "fixture file exceeds read limit",
                )),
                Some(bytes) => Ok(Some(bytes.clone())),
                None => Ok(None),
            }
        }

        fn write_atomic_confined(
            &self,
            _repository_root: &Path,
            _path: &RepoRelativePath,
            _bytes: &[u8],
        ) -> io::Result<()> {
            self.writes.set(self.writes.get() + 1);
            Err(io::Error::other("inspection must not write"))
        }
    }

    #[derive(Debug)]
    struct FixtureHasher;

    impl Hasher for FixtureHasher {
        fn digest(&self, chunks: &[&[u8]]) -> Digest {
            let mut hash = 0xcbf2_9ce4_8422_2325_u64;
            for chunk in chunks {
                hash ^= chunk.len() as u64;
                hash = hash.wrapping_mul(0x100_0000_01b3);
                for byte in *chunk {
                    hash ^= u64::from(*byte);
                    hash = hash.wrapping_mul(0x100_0000_01b3);
                }
            }
            Digest::new(format!("fixture:{hash:016x}"))
        }
    }

    #[test]
    fn aggregates_all_six_states_without_treating_user_edits_as_authorization()
    -> Result<(), Box<dyn Error>> {
        let paths = [
            RepoRelativePath::new("01-missing.md")?,
            RepoRelativePath::new("02-block-missing.md")?,
            RepoRelativePath::new("03-asset-changed.md")?,
            RepoRelativePath::new("04-user-edited.md")?,
            RepoRelativePath::new("05-satisfied.md")?,
            RepoRelativePath::new("06-equivalent.md")?,
        ];
        let old_block = rendered_block("old body")?;
        let user_edited = String::from_utf8(rendered_block("original body")?)?
            .replace("original body", "human body")
            .into_bytes();
        let satisfied = merge_markdown_block(
            Some(b"# Human preface\r\n"),
            &ManagedBlock {
                id: "project-index",
                body: "desired body",
            },
            &FixtureHasher,
            false,
        )?
        .content;
        let files = MemoryFiles::from_files([
            (paths[1].as_path().to_path_buf(), b"human only\n".to_vec()),
            (paths[2].as_path().to_path_buf(), old_block),
            (paths[3].as_path().to_path_buf(), user_edited.clone()),
            (paths[4].as_path().to_path_buf(), satisfied.clone()),
            (
                paths[5].as_path().to_path_buf(),
                b"@AGENTS.md\r\n\r\n".to_vec(),
            ),
        ]);
        let requests = paths
            .iter()
            .enumerate()
            .map(|(index, path)| AdapterInspectionRequest {
                path,
                block_id: if index == 5 {
                    "claude-pointer"
                } else {
                    "project-index"
                },
                desired_body: if index == 5 {
                    "@AGENTS.md"
                } else {
                    "desired body"
                },
                syntax: ManagedBlockSyntax::Markdown,
                fallback_line_ending: LineEnding::Lf,
                equivalent_unmanaged: (index == 5).then_some("@AGENTS.md"),
            })
            .collect::<Vec<_>>();

        let report =
            inspect_adapter_targets(Path::new("/repo"), &requests, &files, &FixtureHasher)?;

        assert_eq!(
            report
                .targets
                .iter()
                .map(|target| target.kind())
                .collect::<Vec<_>>(),
            [
                AdapterInspectionKind::MissingFile,
                AdapterInspectionKind::MissingManagedBlock,
                AdapterInspectionKind::AssetChanged,
                AdapterInspectionKind::UserEdited,
                AdapterInspectionKind::Satisfied,
                AdapterInspectionKind::EquivalentUnmanaged,
            ]
        );
        let edited = report
            .targets
            .iter()
            .find(|target| target.kind() == AdapterInspectionKind::UserEdited)
            .ok_or_else(|| io::Error::other("missing user-edited observation"))?;
        match &edited.state {
            AdapterInspectionState::Edit(edit) => {
                assert_eq!(edit.reason, FileEditReason::UserEdited);
                assert!(std::str::from_utf8(&edit.preview_postimage)?.contains("desired body"));
                assert_ne!(edit.preview_postimage, user_edited);
            }
            _ => return Err("user-edited target did not retain its preview".into()),
        }
        let complete = report
            .targets
            .iter()
            .find(|target| target.kind() == AdapterInspectionKind::Satisfied)
            .ok_or_else(|| io::Error::other("missing satisfied observation"))?;
        match &complete.state {
            AdapterInspectionState::Satisfied {
                full_postimage_digest,
            } => assert_eq!(
                full_postimage_digest,
                &repository_file_digest(&FixtureHasher, &satisfied)
            ),
            _ => return Err("satisfied target did not retain its full-file digest".into()),
        }
        assert_eq!(files.writes.get(), 0);
        Ok(())
    }

    #[test]
    fn rejects_oversized_existing_and_resulting_files_before_returning_a_preview()
    -> Result<(), Box<dyn Error>> {
        let path = RepoRelativePath::new("AGENTS.md")?;
        let request = AdapterInspectionRequest {
            path: &path,
            block_id: "project-index",
            desired_body: "body",
            syntax: ManagedBlockSyntax::Markdown,
            fallback_line_ending: LineEnding::Lf,
            equivalent_unmanaged: None,
        };
        let oversized = MemoryFiles::from_files([(
            path.as_path().to_path_buf(),
            vec![b'a'; ADAPTER_FILE_MAX_BYTES + 1],
        )]);
        assert!(matches!(
            inspect_adapter_targets(Path::new("/repo"), &[request], &oversized, &FixtureHasher),
            Err(AdapterInspectionError::ExistingFileTooLarge {
                max_bytes: ADAPTER_FILE_MAX_BYTES,
                ..
            })
        ));

        let at_limit = MemoryFiles::from_files([(
            path.as_path().to_path_buf(),
            vec![b'a'; ADAPTER_FILE_MAX_BYTES],
        )]);
        assert!(matches!(
            inspect_adapter_targets(Path::new("/repo"), &[request], &at_limit, &FixtureHasher),
            Err(AdapterInspectionError::ResultingFileTooLarge {
                bytes,
                max_bytes: ADAPTER_FILE_MAX_BYTES,
                ..
            }) if bytes > ADAPTER_FILE_MAX_BYTES
        ));
        assert_eq!(oversized.writes.get(), 0);
        assert_eq!(at_limit.writes.get(), 0);
        Ok(())
    }

    #[test]
    fn structural_and_future_marker_errors_remain_typed_failures() -> Result<(), Box<dyn Error>> {
        let path = RepoRelativePath::new("AGENTS.md")?;
        let files = MemoryFiles::from_files([(
            path.as_path().to_path_buf(),
            concat!(
                "<!-- forge:begin block=project-index schema=2 hash=future -->\n",
                "body\n",
                "<!-- forge:end block=project-index -->\n"
            )
            .as_bytes()
            .to_vec(),
        )]);
        let request = AdapterInspectionRequest {
            path: &path,
            block_id: "project-index",
            desired_body: "body",
            syntax: ManagedBlockSyntax::Markdown,
            fallback_line_ending: LineEnding::Lf,
            equivalent_unmanaged: None,
        };

        assert!(matches!(
            inspect_adapter_targets(Path::new("/repo"), &[request], &files, &FixtureHasher),
            Err(AdapterInspectionError::ManagedBlock {
                source: ManagedBlockError::UnsupportedSchema { schema: 2, .. },
                ..
            })
        ));
        Ok(())
    }

    fn rendered_block(body: &str) -> Result<Vec<u8>, ManagedBlockError> {
        ManagedBlock {
            id: "project-index",
            body,
        }
        .render_markdown(&FixtureHasher)
    }
}
