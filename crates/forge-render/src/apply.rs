//! Verified application of reviewed repository change plans.

use std::error::Error;
use std::fmt;
use std::io;
use std::path::Path;

use forge_core::ports::{Hasher, RepositoryFilePort};
use forge_core::{Digest, RepoRelativePath};

use crate::inspection::{ADAPTER_FILE_MAX_BYTES, FileEditReason};
use crate::managed_block::{ManagedBlock, ManagedBlockError, MergeAction, merge_markdown_block};
use crate::plan::{ChangePlan, FileEdit, FileEditKind};
use crate::repository_file_digest;

const SUPPORTED_PLAN_SCHEMA: u16 = 1;

/// One target for which the confined file port confirmed a completed write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrittenFile {
    pub path: RepoRelativePath,
    pub kind: FileEditKind,
    pub preimage: Option<Digest>,
    pub postimage: Digest,
    /// True only after a confined reread matched the recomputed postimage byte-for-byte.
    pub verified: bool,
}

/// Honest multi-file progress. Forge never claims that these writes formed an OS transaction.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ApplyReport {
    pub written: Vec<WrittenFile>,
    /// Targets whose write call had not completed successfully when application stopped.
    pub unwritten: Vec<RepoRelativePath>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyErrorKind {
    UnsupportedPlanSchema,
    DuplicateTarget,
    InvalidEdit,
    ExistingFileTooLarge,
    PostimageTooLarge,
    ReadPreimage,
    PreimagePresenceMismatch,
    PreimageDigestMismatch,
    ManagedBlockConflict,
    UnexpectedMergeAction,
    PostimageDigestMismatch,
    ReadBeforeWrite,
    PrewriteDrift,
    Write,
    ReadAfterWrite,
    PostwriteMissing,
    PostwriteMismatch,
}

#[derive(Debug)]
enum ApplyErrorSource {
    Io(io::Error),
    ManagedBlock(ManagedBlockError),
}

impl fmt::Display for ApplyErrorSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => error.fmt(formatter),
            Self::ManagedBlock(error) => error.fmt(formatter),
        }
    }
}

impl Error for ApplyErrorSource {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::ManagedBlock(error) => Some(error),
        }
    }
}

/// A typed apply failure carrying the exact multi-file progress observed before stopping.
#[derive(Debug)]
pub struct ApplyError {
    kind: ApplyErrorKind,
    path: Option<RepoRelativePath>,
    detail: String,
    source: Option<ApplyErrorSource>,
    report: Box<ApplyReport>,
}

impl ApplyError {
    #[must_use]
    pub const fn kind(&self) -> ApplyErrorKind {
        self.kind
    }

    #[must_use]
    pub fn path(&self) -> Option<&RepoRelativePath> {
        self.path.as_ref()
    }

    #[must_use]
    pub fn report(&self) -> &ApplyReport {
        self.report.as_ref()
    }

    fn plain(
        kind: ApplyErrorKind,
        path: Option<RepoRelativePath>,
        detail: impl Into<String>,
        report: ApplyReport,
    ) -> Self {
        Self {
            kind,
            path,
            detail: detail.into(),
            source: None,
            report: Box::new(report),
        }
    }

    fn io(
        kind: ApplyErrorKind,
        path: RepoRelativePath,
        detail: impl Into<String>,
        source: io::Error,
        report: ApplyReport,
    ) -> Self {
        Self {
            kind,
            path: Some(path),
            detail: detail.into(),
            source: Some(ApplyErrorSource::Io(source)),
            report: Box::new(report),
        }
    }

    fn managed_block(
        path: RepoRelativePath,
        source: ManagedBlockError,
        report: ApplyReport,
    ) -> Self {
        Self {
            kind: ApplyErrorKind::ManagedBlockConflict,
            path: Some(path),
            detail: String::from("managed-block merge failed during apply preflight"),
            source: Some(ApplyErrorSource::ManagedBlock(source)),
            report: Box::new(report),
        }
    }
}

impl fmt::Display for ApplyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "change-plan apply failed ({:?})", self.kind)?;
        if let Some(path) = &self.path {
            write!(formatter, " at `{}`", path.as_path().display())?;
        }
        write!(formatter, ": {}", self.detail)?;
        if let Some(source) = &self.source {
            write!(formatter, ": {source}")?;
        }
        Ok(())
    }
}

impl Error for ApplyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| source as &(dyn Error + 'static))
    }
}

#[derive(Debug)]
struct PreparedEdit {
    kind: FileEditKind,
    path: RepoRelativePath,
    preimage: Option<Vec<u8>>,
    preimage_digest: Option<Digest>,
    postimage: Vec<u8>,
    postimage_digest: Digest,
}

/// Applies a complete plan only after every target passes an all-files, zero-write preflight.
///
/// Each file replacement is atomic through `RepositoryFilePort`; multiple targets are not one OS
/// transaction. Any write or verification failure returns an `ApplyError` with partial progress.
pub fn apply_change_plan<F, H>(
    repository_root: &Path,
    plan: &ChangePlan,
    filesystem: &F,
    hasher: &H,
) -> Result<ApplyReport, ApplyError>
where
    F: RepositoryFilePort + ?Sized,
    H: Hasher + ?Sized,
{
    let mut edits = plan.edits.iter().collect::<Vec<_>>();
    edits.sort_by(|left, right| left.path.cmp(&right.path));
    let mut report = initial_report(&edits);
    if let Some(pair) = edits.windows(2).find(|pair| pair[0].path == pair[1].path) {
        return Err(ApplyError::plain(
            ApplyErrorKind::DuplicateTarget,
            Some(pair[0].path.clone()),
            "the plan contains more than one edit for the same target",
            report,
        ));
    }
    if plan.schema != SUPPORTED_PLAN_SCHEMA {
        return Err(ApplyError::plain(
            ApplyErrorKind::UnsupportedPlanSchema,
            None,
            format!(
                "plan schema {} is unsupported; expected {SUPPORTED_PLAN_SCHEMA}",
                plan.schema
            ),
            report,
        ));
    }

    let mut prepared = Vec::with_capacity(edits.len());
    for edit in edits {
        prepared.push(preflight_edit(
            repository_root,
            edit,
            filesystem,
            hasher,
            &report,
        )?);
    }

    for edit in prepared {
        let current = filesystem
            .read_confined_bounded(repository_root, &edit.path, ADAPTER_FILE_MAX_BYTES)
            .map_err(|source| {
                if source.kind() == io::ErrorKind::InvalidData {
                    return ApplyError::io(
                        ApplyErrorKind::ExistingFileTooLarge,
                        edit.path.clone(),
                        format!(
                            "target exceeds the {ADAPTER_FILE_MAX_BYTES}-byte adapter file limit immediately before writing"
                        ),
                        source,
                        report.clone(),
                    );
                }
                ApplyError::io(
                    ApplyErrorKind::ReadBeforeWrite,
                    edit.path.clone(),
                    "failed to recheck the target immediately before writing",
                    source,
                    report.clone(),
                )
            })?;
        if current != edit.preimage {
            return Err(ApplyError::plain(
                ApplyErrorKind::PrewriteDrift,
                Some(edit.path.clone()),
                "target changed after all-files preflight; the current and remaining edits were not written",
                report,
            ));
        }

        filesystem
            .write_atomic_confined(repository_root, &edit.path, &edit.postimage)
            .map_err(|source| {
                ApplyError::io(
                    ApplyErrorKind::Write,
                    edit.path.clone(),
                    "confined atomic file write did not complete successfully",
                    source,
                    report.clone(),
                )
            })?;
        report.unwritten.retain(|path| path != &edit.path);
        report.written.push(WrittenFile {
            path: edit.path.clone(),
            kind: edit.kind,
            preimage: edit.preimage_digest.clone(),
            postimage: edit.postimage_digest.clone(),
            verified: false,
        });

        let observed = filesystem
            .read_confined_bounded(repository_root, &edit.path, ADAPTER_FILE_MAX_BYTES)
            .map_err(|source| {
                if source.kind() == io::ErrorKind::InvalidData {
                    return ApplyError::io(
                        ApplyErrorKind::PostimageTooLarge,
                        edit.path.clone(),
                        format!(
                            "write completed but the target exceeds the {ADAPTER_FILE_MAX_BYTES}-byte adapter file limit"
                        ),
                        source,
                        report.clone(),
                    );
                }
                ApplyError::io(
                    ApplyErrorKind::ReadAfterWrite,
                    edit.path.clone(),
                    "write completed but the target could not be reread for verification",
                    source,
                    report.clone(),
                )
            })?
            .ok_or_else(|| {
                ApplyError::plain(
                    ApplyErrorKind::PostwriteMissing,
                    Some(edit.path.clone()),
                    "write completed but the target was missing during verification",
                    report.clone(),
                )
            })?;
        let observed_digest = repository_file_digest(hasher, &observed);
        if observed != edit.postimage || observed_digest != edit.postimage_digest {
            return Err(ApplyError::plain(
                ApplyErrorKind::PostwriteMismatch,
                Some(edit.path.clone()),
                format!(
                    "write completed but verification observed digest {}, expected {}",
                    observed_digest.as_str(),
                    edit.postimage_digest.as_str()
                ),
                report,
            ));
        }
        if let Some(written) = report.written.last_mut() {
            written.verified = true;
        }
    }
    Ok(report)
}

fn initial_report(edits: &[&FileEdit]) -> ApplyReport {
    let mut unwritten = edits
        .iter()
        .map(|edit| edit.path.clone())
        .collect::<Vec<_>>();
    unwritten.dedup();
    ApplyReport {
        written: Vec::new(),
        unwritten,
    }
}

fn preflight_edit<F, H>(
    repository_root: &Path,
    edit: &FileEdit,
    filesystem: &F,
    hasher: &H,
    report: &ApplyReport,
) -> Result<PreparedEdit, ApplyError>
where
    F: RepositoryFilePort + ?Sized,
    H: Hasher + ?Sized,
{
    let valid_shape = match (edit.kind, edit.reason, edit.expected_preimage.is_some()) {
        (FileEditKind::Create, FileEditReason::MissingFile, false) => true,
        (
            FileEditKind::ReplaceManagedBlock,
            FileEditReason::MissingManagedBlock | FileEditReason::AssetChanged,
            true,
        ) => true,
        (FileEditKind::ReplaceManagedBlock, FileEditReason::UserEdited, true) => edit.force,
        _ => false,
    };
    if !valid_shape {
        return Err(ApplyError::plain(
            ApplyErrorKind::InvalidEdit,
            Some(edit.path.clone()),
            "edit kind, reason, preimage presence, and force authorization contradict each other",
            report.clone(),
        ));
    }
    if edit.preview_postimage.len() > ADAPTER_FILE_MAX_BYTES {
        return Err(ApplyError::plain(
            ApplyErrorKind::PostimageTooLarge,
            Some(edit.path.clone()),
            format!(
                "reviewed postimage is {} bytes, above the {}-byte adapter file limit",
                edit.preview_postimage.len(),
                ADAPTER_FILE_MAX_BYTES
            ),
            report.clone(),
        ));
    }
    let existing = filesystem
        .read_confined_bounded(repository_root, &edit.path, ADAPTER_FILE_MAX_BYTES)
        .map_err(|source| {
            if source.kind() == io::ErrorKind::InvalidData {
                return ApplyError::io(
                    ApplyErrorKind::ExistingFileTooLarge,
                    edit.path.clone(),
                    format!("current adapter file exceeds the {ADAPTER_FILE_MAX_BYTES}-byte limit"),
                    source,
                    report.clone(),
                );
            }
            ApplyError::io(
                ApplyErrorKind::ReadPreimage,
                edit.path.clone(),
                "failed to read target during all-files preflight",
                source,
                report.clone(),
            )
        })?;
    if existing.is_some() != edit.expected_preimage.is_some() {
        return Err(ApplyError::plain(
            ApplyErrorKind::PreimagePresenceMismatch,
            Some(edit.path.clone()),
            "target presence differs from the reviewed plan",
            report.clone(),
        ));
    }
    let observed_preimage = existing
        .as_deref()
        .map(|bytes| repository_file_digest(hasher, bytes));
    if observed_preimage != edit.expected_preimage {
        return Err(ApplyError::plain(
            ApplyErrorKind::PreimageDigestMismatch,
            Some(edit.path.clone()),
            "target content digest differs from the reviewed preimage",
            report.clone(),
        ));
    }

    let block = ManagedBlock {
        id: edit.desired.kind.id(),
        body: &edit.desired.body,
    };
    let ordinary = merge_markdown_block(existing.as_deref(), &block, hasher, false);
    let (observed_reason, merged) = match ordinary {
        Ok(merged) => {
            let observed_reason = match (merged.action, existing.is_some()) {
                (MergeAction::Create, false) => Some(FileEditReason::MissingFile),
                (MergeAction::Append, true) => Some(FileEditReason::MissingManagedBlock),
                (MergeAction::Replace, true) => Some(FileEditReason::AssetChanged),
                (MergeAction::NoOp, true) => None,
                _ => {
                    return Err(ApplyError::plain(
                        ApplyErrorKind::UnexpectedMergeAction,
                        Some(edit.path.clone()),
                        format!(
                            "recomputed managed-block action {:?} contradicts target presence {}",
                            merged.action,
                            existing.is_some()
                        ),
                        report.clone(),
                    ));
                }
            };
            (observed_reason, merged)
        }
        Err(source @ ManagedBlockError::UserEdited { .. }) => {
            if edit.reason != FileEditReason::UserEdited {
                return Err(ApplyError::managed_block(
                    edit.path.clone(),
                    source,
                    report.clone(),
                ));
            }
            let merged = merge_markdown_block(existing.as_deref(), &block, hasher, true).map_err(
                |source| ApplyError::managed_block(edit.path.clone(), source, report.clone()),
            )?;
            if merged.action != MergeAction::Replace {
                return Err(ApplyError::plain(
                    ApplyErrorKind::UnexpectedMergeAction,
                    Some(edit.path.clone()),
                    format!(
                        "forced user-edited merge returned unexpected action {:?}",
                        merged.action
                    ),
                    report.clone(),
                ));
            }
            (Some(FileEditReason::UserEdited), merged)
        }
        Err(source) => {
            return Err(ApplyError::managed_block(
                edit.path.clone(),
                source,
                report.clone(),
            ));
        }
    };
    if observed_reason != Some(edit.reason) {
        return Err(ApplyError::plain(
            ApplyErrorKind::UnexpectedMergeAction,
            Some(edit.path.clone()),
            format!(
                "recomputed edit reason {observed_reason:?} differs from reviewed reason {:?}",
                edit.reason
            ),
            report.clone(),
        ));
    }
    if merged.content.len() > ADAPTER_FILE_MAX_BYTES {
        return Err(ApplyError::plain(
            ApplyErrorKind::PostimageTooLarge,
            Some(edit.path.clone()),
            format!(
                "recomputed postimage is {} bytes, above the {}-byte adapter file limit",
                merged.content.len(),
                ADAPTER_FILE_MAX_BYTES
            ),
            report.clone(),
        ));
    }
    let postimage_digest = repository_file_digest(hasher, &merged.content);
    if postimage_digest != edit.expected_postimage {
        return Err(ApplyError::plain(
            ApplyErrorKind::PostimageDigestMismatch,
            Some(edit.path.clone()),
            format!(
                "recomputed postimage digest {} differs from reviewed digest {}",
                postimage_digest.as_str(),
                edit.expected_postimage.as_str()
            ),
            report.clone(),
        ));
    }
    Ok(PreparedEdit {
        kind: edit.kind,
        path: edit.path.clone(),
        preimage: existing,
        preimage_digest: observed_preimage,
        postimage: merged.content,
        postimage_digest,
    })
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::error::Error;
    use std::io;
    use std::path::{Path, PathBuf};

    use forge_core::ports::{Hasher, RepositoryFilePort};
    use forge_core::{Digest, RepoId, RepoRelativePath};

    use crate::inspection::FileEditReason;
    use crate::managed_block::{
        ManagedBlock, ManagedBlockError, MergeAction, merge_markdown_block,
    };
    use crate::plan::{
        ChangePlan, DesiredManagedBlock, FileEdit, FileEditKind, ManagedBlockKind, RollbackPlan,
    };

    use super::{ApplyError, ApplyErrorKind, ApplyReport, apply_change_plan};
    use crate::repository_file_digest;

    #[derive(Debug)]
    struct ReadMutation {
        path: PathBuf,
        on_read: usize,
        content: Vec<u8>,
    }

    #[derive(Debug, Default)]
    struct ScriptedFiles {
        files: RefCell<BTreeMap<PathBuf, Vec<u8>>>,
        read_counts: RefCell<BTreeMap<PathBuf, usize>>,
        write_attempts: RefCell<Vec<PathBuf>>,
        read_mutation: RefCell<Option<ReadMutation>>,
        fail_read: Option<PathBuf>,
        fail_write: Option<PathBuf>,
        corrupt_write: Option<PathBuf>,
    }

    impl ScriptedFiles {
        fn with_files(files: impl IntoIterator<Item = (&'static str, Vec<u8>)>) -> Self {
            Self {
                files: RefCell::new(
                    files
                        .into_iter()
                        .map(|(path, content)| (PathBuf::from(path), content))
                        .collect(),
                ),
                ..Self::default()
            }
        }

        fn content(&self, path: &str) -> Option<Vec<u8>> {
            self.files.borrow().get(Path::new(path)).cloned()
        }

        fn total_reads(&self) -> usize {
            self.read_counts.borrow().values().sum()
        }

        fn attempts(&self) -> Vec<PathBuf> {
            self.write_attempts.borrow().clone()
        }

        fn read_with_limit(
            &self,
            path: &RepoRelativePath,
            max_bytes: usize,
        ) -> io::Result<Option<Vec<u8>>> {
            let path = path.as_path();
            if self.fail_read.as_deref() == Some(path) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "confined path rejected",
                ));
            }
            let read_number = {
                let mut counts = self.read_counts.borrow_mut();
                let count = counts.entry(path.to_path_buf()).or_default();
                *count += 1;
                *count
            };
            let mutation = {
                let mut pending = self.read_mutation.borrow_mut();
                if pending.as_ref().is_some_and(|mutation| {
                    mutation.path == path && mutation.on_read == read_number
                }) {
                    pending.take()
                } else {
                    None
                }
            };
            if let Some(mutation) = mutation {
                self.files
                    .borrow_mut()
                    .insert(mutation.path, mutation.content);
            }
            let files = self.files.borrow();
            match files.get(path) {
                Some(bytes) if bytes.len() > max_bytes => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "fixture file exceeds read limit",
                )),
                Some(bytes) => Ok(Some(bytes.clone())),
                None => Ok(None),
            }
        }
    }

    impl RepositoryFilePort for ScriptedFiles {
        fn read_confined(
            &self,
            _repository_root: &Path,
            _path: &RepoRelativePath,
        ) -> io::Result<Option<Vec<u8>>> {
            Err(io::Error::other("apply fixture forbids unbounded reads"))
        }

        fn read_confined_bounded(
            &self,
            _repository_root: &Path,
            path: &RepoRelativePath,
            max_bytes: usize,
        ) -> io::Result<Option<Vec<u8>>> {
            self.read_with_limit(path, max_bytes)
        }

        fn write_atomic_confined(
            &self,
            _repository_root: &Path,
            path: &RepoRelativePath,
            bytes: &[u8],
        ) -> io::Result<()> {
            let path = path.as_path();
            self.write_attempts.borrow_mut().push(path.to_path_buf());
            if self.fail_write.as_deref() == Some(path) {
                return Err(io::Error::other("scripted atomic-write failure"));
            }
            let content = if self.corrupt_write.as_deref() == Some(path) {
                b"unexpected postimage".to_vec()
            } else {
                bytes.to_vec()
            };
            self.files.borrow_mut().insert(path.to_path_buf(), content);
            Ok(())
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

    fn edit(
        path: &str,
        existing: Option<&[u8]>,
        kind: ManagedBlockKind,
        body: &str,
        force: bool,
    ) -> Result<FileEdit, Box<dyn Error>> {
        let desired = DesiredManagedBlock {
            kind,
            body: body.to_owned(),
        };
        let ordinary = merge_markdown_block(
            existing,
            &ManagedBlock {
                id: desired.kind.id(),
                body: &desired.body,
            },
            &FixtureHasher,
            false,
        );
        let (reason, merged) = match ordinary {
            Ok(merged) => {
                let reason = match merged.action {
                    MergeAction::Create => FileEditReason::MissingFile,
                    MergeAction::Append => FileEditReason::MissingManagedBlock,
                    MergeAction::Replace | MergeAction::NoOp => FileEditReason::AssetChanged,
                };
                (reason, merged)
            }
            Err(ManagedBlockError::UserEdited { .. }) if force => (
                FileEditReason::UserEdited,
                merge_markdown_block(
                    existing,
                    &ManagedBlock {
                        id: desired.kind.id(),
                        body: &desired.body,
                    },
                    &FixtureHasher,
                    true,
                )?,
            ),
            Err(error) => return Err(error.into()),
        };
        Ok(FileEdit {
            kind: if existing.is_some() {
                FileEditKind::ReplaceManagedBlock
            } else {
                FileEditKind::Create
            },
            reason,
            path: RepoRelativePath::new(path)?,
            desired,
            expected_preimage: existing
                .map(|content| repository_file_digest(&FixtureHasher, content)),
            expected_postimage: repository_file_digest(&FixtureHasher, &merged.content),
            preview_postimage: merged.content,
            force,
        })
    }

    fn plan(edits: Vec<FileEdit>) -> ChangePlan {
        ChangePlan {
            schema: 1,
            repository: RepoId::from("local:apply-fixture"),
            model_digest: Digest::from("fixture:model"),
            edits,
            assumptions: Vec::new(),
            skipped: Vec::new(),
            rollback: RollbackPlan::default(),
        }
    }

    fn error_from(result: Result<ApplyReport, ApplyError>) -> Result<ApplyError, Box<dyn Error>> {
        match result {
            Ok(_) => Err(io::Error::other("expected apply to fail").into()),
            Err(error) => Ok(error),
        }
    }

    #[test]
    fn later_preimage_drift_prevents_every_write() -> Result<(), Box<dyn Error>> {
        let valid = edit("A.md", None, ManagedBlockKind::ProjectIndex, "a", false)?;
        let existing = b"human-owned\n".to_vec();
        let mut stale = edit(
            "B.md",
            Some(&existing),
            ManagedBlockKind::ProjectIndex,
            "b",
            false,
        )?;
        stale.expected_preimage = Some(Digest::from("fixture:stale"));
        let files = ScriptedFiles::with_files([("B.md", existing)]);

        let error = error_from(apply_change_plan(
            Path::new("/repo"),
            &plan(vec![valid, stale]),
            &files,
            &FixtureHasher,
        ))?;

        assert_eq!(error.kind(), ApplyErrorKind::PreimageDigestMismatch);
        assert!(error.report().written.is_empty());
        assert_eq!(
            error.report().unwritten,
            vec![
                RepoRelativePath::new("A.md")?,
                RepoRelativePath::new("B.md")?
            ]
        );
        assert!(files.attempts().is_empty());
        assert_eq!(files.total_reads(), 2);
        Ok(())
    }

    #[test]
    fn duplicate_target_is_rejected_before_any_read() -> Result<(), Box<dyn Error>> {
        let target = edit(
            "AGENTS.md",
            None,
            ManagedBlockKind::ProjectIndex,
            "body",
            false,
        )?;
        let files = ScriptedFiles::default();

        let error = error_from(apply_change_plan(
            Path::new("/repo"),
            &plan(vec![target.clone(), target]),
            &files,
            &FixtureHasher,
        ))?;

        assert_eq!(error.kind(), ApplyErrorKind::DuplicateTarget);
        assert_eq!(files.total_reads(), 0);
        assert!(files.attempts().is_empty());
        Ok(())
    }

    #[test]
    fn contradictory_edit_reason_is_rejected_before_any_read() -> Result<(), Box<dyn Error>> {
        let mut target = edit(
            "AGENTS.md",
            None,
            ManagedBlockKind::ProjectIndex,
            "body",
            false,
        )?;
        target.reason = FileEditReason::MissingManagedBlock;
        let files = ScriptedFiles::default();

        let error = error_from(apply_change_plan(
            Path::new("/repo"),
            &plan(vec![target]),
            &files,
            &FixtureHasher,
        ))?;

        assert_eq!(error.kind(), ApplyErrorKind::InvalidEdit);
        assert_eq!(files.total_reads(), 0);
        assert!(files.attempts().is_empty());
        Ok(())
    }

    #[test]
    fn force_cannot_make_a_user_edit_look_like_asset_drift() -> Result<(), Box<dyn Error>> {
        let original = merge_markdown_block(
            None,
            &ManagedBlock {
                id: ManagedBlockKind::ProjectIndex.id(),
                body: "original body",
            },
            &FixtureHasher,
            false,
        )?
        .content;
        let edited = String::from_utf8(original)?
            .replace("original body", "human body")
            .into_bytes();
        let mut target = edit(
            "AGENTS.md",
            Some(&edited),
            ManagedBlockKind::ProjectIndex,
            "new generated body",
            true,
        )?;
        assert_eq!(target.reason, FileEditReason::UserEdited);
        target.reason = FileEditReason::AssetChanged;
        let files = ScriptedFiles::with_files([("AGENTS.md", edited)]);

        let error = error_from(apply_change_plan(
            Path::new("/repo"),
            &plan(vec![target]),
            &files,
            &FixtureHasher,
        ))?;

        assert_eq!(error.kind(), ApplyErrorKind::ManagedBlockConflict);
        assert!(files.attempts().is_empty());
        Ok(())
    }

    #[test]
    fn oversized_preimage_is_rejected_by_the_bounded_read_without_writing()
    -> Result<(), Box<dyn Error>> {
        let reviewed = b"human guidance\n".to_vec();
        let target = edit(
            "AGENTS.md",
            Some(&reviewed),
            ManagedBlockKind::ProjectIndex,
            "body",
            false,
        )?;
        let files = ScriptedFiles::with_files([(
            "AGENTS.md",
            vec![b'x'; crate::inspection::ADAPTER_FILE_MAX_BYTES + 1],
        )]);

        let error = error_from(apply_change_plan(
            Path::new("/repo"),
            &plan(vec![target]),
            &files,
            &FixtureHasher,
        ))?;

        assert_eq!(error.kind(), ApplyErrorKind::ExistingFileTooLarge);
        assert_eq!(files.total_reads(), 1);
        assert!(files.attempts().is_empty());
        Ok(())
    }

    #[test]
    fn preview_bytes_are_not_a_write_authority() -> Result<(), Box<dyn Error>> {
        let mut target = edit(
            "AGENTS.md",
            None,
            ManagedBlockKind::ProjectIndex,
            "reviewed body",
            false,
        )?;
        let recomputed = target.preview_postimage.clone();
        target.preview_postimage = b"tampered preview".to_vec();
        let files = ScriptedFiles::default();

        let report = apply_change_plan(
            Path::new("/repo"),
            &plan(vec![target]),
            &files,
            &FixtureHasher,
        )?;

        assert_eq!(files.content("AGENTS.md"), Some(recomputed));
        assert!(report.unwritten.is_empty());
        assert_eq!(report.written.len(), 1);
        assert!(report.written[0].verified);
        Ok(())
    }

    #[test]
    fn create_race_is_detected_before_the_write() -> Result<(), Box<dyn Error>> {
        let target = edit(
            "AGENTS.md",
            None,
            ManagedBlockKind::ProjectIndex,
            "body",
            false,
        )?;
        let intruder = b"created concurrently\n".to_vec();
        let files = ScriptedFiles {
            read_mutation: RefCell::new(Some(ReadMutation {
                path: PathBuf::from("AGENTS.md"),
                on_read: 2,
                content: intruder.clone(),
            })),
            ..ScriptedFiles::default()
        };

        let error = error_from(apply_change_plan(
            Path::new("/repo"),
            &plan(vec![target]),
            &files,
            &FixtureHasher,
        ))?;

        assert_eq!(error.kind(), ApplyErrorKind::PrewriteDrift);
        assert!(error.report().written.is_empty());
        assert_eq!(files.content("AGENTS.md"), Some(intruder));
        assert!(files.attempts().is_empty());
        Ok(())
    }

    #[test]
    fn write_failure_reports_verified_prefix_and_unwritten_suffix() -> Result<(), Box<dyn Error>> {
        let a = edit("A.md", None, ManagedBlockKind::ProjectIndex, "a", false)?;
        let b = edit("B.md", None, ManagedBlockKind::ProjectIndex, "b", false)?;
        let c = edit("C.md", None, ManagedBlockKind::ProjectIndex, "c", false)?;
        let files = ScriptedFiles {
            fail_write: Some(PathBuf::from("B.md")),
            ..ScriptedFiles::default()
        };

        let error = error_from(apply_change_plan(
            Path::new("/repo"),
            &plan(vec![c, b, a]),
            &files,
            &FixtureHasher,
        ))?;

        assert_eq!(error.kind(), ApplyErrorKind::Write);
        assert_eq!(error.report().written.len(), 1);
        assert_eq!(error.report().written[0].path.as_path(), Path::new("A.md"));
        assert!(error.report().written[0].verified);
        assert_eq!(
            error.report().unwritten,
            vec![
                RepoRelativePath::new("B.md")?,
                RepoRelativePath::new("C.md")?
            ]
        );
        assert_eq!(
            files.attempts(),
            vec![PathBuf::from("A.md"), PathBuf::from("B.md")]
        );
        assert!(files.content("A.md").is_some());
        assert!(files.content("C.md").is_none());
        Ok(())
    }

    #[test]
    fn postwrite_inconsistency_is_reported_as_unverified_written_state()
    -> Result<(), Box<dyn Error>> {
        let target = edit(
            "AGENTS.md",
            None,
            ManagedBlockKind::ProjectIndex,
            "body",
            false,
        )?;
        let files = ScriptedFiles {
            corrupt_write: Some(PathBuf::from("AGENTS.md")),
            ..ScriptedFiles::default()
        };

        let error = error_from(apply_change_plan(
            Path::new("/repo"),
            &plan(vec![target]),
            &files,
            &FixtureHasher,
        ))?;

        assert_eq!(error.kind(), ApplyErrorKind::PostwriteMismatch);
        assert_eq!(error.report().written.len(), 1);
        assert!(!error.report().written[0].verified);
        assert!(error.report().unwritten.is_empty());
        assert_eq!(
            files.content("AGENTS.md"),
            Some(b"unexpected postimage".to_vec())
        );
        Ok(())
    }

    #[test]
    fn oversized_postwrite_observation_is_bounded_and_reported_as_unverified()
    -> Result<(), Box<dyn Error>> {
        let target = edit(
            "AGENTS.md",
            None,
            ManagedBlockKind::ProjectIndex,
            "body",
            false,
        )?;
        let files = ScriptedFiles {
            read_mutation: RefCell::new(Some(ReadMutation {
                path: PathBuf::from("AGENTS.md"),
                on_read: 3,
                content: vec![b'x'; crate::inspection::ADAPTER_FILE_MAX_BYTES + 1],
            })),
            ..ScriptedFiles::default()
        };

        let error = error_from(apply_change_plan(
            Path::new("/repo"),
            &plan(vec![target]),
            &files,
            &FixtureHasher,
        ))?;

        assert_eq!(error.kind(), ApplyErrorKind::PostimageTooLarge);
        assert_eq!(error.report().written.len(), 1);
        assert!(!error.report().written[0].verified);
        assert!(error.report().unwritten.is_empty());
        Ok(())
    }

    #[test]
    fn success_sorts_targets_and_preserves_unmanaged_bytes() -> Result<(), Box<dyn Error>> {
        let existing = b"# Human guidance\r\nkeep exactly\r\n".to_vec();
        let replace = edit(
            "Z.md",
            Some(&existing),
            ManagedBlockKind::ProjectIndex,
            "generated",
            false,
        )?;
        let expected_replace = replace.preview_postimage.clone();
        let create = edit(
            "A.md",
            None,
            ManagedBlockKind::ClaudePointer,
            "See AGENTS.md.",
            false,
        )?;
        let files = ScriptedFiles::with_files([("Z.md", existing.clone())]);

        let report = apply_change_plan(
            Path::new("/repo"),
            &plan(vec![replace, create]),
            &files,
            &FixtureHasher,
        )?;

        assert!(report.unwritten.is_empty());
        assert_eq!(
            report
                .written
                .iter()
                .map(|written| written.path.as_path())
                .collect::<Vec<_>>(),
            vec![Path::new("A.md"), Path::new("Z.md")]
        );
        assert!(report.written.iter().all(|written| written.verified));
        assert_eq!(files.content("Z.md"), Some(expected_replace));
        assert!(
            files
                .content("Z.md")
                .is_some_and(|content| content.starts_with(&existing))
        );
        Ok(())
    }

    #[test]
    fn force_replaces_only_the_selected_block() -> Result<(), Box<dyn Error>> {
        let first = merge_markdown_block(
            None,
            &ManagedBlock {
                id: ManagedBlockKind::ProjectIndex.id(),
                body: "first old",
            },
            &FixtureHasher,
            false,
        )?;
        let second = merge_markdown_block(
            Some(&first.content),
            &ManagedBlock {
                id: ManagedBlockKind::ClaudePointer.id(),
                body: "second old",
            },
            &FixtureHasher,
            false,
        )?;
        let edited = String::from_utf8(second.content)?
            .replace("first old", "first human edit")
            .replace("second old", "second human edit")
            .into_bytes();
        let target = edit(
            "AGENTS.md",
            Some(&edited),
            ManagedBlockKind::ProjectIndex,
            "first new",
            true,
        )?;
        let expected = target.preview_postimage.clone();
        let files = ScriptedFiles::with_files([("AGENTS.md", edited)]);

        let report = apply_change_plan(
            Path::new("/repo"),
            &plan(vec![target]),
            &files,
            &FixtureHasher,
        )?;

        assert_eq!(files.content("AGENTS.md"), Some(expected.clone()));
        assert!(String::from_utf8(expected)?.contains("second human edit"));
        assert!(report.written[0].verified);
        Ok(())
    }

    #[test]
    fn port_path_rejection_fails_closed_without_writing() -> Result<(), Box<dyn Error>> {
        let target = edit(
            "AGENTS.md",
            None,
            ManagedBlockKind::ProjectIndex,
            "body",
            false,
        )?;
        let files = ScriptedFiles {
            fail_read: Some(PathBuf::from("AGENTS.md")),
            ..ScriptedFiles::default()
        };

        let error = error_from(apply_change_plan(
            Path::new("/repo"),
            &plan(vec![target]),
            &files,
            &FixtureHasher,
        ))?;

        assert_eq!(error.kind(), ApplyErrorKind::ReadPreimage);
        assert!(error.report().written.is_empty());
        assert!(files.attempts().is_empty());
        Ok(())
    }

    #[test]
    fn no_op_edit_is_rejected_as_a_planner_error() -> Result<(), Box<dyn Error>> {
        let created = edit(
            "AGENTS.md",
            None,
            ManagedBlockKind::ProjectIndex,
            "same body",
            false,
        )?;
        let existing = created.preview_postimage;
        let target = FileEdit {
            kind: FileEditKind::ReplaceManagedBlock,
            reason: FileEditReason::AssetChanged,
            path: RepoRelativePath::new("AGENTS.md")?,
            desired: created.desired,
            expected_preimage: Some(repository_file_digest(&FixtureHasher, &existing)),
            preview_postimage: existing.clone(),
            expected_postimage: repository_file_digest(&FixtureHasher, &existing),
            force: false,
        };
        let files = ScriptedFiles::with_files([("AGENTS.md", existing)]);

        let error = error_from(apply_change_plan(
            Path::new("/repo"),
            &plan(vec![target]),
            &files,
            &FixtureHasher,
        ))?;

        assert_eq!(error.kind(), ApplyErrorKind::UnexpectedMergeAction);
        assert!(files.attempts().is_empty());
        Ok(())
    }
}
