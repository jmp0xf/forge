//! Typed, side-effect-free Git domain types and porcelain v2 parser.

use std::collections::BTreeSet;
use std::io::{self, BufRead, Cursor, Read as _};
use std::path::PathBuf;

use thiserror::Error;

use crate::RepoRelativePath;

/// Object format selected by the repository for Git command output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitObjectFormat {
    Sha1,
    Sha256,
}

impl GitObjectFormat {
    #[must_use]
    fn hexadecimal_width(self) -> usize {
        match self {
            Self::Sha1 => 40,
            Self::Sha256 => 64,
        }
    }
}

/// A full object ID emitted by Git in the repository's selected output format.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GitObjectId(Vec<u8>);

impl GitObjectId {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A branch or upstream name exactly as emitted by Git.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GitRefName(Vec<u8>);

impl GitRefName {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// The current commit, including Git's explicit unborn-repository state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BranchOid {
    Commit(GitObjectId),
    Unborn,
}

/// The current branch, including detached HEAD.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BranchHead {
    Named(GitRefName),
    Detached,
}

/// Distance from the configured upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AheadBehind {
    pub ahead: u64,
    pub behind: u64,
}

/// Typed branch headers from porcelain v2.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BranchStatus {
    pub oid: Option<BranchOid>,
    pub head: Option<BranchHead>,
    pub upstream: Option<GitRefName>,
    pub ahead_behind: Option<AheadBehind>,
}

/// One side of porcelain v2's `XY` state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    Unmodified,
    Modified,
    TypeChanged,
    Added,
    Deleted,
    Renamed,
    Copied,
    Unmerged,
}

/// Index and worktree state for a tracked entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XyStatus {
    pub index: ChangeKind,
    pub worktree: ChangeKind,
}

/// Porcelain v2's four-byte submodule state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmoduleState {
    NotSubmodule,
    Submodule {
        commit_changed: bool,
        tracked_changes: bool,
        untracked_changes: bool,
    },
}

/// A six-digit octal mode emitted by porcelain v2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GitMode([u8; 6]);

impl GitMode {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
}

/// An ordinary changed tracked entry (`1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrdinaryEntry {
    pub status: XyStatus,
    pub submodule: SubmoduleState,
    pub head_mode: GitMode,
    pub index_mode: GitMode,
    pub worktree_mode: GitMode,
    pub head_oid: GitObjectId,
    pub index_oid: GitObjectId,
    pub path: RepoRelativePath,
}

/// Whether a type-2 record reports a rename or copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenameOrCopy {
    Rename,
    Copy,
}

/// A renamed or copied tracked entry (`2`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenamedOrCopiedEntry {
    pub status: XyStatus,
    pub submodule: SubmoduleState,
    pub head_mode: GitMode,
    pub index_mode: GitMode,
    pub worktree_mode: GitMode,
    pub head_oid: GitObjectId,
    pub index_oid: GitObjectId,
    pub operation: RenameOrCopy,
    pub score: u8,
    pub path: RepoRelativePath,
    pub original_path: RepoRelativePath,
}

/// An unmerged tracked entry (`u`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnmergedEntry {
    pub status: XyStatus,
    pub submodule: SubmoduleState,
    pub stage1_mode: GitMode,
    pub stage2_mode: GitMode,
    pub stage3_mode: GitMode,
    pub worktree_mode: GitMode,
    pub stage1_oid: GitObjectId,
    pub stage2_oid: GitObjectId,
    pub stage3_oid: GitObjectId,
    pub path: RepoRelativePath,
}

/// One porcelain v2 worktree entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusEntry {
    Ordinary(OrdinaryEntry),
    RenamedOrCopied(RenamedOrCopiedEntry),
    Unmerged(UnmergedEntry),
    Untracked(RepoRelativePath),
    Ignored(RepoRelativePath),
}

/// Parsed output of `git status --porcelain=v2 -z`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PorcelainV2Status {
    pub object_format: GitObjectFormat,
    pub branch: BranchStatus,
    pub entries: Vec<StatusEntry>,
}

impl PorcelainV2Status {
    /// Returns every changed repository path in stable order.
    ///
    /// Rename and copy records retain both endpoints so downstream impact and risk evaluation
    /// cannot silently forget the source path. Ignored entries are not worktree changes.
    #[must_use]
    pub fn changed_paths(&self) -> Vec<RepoRelativePath> {
        let mut paths = BTreeSet::new();
        for entry in &self.entries {
            match entry {
                StatusEntry::Ordinary(entry) => {
                    paths.insert(entry.path.clone());
                }
                StatusEntry::RenamedOrCopied(entry) => {
                    paths.insert(entry.path.clone());
                    paths.insert(entry.original_path.clone());
                }
                StatusEntry::Unmerged(entry) => {
                    paths.insert(entry.path.clone());
                }
                StatusEntry::Untracked(path) => {
                    paths.insert(path.clone());
                }
                StatusEntry::Ignored(_) => {}
            }
        }
        paths.into_iter().collect()
    }
}

/// Git's authoritative tracked and untracked repository paths.
///
/// Tracked paths come from the index and intentionally remain distinct from untracked paths so
/// callers can apply supplementary search-tool ignores only to the latter. Both lists are stable,
/// deduplicated native repository-relative paths.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GitFileSet {
    pub tracked: Vec<RepoRelativePath>,
    pub untracked: Vec<RepoRelativePath>,
}

/// Stable failure categories exposed by the Git side-effect port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitErrorKind {
    ExecutableUnavailable,
    UnsafeEnvironment,
    NotRepository,
    CorruptRepository,
    TimedOut,
    Interrupted,
    OutputLimit,
    InvalidData,
    CommandFailed,
    Io,
}

/// A bounded, operation-scoped Git failure suitable for deterministic policy decisions.
///
/// `detail` may contain a bounded diagnostic emitted by Git, but never command environment
/// values. Callers should branch on [`GitError::kind`] rather than parsing this text.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("git {operation} failed ({kind:?}): {detail}")]
pub struct GitError {
    kind: GitErrorKind,
    operation: &'static str,
    detail: String,
}

impl GitError {
    #[must_use]
    pub fn new(kind: GitErrorKind, operation: &'static str, detail: impl Into<String>) -> Self {
        Self {
            kind,
            operation,
            detail: detail.into(),
        }
    }

    #[must_use]
    pub const fn kind(&self) -> GitErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn operation(&self) -> &'static str {
        self.operation
    }

    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl GitFileSet {
    #[must_use]
    pub fn new(mut tracked: Vec<RepoRelativePath>, mut untracked: Vec<RepoRelativePath>) -> Self {
        tracked.sort();
        tracked.dedup();
        untracked.sort();
        untracked.dedup();
        Self { tracked, untracked }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.tracked.len().saturating_add(self.untracked.len())
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tracked.is_empty() && self.untracked.is_empty()
    }
}

/// Classification prefix emitted by `git ls-files --stage -v -z`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitIndexTag {
    Cached,
    SkipWorktree,
    Unmerged,
    Removed,
    Modified,
    Killed,
    Other,
    /// `-v` lowercases any normal tag when the assume-unchanged bit is set.
    AssumeUnchanged {
        underlying: u8,
    },
}

impl GitIndexTag {
    #[must_use]
    pub const fn is_ordinary_cached(self) -> bool {
        matches!(self, Self::Cached)
    }
}

/// One entry emitted by `git ls-files --stage -v -z`.
///
/// Multiple entries for the same path are retained when the index is unmerged; callers must
/// inspect `stage` rather than silently choosing one side of a conflict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitIndexEntry {
    pub tag: GitIndexTag,
    pub mode: GitMode,
    pub object_id: GitObjectId,
    pub stage: u8,
    pub path: RepoRelativePath,
}

/// A bounded streaming failure while parsing `git ls-files --stage -v -z` output.
#[derive(Debug, Error)]
pub enum GitIndexReadError {
    #[error("failed to read Git index at byte {offset}, record {record}: {source}")]
    Input {
        offset: usize,
        record: usize,
        #[source]
        source: io::Error,
    },
    #[error("Git index record {record} is not terminated by NUL at byte {offset}")]
    MissingNulTerminator { offset: usize, record: usize },
    #[error(
        "Git index record {record} exceeds the configured {max_bytes}-byte bound at byte {offset}"
    )]
    RecordTooLong {
        offset: usize,
        record: usize,
        max_bytes: usize,
    },
    #[error("Git index contains more than the configured {max_entries} entries")]
    TooManyEntries { max_entries: usize },
    #[error("Git index record {record} has malformed metadata at byte {offset}")]
    InvalidMetadata { offset: usize, record: usize },
    #[error("Git index record {record} has an invalid status tag at byte {offset}")]
    InvalidTag { offset: usize, record: usize },
    #[error("Git index record {record} has an invalid mode at byte {offset}")]
    InvalidMode { offset: usize, record: usize },
    #[error("Git index record {record} has an invalid object ID at byte {offset}")]
    InvalidObjectId { offset: usize, record: usize },
    #[error("Git index record {record} has an invalid stage at byte {offset}")]
    InvalidStage { offset: usize, record: usize },
    #[error("Git index record {record} contains an empty path at byte {offset}")]
    EmptyPath { offset: usize, record: usize },
    #[error("Git index record {record} contains an invalid repository path at byte {offset}")]
    InvalidPath { offset: usize, record: usize },
    #[error("Git index contains duplicate stage {stage} entries for one path")]
    DuplicatePathStage { stage: u8 },
}

/// Incrementally parses bounded, NUL-delimited index entries.
///
/// The parser accepts only the fixed `tag SP mode SP object-id SP stage TAB path NUL`
/// representation
/// requested by Forge. It preserves unmerged stages and native path bytes, rejects duplicate
/// `(path, stage)` entries, and never returns a partial typed result.
pub fn parse_git_index_reader<R>(
    mut reader: R,
    object_format: GitObjectFormat,
    max_record_bytes: usize,
    max_entries: usize,
) -> Result<Vec<GitIndexEntry>, GitIndexReadError>
where
    R: BufRead,
{
    let mut entries = Vec::new();
    let mut record = Vec::with_capacity(max_record_bytes.min(8 * 1024));
    let mut offset = 0_usize;
    let mut record_number = 0_usize;

    loop {
        record.clear();
        let record_start = offset;
        let read_bound = u64::try_from(max_record_bytes)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let bytes_read = reader
            .by_ref()
            .take(read_bound)
            .read_until(0, &mut record)
            .map_err(|source| GitIndexReadError::Input {
                offset: record_start,
                record: record_number.saturating_add(1),
                source,
            })?;
        if bytes_read == 0 {
            break;
        }

        record_number = record_number.saturating_add(1);
        offset = offset.saturating_add(bytes_read);
        if record.last().copied() != Some(0) {
            if record.len() > max_record_bytes {
                return Err(GitIndexReadError::RecordTooLong {
                    offset: record_start.saturating_add(max_record_bytes),
                    record: record_number,
                    max_bytes: max_record_bytes,
                });
            }
            return Err(GitIndexReadError::MissingNulTerminator {
                offset,
                record: record_number,
            });
        }
        record.pop();
        if record.len() > max_record_bytes {
            return Err(GitIndexReadError::RecordTooLong {
                offset: record_start.saturating_add(max_record_bytes),
                record: record_number,
                max_bytes: max_record_bytes,
            });
        }
        if entries.len() >= max_entries {
            return Err(GitIndexReadError::TooManyEntries { max_entries });
        }

        let Some(tab) = record.iter().position(|byte| *byte == b'\t') else {
            return Err(GitIndexReadError::InvalidMetadata {
                offset: record_start,
                record: record_number,
            });
        };
        let metadata = &record[..tab];
        let path_bytes = &record[tab + 1..];
        if path_bytes.is_empty() {
            return Err(GitIndexReadError::EmptyPath {
                offset: record_start.saturating_add(tab + 1),
                record: record_number,
            });
        }
        let mut fields = metadata.split(|byte| *byte == b' ');
        let (Some(tag), Some(mode), Some(object_id), Some(stage), None) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            return Err(GitIndexReadError::InvalidMetadata {
                offset: record_start,
                record: record_number,
            });
        };
        let tag = parse_index_tag(tag).ok_or(GitIndexReadError::InvalidTag {
            offset: record_start,
            record: record_number,
        })?;
        let mode_offset = record_start.saturating_add(2);
        let object_id_offset = mode_offset.saturating_add(mode.len() + 1);
        let stage_offset = object_id_offset.saturating_add(object_id.len() + 1);
        let mode = parse_index_mode(mode).ok_or(GitIndexReadError::InvalidMode {
            offset: mode_offset,
            record: record_number,
        })?;
        let object_id = parse_index_oid(object_id, object_format).ok_or(
            GitIndexReadError::InvalidObjectId {
                offset: object_id_offset,
                record: record_number,
            },
        )?;
        let stage = match stage {
            [value @ b'0'..=b'3'] => value - b'0',
            _ => {
                return Err(GitIndexReadError::InvalidStage {
                    offset: stage_offset,
                    record: record_number,
                });
            }
        };
        let path = native_path_from_git_bytes(path_bytes)
            .and_then(|path| RepoRelativePath::new(path).ok())
            .ok_or(GitIndexReadError::InvalidPath {
                offset: record_start.saturating_add(tab + 1),
                record: record_number,
            })?;
        entries.push(GitIndexEntry {
            tag,
            mode,
            object_id,
            stage,
            path,
        });
    }

    entries.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.stage.cmp(&right.stage))
    });
    if let Some(pair) = entries
        .windows(2)
        .find(|pair| pair[0].path == pair[1].path && pair[0].stage == pair[1].stage)
    {
        return Err(GitIndexReadError::DuplicatePathStage {
            stage: pair[0].stage,
        });
    }
    Ok(entries)
}

fn parse_index_tag(field: &[u8]) -> Option<GitIndexTag> {
    match field {
        b"H" => Some(GitIndexTag::Cached),
        b"S" => Some(GitIndexTag::SkipWorktree),
        b"M" => Some(GitIndexTag::Unmerged),
        b"R" => Some(GitIndexTag::Removed),
        b"C" => Some(GitIndexTag::Modified),
        b"K" => Some(GitIndexTag::Killed),
        b"?" => Some(GitIndexTag::Other),
        [underlying] if underlying.is_ascii_lowercase() => Some(GitIndexTag::AssumeUnchanged {
            underlying: underlying.to_ascii_uppercase(),
        }),
        _ => None,
    }
}

fn parse_index_mode(field: &[u8]) -> Option<GitMode> {
    if field.len() != 6 || !field.iter().all(|byte| matches!(byte, b'0'..=b'7')) {
        return None;
    }
    Some(GitMode(field.try_into().ok()?))
}

fn parse_index_oid(field: &[u8], object_format: GitObjectFormat) -> Option<GitObjectId> {
    if field.len() != object_format.hexadecimal_width() || !field.iter().all(u8::is_ascii_hexdigit)
    {
        return None;
    }
    Some(GitObjectId(field.to_vec()))
}

/// A bounded streaming failure while parsing `git ls-files -z` output.
#[derive(Debug, Error)]
pub enum GitPathListReadError {
    #[error("failed to read Git path list at byte {offset}, record {record}: {source}")]
    Input {
        offset: usize,
        record: usize,
        #[source]
        source: io::Error,
    },
    #[error("Git path list record {record} is not terminated by NUL at byte {offset}")]
    MissingNulTerminator { offset: usize, record: usize },
    #[error("Git path list record {record} contains an empty path at byte {offset}")]
    EmptyPath { offset: usize, record: usize },
    #[error("Git path list record {record} contains an invalid repository path at byte {offset}")]
    InvalidPath { offset: usize, record: usize },
    #[error(
        "Git path list record {record} exceeds the configured {max_bytes}-byte bound at byte {offset}"
    )]
    PathTooLong {
        offset: usize,
        record: usize,
        max_bytes: usize,
    },
    #[error("Git path list contains more than the configured {max_paths} paths")]
    TooManyPaths { max_paths: usize },
}

/// Incrementally parses NUL-delimited native repository paths from `git ls-files -z`.
///
/// At most `max_path_bytes + 1` bytes are buffered for one path, and `max_paths` bounds typed
/// allocation. Clean empty output is valid; every non-empty record must have a NUL terminator.
pub fn parse_git_path_list_reader<R>(
    mut reader: R,
    max_path_bytes: usize,
    max_paths: usize,
) -> Result<Vec<RepoRelativePath>, GitPathListReadError>
where
    R: BufRead,
{
    let mut paths = Vec::new();
    let mut record = Vec::with_capacity(max_path_bytes.min(8 * 1024));
    let mut offset = 0_usize;
    let mut record_number = 0_usize;

    loop {
        record.clear();
        let record_start = offset;
        let read_bound = u64::try_from(max_path_bytes)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let bytes_read = reader
            .by_ref()
            .take(read_bound)
            .read_until(0, &mut record)
            .map_err(|source| GitPathListReadError::Input {
                offset: record_start,
                record: record_number.saturating_add(1),
                source,
            })?;
        if bytes_read == 0 {
            break;
        }

        record_number = record_number.saturating_add(1);
        offset = offset.saturating_add(bytes_read);
        if record.last().copied() != Some(0) {
            if record.len() > max_path_bytes {
                return Err(GitPathListReadError::PathTooLong {
                    offset: record_start.saturating_add(max_path_bytes),
                    record: record_number,
                    max_bytes: max_path_bytes,
                });
            }
            return Err(GitPathListReadError::MissingNulTerminator {
                offset,
                record: record_number,
            });
        }
        record.pop();
        if record.is_empty() {
            return Err(GitPathListReadError::EmptyPath {
                offset: record_start,
                record: record_number,
            });
        }
        if paths.len() >= max_paths {
            return Err(GitPathListReadError::TooManyPaths { max_paths });
        }
        let path = native_path_from_git_bytes(&record)
            .and_then(|path| RepoRelativePath::new(path).ok())
            .ok_or(GitPathListReadError::InvalidPath {
                offset: record_start,
                record: record_number,
            })?;
        paths.push(path);
    }

    paths.sort();
    paths.dedup();
    Ok(paths)
}

/// Why porcelain v2 input could not be parsed.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PorcelainV2ParseErrorKind {
    #[error("record is not terminated by NUL")]
    MissingNulTerminator,
    #[error("record is empty")]
    EmptyRecord,
    #[error("record does not use the expected marker and space prefix")]
    InvalidRecordPrefix,
    #[error("record type byte 0x{marker:02x} is unknown")]
    UnknownRecordType { marker: u8 },
    #[error("field `{field}` is missing")]
    MissingField { field: &'static str },
    #[error("field `{field}` is empty")]
    EmptyField { field: &'static str },
    #[error("field `{field}` has an invalid value")]
    InvalidField { field: &'static str },
    #[error("numeric field `{field}` overflows its supported range")]
    NumberOverflow { field: &'static str },
    #[error("known header `{header}` appears more than once")]
    DuplicateHeader { header: &'static str },
    #[error("rename/copy record is missing its NUL-terminated original path")]
    MissingOriginalPath,
    #[error("record exceeds the configured {max_bytes}-byte bound")]
    RecordTooLong { max_bytes: usize },
    #[error("status contains more than the configured {max_entries} entries")]
    TooManyEntries { max_entries: usize },
    #[error("input reader failed with {kind:?}")]
    InputReadFailure { kind: io::ErrorKind },
}

/// A parse error located by byte offset and one-based logical record number.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("invalid Git porcelain v2 at byte {offset}, record {record}: {kind}")]
pub struct PorcelainV2ParseError {
    pub offset: usize,
    pub record: usize,
    pub kind: PorcelainV2ParseErrorKind,
}

/// A bounded streaming parse failure, preserving parser locations separately from input I/O.
#[derive(Debug, Error)]
pub enum PorcelainV2ReadError {
    #[error("failed to read Git porcelain v2 at byte {offset}, record {record}: {source}")]
    Input {
        offset: usize,
        record: usize,
        #[source]
        source: io::Error,
    },
    #[error(transparent)]
    Parse(#[from] PorcelainV2ParseError),
}

/// Parses raw, NUL-delimited porcelain v2 bytes using one explicit object format.
///
/// Git paths become native [`RepoRelativePath`] values. Unix preserves the original bytes;
/// platforms without byte-native paths require valid UTF-8 and fail closed otherwise.
pub fn parse_status_porcelain_v2(
    input: &[u8],
    object_format: GitObjectFormat,
) -> Result<PorcelainV2Status, PorcelainV2ParseError> {
    match parse_status_porcelain_v2_reader(
        Cursor::new(input),
        object_format,
        input.len(),
        usize::MAX,
    ) {
        Ok(status) => Ok(status),
        Err(PorcelainV2ReadError::Parse(error)) => Err(error),
        Err(PorcelainV2ReadError::Input {
            offset,
            record,
            source,
        }) => Err(PorcelainV2ParseError {
            offset,
            record,
            // `Cursor<&[u8]>` cannot produce an I/O error. Retaining a typed fallback keeps this
            // wrapper total without hiding a theoretically impossible branch behind a panic.
            kind: PorcelainV2ParseErrorKind::InputReadFailure {
                kind: source.kind(),
            },
        }),
    }
}

/// Incrementally parses NUL-delimited porcelain v2 from a buffered reader.
///
/// `max_record_bytes` bounds one logical record. A type-2 rename/copy's second path shares that
/// byte budget and retains the same logical record number and absolute byte offsets. `max_entries`
/// bounds typed worktree entries; branch headers do not consume this allowance.
/// Neither bound causes an unbounded read: the implementation only uses [`BufRead::fill_buf`] and
/// [`BufRead::consume`].
pub fn parse_status_porcelain_v2_reader<R>(
    mut reader: R,
    object_format: GitObjectFormat,
    max_record_bytes: usize,
    max_entries: usize,
) -> Result<PorcelainV2Status, PorcelainV2ReadError>
where
    R: BufRead,
{
    let mut parsed = PorcelainV2Status {
        object_format,
        branch: BranchStatus::default(),
        entries: Vec::new(),
    };
    let mut offset = 0;
    let mut record_number = 0;
    let mut record = Vec::with_capacity(max_record_bytes.min(8 * 1024));

    loop {
        let next_record_number = record_number + 1;
        let record_start = offset;
        if !read_nul_record(
            &mut reader,
            &mut record,
            max_record_bytes,
            max_record_bytes,
            record_start,
            next_record_number,
            RecordExpectation::OptionalStatus,
        )? {
            break;
        }
        record_number = next_record_number;
        offset = record_start + record.len() + 1;

        let marker = record.first().copied().ok_or(PorcelainV2ParseError {
            offset: record_start,
            record: record_number,
            kind: PorcelainV2ParseErrorKind::EmptyRecord,
        })?;

        if matches!(marker, b'1' | b'2' | b'u' | b'?' | b'!') && parsed.entries.len() >= max_entries
        {
            return Err(PorcelainV2ParseError {
                offset: record_start,
                record: record_number,
                kind: PorcelainV2ParseErrorKind::TooManyEntries { max_entries },
            }
            .into());
        }

        match marker {
            b'#' => parse_header(
                &record,
                record_start,
                record_number,
                object_format,
                &mut parsed.branch,
            )?,
            b'1' => parsed.entries.push(StatusEntry::Ordinary(parse_ordinary(
                &record,
                record_start,
                record_number,
                object_format,
            )?)),
            b'2' => {
                let partial = parse_renamed(&record, record_start, record_number, object_format)?;
                let original_limit = max_record_bytes.saturating_sub(record.len());
                let original_start = offset;
                let _present = read_nul_record(
                    &mut reader,
                    &mut record,
                    original_limit,
                    max_record_bytes,
                    original_start,
                    record_number,
                    RecordExpectation::RequiredOriginalPath,
                )?;
                if record.is_empty() {
                    return Err(PorcelainV2ParseError {
                        offset: original_start,
                        record: record_number,
                        kind: PorcelainV2ParseErrorKind::EmptyField {
                            field: "original-path",
                        },
                    }
                    .into());
                }
                offset = original_start + record.len() + 1;
                parsed
                    .entries
                    .push(StatusEntry::RenamedOrCopied(partial.finish(
                        &record,
                        original_start,
                        record_number,
                    )?));
            }
            b'u' => parsed.entries.push(StatusEntry::Unmerged(parse_unmerged(
                &record,
                record_start,
                record_number,
                object_format,
            )?)),
            b'?' => parsed
                .entries
                .push(StatusEntry::Untracked(parse_simple_path(
                    &record,
                    record_start,
                    record_number,
                )?)),
            b'!' => parsed.entries.push(StatusEntry::Ignored(parse_simple_path(
                &record,
                record_start,
                record_number,
            )?)),
            unknown => {
                return Err(PorcelainV2ParseError {
                    offset: record_start,
                    record: record_number,
                    kind: PorcelainV2ParseErrorKind::UnknownRecordType { marker: unknown },
                }
                .into());
            }
        }
    }

    Ok(parsed)
}

#[derive(Debug, Clone, Copy)]
enum RecordExpectation {
    OptionalStatus,
    RequiredOriginalPath,
}

impl RecordExpectation {
    fn missing_kind(self) -> PorcelainV2ParseErrorKind {
        match self {
            Self::OptionalStatus => PorcelainV2ParseErrorKind::MissingNulTerminator,
            Self::RequiredOriginalPath => PorcelainV2ParseErrorKind::MissingOriginalPath,
        }
    }

    fn allows_clean_end(self) -> bool {
        matches!(self, Self::OptionalStatus)
    }
}

fn read_nul_record<R>(
    reader: &mut R,
    record: &mut Vec<u8>,
    buffer_limit_bytes: usize,
    reported_record_limit_bytes: usize,
    record_start: usize,
    record_number: usize,
    expectation: RecordExpectation,
) -> Result<bool, PorcelainV2ReadError>
where
    R: BufRead,
{
    record.clear();
    loop {
        let available = reader
            .fill_buf()
            .map_err(|source| PorcelainV2ReadError::Input {
                offset: record_start + record.len(),
                record: record_number,
                source,
            })?;
        if available.is_empty() {
            if record.is_empty() && expectation.allows_clean_end() {
                return Ok(false);
            }
            return Err(PorcelainV2ParseError {
                offset: record_start + record.len(),
                record: record_number,
                kind: expectation.missing_kind(),
            }
            .into());
        }

        let terminator = available.iter().position(|byte| *byte == 0);
        let bytes_before_terminator = terminator.unwrap_or(available.len());
        let remaining = buffer_limit_bytes.saturating_sub(record.len());
        if bytes_before_terminator > remaining {
            return Err(PorcelainV2ParseError {
                offset: record_start + buffer_limit_bytes,
                record: record_number,
                kind: PorcelainV2ParseErrorKind::RecordTooLong {
                    max_bytes: reported_record_limit_bytes,
                },
            }
            .into());
        }

        record.extend_from_slice(&available[..bytes_before_terminator]);
        let consumed = bytes_before_terminator + usize::from(terminator.is_some());
        reader.consume(consumed);
        if terminator.is_some() {
            return Ok(true);
        }
    }
}

fn parse_header(
    record: &[u8],
    record_start: usize,
    record_number: usize,
    object_format: GitObjectFormat,
    branch: &mut BranchStatus,
) -> Result<(), PorcelainV2ParseError> {
    let content = record.strip_prefix(b"# ").ok_or(PorcelainV2ParseError {
        offset: record_start,
        record: record_number,
        kind: PorcelainV2ParseErrorKind::InvalidRecordPrefix,
    })?;
    let Some(separator) = content.iter().position(|byte| *byte == b' ') else {
        if let Some(header) = known_branch_header(content) {
            return Err(PorcelainV2ParseError {
                offset: record_start + record.len(),
                record: record_number,
                kind: PorcelainV2ParseErrorKind::MissingField { field: header },
            });
        }
        return Ok(());
    };
    let name = &content[..separator];
    let value = &content[separator + 1..];
    let value_offset = record_start + 2 + separator + 1;

    match name {
        b"branch.oid" => {
            reject_duplicate(
                branch.oid.is_some(),
                "branch.oid",
                value_offset,
                record_number,
            )?;
            branch.oid = Some(if value == b"(initial)" {
                BranchOid::Unborn
            } else {
                BranchOid::Commit(parse_oid(
                    value,
                    "branch.oid",
                    value_offset,
                    record_number,
                    object_format,
                )?)
            });
        }
        b"branch.head" => {
            reject_duplicate(
                branch.head.is_some(),
                "branch.head",
                value_offset,
                record_number,
            )?;
            branch.head = Some(if value == b"(detached)" {
                BranchHead::Detached
            } else {
                BranchHead::Named(parse_ref_name(
                    value,
                    "branch.head",
                    value_offset,
                    record_number,
                )?)
            });
        }
        b"branch.upstream" => {
            reject_duplicate(
                branch.upstream.is_some(),
                "branch.upstream",
                value_offset,
                record_number,
            )?;
            branch.upstream = Some(parse_ref_name(
                value,
                "branch.upstream",
                value_offset,
                record_number,
            )?);
        }
        b"branch.ab" => {
            reject_duplicate(
                branch.ahead_behind.is_some(),
                "branch.ab",
                value_offset,
                record_number,
            )?;
            branch.ahead_behind = Some(parse_ahead_behind(value, value_offset, record_number)?);
        }
        _ => {}
    }
    Ok(())
}

fn known_branch_header(name: &[u8]) -> Option<&'static str> {
    match name {
        b"branch.oid" => Some("branch.oid"),
        b"branch.head" => Some("branch.head"),
        b"branch.upstream" => Some("branch.upstream"),
        b"branch.ab" => Some("branch.ab"),
        _ => None,
    }
}

fn reject_duplicate(
    duplicate: bool,
    header: &'static str,
    offset: usize,
    record: usize,
) -> Result<(), PorcelainV2ParseError> {
    if duplicate {
        return Err(PorcelainV2ParseError {
            offset,
            record,
            kind: PorcelainV2ParseErrorKind::DuplicateHeader { header },
        });
    }
    Ok(())
}

fn parse_ahead_behind(
    value: &[u8],
    value_offset: usize,
    record: usize,
) -> Result<AheadBehind, PorcelainV2ParseError> {
    let separator = value
        .iter()
        .position(|byte| *byte == b' ')
        .ok_or(PorcelainV2ParseError {
            offset: value_offset,
            record,
            kind: PorcelainV2ParseErrorKind::MissingField { field: "behind" },
        })?;
    let ahead = value[..separator]
        .strip_prefix(b"+")
        .ok_or(PorcelainV2ParseError {
            offset: value_offset,
            record,
            kind: PorcelainV2ParseErrorKind::InvalidField { field: "ahead" },
        })?;
    let behind_offset = value_offset + separator + 1;
    let behind_field = &value[separator + 1..];
    if behind_field.contains(&b' ') {
        return Err(PorcelainV2ParseError {
            offset: behind_offset,
            record,
            kind: PorcelainV2ParseErrorKind::InvalidField { field: "behind" },
        });
    }
    let behind = behind_field
        .strip_prefix(b"-")
        .ok_or(PorcelainV2ParseError {
            offset: behind_offset,
            record,
            kind: PorcelainV2ParseErrorKind::InvalidField { field: "behind" },
        })?;
    Ok(AheadBehind {
        ahead: parse_decimal(ahead, "ahead", value_offset + 1, record)?,
        behind: parse_decimal(behind, "behind", behind_offset + 1, record)?,
    })
}

fn parse_ordinary(
    record: &[u8],
    record_start: usize,
    record_number: usize,
    object_format: GitObjectFormat,
) -> Result<OrdinaryEntry, PorcelainV2ParseError> {
    let mut fields = Fields::new(record, b"1 ", record_start, record_number)?;
    let (xy, xy_offset) = fields.take("xy")?;
    let (submodule, submodule_offset) = fields.take("sub")?;
    let (head_mode, head_mode_offset) = fields.take("head-mode")?;
    let (index_mode, index_mode_offset) = fields.take("index-mode")?;
    let (worktree_mode, worktree_mode_offset) = fields.take("worktree-mode")?;
    let (head_oid, head_oid_offset) = fields.take("head-oid")?;
    let (index_oid, index_oid_offset) = fields.take("index-oid")?;
    let (path, path_offset) = fields.rest("path")?;
    Ok(OrdinaryEntry {
        status: parse_xy(xy, xy_offset, record_number)?,
        submodule: parse_submodule(submodule, submodule_offset, record_number)?,
        head_mode: parse_mode(head_mode, "head-mode", head_mode_offset, record_number)?,
        index_mode: parse_mode(index_mode, "index-mode", index_mode_offset, record_number)?,
        worktree_mode: parse_mode(
            worktree_mode,
            "worktree-mode",
            worktree_mode_offset,
            record_number,
        )?,
        head_oid: parse_oid(
            head_oid,
            "head-oid",
            head_oid_offset,
            record_number,
            object_format,
        )?,
        index_oid: parse_oid(
            index_oid,
            "index-oid",
            index_oid_offset,
            record_number,
            object_format,
        )?,
        path: parse_git_path(path, "path", path_offset, record_number)?,
    })
}

struct PartialRenamedEntry {
    status: XyStatus,
    submodule: SubmoduleState,
    head_mode: GitMode,
    index_mode: GitMode,
    worktree_mode: GitMode,
    head_oid: GitObjectId,
    index_oid: GitObjectId,
    operation: RenameOrCopy,
    score: u8,
    path: RepoRelativePath,
}

impl PartialRenamedEntry {
    fn finish(
        self,
        original_path: &[u8],
        original_path_offset: usize,
        record: usize,
    ) -> Result<RenamedOrCopiedEntry, PorcelainV2ParseError> {
        Ok(RenamedOrCopiedEntry {
            status: self.status,
            submodule: self.submodule,
            head_mode: self.head_mode,
            index_mode: self.index_mode,
            worktree_mode: self.worktree_mode,
            head_oid: self.head_oid,
            index_oid: self.index_oid,
            operation: self.operation,
            score: self.score,
            path: self.path,
            original_path: parse_git_path(
                original_path,
                "original-path",
                original_path_offset,
                record,
            )?,
        })
    }
}

fn parse_renamed(
    record: &[u8],
    record_start: usize,
    record_number: usize,
    object_format: GitObjectFormat,
) -> Result<PartialRenamedEntry, PorcelainV2ParseError> {
    let mut fields = Fields::new(record, b"2 ", record_start, record_number)?;
    let (xy, xy_offset) = fields.take("xy")?;
    let (submodule, submodule_offset) = fields.take("sub")?;
    let (head_mode, head_mode_offset) = fields.take("head-mode")?;
    let (index_mode, index_mode_offset) = fields.take("index-mode")?;
    let (worktree_mode, worktree_mode_offset) = fields.take("worktree-mode")?;
    let (head_oid, head_oid_offset) = fields.take("head-oid")?;
    let (index_oid, index_oid_offset) = fields.take("index-oid")?;
    let (score, score_offset) = fields.take("score")?;
    let (path, path_offset) = fields.rest("path")?;
    let (operation, score) = parse_score(score, score_offset, record_number)?;
    Ok(PartialRenamedEntry {
        status: parse_xy(xy, xy_offset, record_number)?,
        submodule: parse_submodule(submodule, submodule_offset, record_number)?,
        head_mode: parse_mode(head_mode, "head-mode", head_mode_offset, record_number)?,
        index_mode: parse_mode(index_mode, "index-mode", index_mode_offset, record_number)?,
        worktree_mode: parse_mode(
            worktree_mode,
            "worktree-mode",
            worktree_mode_offset,
            record_number,
        )?,
        head_oid: parse_oid(
            head_oid,
            "head-oid",
            head_oid_offset,
            record_number,
            object_format,
        )?,
        index_oid: parse_oid(
            index_oid,
            "index-oid",
            index_oid_offset,
            record_number,
            object_format,
        )?,
        operation,
        score,
        path: parse_git_path(path, "path", path_offset, record_number)?,
    })
}

fn parse_unmerged(
    record: &[u8],
    record_start: usize,
    record_number: usize,
    object_format: GitObjectFormat,
) -> Result<UnmergedEntry, PorcelainV2ParseError> {
    let mut fields = Fields::new(record, b"u ", record_start, record_number)?;
    let (xy, xy_offset) = fields.take("xy")?;
    let (submodule, submodule_offset) = fields.take("sub")?;
    let (stage1_mode, stage1_mode_offset) = fields.take("stage1-mode")?;
    let (stage2_mode, stage2_mode_offset) = fields.take("stage2-mode")?;
    let (stage3_mode, stage3_mode_offset) = fields.take("stage3-mode")?;
    let (worktree_mode, worktree_mode_offset) = fields.take("worktree-mode")?;
    let (stage1_oid, stage1_oid_offset) = fields.take("stage1-oid")?;
    let (stage2_oid, stage2_oid_offset) = fields.take("stage2-oid")?;
    let (stage3_oid, stage3_oid_offset) = fields.take("stage3-oid")?;
    let (path, path_offset) = fields.rest("path")?;
    Ok(UnmergedEntry {
        status: parse_xy(xy, xy_offset, record_number)?,
        submodule: parse_submodule(submodule, submodule_offset, record_number)?,
        stage1_mode: parse_mode(
            stage1_mode,
            "stage1-mode",
            stage1_mode_offset,
            record_number,
        )?,
        stage2_mode: parse_mode(
            stage2_mode,
            "stage2-mode",
            stage2_mode_offset,
            record_number,
        )?,
        stage3_mode: parse_mode(
            stage3_mode,
            "stage3-mode",
            stage3_mode_offset,
            record_number,
        )?,
        worktree_mode: parse_mode(
            worktree_mode,
            "worktree-mode",
            worktree_mode_offset,
            record_number,
        )?,
        stage1_oid: parse_oid(
            stage1_oid,
            "stage1-oid",
            stage1_oid_offset,
            record_number,
            object_format,
        )?,
        stage2_oid: parse_oid(
            stage2_oid,
            "stage2-oid",
            stage2_oid_offset,
            record_number,
            object_format,
        )?,
        stage3_oid: parse_oid(
            stage3_oid,
            "stage3-oid",
            stage3_oid_offset,
            record_number,
            object_format,
        )?,
        path: parse_git_path(path, "path", path_offset, record_number)?,
    })
}

fn parse_simple_path(
    record: &[u8],
    record_start: usize,
    record_number: usize,
) -> Result<RepoRelativePath, PorcelainV2ParseError> {
    let prefix_valid = record.get(1).copied() == Some(b' ');
    if !prefix_valid {
        return Err(PorcelainV2ParseError {
            offset: record_start,
            record: record_number,
            kind: PorcelainV2ParseErrorKind::InvalidRecordPrefix,
        });
    }
    let path = record.get(2..).ok_or(PorcelainV2ParseError {
        offset: record_start + record.len(),
        record: record_number,
        kind: PorcelainV2ParseErrorKind::MissingField { field: "path" },
    })?;
    if path.is_empty() {
        return Err(PorcelainV2ParseError {
            offset: record_start + 2,
            record: record_number,
            kind: PorcelainV2ParseErrorKind::EmptyField { field: "path" },
        });
    }
    parse_git_path(path, "path", record_start + 2, record_number)
}

fn parse_xy(field: &[u8], offset: usize, record: usize) -> Result<XyStatus, PorcelainV2ParseError> {
    if field.len() != 2 {
        return Err(invalid_field("xy", offset, record));
    }
    let index = parse_change_kind(field[0]).ok_or_else(|| invalid_field("xy", offset, record))?;
    let worktree =
        parse_change_kind(field[1]).ok_or_else(|| invalid_field("xy", offset + 1, record))?;
    Ok(XyStatus { index, worktree })
}

fn parse_change_kind(value: u8) -> Option<ChangeKind> {
    match value {
        b'.' => Some(ChangeKind::Unmodified),
        b'M' => Some(ChangeKind::Modified),
        b'T' => Some(ChangeKind::TypeChanged),
        b'A' => Some(ChangeKind::Added),
        b'D' => Some(ChangeKind::Deleted),
        b'R' => Some(ChangeKind::Renamed),
        b'C' => Some(ChangeKind::Copied),
        b'U' => Some(ChangeKind::Unmerged),
        _ => None,
    }
}

fn parse_submodule(
    field: &[u8],
    offset: usize,
    record: usize,
) -> Result<SubmoduleState, PorcelainV2ParseError> {
    match field {
        b"N..." => Ok(SubmoduleState::NotSubmodule),
        [b'S', commit, tracked, untracked]
            if matches!(commit, b'C' | b'.')
                && matches!(tracked, b'M' | b'.')
                && matches!(untracked, b'U' | b'.') =>
        {
            Ok(SubmoduleState::Submodule {
                commit_changed: *commit == b'C',
                tracked_changes: *tracked == b'M',
                untracked_changes: *untracked == b'U',
            })
        }
        _ => Err(invalid_field("sub", offset, record)),
    }
}

fn parse_mode(
    field: &[u8],
    name: &'static str,
    offset: usize,
    record: usize,
) -> Result<GitMode, PorcelainV2ParseError> {
    if field.len() != 6 || !field.iter().all(|byte| matches!(byte, b'0'..=b'7')) {
        return Err(invalid_field(name, offset, record));
    }
    let bytes: [u8; 6] = field
        .try_into()
        .map_err(|_| invalid_field(name, offset, record))?;
    Ok(GitMode(bytes))
}

fn parse_oid(
    field: &[u8],
    name: &'static str,
    offset: usize,
    record: usize,
    object_format: GitObjectFormat,
) -> Result<GitObjectId, PorcelainV2ParseError> {
    if field.len() != object_format.hexadecimal_width() || !field.iter().all(u8::is_ascii_hexdigit)
    {
        return Err(invalid_field(name, offset, record));
    }
    Ok(GitObjectId(field.to_vec()))
}

fn parse_git_path(
    field: &[u8],
    name: &'static str,
    offset: usize,
    record: usize,
) -> Result<RepoRelativePath, PorcelainV2ParseError> {
    let path =
        native_path_from_git_bytes(field).ok_or_else(|| invalid_field(name, offset, record))?;
    RepoRelativePath::new(path).map_err(|_| invalid_field(name, offset, record))
}

#[cfg(unix)]
fn native_path_from_git_bytes(bytes: &[u8]) -> Option<PathBuf> {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt as _;

    Some(PathBuf::from(OsString::from_vec(bytes.to_vec())))
}

#[cfg(not(unix))]
fn native_path_from_git_bytes(bytes: &[u8]) -> Option<PathBuf> {
    String::from_utf8(bytes.to_vec()).ok().map(PathBuf::from)
}

fn parse_ref_name(
    field: &[u8],
    name: &'static str,
    offset: usize,
    record: usize,
) -> Result<GitRefName, PorcelainV2ParseError> {
    if field.is_empty() {
        return Err(PorcelainV2ParseError {
            offset,
            record,
            kind: PorcelainV2ParseErrorKind::EmptyField { field: name },
        });
    }
    Ok(GitRefName(field.to_vec()))
}

fn parse_score(
    field: &[u8],
    offset: usize,
    record: usize,
) -> Result<(RenameOrCopy, u8), PorcelainV2ParseError> {
    let (operation, digits) = match field.split_first() {
        Some((b'R', digits)) => (RenameOrCopy::Rename, digits),
        Some((b'C', digits)) => (RenameOrCopy::Copy, digits),
        _ => return Err(invalid_field("score", offset, record)),
    };
    let score = parse_decimal(digits, "score", offset + 1, record)?;
    let score = u8::try_from(score).map_err(|_| PorcelainV2ParseError {
        offset,
        record,
        kind: PorcelainV2ParseErrorKind::NumberOverflow { field: "score" },
    })?;
    if score > 100 {
        return Err(invalid_field("score", offset, record));
    }
    Ok((operation, score))
}

fn parse_decimal(
    field: &[u8],
    name: &'static str,
    offset: usize,
    record: usize,
) -> Result<u64, PorcelainV2ParseError> {
    if field.is_empty() || !field.iter().all(u8::is_ascii_digit) {
        return Err(invalid_field(name, offset, record));
    }
    let mut value = 0_u64;
    for digit in field {
        value = value
            .checked_mul(10)
            .and_then(|current| current.checked_add(u64::from(*digit - b'0')))
            .ok_or(PorcelainV2ParseError {
                offset,
                record,
                kind: PorcelainV2ParseErrorKind::NumberOverflow { field: name },
            })?;
    }
    Ok(value)
}

fn invalid_field(name: &'static str, offset: usize, record: usize) -> PorcelainV2ParseError {
    PorcelainV2ParseError {
        offset,
        record,
        kind: PorcelainV2ParseErrorKind::InvalidField { field: name },
    }
}

struct Fields<'a> {
    remaining: &'a [u8],
    offset: usize,
    record: usize,
}

impl<'a> Fields<'a> {
    fn new(
        record_bytes: &'a [u8],
        prefix: &[u8],
        record_start: usize,
        record: usize,
    ) -> Result<Self, PorcelainV2ParseError> {
        let remaining = record_bytes
            .strip_prefix(prefix)
            .ok_or(PorcelainV2ParseError {
                offset: record_start,
                record,
                kind: PorcelainV2ParseErrorKind::InvalidRecordPrefix,
            })?;
        Ok(Self {
            remaining,
            offset: record_start + prefix.len(),
            record,
        })
    }

    fn take(&mut self, name: &'static str) -> Result<(&'a [u8], usize), PorcelainV2ParseError> {
        let field_offset = self.offset;
        let separator =
            self.remaining
                .iter()
                .position(|byte| *byte == b' ')
                .ok_or(PorcelainV2ParseError {
                    offset: self.offset + self.remaining.len(),
                    record: self.record,
                    kind: PorcelainV2ParseErrorKind::MissingField { field: name },
                })?;
        if separator == 0 {
            return Err(PorcelainV2ParseError {
                offset: field_offset,
                record: self.record,
                kind: PorcelainV2ParseErrorKind::EmptyField { field: name },
            });
        }
        let field = &self.remaining[..separator];
        self.remaining = &self.remaining[separator + 1..];
        self.offset += separator + 1;
        Ok((field, field_offset))
    }

    fn rest(self, name: &'static str) -> Result<(&'a [u8], usize), PorcelainV2ParseError> {
        if self.remaining.is_empty() {
            return Err(PorcelainV2ParseError {
                offset: self.offset,
                record: self.record,
                kind: PorcelainV2ParseErrorKind::EmptyField { field: name },
            });
        }
        Ok((self.remaining, self.offset))
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufReader, Cursor};
    use std::path::Path;

    use super::{
        AheadBehind, BranchHead, BranchOid, GitIndexReadError, GitObjectFormat,
        GitPathListReadError, PorcelainV2ParseErrorKind, PorcelainV2ReadError, RenameOrCopy,
        StatusEntry, parse_git_index_reader, parse_git_path_list_reader, parse_status_porcelain_v2,
        parse_status_porcelain_v2_reader,
    };
    use crate::RepoRelativePath;

    const OID_1: &[u8] = b"1111111111111111111111111111111111111111";
    const OID_2: &[u8] = b"2222222222222222222222222222222222222222";

    #[test]
    fn parses_branch_headers_and_all_entry_kinds_losslessly()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut input = Vec::new();
        input.extend_from_slice(b"# branch.oid 1111111111111111111111111111111111111111\0");
        input.extend_from_slice(b"# branch.head feature/test\0");
        input.extend_from_slice(b"# branch.upstream origin/feature/test\0");
        input.extend_from_slice(b"# branch.ab +12 -3\0");
        input.extend_from_slice(b"# future.header ignored\0");
        input.extend_from_slice(b"1 .M N... 100644 100644 100644 ");
        input.extend_from_slice(OID_1);
        input.push(b' ');
        input.extend_from_slice(OID_2);
        input.extend_from_slice(b" path with space\nand-byte\0");
        input.extend_from_slice(b"2 R. N... 100644 100644 100644 ");
        input.extend_from_slice(OID_1);
        input.push(b' ');
        input.extend_from_slice(OID_2);
        input.extend_from_slice(b" R87 new name\0old\nname\0");
        input.extend_from_slice(b"u UU N... 100644 100644 100644 100644 ");
        input.extend_from_slice(OID_1);
        input.push(b' ');
        input.extend_from_slice(OID_2);
        input.push(b' ');
        input.extend_from_slice(OID_1);
        input.extend_from_slice(b" conflict file\0? untracked file\0! ignored\nfile\0");

        let parsed = parse_status_porcelain_v2(&input, GitObjectFormat::Sha1)?;
        assert_eq!(
            parsed.branch.ahead_behind,
            Some(AheadBehind {
                ahead: 12,
                behind: 3
            })
        );
        assert!(matches!(parsed.branch.oid, Some(BranchOid::Commit(_))));
        assert!(matches!(parsed.branch.head, Some(BranchHead::Named(_))));
        assert_eq!(parsed.entries.len(), 5);
        assert_eq!(
            parsed.changed_paths(),
            [
                "conflict file",
                "new name",
                "old\nname",
                "path with space\nand-byte",
                "untracked file",
            ]
            .into_iter()
            .map(RepoRelativePath::new)
            .collect::<Result<Vec<_>, _>>()?
        );

        match parsed.entries.as_slice() {
            [
                StatusEntry::Ordinary(ordinary),
                StatusEntry::RenamedOrCopied(renamed),
                StatusEntry::Unmerged(_),
                StatusEntry::Untracked(untracked),
                StatusEntry::Ignored(ignored),
            ] => {
                assert_eq!(
                    ordinary.path.as_path(),
                    Path::new("path with space\nand-byte")
                );
                assert_eq!(renamed.operation, RenameOrCopy::Rename);
                assert_eq!(renamed.score, 87);
                assert_eq!(renamed.path.as_path(), Path::new("new name"));
                assert_eq!(renamed.original_path.as_path(), Path::new("old\nname"));
                assert_eq!(untracked.as_path(), Path::new("untracked file"));
                assert_eq!(ignored.as_path(), Path::new("ignored\nfile"));
            }
            _ => return Err("entry variants were not preserved".into()),
        }
        Ok(())
    }

    #[test]
    fn maps_unborn_and_detached_branch_states() -> Result<(), Box<dyn std::error::Error>> {
        let parsed = parse_status_porcelain_v2(
            b"# branch.oid (initial)\0# branch.head (detached)\0",
            GitObjectFormat::Sha1,
        )?;
        assert_eq!(parsed.branch.oid, Some(BranchOid::Unborn));
        assert_eq!(parsed.branch.head, Some(BranchHead::Detached));
        Ok(())
    }

    #[test]
    fn accepts_full_sha256_object_ids() -> Result<(), Box<dyn std::error::Error>> {
        let oid = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let mut input = b"# branch.oid ".to_vec();
        input.extend_from_slice(oid);
        input.extend_from_slice(b"\0# branch.head main\0");

        let parsed = parse_status_porcelain_v2(&input, GitObjectFormat::Sha256)?;
        let Some(BranchOid::Commit(parsed_oid)) = parsed.branch.oid else {
            return Err("SHA-256 object ID was not parsed as a commit".into());
        };
        assert_eq!(parsed_oid.as_bytes(), oid);
        Ok(())
    }

    #[test]
    fn rejects_object_ids_from_a_different_output_format() {
        let input =
            b"# branch.oid 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\0";
        let error = parse_status_porcelain_v2(input, GitObjectFormat::Sha1).err();
        assert_eq!(
            error.map(|error| error.kind),
            Some(PorcelainV2ParseErrorKind::InvalidField {
                field: "branch.oid"
            })
        );
    }

    #[test]
    fn rejects_paths_that_are_not_repository_relative() {
        for input in [b"? ../escape\0".as_slice(), b"? /absolute\0".as_slice()] {
            let error = parse_status_porcelain_v2(input, GitObjectFormat::Sha1).err();
            assert_eq!(
                error.map(|error| error.kind),
                Some(PorcelainV2ParseErrorKind::InvalidField { field: "path" })
            );
        }
    }

    #[test]
    fn rename_consumes_the_additional_nul_path_before_the_next_record()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut input = b"2 C. N... 100644 100644 100644 ".to_vec();
        input.extend_from_slice(OID_1);
        input.push(b' ');
        input.extend_from_slice(OID_2);
        input.extend_from_slice(b" C100 target\0source\0? next\0");
        let parsed = parse_status_porcelain_v2(&input, GitObjectFormat::Sha1)?;
        assert_eq!(parsed.entries.len(), 2);
        assert!(matches!(
            parsed.entries.first(),
            Some(StatusEntry::RenamedOrCopied(_))
        ));
        assert!(matches!(
            parsed.entries.get(1),
            Some(StatusEntry::Untracked(_))
        ));
        Ok(())
    }

    #[test]
    fn incremental_reader_preserves_type_two_logical_record_boundaries()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut input = b"2 C. N... 100644 100644 100644 ".to_vec();
        input.extend_from_slice(OID_1);
        input.push(b' ');
        input.extend_from_slice(OID_2);
        input.extend_from_slice(b" C100 target\0source\0? next\0");
        let reader = BufReader::with_capacity(3, Cursor::new(input));

        let parsed = parse_status_porcelain_v2_reader(reader, GitObjectFormat::Sha1, 256, 2)?;

        assert_eq!(parsed.entries.len(), 2);
        let Some(StatusEntry::RenamedOrCopied(renamed)) = parsed.entries.first() else {
            return Err("type-2 entry was not preserved".into());
        };
        assert_eq!(renamed.path.as_path(), Path::new("target"));
        assert_eq!(renamed.original_path.as_path(), Path::new("source"));
        assert!(matches!(
            parsed.entries.get(1),
            Some(StatusEntry::Untracked(_))
        ));
        Ok(())
    }

    #[test]
    fn type_two_original_path_shares_the_logical_record_byte_cap()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut first_record = b"2 C. N... 100644 100644 100644 ".to_vec();
        first_record.extend_from_slice(OID_1);
        first_record.push(b' ');
        first_record.extend_from_slice(OID_2);
        first_record.extend_from_slice(b" C100 target");
        let max_record_bytes = first_record.len() + 3;
        let original_start = first_record.len() + 1;
        let mut input = first_record;
        input.extend_from_slice(b"\0source\0");
        let reader = BufReader::with_capacity(5, Cursor::new(input));

        let error =
            parse_status_porcelain_v2_reader(reader, GitObjectFormat::Sha1, max_record_bytes, 1)
                .err()
                .ok_or("overlong type-2 original path unexpectedly parsed")?;
        let PorcelainV2ReadError::Parse(error) = error else {
            return Err("overlong type-2 original path returned an I/O error".into());
        };
        assert_eq!(error.offset, original_start + 3);
        assert_eq!(error.record, 1);
        assert_eq!(
            error.kind,
            PorcelainV2ParseErrorKind::RecordTooLong {
                max_bytes: max_record_bytes
            }
        );
        Ok(())
    }

    #[test]
    fn incremental_reader_accepts_one_hundred_thousand_entries()
    -> Result<(), Box<dyn std::error::Error>> {
        const ENTRY_COUNT: usize = 100_000;
        let mut input = Vec::with_capacity(1_500_000);
        for index in 0..ENTRY_COUNT {
            input.extend_from_slice(b"? file-");
            input.extend_from_slice(index.to_string().as_bytes());
            input.push(0);
        }
        let reader = BufReader::with_capacity(127, Cursor::new(input));

        let parsed =
            parse_status_porcelain_v2_reader(reader, GitObjectFormat::Sha1, 64, ENTRY_COUNT)?;

        assert_eq!(parsed.entries.len(), ENTRY_COUNT);
        assert!(matches!(
            parsed.entries.last(),
            Some(StatusEntry::Untracked(_))
        ));
        Ok(())
    }

    #[test]
    fn index_reader_preserves_modes_object_ids_stages_and_native_paths()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut input = b"H 100644 ".to_vec();
        input.extend_from_slice(OID_1);
        input.extend_from_slice(b" 0\tordinary file\0");
        input.extend_from_slice(b"H 100755 ");
        input.extend_from_slice(OID_2);
        input.extend_from_slice(b" 2\tconflicted\0");
        input.extend_from_slice(b"H 100755 ");
        input.extend_from_slice(OID_1);
        input.extend_from_slice(b" 3\tconflicted\0");

        let entries = parse_git_index_reader(
            BufReader::with_capacity(5, Cursor::new(input)),
            GitObjectFormat::Sha1,
            256,
            3,
        )?;

        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].path.as_path(), Path::new("conflicted"));
        assert_eq!(entries[0].stage, 2);
        assert_eq!(entries[1].stage, 3);
        assert_eq!(entries[2].path.as_path(), Path::new("ordinary file"));
        assert!(entries[2].tag.is_ordinary_cached());
        assert_eq!(entries[2].mode.as_bytes(), b"100644");
        assert_eq!(entries[2].object_id.as_bytes(), OID_1);
        Ok(())
    }

    #[test]
    fn index_reader_rejects_partial_duplicate_and_wrong_format_records()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut duplicate = b"H 100644 ".to_vec();
        duplicate.extend_from_slice(OID_1);
        duplicate.extend_from_slice(b" 0\tsame\0");
        duplicate.extend_from_slice(b"H 100755 ");
        duplicate.extend_from_slice(OID_2);
        duplicate.extend_from_slice(b" 0\tsame\0");
        assert!(matches!(
            parse_git_index_reader(
                BufReader::new(Cursor::new(duplicate)),
                GitObjectFormat::Sha1,
                256,
                2,
            ),
            Err(GitIndexReadError::DuplicatePathStage { stage: 0 })
        ));

        let mut wrong_format = b"H 100644 ".to_vec();
        wrong_format.extend_from_slice(OID_1);
        wrong_format.extend_from_slice(b" 0\tpath\0");
        assert!(matches!(
            parse_git_index_reader(
                BufReader::new(Cursor::new(wrong_format)),
                GitObjectFormat::Sha256,
                256,
                1,
            ),
            Err(GitIndexReadError::InvalidObjectId { .. })
        ));

        let mut unterminated = b"H 100644 ".to_vec();
        unterminated.extend_from_slice(OID_1);
        unterminated.extend_from_slice(b" 0\tpath");
        assert!(matches!(
            parse_git_index_reader(
                BufReader::new(Cursor::new(unterminated)),
                GitObjectFormat::Sha1,
                256,
                1,
            ),
            Err(GitIndexReadError::MissingNulTerminator { .. })
        ));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn index_reader_preserves_non_utf8_paths() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::ffi::OsStrExt as _;

        let mut input = b"H 100644 ".to_vec();
        input.extend_from_slice(OID_1);
        input.extend_from_slice(b" 0\tnon-utf8-\xff\0");
        let entries = parse_git_index_reader(
            BufReader::new(Cursor::new(input)),
            GitObjectFormat::Sha1,
            256,
            1,
        )?;

        assert_eq!(
            entries[0].path.as_path().as_os_str().as_bytes(),
            b"non-utf8-\xff"
        );
        Ok(())
    }

    #[test]
    fn git_path_list_streams_more_than_one_hundred_thousand_paths_and_enforces_its_cap()
    -> Result<(), Box<dyn std::error::Error>> {
        const PATH_COUNT: usize = 100_001;
        let mut input = Vec::with_capacity(1_700_000);
        for index in 0..PATH_COUNT {
            input.extend_from_slice(b"path-");
            input.extend_from_slice(index.to_string().as_bytes());
            input.push(0);
        }

        let parsed = parse_git_path_list_reader(
            BufReader::with_capacity(127, Cursor::new(input.as_slice())),
            64,
            PATH_COUNT,
        )?;
        assert_eq!(parsed.len(), PATH_COUNT);

        let error = parse_git_path_list_reader(
            BufReader::with_capacity(127, Cursor::new(input.as_slice())),
            64,
            PATH_COUNT - 1,
        )
        .err()
        .ok_or("path-list cap unexpectedly accepted an extra path")?;
        assert!(matches!(
            error,
            GitPathListReadError::TooManyPaths { max_paths }
                if max_paths == PATH_COUNT - 1
        ));
        Ok(())
    }

    #[test]
    fn incremental_reader_rejects_overlong_records_at_the_first_excess_byte()
    -> Result<(), Box<dyn std::error::Error>> {
        let reader = BufReader::with_capacity(2, Cursor::new(b"? abc\0"));
        let error = parse_status_porcelain_v2_reader(reader, GitObjectFormat::Sha1, 4, 10)
            .err()
            .ok_or("overlong record unexpectedly parsed")?;
        let PorcelainV2ReadError::Parse(error) = error else {
            return Err("overlong record returned an I/O error".into());
        };
        assert_eq!(error.offset, 4);
        assert_eq!(error.record, 1);
        assert_eq!(
            error.kind,
            PorcelainV2ParseErrorKind::RecordTooLong { max_bytes: 4 }
        );
        Ok(())
    }

    #[test]
    fn incremental_reader_rejects_the_first_entry_beyond_the_cap()
    -> Result<(), Box<dyn std::error::Error>> {
        let reader = BufReader::with_capacity(2, Cursor::new(b"? a\0? b\0"));
        let error = parse_status_porcelain_v2_reader(reader, GitObjectFormat::Sha1, 16, 1)
            .err()
            .ok_or("entry limit unexpectedly accepted too many entries")?;
        let PorcelainV2ReadError::Parse(error) = error else {
            return Err("entry limit returned an I/O error".into());
        };
        assert_eq!(error.offset, 4);
        assert_eq!(error.record, 2);
        assert_eq!(
            error.kind,
            PorcelainV2ParseErrorKind::TooManyEntries { max_entries: 1 }
        );
        Ok(())
    }

    #[test]
    fn malformed_inputs_report_offset_and_record() {
        const MISSING_ORIGINAL_PATH: &[u8] = b"2 R. N... 100644 100644 100644 1111111111111111111111111111111111111111 2222222222222222222222222222222222222222 R100 target\0source";

        struct Case {
            input: &'static [u8],
            record: usize,
            offset: usize,
            kind: PorcelainV2ParseErrorKind,
        }

        let cases = [
            Case {
                input: b"? truncated",
                record: 1,
                offset: 11,
                kind: PorcelainV2ParseErrorKind::MissingNulTerminator,
            },
            Case {
                input: b"? ok\0x bad\0",
                record: 2,
                offset: 5,
                kind: PorcelainV2ParseErrorKind::UnknownRecordType { marker: b'x' },
            },
            Case {
                input: b"# branch.ab +x -2\0",
                record: 1,
                offset: 13,
                kind: PorcelainV2ParseErrorKind::InvalidField { field: "ahead" },
            },
            Case {
                input: b"# branch.oid\0",
                record: 1,
                offset: 12,
                kind: PorcelainV2ParseErrorKind::MissingField {
                    field: "branch.oid",
                },
            },
            Case {
                input: b"1 .M N... 100644 100644 100644 1 2222222222222222222222222222222222222222 path\0",
                record: 1,
                offset: 31,
                kind: PorcelainV2ParseErrorKind::InvalidField { field: "head-oid" },
            },
            Case {
                input: MISSING_ORIGINAL_PATH,
                record: 1,
                offset: MISSING_ORIGINAL_PATH.len(),
                kind: PorcelainV2ParseErrorKind::MissingOriginalPath,
            },
        ];

        for case in cases {
            let error = parse_status_porcelain_v2(case.input, GitObjectFormat::Sha1).err();
            assert_eq!(error.as_ref().map(|error| error.record), Some(case.record));
            assert_eq!(error.as_ref().map(|error| error.offset), Some(case.offset));
            assert_eq!(error.map(|error| error.kind), Some(case.kind));
        }
    }

    #[test]
    fn fuzz_seed_corpus_covers_empty_truncated_and_binary_records() {
        const SEEDS: &[&[u8]] = &[
            b"",
            b"\0",
            b"#",
            b"? a\0",
            b"! line\nname\0",
            b"? non-utf8-\xff\0",
            b"2 R. N... 100644 100644 100644 0 0 R100 to\0from\0",
            b"2 R. N... 100644 100644 100644 0 0 R100 to\0from",
            b"u UU N... 000000 100644 100644 100644 0 0 0 p\0",
            b"# branch.oid 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\0# branch.head main\0",
            b"\xff random\0",
        ];

        for seed in SEEDS {
            let _sha1_result = parse_status_porcelain_v2(seed, GitObjectFormat::Sha1);
            let _sha256_result = parse_status_porcelain_v2(seed, GitObjectFormat::Sha256);
        }
    }

    #[cfg(unix)]
    #[test]
    fn preserves_non_utf8_git_path_as_native_bytes() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::ffi::OsStrExt as _;

        let parsed = parse_status_porcelain_v2(b"? non-utf8-\xff\0", GitObjectFormat::Sha1)?;
        let Some(StatusEntry::Untracked(path)) = parsed.entries.first() else {
            return Err("untracked path was not parsed".into());
        };
        assert_eq!(path.as_path().as_os_str().as_bytes(), b"non-utf8-\xff");
        Ok(())
    }

    #[cfg(not(unix))]
    #[test]
    fn rejects_non_utf8_git_paths_without_a_byte_native_path_type() {
        let error = parse_status_porcelain_v2(b"? non-utf8-\xff\0", GitObjectFormat::Sha1).err();
        assert_eq!(
            error.map(|error| error.kind),
            Some(PorcelainV2ParseErrorKind::InvalidField { field: "path" })
        );
    }
}
