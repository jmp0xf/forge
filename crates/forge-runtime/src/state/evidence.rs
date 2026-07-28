//! Immutable Receipt, Evidence, and log storage with bounded read-only scans and retention.

use std::collections::{BTreeMap, BTreeSet};
#[cfg(unix)]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{self, Read, Write as _};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime};

use thiserror::Error;

use forge_core::{OperationControl, OperationControlError, UnlimitedOperationControl};

use super::{
    AtomicStateStore, GitStateLayout, StateError, StateLock, ensure_private_directory,
    ensure_private_relative_directories, metadata_is_link_or_reparse, sync_directory,
    validate_existing_state_directory, validate_private_directory,
    validate_private_file_permissions, validate_resolved_directory, validate_state_key,
};
use crate::fs::{FileSystemError, RepositoryWriter};

/// Maximum number of Receipt objects inspected across legacy v1 and current v2 state.
pub const EVIDENCE_GC_MAX_RECEIPTS: usize = 4_096;

/// Maximum number of Evidence objects inspected across legacy v1 and current v2 state.
pub const EVIDENCE_GC_MAX_EVIDENCE: usize = 4_096;

/// Maximum number of immutable log objects inspected.
pub const EVIDENCE_GC_MAX_LOGS: usize = 4_096;

/// Maximum total object bytes read while building one evidence-state GC snapshot.
///
/// Files are decoded or hashed one at a time. This I/O bound therefore does not become a resident
/// memory reservation, but it prevents corrupted state from forcing an unbounded scan.
pub const EVIDENCE_GC_MAX_SCAN_BYTES: u64 = 512 * 1024 * 1024;

/// Maximum number of Receipt/log references retained across one complete GC snapshot.
///
/// Together with the per-object byte bounds and streaming scan this keeps the state metadata well
/// below the 150 MiB resident-memory ceiling even for adversarial but otherwise valid JSON.
pub const EVIDENCE_GC_MAX_REFERENCES: usize = 131_072;

/// Maximum encoded size of one Receipt document.
pub const RECEIPT_OBJECT_MAX_BYTES: usize = 4 * 1024 * 1024;

/// Maximum encoded size of one Evidence document.
pub const EVIDENCE_OBJECT_MAX_BYTES: usize = 8 * 1024 * 1024;

/// Maximum retained size of Receipt, Evidence, and referenced log objects in one worktree.
pub const EVIDENCE_STATE_MAX_BYTES: u64 = 256 * 1024 * 1024;

/// Minimum number of newest current objects retained per Receipt/Evidence class.
pub const EVIDENCE_GC_KEEP_LATEST: usize = 200;

/// Minimum age window retained for current Receipt/Evidence objects.
pub const EVIDENCE_GC_KEEP_AGE: Duration = Duration::from_secs(14 * 24 * 60 * 60);

const RECEIPTS_V1_DIRECTORY: &str = "receipts/v1";
const RECEIPTS_V2_DIRECTORY: &str = "receipts/v2";
const EVIDENCE_V1_DIRECTORY: &str = "evidence/v1";
const EVIDENCE_V2_DIRECTORY: &str = "evidence/v2";
const LOGS_V1_DIRECTORY: &str = "logs/v1";
const GC_QUARANTINE_PREFIX: &str = ".forge-gc-quarantine-";
const GC_QUARANTINE_OBJECT: &str = "object";
const LOG_IDENTITY_DOMAIN: &[u8] = b"forge.log-identity/v1";
const DIGEST_FRAMING_DOMAIN: &[u8] = b"forge.digest/v1\0";
const MINIMUM_SUPPORTED_UTC_YEAR: u32 = 1970;
const MAXIMUM_SUPPORTED_UTC_YEAR: u32 = 9_999;

/// A frozen immutable-object layout version understood by the v0 retention engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EvidenceStateVersion {
    V1,
    V2,
}

impl EvidenceStateVersion {
    #[must_use]
    pub const fn major(self) -> u16 {
        match self {
            Self::V1 => 1,
            Self::V2 => 2,
        }
    }

    const fn is_legacy(self) -> bool {
        matches!(self, Self::V1)
    }
}

/// Validated 64-character lowercase hexadecimal payload used by immutable state filenames.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EvidenceStateObjectName(String);

impl EvidenceStateObjectName {
    pub fn new(value: impl Into<String>) -> Result<Self, EvidenceStateObjectNameError> {
        let value = value.into();
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(EvidenceStateObjectNameError);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An immutable state identity is not a canonical lowercase digest payload.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("immutable state object names must be 64 lowercase hexadecimal characters")]
pub struct EvidenceStateObjectNameError;

/// Retention timestamp semantics for one schema generation.
///
/// Legacy v1 Evidence has no timestamp field and is retained unconditionally. Current v2 objects
/// must carry a parsed UTC timestamp; mixing either state with the other layout fails closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceRetentionTime {
    Legacy,
    Current(UtcTimestamp),
}

/// A platform-independent UTC instant with the wire contract's nanosecond precision.
///
/// `SystemTime` cannot represent the final two fractional digits on Windows because its native
/// representation uses 100-nanosecond intervals. Parsed Receipt and Evidence timestamps therefore
/// use this value for deterministic ordering and retention on every supported platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct UtcTimestamp {
    unix_nanoseconds: i128,
}

impl From<SystemTime> for UtcTimestamp {
    fn from(value: SystemTime) -> Self {
        let unix_nanoseconds = match value.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(duration) => duration_to_nanos(duration),
            Err(error) => -duration_to_nanos(error.duration()),
        };
        Self { unix_nanoseconds }
    }
}

/// Strict UTC RFC 3339 conversion failure.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum UtcTimestampError {
    #[error("timestamp must use strict `YYYY-MM-DDTHH:MM:SS[.fraction]Z` UTC form")]
    Invalid,
    #[error("timestamp is outside the supported UTC year range 1970..=9999")]
    OutOfRange,
}

/// Parses strict UTC `YYYY-MM-DDTHH:MM:SS[.fraction]Z` without accepting numeric offsets.
pub fn parse_utc_rfc3339(value: &str) -> Result<UtcTimestamp, UtcTimestampError> {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
        || bytes.last() != Some(&b'Z')
    {
        return Err(UtcTimestampError::Invalid);
    }
    let year = parse_fixed_decimal(bytes, 0, 4)?;
    let month = parse_fixed_decimal(bytes, 5, 2)?;
    let day = parse_fixed_decimal(bytes, 8, 2)?;
    let hour = parse_fixed_decimal(bytes, 11, 2)?;
    let minute = parse_fixed_decimal(bytes, 14, 2)?;
    let second = parse_fixed_decimal(bytes, 17, 2)?;
    if !(MINIMUM_SUPPORTED_UTC_YEAR..=MAXIMUM_SUPPORTED_UTC_YEAR).contains(&year) {
        return Err(UtcTimestampError::OutOfRange);
    }
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(UtcTimestampError::Invalid);
    }

    let fraction = &bytes[19..bytes.len() - 1];
    let nanoseconds = if fraction.is_empty() {
        0_u32
    } else {
        if fraction.first() != Some(&b'.')
            || fraction.len() == 1
            || fraction.len() > 10
            || !fraction[1..].iter().all(u8::is_ascii_digit)
        {
            return Err(UtcTimestampError::Invalid);
        }
        let mut value = 0_u32;
        for digit in &fraction[1..] {
            value = value
                .checked_mul(10)
                .and_then(|current| current.checked_add(u32::from(digit - b'0')))
                .ok_or(UtcTimestampError::OutOfRange)?;
        }
        value
            .checked_mul(10_u32.pow(9 - (fraction.len() as u32 - 1)))
            .ok_or(UtcTimestampError::OutOfRange)?
    };

    let days = days_from_civil(i64::from(year), month, day);
    let seconds = i128::from(days)
        .checked_mul(86_400)
        .and_then(|value| value.checked_add(i128::from(hour * 3_600 + minute * 60 + second)))
        .ok_or(UtcTimestampError::OutOfRange)?;
    let unix_nanoseconds = seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(i128::from(nanoseconds)))
        .ok_or(UtcTimestampError::OutOfRange)?;
    Ok(UtcTimestamp { unix_nanoseconds })
}

/// Formats one UTC instant in canonical RFC 3339 form with trimmed fractional seconds.
pub fn format_utc_rfc3339(value: impl Into<UtcTimestamp>) -> Result<String, UtcTimestampError> {
    let total_nanoseconds = value.into().unix_nanoseconds;
    let whole_seconds = total_nanoseconds.div_euclid(1_000_000_000);
    let nanoseconds = total_nanoseconds.rem_euclid(1_000_000_000) as u32;
    let days = whole_seconds.div_euclid(86_400);
    let second_of_day = whole_seconds.rem_euclid(86_400);
    let days = i64::try_from(days).map_err(|_| UtcTimestampError::OutOfRange)?;
    let (year, month, day) = civil_from_days(days);
    if !(i64::from(MINIMUM_SUPPORTED_UTC_YEAR)..=i64::from(MAXIMUM_SUPPORTED_UTC_YEAR))
        .contains(&year)
    {
        return Err(UtcTimestampError::OutOfRange);
    }
    let hour = second_of_day / 3_600;
    let minute = second_of_day % 3_600 / 60;
    let second = second_of_day % 60;
    let mut rendered = format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}");
    if nanoseconds != 0 {
        let fraction = format!("{nanoseconds:09}");
        rendered.push('.');
        rendered.push_str(fraction.trim_end_matches('0'));
    }
    rendered.push('Z');
    Ok(rendered)
}

fn parse_fixed_decimal(
    bytes: &[u8],
    offset: usize,
    width: usize,
) -> Result<u32, UtcTimestampError> {
    let digits = bytes
        .get(offset..offset.saturating_add(width))
        .ok_or(UtcTimestampError::Invalid)?;
    if !digits.iter().all(u8::is_ascii_digit) {
        return Err(UtcTimestampError::Invalid);
    }
    Ok(digits
        .iter()
        .fold(0_u32, |value, digit| value * 10 + u32::from(digit - b'0')))
}

fn is_leap_year(year: u32) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = year - if month <= 2 { 1 } else { 0 };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let shifted_month = i64::from(month) + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += if month <= 2 { 1 } else { 0 };
    (year, month as u32, day as u32)
}

fn duration_to_nanos(duration: Duration) -> i128 {
    // `Duration` stores at most `u64::MAX` seconds, whose nanosecond expansion remains far below
    // `i128::MAX`; this conversion is therefore exact.
    i128::from(duration.as_secs()) * 1_000_000_000 + i128::from(duration.subsec_nanos())
}

/// One Receipt object referenced by an Evidence document.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReceiptStateReference {
    version: EvidenceStateVersion,
    object_name: EvidenceStateObjectName,
}

impl ReceiptStateReference {
    #[must_use]
    pub fn new(version: EvidenceStateVersion, object_name: EvidenceStateObjectName) -> Self {
        Self {
            version,
            object_name,
        }
    }

    #[must_use]
    pub const fn version(&self) -> EvidenceStateVersion {
        self.version
    }

    #[must_use]
    pub const fn object_name(&self) -> &EvidenceStateObjectName {
        &self.object_name
    }
}

/// Conservative reference knowledge decoded from a supported schema major.
///
/// A decoder returns [`Self::RetainAll`] when an otherwise valid same-major extension may contain
/// references whose meaning this Forge version cannot prove. GC then retains the entire target
/// object class instead of guessing that the unknown variant has no references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReferenceClosure<T: Ord> {
    Complete(BTreeSet<T>),
    RetainAll,
}

impl<T: Ord> ReferenceClosure<T> {
    #[must_use]
    pub fn complete(references: impl IntoIterator<Item = T>) -> Self {
        Self::Complete(references.into_iter().collect())
    }

    #[must_use]
    pub const fn retain_all() -> Self {
        Self::RetainAll
    }
}

/// Retention facts decoded from one bounded Receipt document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptRetentionMetadata {
    object_name: EvidenceStateObjectName,
    started_at: EvidenceRetentionTime,
    log_references: ReferenceClosure<EvidenceStateObjectName>,
}

impl ReceiptRetentionMetadata {
    #[must_use]
    pub fn new(
        object_name: EvidenceStateObjectName,
        started_at: EvidenceRetentionTime,
        log_references: impl IntoIterator<Item = EvidenceStateObjectName>,
    ) -> Self {
        Self {
            object_name,
            started_at,
            log_references: ReferenceClosure::complete(log_references),
        }
    }

    #[must_use]
    pub fn with_log_reference_closure(
        object_name: EvidenceStateObjectName,
        started_at: EvidenceRetentionTime,
        log_references: ReferenceClosure<EvidenceStateObjectName>,
    ) -> Self {
        Self {
            object_name,
            started_at,
            log_references,
        }
    }
}

/// Retention facts decoded from one bounded Evidence document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceRetentionMetadata {
    object_name: EvidenceStateObjectName,
    created_at: EvidenceRetentionTime,
    receipt_references: ReferenceClosure<ReceiptStateReference>,
    log_references: ReferenceClosure<EvidenceStateObjectName>,
}

impl EvidenceRetentionMetadata {
    #[must_use]
    pub fn new(
        object_name: EvidenceStateObjectName,
        created_at: EvidenceRetentionTime,
        receipt_references: impl IntoIterator<Item = ReceiptStateReference>,
        log_references: impl IntoIterator<Item = EvidenceStateObjectName>,
    ) -> Self {
        Self {
            object_name,
            created_at,
            receipt_references: ReferenceClosure::complete(receipt_references),
            log_references: ReferenceClosure::complete(log_references),
        }
    }

    #[must_use]
    pub fn with_reference_closures(
        object_name: EvidenceStateObjectName,
        created_at: EvidenceRetentionTime,
        receipt_references: ReferenceClosure<ReceiptStateReference>,
        log_references: ReferenceClosure<EvidenceStateObjectName>,
    ) -> Self {
        Self {
            object_name,
            created_at,
            receipt_references,
            log_references,
        }
    }
}

/// Content-safe decoder failure for one bounded Receipt or Evidence document.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceStateDecodeError {
    #[error("document is malformed")]
    Malformed,
    #[error("document uses an unsupported future schema")]
    FutureSchema,
    #[error("document has an invalid UTC timestamp")]
    InvalidTimestamp,
    #[error("document contains an invalid immutable-state reference")]
    InvalidReference,
}

/// Schema-aware boundary used by the storage layer without teaching it JSON field paths.
///
/// Implementations must validate the complete envelope/schema major, parse current timestamps with
/// [`parse_utc_rfc3339`], and recompute the domain-separated content identity from the original raw
/// JSON after removing only `data.id`. Re-serializing known fields is insufficient because it could
/// discard unknown fields from the supported major. Only after that recomputation may a decoder
/// convert the public identity to the canonical filename payload and return success. Malformed,
/// future-major, or content-address-mismatched data must be rejected. When a valid same-major
/// extension could carry reference semantics the decoder does not understand, it must return
/// [`ReferenceClosure::RetainAll`] for every affected object class rather than an incomplete known
/// set. Legacy objects use [`EvidenceRetentionTime::Legacy`].
pub trait EvidenceStateMetadataDecoder {
    fn decode_receipt(
        &self,
        version: EvidenceStateVersion,
        bytes: &[u8],
    ) -> Result<ReceiptRetentionMetadata, EvidenceStateDecodeError>;

    fn decode_evidence(
        &self,
        version: EvidenceStateVersion,
        bytes: &[u8],
    ) -> Result<EvidenceRetentionMetadata, EvidenceStateDecodeError>;
}

/// Observable result of one successful immutable evidence-state collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvidenceGcReport {
    deleted_evidence: usize,
    deleted_receipts: usize,
    deleted_logs: usize,
    reclaimed_bytes: u64,
    retained_bytes: u64,
}

impl EvidenceGcReport {
    #[must_use]
    pub const fn deleted_evidence(self) -> usize {
        self.deleted_evidence
    }

    #[must_use]
    pub const fn deleted_receipts(self) -> usize {
        self.deleted_receipts
    }

    #[must_use]
    pub const fn deleted_logs(self) -> usize {
        self.deleted_logs
    }

    #[must_use]
    pub const fn reclaimed_bytes(self) -> u64 {
        self.reclaimed_bytes
    }

    #[must_use]
    pub const fn retained_bytes(self) -> u64 {
        self.retained_bytes
    }
}

/// Kind and schema generation of one safely enumerated immutable Evidence-state object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceStateObjectKind {
    Receipt(EvidenceStateVersion),
    Evidence(EvidenceStateVersion),
    LogV1,
}

/// A stable object identity plus a bounded byte stream exposed during a read-only snapshot visit.
///
/// The stream ends after exactly [`Self::size`] bytes. Callers may consume it incrementally instead
/// of retaining a complete log in memory.
pub struct EvidenceStateObjectSnapshot<'a> {
    kind: EvidenceStateObjectKind,
    key: &'a str,
    object_name: &'a EvidenceStateObjectName,
    size: u64,
    bytes: &'a mut dyn Read,
}

impl std::fmt::Debug for EvidenceStateObjectSnapshot<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EvidenceStateObjectSnapshot")
            .field("kind", &self.kind)
            .field("key", &self.key)
            .field("object_name", &self.object_name)
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl EvidenceStateObjectSnapshot<'_> {
    #[must_use]
    pub const fn kind(&self) -> EvidenceStateObjectKind {
        self.kind
    }

    #[must_use]
    pub const fn key(&self) -> &str {
        self.key
    }

    #[must_use]
    pub const fn object_name(&self) -> &EvidenceStateObjectName {
        self.object_name
    }

    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    pub fn bytes(&mut self) -> &mut dyn Read {
        self.bytes
    }
}

impl AtomicStateStore {
    /// Creates a state store only where owner-only Evidence permissions can be enforced.
    ///
    /// Windows enforcement is proved by creating the empty state root with an explicit security
    /// descriptor and immediately reading back its exact ACL before any Evidence bytes are
    /// written. This works for local and UNC paths without depending on volume-management APIs
    /// that SMB does not implement. Evidence state is worktree-local, so this entry point
    /// deliberately does not create the shared cache.
    pub fn new_evidence(layout: GitStateLayout) -> Result<Self, StateError> {
        ensure_evidence_state_mutation_supported()?;
        validate_resolved_directory(layout.git_dir())?;
        validate_resolved_directory(layout.common_dir())?;
        let _created = ensure_private_directory(layout.worktree_dir())?;
        let writer = RepositoryWriter::new(layout.worktree_dir())?;
        let store = Self {
            layout,
            writer,
            evidence_security: true,
        };
        let metadata = fs::symlink_metadata(store.layout.worktree_dir()).map_err(|source| {
            StateError::io(
                "inspect private evidence state root",
                store.layout.worktree_dir(),
                source,
            )
        })?;
        validate_private_evidence_directory(store.layout.worktree_dir(), &metadata)?;
        Ok(store)
    }

    /// Opens existing Evidence state read-only only where owner-only ACLs can be verified.
    ///
    /// The existing root and every visited typed object are verified directly. No directory,
    /// cache, or lock is created; an absent state root remains `Ok(None)` on supported platforms.
    pub fn open_existing_evidence_read_only(
        layout: GitStateLayout,
    ) -> Result<Option<Self>, StateError> {
        ensure_evidence_state_read_supported()?;
        let Some(mut store) = Self::open_existing_read_only(layout)? else {
            return Ok(None);
        };
        store.evidence_security = true;
        let metadata = fs::symlink_metadata(store.layout.worktree_dir()).map_err(|source| {
            StateError::io(
                "inspect private evidence state root",
                store.layout.worktree_dir(),
                source,
            )
        })?;
        validate_private_evidence_directory(store.layout.worktree_dir(), &metadata)?;
        Ok(Some(store))
    }

    /// Persists one current v2 Receipt under the matching worktree lock, then runs bounded GC.
    ///
    /// The decoder's success is a trusted assertion that the complete raw JSON object, including
    /// unknown fields of the supported major, has been schema-validated and its content-addressed
    /// identity recomputed. The storage boundary additionally checks the returned identity,
    /// timestamp generation, path, size, references, private permissions, and global budgets.
    pub fn persist_current_receipt<D: EvidenceStateMetadataDecoder + ?Sized>(
        &self,
        lock: &StateLock,
        now: SystemTime,
        object_name: &EvidenceStateObjectName,
        bytes: &[u8],
        decoder: &D,
    ) -> Result<EvidenceGcReport, StateError> {
        self.ensure_matching_lock(lock)?;
        ensure_evidence_state_mutation_supported()?;
        if bytes.len() > RECEIPT_OBJECT_MAX_BYTES {
            return Err(StateError::ObjectTooLarge {
                key: receipt_object_key(EvidenceStateVersion::V2, object_name),
                max_bytes: RECEIPT_OBJECT_MAX_BYTES,
            });
        }
        let metadata = decoder
            .decode_receipt(EvidenceStateVersion::V2, bytes)
            .map_err(|reason| StateError::ObjectDecode {
                key: receipt_object_key(EvidenceStateVersion::V2, object_name),
                reason,
            })?;
        ensure_declared_identity(
            &receipt_object_key(EvidenceStateVersion::V2, object_name),
            object_name,
            &metadata.object_name,
        )?;
        validate_retention_time(
            EvidenceStateVersion::V2,
            metadata.started_at,
            &receipt_object_key(EvidenceStateVersion::V2, object_name),
        )?;
        self.persist_current_object(
            lock,
            now,
            PendingEvidenceObject::Receipt {
                object_name: object_name.clone(),
                bytes,
                metadata,
            },
            decoder,
        )
    }

    /// Persists one current v2 Evidence object under the matching worktree lock, then runs GC.
    pub fn persist_current_evidence<D: EvidenceStateMetadataDecoder + ?Sized>(
        &self,
        lock: &StateLock,
        now: SystemTime,
        object_name: &EvidenceStateObjectName,
        bytes: &[u8],
        decoder: &D,
    ) -> Result<EvidenceGcReport, StateError> {
        self.ensure_matching_lock(lock)?;
        ensure_evidence_state_mutation_supported()?;
        if bytes.len() > EVIDENCE_OBJECT_MAX_BYTES {
            return Err(StateError::ObjectTooLarge {
                key: evidence_object_key(EvidenceStateVersion::V2, object_name),
                max_bytes: EVIDENCE_OBJECT_MAX_BYTES,
            });
        }
        let metadata = decoder
            .decode_evidence(EvidenceStateVersion::V2, bytes)
            .map_err(|reason| StateError::ObjectDecode {
                key: evidence_object_key(EvidenceStateVersion::V2, object_name),
                reason,
            })?;
        ensure_declared_identity(
            &evidence_object_key(EvidenceStateVersion::V2, object_name),
            object_name,
            &metadata.object_name,
        )?;
        validate_retention_time(
            EvidenceStateVersion::V2,
            metadata.created_at,
            &evidence_object_key(EvidenceStateVersion::V2, object_name),
        )?;
        self.persist_current_object(
            lock,
            now,
            PendingEvidenceObject::Evidence {
                object_name: object_name.clone(),
                bytes,
                metadata,
            },
            decoder,
        )
    }

    /// Persists one already-redacted immutable log under the matching worktree lock.
    ///
    /// `configured_max_bytes` is the effective policy limit for this write. Existing logs remain
    /// subject to the global scan and retained-state budgets during every collection.
    pub fn persist_current_log<D: EvidenceStateMetadataDecoder + ?Sized>(
        &self,
        lock: &StateLock,
        now: SystemTime,
        object_name: &EvidenceStateObjectName,
        bytes: &[u8],
        configured_max_bytes: usize,
        decoder: &D,
    ) -> Result<EvidenceGcReport, StateError> {
        self.ensure_matching_lock(lock)?;
        ensure_evidence_state_mutation_supported()?;
        if bytes.len() > configured_max_bytes {
            return Err(StateError::ObjectTooLarge {
                key: log_object_key(object_name),
                max_bytes: configured_max_bytes,
            });
        }
        ensure_log_content_address(&log_object_key(object_name), object_name, bytes)?;
        self.persist_current_object(
            lock,
            now,
            PendingEvidenceObject::Log {
                object_name: object_name.clone(),
                bytes,
            },
            decoder,
        )
    }

    fn persist_current_object<D: EvidenceStateMetadataDecoder + ?Sized>(
        &self,
        lock: &StateLock,
        now: SystemTime,
        pending: PendingEvidenceObject<'_>,
        decoder: &D,
    ) -> Result<EvidenceGcReport, StateError> {
        self.ensure_matching_lock(lock)?;
        ensure_evidence_state_mutation_supported()?;
        recover_evidence_gc_quarantines(self)?;

        let key = pending.key();
        let relative = validate_state_key(&key)?;
        let existing =
            existing_private_file_matches(self, &key, pending.bytes(), pending.max_bytes())?;
        if let Some(matches) = existing {
            if !matches {
                return Err(StateError::ImmutableCollision { key });
            }
            return self.collect_evidence_garbage_with_root(lock, now, decoder, Some(&key));
        }

        let projected = build_evidence_gc_plan(self, now, decoder, Some(&pending), None)?;
        projected.ensure_prewrite_fits(&pending)?;

        store_new_atomic_idempotent_evidence(self, &key, &relative, pending.bytes())?;
        self.collect_evidence_garbage_with_root(lock, now, decoder, Some(&key))
    }

    /// Visits a complete, validated immutable Evidence-state snapshot without creating state.
    ///
    /// The hierarchy, private permissions, version directories, canonical filenames, per-class
    /// counts, per-document byte limits, total scan bytes, reference count, document identities,
    /// log content addresses, and referential integrity are all validated before the first callback.
    /// Objects are then visited in stable Receipt, Evidence, log and lexical-key order. Each callback
    /// receives a bounded stream, so a caller need not retain complete logs in memory. A file change
    /// between validation and visitation fails closed with [`StateError::StateChanged`].
    ///
    /// Forge performs no application-level writes and does not create a directory or lock. Reading
    /// may still let the host filesystem update implementation-managed access timestamps.
    pub fn visit_evidence_state_snapshot<
        D: EvidenceStateMetadataDecoder + ?Sized,
        F: FnMut(EvidenceStateObjectSnapshot<'_>) -> io::Result<()>,
    >(
        &self,
        configured_log_max_bytes: usize,
        decoder: &D,
        visit: F,
    ) -> Result<(), StateError> {
        self.visit_evidence_state_snapshot_controlled(
            configured_log_max_bytes,
            decoder,
            &UnlimitedOperationControl,
            visit,
        )
    }

    /// Visits a validated snapshot with one checkpoint per retained object and reference owner.
    pub fn visit_evidence_state_snapshot_controlled<
        D: EvidenceStateMetadataDecoder + ?Sized,
        F: FnMut(EvidenceStateObjectSnapshot<'_>) -> io::Result<()>,
    >(
        &self,
        configured_log_max_bytes: usize,
        decoder: &D,
        control: &dyn OperationControl,
        mut visit: F,
    ) -> Result<(), StateError> {
        ensure_evidence_state_read_supported()?;
        control
            .checkpoint()
            .map_err(operation_control_state_error)?;
        let state = scan_evidence_state_controlled(self, decoder, control)?;
        validate_evidence_references_controlled(
            &state.receipts,
            &state.evidence,
            &state.logs,
            control,
        )?;
        for item in &state.logs {
            control
                .checkpoint()
                .map_err(operation_control_state_error)?;
            if item.size > configured_log_max_bytes as u64 {
                return Err(StateError::ObjectTooLarge {
                    key: item.key.clone(),
                    max_bytes: configured_log_max_bytes,
                });
            }
        }

        for item in &state.receipts {
            control
                .checkpoint()
                .map_err(operation_control_state_error)?;
            visit_scanned_object(
                self,
                EvidenceStateObjectKind::Receipt(item.version),
                &item.key,
                &item.object_name,
                item.size,
                item.snapshot.as_ref(),
                RECEIPT_OBJECT_MAX_BYTES,
                &mut visit,
            )?;
        }
        for item in &state.evidence {
            control
                .checkpoint()
                .map_err(operation_control_state_error)?;
            visit_scanned_object(
                self,
                EvidenceStateObjectKind::Evidence(item.version),
                &item.key,
                &item.object_name,
                item.size,
                item.snapshot.as_ref(),
                EVIDENCE_OBJECT_MAX_BYTES,
                &mut visit,
            )?;
        }
        for item in &state.logs {
            control
                .checkpoint()
                .map_err(operation_control_state_error)?;
            visit_scanned_object(
                self,
                EvidenceStateObjectKind::LogV1,
                &item.key,
                &item.object_name,
                item.size,
                item.snapshot.as_ref(),
                configured_log_max_bytes,
                &mut visit,
            )?;
        }
        Ok(())
    }

    /// Collects expired immutable Receipt, Evidence, and orphan log objects under the held
    /// per-worktree lock.
    ///
    /// The complete bounded hierarchy is validated and decoded before the first deletion. Legacy
    /// v1 Receipt/Evidence objects are read and retained but never deleted. Current v2 objects keep
    /// the union of the newest 200, objects no older than 14 days, and objects referenced by
    /// retained Evidence. Logs have no timestamp envelope in v0, so only logs referenced by a
    /// retained Receipt/Evidence are kept; adding count/age roots for logs requires a new contract.
    ///
    /// A decoder or layout error, missing reference, scan/file bound violation, or retained closure
    /// above the total budget returns before any file is removed.
    pub fn collect_evidence_garbage<D: EvidenceStateMetadataDecoder + ?Sized>(
        &self,
        lock: &StateLock,
        now: SystemTime,
        decoder: &D,
    ) -> Result<EvidenceGcReport, StateError> {
        self.collect_evidence_garbage_with_root(lock, now, decoder, None)
    }

    fn collect_evidence_garbage_with_root<D: EvidenceStateMetadataDecoder + ?Sized>(
        &self,
        lock: &StateLock,
        now: SystemTime,
        decoder: &D,
        forced_root: Option<&str>,
    ) -> Result<EvidenceGcReport, StateError> {
        self.ensure_matching_lock(lock)?;
        ensure_evidence_state_mutation_supported()?;
        recover_evidence_gc_quarantines(self)?;
        let plan = build_evidence_gc_plan(self, now, decoder, None, forced_root)?;
        preflight_deletions(self, &plan)?;
        apply_evidence_gc_plan(self, &plan)
    }
}

#[derive(Debug)]
enum PendingEvidenceObject<'a> {
    Receipt {
        object_name: EvidenceStateObjectName,
        bytes: &'a [u8],
        metadata: ReceiptRetentionMetadata,
    },
    Evidence {
        object_name: EvidenceStateObjectName,
        bytes: &'a [u8],
        metadata: EvidenceRetentionMetadata,
    },
    Log {
        object_name: EvidenceStateObjectName,
        bytes: &'a [u8],
    },
}

impl PendingEvidenceObject<'_> {
    fn key(&self) -> String {
        match self {
            Self::Receipt { object_name, .. } => {
                receipt_object_key(EvidenceStateVersion::V2, object_name)
            }
            Self::Evidence { object_name, .. } => {
                evidence_object_key(EvidenceStateVersion::V2, object_name)
            }
            Self::Log { object_name, .. } => log_object_key(object_name),
        }
    }

    const fn bytes(&self) -> &[u8] {
        match self {
            Self::Receipt { bytes, .. }
            | Self::Evidence { bytes, .. }
            | Self::Log { bytes, .. } => bytes,
        }
    }

    const fn max_bytes(&self) -> usize {
        match self {
            Self::Receipt { .. } => RECEIPT_OBJECT_MAX_BYTES,
            Self::Evidence { .. } => EVIDENCE_OBJECT_MAX_BYTES,
            Self::Log { bytes, .. } => bytes.len(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StateFileIdentity {
    size: u64,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    modified_seconds: i64,
    #[cfg(unix)]
    modified_nanoseconds: i64,
    #[cfg(unix)]
    changed_seconds: i64,
    #[cfg(unix)]
    changed_nanoseconds: i64,
    #[cfg(windows)]
    creation_time: u64,
    #[cfg(windows)]
    last_write_time: u64,
    #[cfg(windows)]
    file_attributes: u32,
    #[cfg(not(any(unix, windows)))]
    modified: Option<SystemTime>,
    #[cfg(not(any(unix, windows)))]
    created: Option<SystemTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StateFileSnapshot {
    identity: StateFileIdentity,
    content_digest: [u8; 32],
}

#[derive(Debug)]
struct StoredDocument<M> {
    key: String,
    version: EvidenceStateVersion,
    object_name: EvidenceStateObjectName,
    size: u64,
    metadata: M,
    snapshot: Option<StateFileSnapshot>,
    pending: bool,
}

#[derive(Debug)]
struct StoredLog {
    key: String,
    object_name: EvidenceStateObjectName,
    size: u64,
    snapshot: Option<StateFileSnapshot>,
    pending: bool,
}

#[derive(Debug)]
struct ScannedEvidenceState {
    receipts: Vec<StoredDocument<ReceiptRetentionMetadata>>,
    evidence: Vec<StoredDocument<EvidenceRetentionMetadata>>,
    logs: Vec<StoredLog>,
    budget: EvidenceScanBudget,
}

#[derive(Debug, Clone)]
struct PlannedDeletion {
    key: String,
    size: u64,
    snapshot: StateFileSnapshot,
}

#[derive(Debug, Default)]
struct EvidenceScanBudget {
    bytes: u64,
    references: usize,
}

impl EvidenceScanBudget {
    fn charge_bytes(&mut self, key: &str, bytes: u64) -> Result<(), StateError> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or(StateError::StateSizeOverflow)?;
        if self.bytes > EVIDENCE_GC_MAX_SCAN_BYTES {
            return Err(StateError::ScanByteLimit {
                key: key.to_owned(),
                scanned_bytes: self.bytes,
                max_bytes: EVIDENCE_GC_MAX_SCAN_BYTES,
            });
        }
        Ok(())
    }

    fn charge_references(&mut self, key: &str, references: usize) -> Result<(), StateError> {
        self.references = self
            .references
            .checked_add(references)
            .ok_or(StateError::StateSizeOverflow)?;
        if self.references > EVIDENCE_GC_MAX_REFERENCES {
            return Err(StateError::ReferenceLimit {
                key: key.to_owned(),
                references: self.references,
                max_references: EVIDENCE_GC_MAX_REFERENCES,
            });
        }
        Ok(())
    }
}

#[derive(Debug)]
struct EvidenceGcPlan {
    delete_evidence: Vec<PlannedDeletion>,
    delete_receipts: Vec<PlannedDeletion>,
    delete_logs: Vec<PlannedDeletion>,
    reclaimed_bytes: u64,
    retained_bytes: u64,
    projected_scan_bytes: u64,
    projected_receipts: usize,
    projected_evidence: usize,
    projected_logs: usize,
}

impl EvidenceGcPlan {
    fn ensure_prewrite_fits(&self, pending: &PendingEvidenceObject<'_>) -> Result<(), StateError> {
        if self.projected_scan_bytes > EVIDENCE_GC_MAX_SCAN_BYTES {
            return Err(StateError::ScanByteLimit {
                key: pending.key(),
                scanned_bytes: self.projected_scan_bytes,
                max_bytes: EVIDENCE_GC_MAX_SCAN_BYTES,
            });
        }
        for (directory, actual, maximum) in [
            (
                "receipts",
                self.projected_receipts,
                EVIDENCE_GC_MAX_RECEIPTS,
            ),
            (
                "evidence",
                self.projected_evidence,
                EVIDENCE_GC_MAX_EVIDENCE,
            ),
            ("logs", self.projected_logs, EVIDENCE_GC_MAX_LOGS),
        ] {
            if actual > maximum {
                return Err(StateError::RetainedObjectCountExceeded {
                    directory: directory.to_owned(),
                    retained_entries: actual,
                    max_entries: maximum,
                });
            }
        }
        Ok(())
    }
}

fn scan_evidence_state<D: EvidenceStateMetadataDecoder + ?Sized>(
    store: &AtomicStateStore,
    decoder: &D,
) -> Result<ScannedEvidenceState, StateError> {
    scan_evidence_state_controlled(store, decoder, &UnlimitedOperationControl)
}

fn scan_evidence_state_controlled<D: EvidenceStateMetadataDecoder + ?Sized>(
    store: &AtomicStateStore,
    decoder: &D,
    control: &dyn OperationControl,
) -> Result<ScannedEvidenceState, StateError> {
    control
        .checkpoint()
        .map_err(operation_control_state_error)?;
    validate_evidence_root(store)?;
    validate_version_hierarchy(store, "receipts", &["v1", "v2"])?;
    validate_version_hierarchy(store, "evidence", &["v1", "v2"])?;
    validate_version_hierarchy(store, "logs", &["v1"])?;

    let mut budget = EvidenceScanBudget::default();
    let receipts = scan_receipt_files(store, decoder, &mut budget, control)?;
    let evidence = scan_evidence_files(store, decoder, &mut budget, control)?;
    let logs = scan_log_files(store, &mut budget, control)?;
    charge_reference_budget(&mut budget, &receipts, &evidence, logs.len())?;
    Ok(ScannedEvidenceState {
        receipts,
        evidence,
        logs,
        budget,
    })
}

fn operation_control_state_error(error: OperationControlError) -> StateError {
    let kind = match error {
        OperationControlError::TimedOut => io::ErrorKind::TimedOut,
        OperationControlError::Interrupted => io::ErrorKind::Interrupted,
    };
    StateError::Io {
        operation: "check evidence operation budget",
        path: PathBuf::from("evidence-state"),
        source: io::Error::new(kind, error.to_string()),
    }
}

fn validate_evidence_references(
    receipts: &[StoredDocument<ReceiptRetentionMetadata>],
    evidence: &[StoredDocument<EvidenceRetentionMetadata>],
    logs: &[StoredLog],
) -> Result<(), StateError> {
    validate_evidence_references_controlled(receipts, evidence, logs, &UnlimitedOperationControl)
}

fn validate_evidence_references_controlled(
    receipts: &[StoredDocument<ReceiptRetentionMetadata>],
    evidence: &[StoredDocument<EvidenceRetentionMetadata>],
    logs: &[StoredLog],
    control: &dyn OperationControl,
) -> Result<(), StateError> {
    let receipt_by_key: BTreeMap<_, _> = receipts
        .iter()
        .map(|receipt| (receipt.key.as_str(), receipt))
        .collect();
    let log_by_key: BTreeMap<_, _> = logs.iter().map(|log| (log.key.as_str(), log)).collect();

    // Referential integrity belongs to the complete immutable snapshot, not only its retained
    // closure. An expired object's dangling reference remains malformed state.
    for item in evidence {
        control
            .checkpoint()
            .map_err(operation_control_state_error)?;
        if let ReferenceClosure::Complete(references) = &item.metadata.receipt_references {
            for receipt_reference in references {
                require_reference(&receipt_by_key, &item.key, &receipt_key(receipt_reference))?;
            }
        }
        if let ReferenceClosure::Complete(references) = &item.metadata.log_references {
            for log_reference in references {
                require_reference(&log_by_key, &item.key, &log_key(log_reference))?;
            }
        }
    }
    for item in receipts {
        control
            .checkpoint()
            .map_err(operation_control_state_error)?;
        if let ReferenceClosure::Complete(references) = &item.metadata.log_references {
            for log_reference in references {
                require_reference(&log_by_key, &item.key, &log_key(log_reference))?;
            }
        }
    }
    Ok(())
}

fn charge_reference_budget(
    budget: &mut EvidenceScanBudget,
    receipts: &[StoredDocument<ReceiptRetentionMetadata>],
    evidence: &[StoredDocument<EvidenceRetentionMetadata>],
    log_count: usize,
) -> Result<(), StateError> {
    for item in receipts {
        budget.charge_references(
            &item.key,
            reference_closure_count(&item.metadata.log_references, log_count),
        )?;
    }
    for item in evidence {
        let references = reference_closure_count(&item.metadata.receipt_references, receipts.len())
            .checked_add(reference_closure_count(
                &item.metadata.log_references,
                log_count,
            ))
            .ok_or(StateError::StateSizeOverflow)?;
        budget.charge_references(&item.key, references)?;
    }
    Ok(())
}

fn reference_closure_count<T: Ord>(closure: &ReferenceClosure<T>, all_count: usize) -> usize {
    match closure {
        ReferenceClosure::Complete(references) => references.len(),
        ReferenceClosure::RetainAll => all_count,
    }
}

fn build_evidence_gc_plan<D: EvidenceStateMetadataDecoder + ?Sized>(
    store: &AtomicStateStore,
    now: SystemTime,
    decoder: &D,
    pending: Option<&PendingEvidenceObject<'_>>,
    forced_root: Option<&str>,
) -> Result<EvidenceGcPlan, StateError> {
    let ScannedEvidenceState {
        mut receipts,
        mut evidence,
        mut logs,
        mut budget,
    } = scan_evidence_state(store, decoder)?;

    if let Some(pending) = pending {
        let pending_size =
            u64::try_from(pending.bytes().len()).map_err(|_| StateError::StateSizeOverflow)?;
        match pending {
            PendingEvidenceObject::Receipt {
                object_name,
                metadata,
                ..
            } => {
                budget.charge_references(
                    &pending.key(),
                    reference_closure_count(&metadata.log_references, logs.len()),
                )?;
                receipts.push(StoredDocument {
                    key: pending.key(),
                    version: EvidenceStateVersion::V2,
                    object_name: object_name.clone(),
                    size: pending_size,
                    metadata: metadata.clone(),
                    snapshot: None,
                    pending: true,
                });
            }
            PendingEvidenceObject::Evidence {
                object_name,
                metadata,
                ..
            } => {
                budget.charge_references(
                    &pending.key(),
                    reference_closure_count(&metadata.receipt_references, receipts.len())
                        .checked_add(reference_closure_count(
                            &metadata.log_references,
                            logs.len(),
                        ))
                        .ok_or(StateError::StateSizeOverflow)?,
                )?;
                evidence.push(StoredDocument {
                    key: pending.key(),
                    version: EvidenceStateVersion::V2,
                    object_name: object_name.clone(),
                    size: pending_size,
                    metadata: metadata.clone(),
                    snapshot: None,
                    pending: true,
                });
            }
            PendingEvidenceObject::Log { object_name, .. } => logs.push(StoredLog {
                key: pending.key(),
                object_name: object_name.clone(),
                size: pending_size,
                snapshot: None,
                pending: true,
            }),
        }
    }

    let pending_bytes = pending
        .map(|object| u64::try_from(object.bytes().len()))
        .transpose()
        .map_err(|_| StateError::StateSizeOverflow)?
        .unwrap_or_default();
    let projected_scan_bytes = budget
        .bytes
        .checked_add(pending_bytes)
        .ok_or(StateError::StateSizeOverflow)?;
    validate_evidence_references(&receipts, &evidence, &logs)?;

    let mut retained_evidence = select_time_roots(&evidence, now, |item| item.metadata.created_at)?;
    let mut retained_receipts = select_time_roots(&receipts, now, |item| item.metadata.started_at)?;
    let mut retained_logs = BTreeSet::new();

    // The prospective object is a root for pre-write capacity planning so its complete dependency
    // closure is included in the retained-byte check. No deletion occurs before the immutable
    // create succeeds.
    for item in &evidence {
        if item.pending {
            retained_evidence.insert(item.key.clone());
        }
    }
    for item in &receipts {
        if item.pending {
            retained_receipts.insert(item.key.clone());
        }
    }
    for item in &logs {
        if item.pending {
            retained_logs.insert(item.key.clone());
        }
    }
    if let Some(forced_root) = forced_root {
        let found = if evidence.iter().any(|item| item.key == forced_root) {
            retained_evidence.insert(forced_root.to_owned());
            true
        } else if receipts.iter().any(|item| item.key == forced_root) {
            retained_receipts.insert(forced_root.to_owned());
            true
        } else if logs.iter().any(|item| item.key == forced_root) {
            retained_logs.insert(forced_root.to_owned());
            true
        } else {
            false
        };
        if !found {
            return Err(StateError::StateChanged {
                key: forced_root.to_owned(),
            });
        }
    }

    // Only retained Evidence contributes references. References owned solely by Evidence selected
    // for deletion are intentionally removed before recomputing the Receipt/log closure.
    for item in evidence
        .iter()
        .filter(|item| retained_evidence.contains(&item.key))
    {
        match &item.metadata.receipt_references {
            ReferenceClosure::Complete(references) => {
                for receipt_reference in references {
                    retained_receipts.insert(receipt_key(receipt_reference));
                }
            }
            ReferenceClosure::RetainAll => {
                retained_receipts.extend(receipts.iter().map(|receipt| receipt.key.clone()));
            }
        }
        match &item.metadata.log_references {
            ReferenceClosure::Complete(references) => {
                for log_reference in references {
                    retained_logs.insert(log_key(log_reference));
                }
            }
            ReferenceClosure::RetainAll => {
                retained_logs.extend(logs.iter().map(|log| log.key.clone()));
            }
        }
    }

    for item in receipts
        .iter()
        .filter(|item| retained_receipts.contains(&item.key))
    {
        match &item.metadata.log_references {
            ReferenceClosure::Complete(references) => {
                for log_reference in references {
                    retained_logs.insert(log_key(log_reference));
                }
            }
            ReferenceClosure::RetainAll => {
                retained_logs.extend(logs.iter().map(|log| log.key.clone()));
            }
        }
    }

    let delete_evidence = planned_deletions(&evidence, &retained_evidence)?;
    let delete_receipts = planned_deletions(&receipts, &retained_receipts)?;
    let delete_logs: Vec<_> = logs
        .iter()
        .filter(|item| !retained_logs.contains(&item.key))
        .map(planned_log_deletion)
        .collect::<Result<_, _>>()?;

    let retained_bytes = retained_state_bytes(
        &receipts,
        &retained_receipts,
        &evidence,
        &retained_evidence,
        &logs,
        &retained_logs,
    )?;
    ensure_retained_budget(retained_bytes)?;
    let reclaimed_bytes = deletion_bytes(
        delete_evidence
            .iter()
            .chain(&delete_receipts)
            .chain(&delete_logs),
    )?;
    let projected_receipts = receipts.len();
    let projected_evidence = evidence.len();
    let projected_logs = logs.len();

    Ok(EvidenceGcPlan {
        delete_evidence,
        delete_receipts,
        delete_logs,
        reclaimed_bytes,
        retained_bytes,
        projected_scan_bytes,
        projected_receipts,
        projected_evidence,
        projected_logs,
    })
}

fn scan_document_keys(
    store: &AtomicStateStore,
    directories: &[(EvidenceStateVersion, &str)],
    max_entries: usize,
) -> Result<Vec<(EvidenceStateVersion, String, EvidenceStateObjectName)>, StateError> {
    let mut files = Vec::new();
    for (version, directory) in directories {
        let remaining = max_entries.saturating_sub(files.len());
        let relative = validate_state_key(directory)?;
        let keys = store.list_regular_keys_bounded_inner(directory, &relative, remaining)?;
        for key in keys {
            let object_name = object_name_from_key(&key, ".json")?;
            files.push((*version, key, object_name));
        }
    }
    Ok(files)
}

fn scan_receipt_files<D: EvidenceStateMetadataDecoder + ?Sized>(
    store: &AtomicStateStore,
    decoder: &D,
    budget: &mut EvidenceScanBudget,
    control: &dyn OperationControl,
) -> Result<Vec<StoredDocument<ReceiptRetentionMetadata>>, StateError> {
    let files = scan_document_keys(
        store,
        &[
            (EvidenceStateVersion::V1, RECEIPTS_V1_DIRECTORY),
            (EvidenceStateVersion::V2, RECEIPTS_V2_DIRECTORY),
        ],
        EVIDENCE_GC_MAX_RECEIPTS,
    )?;
    let mut receipts = Vec::with_capacity(files.len());
    for (version, key, object_name) in files {
        control
            .checkpoint()
            .map_err(operation_control_state_error)?;
        let file = read_private_state_file_bounded(store, &key, RECEIPT_OBJECT_MAX_BYTES, budget)?;
        let metadata = decoder
            .decode_receipt(version, &file.bytes)
            .map_err(|reason| StateError::ObjectDecode {
                key: key.clone(),
                reason,
            })?;
        ensure_declared_identity(&key, &object_name, &metadata.object_name)?;
        validate_retention_time(version, metadata.started_at, &key)?;
        receipts.push(StoredDocument {
            key,
            version,
            object_name,
            size: file.snapshot.identity.size,
            metadata,
            snapshot: Some(file.snapshot),
            pending: false,
        });
    }
    Ok(receipts)
}

fn scan_evidence_files<D: EvidenceStateMetadataDecoder + ?Sized>(
    store: &AtomicStateStore,
    decoder: &D,
    budget: &mut EvidenceScanBudget,
    control: &dyn OperationControl,
) -> Result<Vec<StoredDocument<EvidenceRetentionMetadata>>, StateError> {
    let files = scan_document_keys(
        store,
        &[
            (EvidenceStateVersion::V1, EVIDENCE_V1_DIRECTORY),
            (EvidenceStateVersion::V2, EVIDENCE_V2_DIRECTORY),
        ],
        EVIDENCE_GC_MAX_EVIDENCE,
    )?;
    let mut evidence = Vec::with_capacity(files.len());
    for (version, key, object_name) in files {
        control
            .checkpoint()
            .map_err(operation_control_state_error)?;
        let file = read_private_state_file_bounded(store, &key, EVIDENCE_OBJECT_MAX_BYTES, budget)?;
        let metadata = decoder
            .decode_evidence(version, &file.bytes)
            .map_err(|reason| StateError::ObjectDecode {
                key: key.clone(),
                reason,
            })?;
        ensure_declared_identity(&key, &object_name, &metadata.object_name)?;
        validate_retention_time(version, metadata.created_at, &key)?;
        evidence.push(StoredDocument {
            key,
            version,
            object_name,
            size: file.snapshot.identity.size,
            metadata,
            snapshot: Some(file.snapshot),
            pending: false,
        });
    }
    Ok(evidence)
}

fn scan_log_files(
    store: &AtomicStateStore,
    budget: &mut EvidenceScanBudget,
    control: &dyn OperationControl,
) -> Result<Vec<StoredLog>, StateError> {
    let relative = validate_state_key(LOGS_V1_DIRECTORY)?;
    let keys = store.list_regular_keys_bounded_inner(
        LOGS_V1_DIRECTORY,
        &relative,
        EVIDENCE_GC_MAX_LOGS,
    )?;
    let mut logs = Vec::with_capacity(keys.len());
    for key in keys {
        control
            .checkpoint()
            .map_err(operation_control_state_error)?;
        let object_name = object_name_from_key(&key, ".log")?;
        let (snapshot, content_address) = stream_private_state_file(store, &key, budget, true)?;
        if content_address.as_deref() != Some(object_name.as_str()) {
            return Err(StateError::ObjectContentAddressMismatch { key });
        }
        logs.push(StoredLog {
            key,
            object_name,
            size: snapshot.identity.size,
            snapshot: Some(snapshot),
            pending: false,
        });
    }
    Ok(logs)
}

fn validate_version_hierarchy(
    store: &AtomicStateStore,
    parent: &str,
    allowed_versions: &[&str],
) -> Result<(), StateError> {
    let relative = validate_state_key(parent)?;
    let Some(path) = validate_existing_state_directory(store.layout.worktree_dir(), &relative)?
    else {
        return Ok(());
    };
    let parent_metadata = fs::symlink_metadata(&path)
        .map_err(|source| StateError::io("inspect immutable state hierarchy", &path, source))?;
    validate_private_evidence_directory(&path, &parent_metadata)?;
    for entry in fs::read_dir(&path)
        .map_err(|source| StateError::io("list immutable state hierarchy", &path, source))?
    {
        let entry = entry
            .map_err(|source| StateError::io("read immutable state hierarchy", &path, source))?;
        let entry_path = entry.path();
        let metadata = fs::symlink_metadata(&entry_path).map_err(|source| {
            StateError::io("inspect immutable state hierarchy", &entry_path, source)
        })?;
        if metadata_is_link_or_reparse(&metadata) {
            return Err(StateError::PathSafety(FileSystemError::SymlinkComponent {
                path: entry_path,
            }));
        }
        if !metadata.is_dir() {
            return Err(StateError::InvalidLayout {
                path: entry_path,
                reason: "immutable state kind contains a non-version directory entry".to_owned(),
            });
        }
        let version = entry
            .file_name()
            .into_string()
            .map_err(|_| StateError::InvalidLayout {
                path: entry.path(),
                reason: "immutable state versions must use portable ASCII names".to_owned(),
            })?;
        if !allowed_versions.contains(&version.as_str()) {
            return Err(StateError::UnsupportedEvidenceStateVersion { path: entry.path() });
        }
        validate_private_evidence_directory(&entry.path(), &metadata)?;
    }
    Ok(())
}

fn object_name_from_key(key: &str, extension: &str) -> Result<EvidenceStateObjectName, StateError> {
    let file_name = key.rsplit('/').next().unwrap_or(key);
    let Some(payload) = file_name.strip_suffix(extension) else {
        return Err(StateError::InvalidLayout {
            path: PathBuf::from(key),
            reason: "immutable state object has an unexpected filename extension".to_owned(),
        });
    };
    EvidenceStateObjectName::new(payload).map_err(|_| StateError::InvalidLayout {
        path: PathBuf::from(key),
        reason: "immutable state object has a non-canonical digest filename".to_owned(),
    })
}

#[derive(Debug)]
struct ReadStateFile {
    bytes: Vec<u8>,
    snapshot: StateFileSnapshot,
}

fn read_private_state_file_bounded(
    store: &AtomicStateStore,
    key: &str,
    max_bytes: usize,
    budget: &mut EvidenceScanBudget,
) -> Result<ReadStateFile, StateError> {
    let Some((path, path_metadata)) = resolve_existing_private_state_file(store, key)? else {
        return Err(StateError::StateChanged {
            key: key.to_owned(),
        });
    };
    validate_private_regular_file(&path, &path_metadata)?;
    if path_metadata.len() > max_bytes as u64 {
        return Err(StateError::ObjectTooLarge {
            key: key.to_owned(),
            max_bytes,
        });
    }
    budget.charge_bytes(key, path_metadata.len())?;

    let mut file = open_private_state_file(&path)?;
    let open_metadata = file
        .metadata()
        .map_err(|source| StateError::io("inspect opened immutable state object", &path, source))?;
    validate_private_regular_file(&path, &open_metadata)?;
    ensure_same_file_identity(key, &path_metadata, &open_metadata)?;

    let capacity = usize::try_from(open_metadata.len())
        .map_err(|_| StateError::StateSizeOverflow)?
        .min(max_bytes);
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take((max_bytes as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| StateError::io("read immutable state object", &path, source))?;
    if bytes.len() > max_bytes {
        return Err(StateError::ObjectTooLarge {
            key: key.to_owned(),
            max_bytes,
        });
    }
    let byte_len = u64::try_from(bytes.len()).map_err(|_| StateError::StateSizeOverflow)?;
    if byte_len != open_metadata.len() {
        return Err(StateError::StateChanged {
            key: key.to_owned(),
        });
    }

    let snapshot = StateFileSnapshot {
        identity: state_file_identity(&open_metadata),
        content_digest: *blake3::hash(&bytes).as_bytes(),
    };
    verify_open_file_still_names_path(key, &path, &file, &snapshot)?;
    Ok(ReadStateFile { bytes, snapshot })
}

fn existing_private_file_matches(
    store: &AtomicStateStore,
    key: &str,
    expected: &[u8],
    max_bytes: usize,
) -> Result<Option<bool>, StateError> {
    existing_private_file_matches_with_hook(store, key, expected, max_bytes, |_| Ok(()))
}

fn existing_private_file_matches_with_hook(
    store: &AtomicStateStore,
    key: &str,
    expected: &[u8],
    max_bytes: usize,
    after_inspect: impl FnOnce(&Path) -> io::Result<()>,
) -> Result<Option<bool>, StateError> {
    let Some((path, path_metadata)) = resolve_existing_private_state_file(store, key)? else {
        return Ok(None);
    };
    validate_private_regular_file(&path, &path_metadata)?;
    if path_metadata.len() > max_bytes as u64 {
        return Err(StateError::ObjectTooLarge {
            key: key.to_owned(),
            max_bytes,
        });
    }
    let expected_len = u64::try_from(expected.len()).map_err(|_| StateError::StateSizeOverflow)?;
    if path_metadata.len() != expected_len {
        return Ok(Some(false));
    }

    after_inspect(&path).map_err(|source| {
        StateError::io("run immutable collision read race hook", &path, source)
    })?;
    let mut file = open_private_state_file(&path)?;
    let open_metadata = file
        .metadata()
        .map_err(|source| StateError::io("inspect opened immutable state object", &path, source))?;
    validate_private_regular_file(&path, &open_metadata)?;
    ensure_same_file_identity(key, &path_metadata, &open_metadata)?;

    let mut offset = 0_usize;
    let mut buffer = [0_u8; 64 * 1024];
    let mut raw_hasher = blake3::Hasher::new();
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|source| StateError::io("read immutable state object", &path, source))?;
        if count == 0 {
            break;
        }
        raw_hasher.update(&buffer[..count]);
        let Some(expected_chunk) = expected.get(offset..offset.saturating_add(count)) else {
            return Ok(Some(false));
        };
        if buffer[..count] != *expected_chunk {
            return Ok(Some(false));
        }
        offset = offset
            .checked_add(count)
            .ok_or(StateError::StateSizeOverflow)?;
    }
    if offset != expected.len() {
        return Ok(Some(false));
    }
    let snapshot = StateFileSnapshot {
        identity: state_file_identity(&open_metadata),
        content_digest: *raw_hasher.finalize().as_bytes(),
    };
    verify_open_file_still_names_path(key, &path, &file, &snapshot)?;
    Ok(Some(true))
}

fn stream_private_state_file(
    store: &AtomicStateStore,
    key: &str,
    budget: &mut EvidenceScanBudget,
    compute_log_identity: bool,
) -> Result<(StateFileSnapshot, Option<String>), StateError> {
    let Some((path, path_metadata)) = resolve_existing_private_state_file(store, key)? else {
        return Err(StateError::StateChanged {
            key: key.to_owned(),
        });
    };
    validate_private_regular_file(&path, &path_metadata)?;
    budget.charge_bytes(key, path_metadata.len())?;
    stream_opened_private_state_file(key, &path, &path_metadata, compute_log_identity)
}

fn snapshot_private_state_file(
    store: &AtomicStateStore,
    key: &str,
) -> Result<StateFileSnapshot, StateError> {
    let Some((path, path_metadata)) = resolve_existing_private_state_file(store, key)? else {
        return Err(StateError::StateChanged {
            key: key.to_owned(),
        });
    };
    validate_private_regular_file(&path, &path_metadata)?;
    stream_opened_private_state_file(key, &path, &path_metadata, false)
        .map(|(snapshot, _)| snapshot)
}

struct SnapshotReader<'a> {
    file: &'a mut File,
    remaining: u64,
    hasher: blake3::Hasher,
}

impl Read for SnapshotReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 || buffer.is_empty() {
            return Ok(0);
        }
        let limit = usize::try_from(self.remaining.min(buffer.len() as u64))
            .map_err(|_| io::Error::other("evidence object read bound overflowed"))?;
        let count = self.file.read(&mut buffer[..limit])?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "evidence object changed while reading its bounded snapshot",
            ));
        }
        self.hasher.update(&buffer[..count]);
        self.remaining -= count as u64;
        Ok(count)
    }
}

impl SnapshotReader<'_> {
    fn finish(mut self) -> io::Result<[u8; 32]> {
        let mut buffer = [0_u8; 64 * 1024];
        while self.remaining != 0 {
            let _count = self.read(&mut buffer)?;
        }
        Ok(*self.hasher.finalize().as_bytes())
    }
}

#[allow(clippy::too_many_arguments)]
fn visit_scanned_object<F>(
    store: &AtomicStateStore,
    kind: EvidenceStateObjectKind,
    key: &str,
    object_name: &EvidenceStateObjectName,
    size: u64,
    expected: Option<&StateFileSnapshot>,
    max_bytes: usize,
    visit: &mut F,
) -> Result<(), StateError>
where
    F: FnMut(EvidenceStateObjectSnapshot<'_>) -> io::Result<()>,
{
    let expected = expected.ok_or_else(|| StateError::StateChanged {
        key: key.to_owned(),
    })?;
    if size > max_bytes as u64 {
        return Err(StateError::ObjectTooLarge {
            key: key.to_owned(),
            max_bytes,
        });
    }
    let Some((path, path_metadata)) = resolve_existing_private_state_file(store, key)? else {
        return Err(StateError::StateChanged {
            key: key.to_owned(),
        });
    };
    validate_private_regular_file(&path, &path_metadata)?;
    if state_file_identity(&path_metadata) != expected.identity {
        return Err(StateError::StateChanged {
            key: key.to_owned(),
        });
    }

    let mut file = open_private_state_file(&path)?;
    let open_metadata = file
        .metadata()
        .map_err(|source| StateError::io("inspect opened immutable state object", &path, source))?;
    validate_private_regular_file(&path, &open_metadata)?;
    ensure_same_file_identity(key, &path_metadata, &open_metadata)?;

    let mut reader = SnapshotReader {
        file: &mut file,
        remaining: size,
        hasher: blake3::Hasher::new(),
    };
    visit(EvidenceStateObjectSnapshot {
        kind,
        key,
        object_name,
        size,
        bytes: &mut reader,
    })
    .map_err(|source| StateError::io("consume read-only evidence object", &path, source))?;
    let content_digest = reader
        .finish()
        .map_err(|source| StateError::io("finish read-only evidence object", &path, source))?;
    if content_digest != expected.content_digest {
        return Err(StateError::StateChanged {
            key: key.to_owned(),
        });
    }
    verify_open_file_still_names_path(key, &path, &file, expected)
}

fn stream_opened_private_state_file(
    key: &str,
    path: &Path,
    path_metadata: &fs::Metadata,
    compute_log_identity: bool,
) -> Result<(StateFileSnapshot, Option<String>), StateError> {
    stream_opened_private_state_file_with_hook(
        key,
        path,
        path_metadata,
        compute_log_identity,
        |_| Ok(()),
    )
}

fn stream_opened_private_state_file_with_hook(
    key: &str,
    path: &Path,
    path_metadata: &fs::Metadata,
    compute_log_identity: bool,
    after_open: impl FnOnce(&Path) -> io::Result<()>,
) -> Result<(StateFileSnapshot, Option<String>), StateError> {
    let mut file = open_private_state_file(path)?;
    let open_metadata = file
        .metadata()
        .map_err(|source| StateError::io("inspect opened immutable state object", path, source))?;
    validate_private_regular_file(path, &open_metadata)?;
    ensure_same_file_identity(key, path_metadata, &open_metadata)?;

    let mut raw_hasher = blake3::Hasher::new();
    let mut log_hasher = compute_log_identity.then(|| {
        let mut hasher = blake3::Hasher::new();
        hasher.update(DIGEST_FRAMING_DOMAIN);
        update_framed_digest_chunk(&mut hasher, LOG_IDENTITY_DOMAIN);
        hasher.update(&open_metadata.len().to_le_bytes());
        hasher
    });
    after_open(path)
        .map_err(|source| StateError::io("run immutable state read race hook", path, source))?;

    // Read exactly the size whose bytes were charged to the scan budget. A concurrently growing
    // file must never turn a bounded state scan into an unbounded read.
    let mut remaining = open_metadata.len();
    let mut buffer = [0_u8; 64 * 1024];
    while remaining != 0 {
        let limit = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| StateError::StateSizeOverflow)?;
        let count = file
            .read(&mut buffer[..limit])
            .map_err(|source| StateError::io("read immutable state object", path, source))?;
        if count == 0 {
            return Err(StateError::StateChanged {
                key: key.to_owned(),
            });
        }
        let chunk = &buffer[..count];
        raw_hasher.update(chunk);
        if let Some(hasher) = &mut log_hasher {
            hasher.update(chunk);
        }
        remaining -= u64::try_from(count).map_err(|_| StateError::StateSizeOverflow)?;
    }
    let snapshot = StateFileSnapshot {
        identity: state_file_identity(&open_metadata),
        content_digest: *raw_hasher.finalize().as_bytes(),
    };
    verify_open_file_still_names_path(key, path, &file, &snapshot)?;
    let log_identity = log_hasher.map(|hasher| hasher.finalize().to_hex().to_string());
    Ok((snapshot, log_identity))
}

fn resolve_existing_private_state_file(
    store: &AtomicStateStore,
    key: &str,
) -> Result<Option<(PathBuf, fs::Metadata)>, StateError> {
    let relative = validate_state_key(key)?;
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));
    if !parent.as_os_str().is_empty()
        && validate_existing_state_directory(store.layout.worktree_dir(), parent)?.is_none()
    {
        return Ok(None);
    }
    if super::is_reserved_state_path(&relative) {
        validate_evidence_ancestor_permissions(store.layout.worktree_dir(), parent)?;
    }
    let path = store.layout.worktree_dir().join(relative);
    match fs::symlink_metadata(&path) {
        Ok(metadata) => Ok(Some((path, metadata))),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(StateError::io(
            "inspect immutable state object",
            path,
            source,
        )),
    }
}

fn validate_private_regular_file(path: &Path, metadata: &fs::Metadata) -> Result<(), StateError> {
    if metadata_is_link_or_reparse(metadata) {
        return Err(StateError::PathSafety(FileSystemError::SymlinkComponent {
            path: path.to_path_buf(),
        }));
    }
    if !metadata.is_file() {
        return Err(StateError::InvalidLayout {
            path: path.to_path_buf(),
            reason: "immutable state object is not a regular file".to_owned(),
        });
    }
    validate_private_file_permissions(path, metadata)?;
    validate_no_extended_acl_path(path, metadata)
}

fn ensure_same_file_identity(
    key: &str,
    expected: &fs::Metadata,
    actual: &fs::Metadata,
) -> Result<(), StateError> {
    if state_file_identity(expected) == state_file_identity(actual) {
        return Ok(());
    }
    Err(StateError::StateChanged {
        key: key.to_owned(),
    })
}

fn verify_open_file_still_names_path(
    key: &str,
    path: &Path,
    file: &File,
    expected: &StateFileSnapshot,
) -> Result<(), StateError> {
    let open_metadata = file.metadata().map_err(|source| {
        StateError::io("reinspect opened immutable state object", path, source)
    })?;
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|source| StateError::io("reinspect immutable state object path", path, source))?;
    validate_private_regular_file(path, &path_metadata)?;
    let identity = state_file_identity(&open_metadata);
    let snapshot_matches =
        identity == expected.identity && state_file_identity(&path_metadata) == identity;
    #[cfg(windows)]
    let path_still_names_handle = super::windows::file_handle_still_names_path(
        file,
        path,
        super::windows_acl_policy::PrivateWindowsObjectKind::File,
    )?;
    #[cfg(not(windows))]
    let path_still_names_handle = true;
    if snapshot_matches && path_still_names_handle {
        return Ok(());
    }
    Err(StateError::StateChanged {
        key: key.to_owned(),
    })
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
                "open immutable state object without following links",
                path,
                source,
            )
        })
}

#[cfg(windows)]
fn open_private_state_file(path: &Path) -> Result<File, StateError> {
    super::windows::open_private_file_read(path).map_err(|source| {
        StateError::io(
            "open immutable state object without following Windows reparse points",
            path,
            source,
        )
    })
}

#[cfg(not(any(unix, windows)))]
fn open_private_state_file(path: &Path) -> Result<File, StateError> {
    Err(StateError::EvidenceStateReadUnsupported {
        platform: std::env::consts::OS,
        reason: "native no-follow evidence-state reads are not implemented",
    })
}

#[cfg(unix)]
fn state_file_identity(metadata: &fs::Metadata) -> StateFileIdentity {
    use std::os::unix::fs::MetadataExt as _;

    StateFileIdentity {
        size: metadata.len(),
        device: metadata.dev(),
        inode: metadata.ino(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}

#[cfg(windows)]
fn state_file_identity(metadata: &fs::Metadata) -> StateFileIdentity {
    use std::os::windows::fs::MetadataExt as _;

    StateFileIdentity {
        size: metadata.len(),
        creation_time: metadata.creation_time(),
        last_write_time: metadata.last_write_time(),
        file_attributes: metadata.file_attributes(),
    }
}

#[cfg(not(any(unix, windows)))]
fn state_file_identity(metadata: &fs::Metadata) -> StateFileIdentity {
    StateFileIdentity {
        size: metadata.len(),
        modified: metadata.modified().ok(),
        created: metadata.created().ok(),
    }
}

fn ensure_declared_identity(
    key: &str,
    filename: &EvidenceStateObjectName,
    declared: &EvidenceStateObjectName,
) -> Result<(), StateError> {
    if filename == declared {
        return Ok(());
    }
    Err(StateError::ObjectIdentityMismatch {
        key: key.to_owned(),
        declared: declared.as_str().to_owned(),
    })
}

fn validate_retention_time(
    version: EvidenceStateVersion,
    timestamp: EvidenceRetentionTime,
    key: &str,
) -> Result<(), StateError> {
    if matches!(
        (version, timestamp),
        (EvidenceStateVersion::V1, EvidenceRetentionTime::Legacy)
            | (EvidenceStateVersion::V2, EvidenceRetentionTime::Current(_))
    ) {
        return Ok(());
    }
    Err(StateError::ObjectDecode {
        key: key.to_owned(),
        reason: EvidenceStateDecodeError::InvalidTimestamp,
    })
}

fn select_time_roots<M>(
    objects: &[StoredDocument<M>],
    now: SystemTime,
    timestamp: impl Fn(&StoredDocument<M>) -> EvidenceRetentionTime,
) -> Result<BTreeSet<String>, StateError> {
    let now = UtcTimestamp::from(now);
    let keep_age_nanoseconds = duration_to_nanos(EVIDENCE_GC_KEEP_AGE);
    let mut retained: BTreeSet<String> = objects
        .iter()
        .filter(|item| item.version.is_legacy())
        .map(|item| item.key.clone())
        .collect();
    let mut current = Vec::new();
    for item in objects.iter().filter(|item| !item.version.is_legacy()) {
        let EvidenceRetentionTime::Current(timestamp) = timestamp(item) else {
            return Err(StateError::ObjectDecode {
                key: item.key.clone(),
                reason: EvidenceStateDecodeError::InvalidTimestamp,
            });
        };
        current.push((item, timestamp));
    }
    current.sort_by(|left, right| {
        right
            .1
            .cmp(&left.1)
            .then_with(|| left.0.object_name.cmp(&right.0.object_name))
    });
    retained.extend(
        current
            .iter()
            .take(EVIDENCE_GC_KEEP_LATEST)
            .map(|(item, _)| item.key.clone()),
    );
    retained.extend(
        current
            .into_iter()
            .filter(|(_, timestamp)| {
                now.unix_nanoseconds
                    .checked_sub(timestamp.unix_nanoseconds)
                    .is_none_or(|age| age <= keep_age_nanoseconds)
            })
            .map(|(item, _)| item.key.clone()),
    );
    Ok(retained)
}

fn receipt_key(reference: &ReceiptStateReference) -> String {
    receipt_object_key(reference.version, &reference.object_name)
}

fn log_key(object_name: &EvidenceStateObjectName) -> String {
    log_object_key(object_name)
}

fn receipt_object_key(
    version: EvidenceStateVersion,
    object_name: &EvidenceStateObjectName,
) -> String {
    format!(
        "receipts/v{}/{}.json",
        version.major(),
        object_name.as_str()
    )
}

fn evidence_object_key(
    version: EvidenceStateVersion,
    object_name: &EvidenceStateObjectName,
) -> String {
    format!(
        "evidence/v{}/{}.json",
        version.major(),
        object_name.as_str()
    )
}

fn log_object_key(object_name: &EvidenceStateObjectName) -> String {
    format!("logs/v1/{}.log", object_name.as_str())
}

pub(super) fn is_evidence_gc_quarantine_name(name: &std::ffi::OsStr) -> bool {
    name.to_str()
        .is_some_and(|name| name.starts_with(GC_QUARANTINE_PREFIX))
}

fn validate_evidence_ancestor_permissions(root: &Path, relative: &Path) -> Result<(), StateError> {
    let mut candidate = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(segment) = component else {
            return Err(StateError::UnsafeKey {
                key: relative.to_string_lossy().into_owned(),
                reason: "evidence state hierarchy is not normalized".to_owned(),
            });
        };
        candidate.push(segment);
        let metadata = fs::symlink_metadata(&candidate).map_err(|source| {
            StateError::io(
                "inspect private evidence state directory",
                &candidate,
                source,
            )
        })?;
        validate_private_evidence_directory(&candidate, &metadata)?;
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_evidence_state_mutation_supported() -> Result<(), StateError> {
    Ok(())
}

#[cfg(windows)]
fn ensure_evidence_state_mutation_supported() -> Result<(), StateError> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn ensure_evidence_state_mutation_supported() -> Result<(), StateError> {
    Err(StateError::EvidenceStateMutationUnsupported {
        platform: std::env::consts::OS,
        reason: "owner-only evidence-state ACL creation and verification is not implemented",
    })
}

#[cfg(unix)]
fn ensure_evidence_state_read_supported() -> Result<(), StateError> {
    Ok(())
}

#[cfg(windows)]
fn ensure_evidence_state_read_supported() -> Result<(), StateError> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn ensure_evidence_state_read_supported() -> Result<(), StateError> {
    Err(StateError::EvidenceStateReadUnsupported {
        platform: std::env::consts::OS,
        reason: "owner-only evidence-state ACL verification is not implemented",
    })
}

fn ensure_log_content_address(
    key: &str,
    object_name: &EvidenceStateObjectName,
    bytes: &[u8],
) -> Result<(), StateError> {
    if log_content_address(bytes) == object_name.as_str() {
        return Ok(());
    }
    Err(StateError::ObjectContentAddressMismatch {
        key: key.to_owned(),
    })
}

fn log_content_address(bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DIGEST_FRAMING_DOMAIN);
    update_framed_digest_chunk(&mut hasher, LOG_IDENTITY_DOMAIN);
    update_framed_digest_chunk(&mut hasher, bytes);
    hasher.finalize().to_hex().to_string()
}

fn update_framed_digest_chunk(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn require_reference<T>(
    objects: &BTreeMap<&str, &T>,
    owner: &str,
    referenced: &str,
) -> Result<(), StateError> {
    if objects.contains_key(referenced) {
        return Ok(());
    }
    Err(StateError::MissingReference {
        owner: owner.to_owned(),
        referenced: referenced.to_owned(),
    })
}

fn planned_deletions<M>(
    objects: &[StoredDocument<M>],
    retained: &BTreeSet<String>,
) -> Result<Vec<PlannedDeletion>, StateError> {
    objects
        .iter()
        .filter(|item| !item.version.is_legacy() && !retained.contains(&item.key))
        .map(|item| {
            let snapshot = item
                .snapshot
                .clone()
                .ok_or_else(|| StateError::StateChanged {
                    key: item.key.clone(),
                })?;
            Ok(PlannedDeletion {
                key: item.key.clone(),
                size: item.size,
                snapshot,
            })
        })
        .collect()
}

fn planned_log_deletion(item: &StoredLog) -> Result<PlannedDeletion, StateError> {
    let snapshot = item
        .snapshot
        .clone()
        .ok_or_else(|| StateError::StateChanged {
            key: item.key.clone(),
        })?;
    Ok(PlannedDeletion {
        key: item.key.clone(),
        size: item.size,
        snapshot,
    })
}

fn retained_state_bytes(
    receipts: &[StoredDocument<ReceiptRetentionMetadata>],
    retained_receipts: &BTreeSet<String>,
    evidence: &[StoredDocument<EvidenceRetentionMetadata>],
    retained_evidence: &BTreeSet<String>,
    logs: &[StoredLog],
    retained_logs: &BTreeSet<String>,
) -> Result<u64, StateError> {
    receipts
        .iter()
        .filter(|item| retained_receipts.contains(&item.key))
        .map(|item| item.size)
        .chain(
            evidence
                .iter()
                .filter(|item| retained_evidence.contains(&item.key))
                .map(|item| item.size),
        )
        .chain(
            logs.iter()
                .filter(|item| retained_logs.contains(&item.key))
                .map(|item| item.size),
        )
        .try_fold(0_u64, |total, size| {
            total.checked_add(size).ok_or(StateError::StateSizeOverflow)
        })
}

fn ensure_retained_budget(retained_bytes: u64) -> Result<(), StateError> {
    if retained_bytes <= EVIDENCE_STATE_MAX_BYTES {
        return Ok(());
    }
    Err(StateError::RetainedBudgetExceeded {
        retained_bytes,
        max_bytes: EVIDENCE_STATE_MAX_BYTES,
    })
}

fn deletion_bytes<'a>(
    mut objects: impl Iterator<Item = &'a PlannedDeletion>,
) -> Result<u64, StateError> {
    objects.try_fold(0_u64, |total, object| {
        total
            .checked_add(object.size)
            .ok_or(StateError::StateSizeOverflow)
    })
}

fn preflight_deletions(store: &AtomicStateStore, plan: &EvidenceGcPlan) -> Result<(), StateError> {
    for object in plan
        .delete_evidence
        .iter()
        .chain(&plan.delete_receipts)
        .chain(&plan.delete_logs)
    {
        if snapshot_private_state_file(store, &object.key)? != object.snapshot {
            return Err(StateError::StateChanged {
                key: object.key.clone(),
            });
        }
    }
    Ok(())
}

fn apply_evidence_gc_plan(
    store: &AtomicStateStore,
    plan: &EvidenceGcPlan,
) -> Result<EvidenceGcReport, StateError> {
    // Multi-file deletion is not a filesystem transaction. A class-directory durability barrier
    // separates each dependency layer, so a crash cannot make a later Receipt/log deletion durable
    // before the Evidence/Receipt deletions that made it unreferenced. Deterministic quarantine
    // residue is recovered conservatively under the same worktree lock before the next scan.
    for object in &plan.delete_evidence {
        remove_regular_state_file(store, object)?;
    }
    sync_evidence_gc_class(store, EVIDENCE_V2_DIRECTORY)?;
    for object in &plan.delete_receipts {
        remove_regular_state_file(store, object)?;
    }
    sync_evidence_gc_class(store, RECEIPTS_V2_DIRECTORY)?;
    for object in &plan.delete_logs {
        remove_regular_state_file(store, object)?;
    }
    sync_evidence_gc_class(store, LOGS_V1_DIRECTORY)?;

    Ok(EvidenceGcReport {
        deleted_evidence: plan.delete_evidence.len(),
        deleted_receipts: plan.delete_receipts.len(),
        deleted_logs: plan.delete_logs.len(),
        reclaimed_bytes: plan.reclaimed_bytes,
        retained_bytes: plan.retained_bytes,
    })
}

fn remove_regular_state_file(
    store: &AtomicStateStore,
    object: &PlannedDeletion,
) -> Result<(), StateError> {
    remove_regular_state_file_with_hook(store, object, |_| Ok(()))
}

fn remove_regular_state_file_with_hook(
    store: &AtomicStateStore,
    object: &PlannedDeletion,
    before_quarantine: impl FnOnce(&Path) -> io::Result<()>,
) -> Result<(), StateError> {
    if snapshot_private_state_file(store, &object.key)? != object.snapshot {
        return Err(StateError::StateChanged {
            key: object.key.clone(),
        });
    }
    let relative = validate_state_key(&object.key)?;
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));
    validate_evidence_ancestor_permissions(store.layout.worktree_dir(), parent)?;
    let path = store.layout.worktree_dir().join(relative);
    let final_metadata = fs::symlink_metadata(&path).map_err(|source| {
        StateError::io(
            "reinspect immutable state object before removal",
            &path,
            source,
        )
    })?;
    validate_private_regular_file(&path, &final_metadata)?;
    if state_file_identity(&final_metadata) != object.snapshot.identity {
        return Err(StateError::StateChanged {
            key: object.key.clone(),
        });
    }

    let parent_path = path.parent().ok_or_else(|| StateError::InvalidLayout {
        path: path.clone(),
        reason: "immutable state object has no parent directory".to_owned(),
    })?;
    let quarantine = gc_quarantine_path(parent_path, &object.key)?;
    create_gc_quarantine_directory(&quarantine)?;
    let quarantine_path = quarantine.join(GC_QUARANTINE_OBJECT);

    before_quarantine(&path)
        .map_err(|source| StateError::io("run evidence GC race hook", &path, source))?;
    if let Err(source) = fs::rename(&path, &quarantine_path) {
        let _cleanup = fs::remove_dir(&quarantine);
        return Err(StateError::io(
            "atomically quarantine expired immutable state object",
            &path,
            source,
        ));
    }
    sync_directory(&quarantine)?;
    sync_directory(parent_path)?;

    let verification = (|| {
        let quarantined_metadata = fs::symlink_metadata(&quarantine_path).map_err(|source| {
            StateError::io(
                "inspect quarantined immutable state object",
                &quarantine_path,
                source,
            )
        })?;
        validate_private_regular_file(&quarantine_path, &quarantined_metadata)?;
        stream_opened_private_state_file(
            &object.key,
            &quarantine_path,
            &quarantined_metadata,
            false,
        )
        .map(|(snapshot, _)| snapshot)
    })();
    let quarantined_snapshot = match verification {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return restore_quarantined_replacement(
                object,
                &path,
                &quarantine,
                &quarantine_path,
                error,
            );
        }
    };
    if !snapshot_survived_quarantine(&object.snapshot, &quarantined_snapshot) {
        return restore_quarantined_replacement(
            object,
            &path,
            &quarantine,
            &quarantine_path,
            StateError::StateChanged {
                key: object.key.clone(),
            },
        );
    }

    remove_gc_quarantine(&quarantine, Some(&quarantine_path))
}

#[cfg(unix)]
fn create_gc_quarantine_directory(path: &Path) -> Result<(), StateError> {
    use std::os::unix::fs::DirBuilderExt as _;

    let mut builder = fs::DirBuilder::new();
    match builder.mode(0o700).create(path) {
        Ok(()) => {}
        Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
            return Err(StateError::InvalidLayout {
                path: path.to_path_buf(),
                reason: "immutable evidence GC residue requires held-lock recovery before deletion"
                    .to_owned(),
            });
        }
        Err(source) => {
            return Err(StateError::io(
                "create evidence GC quarantine",
                path,
                source,
            ));
        }
    }
    clear_inherited_extended_acl(path)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| StateError::io("inspect evidence GC quarantine", path, source))?;
    validate_private_evidence_directory(path, &metadata)?;
    sync_directory(path)?;
    let parent = path.parent().ok_or_else(|| StateError::InvalidLayout {
        path: path.to_path_buf(),
        reason: "evidence GC quarantine has no parent directory".to_owned(),
    })?;
    sync_directory(parent)
}

#[cfg(windows)]
fn create_gc_quarantine_directory(path: &Path) -> Result<(), StateError> {
    match super::windows::create_private_directory(path) {
        Ok(()) => {}
        Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
            return Err(StateError::InvalidLayout {
                path: path.to_path_buf(),
                reason: "immutable evidence GC residue requires held-lock recovery before deletion"
                    .to_owned(),
            });
        }
        Err(source) => {
            return Err(StateError::io(
                "create evidence GC quarantine",
                path,
                source,
            ));
        }
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| StateError::io("inspect evidence GC quarantine", path, source))?;
    validate_private_evidence_directory(path, &metadata)?;
    sync_directory(path)?;
    let parent = path.parent().ok_or_else(|| StateError::InvalidLayout {
        path: path.to_path_buf(),
        reason: "evidence GC quarantine has no parent directory".to_owned(),
    })?;
    sync_directory(parent)
}

#[cfg(not(any(unix, windows)))]
fn create_gc_quarantine_directory(_path: &Path) -> Result<(), StateError> {
    ensure_evidence_state_mutation_supported()
}

fn restore_quarantined_replacement(
    object: &PlannedDeletion,
    original_path: &Path,
    quarantine: &Path,
    quarantine_path: &Path,
    verification_error: StateError,
) -> Result<(), StateError> {
    match fs::hard_link(quarantine_path, original_path) {
        Ok(()) => {
            let parent = original_path
                .parent()
                .ok_or_else(|| StateError::InvalidLayout {
                    path: original_path.to_path_buf(),
                    reason: "restored immutable state object has no parent directory".to_owned(),
                })?;
            sync_directory(parent)?;
            remove_gc_quarantine(quarantine, Some(quarantine_path))?;
            Err(verification_error)
        }
        Err(source) => Err(StateError::QuarantineRestore {
            key: object.key.clone(),
            quarantine: quarantine_path.to_path_buf(),
            verification: verification_error.to_string(),
            source,
        }),
    }
}

fn remove_gc_quarantine(quarantine: &Path, object: Option<&Path>) -> Result<(), StateError> {
    if let Some(object) = object {
        fs::remove_file(object).map_err(|source| {
            StateError::io(
                "remove verified quarantined immutable state object",
                object,
                source,
            )
        })?;
        sync_directory(quarantine)?;
    }
    fs::remove_dir(quarantine).map_err(|source| {
        StateError::io("remove empty evidence GC quarantine", quarantine, source)
    })?;
    let parent = quarantine
        .parent()
        .ok_or_else(|| StateError::InvalidLayout {
            path: quarantine.to_path_buf(),
            reason: "evidence GC quarantine has no parent directory".to_owned(),
        })?;
    sync_directory(parent)
}

fn gc_quarantine_path(parent: &Path, key: &str) -> Result<PathBuf, StateError> {
    let extension = if key.starts_with("logs/") {
        ".log"
    } else {
        ".json"
    };
    let object_name = object_name_from_key(key, extension)?;
    Ok(parent.join(format!("{GC_QUARANTINE_PREFIX}{}", object_name.as_str())))
}

fn sync_evidence_gc_class(store: &AtomicStateStore, directory: &str) -> Result<(), StateError> {
    let relative = validate_state_key(directory)?;
    let Some(path) = validate_existing_state_directory(store.layout.worktree_dir(), &relative)?
    else {
        return Ok(());
    };
    validate_evidence_ancestor_permissions(store.layout.worktree_dir(), &relative)?;
    sync_directory(&path)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EvidenceGcRecoveryAction {
    RemoveEmpty,
    RestoreObject,
    FinishRestore,
}

#[derive(Debug)]
struct EvidenceGcResidue {
    key: String,
    parent: PathBuf,
    quarantine: PathBuf,
    object: PathBuf,
    object_identity: Option<StateFileIdentity>,
    action: EvidenceGcRecoveryAction,
}

fn recover_evidence_gc_quarantines(store: &AtomicStateStore) -> Result<(), StateError> {
    validate_evidence_root(store)?;
    let classes = [
        (EVIDENCE_V2_DIRECTORY, ".json", EVIDENCE_GC_MAX_EVIDENCE),
        (RECEIPTS_V2_DIRECTORY, ".json", EVIDENCE_GC_MAX_RECEIPTS),
        (LOGS_V1_DIRECTORY, ".log", EVIDENCE_GC_MAX_LOGS),
    ];
    let mut residues = Vec::new();
    for (directory, extension, max_objects) in classes {
        inspect_evidence_gc_residues(store, directory, extension, max_objects, &mut residues)?;
    }

    // Validate every residue before the first recovery mutation. Stable ordering keeps failures
    // reproducible and prevents directory enumeration order from changing the recovered subset.
    residues.sort_by(|left, right| left.quarantine.cmp(&right.quarantine));
    for residue in &residues {
        recover_evidence_gc_residue(residue)?;
    }
    Ok(())
}

fn store_new_atomic_idempotent_evidence(
    store: &AtomicStateStore,
    key: &str,
    relative: &Path,
    bytes: &[u8],
) -> Result<(), StateError> {
    store_new_atomic_idempotent_evidence_with_hook(store, key, relative, bytes, |_| Ok(()))
}

fn store_new_atomic_idempotent_evidence_with_hook(
    store: &AtomicStateStore,
    key: &str,
    relative: &Path,
    bytes: &[u8],
    after_collision_inspect: impl FnOnce(&Path) -> io::Result<()>,
) -> Result<(), StateError> {
    let parent = relative.parent().ok_or_else(|| StateError::UnsafeKey {
        key: key.to_owned(),
        reason: "immutable evidence key must have a version directory".to_owned(),
    })?;
    ensure_private_relative_directories(store.layout.worktree_dir(), parent)?;
    validate_evidence_root(store)?;
    validate_evidence_ancestor_permissions(store.layout.worktree_dir(), parent)?;

    match write_new_private_evidence_file(store, relative, bytes) {
        Ok(()) => Ok(()),
        Err(error) if error.io_kind() == io::ErrorKind::AlreadyExists => {
            match existing_private_file_matches_with_hook(
                store,
                key,
                bytes,
                bytes.len(),
                after_collision_inspect,
            )? {
                Some(true) => Ok(()),
                Some(false) | None => Err(StateError::ImmutableCollision {
                    key: key.to_owned(),
                }),
            }
        }
        Err(error) => Err(error),
    }
}

fn write_new_private_evidence_file(
    store: &AtomicStateStore,
    relative: &Path,
    bytes: &[u8],
) -> Result<(), StateError> {
    let target = store.layout.worktree_dir().join(relative);
    let parent = target.parent().ok_or_else(|| StateError::InvalidLayout {
        path: target.clone(),
        reason: "immutable evidence target has no parent directory".to_owned(),
    })?;
    let mut temporary = new_private_evidence_temporary_file(parent).map_err(|source| {
        StateError::io(
            "create private immutable evidence temporary file",
            parent,
            source,
        )
    })?;
    clear_inherited_extended_acl_file(temporary.as_file(), temporary.path())?;
    let temporary_metadata = temporary.as_file().metadata().map_err(|source| {
        StateError::io(
            "inspect private immutable evidence temporary file",
            temporary.path(),
            source,
        )
    })?;
    validate_private_regular_file(temporary.path(), &temporary_metadata)?;
    temporary.as_file_mut().write_all(bytes).map_err(|source| {
        StateError::io(
            "write private immutable evidence temporary file",
            temporary.path(),
            source,
        )
    })?;
    temporary.as_file_mut().flush().map_err(|source| {
        StateError::io(
            "flush private immutable evidence temporary file",
            temporary.path(),
            source,
        )
    })?;
    temporary.as_file().sync_all().map_err(|source| {
        StateError::io(
            "synchronize private immutable evidence temporary file",
            temporary.path(),
            source,
        )
    })?;

    let parent_relative = relative.parent().ok_or_else(|| StateError::InvalidLayout {
        path: target.clone(),
        reason: "immutable evidence target has no version directory".to_owned(),
    })?;
    validate_evidence_root(store)?;
    validate_evidence_ancestor_permissions(store.layout.worktree_dir(), parent_relative)?;
    #[cfg(windows)]
    let persistence_target = super::windows::verbatim_child_path(&target).map_err(|source| {
        StateError::io(
            "resolve private Windows evidence target without following the final path",
            &target,
            source,
        )
    })?;
    #[cfg(not(windows))]
    let persistence_target = target.clone();
    #[cfg(windows)]
    let persisted = {
        super::windows::persist_private_file_noclobber(temporary.path(), &persistence_target)
            .map_err(|source| {
                StateError::io(
                    "atomically create private immutable evidence object",
                    &target,
                    source,
                )
            })?;
        temporary.into_file()
    };
    #[cfg(not(windows))]
    let persisted = temporary
        .persist_noclobber(&persistence_target)
        .map_err(|error| {
            StateError::io(
                "atomically create private immutable evidence object",
                &target,
                error.error,
            )
        })?;
    sync_directory(parent)?;
    let persisted_metadata = persisted.metadata().map_err(|source| {
        StateError::io(
            "inspect persisted immutable evidence object",
            &target,
            source,
        )
    })?;
    validate_private_regular_file(&target, &persisted_metadata)?;
    #[cfg(not(windows))]
    let path_metadata = fs::symlink_metadata(&target).map_err(|source| {
        StateError::io(
            "reinspect persisted immutable evidence object path",
            &target,
            source,
        )
    })?;
    #[cfg(windows)]
    let persisted_still_named = super::windows::file_handle_still_names_path(
        &persisted,
        &target,
        super::windows_acl_policy::PrivateWindowsObjectKind::File,
    )?;
    #[cfg(not(windows))]
    let persisted_still_named = same_file_object(&persisted_metadata, &path_metadata);
    if !persisted_still_named {
        return Err(StateError::StateChanged {
            key: relative.to_string_lossy().into_owned(),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn new_private_evidence_temporary_file(parent: &Path) -> io::Result<tempfile::NamedTempFile> {
    use std::os::unix::fs::PermissionsExt as _;

    tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o600))
        .tempfile_in(parent)
}

#[cfg(windows)]
fn new_private_evidence_temporary_file(parent: &Path) -> io::Result<tempfile::NamedTempFile> {
    let parent = fs::canonicalize(parent)?;
    tempfile::Builder::new()
        .prefix(".forge-state-")
        .make_in(&parent, super::windows::create_private_file_new)
}

#[cfg(not(any(unix, windows)))]
fn new_private_evidence_temporary_file(parent: &Path) -> io::Result<tempfile::NamedTempFile> {
    tempfile::NamedTempFile::new_in(parent)
}

fn validate_evidence_root(store: &AtomicStateStore) -> Result<(), StateError> {
    let path = store.layout.worktree_dir();
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| StateError::io("inspect private evidence state root", path, source))?;
    validate_private_evidence_directory(path, &metadata)
}

fn inspect_evidence_gc_residues(
    store: &AtomicStateStore,
    directory: &str,
    extension: &str,
    max_objects: usize,
    residues: &mut Vec<EvidenceGcResidue>,
) -> Result<(), StateError> {
    let relative = validate_state_key(directory)?;
    let Some(parent) = validate_existing_state_directory(store.layout.worktree_dir(), &relative)?
    else {
        return Ok(());
    };
    validate_evidence_ancestor_permissions(store.layout.worktree_dir(), &relative)?;

    let max_entries = max_objects
        .checked_mul(2)
        .ok_or(StateError::StateSizeOverflow)?;
    let mut entries_seen = 0_usize;
    for entry in fs::read_dir(&parent)
        .map_err(|source| StateError::io("list evidence GC recovery directory", &parent, source))?
    {
        let entry = entry
            .map_err(|source| StateError::io("read evidence GC recovery entry", &parent, source))?;
        entries_seen = entries_seen
            .checked_add(1)
            .ok_or(StateError::StateSizeOverflow)?;
        if entries_seen > max_entries {
            return Err(StateError::EntryLimit {
                directory: directory.to_owned(),
                max_entries,
            });
        }
        if !is_evidence_gc_quarantine_name(&entry.file_name()) {
            continue;
        }

        let quarantine = entry.path();
        let metadata = fs::symlink_metadata(&quarantine).map_err(|source| {
            StateError::io("inspect evidence GC recovery residue", &quarantine, source)
        })?;
        validate_private_evidence_directory(&quarantine, &metadata)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| StateError::InvalidLayout {
                path: quarantine.clone(),
                reason: "evidence GC quarantine name must use portable ASCII".to_owned(),
            })?;
        let digest =
            name.strip_prefix(GC_QUARANTINE_PREFIX)
                .ok_or_else(|| StateError::InvalidLayout {
                    path: quarantine.clone(),
                    reason: "evidence GC quarantine has an invalid deterministic name".to_owned(),
                })?;
        let object_name = EvidenceStateObjectName::new(digest.to_owned()).map_err(|_| {
            StateError::InvalidLayout {
                path: quarantine.clone(),
                reason: "evidence GC quarantine has a non-canonical object identity".to_owned(),
            }
        })?;
        let key = format!("{directory}/{}{extension}", object_name.as_str());
        let original = parent.join(format!("{}{extension}", object_name.as_str()));
        let object = quarantine.join(GC_QUARANTINE_OBJECT);

        let mut contents = fs::read_dir(&quarantine)
            .map_err(|source| StateError::io("list evidence GC quarantine", &quarantine, source))?;
        let first = contents.next().transpose().map_err(|source| {
            StateError::io("read evidence GC quarantine entry", &quarantine, source)
        })?;
        let second = contents.next().transpose().map_err(|source| {
            StateError::io("read evidence GC quarantine entry", &quarantine, source)
        })?;
        if second.is_some() {
            return Err(StateError::InvalidLayout {
                path: quarantine,
                reason: "evidence GC quarantine contains more than its single recovery object"
                    .to_owned(),
            });
        }

        let Some(first) = first else {
            residues.push(EvidenceGcResidue {
                key,
                parent: parent.clone(),
                quarantine,
                object,
                object_identity: None,
                action: EvidenceGcRecoveryAction::RemoveEmpty,
            });
            continue;
        };
        if first.file_name() != std::ffi::OsStr::new(GC_QUARANTINE_OBJECT) {
            return Err(StateError::InvalidLayout {
                path: first.path(),
                reason: "evidence GC quarantine contains an unknown recovery entry".to_owned(),
            });
        }
        let object_metadata = fs::symlink_metadata(&object).map_err(|source| {
            StateError::io("inspect quarantined recovery object", &object, source)
        })?;
        validate_private_regular_file(&object, &object_metadata)?;
        let object_identity = state_file_identity(&object_metadata);
        let action = match fs::symlink_metadata(&original) {
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                EvidenceGcRecoveryAction::RestoreObject
            }
            Err(source) => {
                return Err(StateError::io(
                    "inspect original path during evidence GC recovery",
                    &original,
                    source,
                ));
            }
            Ok(original_metadata) => {
                validate_private_regular_file(&original, &original_metadata)?;
                if !same_file_object(&object_metadata, &original_metadata) {
                    return Err(StateError::InvalidLayout {
                        path: original,
                        reason: format!(
                            "held-lock recovery found a conflicting original for quarantined `{key}`; both objects were retained"
                        ),
                    });
                }
                EvidenceGcRecoveryAction::FinishRestore
            }
        };
        residues.push(EvidenceGcResidue {
            key,
            parent: parent.clone(),
            quarantine,
            object,
            object_identity: Some(object_identity),
            action,
        });
    }
    Ok(())
}

fn recover_evidence_gc_residue(residue: &EvidenceGcResidue) -> Result<(), StateError> {
    match residue.action {
        EvidenceGcRecoveryAction::RemoveEmpty => remove_gc_quarantine(&residue.quarantine, None),
        EvidenceGcRecoveryAction::RestoreObject => {
            verify_gc_recovery_object(residue)?;
            let original =
                residue
                    .parent
                    .join(residue.key.rsplit('/').next().ok_or_else(|| {
                        StateError::InvalidLayout {
                            path: residue.parent.clone(),
                            reason: "evidence GC recovery key has no filename".to_owned(),
                        }
                    })?);
            match fs::hard_link(&residue.object, &original) {
                Ok(()) => {}
                Err(source) => {
                    return Err(StateError::QuarantineRestore {
                        key: residue.key.clone(),
                        quarantine: residue.object.clone(),
                        verification: "held-lock recovery could not restore the quarantined object"
                            .to_owned(),
                        source,
                    });
                }
            }
            sync_directory(&residue.parent)?;
            let original_metadata = fs::symlink_metadata(&original).map_err(|source| {
                StateError::io("verify restored immutable state object", &original, source)
            })?;
            let object_metadata = fs::symlink_metadata(&residue.object).map_err(|source| {
                StateError::io(
                    "reinspect quarantined immutable state object",
                    &residue.object,
                    source,
                )
            })?;
            if !same_file_object(&original_metadata, &object_metadata) {
                return Err(StateError::StateChanged {
                    key: residue.key.clone(),
                });
            }
            remove_gc_quarantine(&residue.quarantine, Some(&residue.object))
        }
        EvidenceGcRecoveryAction::FinishRestore => {
            verify_gc_recovery_object(residue)?;
            let original =
                residue
                    .parent
                    .join(residue.key.rsplit('/').next().ok_or_else(|| {
                        StateError::InvalidLayout {
                            path: residue.parent.clone(),
                            reason: "evidence GC recovery key has no filename".to_owned(),
                        }
                    })?);
            let original_metadata = fs::symlink_metadata(&original).map_err(|source| {
                StateError::io(
                    "reinspect restored immutable state object",
                    &original,
                    source,
                )
            })?;
            let object_metadata = fs::symlink_metadata(&residue.object).map_err(|source| {
                StateError::io(
                    "reinspect quarantined immutable state object",
                    &residue.object,
                    source,
                )
            })?;
            if !same_file_object(&original_metadata, &object_metadata) {
                return Err(StateError::InvalidLayout {
                    path: original,
                    reason: format!(
                        "held-lock recovery found a conflicting original for quarantined `{}`; both objects were retained",
                        residue.key
                    ),
                });
            }
            remove_gc_quarantine(&residue.quarantine, Some(&residue.object))
        }
    }
}

fn verify_gc_recovery_object(residue: &EvidenceGcResidue) -> Result<(), StateError> {
    let metadata = fs::symlink_metadata(&residue.object).map_err(|source| {
        StateError::io(
            "reinspect evidence GC recovery object",
            &residue.object,
            source,
        )
    })?;
    validate_private_regular_file(&residue.object, &metadata)?;
    if residue.object_identity.as_ref() != Some(&state_file_identity(&metadata)) {
        return Err(StateError::StateChanged {
            key: residue.key.clone(),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn same_file_object(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file_object(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    state_file_identity(left) == state_file_identity(right)
}

#[cfg(target_os = "macos")]
mod macos_acl {
    #![allow(unsafe_code)]

    use std::ffi::c_void;
    use std::fs::File;
    use std::io;
    use std::os::fd::AsRawFd as _;
    use std::path::Path;

    use super::StateError;

    const ACL_TYPE_EXTENDED: i32 = 0x0000_0100;

    unsafe extern "C" {
        fn acl_free(object: *mut c_void) -> i32;
        fn acl_get_fd_np(fd: i32, acl_type: i32) -> *mut c_void;
        fn acl_init(count: i32) -> *mut c_void;
        fn acl_set_fd_np(fd: i32, acl: *mut c_void, acl_type: i32) -> i32;
    }

    pub(super) fn reject_extended_acl(file: &File, path: &Path) -> Result<(), StateError> {
        if !has_extended_acl(file, path)? {
            return Ok(());
        }
        Err(StateError::InvalidLayout {
            path: path.to_path_buf(),
            reason: "private evidence path has an extended ACL; owner-only access cannot be proven"
                .to_owned(),
        })
    }

    pub(super) fn clear_extended_acl(file: &File, path: &Path) -> Result<(), StateError> {
        // SAFETY: `acl_init` returns a standalone ACL allocation; count zero creates the empty ACL
        // Darwin accepts as removal of ACL_TYPE_EXTENDED from this live descriptor.
        let empty = unsafe { acl_init(0) };
        if empty.is_null() {
            return Err(StateError::io(
                "allocate empty macOS extended ACL",
                path,
                io::Error::last_os_error(),
            ));
        }

        // SAFETY: `empty` is live and `file` owns a live descriptor for the inspected path.
        let set_result = unsafe { acl_set_fd_np(file.as_raw_fd(), empty, ACL_TYPE_EXTENDED) };
        let set_error = (set_result != 0).then(io::Error::last_os_error);
        // SAFETY: `empty` came from `acl_init` and is released exactly once here.
        let free_result = unsafe { acl_free(empty) };
        let free_error = (free_result != 0).then(io::Error::last_os_error);
        if let Some(source) = set_error {
            return Err(StateError::io(
                "clear inherited macOS extended ACL",
                path,
                source,
            ));
        }
        if let Some(source) = free_error {
            return Err(StateError::io(
                "release empty macOS extended ACL",
                path,
                source,
            ));
        }
        reject_extended_acl(file, path)
    }

    fn has_extended_acl(file: &File, path: &Path) -> Result<bool, StateError> {
        // Darwin returns NULL/ENOENT when no extended ACL exists. Any non-NULL ACL is rejected
        // conservatively and independently freed, even if a future Darwin version can represent an
        // empty-but-present extended ACL.
        // SAFETY: the descriptor remains live and the type value is ACL_TYPE_EXTENDED from the
        // Darwin SDK.
        let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
        if acl.is_null() {
            let source = io::Error::last_os_error();
            if source.raw_os_error() == Some(nix::libc::ENOENT) {
                return Ok(false);
            }
            return Err(StateError::io("inspect macOS extended ACL", path, source));
        }

        // SAFETY: `acl` is the non-NULL owned allocation returned immediately above and is freed
        // exactly once.
        if unsafe { acl_free(acl) } != 0 {
            return Err(StateError::io(
                "release inspected macOS extended ACL",
                path,
                io::Error::last_os_error(),
            ));
        }
        Ok(true)
    }
}

#[cfg(target_os = "macos")]
fn open_extended_acl_target(path: &Path) -> Result<File, StateError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
    options.open(path).map_err(|source| {
        StateError::io(
            "open private evidence path for ACL inspection",
            path,
            source,
        )
    })
}

#[cfg(target_os = "macos")]
fn validate_no_extended_acl_path(path: &Path, expected: &fs::Metadata) -> Result<(), StateError> {
    let file = open_extended_acl_target(path)?;
    let opened = file.metadata().map_err(|source| {
        StateError::io("inspect opened private evidence ACL target", path, source)
    })?;
    if !same_file_object(expected, &opened) {
        return Err(StateError::InvalidLayout {
            path: path.to_path_buf(),
            reason: "private evidence path changed during extended ACL inspection".to_owned(),
        });
    }
    macos_acl::reject_extended_acl(&file, path)
}

#[cfg(windows)]
fn validate_no_extended_acl_path(path: &Path, expected: &fs::Metadata) -> Result<(), StateError> {
    super::windows::validate_private_path_acl(
        path,
        expected,
        super::windows_acl_policy::PrivateWindowsObjectKind::File,
    )
}

#[cfg(not(any(target_os = "macos", windows)))]
fn validate_no_extended_acl_path(_path: &Path, _expected: &fs::Metadata) -> Result<(), StateError> {
    Ok(())
}

pub(super) fn validate_private_file_acl(
    path: &Path,
    expected: &fs::Metadata,
) -> Result<(), StateError> {
    validate_no_extended_acl_path(path, expected)
}

#[cfg(windows)]
pub(super) fn validate_private_directory_acl(
    path: &Path,
    expected: &fs::Metadata,
) -> Result<(), StateError> {
    super::windows::validate_private_path_acl(
        path,
        expected,
        super::windows_acl_policy::PrivateWindowsObjectKind::Directory,
    )
}

#[cfg(not(windows))]
pub(super) fn validate_private_directory_acl(
    path: &Path,
    expected: &fs::Metadata,
) -> Result<(), StateError> {
    validate_no_extended_acl_path(path, expected)
}

#[cfg(target_os = "macos")]
pub(super) fn clear_inherited_extended_acl(path: &Path) -> Result<(), StateError> {
    let file = open_extended_acl_target(path)?;
    macos_acl::clear_extended_acl(&file, path)
}

#[cfg(windows)]
pub(super) fn clear_inherited_extended_acl(path: &Path) -> Result<(), StateError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| StateError::io("inspect new private Windows directory", path, source))?;
    super::windows::validate_private_path_acl(
        path,
        &metadata,
        super::windows_acl_policy::PrivateWindowsObjectKind::Directory,
    )
}

#[cfg(not(any(target_os = "macos", windows)))]
pub(super) fn clear_inherited_extended_acl(_path: &Path) -> Result<(), StateError> {
    Ok(())
}

#[cfg(target_os = "macos")]
pub(super) fn clear_inherited_extended_acl_file(
    file: &File,
    path: &Path,
) -> Result<(), StateError> {
    macos_acl::clear_extended_acl(file, path)
}

#[cfg(windows)]
pub(super) fn clear_inherited_extended_acl_file(
    file: &File,
    path: &Path,
) -> Result<(), StateError> {
    super::windows::set_owner_only_acl(
        file,
        path,
        super::windows_acl_policy::PrivateWindowsObjectKind::File,
    )
}

#[cfg(not(any(target_os = "macos", windows)))]
pub(super) fn clear_inherited_extended_acl_file(
    _file: &File,
    _path: &Path,
) -> Result<(), StateError> {
    Ok(())
}

#[cfg(target_os = "macos")]
pub(super) fn validate_evidence_lock_acl(file: &File, path: &Path) -> Result<(), StateError> {
    macos_acl::reject_extended_acl(file, path)
}

#[cfg(windows)]
pub(super) fn validate_evidence_lock_acl(file: &File, path: &Path) -> Result<(), StateError> {
    super::windows::validate_owner_only_file_handle(file, path)
}

#[cfg(not(any(target_os = "macos", windows)))]
pub(super) fn validate_evidence_lock_acl(_file: &File, _path: &Path) -> Result<(), StateError> {
    Ok(())
}

fn snapshot_survived_quarantine(expected: &StateFileSnapshot, actual: &StateFileSnapshot) -> bool {
    expected.content_digest == actual.content_digest
        && file_identity_survived_rename(&expected.identity, &actual.identity)
}

#[cfg(unix)]
fn file_identity_survived_rename(expected: &StateFileIdentity, actual: &StateFileIdentity) -> bool {
    expected.size == actual.size
        && expected.device == actual.device
        && expected.inode == actual.inode
        && expected.modified_seconds == actual.modified_seconds
        && expected.modified_nanoseconds == actual.modified_nanoseconds
}

#[cfg(not(unix))]
fn file_identity_survived_rename(expected: &StateFileIdentity, actual: &StateFileIdentity) -> bool {
    expected == actual
}

fn validate_private_evidence_directory(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), StateError> {
    validate_private_directory(path, metadata)?;
    validate_private_evidence_directory_permissions(path, metadata)
}

#[cfg(unix)]
fn validate_private_evidence_directory_permissions(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), StateError> {
    use std::os::unix::fs::PermissionsExt as _;

    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 || mode & 0o700 != 0o700 {
        return Err(StateError::InvalidLayout {
            path: path.to_path_buf(),
            reason: format!(
                "private evidence directory mode {mode:o} must grant owner rwx and no group or other access"
            ),
        });
    }
    validate_no_extended_acl_path(path, metadata)
}

#[cfg(windows)]
fn validate_private_evidence_directory_permissions(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), StateError> {
    super::windows::validate_private_path_acl(
        path,
        metadata,
        super::windows_acl_policy::PrivateWindowsObjectKind::Directory,
    )
}

#[cfg(not(any(unix, windows)))]
fn validate_private_evidence_directory_permissions(
    _path: &Path,
    _metadata: &fs::Metadata,
) -> Result<(), StateError> {
    Err(StateError::EvidenceStateMutationUnsupported {
        platform: std::env::consts::OS,
        reason: "owner-only evidence-state ACL verification is not implemented",
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::error::Error;
    use std::fs;
    use std::io;
    use std::path::{Path, PathBuf};
    #[cfg(target_os = "macos")]
    use std::process::Command;
    use std::time::{Duration, SystemTime};

    #[cfg(unix)]
    use forge_core::Digest;
    use tempfile::{TempDir, tempdir};

    #[cfg(unix)]
    use crate::state::{SharedCacheKind, SharedCacheStore, SharedCacheWrite};

    use super::{
        AtomicStateStore, EVIDENCE_GC_KEEP_AGE, EVIDENCE_GC_MAX_LOGS, EVIDENCE_OBJECT_MAX_BYTES,
        EVIDENCE_STATE_MAX_BYTES, EvidenceRetentionMetadata, EvidenceRetentionTime,
        EvidenceStateDecodeError, EvidenceStateMetadataDecoder, EvidenceStateObjectKind,
        EvidenceStateObjectName, EvidenceStateVersion, GitStateLayout, RECEIPT_OBJECT_MAX_BYTES,
        ReceiptRetentionMetadata, ReceiptStateReference, StateError, UtcTimestampError,
        ensure_retained_budget, format_utc_rfc3339, log_content_address, parse_utc_rfc3339,
        stream_opened_private_state_file_with_hook, validate_state_key,
    };
    #[cfg(unix)]
    use super::{
        EvidenceGcPlan, GC_QUARANTINE_OBJECT, GC_QUARANTINE_PREFIX, PlannedDeletion,
        ReferenceClosure, apply_evidence_gc_plan, preflight_deletions,
        remove_regular_state_file_with_hook, snapshot_private_state_file,
        store_new_atomic_idempotent_evidence_with_hook,
    };
    #[cfg(target_os = "macos")]
    use super::{validate_private_evidence_directory, validate_private_regular_file};

    type FileSystemSnapshot = Vec<(PathBuf, u32, Option<Vec<u8>>)>;

    #[derive(Debug, Default)]
    struct FixtureDecoder {
        receipts: BTreeMap<Vec<u8>, ReceiptRetentionMetadata>,
        evidence: BTreeMap<Vec<u8>, EvidenceRetentionMetadata>,
    }

    impl EvidenceStateMetadataDecoder for FixtureDecoder {
        fn decode_receipt(
            &self,
            _version: EvidenceStateVersion,
            bytes: &[u8],
        ) -> Result<ReceiptRetentionMetadata, EvidenceStateDecodeError> {
            if bytes == b"future" {
                return Err(EvidenceStateDecodeError::FutureSchema);
            }
            self.receipts
                .get(bytes)
                .cloned()
                .ok_or(EvidenceStateDecodeError::Malformed)
        }

        fn decode_evidence(
            &self,
            _version: EvidenceStateVersion,
            bytes: &[u8],
        ) -> Result<EvidenceRetentionMetadata, EvidenceStateDecodeError> {
            if bytes == b"future" {
                return Err(EvidenceStateDecodeError::FutureSchema);
            }
            self.evidence
                .get(bytes)
                .cloned()
                .ok_or(EvidenceStateDecodeError::Malformed)
        }
    }

    fn temporary_store() -> Result<(TempDir, AtomicStateStore), Box<dyn Error>> {
        let temporary = tempdir()?;
        let git_dir = temporary.path().join("git");
        fs::create_dir(&git_dir)?;
        let store = AtomicStateStore::new(GitStateLayout::new(&git_dir, &git_dir))?;
        Ok((temporary, store))
    }

    fn object_name(value: u64) -> Result<EvidenceStateObjectName, Box<dyn Error>> {
        Ok(EvidenceStateObjectName::new(format!("{value:064x}"))?)
    }

    fn receipt_state_key(
        version: EvidenceStateVersion,
        object_name: &EvidenceStateObjectName,
    ) -> String {
        format!(
            "receipts/v{}/{}.json",
            version.major(),
            object_name.as_str()
        )
    }

    fn evidence_state_key(
        version: EvidenceStateVersion,
        object_name: &EvidenceStateObjectName,
    ) -> String {
        format!(
            "evidence/v{}/{}.json",
            version.major(),
            object_name.as_str()
        )
    }

    fn log_state_key(object_name: &EvidenceStateObjectName) -> String {
        format!("logs/v1/{}.log", object_name.as_str())
    }

    fn store_immutable_fixture(
        store: &AtomicStateStore,
        key: &str,
        bytes: &[u8],
    ) -> Result<(), StateError> {
        let relative = validate_state_key(key)?;
        store.store_new_atomic_inner(&relative, bytes)?;
        #[cfg(windows)]
        super::super::windows::set_owner_only_path(
            &store.layout.worktree_dir().join(&relative),
            super::super::windows_acl_policy::PrivateWindowsObjectKind::File,
        )?;
        Ok(())
    }

    fn load_immutable_fixture(
        store: &AtomicStateStore,
        key: &str,
    ) -> Result<Option<Vec<u8>>, StateError> {
        let relative = validate_state_key(key)?;
        store.load_inner(&relative)
    }

    #[cfg(unix)]
    fn list_immutable_fixture(
        store: &AtomicStateStore,
        directory: &str,
        max_entries: usize,
    ) -> Result<Vec<String>, StateError> {
        let relative = validate_state_key(directory)?;
        store.list_regular_keys_bounded_inner(directory, &relative, max_entries)
    }

    fn store_fixture_log(
        store: &AtomicStateStore,
        bytes: &[u8],
    ) -> Result<(EvidenceStateObjectName, String, u64), Box<dyn Error>> {
        let object_name = EvidenceStateObjectName::new(log_content_address(bytes))?;
        let key = log_state_key(&object_name);
        store_immutable_fixture(store, &key, bytes)?;
        Ok((object_name, key, bytes.len() as u64))
    }

    #[test]
    fn log_content_address_has_a_fixed_golden_vector_and_covers_complete_bytes() {
        assert_eq!(
            log_content_address(b"golden log\n"),
            "baaff6c6c62c823b372c16ddf3e29e8da2195fb01d30ff8117d0a8278b6a18a9"
        );
        assert_ne!(
            log_content_address(b"redacted output\n"),
            log_content_address(b"redacted output")
        );
    }

    fn write_private_test_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
        fs::write(path, bytes)?;
        set_private_test_file_mode(path)
    }

    #[cfg(unix)]
    fn set_private_test_directory_mode(path: &Path) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
    }

    #[cfg(unix)]
    fn set_private_test_file_mode(path: &Path) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
    }

    #[cfg(windows)]
    fn set_private_test_file_mode(path: &Path) -> io::Result<()> {
        super::super::windows::set_owner_only_path(
            path,
            super::super::windows_acl_policy::PrivateWindowsObjectKind::File,
        )
        .map_err(StateError::into_io_error)
    }

    #[cfg(not(any(unix, windows)))]
    fn set_private_test_file_mode(_path: &Path) -> io::Result<()> {
        Ok(())
    }

    fn store_fixture_receipt(
        store: &AtomicStateStore,
        decoder: &mut FixtureDecoder,
        version: EvidenceStateVersion,
        object_name: EvidenceStateObjectName,
        started_at: EvidenceRetentionTime,
        log_references: Vec<EvidenceStateObjectName>,
    ) -> Result<(String, u64), Box<dyn Error>> {
        let key = receipt_state_key(version, &object_name);
        let bytes = format!("receipt-v{}-{}", version.major(), object_name.as_str()).into_bytes();
        store_immutable_fixture(store, &key, &bytes)?;
        decoder.receipts.insert(
            bytes.clone(),
            ReceiptRetentionMetadata::new(object_name, started_at, log_references),
        );
        Ok((key, bytes.len() as u64))
    }

    fn store_fixture_evidence(
        store: &AtomicStateStore,
        decoder: &mut FixtureDecoder,
        version: EvidenceStateVersion,
        object_name: EvidenceStateObjectName,
        created_at: EvidenceRetentionTime,
        receipt_references: Vec<ReceiptStateReference>,
        log_references: Vec<EvidenceStateObjectName>,
    ) -> Result<(String, u64), Box<dyn Error>> {
        let key = evidence_state_key(version, &object_name);
        let bytes = format!("evidence-v{}-{}", version.major(), object_name.as_str()).into_bytes();
        store_immutable_fixture(store, &key, &bytes)?;
        decoder.evidence.insert(
            bytes.clone(),
            EvidenceRetentionMetadata::new(
                object_name,
                created_at,
                receipt_references,
                log_references,
            ),
        );
        Ok((key, bytes.len() as u64))
    }

    #[test]
    fn utc_rfc3339_conversion_is_strict_and_round_trips() -> Result<(), Box<dyn Error>> {
        let cases = [
            ("1970-01-01T00:00:00Z", "1970-01-01T00:00:00Z"),
            ("1972-02-29T00:00:00Z", "1972-02-29T00:00:00Z"),
            (
                "2000-02-29T23:59:59.123456789Z",
                "2000-02-29T23:59:59.123456789Z",
            ),
            ("2026-07-27T08:09:10.120000000Z", "2026-07-27T08:09:10.12Z"),
            (
                "9999-12-31T23:59:59.999999999Z",
                "9999-12-31T23:59:59.999999999Z",
            ),
        ];
        for (input, canonical) in cases {
            let parsed = parse_utc_rfc3339(input)?;
            assert_eq!(format_utc_rfc3339(parsed)?, canonical);
            assert_eq!(parse_utc_rfc3339(canonical)?, parsed);
        }

        for invalid in [
            "",
            "2026-07-27 08:09:10Z",
            "2026-07-27T08:09:10z",
            "2026-07-27T08:09:10+00:00",
            "2026-07-27T08:09:10. Z",
            "2026-07-27T08:09:10.Z",
            "2026-07-27T08:09:10.1234567890Z",
            "2023-02-29T08:09:10Z",
            "2100-02-29T08:09:10Z",
            "2200-02-29T08:09:10Z",
            "2300-02-29T08:09:10Z",
            "2024-13-01T08:09:10Z",
            "2024-01-00T08:09:10Z",
            "2024-01-01T24:00:00Z",
            "2024-01-01T00:60:00Z",
            "2024-01-01T00:00:60Z",
        ] {
            assert_eq!(parse_utc_rfc3339(invalid), Err(UtcTimestampError::Invalid));
        }
        for unsupported in [
            "0000-01-01T00:00:00Z",
            "1900-02-28T00:00:00Z",
            "1969-12-31T23:59:59.999999999Z",
        ] {
            assert_eq!(
                parse_utc_rfc3339(unsupported),
                Err(UtcTimestampError::OutOfRange)
            );
        }
        for supported_leap_day in ["2000-02-29T00:00:00Z", "2400-02-29T00:00:00Z"] {
            let parsed = parse_utc_rfc3339(supported_leap_day)?;
            assert_eq!(format_utc_rfc3339(parsed)?, supported_leap_day);
        }
        Ok(())
    }

    #[test]
    fn generic_access_rejects_all_reserved_state_paths() -> Result<(), Box<dyn Error>> {
        let (_temporary, store) = temporary_store()?;
        for key in [
            "lock".to_owned(),
            "LOCK".to_owned(),
            "Lock/child".to_owned(),
            format!("receipts/v2/{}.json", object_name(1)?.as_str()),
            format!("evidence/v2/{}.json", object_name(2)?.as_str()),
            format!("logs/v1/{}.log", object_name(3)?.as_str()),
            format!("Receipts/v2/{}.json", object_name(4)?.as_str()),
            format!("EVIDENCE/v2/{}.json", object_name(5)?.as_str()),
            format!("LoGs/v1/{}.log", object_name(6)?.as_str()),
        ] {
            assert!(matches!(
                store.store_atomic(&key, b"bytes"),
                Err(StateError::ReservedStatePath { .. })
            ));
            assert!(matches!(
                store.store_new_atomic(&key, b"bytes"),
                Err(StateError::ReservedStatePath { .. })
            ));
            assert!(matches!(
                store.load(&key),
                Err(StateError::ReservedStatePath { .. })
            ));
            assert!(matches!(
                store.load_bounded(&key, 1_024),
                Err(StateError::ReservedStatePath { .. })
            ));
            assert!(matches!(
                store.list_regular_keys_bounded(&key, 10),
                Err(StateError::ReservedStatePath { .. })
            ));
        }
        Ok(())
    }

    #[test]
    fn generic_readers_reject_all_reserved_evidence_namespaces() -> Result<(), Box<dyn Error>> {
        let (_temporary, store) = temporary_store()?;
        let object = object_name(7)?;
        let key = format!("receipts/v2/{}.json", object.as_str());
        store_immutable_fixture(&store, &key, b"receipt")?;

        for alias in [key, format!("Receipts/v2/{}.json", object.as_str())] {
            assert!(matches!(
                store.load(&alias),
                Err(StateError::ReservedStatePath { .. })
            ));
            assert!(matches!(
                store.load_bounded(&alias, 1_024),
                Err(StateError::ReservedStatePath { .. })
            ));
        }
        assert!(matches!(
            store.list_regular_keys_bounded("receipts/v2", 10),
            Err(StateError::ReservedStatePath { .. })
        ));
        Ok(())
    }

    #[test]
    fn state_keys_reject_win32_trailing_dot_aliases_in_every_segment() -> Result<(), Box<dyn Error>>
    {
        let (_temporary, store) = temporary_store()?;

        for key in ["lock.", "Receipts.", "portable./file", "portable/file."] {
            assert!(matches!(
                store.load(key),
                Err(StateError::UnsafeKey { ref reason, .. })
                    if reason.contains("Win32 aliases")
            ));
            assert!(matches!(
                store.store_atomic(key, b"unsafe"),
                Err(StateError::UnsafeKey { ref reason, .. })
                    if reason.contains("Win32 aliases")
            ));
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn case_insensitive_generic_lock_alias_cannot_replace_the_held_lock()
    -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::MetadataExt as _;

        let (_temporary, store) = temporary_store()?;
        let _lock = store.try_lock()?;
        let path = store.layout().lock_file();
        let before_metadata = fs::symlink_metadata(&path)?;
        let before_bytes = fs::read(&path)?;

        assert!(matches!(
            store.store_atomic("LOCK", b"replacement"),
            Err(StateError::ReservedStatePath { .. })
        ));
        assert!(matches!(
            store.store_new_atomic("LOCK", b"replacement"),
            Err(StateError::ReservedStatePath { .. })
        ));
        assert!(matches!(
            store.load("LOCK"),
            Err(StateError::ReservedStatePath { .. })
        ));
        assert!(matches!(
            store.load_bounded("LOCK", 1_024),
            Err(StateError::ReservedStatePath { .. })
        ));
        assert!(matches!(
            store.list_regular_keys_bounded("LOCK", 10),
            Err(StateError::ReservedStatePath { .. })
        ));

        let after_metadata = fs::symlink_metadata(&path)?;
        assert_eq!(before_metadata.dev(), after_metadata.dev());
        assert_eq!(before_metadata.ino(), after_metadata.ino());
        assert_eq!(fs::read(path)?, before_bytes);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn idempotent_collision_read_never_follows_a_raced_external_symlink()
    -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::symlink;

        let (temporary, store) = temporary_store()?;
        let key = format!("logs/v1/{}.log", object_name(8)?.as_str());
        let relative = validate_state_key(&key)?;
        let expected = b"same-length-secret";
        store_immutable_fixture(&store, &key, expected)?;
        let outside = temporary.path().join("outside-secret");
        fs::write(&outside, expected)?;
        let displaced = temporary.path().join("displaced-original");

        let error = match store_new_atomic_idempotent_evidence_with_hook(
            &store,
            &key,
            &relative,
            expected,
            |path| {
                fs::rename(path, &displaced)?;
                symlink(&outside, path)
            },
        ) {
            Err(error) => error,
            Ok(()) => {
                return Err(io::Error::other(
                    "a raced symlink was accepted during an idempotent collision read",
                )
                .into());
            }
        };

        assert!(matches!(
            error,
            StateError::Io {
                operation: "open immutable state object without following links",
                ..
            }
        ));
        assert!(
            fs::symlink_metadata(store.layout().worktree_dir().join(&key))?
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read(outside)?, expected);
        Ok(())
    }

    #[test]
    fn immutable_state_stream_is_bounded_by_the_charged_snapshot_size() -> Result<(), Box<dyn Error>>
    {
        use std::io::Write as _;

        let (_temporary, store) = temporary_store()?;
        let key = "mutable/growing.log";
        store.store_new_atomic(key, b"initial")?;
        let path = store.layout().worktree_dir().join(key);
        let metadata = fs::symlink_metadata(&path)?;

        let result =
            stream_opened_private_state_file_with_hook(key, &path, &metadata, true, |path| {
                let mut appender = std::fs::OpenOptions::new().append(true).open(path)?;
                appender.write_all(b"-growth")
            });
        let Err(error) = result else {
            return Err(
                io::Error::other("growth beyond the charged snapshot did not fail closed").into(),
            );
        };

        assert!(matches!(error, StateError::StateChanged { .. }));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn evidence_mutation_rejects_a_replaced_lock_inode() -> Result<(), Box<dyn Error>> {
        let (temporary, store) = temporary_store()?;
        let lock = store.try_lock()?;
        let lock_path = store.layout().lock_file();
        fs::rename(&lock_path, temporary.path().join("held-lock"))?;
        write_private_test_file(&lock_path, b"replacement")?;
        let bytes = b"redacted log";
        let object = EvidenceStateObjectName::new(log_content_address(bytes))?;

        assert!(matches!(
            store.persist_current_log(
                &lock,
                SystemTime::UNIX_EPOCH,
                &object,
                bytes,
                1_024,
                &FixtureDecoder::default(),
            ),
            Err(StateError::WrongLock { .. })
        ));
        assert!(
            !store
                .layout()
                .worktree_dir()
                .join(log_state_key(&object))
                .exists()
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn read_only_fails_closed_and_locked_gc_recovers_a_quarantined_object()
    -> Result<(), Box<dyn Error>> {
        let (temporary, store) = temporary_store()?;
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let mut decoder = FixtureDecoder::default();
        let log_bytes = b"recoverable log";
        let (log_name, log_key, _) = store_fixture_log(&store, log_bytes)?;
        store_fixture_receipt(
            &store,
            &mut decoder,
            EvidenceStateVersion::V2,
            object_name(8)?,
            EvidenceRetentionTime::Current(now.into()),
            vec![log_name.clone()],
        )?;
        let log_path = store.layout().worktree_dir().join(&log_key);
        let version_directory = log_path
            .parent()
            .ok_or_else(|| io::Error::other("log fixture has no parent"))?;
        let quarantine =
            version_directory.join(format!(".forge-gc-quarantine-{}", log_name.as_str()));
        fs::create_dir(&quarantine)?;
        set_private_test_directory_mode(&quarantine)?;
        fs::rename(&log_path, quarantine.join("object"))?;
        let before = filesystem_snapshot(temporary.path())?;

        let read_error = match store.visit_evidence_state_snapshot(1_024, &decoder, |_| Ok(())) {
            Err(error) => error,
            Ok(()) => {
                return Err(
                    io::Error::other("read-only scan accepted recoverable GC residue").into(),
                );
            }
        };
        assert!(matches!(
            read_error,
            StateError::InvalidLayout { ref reason, .. }
                if reason.contains("held-lock recovery")
        ));
        assert_eq!(filesystem_snapshot(temporary.path())?, before);

        let lock = store.try_lock()?;
        store.collect_evidence_garbage(&lock, now, &decoder)?;
        assert!(!quarantine.exists());
        assert_eq!(fs::read(log_path)?, log_bytes);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn locked_gc_removes_an_empty_crash_quarantine_without_touching_the_object()
    -> Result<(), Box<dyn Error>> {
        let (_temporary, store) = temporary_store()?;
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let mut decoder = FixtureDecoder::default();
        let log_bytes = b"log retained across empty quarantine recovery";
        let (log_name, log_key, _) = store_fixture_log(&store, log_bytes)?;
        store_fixture_receipt(
            &store,
            &mut decoder,
            EvidenceStateVersion::V2,
            object_name(9)?,
            EvidenceRetentionTime::Current(now.into()),
            vec![log_name.clone()],
        )?;
        let log_path = store.layout().worktree_dir().join(&log_key);
        let parent = log_path
            .parent()
            .ok_or_else(|| io::Error::other("log fixture has no parent"))?;
        let quarantine = parent.join(format!("{GC_QUARANTINE_PREFIX}{}", log_name.as_str()));
        fs::create_dir(&quarantine)?;
        set_private_test_directory_mode(&quarantine)?;

        let lock = store.try_lock()?;
        store.collect_evidence_garbage(&lock, now, &decoder)?;

        assert!(!quarantine.exists());
        assert_eq!(fs::read(log_path)?, log_bytes);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn locked_gc_finishes_a_durable_restore_link_after_crash() -> Result<(), Box<dyn Error>> {
        let (_temporary, store) = temporary_store()?;
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let mut decoder = FixtureDecoder::default();
        let log_bytes = b"log with both durable recovery links";
        let (log_name, log_key, _) = store_fixture_log(&store, log_bytes)?;
        store_fixture_receipt(
            &store,
            &mut decoder,
            EvidenceStateVersion::V2,
            object_name(10)?,
            EvidenceRetentionTime::Current(now.into()),
            vec![log_name.clone()],
        )?;
        let log_path = store.layout().worktree_dir().join(&log_key);
        let parent = log_path
            .parent()
            .ok_or_else(|| io::Error::other("log fixture has no parent"))?;
        let quarantine = parent.join(format!("{GC_QUARANTINE_PREFIX}{}", log_name.as_str()));
        fs::create_dir(&quarantine)?;
        set_private_test_directory_mode(&quarantine)?;
        fs::hard_link(&log_path, quarantine.join(GC_QUARANTINE_OBJECT))?;

        let lock = store.try_lock()?;
        store.collect_evidence_garbage(&lock, now, &decoder)?;

        assert!(!quarantine.exists());
        assert_eq!(fs::read(log_path)?, log_bytes);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn locked_gc_fails_closed_on_conflicting_recovery_objects() -> Result<(), Box<dyn Error>> {
        let (temporary, store) = temporary_store()?;
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        let log_bytes = b"original recovery object";
        let (log_name, log_key, _) = store_fixture_log(&store, log_bytes)?;
        let log_path = store.layout().worktree_dir().join(&log_key);
        let parent = log_path
            .parent()
            .ok_or_else(|| io::Error::other("log fixture has no parent"))?;
        let quarantine = parent.join(format!("{GC_QUARANTINE_PREFIX}{}", log_name.as_str()));
        fs::create_dir(&quarantine)?;
        set_private_test_directory_mode(&quarantine)?;
        write_private_test_file(
            &quarantine.join(GC_QUARANTINE_OBJECT),
            b"conflicting recovery object",
        )?;
        let lock = store.try_lock()?;
        let before = filesystem_snapshot(temporary.path())?;

        let error = match store.collect_evidence_garbage(&lock, now, &FixtureDecoder::default()) {
            Err(error) => error,
            Ok(_) => {
                return Err(io::Error::other("conflicting recovery paths were accepted").into());
            }
        };

        assert!(matches!(
            error,
            StateError::InvalidLayout { ref reason, .. }
                if reason.contains("conflicting original")
        ));
        assert_eq!(filesystem_snapshot(temporary.path())?, before);
        assert_eq!(fs::read(log_path)?, log_bytes);
        assert_eq!(
            fs::read(quarantine.join(GC_QUARANTINE_OBJECT))?,
            b"conflicting recovery object"
        );
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn evidence_open_rejects_extended_acl_even_with_private_mode() -> Result<(), Box<dyn Error>> {
        let temporary = tempdir()?;
        let git_dir = temporary.path().join("git");
        fs::create_dir(&git_dir)?;
        let layout = GitStateLayout::new(&git_dir, &git_dir);
        AtomicStateStore::new_evidence(layout.clone())?;
        let status = Command::new("/bin/chmod")
            .arg("+a")
            .arg("everyone allow read")
            .arg(layout.worktree_dir())
            .status()?;
        if !status.success() {
            return Err(io::Error::other("failed to install macOS ACL fixture").into());
        }

        assert!(matches!(
            AtomicStateStore::open_existing_evidence_read_only(layout),
            Err(StateError::InvalidLayout { ref reason, .. })
                if reason.contains("extended ACL")
        ));
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn evidence_creation_clears_inherited_acl_before_typed_paths_are_used()
    -> Result<(), Box<dyn Error>> {
        let temporary = tempdir()?;
        let git_dir = temporary.path().join("git");
        fs::create_dir(&git_dir)?;
        let status = Command::new("/bin/chmod")
            .arg("+a")
            .arg("everyone allow read,file_inherit,directory_inherit")
            .arg(&git_dir)
            .status()?;
        if !status.success() {
            return Err(io::Error::other("failed to install inheritable macOS ACL fixture").into());
        }

        let layout = GitStateLayout::new(&git_dir, &git_dir);
        let store = AtomicStateStore::new_evidence(layout.clone())?;
        let lock = store.try_lock()?;
        let bytes = b"inherited ACL must not reach this redacted log";
        let object = EvidenceStateObjectName::new(log_content_address(bytes))?;
        store.persist_current_log(
            &lock,
            SystemTime::UNIX_EPOCH,
            &object,
            bytes,
            1_024,
            &FixtureDecoder::default(),
        )?;

        for directory in [
            layout.worktree_dir().to_path_buf(),
            layout.worktree_dir().join("logs"),
            layout.worktree_dir().join("logs/v1"),
        ] {
            let metadata = fs::symlink_metadata(&directory)?;
            validate_private_evidence_directory(&directory, &metadata)?;
        }
        for file in [
            layout.lock_file(),
            layout.worktree_dir().join(log_state_key(&object)),
        ] {
            let metadata = fs::symlink_metadata(&file)?;
            validate_private_regular_file(&file, &metadata)?;
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn evidence_read_rejects_an_extended_acl_on_a_typed_file() -> Result<(), Box<dyn Error>> {
        let temporary = tempdir()?;
        let git_dir = temporary.path().join("git");
        fs::create_dir(&git_dir)?;
        let layout = GitStateLayout::new(&git_dir, &git_dir);
        let store = AtomicStateStore::new_evidence(layout.clone())?;
        let bytes = b"typed file ACL fixture";
        let object = EvidenceStateObjectName::new(log_content_address(bytes))?;
        let lock = store.try_lock()?;
        store.persist_current_log(
            &lock,
            SystemTime::UNIX_EPOCH,
            &object,
            bytes,
            1_024,
            &FixtureDecoder::default(),
        )?;
        drop(lock);
        let path = layout.worktree_dir().join(log_state_key(&object));
        let status = Command::new("/bin/chmod")
            .arg("+a")
            .arg("everyone allow read")
            .arg(&path)
            .status()?;
        if !status.success() {
            return Err(io::Error::other("failed to install typed-file macOS ACL fixture").into());
        }

        let error = match store.visit_evidence_state_snapshot(
            1_024,
            &FixtureDecoder::default(),
            |_| Ok(()),
        ) {
            Err(error) => error,
            Ok(()) => {
                return Err(io::Error::other("typed evidence file ACL was accepted").into());
            }
        };
        assert!(matches!(
            error,
            StateError::InvalidLayout { ref reason, .. }
                if reason.contains("extended ACL")
        ));
        Ok(())
    }

    #[cfg(not(any(unix, windows)))]
    #[test]
    fn evidence_entrypoints_fail_closed_without_acl_capability_and_create_nothing()
    -> Result<(), Box<dyn Error>> {
        let temporary = tempdir()?;
        let git_dir = temporary.path().join("git");
        let common_dir = temporary.path().join("common");
        fs::create_dir(&git_dir)?;
        fs::create_dir(&common_dir)?;
        let layout = GitStateLayout::new(&git_dir, &common_dir);
        let before = filesystem_snapshot(temporary.path())?;

        assert!(matches!(
            AtomicStateStore::new_evidence(layout.clone()),
            Err(StateError::EvidenceStateMutationUnsupported { .. })
        ));
        assert!(matches!(
            AtomicStateStore::open_existing_evidence_read_only(layout.clone()),
            Err(StateError::EvidenceStateReadUnsupported { .. })
        ));
        assert_eq!(filesystem_snapshot(temporary.path())?, before);
        assert!(!layout.worktree_dir().exists());
        assert!(!layout.shared_cache_dir().exists());
        assert!(!layout.lock_file().exists());
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn windows_typed_evidence_state_round_trips_an_idempotent_immutable_log()
    -> Result<(), Box<dyn Error>> {
        let temporary = tempdir()?;
        let git_dir = temporary.path().join("git");
        let common_dir = temporary.path().join("common");
        fs::create_dir(&git_dir)?;
        fs::create_dir(&common_dir)?;
        let layout = GitStateLayout::new(&git_dir, &common_dir);
        let store = AtomicStateStore::new_evidence(layout.clone())?;
        let lock = store.try_lock()?;
        let bytes = b"already-redacted Windows log";
        let object_name = EvidenceStateObjectName::new(log_content_address(bytes))?;
        store.persist_current_log(
            &lock,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000),
            &object_name,
            bytes,
            1_024,
            &FixtureDecoder::default(),
        )?;
        store.persist_current_log(
            &lock,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_001),
            &object_name,
            bytes,
            1_024,
            &FixtureDecoder::default(),
        )?;
        drop(lock);

        let read_only = AtomicStateStore::open_existing_evidence_read_only(layout.clone())?
            .ok_or_else(|| io::Error::other("Windows evidence state disappeared"))?;
        let mut visited = Vec::new();
        read_only.visit_evidence_state_snapshot(
            1_024,
            &FixtureDecoder::default(),
            |mut snapshot| {
                let mut contents = Vec::new();
                snapshot.bytes().read_to_end(&mut contents)?;
                visited.push((snapshot.kind(), snapshot.object_name().clone(), contents));
                Ok(())
            },
        )?;
        assert_eq!(
            visited,
            vec![(EvidenceStateObjectKind::LogV1, object_name, bytes.to_vec())]
        );
        assert!(!layout.shared_cache_dir().exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn evidence_store_creation_does_not_create_the_shared_cache_or_lock()
    -> Result<(), Box<dyn Error>> {
        let temporary = tempdir()?;
        let git_dir = temporary.path().join("git");
        let common_dir = temporary.path().join("common");
        fs::create_dir(&git_dir)?;
        fs::create_dir(&common_dir)?;
        let layout = GitStateLayout::new(&git_dir, &common_dir);

        let store = AtomicStateStore::new_evidence(layout.clone())?;

        assert_eq!(store.layout(), &layout);
        assert!(layout.worktree_dir().is_dir());
        assert!(!layout.shared_cache_dir().exists());
        assert!(!layout.lock_file().exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn typed_persistence_keeps_log_receipt_evidence_chain_and_read_only_visit_is_stable()
    -> Result<(), Box<dyn Error>> {
        let (_temporary, store) = temporary_store()?;
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(20 * 365 * 24 * 60 * 60);
        let mut decoder = FixtureDecoder::default();
        let log_bytes = b"complete redacted log";
        let log_name = EvidenceStateObjectName::new(log_content_address(log_bytes))?;
        let receipt_name = object_name(200_001)?;
        let receipt_bytes = b"typed receipt".to_vec();
        decoder.receipts.insert(
            receipt_bytes.clone(),
            ReceiptRetentionMetadata::new(
                receipt_name.clone(),
                EvidenceRetentionTime::Current(now.into()),
                [log_name.clone()],
            ),
        );
        let evidence_name = object_name(200_002)?;
        let evidence_bytes = b"typed evidence".to_vec();
        decoder.evidence.insert(
            evidence_bytes.clone(),
            EvidenceRetentionMetadata::new(
                evidence_name.clone(),
                EvidenceRetentionTime::Current(now.into()),
                [ReceiptStateReference::new(
                    EvidenceStateVersion::V2,
                    receipt_name.clone(),
                )],
                [log_name.clone()],
            ),
        );
        let lock = store.try_lock()?;

        store.persist_current_log(&lock, now, &log_name, log_bytes, 1_024, &decoder)?;
        assert!(load_immutable_fixture(&store, &log_state_key(&log_name))?.is_some());
        store.persist_current_receipt(&lock, now, &receipt_name, &receipt_bytes, &decoder)?;
        store.persist_current_evidence(&lock, now, &evidence_name, &evidence_bytes, &decoder)?;

        let before = filesystem_snapshot(store.layout().worktree_dir())?;
        let mut visited = Vec::new();
        store.visit_evidence_state_snapshot(1_024, &decoder, |mut object| {
            let mut bytes = Vec::new();
            object.bytes().read_to_end(&mut bytes)?;
            visited.push((object.kind(), object.key().to_owned(), bytes));
            Ok(())
        })?;
        assert_eq!(
            visited,
            [
                (
                    EvidenceStateObjectKind::Receipt(EvidenceStateVersion::V2),
                    receipt_state_key(EvidenceStateVersion::V2, &receipt_name),
                    receipt_bytes,
                ),
                (
                    EvidenceStateObjectKind::Evidence(EvidenceStateVersion::V2),
                    evidence_state_key(EvidenceStateVersion::V2, &evidence_name),
                    evidence_bytes,
                ),
                (
                    EvidenceStateObjectKind::LogV1,
                    log_state_key(&log_name),
                    log_bytes.to_vec(),
                ),
            ]
        );
        assert_eq!(filesystem_snapshot(store.layout().worktree_dir())?, before);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn typed_persistence_rejects_wrong_lock_and_missing_reference_before_writing()
    -> Result<(), Box<dyn Error>> {
        let (_temporary, store) = temporary_store()?;
        let (_other_temporary, other_store) = temporary_store()?;
        let wrong_lock = other_store.try_lock()?;
        let now = SystemTime::UNIX_EPOCH;
        let receipt_name = object_name(201_001)?;
        let receipt_bytes = b"wrong lock receipt".to_vec();
        let mut decoder = FixtureDecoder::default();
        decoder.receipts.insert(
            receipt_bytes.clone(),
            ReceiptRetentionMetadata::new(
                receipt_name.clone(),
                EvidenceRetentionTime::Current(now.into()),
                [],
            ),
        );
        assert!(matches!(
            store.persist_current_receipt(
                &wrong_lock,
                now,
                &receipt_name,
                &receipt_bytes,
                &decoder,
            ),
            Err(StateError::WrongLock { .. })
        ));
        assert_eq!(
            load_immutable_fixture(
                &store,
                &receipt_state_key(EvidenceStateVersion::V2, &receipt_name),
            )?,
            None
        );
        drop(wrong_lock);

        let evidence_name = object_name(201_002)?;
        let evidence_bytes = b"missing reference evidence".to_vec();
        decoder.evidence.insert(
            evidence_bytes.clone(),
            EvidenceRetentionMetadata::new(
                evidence_name.clone(),
                EvidenceRetentionTime::Current(now.into()),
                [ReceiptStateReference::new(
                    EvidenceStateVersion::V2,
                    object_name(201_003)?,
                )],
                [],
            ),
        );
        let lock = store.try_lock()?;
        assert!(matches!(
            store.persist_current_evidence(&lock, now, &evidence_name, &evidence_bytes, &decoder,),
            Err(StateError::MissingReference { .. })
        ));
        assert_eq!(
            load_immutable_fixture(
                &store,
                &evidence_state_key(EvidenceStateVersion::V2, &evidence_name),
            )?,
            None
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn typed_write_at_exact_log_cap_fails_without_prewrite_deletion() -> Result<(), Box<dyn Error>>
    {
        let (_temporary, store) = temporary_store()?;
        let (first_name, first_key, _) = store_fixture_log(&store, &0_u64.to_le_bytes())?;
        let log_directory = store.layout().worktree_dir().join("logs/v1");
        for index in 1_u64..EVIDENCE_GC_MAX_LOGS as u64 {
            let bytes = index.to_le_bytes();
            let name = EvidenceStateObjectName::new(log_content_address(&bytes))?;
            assert_ne!(name, first_name);
            write_private_test_file(
                &log_directory.join(format!("{}.log", name.as_str())),
                &bytes,
            )?;
        }
        let pending_bytes = b"pending capped log";
        let pending_name = EvidenceStateObjectName::new(log_content_address(pending_bytes))?;
        let pending_key = log_state_key(&pending_name);
        let lock = store.try_lock()?;

        assert!(matches!(
            store.persist_current_log(
                &lock,
                SystemTime::UNIX_EPOCH,
                &pending_name,
                pending_bytes,
                1_024,
                &FixtureDecoder::default(),
            ),
            Err(StateError::RetainedObjectCountExceeded {
                ref directory,
                retained_entries,
                max_entries: EVIDENCE_GC_MAX_LOGS,
            }) if directory == "logs" && retained_entries == EVIDENCE_GC_MAX_LOGS + 1
        ));
        assert_eq!(load_immutable_fixture(&store, &pending_key)?, None);
        assert!(load_immutable_fixture(&store, &first_key)?.is_some());
        assert_eq!(
            list_immutable_fixture(&store, "logs/v1", EVIDENCE_GC_MAX_LOGS)?.len(),
            EVIDENCE_GC_MAX_LOGS
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn write_failure_after_preflight_does_not_delete_expired_objects() -> Result<(), Box<dyn Error>>
    {
        use std::cell::Cell;

        struct RacedTargetDecoder<'a> {
            inner: &'a FixtureDecoder,
            pending_bytes: &'a [u8],
            target: &'a Path,
            raced: Cell<bool>,
        }

        impl EvidenceStateMetadataDecoder for RacedTargetDecoder<'_> {
            fn decode_receipt(
                &self,
                version: EvidenceStateVersion,
                bytes: &[u8],
            ) -> Result<ReceiptRetentionMetadata, EvidenceStateDecodeError> {
                if bytes != self.pending_bytes && !self.raced.replace(true) {
                    fs::create_dir(self.target).map_err(|_| EvidenceStateDecodeError::Malformed)?;
                }
                self.inner.decode_receipt(version, bytes)
            }

            fn decode_evidence(
                &self,
                version: EvidenceStateVersion,
                bytes: &[u8],
            ) -> Result<EvidenceRetentionMetadata, EvidenceStateDecodeError> {
                self.inner.decode_evidence(version, bytes)
            }
        }

        let (_temporary, store) = temporary_store()?;
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(20 * 365 * 24 * 60 * 60);
        let old = now - EVIDENCE_GC_KEEP_AGE - Duration::from_secs(1_000);
        let mut decoder = FixtureDecoder::default();
        let mut receipt_keys = Vec::new();
        for index in 0_u64..201 {
            let (key, _) = store_fixture_receipt(
                &store,
                &mut decoder,
                EvidenceStateVersion::V2,
                object_name(210_000 + index)?,
                EvidenceRetentionTime::Current((old + Duration::from_secs(index)).into()),
                Vec::new(),
            )?;
            receipt_keys.push(key);
        }
        let pending_name = object_name(211_000)?;
        let pending_key = receipt_state_key(EvidenceStateVersion::V2, &pending_name);
        let pending_bytes = b"raced pending receipt".to_vec();
        decoder.receipts.insert(
            pending_bytes.clone(),
            ReceiptRetentionMetadata::new(
                pending_name.clone(),
                EvidenceRetentionTime::Current(now.into()),
                [],
            ),
        );
        let target = store.layout().worktree_dir().join(&pending_key);
        let raced = RacedTargetDecoder {
            inner: &decoder,
            pending_bytes: &pending_bytes,
            target: &target,
            raced: Cell::new(false),
        };
        let lock = store.try_lock()?;

        assert!(
            store
                .persist_current_receipt(&lock, now, &pending_name, &pending_bytes, &raced)
                .is_err()
        );
        assert!(raced.raced.get());
        assert!(target.is_dir());
        assert!(load_immutable_fixture(&store, &receipt_keys[0])?.is_some());
        assert!(load_immutable_fixture(&store, &receipt_keys[200])?.is_some());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn successful_receipt_write_is_visible_before_postwrite_gc() -> Result<(), Box<dyn Error>> {
        use std::cell::Cell;

        struct PendingVisibilityDecoder<'a> {
            inner: &'a FixtureDecoder,
            pending_bytes: &'a [u8],
            pending_path: &'a Path,
            saw_pending_during_existing_decode: Cell<bool>,
        }

        impl EvidenceStateMetadataDecoder for PendingVisibilityDecoder<'_> {
            fn decode_receipt(
                &self,
                version: EvidenceStateVersion,
                bytes: &[u8],
            ) -> Result<ReceiptRetentionMetadata, EvidenceStateDecodeError> {
                if bytes != self.pending_bytes && self.pending_path.is_file() {
                    self.saw_pending_during_existing_decode.set(true);
                }
                self.inner.decode_receipt(version, bytes)
            }

            fn decode_evidence(
                &self,
                version: EvidenceStateVersion,
                bytes: &[u8],
            ) -> Result<EvidenceRetentionMetadata, EvidenceStateDecodeError> {
                self.inner.decode_evidence(version, bytes)
            }
        }

        let (_temporary, store) = temporary_store()?;
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(20 * 365 * 24 * 60 * 60);
        let old = now - EVIDENCE_GC_KEEP_AGE - Duration::from_secs(1_000);
        let mut decoder = FixtureDecoder::default();
        let mut receipt_keys = Vec::new();
        for index in 0_u64..201 {
            let (key, _) = store_fixture_receipt(
                &store,
                &mut decoder,
                EvidenceStateVersion::V2,
                object_name(212_000 + index)?,
                EvidenceRetentionTime::Current((old + Duration::from_secs(index)).into()),
                Vec::new(),
            )?;
            receipt_keys.push(key);
        }
        let pending_name = object_name(213_000)?;
        let pending_key = receipt_state_key(EvidenceStateVersion::V2, &pending_name);
        let pending_bytes = b"successfully persisted receipt".to_vec();
        decoder.receipts.insert(
            pending_bytes.clone(),
            ReceiptRetentionMetadata::new(
                pending_name.clone(),
                EvidenceRetentionTime::Current(now.into()),
                [],
            ),
        );
        let pending_path = store.layout().worktree_dir().join(&pending_key);
        let observing = PendingVisibilityDecoder {
            inner: &decoder,
            pending_bytes: &pending_bytes,
            pending_path: &pending_path,
            saw_pending_during_existing_decode: Cell::new(false),
        };
        let lock = store.try_lock()?;

        let report =
            store.persist_current_receipt(&lock, now, &pending_name, &pending_bytes, &observing)?;

        assert!(observing.saw_pending_during_existing_decode.get());
        assert!(pending_path.is_file());
        assert!(report.deleted_receipts() >= 1);
        assert_eq!(load_immutable_fixture(&store, &receipt_keys[0])?, None);
        assert!(load_immutable_fixture(&store, &receipt_keys[200])?.is_some());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn garbage_collection_rejects_log_content_address_mismatch_before_deletion()
    -> Result<(), Box<dyn Error>> {
        let (temporary, store) = temporary_store()?;
        let key = log_state_key(&object_name(202_001)?);
        store_immutable_fixture(&store, &key, b"wrong content")?;
        let lock = store.try_lock()?;
        let before = filesystem_snapshot(temporary.path())?;

        assert!(matches!(
            store.collect_evidence_garbage(
                &lock,
                SystemTime::UNIX_EPOCH,
                &FixtureDecoder::default()
            ),
            Err(StateError::ObjectContentAddressMismatch { .. })
        ));
        assert_eq!(filesystem_snapshot(temporary.path())?, before);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn garbage_collection_partial_failure_preserves_reference_safe_delete_order()
    -> Result<(), Box<dyn Error>> {
        let (_temporary, store) = temporary_store()?;
        let mut decoder = FixtureDecoder::default();
        let (log_name, log_key, log_size) = store_fixture_log(&store, b"partial failure log")?;
        let receipt_name = object_name(203_001)?;
        let (receipt_key, receipt_size) = store_fixture_receipt(
            &store,
            &mut decoder,
            EvidenceStateVersion::V2,
            receipt_name.clone(),
            EvidenceRetentionTime::Current(SystemTime::UNIX_EPOCH.into()),
            [log_name.clone()].into(),
        )?;
        let (evidence_key, evidence_size) = store_fixture_evidence(
            &store,
            &mut decoder,
            EvidenceStateVersion::V2,
            object_name(203_002)?,
            EvidenceRetentionTime::Current(SystemTime::UNIX_EPOCH.into()),
            [ReceiptStateReference::new(
                EvidenceStateVersion::V2,
                receipt_name,
            )]
            .into(),
            [log_name].into(),
        )?;
        let deletion = |key: &str, size| -> Result<PlannedDeletion, StateError> {
            Ok(PlannedDeletion {
                key: key.to_owned(),
                size,
                snapshot: snapshot_private_state_file(&store, key)?,
            })
        };
        let plan = EvidenceGcPlan {
            delete_evidence: vec![deletion(&evidence_key, evidence_size)?],
            delete_receipts: vec![deletion(&receipt_key, receipt_size)?],
            delete_logs: vec![deletion(&log_key, log_size)?],
            reclaimed_bytes: evidence_size + receipt_size + log_size,
            retained_bytes: 0,
            projected_scan_bytes: evidence_size + receipt_size + log_size,
            projected_receipts: 1,
            projected_evidence: 1,
            projected_logs: 1,
        };
        preflight_deletions(&store, &plan)?;
        write_private_test_file(
            &store.layout().worktree_dir().join(&receipt_key),
            b"receipt changed after preflight",
        )?;

        assert!(matches!(
            apply_evidence_gc_plan(&store, &plan),
            Err(StateError::StateChanged { .. })
        ));
        assert_eq!(load_immutable_fixture(&store, &evidence_key)?, None);
        assert!(load_immutable_fixture(&store, &receipt_key)?.is_some());
        assert!(load_immutable_fixture(&store, &log_key)?.is_some());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn garbage_collection_quarantine_does_not_unlink_a_raced_replacement()
    -> Result<(), Box<dyn Error>> {
        let (temporary, store) = temporary_store()?;
        let original = b"planned-log";
        let replacement = b"changed-log";
        assert_eq!(original.len(), replacement.len());
        let (_, key, size) = store_fixture_log(&store, original)?;
        let object = PlannedDeletion {
            key: key.clone(),
            size,
            snapshot: snapshot_private_state_file(&store, &key)?,
        };
        let saved_original = temporary.path().join("saved-original.log");

        let result = remove_regular_state_file_with_hook(&store, &object, |path| {
            fs::rename(path, &saved_original)?;
            write_private_test_file(path, replacement)
        });

        assert!(matches!(result, Err(StateError::StateChanged { .. })));
        assert_eq!(
            load_immutable_fixture(&store, &key)?,
            Some(replacement.to_vec())
        );
        assert_eq!(fs::read(saved_original)?, original);
        assert_eq!(
            fs::read_dir(store.layout().worktree_dir().join("logs/v1"))?.count(),
            1
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn garbage_collection_quarantine_restores_a_raced_symlink_without_following_it()
    -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::symlink;

        let (temporary, store) = temporary_store()?;
        let original = b"planned symlink race";
        let (_, key, size) = store_fixture_log(&store, original)?;
        let object = PlannedDeletion {
            key: key.clone(),
            size,
            snapshot: snapshot_private_state_file(&store, &key)?,
        };
        let saved_original = temporary.path().join("saved-symlink-original.log");
        let outside = temporary.path().join("outside.log");
        fs::write(&outside, b"outside")?;
        let state_path = store.layout().worktree_dir().join(&key);

        let result = remove_regular_state_file_with_hook(&store, &object, |path| {
            fs::rename(path, &saved_original)?;
            symlink(&outside, path)
        });

        assert!(result.is_err());
        assert!(fs::symlink_metadata(&state_path)?.file_type().is_symlink());
        assert_eq!(fs::read_link(&state_path)?, outside);
        assert_eq!(fs::read(&outside)?, b"outside");
        assert_eq!(fs::read(saved_original)?, original);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn garbage_collection_quarantine_keeps_a_raced_directory_when_restore_is_impossible()
    -> Result<(), Box<dyn Error>> {
        let (temporary, store) = temporary_store()?;
        let original = b"planned directory race";
        let (_, key, size) = store_fixture_log(&store, original)?;
        let object = PlannedDeletion {
            key: key.clone(),
            size,
            snapshot: snapshot_private_state_file(&store, &key)?,
        };
        let saved_original = temporary.path().join("saved-directory-original.log");
        let state_path = store.layout().worktree_dir().join(&key);

        let error = match remove_regular_state_file_with_hook(&store, &object, |path| {
            fs::rename(path, &saved_original)?;
            fs::create_dir(path)
        }) {
            Err(error) => error,
            Ok(()) => {
                return Err(
                    io::Error::other("a raced directory was deleted as the planned log").into(),
                );
            }
        };

        let StateError::QuarantineRestore { quarantine, .. } = error else {
            return Err(io::Error::other(format!("unexpected error: {error}")).into());
        };
        assert!(!state_path.exists());
        assert!(quarantine.is_dir());
        assert_eq!(fs::read(saved_original)?, original);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn garbage_collection_quarantine_preserves_a_replacement_when_reverification_cannot_read_it()
    -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::PermissionsExt as _;

        let (temporary, store) = temporary_store()?;
        let original = b"planned unreadable race";
        let replacement = b"changed unreadable race";
        assert_eq!(original.len(), replacement.len());
        let (_, key, size) = store_fixture_log(&store, original)?;
        let object = PlannedDeletion {
            key: key.clone(),
            size,
            snapshot: snapshot_private_state_file(&store, &key)?,
        };
        let saved_original = temporary.path().join("saved-unreadable-original.log");
        let state_path = store.layout().worktree_dir().join(&key);

        let result = remove_regular_state_file_with_hook(&store, &object, |path| {
            fs::rename(path, &saved_original)?;
            write_private_test_file(path, replacement)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o000))
        });

        assert!(result.is_err());
        assert!(fs::symlink_metadata(&state_path)?.is_file());
        fs::set_permissions(&state_path, fs::Permissions::from_mode(0o600))?;
        assert_eq!(fs::read(&state_path)?, replacement);
        assert_eq!(fs::read(saved_original)?, original);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn garbage_collection_requires_owner_rwx_on_evidence_directories_before_deletion()
    -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::PermissionsExt as _;

        let (temporary, store) = temporary_store()?;
        let (_, log_key, _) = store_fixture_log(&store, b"permission log")?;
        let lock = store.try_lock()?;
        let directory = store.layout().worktree_dir().join("logs/v1");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o500))?;
        let before = filesystem_snapshot(temporary.path())?;

        let result = store.collect_evidence_garbage(
            &lock,
            SystemTime::UNIX_EPOCH,
            &FixtureDecoder::default(),
        );
        assert!(matches!(
            result,
            Err(StateError::InvalidLayout { ref reason, .. }) if reason.contains("owner rwx")
        ));
        assert_eq!(filesystem_snapshot(temporary.path())?, before);
        assert!(load_immutable_fixture(&store, &log_key)?.is_some());
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        Ok(())
    }

    #[test]
    fn garbage_collection_keeps_count_age_and_reference_union() -> Result<(), Box<dyn Error>> {
        let (_temporary, store) = temporary_store()?;
        let mut decoder = FixtureDecoder::default();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(20 * 365 * 24 * 60 * 60);
        let old_base = now - EVIDENCE_GC_KEEP_AGE - Duration::from_secs(1_000);
        let (expired_log, expired_log_key, expired_log_size) =
            store_fixture_log(&store, b"expired log")?;
        let (retained_log, retained_log_key, retained_log_size) =
            store_fixture_log(&store, b"retained log")?;

        let mut receipt_keys = Vec::new();
        let mut evidence_keys = Vec::new();
        let mut total_bytes = expired_log_size + retained_log_size;
        let mut expired_bytes = expired_log_size;
        for index in 0_u64..201 {
            let receipt_name = object_name(index)?;
            let receipt_logs = match index {
                0 => vec![expired_log.clone()],
                1 => vec![retained_log.clone()],
                _ => Vec::new(),
            };
            let (key, size) = store_fixture_receipt(
                &store,
                &mut decoder,
                EvidenceStateVersion::V2,
                receipt_name,
                EvidenceRetentionTime::Current((old_base + Duration::from_secs(index)).into()),
                receipt_logs,
            )?;
            if index == 0 {
                expired_bytes += size;
            }
            total_bytes += size;
            receipt_keys.push(key);

            let evidence_name = object_name(1_000 + index)?;
            let receipt_references = if index == 0 {
                vec![ReceiptStateReference::new(
                    EvidenceStateVersion::V2,
                    object_name(0)?,
                )]
            } else {
                Vec::new()
            };
            let evidence_logs = if index == 0 {
                vec![expired_log.clone()]
            } else {
                Vec::new()
            };
            let (key, size) = store_fixture_evidence(
                &store,
                &mut decoder,
                EvidenceStateVersion::V2,
                evidence_name,
                EvidenceRetentionTime::Current((old_base + Duration::from_secs(index)).into()),
                receipt_references,
                evidence_logs,
            )?;
            if index == 0 {
                expired_bytes += size;
            }
            total_bytes += size;
            evidence_keys.push(key);
        }

        let lock = store.try_lock()?;
        let report = store.collect_evidence_garbage(&lock, now, &decoder)?;

        assert_eq!(report.deleted_receipts(), 1);
        assert_eq!(report.deleted_evidence(), 1);
        assert_eq!(report.deleted_logs(), 1);
        assert_eq!(report.reclaimed_bytes(), expired_bytes);
        assert_eq!(report.retained_bytes(), total_bytes - expired_bytes);
        assert_eq!(load_immutable_fixture(&store, &receipt_keys[0])?, None);
        assert!(load_immutable_fixture(&store, &receipt_keys[1])?.is_some());
        assert_eq!(load_immutable_fixture(&store, &evidence_keys[0])?, None);
        assert!(load_immutable_fixture(&store, &evidence_keys[1])?.is_some());
        assert_eq!(load_immutable_fixture(&store, &expired_log_key)?, None);
        assert!(load_immutable_fixture(&store, &retained_log_key)?.is_some());
        Ok(())
    }

    #[test]
    fn garbage_collection_keeps_every_current_object_inside_age_window()
    -> Result<(), Box<dyn Error>> {
        let (_temporary, store) = temporary_store()?;
        let mut decoder = FixtureDecoder::default();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(20 * 365 * 24 * 60 * 60);
        for index in 0_u64..201 {
            store_fixture_evidence(
                &store,
                &mut decoder,
                EvidenceStateVersion::V2,
                object_name(index)?,
                EvidenceRetentionTime::Current((now - Duration::from_secs(index + 1)).into()),
                Vec::new(),
                Vec::new(),
            )?;
        }

        let lock = store.try_lock()?;
        let report = store.collect_evidence_garbage(&lock, now, &decoder)?;

        assert_eq!(report.deleted_evidence(), 0);
        assert_eq!(report.deleted_receipts(), 0);
        assert_eq!(report.deleted_logs(), 0);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn conservative_unknown_reference_closure_retains_complete_target_classes()
    -> Result<(), Box<dyn Error>> {
        let (_temporary, store) = temporary_store()?;
        let mut decoder = FixtureDecoder::default();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(20 * 365 * 24 * 60 * 60);
        let old = now - EVIDENCE_GC_KEEP_AGE - Duration::from_secs(1_000);

        let mut log_names = Vec::new();
        for index in 0_u64..202 {
            let (name, _, _) = store_fixture_log(&store, &index.to_le_bytes())?;
            log_names.push(name);
        }
        let first_receipt_name = object_name(220_000)?;
        let first_receipt_key = receipt_state_key(EvidenceStateVersion::V2, &first_receipt_name);
        let first_receipt_bytes = b"receipt with unknown log reference semantics".to_vec();
        store_immutable_fixture(&store, &first_receipt_key, &first_receipt_bytes)?;
        decoder.receipts.insert(
            first_receipt_bytes,
            ReceiptRetentionMetadata::with_log_reference_closure(
                first_receipt_name,
                EvidenceRetentionTime::Current(old.into()),
                ReferenceClosure::RetainAll,
            ),
        );
        for index in 1_u64..202 {
            store_fixture_receipt(
                &store,
                &mut decoder,
                EvidenceStateVersion::V2,
                object_name(220_000 + index)?,
                EvidenceRetentionTime::Current((old + Duration::from_secs(index)).into()),
                Vec::new(),
            )?;
        }
        let evidence_name = object_name(221_000)?;
        let evidence_key = evidence_state_key(EvidenceStateVersion::V2, &evidence_name);
        let evidence_bytes = b"evidence with unknown receipt reference semantics".to_vec();
        store_immutable_fixture(&store, &evidence_key, &evidence_bytes)?;
        decoder.evidence.insert(
            evidence_bytes,
            EvidenceRetentionMetadata::with_reference_closures(
                evidence_name,
                EvidenceRetentionTime::Current(now.into()),
                ReferenceClosure::RetainAll,
                ReferenceClosure::complete([]),
            ),
        );
        let lock = store.try_lock()?;

        let report = store.collect_evidence_garbage(&lock, now, &decoder)?;

        assert_eq!(report.deleted_evidence(), 0);
        assert_eq!(report.deleted_receipts(), 0);
        assert_eq!(report.deleted_logs(), 0);
        assert!(load_immutable_fixture(&store, &first_receipt_key)?.is_some());
        assert!(load_immutable_fixture(&store, &evidence_key)?.is_some());
        assert!(load_immutable_fixture(&store, &log_state_key(&log_names[0]))?.is_some());
        assert!(load_immutable_fixture(&store, &log_state_key(&log_names[201]))?.is_some());
        Ok(())
    }

    #[test]
    fn garbage_collection_never_deletes_legacy_objects_or_their_closure()
    -> Result<(), Box<dyn Error>> {
        let (_temporary, store) = temporary_store()?;
        let mut decoder = FixtureDecoder::default();
        let (log_name, log_key, _) = store_fixture_log(&store, b"legacy log")?;
        let receipt_name = object_name(51)?;
        let (receipt_key, _) = store_fixture_receipt(
            &store,
            &mut decoder,
            EvidenceStateVersion::V1,
            receipt_name.clone(),
            EvidenceRetentionTime::Legacy,
            vec![log_name],
        )?;
        let (evidence_key, _) = store_fixture_evidence(
            &store,
            &mut decoder,
            EvidenceStateVersion::V1,
            object_name(52)?,
            EvidenceRetentionTime::Legacy,
            vec![ReceiptStateReference::new(
                EvidenceStateVersion::V1,
                receipt_name,
            )],
            Vec::new(),
        )?;

        let lock = store.try_lock()?;
        let report = store.collect_evidence_garbage(
            &lock,
            SystemTime::UNIX_EPOCH + Duration::from_secs(100 * 365 * 24 * 60 * 60),
            &decoder,
        )?;

        assert_eq!(report.deleted_evidence(), 0);
        assert_eq!(report.deleted_receipts(), 0);
        assert_eq!(report.deleted_logs(), 0);
        assert!(load_immutable_fixture(&store, &receipt_key)?.is_some());
        assert!(load_immutable_fixture(&store, &evidence_key)?.is_some());
        assert!(load_immutable_fixture(&store, &log_key)?.is_some());
        Ok(())
    }

    #[derive(Debug, Clone, Copy)]
    enum InvalidStateFixture {
        Malformed,
        FutureSchema,
        IdentityMismatch,
        MissingReference,
        WrongGenerationTimestamp,
    }

    #[test]
    fn garbage_collection_rejects_invalid_documents_before_deleting_anything()
    -> Result<(), Box<dyn Error>> {
        let cases = [
            InvalidStateFixture::Malformed,
            InvalidStateFixture::FutureSchema,
            InvalidStateFixture::IdentityMismatch,
            InvalidStateFixture::MissingReference,
            InvalidStateFixture::WrongGenerationTimestamp,
        ];
        for case in cases {
            let (temporary, store) = temporary_store()?;
            let mut decoder = FixtureDecoder::default();
            let now = SystemTime::UNIX_EPOCH + Duration::from_secs(30 * 365 * 24 * 60 * 60);
            let (_, orphan_log_key, _) = store_fixture_log(&store, b"orphan")?;

            match case {
                InvalidStateFixture::Malformed => {
                    store_immutable_fixture(
                        &store,
                        &receipt_state_key(EvidenceStateVersion::V2, &object_name(90_001)?),
                        b"malformed",
                    )?;
                }
                InvalidStateFixture::FutureSchema => {
                    store_immutable_fixture(
                        &store,
                        &receipt_state_key(EvidenceStateVersion::V2, &object_name(90_001)?),
                        b"future",
                    )?;
                }
                InvalidStateFixture::IdentityMismatch => {
                    let filename = object_name(90_001)?;
                    let bytes = b"identity mismatch".to_vec();
                    store_immutable_fixture(
                        &store,
                        &receipt_state_key(EvidenceStateVersion::V2, &filename),
                        &bytes,
                    )?;
                    decoder.receipts.insert(
                        bytes,
                        ReceiptRetentionMetadata::new(
                            object_name(90_002)?,
                            EvidenceRetentionTime::Current(now.into()),
                            Vec::new(),
                        ),
                    );
                }
                InvalidStateFixture::MissingReference => {
                    store_fixture_evidence(
                        &store,
                        &mut decoder,
                        EvidenceStateVersion::V2,
                        object_name(90_001)?,
                        EvidenceRetentionTime::Current(now.into()),
                        vec![ReceiptStateReference::new(
                            EvidenceStateVersion::V2,
                            object_name(90_002)?,
                        )],
                        Vec::new(),
                    )?;
                }
                InvalidStateFixture::WrongGenerationTimestamp => {
                    store_fixture_receipt(
                        &store,
                        &mut decoder,
                        EvidenceStateVersion::V1,
                        object_name(90_001)?,
                        EvidenceRetentionTime::Current(now.into()),
                        Vec::new(),
                    )?;
                }
            }

            let lock = store.try_lock()?;
            let before = filesystem_snapshot(temporary.path())?;
            let result = store.collect_evidence_garbage(&lock, now, &decoder);
            let error = match result {
                Err(error) => error,
                Ok(_) => {
                    return Err(
                        io::Error::other(format!("invalid fixture {case:?} was accepted")).into(),
                    );
                }
            };
            match case {
                InvalidStateFixture::Malformed => assert!(matches!(
                    error,
                    StateError::ObjectDecode {
                        reason: EvidenceStateDecodeError::Malformed,
                        ..
                    }
                )),
                InvalidStateFixture::FutureSchema => assert!(matches!(
                    error,
                    StateError::ObjectDecode {
                        reason: EvidenceStateDecodeError::FutureSchema,
                        ..
                    }
                )),
                InvalidStateFixture::IdentityMismatch => {
                    assert!(matches!(error, StateError::ObjectIdentityMismatch { .. }));
                }
                InvalidStateFixture::MissingReference => {
                    assert!(matches!(error, StateError::MissingReference { .. }));
                }
                InvalidStateFixture::WrongGenerationTimestamp => assert!(matches!(
                    error,
                    StateError::ObjectDecode {
                        reason: EvidenceStateDecodeError::InvalidTimestamp,
                        ..
                    }
                )),
            }
            assert_eq!(filesystem_snapshot(temporary.path())?, before);
            assert!(load_immutable_fixture(&store, &orphan_log_key)?.is_some());
        }
        Ok(())
    }

    #[derive(Debug, Clone, Copy)]
    enum InvalidLayoutFixture {
        FutureVersion,
        UnknownFilename,
        NonRegularObject,
    }

    #[test]
    fn garbage_collection_rejects_unknown_and_nonregular_layout_before_deletion()
    -> Result<(), Box<dyn Error>> {
        for case in [
            InvalidLayoutFixture::FutureVersion,
            InvalidLayoutFixture::UnknownFilename,
            InvalidLayoutFixture::NonRegularObject,
        ] {
            let (temporary, store) = temporary_store()?;
            let mut decoder = FixtureDecoder::default();
            let (_, orphan_log_key, _) = store_fixture_log(&store, b"orphan")?;
            match case {
                InvalidLayoutFixture::FutureVersion => {
                    store_immutable_fixture(
                        &store,
                        &format!("evidence/v3/{}.json", object_name(91_001)?.as_str()),
                        b"future layout",
                    )?;
                }
                InvalidLayoutFixture::UnknownFilename => {
                    store_immutable_fixture(&store, "evidence/v2/.partial", b"residue")?;
                }
                InvalidLayoutFixture::NonRegularObject => {
                    store_fixture_evidence(
                        &store,
                        &mut decoder,
                        EvidenceStateVersion::V2,
                        object_name(91_001)?,
                        EvidenceRetentionTime::Current(SystemTime::UNIX_EPOCH.into()),
                        Vec::new(),
                        Vec::new(),
                    )?;
                    fs::create_dir(store.layout().worktree_dir().join(evidence_state_key(
                        EvidenceStateVersion::V2,
                        &object_name(91_002)?,
                    )))?;
                }
            }

            let lock = store.try_lock()?;
            let before = filesystem_snapshot(temporary.path())?;
            let result = store.collect_evidence_garbage(
                &lock,
                SystemTime::UNIX_EPOCH + Duration::from_secs(100),
                &decoder,
            );
            assert!(
                matches!(
                    (case, result),
                    (
                        InvalidLayoutFixture::FutureVersion,
                        Err(StateError::UnsupportedEvidenceStateVersion { .. })
                    ) | (
                        InvalidLayoutFixture::UnknownFilename
                            | InvalidLayoutFixture::NonRegularObject,
                        Err(StateError::InvalidLayout { .. })
                    )
                ),
                "invalid layout fixture {case:?} was accepted"
            );
            assert_eq!(filesystem_snapshot(temporary.path())?, before);
            assert!(load_immutable_fixture(&store, &orphan_log_key)?.is_some());
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn garbage_collection_rejects_symlinks_before_deletion() -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::symlink;

        let (temporary, store) = temporary_store()?;
        let (_, orphan_log_key, _) = store_fixture_log(&store, b"orphan")?;
        let outside = temporary.path().join("outside");
        fs::write(&outside, b"outside")?;
        symlink(
            &outside,
            store
                .layout()
                .worktree_dir()
                .join(log_state_key(&object_name(92_001)?)),
        )?;
        let lock = store.try_lock()?;
        let before = filesystem_snapshot(temporary.path())?;

        let result = store.collect_evidence_garbage(
            &lock,
            SystemTime::UNIX_EPOCH,
            &FixtureDecoder::default(),
        );

        assert!(matches!(
            result,
            Err(StateError::PathSafety(
                crate::fs::FileSystemError::SymlinkComponent { .. }
            ))
        ));
        assert_eq!(filesystem_snapshot(temporary.path())?, before);
        assert_eq!(fs::read(&outside)?, b"outside");
        assert!(load_immutable_fixture(&store, &orphan_log_key)?.is_some());
        Ok(())
    }

    #[test]
    fn garbage_collection_enforces_the_exact_per_class_scan_cap() -> Result<(), Box<dyn Error>> {
        let (_temporary, store) = temporary_store()?;
        let (_, first_key, _) = store_fixture_log(&store, b"first")?;
        let log_directory = store.layout().worktree_dir().join("logs/v1");
        for index in 1..=EVIDENCE_GC_MAX_LOGS {
            let name = object_name(100_000 + index as u64)?;
            write_private_test_file(&log_directory.join(format!("{}.log", name.as_str())), b"x")?;
        }
        let lock = store.try_lock()?;

        let result = store.collect_evidence_garbage(
            &lock,
            SystemTime::UNIX_EPOCH,
            &FixtureDecoder::default(),
        );

        assert!(matches!(
            result,
            Err(StateError::EntryLimit {
                max_entries: EVIDENCE_GC_MAX_LOGS,
                ..
            })
        ));
        assert!(load_immutable_fixture(&store, &first_key)?.is_some());
        Ok(())
    }

    #[test]
    fn garbage_collection_enforces_receipt_and_evidence_file_bounds_before_deletion()
    -> Result<(), Box<dyn Error>> {
        let cases = [
            (
                EvidenceStateVersion::V2,
                "receipts",
                RECEIPT_OBJECT_MAX_BYTES,
                110_000_u64,
            ),
            (
                EvidenceStateVersion::V2,
                "evidence",
                EVIDENCE_OBJECT_MAX_BYTES,
                110_001_u64,
            ),
        ];
        for (version, kind, max_bytes, identity) in cases {
            let (_temporary, store) = temporary_store()?;
            let (_, orphan_log_key, _) = store_fixture_log(&store, b"orphan")?;
            let name = object_name(identity)?;
            let key = format!("{kind}/v{}/{}.json", version.major(), name.as_str());
            store_immutable_fixture(&store, &key, b"x")?;
            fs::OpenOptions::new()
                .write(true)
                .open(store.layout().worktree_dir().join(&key))?
                .set_len(max_bytes as u64 + 1)?;
            let lock = store.try_lock()?;

            let result = store.collect_evidence_garbage(
                &lock,
                SystemTime::UNIX_EPOCH,
                &FixtureDecoder::default(),
            );

            assert!(matches!(
                result,
                Err(StateError::ObjectTooLarge {
                    max_bytes: actual,
                    ..
                }) if actual == max_bytes
            ));
            assert!(load_immutable_fixture(&store, &orphan_log_key)?.is_some());
            assert_eq!(
                fs::metadata(store.layout().worktree_dir().join(key))?.len(),
                max_bytes as u64 + 1
            );
        }
        Ok(())
    }

    #[test]
    fn retained_state_budget_rejects_overflow() {
        assert!(matches!(
            ensure_retained_budget(EVIDENCE_STATE_MAX_BYTES + 1),
            Err(StateError::RetainedBudgetExceeded {
                retained_bytes,
                max_bytes: EVIDENCE_STATE_MAX_BYTES,
            }) if retained_bytes == EVIDENCE_STATE_MAX_BYTES + 1
        ));
        assert!(ensure_retained_budget(EVIDENCE_STATE_MAX_BYTES).is_ok());
    }

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
        store.store_atomic("read-only/current.json", br#"{"schema":1}"#)?;
        let before = filesystem_snapshot(temporary.path())?;

        let read_only = AtomicStateStore::open_existing_read_only(layout.clone())?
            .ok_or_else(|| io::Error::other("existing state store was not opened"))?;

        assert_eq!(
            read_only.load("read-only/current.json")?,
            Some(br#"{"schema":1}"#.to_vec())
        );
        assert_eq!(filesystem_snapshot(temporary.path())?, before);
        assert!(!layout.lock_file().exists());
        Ok(())
    }

    #[test]
    fn state_store_enforces_the_bounded_load_contract() -> Result<(), Box<dyn Error>> {
        let temporary = tempdir()?;
        let git_dir = temporary.path().join("git");
        fs::create_dir(&git_dir)?;
        let store = AtomicStateStore::new(GitStateLayout::new(&git_dir, &git_dir))?;
        store.store_atomic("generated-v1.json", b"12345")?;

        assert_eq!(
            forge_core::ports::StateStore::load_bounded(&store, "generated-v1.json", 5)?,
            Some(b"12345".to_vec())
        );
        let oversized = forge_core::ports::StateStore::load_bounded(&store, "generated-v1.json", 4);
        assert!(matches!(
            oversized,
            Err(ref error) if error.kind() == io::ErrorKind::InvalidData
        ));
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

    #[test]
    fn garbage_collection_requires_the_matching_lock_and_stays_in_one_worktree()
    -> Result<(), Box<dyn Error>> {
        let temporary = tempdir()?;
        let common = temporary.path().join("common");
        let worktree_a = temporary.path().join("worktree-a-git");
        let worktree_b = temporary.path().join("worktree-b-git");
        fs::create_dir(&common)?;
        fs::create_dir(&worktree_a)?;
        fs::create_dir(&worktree_b)?;
        let store_a = AtomicStateStore::new(GitStateLayout::new(&worktree_a, &common))?;
        let store_b = AtomicStateStore::new(GitStateLayout::new(&worktree_b, &common))?;
        let object_name = EvidenceStateObjectName::new(log_content_address(b"shared log"))?;
        let key = log_state_key(&object_name);
        store_immutable_fixture(&store_a, &key, b"shared log")?;
        store_immutable_fixture(&store_b, &key, b"shared log")?;
        let lock_b = store_b.try_lock()?;

        let wrong_lock = store_a.collect_evidence_garbage(
            &lock_b,
            SystemTime::UNIX_EPOCH,
            &FixtureDecoder::default(),
        );

        assert!(matches!(wrong_lock, Err(StateError::WrongLock { .. })));
        assert_eq!(
            load_immutable_fixture(&store_a, &key)?,
            Some(b"shared log".to_vec())
        );
        assert_eq!(
            load_immutable_fixture(&store_b, &key)?,
            Some(b"shared log".to_vec())
        );
        drop(lock_b);

        let lock_a = store_a.try_lock()?;
        let report = store_a.collect_evidence_garbage(
            &lock_a,
            SystemTime::UNIX_EPOCH,
            &FixtureDecoder::default(),
        )?;
        assert_eq!(report.deleted_logs(), 1);
        assert_eq!(load_immutable_fixture(&store_a, &key)?, None);
        assert_eq!(
            load_immutable_fixture(&store_b, &key)?,
            Some(b"shared log".to_vec())
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

        store.store_atomic("mutable/one.json", br#"{"schema":1}"#)?;
        let _lock = store.try_lock()?;

        assert_private_mode(layout.worktree_dir(), 0o700)?;
        assert_private_mode(&layout.worktree_dir().join("mutable"), 0o700)?;
        assert_private_mode(&layout.worktree_dir().join("mutable/one.json"), 0o600)?;
        assert_private_mode(&layout.lock_file(), 0o600)?;

        assert!(
            !layout.shared_cache_dir().exists(),
            "per-worktree state writes must not eagerly create the shared cache"
        );
        let cache = SharedCacheStore::new(&layout)?;
        let cache_hex = "a".repeat(64);
        let cache_key = Digest::new(format!("blake3:{cache_hex}"));
        assert_eq!(
            cache.store_immutable(SharedCacheKind::Inventory, &cache_key, b"inventory")?,
            SharedCacheWrite::Created
        );
        assert_private_mode(layout.shared_cache_dir(), 0o700)?;
        assert_private_mode(&layout.shared_cache_dir().join("inventory"), 0o700)?;
        assert_private_mode(
            &layout
                .shared_cache_dir()
                .join("inventory")
                .join(format!("{cache_hex}.json")),
            0o600,
        )?;
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

        store.store_atomic("portable/01ABC.json", b"schema bytes")?;
        assert_eq!(
            store.load("portable/01ABC.json")?,
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

    #[test]
    fn immutable_state_create_never_replaces_an_existing_identity() -> Result<(), Box<dyn Error>> {
        let temporary = tempdir()?;
        let git_dir = temporary.path().join("git");
        fs::create_dir(&git_dir)?;
        let store = AtomicStateStore::new(GitStateLayout::new(&git_dir, &git_dir))?;

        store.store_new_atomic("immutable/01ABC.json", b"first")?;
        let duplicate = store.store_new_atomic("immutable/01ABC.json", b"first");
        let collision = store.store_new_atomic("immutable/01ABC.json", b"second");

        assert!(matches!(
            duplicate,
            Err(ref error) if error.io_kind() == io::ErrorKind::AlreadyExists
        ));
        assert!(matches!(
            collision,
            Err(ref error) if error.io_kind() == io::ErrorKind::AlreadyExists
        ));
        assert_eq!(store.load("immutable/01ABC.json")?, Some(b"first".to_vec()));
        Ok(())
    }

    #[test]
    fn bounded_state_listing_is_stable_complete_and_read_only() -> Result<(), Box<dyn Error>> {
        let temporary = tempdir()?;
        let git_dir = temporary.path().join("git");
        fs::create_dir(&git_dir)?;
        let store = AtomicStateStore::new(GitStateLayout::new(&git_dir, &git_dir))?;
        store.store_new_atomic("listing/Z.json", b"z")?;
        store.store_new_atomic("listing/A.json", b"a")?;
        let before = filesystem_snapshot(temporary.path())?;

        assert_eq!(
            store.list_regular_keys_bounded("listing", 2)?,
            ["listing/A.json", "listing/Z.json"]
        );
        assert!(matches!(
            store.list_regular_keys_bounded("listing", 1),
            Err(StateError::EntryLimit { max_entries: 1, .. })
        ));
        assert!(store.list_regular_keys_bounded("missing", 2)?.is_empty());
        assert_eq!(filesystem_snapshot(temporary.path())?, before);
        Ok(())
    }

    #[test]
    fn direct_state_listing_rejects_nested_entries() -> Result<(), Box<dyn Error>> {
        let temporary = tempdir()?;
        let git_dir = temporary.path().join("git");
        fs::create_dir(&git_dir)?;
        let store = AtomicStateStore::new(GitStateLayout::new(&git_dir, &git_dir))?;
        store.store_new_atomic("listing/nested/value.json", b"nested")?;

        assert!(matches!(
            store.list_regular_keys_bounded("listing", 10),
            Err(StateError::InvalidLayout { .. })
        ));
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
        store.store_atomic("mutable/bootstrap.json", b"schema bytes")?;
        let outside = temporary.path().join("outside.json");
        fs::write(&outside, b"outside")?;
        symlink(&outside, layout.worktree_dir().join("mutable/linked.json"))?;

        let result = store.store_atomic("mutable/linked.json", b"unsafe");

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
