//! Versioned codec and complete dependency key for the shared clean-commit inventory cache.

use std::io::{self, BufReader, Read, Write};
use std::path::Path;

use forge_core::ports::Hasher;
use forge_core::{
    Confidence, Digest, GitFileSet, GitIndexEntry, GitIndexTag, Inventory, InventoryEntry,
    InventoryKind, InventoryOptions, OperationControl, OperationControlError, RepoRelativePath,
    UnlimitedOperationControl, WorkState,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::policy::PolicyBaseCompleteness;
use crate::repository::RepositoryDetection;

const CACHE_KEY_DOMAIN: &[u8] = b"forge.shared-inventory-cache-key/v3";
const INDEX_SNAPSHOT_DOMAIN: &[u8] = b"forge.raw-git-index-snapshot/v1";
const INDEX_PROJECTION_DOMAIN: &[u8] = b"forge.git-index-semantic-projection/v1";
const PAYLOAD_DIGEST_DOMAIN: &[u8] = b"forge.shared-inventory-cache-payload/v1";
const CACHE_SCHEMA: &str = "forge.inventory-cache/v2";
const CACHE_BEHAVIOR: &str = "forge.inventory-cache-behavior/v3";
const INVENTORY_COMMAND: &str = "clean-index-path-projection/v3";
const ELIGIBILITY_RULE: &str = "stage0-cached-regular-files-only/v1";
const NOT_APPLICABLE_TOOLCHAIN: &str = "not-applicable:inventory-toolchain/v1";
const EMPTY_ENVIRONMENT: &str = "known-empty:inventory-environment/v1";
const CONTROL_CHUNK_BYTES: usize = 64 * 1024;

/// Hard bound for one encoded shared inventory entry.
pub const MAX_INVENTORY_CACHE_BYTES: usize = 64 * 1024 * 1024;
/// Hard bound for the raw Git index bytes used to form a clean snapshot identity.
pub const MAX_INDEX_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;

/// Byte-oriented read port implemented by CLI composition over the Git common-dir store.
///
/// Model detection receives only this interface so a read-only scan cannot publish a cache entry.
pub trait InventoryCacheReadPort {
    fn load(&self, key: &Digest, max_bytes: usize) -> io::Result<Option<Vec<u8>>>;
}

/// Byte-oriented publication port used only after an authorized state write has succeeded.
pub trait InventoryCacheWritePort {
    fn store_new(&self, key: &Digest, bytes: &[u8]) -> io::Result<()>;
}

/// A complete immutable entry retained in memory until a caller reaches a write boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryCachePublication {
    key: Digest,
    bytes: Vec<u8>,
}

/// Produces a reusable key only for a complete, clean, committed repository identity.
#[must_use]
pub fn inventory_cache_key(
    repository: &RepositoryDetection,
    index_projection: &Digest,
    options: InventoryOptions,
    effective_policy: &Digest,
    policy_base_completeness: PolicyBaseCompleteness,
    hasher: &dyn Hasher,
) -> Option<Digest> {
    if repository.confidence == Confidence::Unknown
        || repository.facts.work_state != WorkState::Clean
        || policy_base_completeness != PolicyBaseCompleteness::Complete
    {
        return None;
    }
    let head = repository.facts.head.as_ref()?.as_git_object_id();
    let max_entries = u64::try_from(options.max_entries).ok()?;
    let mut encoded = Vec::new();
    append_field(
        &mut encoded,
        b"repository",
        repository.facts.id.as_str().as_bytes(),
    );
    append_field(&mut encoded, b"scope-head", head.as_bytes());
    append_field(
        &mut encoded,
        b"index-projection",
        index_projection.as_str().as_bytes(),
    );
    append_field(&mut encoded, b"command", INVENTORY_COMMAND.as_bytes());
    append_field(&mut encoded, b"max-entries", &max_entries.to_be_bytes());
    append_field(
        &mut encoded,
        b"max-text-file-bytes",
        &options.max_text_file_bytes.to_be_bytes(),
    );
    append_field(
        &mut encoded,
        b"toolchain",
        NOT_APPLICABLE_TOOLCHAIN.as_bytes(),
    );
    append_field(&mut encoded, b"environment", EMPTY_ENVIRONMENT.as_bytes());
    append_field(
        &mut encoded,
        b"effective-policy",
        effective_policy.as_str().as_bytes(),
    );
    append_field(&mut encoded, b"platform", platform_encoding().as_bytes());
    append_field(&mut encoded, b"behavior", CACHE_BEHAVIOR.as_bytes());
    Some(hasher.digest(&[CACHE_KEY_DOMAIN, &encoded]))
}

/// Derives the collision-resistant identity used to bracket one hardened Git status snapshot.
#[must_use]
pub fn index_snapshot_digest(bytes: &[u8], hasher: &dyn Hasher) -> Digest {
    hasher.digest(&[INDEX_SNAPSHOT_DOMAIN, bytes])
}

/// Digests a bounded raw index snapshot without returning a fact after control stops.
pub fn index_snapshot_digest_controlled(
    bytes: &[u8],
    hasher: &dyn Hasher,
    control: &dyn OperationControl,
) -> Result<Digest, OperationControlError> {
    control.checkpoint()?;
    let digest = hasher.digest(&[INDEX_SNAPSHOT_DOMAIN, bytes]);
    control.checkpoint()?;
    Ok(digest)
}

/// Digests the worktree-independent semantic projection of one ordinary Git index.
///
/// Raw index bytes contain checkout-local stat data and therefore cannot identify content shared
/// by linked worktrees. Only the explicitly accepted stage-zero cached regular-file subset enters
/// this projection; every exposed state outside that subset fails closed before cache lookup.
#[must_use]
pub fn index_projection_digest(
    index_entries: &[GitIndexEntry],
    hasher: &dyn Hasher,
) -> Option<Digest> {
    index_projection_digest_controlled(index_entries, hasher, &UnlimitedOperationControl)
        .ok()
        .flatten()
}

/// Digests the semantic index projection while observing one operation-wide control.
pub fn index_projection_digest_controlled(
    index_entries: &[GitIndexEntry],
    hasher: &dyn Hasher,
    control: &dyn OperationControl,
) -> Result<Option<Digest>, OperationControlError> {
    control.checkpoint()?;
    let mut ordered = index_entries.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.stage.cmp(&right.stage))
    });
    control.checkpoint()?;
    let mut encoded = Vec::new();
    let mut previous = None;
    for entry in ordered {
        control.checkpoint()?;
        if entry.stage != 0
            || !matches!(entry.tag, GitIndexTag::Cached)
            || !matches!(entry.mode.as_bytes(), b"100644" | b"100755")
            || previous == Some(&entry.path)
        {
            return Ok(None);
        }
        previous = Some(&entry.path);
        append_field_controlled(&mut encoded, b"mode", entry.mode.as_bytes(), control)?;
        append_field_controlled(
            &mut encoded,
            b"object-id",
            entry.object_id.as_bytes(),
            control,
        )?;
        let path = match native_path_bytes(entry.path.as_path()) {
            Ok(path) => path,
            Err(CacheCodecError::Invalid) => return Ok(None),
            Err(CacheCodecError::Control(error)) => return Err(error),
        };
        append_field_controlled(&mut encoded, b"path", &path, control)?;
    }
    control.checkpoint()?;
    let digest = hasher.digest(&[INDEX_PROJECTION_DOMAIN, &encoded]);
    control.checkpoint()?;
    Ok(Some(digest))
}

/// Proves that one slow-path inventory is a worktree-independent projection of an ordinary index.
///
/// v0 fast reuse is deliberately restricted to regular/executable tracked files whose bounded Git
/// reads expose the ordinary cached state. Symlinks, Gitlinks, sparse directories, unmerged stages,
/// assume-unchanged entries, untracked paths, and incomplete inventories fall back to the
/// authoritative path.
#[must_use]
pub fn inventory_cache_basis_is_eligible(
    file_set: &GitFileSet,
    index_entries: &[GitIndexEntry],
    inventory: &Inventory,
) -> bool {
    inventory_cache_basis_is_eligible_controlled(
        file_set,
        index_entries,
        inventory,
        &UnlimitedOperationControl,
    )
    .unwrap_or(false)
}

/// Proves cache eligibility while observing one operation-wide control.
pub fn inventory_cache_basis_is_eligible_controlled(
    file_set: &GitFileSet,
    index_entries: &[GitIndexEntry],
    inventory: &Inventory,
    control: &dyn OperationControl,
) -> Result<bool, OperationControlError> {
    control.checkpoint()?;
    if !file_set.untracked.is_empty()
        || !inventory.skipped.is_empty()
        || index_entries.len() != file_set.tracked.len()
        || inventory.entries.len() != file_set.tracked.len()
    {
        return Ok(false);
    }

    let mut ordered = index_entries.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.stage.cmp(&right.stage))
    });
    control.checkpoint()?;
    for (entry, tracked) in ordered.into_iter().zip(&file_set.tracked) {
        control.checkpoint()?;
        if entry.stage != 0
            || !matches!(entry.tag, GitIndexTag::Cached)
            || !matches!(entry.mode.as_bytes(), b"100644" | b"100755")
            || &entry.path != tracked
        {
            return Ok(false);
        }
    }

    for (entry, tracked) in inventory.entries.iter().zip(&file_set.tracked) {
        control.checkpoint()?;
        if entry.kind != InventoryKind::File
            || RepoRelativePath::new(&entry.path).ok().as_ref() != Some(tracked)
        {
            return Ok(false);
        }
    }
    control.checkpoint()?;
    Ok(true)
}

/// Reads and validates a cache entry. Any storage or decoding failure is an ordinary miss.
#[must_use]
pub fn load_cached_inventory(
    cache: &dyn InventoryCacheReadPort,
    key: &Digest,
    index_projection: &Digest,
    index_entries: &[GitIndexEntry],
    options: InventoryOptions,
    hasher: &dyn Hasher,
) -> Option<Inventory> {
    load_cached_inventory_controlled(
        cache,
        key,
        index_projection,
        index_entries,
        options,
        hasher,
        &UnlimitedOperationControl,
    )
    .ok()
    .flatten()
}

/// Reads and validates one cache entry without swallowing deadline or interruption failures.
pub fn load_cached_inventory_controlled(
    cache: &dyn InventoryCacheReadPort,
    key: &Digest,
    index_projection: &Digest,
    index_entries: &[GitIndexEntry],
    options: InventoryOptions,
    hasher: &dyn Hasher,
    control: &dyn OperationControl,
) -> Result<Option<Inventory>, OperationControlError> {
    control.checkpoint()?;
    let Some(bytes) = cache.load(key, MAX_INVENTORY_CACHE_BYTES).ok().flatten() else {
        control.checkpoint()?;
        return Ok(None);
    };
    control.checkpoint()?;
    if bytes.len() > MAX_INVENTORY_CACHE_BYTES {
        return Ok(None);
    }
    match decode_inventory(
        &bytes,
        key,
        index_projection,
        index_entries,
        options,
        hasher,
        control,
    ) {
        Ok(inventory) => Ok(Some(inventory)),
        Err(CacheCodecError::Invalid) => Ok(None),
        Err(CacheCodecError::Control(error)) => Err(error),
    }
}

/// Prepares a complete inventory for later publication without changing the filesystem.
#[must_use]
pub fn prepare_cached_inventory(
    key: &Digest,
    index_projection: &Digest,
    inventory: &Inventory,
    hasher: &dyn Hasher,
) -> Option<InventoryCachePublication> {
    prepare_cached_inventory_controlled(
        key,
        index_projection,
        inventory,
        hasher,
        &UnlimitedOperationControl,
    )
    .ok()
    .flatten()
}

/// Prepares one publication without swallowing deadline or interruption failures.
pub fn prepare_cached_inventory_controlled(
    key: &Digest,
    index_projection: &Digest,
    inventory: &Inventory,
    hasher: &dyn Hasher,
    control: &dyn OperationControl,
) -> Result<Option<InventoryCachePublication>, OperationControlError> {
    control.checkpoint()?;
    if !inventory.skipped.is_empty() {
        return Ok(None);
    }
    for entry in &inventory.entries {
        control.checkpoint()?;
        if entry.kind != InventoryKind::File {
            return Ok(None);
        }
    }
    let bytes = match encode_inventory(inventory, key, index_projection, hasher, control) {
        Ok(bytes) => bytes,
        Err(CacheCodecError::Invalid) => return Ok(None),
        Err(CacheCodecError::Control(error)) => return Err(error),
    };
    control.checkpoint()?;
    Ok(
        (bytes.len() <= MAX_INVENTORY_CACHE_BYTES).then(|| InventoryCachePublication {
            key: key.clone(),
            bytes,
        }),
    )
}

/// Publishes one prepared entry after the caller has completed its authorized state write.
///
/// Publication remains opportunistic: callers decide whether a cache error affects their own
/// operation. The CLI intentionally ignores such an error after its authoritative write succeeds.
pub fn publish_cached_inventory(
    cache: &dyn InventoryCacheWritePort,
    publication: &InventoryCachePublication,
) -> io::Result<()> {
    cache.store_new(&publication.key, &publication.bytes)
}

fn append_field(target: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    target.extend_from_slice(&(name.len() as u128).to_be_bytes());
    target.extend_from_slice(name);
    target.extend_from_slice(&(value.len() as u128).to_be_bytes());
    target.extend_from_slice(value);
}

fn append_field_controlled(
    target: &mut Vec<u8>,
    name: &[u8],
    value: &[u8],
    control: &dyn OperationControl,
) -> Result<(), OperationControlError> {
    control.checkpoint()?;
    target.extend_from_slice(&(name.len() as u128).to_be_bytes());
    target.extend_from_slice(name);
    target.extend_from_slice(&(value.len() as u128).to_be_bytes());
    for chunk in value.chunks(CONTROL_CHUNK_BYTES) {
        control.checkpoint()?;
        target.extend_from_slice(chunk);
    }
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheEnvelope {
    schema: String,
    key: String,
    payload_digest: String,
    payload: CachePayload,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CachePayload {
    platform_encoding: String,
    eligibility: CacheEligibility,
    entries: Vec<CacheEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheEligibility {
    rule: String,
    index_projection: String,
    entry_count: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheEntry {
    path_hex: String,
}

fn encode_inventory(
    inventory: &Inventory,
    key: &Digest,
    index_projection: &Digest,
    hasher: &dyn Hasher,
    control: &dyn OperationControl,
) -> Result<Vec<u8>, CacheCodecError> {
    let mut entries = Vec::with_capacity(inventory.entries.len());
    for entry in &inventory.entries {
        control.checkpoint()?;
        entries.push(CacheEntry {
            path_hex: encode_hex_controlled(&native_path_bytes(&entry.path)?, control)?,
        });
    }
    let payload = CachePayload {
        platform_encoding: platform_encoding().to_owned(),
        eligibility: CacheEligibility {
            rule: ELIGIBILITY_RULE.to_owned(),
            index_projection: index_projection.as_str().to_owned(),
            entry_count: u64::try_from(entries.len()).map_err(|_| CacheCodecError::Invalid)?,
        },
        entries,
    };
    let payload_bytes = serialize_json_controlled(&payload, control)?;
    control.checkpoint()?;
    let payload_digest = hasher.digest(&[PAYLOAD_DIGEST_DOMAIN, &payload_bytes]);
    control.checkpoint()?;
    serialize_json_controlled(
        &CacheEnvelope {
            schema: CACHE_SCHEMA.to_owned(),
            key: key.as_str().to_owned(),
            payload_digest: payload_digest.as_str().to_owned(),
            payload,
        },
        control,
    )
}

fn decode_inventory(
    bytes: &[u8],
    expected_key: &Digest,
    expected_index_projection: &Digest,
    index_entries: &[GitIndexEntry],
    options: InventoryOptions,
    hasher: &dyn Hasher,
    control: &dyn OperationControl,
) -> Result<Inventory, CacheCodecError> {
    let envelope: CacheEnvelope = deserialize_json_controlled(bytes, control)?;
    if envelope.schema != CACHE_SCHEMA
        || envelope.key != expected_key.as_str()
        || envelope.payload.platform_encoding != platform_encoding()
        || envelope.payload.eligibility.rule != ELIGIBILITY_RULE
        || envelope.payload.eligibility.index_projection != expected_index_projection.as_str()
        || usize::try_from(envelope.payload.eligibility.entry_count).ok()
            != Some(envelope.payload.entries.len())
    {
        return Err(CacheCodecError::Invalid);
    }
    let payload_bytes = serialize_json_controlled(&envelope.payload, control)?;
    control.checkpoint()?;
    if hasher
        .digest(&[PAYLOAD_DIGEST_DOMAIN, &payload_bytes])
        .as_str()
        != envelope.payload_digest
    {
        return Err(CacheCodecError::Invalid);
    }
    control.checkpoint()?;
    if envelope.payload.entries.len() > options.max_entries {
        return Err(CacheCodecError::Invalid);
    }

    // The current index is already the typed, complete source of the paths used below. Compare the
    // untrusted cache projection directly against those paths instead of decoding, normalizing,
    // inserting, and sorting a second 100,000-path tree. This preserves the same exact-path proof
    // while keeping a warm cache hit linear with one allocation per retained model entry.
    let mut ordered_index = index_entries.iter().collect::<Vec<_>>();
    ordered_index.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.stage.cmp(&right.stage))
    });
    control.checkpoint()?;
    if ordered_index.len() != envelope.payload.entries.len() {
        return Err(CacheCodecError::Invalid);
    }
    let mut previous = None;
    let mut entries = Vec::with_capacity(ordered_index.len());
    for (cached, index) in envelope.payload.entries.into_iter().zip(ordered_index) {
        control.checkpoint()?;
        if index.stage != 0
            || !matches!(index.tag, GitIndexTag::Cached)
            || !matches!(index.mode.as_bytes(), b"100644" | b"100755")
            || previous == Some(&index.path)
            || !path_hex_matches_controlled(&cached.path_hex, index.path.as_path(), control)?
        {
            return Err(CacheCodecError::Invalid);
        }
        previous = Some(&index.path);
        entries.push(InventoryEntry {
            path: index.path.as_path().to_path_buf(),
            kind: InventoryKind::File,
            size_bytes: None,
        });
    }
    control.checkpoint()?;
    Ok(Inventory {
        entries,
        skipped: Vec::new(),
    })
}

#[derive(Debug, Clone, Copy)]
enum CacheCodecError {
    Invalid,
    Control(OperationControlError),
}

impl From<OperationControlError> for CacheCodecError {
    fn from(error: OperationControlError) -> Self {
        Self::Control(error)
    }
}

fn serialize_json_controlled(
    value: &impl Serialize,
    control: &dyn OperationControl,
) -> Result<Vec<u8>, CacheCodecError> {
    let mut writer = ControlledVecWriter::new(control);
    let result = serde_json::to_writer(&mut writer, value);
    if let Some(error) = writer.control_error {
        return Err(CacheCodecError::Control(error));
    }
    result.map_err(|_| CacheCodecError::Invalid)?;
    writer.finish()
}

fn deserialize_json_controlled<T: DeserializeOwned>(
    bytes: &[u8],
    control: &dyn OperationControl,
) -> Result<T, CacheCodecError> {
    let mut reader = ControlledSliceReader::new(bytes, control);
    let result = {
        let mut buffered = BufReader::with_capacity(CONTROL_CHUNK_BYTES, &mut reader);
        serde_json::from_reader(&mut buffered)
    };
    if let Some(error) = reader.control_error {
        return Err(CacheCodecError::Control(error));
    }
    let value = result.map_err(|_| CacheCodecError::Invalid)?;
    control.checkpoint()?;
    Ok(value)
}

struct ControlledVecWriter<'a> {
    bytes: Vec<u8>,
    bytes_since_checkpoint: usize,
    control: &'a dyn OperationControl,
    control_error: Option<OperationControlError>,
}

impl<'a> ControlledVecWriter<'a> {
    fn new(control: &'a dyn OperationControl) -> Self {
        Self {
            bytes: Vec::new(),
            bytes_since_checkpoint: 0,
            control,
            control_error: None,
        }
    }

    fn checkpoint(&mut self) -> io::Result<()> {
        match self.control.checkpoint() {
            Ok(_) => Ok(()),
            Err(error) => {
                self.control_error = Some(error);
                // `Interrupted` is automatically retried by `write_all`, which would spin forever
                // for a sticky operation stop. The typed error is retained separately above.
                Err(io::Error::other(error))
            }
        }
    }

    fn finish(self) -> Result<Vec<u8>, CacheCodecError> {
        self.control.checkpoint()?;
        Ok(self.bytes)
    }
}

impl Write for ControlledVecWriter<'_> {
    fn write(&mut self, mut buffer: &[u8]) -> io::Result<usize> {
        let total = buffer.len();
        while !buffer.is_empty() {
            if self.bytes_since_checkpoint == 0 {
                self.checkpoint()?;
            }
            let remaining = CONTROL_CHUNK_BYTES - self.bytes_since_checkpoint;
            let count = remaining.min(buffer.len());
            self.bytes.extend_from_slice(&buffer[..count]);
            self.bytes_since_checkpoint =
                (self.bytes_since_checkpoint + count) % CONTROL_CHUNK_BYTES;
            buffer = &buffer[count..];
        }
        Ok(total)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct ControlledSliceReader<'a> {
    bytes: &'a [u8],
    offset: usize,
    control: &'a dyn OperationControl,
    control_error: Option<OperationControlError>,
}

impl<'a> ControlledSliceReader<'a> {
    const fn new(bytes: &'a [u8], control: &'a dyn OperationControl) -> Self {
        Self {
            bytes,
            offset: 0,
            control,
            control_error: None,
        }
    }
}

impl Read for ControlledSliceReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.offset == self.bytes.len() {
            return Ok(0);
        }
        if let Err(error) = self.control.checkpoint() {
            self.control_error = Some(error);
            // Readers commonly retry `Interrupted`; use a non-retryable sentinel and recover the
            // typed operation error from `control_error` after serde returns.
            return Err(io::Error::other(error));
        }
        let count = buffer
            .len()
            .min(CONTROL_CHUNK_BYTES)
            .min(self.bytes.len() - self.offset);
        buffer[..count].copy_from_slice(&self.bytes[self.offset..self.offset + count]);
        self.offset += count;
        Ok(count)
    }
}

#[cfg(test)]
fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn encode_hex_controlled(
    bytes: &[u8],
    control: &dyn OperationControl,
) -> Result<String, OperationControlError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for chunk in bytes.chunks(CONTROL_CHUNK_BYTES) {
        control.checkpoint()?;
        for byte in chunk {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    control.checkpoint()?;
    Ok(encoded)
}

#[cfg(unix)]
fn path_hex_matches_controlled(
    value: &str,
    path: &Path,
    control: &dyn OperationControl,
) -> Result<bool, OperationControlError> {
    use std::os::unix::ffi::OsStrExt as _;
    hex_matches_bytes_controlled(value, path.as_os_str().as_bytes(), control)
}

#[cfg(not(unix))]
fn path_hex_matches_controlled(
    value: &str,
    path: &Path,
    control: &dyn OperationControl,
) -> Result<bool, OperationControlError> {
    let Ok(bytes) = native_path_bytes(path) else {
        return Ok(false);
    };
    hex_matches_bytes_controlled(value, &bytes, control)
}

fn hex_matches_bytes_controlled(
    value: &str,
    expected: &[u8],
    control: &dyn OperationControl,
) -> Result<bool, OperationControlError> {
    if value.len() != expected.len().saturating_mul(2) {
        return Ok(false);
    }
    for (pairs, expected) in value
        .as_bytes()
        .chunks(CONTROL_CHUNK_BYTES.saturating_mul(2))
        .zip(expected.chunks(CONTROL_CHUNK_BYTES))
    {
        control.checkpoint()?;
        if !pairs.chunks_exact(2).zip(expected).all(|(pair, expected)| {
            decode_nibble(pair[0])
                .zip(decode_nibble(pair[1]))
                .is_some_and(|(high, low)| (high << 4) | low == *expected)
        }) {
            return Ok(false);
        }
    }
    control.checkpoint()?;
    Ok(true)
}

const fn decode_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(unix)]
fn native_path_bytes(path: &Path) -> Result<Vec<u8>, CacheCodecError> {
    use std::os::unix::ffi::OsStrExt as _;
    Ok(path.as_os_str().as_bytes().to_vec())
}

#[cfg(windows)]
fn native_path_bytes(path: &Path) -> Result<Vec<u8>, CacheCodecError> {
    use std::os::windows::ffi::OsStrExt as _;
    Ok(path
        .as_os_str()
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect())
}

#[cfg(not(any(unix, windows)))]
fn native_path_bytes(path: &Path) -> Result<Vec<u8>, CacheCodecError> {
    path.to_str()
        .map(|path| path.as_bytes().to_vec())
        .ok_or(CacheCodecError::Invalid)
}

#[cfg(unix)]
const fn platform_encoding() -> &'static str {
    "unix-bytes"
}

#[cfg(windows)]
const fn platform_encoding() -> &'static str {
    "windows-wide-le"
}

#[cfg(not(any(unix, windows)))]
const fn platform_encoding() -> &'static str {
    "utf8"
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;
    use std::io::Cursor;
    use std::path::PathBuf;

    use forge_core::{
        GitObjectFormat, OperationControl, OperationControlError, OperationPermit, RepoFacts,
        RepoId, parse_git_index_reader,
    };

    use super::*;

    #[derive(Debug, Default)]
    struct MemoryCache(RefCell<BTreeMap<String, Vec<u8>>>);

    impl InventoryCacheReadPort for MemoryCache {
        fn load(&self, key: &Digest, _max_bytes: usize) -> io::Result<Option<Vec<u8>>> {
            Ok(self.0.borrow().get(key.as_str()).cloned())
        }
    }

    impl InventoryCacheWritePort for MemoryCache {
        fn store_new(&self, key: &Digest, bytes: &[u8]) -> io::Result<()> {
            self.0
                .borrow_mut()
                .entry(key.as_str().to_owned())
                .or_insert_with(|| bytes.to_vec());
            Ok(())
        }
    }

    struct TestHasher;

    impl Hasher for TestHasher {
        fn digest(&self, chunks: &[&[u8]]) -> Digest {
            let mut state = 0xcbf2_9ce4_8422_2325_u64;
            for chunk in chunks {
                for byte in *chunk {
                    state ^= u64::from(*byte);
                    state = state.wrapping_mul(0x0000_0100_0000_01b3);
                }
            }
            Digest::new(format!("blake3:{state:016x}{}", "0".repeat(48)))
        }
    }

    struct CountingHasher {
        calls: Cell<usize>,
    }

    impl Hasher for CountingHasher {
        fn digest(&self, _chunks: &[&[u8]]) -> Digest {
            self.calls.set(self.calls.get().saturating_add(1));
            Digest::new(format!("blake3:{}", "0".repeat(64)))
        }
    }

    struct FailAtCheckpoint {
        calls: Cell<usize>,
        fail_at: usize,
        error: OperationControlError,
    }

    impl FailAtCheckpoint {
        const fn new(fail_at: usize, error: OperationControlError) -> Self {
            Self {
                calls: Cell::new(0),
                fail_at,
                error,
            }
        }
    }

    impl OperationControl for FailAtCheckpoint {
        fn checkpoint(&self) -> Result<OperationPermit, OperationControlError> {
            let call = self.calls.get().saturating_add(1);
            self.calls.set(call);
            if call >= self.fail_at {
                Err(self.error)
            } else {
                Ok(OperationPermit::unlimited())
            }
        }
    }

    fn rewrite_cache_envelope<F>(
        bytes: &[u8],
        hasher: &dyn Hasher,
        mutate: F,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>>
    where
        F: FnOnce(&mut CacheEnvelope),
    {
        let mut envelope: CacheEnvelope = serde_json::from_slice(bytes)?;
        mutate(&mut envelope);
        let payload_bytes = serde_json::to_vec(&envelope.payload)?;
        envelope.payload_digest = hasher
            .digest(&[PAYLOAD_DIGEST_DOMAIN, &payload_bytes])
            .as_str()
            .to_owned();
        Ok(serde_json::to_vec(&envelope)?)
    }

    fn cache_with(key: &Digest, bytes: Vec<u8>) -> MemoryCache {
        MemoryCache(RefCell::new(BTreeMap::from([(
            key.as_str().to_owned(),
            bytes,
        )])))
    }

    fn ordinary_index(paths: &[&str]) -> Result<Vec<GitIndexEntry>, Box<dyn std::error::Error>> {
        let mut records = Vec::new();
        for path in paths {
            records.extend_from_slice(b"H 100644 ");
            records.extend_from_slice(b"1111111111111111111111111111111111111111");
            records.extend_from_slice(b" 0\t");
            records.extend_from_slice(path.as_bytes());
            records.push(0);
        }
        Ok(parse_git_index_reader(
            Cursor::new(records),
            GitObjectFormat::Sha1,
            1024 * 1024,
            paths.len(),
        )?)
    }

    fn repository(
        work_state: WorkState,
    ) -> Result<RepositoryDetection, Box<dyn std::error::Error>> {
        Ok(RepositoryDetection {
            facts: RepoFacts {
                id: RepoId::new("repo:fixture"),
                root: PathBuf::from("/repo"),
                git_dir: PathBuf::from("/repo/.git"),
                git_common_dir: PathBuf::from("/repo/.git"),
                is_linked_worktree: false,
                head: None,
                branch: Some(String::from("main")),
                upstream: None,
                work_state,
            },
            status: None,
            provenance: Vec::new(),
            confidence: Confidence::High,
            diagnostics: Vec::new(),
        })
    }

    #[test]
    fn clean_commits_roundtrip_complete_native_inventory() -> Result<(), Box<dyn std::error::Error>>
    {
        let hasher = TestHasher;
        let options = InventoryOptions::default();
        let key = hasher.digest(&[b"fixture-key"]);
        let index_projection = hasher.digest(&[b"fixture-index-projection"]);
        let inventory = Inventory {
            entries: vec![InventoryEntry {
                path: PathBuf::from("src/lib.rs"),
                kind: InventoryKind::File,
                size_bytes: Some(7),
            }],
            skipped: Vec::new(),
        };
        let cache = MemoryCache::default();
        let index = ordinary_index(&["src/lib.rs"])?;

        let publication = prepare_cached_inventory(&key, &index_projection, &inventory, &hasher)
            .ok_or("complete inventory did not produce a cache publication")?;
        publish_cached_inventory(&cache, &publication)?;
        assert_eq!(
            load_cached_inventory(&cache, &key, &index_projection, &index, options, &hasher,),
            Some(Inventory {
                entries: vec![InventoryEntry {
                    path: PathBuf::from("src/lib.rs"),
                    kind: InventoryKind::File,
                    size_bytes: None,
                }],
                skipped: Vec::new(),
            })
        );
        assert!(
            load_cached_inventory(
                &cache,
                &key,
                &hasher.digest(&[b"different-index-projection"]),
                &index,
                options,
                &hasher,
            )
            .is_none(),
            "a payload is bound to the semantic index projection used to publish it"
        );
        assert!(
            inventory_cache_key(
                &repository(WorkState::Dirty)?,
                &index_projection,
                options,
                &Digest::new(format!("blake3:{}", "b".repeat(64))),
                PolicyBaseCompleteness::Complete,
                &hasher,
            )
            .is_none()
        );
        assert!(
            inventory_cache_key(
                &repository(WorkState::Clean)?,
                &index_projection,
                options,
                &Digest::new(format!("blake3:{}", "b".repeat(64))),
                PolicyBaseCompleteness::Complete,
                &hasher,
            )
            .is_none(),
            "an unborn repository has no commit-addressed cache key"
        );
        Ok(())
    }

    #[test]
    fn controlled_cache_stops_before_hashing_later_work() -> Result<(), Box<dyn std::error::Error>>
    {
        let key = Digest::new(format!("blake3:{}", "1".repeat(64)));
        let projection = Digest::new(format!("blake3:{}", "2".repeat(64)));
        let inventory = Inventory {
            entries: vec![
                InventoryEntry {
                    path: PathBuf::from("a"),
                    kind: InventoryKind::File,
                    size_bytes: Some(1),
                },
                InventoryEntry {
                    path: PathBuf::from("b"),
                    kind: InventoryKind::File,
                    size_bytes: Some(1),
                },
            ],
            skipped: Vec::new(),
        };
        let hasher = CountingHasher {
            calls: Cell::new(0),
        };
        let control = FailAtCheckpoint::new(2, OperationControlError::Interrupted);

        let result =
            prepare_cached_inventory_controlled(&key, &projection, &inventory, &hasher, &control);

        assert_eq!(result.err(), Some(OperationControlError::Interrupted));
        assert_eq!(hasher.calls.get(), 0, "encoding continued into digest work");

        let publication = prepare_cached_inventory(&key, &projection, &inventory, &TestHasher)
            .ok_or("fixture cache publication was not prepared")?;
        let cache = cache_with(&key, publication.bytes.clone());
        let hasher = CountingHasher {
            calls: Cell::new(0),
        };
        let control = FailAtCheckpoint::new(3, OperationControlError::TimedOut);
        let result = load_cached_inventory_controlled(
            &cache,
            &key,
            &projection,
            &ordinary_index(&["a", "b"])?,
            InventoryOptions::default(),
            &hasher,
            &control,
        );
        assert_eq!(result.err(), Some(OperationControlError::TimedOut));
        assert_eq!(hasher.calls.get(), 0, "decode continued into digest work");
        Ok(())
    }

    #[test]
    fn raw_index_identity_and_regular_file_eligibility_are_independent_contracts()
    -> Result<(), Box<dyn std::error::Error>> {
        let hasher = TestHasher;
        let path = RepoRelativePath::new("src/lib.rs")?;
        let file_set = GitFileSet::new(vec![path], Vec::new());
        let parse = |mode: &str, object_id: u8| {
            let record = format!(
                "H {mode} {} 0\tsrc/lib.rs\0",
                char::from(object_id).to_string().repeat(40)
            );
            parse_git_index_reader(
                Cursor::new(record.into_bytes()),
                GitObjectFormat::Sha1,
                1024,
                1,
            )
        };
        let baseline = parse("100644", b'1')?;
        let different_object = parse("100644", b'2')?;
        let different_mode = parse("100755", b'1')?;
        let inventory = Inventory {
            entries: vec![InventoryEntry {
                path: PathBuf::from("src/lib.rs"),
                kind: InventoryKind::File,
                size_bytes: Some(7),
            }],
            skipped: Vec::new(),
        };

        assert!(inventory_cache_basis_is_eligible(
            &file_set, &baseline, &inventory
        ));
        assert!(inventory_cache_basis_is_eligible(
            &file_set,
            &different_object,
            &inventory
        ));
        assert!(inventory_cache_basis_is_eligible(
            &file_set,
            &different_mode,
            &inventory
        ));
        assert_ne!(
            index_projection_digest(&baseline, &hasher),
            index_projection_digest(&different_object, &hasher)
        );
        assert_ne!(
            index_projection_digest(&baseline, &hasher),
            index_projection_digest(&different_mode, &hasher)
        );
        let gitlink = parse("160000", b'1')?;
        assert!(
            !inventory_cache_basis_is_eligible(&file_set, &gitlink, &inventory),
            "Gitlinks require the authoritative inventory path"
        );
        assert!(index_projection_digest(&gitlink, &hasher).is_none());
        Ok(())
    }

    #[test]
    fn malformed_or_forged_cache_envelopes_are_never_reused()
    -> Result<(), Box<dyn std::error::Error>> {
        let hasher = TestHasher;
        let key = hasher.digest(&[b"cache-key"]);
        let projection = hasher.digest(&[b"index-projection"]);
        let options = InventoryOptions::default();
        let inventory = Inventory {
            entries: vec![InventoryEntry {
                path: PathBuf::from("src/lib.rs"),
                kind: InventoryKind::File,
                size_bytes: Some(7),
            }],
            skipped: Vec::new(),
        };
        let valid = prepare_cached_inventory(&key, &projection, &inventory, &hasher)
            .ok_or("valid inventory did not produce a publication")?
            .bytes;
        let index = ordinary_index(&["src/lib.rs"])?;
        let absolute_path = encode_hex(
            &native_path_bytes(&std::env::current_dir()?)
                .map_err(|_| io::Error::other("current directory has no native path encoding"))?,
        );

        let mut invalid = Vec::new();
        invalid.push(rewrite_cache_envelope(&valid, &hasher, |envelope| {
            envelope.key = String::from("wrong-key");
        })?);
        invalid.push(rewrite_cache_envelope(&valid, &hasher, |envelope| {
            envelope.payload.eligibility.index_projection = String::from("wrong-projection");
        })?);
        invalid.push(rewrite_cache_envelope(&valid, &hasher, |envelope| {
            envelope.payload.platform_encoding = String::from("wrong-platform");
        })?);
        invalid.push(rewrite_cache_envelope(&valid, &hasher, |envelope| {
            envelope.payload.eligibility.rule = String::from("wrong-rule");
        })?);
        invalid.push(rewrite_cache_envelope(&valid, &hasher, |envelope| {
            envelope.payload.eligibility.entry_count = 2;
        })?);
        invalid.push(rewrite_cache_envelope(&valid, &hasher, |envelope| {
            envelope.payload.entries[0].path_hex = encode_hex(b"../escape");
        })?);
        invalid.push(rewrite_cache_envelope(&valid, &hasher, |envelope| {
            envelope.payload.entries[0].path_hex = absolute_path;
        })?);
        invalid.push(rewrite_cache_envelope(&valid, &hasher, |envelope| {
            envelope.payload.entries[0].path_hex = String::new();
        })?);
        invalid.push(rewrite_cache_envelope(&valid, &hasher, |envelope| {
            envelope.payload.entries.push(CacheEntry {
                path_hex: encode_hex(b"src/lib.rs"),
            });
            envelope.payload.eligibility.entry_count = 2;
        })?);
        let mut wrong_digest = valid.clone();
        let digest_marker = b"payload_digest\":";
        let digest_offset = wrong_digest
            .windows(digest_marker.len())
            .position(|window| window == digest_marker)
            .ok_or("valid cache envelope omitted payload_digest")?;
        let value_offset = digest_offset + digest_marker.len() + 1;
        wrong_digest[value_offset] = if wrong_digest[value_offset] == b'0' {
            b'1'
        } else {
            b'0'
        };
        invalid.push(wrong_digest);
        let mut trailing = valid.clone();
        trailing.extend_from_slice(b"not-json-whitespace");
        invalid.push(trailing);
        let mut unknown: serde_json::Value = serde_json::from_slice(&valid)?;
        unknown
            .as_object_mut()
            .ok_or("cache envelope was not a JSON object")?
            .insert(String::from("unknown"), serde_json::Value::Bool(true));
        invalid.push(serde_json::to_vec(&unknown)?);

        for (case, bytes) in invalid.into_iter().enumerate() {
            assert!(
                load_cached_inventory(
                    &cache_with(&key, bytes),
                    &key,
                    &projection,
                    &index,
                    options,
                    &hasher,
                )
                .is_none(),
                "malformed cache case {case} was reused"
            );
        }
        Ok(())
    }

    #[test]
    fn cache_reader_enforces_its_bound_even_if_the_port_does_not() {
        let hasher = TestHasher;
        let key = hasher.digest(&[b"cache-key"]);
        let projection = hasher.digest(&[b"index-projection"]);
        let cache = cache_with(&key, vec![b' '; MAX_INVENTORY_CACHE_BYTES + 1]);

        assert!(
            load_cached_inventory(
                &cache,
                &key,
                &projection,
                &[],
                InventoryOptions::default(),
                &hasher,
            )
            .is_none()
        );
    }
}
