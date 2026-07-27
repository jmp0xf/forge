//! Canonical aggregation of already-prepared repository scope identities.
//!
//! This module deliberately performs no Git or filesystem access. The acquisition layer must
//! first determine the complete intent scope, read every dirty/untracked file or symlink target,
//! and construct [`PreparedScope`] only when every input is known. An acquisition or read failure
//! must be represented as [`DependencyValue::Unknown`]; it must never be replaced with an empty,
//! partial, mtime-only, or size-only scope.

use forge_schema::Digest;
use thiserror::Error;

use crate::evidence::DependencyValue;
use crate::fingerprint::canonical_native_path_bytes;
use crate::git::{GitMode, GitObjectFormat};
use crate::path::RepoRelativePath;
use crate::ports::Hasher;

const SCOPE_DIGEST_DOMAIN: &[u8] = b"forge.scope-digest/v1";
const SCOPE_DIGEST_INPUT_VERSION: &str = "forge.scope-digest-input/v1";

/// One validated Git object identity in the repository's configured object format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeObjectId {
    object_format: GitObjectFormat,
    lowercase_hex: Vec<u8>,
}

impl ScopeObjectId {
    /// Validates and canonicalizes an object ID supplied by the Git acquisition layer.
    pub fn new(
        object_format: GitObjectFormat,
        hexadecimal: &[u8],
    ) -> Result<Self, ScopeDigestError> {
        let expected_width = match object_format {
            GitObjectFormat::Sha1 => 40,
            GitObjectFormat::Sha256 => 64,
        };
        if hexadecimal.len() != expected_width
            || !hexadecimal.iter().all(u8::is_ascii_hexdigit)
            || hexadecimal.iter().all(|byte| *byte == b'0')
        {
            return Err(ScopeDigestError::InvalidObjectId);
        }

        Ok(Self {
            object_format,
            lowercase_hex: hexadecimal.iter().map(u8::to_ascii_lowercase).collect(),
        })
    }

    #[must_use]
    pub const fn object_format(&self) -> GitObjectFormat {
        self.object_format
    }

    /// Returns the canonical full object ID for versioned comparison contracts.
    #[must_use]
    pub fn lowercase_hex(&self) -> &[u8] {
        &self.lowercase_hex
    }
}

/// The repository's known `HEAD` state.
///
/// Object format remains explicit for an unborn repository because it governs any staged blob
/// identities and separates otherwise-empty SHA-1 and SHA-256 repositories.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeHead {
    Commit(ScopeObjectId),
    Unborn(GitObjectFormat),
}

impl ScopeHead {
    #[must_use]
    pub const fn object_format(&self) -> GitObjectFormat {
        match self {
            Self::Commit(object_id) => object_id.object_format(),
            Self::Unborn(object_format) => *object_format,
        }
    }
}

/// A canonical Git file mode that may appear in an input scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ScopeMode {
    Regular,
    Executable,
    Symlink,
    Gitlink,
}

impl ScopeMode {
    #[must_use]
    const fn as_bytes(self) -> &'static [u8; 6] {
        match self {
            Self::Regular => b"100644",
            Self::Executable => b"100755",
            Self::Symlink => b"120000",
            Self::Gitlink => b"160000",
        }
    }
}

impl TryFrom<GitMode> for ScopeMode {
    type Error = ScopeDigestError;

    fn try_from(mode: GitMode) -> Result<Self, Self::Error> {
        match mode.as_bytes() {
            b"100644" => Ok(Self::Regular),
            b"100755" => Ok(Self::Executable),
            b"120000" => Ok(Self::Symlink),
            b"160000" => Ok(Self::Gitlink),
            _ => Err(ScopeDigestError::UnsupportedMode),
        }
    }
}

/// Dirty-state bits retained for a Gitlink boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GitlinkDirtyState {
    commit_changed: bool,
    tracked_changes: bool,
    untracked_changes: bool,
}

impl GitlinkDirtyState {
    #[must_use]
    pub const fn new(commit_changed: bool, tracked_changes: bool, untracked_changes: bool) -> Self {
        Self {
            commit_changed,
            tracked_changes,
            untracked_changes,
        }
    }

    #[must_use]
    const fn is_dirty(self) -> bool {
        self.commit_changed || self.tracked_changes || self.untracked_changes
    }
}

/// The complete, already-computed identity of one scope entry's content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeContentIdentity {
    /// An unchanged tracked file or symlink, identified by its index blob.
    IndexBlob(ScopeObjectId),
    /// Complete bytes of a dirty/untracked file, or the link content of a symlink.
    WorktreeBlake3([u8; 32]),
    /// A non-recursive submodule boundary: Gitlink OID plus all porcelain dirty-state bits.
    ///
    /// [`PreparedScopeEntry::new`] accepts this identity only when every dirty bit is false. v0
    /// cannot distinguish different nested changes without recursively hashing the submodule, so a
    /// dirty Gitlink must make acquisition unknown instead of producing a reusable scope digest.
    Gitlink {
        object_id: ScopeObjectId,
        dirty: GitlinkDirtyState,
    },
}

impl ScopeContentIdentity {
    /// Parses a canonical `blake3:<64 lowercase hex>` complete-content digest.
    ///
    /// Computing the digest, including streaming every byte, belongs to the acquisition layer.
    pub fn worktree_blake3(digest: &Digest) -> Result<Self, ScopeDigestError> {
        let Some(hexadecimal) = digest.as_str().strip_prefix("blake3:") else {
            return Err(ScopeDigestError::InvalidWorktreeDigest);
        };
        if hexadecimal.len() != 64
            || !hexadecimal
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(ScopeDigestError::InvalidWorktreeDigest);
        }

        let mut bytes = [0_u8; 32];
        for (target, pair) in bytes.iter_mut().zip(hexadecimal.as_bytes().chunks_exact(2)) {
            let high = decode_lower_hex(pair[0]).ok_or(ScopeDigestError::InvalidWorktreeDigest)?;
            let low = decode_lower_hex(pair[1]).ok_or(ScopeDigestError::InvalidWorktreeDigest)?;
            *target = (high << 4) | low;
        }
        Ok(Self::WorktreeBlake3(bytes))
    }

    #[must_use]
    fn object_format(&self) -> Option<GitObjectFormat> {
        match self {
            Self::IndexBlob(object_id) | Self::Gitlink { object_id, .. } => {
                Some(object_id.object_format())
            }
            Self::WorktreeBlake3(_) => None,
        }
    }

    #[must_use]
    const fn is_gitlink(&self) -> bool {
        matches!(self, Self::Gitlink { .. })
    }
}

/// One validated path/mode/content-identity tuple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedScopeEntry {
    path: RepoRelativePath,
    mode: ScopeMode,
    content_identity: ScopeContentIdentity,
}

impl PreparedScopeEntry {
    pub fn new(
        path: RepoRelativePath,
        mode: ScopeMode,
        content_identity: ScopeContentIdentity,
    ) -> Result<Self, ScopeDigestError> {
        if path.as_path() == std::path::Path::new(".") {
            return Err(ScopeDigestError::RepositoryRootEntry);
        }
        if (mode == ScopeMode::Gitlink) != content_identity.is_gitlink() {
            return Err(ScopeDigestError::ModeContentMismatch);
        }
        if matches!(
            &content_identity,
            ScopeContentIdentity::Gitlink { dirty, .. } if dirty.is_dirty()
        ) {
            return Err(ScopeDigestError::DirtyGitlink);
        }

        Ok(Self {
            path,
            mode,
            content_identity,
        })
    }

    #[must_use]
    fn canonical_path(&self) -> Vec<u8> {
        canonical_native_path_bytes(self.path.as_path())
    }
}

/// A complete, immutable scope ready for canonical aggregation.
///
/// Entries are sorted by their lossless native path representation. Duplicate paths are rejected
/// instead of silently choosing one identity. With that uniqueness invariant, sorting by path is
/// equivalent to sorting the accepted `(path, mode, content_identity)` tuples.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedScope {
    head: ScopeHead,
    entries: Vec<PreparedScopeEntry>,
}

impl PreparedScope {
    pub fn new(
        head: ScopeHead,
        mut entries: Vec<PreparedScopeEntry>,
    ) -> Result<Self, ScopeDigestError> {
        let object_format = head.object_format();
        if entries.iter().any(|entry| {
            entry
                .content_identity
                .object_format()
                .is_some_and(|entry_format| entry_format != object_format)
        }) {
            return Err(ScopeDigestError::ObjectFormatMismatch);
        }

        entries.sort_by_cached_key(PreparedScopeEntry::canonical_path);
        if entries
            .windows(2)
            .any(|pair| pair[0].canonical_path() == pair[1].canonical_path())
        {
            return Err(ScopeDigestError::DuplicatePath);
        }

        Ok(Self { head, entries })
    }

    #[must_use]
    pub const fn head(&self) -> &ScopeHead {
        &self.head
    }

    #[must_use]
    pub fn entries(&self) -> &[PreparedScopeEntry] {
        &self.entries
    }
}

/// Content-safe failures that prevent construction of a canonical scope input.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ScopeDigestError {
    #[error("scope Git object ID is invalid for its object format")]
    InvalidObjectId,
    #[error("scope worktree content digest is not canonical BLAKE3")]
    InvalidWorktreeDigest,
    #[error("scope contains a Git file mode that v0 cannot represent")]
    UnsupportedMode,
    #[error("scope entries must identify a file, symlink, or Gitlink, not the repository root")]
    RepositoryRootEntry,
    #[error("scope contains the same native repository path more than once")]
    DuplicatePath,
    #[error("scope Gitlink mode and content identity disagree")]
    ModeContentMismatch,
    #[error("a dirty Gitlink cannot produce a complete non-recursive v0 scope")]
    DirtyGitlink,
    #[error("scope object identity uses a different Git object format than the repository")]
    ObjectFormatMismatch,
}

/// Computes the canonical digest of one complete prepared scope without taking ownership.
///
/// A [`PreparedScope`] can be large. Callers that already proved acquisition completeness can use
/// this borrowed form to bind the scope into multiple checks without cloning its entries.
#[must_use]
pub fn prepared_scope_dependency_digest<H: Hasher + ?Sized>(
    hasher: &H,
    scope: &PreparedScope,
) -> Digest {
    let mut encoder = CanonicalEncoder::new("scope");
    encoder.text("format-version", SCOPE_DIGEST_INPUT_VERSION);
    encoder.bytes("head", &encode_head(&scope.head));
    encoder.sequence("entries", &scope.entries, encode_entry);
    hasher.digest(&[SCOPE_DIGEST_DOMAIN, &encoder.finish()])
}

/// Computes the canonical dependency digest only for a complete prepared scope.
///
/// `Unknown` is returned without invoking `Hasher`, making it impossible for an I/O caller to
/// accidentally turn a failed or partial acquisition into a reusable digest.
#[must_use]
pub fn scope_dependency_digest<H: Hasher + ?Sized>(
    hasher: &H,
    scope: &DependencyValue<PreparedScope>,
) -> DependencyValue<Digest> {
    let DependencyValue::Known(scope) = scope else {
        return DependencyValue::Unknown;
    };

    DependencyValue::Known(prepared_scope_dependency_digest(hasher, scope))
}

fn encode_head(head: &ScopeHead) -> Vec<u8> {
    let mut encoder = CanonicalEncoder::new("scope-head");
    match head {
        ScopeHead::Commit(object_id) => {
            encoder.text("variant", "commit");
            encoder.bytes("object-id", &encode_object_id(object_id));
        }
        ScopeHead::Unborn(object_format) => {
            encoder.text("variant", "unborn");
            encoder.text("object-format", object_format_name(*object_format));
        }
    }
    encoder.finish()
}

fn encode_entry(entry: &PreparedScopeEntry) -> Vec<u8> {
    let mut encoder = CanonicalEncoder::new("scope-entry");
    encoder.bytes("path", &entry.canonical_path());
    encoder.bytes("mode", entry.mode.as_bytes());
    encoder.bytes(
        "content-identity",
        &encode_content_identity(&entry.content_identity),
    );
    encoder.finish()
}

fn encode_content_identity(identity: &ScopeContentIdentity) -> Vec<u8> {
    let mut encoder = CanonicalEncoder::new("scope-content-identity");
    match identity {
        ScopeContentIdentity::IndexBlob(object_id) => {
            encoder.text("variant", "index-blob");
            encoder.bytes("object-id", &encode_object_id(object_id));
        }
        ScopeContentIdentity::WorktreeBlake3(digest) => {
            encoder.text("variant", "worktree-blake3");
            encoder.bytes("digest", digest);
        }
        ScopeContentIdentity::Gitlink { object_id, dirty } => {
            encoder.text("variant", "gitlink");
            encoder.bytes("object-id", &encode_object_id(object_id));
            encoder.boolean("commit-changed", dirty.commit_changed);
            encoder.boolean("tracked-changes", dirty.tracked_changes);
            encoder.boolean("untracked-changes", dirty.untracked_changes);
        }
    }
    encoder.finish()
}

fn encode_object_id(object_id: &ScopeObjectId) -> Vec<u8> {
    let mut encoder = CanonicalEncoder::new("git-object-id");
    encoder.text("object-format", object_format_name(object_id.object_format));
    encoder.bytes("lowercase-hex", &object_id.lowercase_hex);
    encoder.finish()
}

const fn object_format_name(object_format: GitObjectFormat) -> &'static str {
    match object_format {
        GitObjectFormat::Sha1 => "sha1",
        GitObjectFormat::Sha256 => "sha256",
    }
}

const fn decode_lower_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[derive(Debug)]
struct CanonicalEncoder {
    bytes: Vec<u8>,
}

impl CanonicalEncoder {
    fn new(record_type: &str) -> Self {
        let mut encoder = Self { bytes: Vec::new() };
        encoder.text("record-type", record_type);
        encoder
    }

    fn text(&mut self, field: &str, value: &str) {
        self.bytes(field, value.as_bytes());
    }

    fn boolean(&mut self, field: &str, value: bool) {
        self.bytes(field, &[u8::from(value)]);
    }

    fn bytes(&mut self, field: &str, value: &[u8]) {
        self.bytes.push(1);
        append_length_prefixed(&mut self.bytes, field.as_bytes());
        append_length_prefixed(&mut self.bytes, value);
    }

    fn sequence<T>(
        &mut self,
        field: &str,
        values: impl IntoIterator<Item = T>,
        encode: impl Fn(T) -> Vec<u8>,
    ) {
        let values: Vec<Vec<u8>> = values.into_iter().map(encode).collect();
        let mut sequence = Vec::new();
        sequence.extend_from_slice(&(values.len() as u128).to_be_bytes());
        for value in values {
            append_length_prefixed(&mut sequence, &value);
        }
        self.bytes(field, &sequence);
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

fn append_length_prefixed(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u128).to_be_bytes());
    output.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::error::Error;
    use std::path::PathBuf;

    use forge_schema::Digest;

    use super::{
        GitlinkDirtyState, PreparedScope, PreparedScopeEntry, ScopeContentIdentity,
        ScopeDigestError, ScopeHead, ScopeMode, ScopeObjectId, prepared_scope_dependency_digest,
        scope_dependency_digest,
    };
    use crate::evidence::DependencyValue;
    use crate::git::GitObjectFormat;
    use crate::path::RepoRelativePath;
    use crate::ports::Hasher;

    #[derive(Debug, Default)]
    struct FixtureHasher;

    impl Hasher for FixtureHasher {
        fn digest(&self, chunks: &[&[u8]]) -> Digest {
            let mut framed = Vec::new();
            for chunk in chunks {
                framed.extend_from_slice(&(chunk.len() as u128).to_be_bytes());
                framed.extend_from_slice(chunk);
            }
            Digest::new(format!("fixture:{}", lower_hex(&framed)))
        }
    }

    #[derive(Debug, Default)]
    struct SpyHasher {
        calls: Cell<usize>,
    }

    impl Hasher for SpyHasher {
        fn digest(&self, _chunks: &[&[u8]]) -> Digest {
            self.calls.set(self.calls.get() + 1);
            Digest::from("fixture:called")
        }
    }

    /// Small, deterministic test-only digest with explicit top-level chunk framing.
    ///
    /// This is not a production security primitive. Its fixed output pins the scope protocol
    /// preimage while production BLAKE3 remains the responsibility of `forge-runtime`.
    #[derive(Debug, Default)]
    struct VectorHasher;

    impl Hasher for VectorHasher {
        fn digest(&self, chunks: &[&[u8]]) -> Digest {
            const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
            const PRIME: u64 = 0x0000_0100_0000_01b3;

            let mut state = OFFSET_BASIS;
            for byte in b"forge.scope-fixture-fnv1a64/v1" {
                state = (state ^ u64::from(*byte)).wrapping_mul(PRIME);
            }
            for chunk in chunks {
                for byte in (chunk.len() as u128).to_be_bytes().iter().chain(*chunk) {
                    state = (state ^ u64::from(*byte)).wrapping_mul(PRIME);
                }
            }
            Digest::new(format!("fixture-fnv1a64:{state:016x}"))
        }
    }

    fn lower_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }

    fn sha1(seed: u8) -> Result<ScopeObjectId, ScopeDigestError> {
        ScopeObjectId::new(GitObjectFormat::Sha1, &[seed; 40])
    }

    fn sha256(seed: u8) -> Result<ScopeObjectId, ScopeDigestError> {
        ScopeObjectId::new(GitObjectFormat::Sha256, &[seed; 64])
    }

    fn worktree(seed: char) -> Result<ScopeContentIdentity, ScopeDigestError> {
        ScopeContentIdentity::worktree_blake3(&Digest::new(format!(
            "blake3:{}",
            seed.to_string().repeat(64)
        )))
    }

    fn entry(
        path: impl Into<PathBuf>,
        mode: ScopeMode,
        content_identity: ScopeContentIdentity,
    ) -> Result<PreparedScopeEntry, Box<dyn Error>> {
        Ok(PreparedScopeEntry::new(
            RepoRelativePath::new(path.into())?,
            mode,
            content_identity,
        )?)
    }

    fn scope(
        head: ScopeHead,
        entries: Vec<PreparedScopeEntry>,
    ) -> Result<DependencyValue<PreparedScope>, ScopeDigestError> {
        Ok(DependencyValue::Known(PreparedScope::new(head, entries)?))
    }

    fn digest(scope: &DependencyValue<PreparedScope>) -> DependencyValue<Digest> {
        scope_dependency_digest(&FixtureHasher, scope)
    }

    #[test]
    fn entry_order_does_not_change_the_digest() -> Result<(), Box<dyn Error>> {
        let first = entry(
            "src/lib.rs",
            ScopeMode::Regular,
            ScopeContentIdentity::IndexBlob(sha1(b'a')?),
        )?;
        let second = entry("tests/smoke.rs", ScopeMode::Regular, worktree('b')?)?;
        let forward = scope(
            ScopeHead::Commit(sha1(b'c')?),
            vec![first.clone(), second.clone()],
        )?;
        let reverse = scope(ScopeHead::Commit(sha1(b'c')?), vec![second, first])?;

        assert_eq!(digest(&forward), digest(&reverse));
        Ok(())
    }

    #[test]
    fn duplicate_native_paths_are_rejected_even_when_other_fields_differ()
    -> Result<(), Box<dyn Error>> {
        let first = entry(
            "src/lib.rs",
            ScopeMode::Regular,
            ScopeContentIdentity::IndexBlob(sha1(b'a')?),
        )?;
        let second = entry("src/lib.rs", ScopeMode::Executable, worktree('b')?)?;

        assert_eq!(
            PreparedScope::new(ScopeHead::Commit(sha1(b'c')?), vec![first, second]),
            Err(ScopeDigestError::DuplicatePath)
        );
        Ok(())
    }

    #[test]
    fn head_mode_and_content_changes_each_change_the_digest() -> Result<(), Box<dyn Error>> {
        let baseline = scope(
            ScopeHead::Commit(sha1(b'a')?),
            vec![entry("src/lib.rs", ScopeMode::Regular, worktree('b')?)?],
        )?;
        let changed_head = scope(
            ScopeHead::Commit(sha1(b'c')?),
            vec![entry("src/lib.rs", ScopeMode::Regular, worktree('b')?)?],
        )?;
        let unborn = scope(
            ScopeHead::Unborn(GitObjectFormat::Sha1),
            vec![entry("src/lib.rs", ScopeMode::Regular, worktree('b')?)?],
        )?;
        let changed_mode = scope(
            ScopeHead::Commit(sha1(b'a')?),
            vec![entry("src/lib.rs", ScopeMode::Executable, worktree('b')?)?],
        )?;
        let changed_content = scope(
            ScopeHead::Commit(sha1(b'a')?),
            vec![entry("src/lib.rs", ScopeMode::Regular, worktree('c')?)?],
        )?;

        let expected = digest(&baseline);
        for changed in [&changed_head, &unborn, &changed_mode, &changed_content] {
            assert_ne!(digest(changed), expected);
        }
        Ok(())
    }

    #[test]
    fn object_format_is_canonical_and_repository_wide() -> Result<(), Box<dyn Error>> {
        assert_eq!(
            ScopeObjectId::new(GitObjectFormat::Sha1, &[b'A'; 40])?.lowercase_hex(),
            &[b'a'; 40]
        );
        let lowercase = scope(
            ScopeHead::Commit(sha1(b'a')?),
            vec![entry(
                "src/lib.rs",
                ScopeMode::Regular,
                ScopeContentIdentity::IndexBlob(sha1(b'b')?),
            )?],
        )?;
        let uppercase = scope(
            ScopeHead::Commit(sha1(b'A')?),
            vec![entry(
                "src/lib.rs",
                ScopeMode::Regular,
                ScopeContentIdentity::IndexBlob(sha1(b'B')?),
            )?],
        )?;
        assert_eq!(digest(&lowercase), digest(&uppercase));

        let mismatched = PreparedScope::new(
            ScopeHead::Commit(sha1(b'a')?),
            vec![entry(
                "src/lib.rs",
                ScopeMode::Regular,
                ScopeContentIdentity::IndexBlob(sha256(b'b')?),
            )?],
        );
        assert_eq!(mismatched, Err(ScopeDigestError::ObjectFormatMismatch));

        let sha256_scope = scope(
            ScopeHead::Commit(sha256(b'a')?),
            vec![entry(
                "src/lib.rs",
                ScopeMode::Regular,
                ScopeContentIdentity::IndexBlob(sha256(b'b')?),
            )?],
        )?;
        assert_ne!(digest(&lowercase), digest(&sha256_scope));
        Ok(())
    }

    #[test]
    fn canonical_scope_protocol_has_a_fixed_vector() -> Result<(), Box<dyn Error>> {
        let prepared = scope(
            ScopeHead::Commit(sha1(b'A')?),
            vec![
                entry("src/lib.rs", ScopeMode::Regular, worktree('b')?)?,
                entry(
                    "tests/smoke.rs",
                    ScopeMode::Executable,
                    ScopeContentIdentity::IndexBlob(sha1(b'C')?),
                )?,
            ],
        )?;
        let DependencyValue::Known(scope) = &prepared else {
            unreachable!("the fixture constructs a complete prepared scope")
        };
        let expected = Digest::from("fixture-fnv1a64:87f0bec6599c3a7f");
        let borrowed = prepared_scope_dependency_digest(&VectorHasher, scope);

        assert_eq!(borrowed, expected);
        assert_eq!(
            scope_dependency_digest(&VectorHasher, &prepared),
            DependencyValue::Known(borrowed)
        );
        Ok(())
    }

    #[test]
    fn every_dirty_gitlink_is_rejected_instead_of_colliding() -> Result<(), Box<dyn Error>> {
        for dirty in [
            GitlinkDirtyState::new(true, false, false),
            GitlinkDirtyState::new(false, true, false),
            GitlinkDirtyState::new(false, false, true),
            GitlinkDirtyState::new(true, true, true),
        ] {
            assert_eq!(
                PreparedScopeEntry::new(
                    RepoRelativePath::new("vendor/dependency")?,
                    ScopeMode::Gitlink,
                    ScopeContentIdentity::Gitlink {
                        object_id: sha1(b'b')?,
                        dirty,
                    },
                ),
                Err(ScopeDigestError::DirtyGitlink)
            );
        }
        Ok(())
    }

    #[test]
    fn gitlink_mode_and_identity_must_agree() -> Result<(), Box<dyn Error>> {
        let object_id = sha1(b'a')?;
        let dirty = GitlinkDirtyState::new(false, false, false);
        let path = RepoRelativePath::new("vendor/dependency")?;

        assert_eq!(
            PreparedScopeEntry::new(
                path.clone(),
                ScopeMode::Regular,
                ScopeContentIdentity::Gitlink {
                    object_id: object_id.clone(),
                    dirty,
                },
            )
            .map(|_| ()),
            Err(ScopeDigestError::ModeContentMismatch)
        );
        assert_eq!(
            PreparedScopeEntry::new(
                path,
                ScopeMode::Gitlink,
                ScopeContentIdentity::IndexBlob(object_id),
            )
            .map(|_| ()),
            Err(ScopeDigestError::ModeContentMismatch)
        );
        Ok(())
    }

    #[test]
    fn invalid_prepared_values_never_reach_the_hasher() -> Result<(), Box<dyn Error>> {
        for invalid in [
            ScopeObjectId::new(GitObjectFormat::Sha1, b"abc").map(|_| ()),
            ScopeObjectId::new(GitObjectFormat::Sha1, &[b'g'; 40]).map(|_| ()),
            ScopeObjectId::new(GitObjectFormat::Sha1, &[b'0'; 40]).map(|_| ()),
            ScopeObjectId::new(GitObjectFormat::Sha256, &[b'0'; 64]).map(|_| ()),
            ScopeContentIdentity::worktree_blake3(&Digest::from("sha256:wrong")).map(|_| ()),
            ScopeContentIdentity::worktree_blake3(&Digest::new(format!(
                "blake3:{}",
                "A".repeat(64)
            )))
            .map(|_| ()),
        ] {
            assert!(invalid.is_err());
        }
        assert_eq!(
            PreparedScopeEntry::new(RepoRelativePath::root(), ScopeMode::Regular, worktree('a')?,)
                .map(|_| ()),
            Err(ScopeDigestError::RepositoryRootEntry)
        );
        Ok(())
    }

    #[test]
    fn unknown_acquisition_never_invokes_the_hasher() {
        let hasher = SpyHasher::default();

        assert_eq!(
            scope_dependency_digest(&hasher, &DependencyValue::Unknown),
            DependencyValue::Unknown
        );
        assert_eq!(hasher.calls.get(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_paths_are_lossless_and_distinct_from_lossy_display() -> Result<(), Box<dyn Error>> {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt as _;

        let native = PathBuf::from(OsString::from_vec(b"src/bad-\xff.rs".to_vec()));
        let display = PathBuf::from("src/bad-\u{fffd}.rs");
        let native_scope = scope(
            ScopeHead::Commit(sha1(b'a')?),
            vec![entry(native, ScopeMode::Regular, worktree('b')?)?],
        )?;
        let display_scope = scope(
            ScopeHead::Commit(sha1(b'a')?),
            vec![entry(display, ScopeMode::Regular, worktree('b')?)?],
        )?;

        assert_ne!(digest(&native_scope), digest(&display_scope));
        Ok(())
    }

    #[test]
    fn mode_conversion_accepts_only_canonical_scope_file_modes() {
        // The conversion is covered end-to-end by Git parser tests. This assertion freezes the
        // canonical byte projection without introducing a second public mode parser here.
        assert_eq!(ScopeMode::Regular.as_bytes(), b"100644");
        assert_eq!(ScopeMode::Executable.as_bytes(), b"100755");
        assert_eq!(ScopeMode::Symlink.as_bytes(), b"120000");
        assert_eq!(ScopeMode::Gitlink.as_bytes(), b"160000");
    }

    #[test]
    fn known_scope_invokes_the_hasher_once() -> Result<(), Box<dyn Error>> {
        let hasher = SpyHasher::default();
        let prepared = scope(
            ScopeHead::Commit(sha1(b'a')?),
            vec![entry("src/lib.rs", ScopeMode::Regular, worktree('b')?)?],
        )?;

        assert_eq!(
            scope_dependency_digest(&hasher, &prepared),
            DependencyValue::Known(Digest::from("fixture:called"))
        );
        assert_eq!(hasher.calls.get(), 1);
        Ok(())
    }
}
