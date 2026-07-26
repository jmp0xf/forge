//! Private, repository-bound state for generated host adapters.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::io;
use std::path::Path;

use forge_core::RepoRelativePath;
use forge_core::ports::{Hasher, RepositoryFilePort, StateStore};
use forge_render::{
    ADAPTER_FILE_MAX_BYTES, ChangePlan, SkippedReason, managed_adapter_spec_for_path,
    repository_file_digest,
};
use forge_schema::{Digest, ManagedBlockId, PathEncoding, RepoId, WirePath};
use serde::{Deserialize, Deserializer, Serialize};

pub(crate) const ADAPTER_MANIFEST_STATE_KEY: &str = "generated-v1.json";
pub(crate) const ADAPTER_BEHAVIOR_VERSION: &str = "managed-markdown-v1";
const ADAPTER_MANIFEST_SCHEMA: u16 = 1;
const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const MAX_HOST_BYTES: usize = 64;
const MAX_BEHAVIOR_VERSION_BYTES: usize = 128;
const MAX_OPAQUE_ID_BYTES: usize = 256;

/// The minimal state needed to classify drift without retaining generated or user-authored text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AdapterManifest {
    schema: u16,
    repository: RepoId,
    source_digest: Digest,
    behavior_version: String,
    adapters: Vec<AdapterManifestEntry>,
}

impl AdapterManifest {
    /// Builds a canonical v1 manifest. Entry order supplied by callers is not significant.
    pub(crate) fn new(
        repository: RepoId,
        source_digest: Digest,
        behavior_version: impl Into<String>,
        adapters: Vec<AdapterManifestEntry>,
    ) -> Result<Self, AdapterManifestError> {
        validate_opaque_id(repository.as_str(), AdapterManifestField::Repository)?;
        validate_blake3_digest(source_digest.as_str(), AdapterManifestField::SourceDigest)?;
        let behavior_version = behavior_version.into();
        validate_behavior_version(&behavior_version)?;

        let mut keyed = Vec::with_capacity(adapters.len());
        let mut identities = BTreeSet::new();
        for adapter in adapters {
            let key = adapter.sort_key()?;
            let identity = (key.path.clone(), key.block_id.clone());
            if !identities.insert(identity) {
                return Err(AdapterManifestError::DuplicateAdapter);
            }
            keyed.push((key, adapter));
        }
        keyed.sort_by(|left, right| left.0.cmp(&right.0));

        Ok(Self {
            schema: ADAPTER_MANIFEST_SCHEMA,
            repository,
            source_digest,
            behavior_version,
            adapters: keyed.into_iter().map(|(_, adapter)| adapter).collect(),
        })
    }

    #[must_use]
    pub(crate) fn source_digest(&self) -> &Digest {
        &self.source_digest
    }

    #[must_use]
    pub(crate) fn behavior_version(&self) -> &str {
        &self.behavior_version
    }

    #[must_use]
    pub(crate) fn adapters(&self) -> &[AdapterManifestEntry] {
        &self.adapters
    }

    fn validate(&self, expected_repository: Option<&RepoId>) -> Result<(), AdapterManifestError> {
        if self.schema != ADAPTER_MANIFEST_SCHEMA {
            return Err(AdapterManifestError::UnsupportedSchema {
                schema: u64::from(self.schema),
            });
        }
        validate_opaque_id(self.repository.as_str(), AdapterManifestField::Repository)?;
        validate_blake3_digest(
            self.source_digest.as_str(),
            AdapterManifestField::SourceDigest,
        )?;
        validate_behavior_version(&self.behavior_version)?;
        if expected_repository.is_some_and(|expected| expected != &self.repository) {
            return Err(AdapterManifestError::WrongRepository);
        }

        let mut previous = None;
        let mut identities = BTreeSet::new();
        for adapter in &self.adapters {
            let key = adapter.sort_key()?;
            let identity = (key.path.clone(), key.block_id.clone());
            if !identities.insert(identity) {
                return Err(AdapterManifestError::DuplicateAdapter);
            }
            if previous.as_ref().is_some_and(|prior| prior > &key) {
                return Err(AdapterManifestError::NonCanonicalOrder);
            }
            previous = Some(key);
        }
        Ok(())
    }
}

/// One generated block, represented only by identity and its expected complete-file digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AdapterManifestEntry {
    host: String,
    #[serde(deserialize_with = "deserialize_strict_wire_path")]
    path: WirePath,
    block_id: ManagedBlockId,
    postimage_digest: Digest,
}

impl AdapterManifestEntry {
    pub(crate) fn new(
        host: impl Into<String>,
        path: &RepoRelativePath,
        block_id: ManagedBlockId,
        postimage_digest: Digest,
    ) -> Result<Self, AdapterManifestError> {
        let entry = Self {
            host: host.into(),
            path: WirePath::from_path(path.as_path()),
            block_id,
            postimage_digest,
        };
        let _ = entry.sort_key()?;
        Ok(entry)
    }

    #[must_use]
    pub(crate) fn host(&self) -> &str {
        &self.host
    }

    #[must_use]
    pub(crate) fn path(&self) -> &WirePath {
        &self.path
    }

    #[must_use]
    pub(crate) fn block_id(&self) -> &ManagedBlockId {
        &self.block_id
    }

    #[must_use]
    pub(crate) fn postimage_digest(&self) -> &Digest {
        &self.postimage_digest
    }

    fn sort_key(&self) -> Result<AdapterSortKey, AdapterManifestError> {
        validate_host(&self.host)?;
        validate_block_id(self.block_id.as_str())?;
        validate_blake3_digest(
            self.postimage_digest.as_str(),
            AdapterManifestField::PostimageDigest,
        )?;

        let native_path = self
            .path
            .to_path_buf()
            .map_err(|_| invalid_field(AdapterManifestField::Path))?;
        let relative_path = RepoRelativePath::new(&native_path)
            .map_err(|_| invalid_field(AdapterManifestField::Path))?;
        if relative_path == RepoRelativePath::root()
            || WirePath::from_path(relative_path.as_path()) != self.path
        {
            return Err(invalid_field(AdapterManifestField::Path));
        }

        Ok(AdapterSortKey {
            path: relative_path,
            block_id: self.block_id.clone(),
            host: self.host.clone(),
        })
    }
}

/// Builds private adapter state only from a post-check plan that has converged to no edits.
pub(crate) fn manifest_from_converged_plan<F, H>(
    plan: &ChangePlan,
    repository_root: &Path,
    filesystem: &F,
    hasher: &H,
) -> Result<AdapterManifest, GeneratedManifestError>
where
    F: RepositoryFilePort + ?Sized,
    H: Hasher + ?Sized,
{
    if !plan.edits.is_empty() {
        return Err(GeneratedManifestError::NonConverged);
    }

    let mut entries = Vec::new();
    for skipped in &plan.skipped {
        if skipped.reason != SkippedReason::AlreadySatisfied {
            continue;
        }
        let satisfied = skipped.satisfied_managed.as_ref().ok_or_else(|| {
            GeneratedManifestError::MissingSatisfiedIdentity(skipped.path.clone())
        })?;
        let spec = managed_adapter_spec_for_path(&skipped.path)
            .ok_or_else(|| GeneratedManifestError::UnknownIdentity(skipped.path.clone()))?;
        if spec.block != satisfied.kind {
            return Err(GeneratedManifestError::IdentityMismatch(
                skipped.path.clone(),
            ));
        }
        let bytes = filesystem
            .read_confined_bounded(repository_root, &skipped.path, ADAPTER_FILE_MAX_BYTES)
            .map_err(|error| GeneratedManifestError::Read {
                path: skipped.path.clone(),
                kind: error.kind(),
            })?
            .ok_or_else(|| GeneratedManifestError::Missing(skipped.path.clone()))?;
        if repository_file_digest(hasher, &bytes) != satisfied.full_postimage_digest {
            return Err(GeneratedManifestError::ChangedSincePlan(
                skipped.path.clone(),
            ));
        }
        entries.push(
            AdapterManifestEntry::new(
                spec.host,
                &skipped.path,
                ManagedBlockId::new(satisfied.kind.id()),
                satisfied.full_postimage_digest.clone(),
            )
            .map_err(GeneratedManifestError::Manifest)?,
        );
    }
    if entries.is_empty() {
        return Err(GeneratedManifestError::NoOwnedAdapters);
    }

    AdapterManifest::new(
        plan.repository.clone(),
        plan.model_digest.clone(),
        ADAPTER_BEHAVIOR_VERSION,
        entries,
    )
    .map_err(GeneratedManifestError::Manifest)
}

/// A failure to derive state from the generated files observed by the post-check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GeneratedManifestError {
    NonConverged,
    UnknownIdentity(RepoRelativePath),
    MissingSatisfiedIdentity(RepoRelativePath),
    IdentityMismatch(RepoRelativePath),
    Read {
        path: RepoRelativePath,
        kind: io::ErrorKind,
    },
    Missing(RepoRelativePath),
    ChangedSincePlan(RepoRelativePath),
    NoOwnedAdapters,
    Manifest(AdapterManifestError),
}

impl GeneratedManifestError {
    #[must_use]
    pub(crate) const fn io_kind(&self) -> Option<io::ErrorKind> {
        match self {
            Self::Read { kind, .. } => Some(*kind),
            Self::Manifest(error) => error.io_kind(),
            _ => None,
        }
    }
}

impl fmt::Display for GeneratedManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonConverged => {
                formatter.write_str("adapter plan still contains repository edits")
            }
            Self::UnknownIdentity(path) => write!(
                formatter,
                "managed target `{}` has no registered adapter identity",
                path.as_path().display()
            ),
            Self::MissingSatisfiedIdentity(path) => write!(
                formatter,
                "satisfied target `{}` lacks its planned managed identity",
                path.as_path().display()
            ),
            Self::IdentityMismatch(path) => write!(
                formatter,
                "satisfied target `{}` contradicts the adapter registry",
                path.as_path().display()
            ),
            Self::Read { path, kind } => write!(
                formatter,
                "cannot read generated target `{}` ({kind:?})",
                path.as_path().display()
            ),
            Self::Missing(path) => write!(
                formatter,
                "generated target `{}` disappeared before state persistence",
                path.as_path().display()
            ),
            Self::ChangedSincePlan(path) => write!(
                formatter,
                "generated target `{}` changed after the converged plan",
                path.as_path().display()
            ),
            Self::NoOwnedAdapters => {
                formatter.write_str("converged plan contains no Forge-owned adapter")
            }
            Self::Manifest(error) => error.fmt(formatter),
        }
    }
}

impl Error for GeneratedManifestError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Manifest(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct AdapterSortKey {
    path: RepoRelativePath,
    block_id: ManagedBlockId,
    host: String,
}

/// Loads and validates the one private adapter manifest for this worktree.
pub(crate) fn load_adapter_manifest<S>(
    store: &S,
    expected_repository: &RepoId,
) -> Result<Option<AdapterManifest>, AdapterManifestError>
where
    S: StateStore + ?Sized,
{
    let Some(bytes) = store
        .load_bounded(ADAPTER_MANIFEST_STATE_KEY, MAX_MANIFEST_BYTES)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::InvalidData {
                AdapterManifestError::TooLarge
            } else {
                io_error(AdapterManifestIoOperation::Load, error)
            }
        })?
    else {
        return Ok(None);
    };
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(AdapterManifestError::TooLarge);
    }

    let probe: SchemaProbe = deserialize_json(&bytes)?;
    let schema = probe.schema.ok_or(AdapterManifestError::MissingSchema)?;
    if schema != u64::from(ADAPTER_MANIFEST_SCHEMA) {
        return Err(AdapterManifestError::UnsupportedSchema { schema });
    }

    let manifest: AdapterManifest = deserialize_json(&bytes)?;
    manifest.validate(Some(expected_repository))?;
    Ok(Some(manifest))
}

/// Validates and atomically replaces the one private adapter manifest for this worktree.
///
/// Runtime callers must hold the worktree's exclusive Forge state lock for the full operation.
pub(crate) fn store_adapter_manifest<S>(
    store: &S,
    expected_repository: &RepoId,
    manifest: &AdapterManifest,
) -> Result<(), AdapterManifestError>
where
    S: StateStore + ?Sized,
{
    manifest.validate(Some(expected_repository))?;
    let bytes = serde_json::to_vec(manifest).map_err(json_error)?;
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(AdapterManifestError::TooLarge);
    }
    let existing = match store.load_bounded(ADAPTER_MANIFEST_STATE_KEY, MAX_MANIFEST_BYTES) {
        Ok(existing) => existing,
        // An oversized rebuildable manifest is intentionally replaced below. Treating this as a
        // store failure would make `init --apply` unable to self-repair otherwise safe state.
        Err(error) if error.kind() == io::ErrorKind::InvalidData => None,
        Err(error) => return Err(io_error(AdapterManifestIoOperation::Load, error)),
    };
    if existing.as_deref() == Some(bytes.as_slice()) {
        return Ok(());
    }
    store
        .store_atomic(ADAPTER_MANIFEST_STATE_KEY, &bytes)
        .map_err(|error| io_error(AdapterManifestIoOperation::Store, error))
}

#[derive(Debug, Deserialize)]
struct SchemaProbe {
    #[serde(default)]
    schema: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct StrictWirePath {
    display: String,
    encoding: PathEncoding,
    #[serde(default)]
    raw_base64: Option<String>,
}

fn deserialize_strict_wire_path<'de, D>(deserializer: D) -> Result<WirePath, D::Error>
where
    D: Deserializer<'de>,
{
    let path = StrictWirePath::deserialize(deserializer)?;
    Ok(WirePath {
        display: path.display,
        encoding: path.encoding,
        raw_base64: path.raw_base64,
    })
}

fn deserialize_json<T>(bytes: &[u8]) -> Result<T, AdapterManifestError>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_slice(bytes).map_err(json_error)
}

fn validate_host(value: &str) -> Result<(), AdapterManifestError> {
    let valid = !value.is_empty()
        && value.len() <= MAX_HOST_BYTES
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        });
    if valid {
        Ok(())
    } else {
        Err(invalid_field(AdapterManifestField::Host))
    }
}

fn validate_block_id(value: &str) -> Result<(), AdapterManifestError> {
    let valid = !value.is_empty()
        && value.len() <= MAX_OPAQUE_ID_BYTES
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        });
    if valid {
        Ok(())
    } else {
        Err(invalid_field(AdapterManifestField::BlockId))
    }
}

fn validate_behavior_version(value: &str) -> Result<(), AdapterManifestError> {
    let valid = !value.is_empty()
        && value.len() <= MAX_BEHAVIOR_VERSION_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+'));
    if valid {
        Ok(())
    } else {
        Err(invalid_field(AdapterManifestField::BehaviorVersion))
    }
}

fn validate_opaque_id(
    value: &str,
    field: AdapterManifestField,
) -> Result<(), AdapterManifestError> {
    let valid = !value.is_empty()
        && value.len() <= MAX_OPAQUE_ID_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'-' | b'_' | b'.' | b'+')
        });
    if valid {
        Ok(())
    } else {
        Err(invalid_field(field))
    }
}

fn validate_blake3_digest(
    value: &str,
    field: AdapterManifestField,
) -> Result<(), AdapterManifestError> {
    let Some(hex) = value.strip_prefix("blake3:") else {
        return Err(invalid_field(field));
    };
    if hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(invalid_field(field))
    }
}

const fn invalid_field(field: AdapterManifestField) -> AdapterManifestError {
    AdapterManifestError::InvalidField { field }
}

fn io_error(operation: AdapterManifestIoOperation, error: io::Error) -> AdapterManifestError {
    AdapterManifestError::Io {
        operation,
        kind: error.kind(),
    }
}

fn json_error(error: serde_json::Error) -> AdapterManifestError {
    AdapterManifestError::InvalidJson {
        kind: match error.classify() {
            serde_json::error::Category::Io => AdapterManifestJsonErrorKind::Io,
            serde_json::error::Category::Syntax => AdapterManifestJsonErrorKind::Syntax,
            serde_json::error::Category::Data => AdapterManifestJsonErrorKind::Data,
            serde_json::error::Category::Eof => AdapterManifestJsonErrorKind::Eof,
        },
        line: error.line(),
        column: error.column(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdapterManifestIoOperation {
    Load,
    Store,
}

impl fmt::Display for AdapterManifestIoOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Load => "load",
            Self::Store => "store",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdapterManifestJsonErrorKind {
    Io,
    Syntax,
    Data,
    Eof,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdapterManifestField {
    Repository,
    SourceDigest,
    BehaviorVersion,
    Host,
    Path,
    BlockId,
    PostimageDigest,
}

/// A bounded manifest parse, validation, or persistence failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AdapterManifestError {
    Io {
        operation: AdapterManifestIoOperation,
        kind: io::ErrorKind,
    },
    InvalidJson {
        kind: AdapterManifestJsonErrorKind,
        line: usize,
        column: usize,
    },
    MissingSchema,
    UnsupportedSchema {
        schema: u64,
    },
    WrongRepository,
    DuplicateAdapter,
    NonCanonicalOrder,
    InvalidField {
        field: AdapterManifestField,
    },
    TooLarge,
}

impl AdapterManifestError {
    #[must_use]
    pub(crate) const fn io_kind(&self) -> Option<io::ErrorKind> {
        match self {
            Self::Io { kind, .. } => Some(*kind),
            _ => None,
        }
    }
}

impl fmt::Display for AdapterManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { operation, kind } => {
                write!(formatter, "cannot {operation} adapter manifest ({kind:?})")
            }
            Self::InvalidJson { kind, line, column } => write!(
                formatter,
                "adapter manifest is invalid JSON ({kind:?} at line {line}, column {column})"
            ),
            Self::MissingSchema => formatter.write_str("adapter manifest schema is missing"),
            Self::UnsupportedSchema { schema } => {
                write!(formatter, "adapter manifest schema {schema} is unsupported")
            }
            Self::WrongRepository => {
                formatter.write_str("adapter manifest belongs to a different repository")
            }
            Self::DuplicateAdapter => {
                formatter.write_str("adapter manifest repeats a path and managed block identity")
            }
            Self::NonCanonicalOrder => {
                formatter.write_str("adapter manifest entries are not canonically ordered")
            }
            Self::InvalidField { field } => {
                write!(formatter, "adapter manifest has an invalid {field:?} field")
            }
            Self::TooLarge => formatter.write_str("adapter manifest exceeds its size limit"),
        }
    }
}

impl Error for AdapterManifestError {}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;
    use std::error::Error;
    use std::io;
    use std::path::Path;

    use forge_core::RepoRelativePath;
    use forge_core::ports::{Hasher, RepositoryFilePort, StateStore};
    use forge_render::{
        ChangePlan, RollbackPlan, SatisfiedManagedBlock, SkippedChange, SkippedReason,
        adapter_specs,
    };
    use forge_schema::{Digest, ManagedBlockId, RepoId};
    use serde_json::{Value, json};

    use super::{
        ADAPTER_MANIFEST_STATE_KEY, AdapterManifest, AdapterManifestEntry, AdapterManifestError,
        MAX_MANIFEST_BYTES, load_adapter_manifest, manifest_from_converged_plan,
        store_adapter_manifest,
    };

    #[derive(Debug)]
    struct FixedHasher(Digest);

    impl Hasher for FixedHasher {
        fn digest(&self, _chunks: &[&[u8]]) -> Digest {
            self.0.clone()
        }
    }

    #[derive(Debug, Default)]
    struct ManifestFiles(BTreeMap<std::path::PathBuf, Vec<u8>>);

    impl RepositoryFilePort for ManifestFiles {
        fn read_confined(
            &self,
            _repository_root: &Path,
            _path: &RepoRelativePath,
        ) -> io::Result<Option<Vec<u8>>> {
            Err(io::Error::other("manifest fixture forbids unbounded reads"))
        }

        fn read_confined_bounded(
            &self,
            _repository_root: &Path,
            path: &RepoRelativePath,
            max_bytes: usize,
        ) -> io::Result<Option<Vec<u8>>> {
            match self.0.get(path.as_path()) {
                Some(bytes) if bytes.len() > max_bytes => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "manifest fixture exceeds read limit",
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
            Err(io::Error::other("manifest fixture must not write"))
        }
    }

    #[derive(Debug, Default)]
    struct MemoryStateStore {
        bytes: RefCell<Option<Vec<u8>>>,
        load_failure: Option<io::ErrorKind>,
        store_failure: Option<io::ErrorKind>,
        store_calls: Cell<usize>,
    }

    impl MemoryStateStore {
        fn with_bytes(bytes: Vec<u8>) -> Self {
            Self {
                bytes: RefCell::new(Some(bytes)),
                ..Self::default()
            }
        }

        fn failing_store(kind: io::ErrorKind) -> Self {
            Self {
                store_failure: Some(kind),
                ..Self::default()
            }
        }

        fn stored_bytes(&self) -> io::Result<Vec<u8>> {
            self.bytes
                .borrow()
                .clone()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "manifest is absent"))
        }

        fn store_calls(&self) -> usize {
            self.store_calls.get()
        }
    }

    impl StateStore for MemoryStateStore {
        fn load(&self, key: &str) -> io::Result<Option<Vec<u8>>> {
            if key != ADAPTER_MANIFEST_STATE_KEY {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unexpected state key",
                ));
            }
            if let Some(kind) = self.load_failure {
                return Err(io::Error::new(kind, "injected load failure"));
            }
            Ok(self.bytes.borrow().clone())
        }

        fn load_bounded(&self, key: &str, max_bytes: usize) -> io::Result<Option<Vec<u8>>> {
            if key != ADAPTER_MANIFEST_STATE_KEY {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unexpected state key",
                ));
            }
            if let Some(kind) = self.load_failure {
                return Err(io::Error::new(kind, "injected load failure"));
            }
            let bytes = self.bytes.borrow();
            if bytes.as_ref().is_some_and(|value| value.len() > max_bytes) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "state value exceeds its read limit",
                ));
            }
            Ok(bytes.clone())
        }

        fn store_atomic(&self, key: &str, bytes: &[u8]) -> io::Result<()> {
            if key != ADAPTER_MANIFEST_STATE_KEY {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unexpected state key",
                ));
            }
            if let Some(kind) = self.store_failure {
                return Err(io::Error::new(kind, "injected store failure"));
            }
            self.store_calls.set(self.store_calls.get() + 1);
            self.bytes.replace(Some(bytes.to_vec()));
            Ok(())
        }
    }

    #[test]
    fn roundtrip_is_canonical_and_byte_deterministic() -> Result<(), Box<dyn Error>> {
        let repository = repository('a');
        let manifest = AdapterManifest::new(
            repository.clone(),
            digest('b'),
            "0.0.0",
            vec![
                entry("cursor", "z.md", "project-index", 'd')?,
                entry("claude", "A.md", "claude-pointer", 'c')?,
            ],
        )?;
        assert_eq!(manifest.adapters()[0].host(), "claude");
        assert_eq!(manifest.repository, repository);
        assert_eq!(manifest.source_digest(), &digest('b'));
        assert_eq!(manifest.behavior_version(), "0.0.0");
        assert_eq!(manifest.adapters()[0].block_id().as_str(), "claude-pointer");
        assert_eq!(manifest.adapters()[0].postimage_digest(), &digest('c'));

        let store = MemoryStateStore::default();
        store_adapter_manifest(&store, &repository, &manifest)?;
        let first = store.stored_bytes()?;
        let loaded = load_adapter_manifest(&store, &repository)?.ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "roundtrip manifest is absent")
        })?;
        store_adapter_manifest(&store, &repository, &loaded)?;
        let second = store.stored_bytes()?;

        assert_eq!(first, second);
        assert_eq!(store.store_calls(), 1);
        assert_eq!(loaded, manifest);
        assert_eq!(loaded.adapters()[0].path().display, "A.md");
        assert!(!String::from_utf8_lossy(&second).contains("/Users/"));
        Ok(())
    }

    #[test]
    fn converged_manifest_consumes_every_owned_registry_identity() -> Result<(), Box<dyn Error>> {
        let postimage_digest = digest('c');
        let mut files = BTreeMap::new();
        let mut skipped = Vec::new();
        for spec in adapter_specs()
            .iter()
            .filter(|spec| spec.owns_managed_projection())
        {
            let path = RepoRelativePath::new(spec.path)?;
            files.insert(path.as_path().to_path_buf(), vec![b'x']);
            skipped.push(SkippedChange {
                path,
                reason: SkippedReason::AlreadySatisfied,
                satisfied_managed: Some(SatisfiedManagedBlock {
                    kind: spec.block,
                    full_postimage_digest: postimage_digest.clone(),
                }),
            });
        }
        let plan = ChangePlan {
            schema: 1,
            repository: repository('a'),
            model_digest: digest('b'),
            edits: Vec::new(),
            assumptions: Vec::new(),
            skipped,
            rollback: RollbackPlan::default(),
        };

        let manifest = manifest_from_converged_plan(
            &plan,
            Path::new("/repo"),
            &ManifestFiles(files),
            &FixedHasher(postimage_digest),
        )?;
        let owned = adapter_specs()
            .iter()
            .filter(|spec| spec.owns_managed_projection())
            .collect::<Vec<_>>();
        assert_eq!(manifest.adapters().len(), owned.len());
        for spec in owned {
            assert!(manifest.adapters().iter().any(|entry| {
                entry.host() == spec.host
                    && entry.path().display == spec.path
                    && entry.block_id().as_str() == spec.block.id()
            }));
        }
        Ok(())
    }

    #[test]
    fn absent_state_is_not_an_error() -> Result<(), AdapterManifestError> {
        assert_eq!(
            load_adapter_manifest(&MemoryStateStore::default(), &repository('a'))?,
            None
        );
        Ok(())
    }

    #[test]
    fn future_and_missing_schemas_are_rejected() -> Result<(), Box<dyn Error>> {
        let mut future = valid_document(Vec::new());
        future["schema"] = json!(2);
        let future_store = MemoryStateStore::with_bytes(serde_json::to_vec(&future)?);
        assert!(matches!(
            load_adapter_manifest(&future_store, &repository('a')),
            Err(AdapterManifestError::UnsupportedSchema { schema: 2 })
        ));

        let mut missing = valid_document(Vec::new());
        let object = missing.as_object_mut().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "fixture is not an object")
        })?;
        object.remove("schema");
        let missing_store = MemoryStateStore::with_bytes(serde_json::to_vec(&missing)?);
        assert_eq!(
            load_adapter_manifest(&missing_store, &repository('a')),
            Err(AdapterManifestError::MissingSchema)
        );
        Ok(())
    }

    #[test]
    fn unknown_fields_are_ignored_within_the_same_schema() -> Result<(), Box<dyn Error>> {
        let mut document = valid_document(Vec::new());
        document["private-secret-field"] = json!("must-not-be-echoed");
        let store = MemoryStateStore::with_bytes(serde_json::to_vec(&document)?);
        let loaded = load_adapter_manifest(&store, &repository('a'))?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "manifest is absent"))?;

        assert!(loaded.adapters().is_empty());
        Ok(())
    }

    #[test]
    fn unknown_nested_path_fields_are_ignored() -> Result<(), Box<dyn Error>> {
        let mut adapter = entry_document("claude", "AGENTS.md", "project-index", 'c');
        adapter["path"]["absolute_root"] = json!("/private/worktree");
        let store =
            MemoryStateStore::with_bytes(serde_json::to_vec(&valid_document(vec![adapter]))?);

        let loaded = load_adapter_manifest(&store, &repository('a'))?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "manifest is absent"))?;
        assert_eq!(loaded.adapters()[0].path().display, "AGENTS.md");
        Ok(())
    }

    #[test]
    fn duplicate_path_and_block_are_rejected() -> Result<(), Box<dyn Error>> {
        let duplicate = vec![
            entry_document("claude", "AGENTS.md", "project-index", 'c'),
            entry_document("cursor", "AGENTS.md", "project-index", 'd'),
        ];
        let store = MemoryStateStore::with_bytes(serde_json::to_vec(&valid_document(duplicate))?);

        assert_eq!(
            load_adapter_manifest(&store, &repository('a')),
            Err(AdapterManifestError::DuplicateAdapter)
        );
        Ok(())
    }

    #[test]
    fn unsorted_entries_are_rejected_on_load() -> Result<(), Box<dyn Error>> {
        let unsorted = vec![
            entry_document("cursor", "z.md", "project-index", 'd'),
            entry_document("claude", "A.md", "claude-pointer", 'c'),
        ];
        let store = MemoryStateStore::with_bytes(serde_json::to_vec(&valid_document(unsorted))?);

        assert_eq!(
            load_adapter_manifest(&store, &repository('a')),
            Err(AdapterManifestError::NonCanonicalOrder)
        );
        Ok(())
    }

    #[test]
    fn wrong_repository_is_rejected() -> Result<(), Box<dyn Error>> {
        let store = MemoryStateStore::with_bytes(serde_json::to_vec(&valid_document(Vec::new()))?);

        assert_eq!(
            load_adapter_manifest(&store, &repository('f')),
            Err(AdapterManifestError::WrongRepository)
        );
        Ok(())
    }

    #[test]
    fn corrupt_json_is_rejected_without_echoing_bytes() -> Result<(), Box<dyn Error>> {
        let store = MemoryStateStore::with_bytes(b"{ secret-state".to_vec());
        let error = load_adapter_manifest(&store, &repository('a'))
            .err()
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "corrupt JSON was accepted")
            })?;

        assert!(matches!(error, AdapterManifestError::InvalidJson { .. }));
        assert!(!error.to_string().contains("secret-state"));
        Ok(())
    }

    #[test]
    fn oversized_state_is_rejected_before_parsing() {
        let store = MemoryStateStore::with_bytes(vec![b'x'; MAX_MANIFEST_BYTES + 1]);

        assert_eq!(
            load_adapter_manifest(&store, &repository('a')),
            Err(AdapterManifestError::TooLarge)
        );
    }

    #[test]
    fn store_replaces_oversized_rebuildable_state() -> Result<(), Box<dyn Error>> {
        let repository = repository('a');
        let manifest = AdapterManifest::new(repository.clone(), digest('b'), "0.0.0", Vec::new())?;
        let store = MemoryStateStore::with_bytes(vec![b'x'; MAX_MANIFEST_BYTES + 1]);

        store_adapter_manifest(&store, &repository, &manifest)?;

        assert_eq!(store.store_calls(), 1);
        assert_eq!(load_adapter_manifest(&store, &repository)?, Some(manifest));
        Ok(())
    }

    #[test]
    fn noncanonical_digests_are_rejected() -> Result<(), Box<dyn Error>> {
        let mut source = valid_document(Vec::new());
        source["source_digest"] = json!("sha256:not-a-forge-digest");
        let source_store = MemoryStateStore::with_bytes(serde_json::to_vec(&source)?);
        assert_eq!(
            load_adapter_manifest(&source_store, &repository('a')),
            Err(AdapterManifestError::InvalidField {
                field: super::AdapterManifestField::SourceDigest
            })
        );

        let mut adapter = entry_document("codex", "AGENTS.md", "project-index", 'c');
        adapter["postimage_digest"] = json!(format!("blake3:{}", "C".repeat(64)));
        let postimage_store =
            MemoryStateStore::with_bytes(serde_json::to_vec(&valid_document(vec![adapter]))?);
        assert_eq!(
            load_adapter_manifest(&postimage_store, &repository('a')),
            Err(AdapterManifestError::InvalidField {
                field: super::AdapterManifestField::PostimageDigest
            })
        );
        Ok(())
    }

    #[test]
    fn invalid_or_absolute_adapter_paths_are_rejected() -> Result<(), Box<dyn Error>> {
        let invalid = vec![json!({
            "host": "claude",
            "path": {
                "display": "/private/absolute/AGENTS.md",
                "encoding": "utf8"
            },
            "block_id": "project-index",
            "postimage_digest": digest('c')
        })];
        let store = MemoryStateStore::with_bytes(serde_json::to_vec(&valid_document(invalid))?);

        assert!(matches!(
            load_adapter_manifest(&store, &repository('a')),
            Err(AdapterManifestError::InvalidField { .. })
        ));
        Ok(())
    }

    #[test]
    fn write_failure_preserves_io_kind() -> Result<(), Box<dyn Error>> {
        let manifest = AdapterManifest::new(repository('a'), digest('b'), "0.0.0", Vec::new())?;
        let store = MemoryStateStore::failing_store(io::ErrorKind::PermissionDenied);
        let error = store_adapter_manifest(&store, &repository('a'), &manifest)
            .err()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "write failure was not propagated",
                )
            })?;

        assert_eq!(error.io_kind(), Some(io::ErrorKind::PermissionDenied));
        Ok(())
    }

    #[test]
    fn load_failure_preserves_io_kind() -> Result<(), Box<dyn Error>> {
        let store = MemoryStateStore {
            load_failure: Some(io::ErrorKind::WouldBlock),
            ..MemoryStateStore::default()
        };
        let error = load_adapter_manifest(&store, &repository('a'))
            .err()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "load failure was not propagated",
                )
            })?;

        assert_eq!(error.io_kind(), Some(io::ErrorKind::WouldBlock));
        Ok(())
    }

    fn entry(
        host: &str,
        path: &str,
        block_id: &str,
        digest_seed: char,
    ) -> Result<AdapterManifestEntry, Box<dyn Error>> {
        let path = RepoRelativePath::new(path)?;
        Ok(AdapterManifestEntry::new(
            host,
            &path,
            ManagedBlockId::new(block_id),
            digest(digest_seed),
        )?)
    }

    fn valid_document(adapters: Vec<Value>) -> Value {
        json!({
            "schema": 1,
            "repository": repository('a'),
            "source_digest": digest('b'),
            "behavior_version": "0.0.0",
            "adapters": adapters
        })
    }

    fn entry_document(host: &str, path: &str, block_id: &str, digest_seed: char) -> Value {
        json!({
            "host": host,
            "path": {
                "display": path,
                "encoding": "utf8"
            },
            "block_id": block_id,
            "postimage_digest": digest(digest_seed)
        })
    }

    fn repository(seed: char) -> RepoId {
        RepoId::new(format!("local:{}", digest(seed)))
    }

    fn digest(seed: char) -> Digest {
        Digest::new(format!("blake3:{}", seed.to_string().repeat(64)))
    }
}
