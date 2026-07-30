//! Immutable content-addressed cache storage rooted in Git's common directory.

use std::io;
use std::path::{Path, PathBuf};

use forge_core::Digest;

use super::{
    GitStateLayout, StateError, ensure_private_relative_directories, validate_resolved_directory,
};
use crate::fs::{FileSystemError, RepositoryWriter};

/// Cache categories admitted by the v0 shared-state contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SharedCacheKind {
    Inventory,
}

impl SharedCacheKind {
    const fn directory(self) -> &'static str {
        match self {
            Self::Inventory => "inventory",
        }
    }
}

/// Result of publishing an immutable cache entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedCacheWrite {
    Created,
    AlreadyPresent,
}

/// A no-clobber cache writer confined to `<git-common-dir>/forge/cache`.
#[derive(Debug, Clone)]
pub struct SharedCacheStore {
    root: PathBuf,
    relative_root: PathBuf,
    writer: RepositoryWriter,
}

impl SharedCacheStore {
    /// Prepares a shared cache rooted at Git's common directory without creating cache paths.
    ///
    /// Directories are created lazily only when an eligible immutable value is published. A cache
    /// miss, an ineligible repository, or `--no-cache` therefore leaves Git-private state alone.
    pub fn new(layout: &GitStateLayout) -> Result<Self, StateError> {
        validate_resolved_directory(layout.common_dir())?;
        let relative_root = layout
            .shared_cache_dir()
            .strip_prefix(layout.common_dir())
            .map_err(|_| StateError::InvalidLayout {
                path: layout.shared_cache_dir().to_path_buf(),
                reason: "shared cache path is outside Git's common directory".to_owned(),
            })?
            .to_path_buf();
        let writer = RepositoryWriter::new(layout.common_dir())?;
        Ok(Self {
            root: layout.shared_cache_dir().to_path_buf(),
            relative_root,
            writer,
        })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Reads one bounded cache entry. Missing entries are ordinary cache misses.
    pub fn load(
        &self,
        kind: SharedCacheKind,
        key: &Digest,
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, StateError> {
        let relative = self.relative_cache_entry_path(kind, key)?;
        match self.writer.read_bounded(&relative, max_bytes) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(FileSystemError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                Ok(None)
            }
            Err(error) => Err(StateError::PathSafety(error)),
        }
    }

    /// Publishes one immutable entry and verifies a concurrent/pre-existing identity byte-for-byte.
    pub fn store_immutable(
        &self,
        kind: SharedCacheKind,
        key: &Digest,
        bytes: &[u8],
    ) -> Result<SharedCacheWrite, StateError> {
        let relative = self.relative_cache_entry_path(kind, key)?;
        let parent = relative.parent().ok_or_else(|| StateError::InvalidLayout {
            path: relative.clone(),
            reason: "cache entry path has no category directory".to_owned(),
        })?;
        ensure_private_relative_directories(self.writer.root(), parent)?;
        match self.writer.write_atomic_private_new(&relative, bytes) {
            Ok(()) => Ok(SharedCacheWrite::Created),
            Err(FileSystemError::Io { source, .. })
                if source.kind() == io::ErrorKind::AlreadyExists =>
            {
                let existing = match self.writer.read_bounded(&relative, bytes.len()) {
                    Ok(existing) => existing,
                    Err(FileSystemError::Io { source, .. })
                        if source.kind() == io::ErrorKind::InvalidData =>
                    {
                        return Err(StateError::ImmutableCollision {
                            key: relative.to_string_lossy().into_owned(),
                        });
                    }
                    Err(error) => return Err(StateError::PathSafety(error)),
                };
                if existing == bytes {
                    Ok(SharedCacheWrite::AlreadyPresent)
                } else {
                    Err(StateError::ImmutableCollision {
                        key: relative.to_string_lossy().into_owned(),
                    })
                }
            }
            Err(error) => Err(StateError::PathSafety(error)),
        }
    }

    fn relative_cache_entry_path(
        &self,
        kind: SharedCacheKind,
        key: &Digest,
    ) -> Result<PathBuf, StateError> {
        Ok(self.relative_root.join(cache_entry_path(kind, key)?))
    }
}

fn cache_entry_path(kind: SharedCacheKind, key: &Digest) -> Result<PathBuf, StateError> {
    let Some(hex) = key.as_str().strip_prefix("blake3:") else {
        return Err(invalid_cache_key(key, "cache key is not a BLAKE3 digest"));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(invalid_cache_key(
            key,
            "cache key is not 64 lowercase hexadecimal digits",
        ));
    }
    Ok(Path::new(kind.directory()).join(format!("{hex}.json")))
}

fn invalid_cache_key(key: &Digest, reason: &str) -> StateError {
    StateError::UnsafeKey {
        key: key.as_str().to_owned(),
        reason: reason.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    fn layout() -> Result<(tempfile::TempDir, GitStateLayout), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let git = directory.path().join("git");
        fs::create_dir(&git)?;
        Ok((directory, GitStateLayout::new(&git, &git)))
    }

    #[test]
    fn immutable_entries_are_reused_but_never_replaced() -> Result<(), Box<dyn std::error::Error>> {
        let (_directory, layout) = layout()?;
        let store = SharedCacheStore::new(&layout)?;
        let key = Digest::new(format!("blake3:{}", "a".repeat(64)));

        assert!(!store.root().exists());
        assert_eq!(store.load(SharedCacheKind::Inventory, &key, 16)?, None);
        assert!(!store.root().exists());
        assert_eq!(
            store.store_immutable(SharedCacheKind::Inventory, &key, b"payload")?,
            SharedCacheWrite::Created
        );
        assert!(store.root().is_dir());
        assert_eq!(
            store.store_immutable(SharedCacheKind::Inventory, &key, b"payload")?,
            SharedCacheWrite::AlreadyPresent
        );
        assert_eq!(
            store.load(SharedCacheKind::Inventory, &key, 16)?,
            Some(b"payload".to_vec())
        );
        assert!(matches!(
            store.store_immutable(SharedCacheKind::Inventory, &key, b"changed"),
            Err(StateError::ImmutableCollision { .. })
        ));
        assert_eq!(
            store.load(SharedCacheKind::Inventory, &key, 16)?,
            Some(b"payload".to_vec())
        );
        Ok(())
    }

    #[test]
    fn malformed_keys_cannot_select_cache_paths() -> Result<(), Box<dyn std::error::Error>> {
        let (_directory, layout) = layout()?;
        let store = SharedCacheStore::new(&layout)?;
        for key in ["sha256:abcd", "blake3:../escape", "blake3:AAAA"] {
            assert!(matches!(
                store.load(SharedCacheKind::Inventory, &Digest::new(key), 16),
                Err(StateError::UnsafeKey { .. })
            ));
        }
        Ok(())
    }

    #[test]
    fn collision_comparison_rejects_an_oversized_existing_entry_without_unbounded_read()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_directory, layout) = layout()?;
        let store = SharedCacheStore::new(&layout)?;
        let key = Digest::new(format!("blake3:{}", "b".repeat(64)));
        let entry = store
            .root()
            .join("inventory")
            .join(format!("{}.json", "b".repeat(64)));
        assert_eq!(
            store.store_immutable(SharedCacheKind::Inventory, &key, b"seed")?,
            SharedCacheWrite::Created
        );
        fs::write(&entry, vec![b'x'; 1024 * 1024])?;

        assert!(matches!(
            store.store_immutable(SharedCacheKind::Inventory, &key, b"small"),
            Err(StateError::ImmutableCollision { .. })
        ));
        Ok(())
    }
}
