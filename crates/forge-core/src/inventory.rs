//! Pure repository-inventory contracts shared by detection and runtime.

use std::io;
use std::path::PathBuf;

use thiserror::Error;

/// Default cap for repository entries retained during startup detection.
pub const DEFAULT_MAX_INVENTORY_ENTRIES: usize = 200_000;

/// Default cap for one text file inspected during startup detection.
pub const DEFAULT_MAX_TEXT_FILE_BYTES: u64 = 1024 * 1024;

/// Startup limits for a repository inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InventoryOptions {
    pub max_entries: usize,
    pub max_text_file_bytes: u64,
}

impl Default for InventoryOptions {
    fn default() -> Self {
        Self {
            max_entries: DEFAULT_MAX_INVENTORY_ENTRIES,
            max_text_file_bytes: DEFAULT_MAX_TEXT_FILE_BYTES,
        }
    }
}

/// Filesystem kind without following symlinks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum InventoryKind {
    Directory,
    File,
    Symlink,
    Other,
}

/// The kind of one probed repository path without following symlinks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    Missing,
    Directory,
    File,
    Symlink,
    Other,
}

/// One stable, repository-relative inventory item.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct InventoryEntry {
    pub path: PathBuf,
    pub kind: InventoryKind,
    pub size_bytes: u64,
}

/// A skipped item or bounded degradation that remains visible to callers.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct InventorySkip {
    pub path: Option<PathBuf>,
    pub reason: String,
}

/// Deterministically ordered repository inventory.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Inventory {
    pub entries: Vec<InventoryEntry>,
    pub skipped: Vec<InventorySkip>,
}

impl Inventory {
    /// Applies stable ordering and the configured retained-entry bound.
    pub fn finalize(mut self, options: InventoryOptions) -> Result<Self, InventoryError> {
        self.entries.sort();
        self.skipped.sort();
        if self.entries.len() > options.max_entries {
            return Err(InventoryError::EntryLimit {
                max_entries: options.max_entries,
                observed: self.entries.len(),
            });
        }
        Ok(self)
    }
}

/// Bounded text probe result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedText {
    pub bytes: Vec<u8>,
    pub truncated: bool,
    pub binary: bool,
}

/// Inventory or bounded-read failure.
#[derive(Debug, Error)]
pub enum InventoryError {
    #[error("repository root is not a directory: {0}")]
    InvalidRoot(PathBuf),
    #[error("repository inventory I/O failed at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("repository-relative path points through a symlink: {0}")]
    Symlink(PathBuf),
    #[error("Git-backed repository inventory failed: {0}")]
    Git(#[source] io::Error),
    #[error(
        "repository inventory contains {observed} entries, exceeding the configured {max_entries}-entry bound"
    )]
    EntryLimit { max_entries: usize, observed: usize },
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        DEFAULT_MAX_INVENTORY_ENTRIES, DEFAULT_MAX_TEXT_FILE_BYTES, Inventory, InventoryEntry,
        InventoryError, InventoryKind, InventoryOptions, InventorySkip,
    };

    #[test]
    fn default_limits_are_explicit_and_stable() {
        assert_eq!(
            InventoryOptions::default(),
            InventoryOptions {
                max_entries: DEFAULT_MAX_INVENTORY_ENTRIES,
                max_text_file_bytes: DEFAULT_MAX_TEXT_FILE_BYTES,
            }
        );
    }

    #[test]
    fn finalization_orders_entries_and_skips() -> Result<(), InventoryError> {
        let inventory = Inventory {
            entries: vec![
                InventoryEntry {
                    path: PathBuf::from("z"),
                    kind: InventoryKind::File,
                    size_bytes: 1,
                },
                InventoryEntry {
                    path: PathBuf::from("a"),
                    kind: InventoryKind::Directory,
                    size_bytes: 0,
                },
            ],
            skipped: vec![
                InventorySkip {
                    path: Some(PathBuf::from("z")),
                    reason: String::from("z"),
                },
                InventorySkip {
                    path: Some(PathBuf::from("a")),
                    reason: String::from("a"),
                },
            ],
        }
        .finalize(InventoryOptions::default())?;

        assert_eq!(inventory.entries[0].path, PathBuf::from("a"));
        assert_eq!(inventory.skipped[0].path, Some(PathBuf::from("a")));
        Ok(())
    }

    #[test]
    fn finalization_rejects_an_over_limit_inventory() {
        let inventory = Inventory {
            entries: vec![InventoryEntry {
                path: PathBuf::from("one"),
                kind: InventoryKind::File,
                size_bytes: 1,
            }],
            skipped: Vec::new(),
        };

        assert!(matches!(
            inventory.finalize(InventoryOptions {
                max_entries: 0,
                ..InventoryOptions::default()
            }),
            Err(InventoryError::EntryLimit {
                max_entries: 0,
                observed: 1
            })
        ));
    }
}
