//! Read-only repository inventory with standard ignore handling.

use std::fs::{self, File};
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};

use forge_core::RepoRelativePath;
use ignore::WalkBuilder;
use thiserror::Error;

const GENERATED_DIRECTORIES: &[&str] = &[".git", "target", "vendor", "node_modules"];

/// Startup limits for a repository inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InventoryOptions {
    pub max_entries: usize,
    pub max_text_file_bytes: u64,
}

impl Default for InventoryOptions {
    fn default() -> Self {
        Self {
            max_entries: 200_000,
            max_text_file_bytes: 1024 * 1024,
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
}

/// Walks repository inputs without following symlinks or generated directories.
pub fn build_inventory(
    root: &Path,
    options: InventoryOptions,
) -> Result<Inventory, InventoryError> {
    let root_metadata = fs::symlink_metadata(root).map_err(|source| InventoryError::Io {
        path: root.to_path_buf(),
        source,
    })?;
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
        return Err(InventoryError::InvalidRoot(root.to_path_buf()));
    }
    let mut builder = WalkBuilder::new(root);
    builder
        .standard_filters(true)
        .hidden(false)
        .follow_links(false)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .require_git(false)
        .parents(true)
        .filter_entry(|entry| {
            entry.depth() == 0
                || !GENERATED_DIRECTORIES
                    .iter()
                    .any(|name| entry.file_name() == *name)
        });

    let mut inventory = Inventory::default();
    for result in builder.build() {
        let entry = match result {
            Ok(entry) => entry,
            Err(error) => {
                inventory.skipped.push(InventorySkip {
                    path: ignore_error_path(&error),
                    reason: error.to_string(),
                });
                continue;
            }
        };
        if entry.depth() == 0 {
            continue;
        }
        let relative = match entry.path().strip_prefix(root) {
            Ok(relative) => relative.to_path_buf(),
            Err(_) => {
                inventory.skipped.push(InventorySkip {
                    path: Some(entry.path().to_path_buf()),
                    reason: String::from("walker returned a path outside the repository root"),
                });
                continue;
            }
        };
        let metadata = match fs::symlink_metadata(entry.path()) {
            Ok(metadata) => metadata,
            Err(error) => {
                inventory.skipped.push(InventorySkip {
                    path: Some(relative),
                    reason: error.to_string(),
                });
                continue;
            }
        };
        let file_type = metadata.file_type();
        let kind = if file_type.is_symlink() {
            InventoryKind::Symlink
        } else if file_type.is_dir() {
            InventoryKind::Directory
        } else if file_type.is_file() {
            InventoryKind::File
        } else {
            InventoryKind::Other
        };
        inventory.entries.push(InventoryEntry {
            path: relative,
            kind,
            size_bytes: metadata.len(),
        });
    }

    inventory.entries.sort();
    inventory.skipped.sort();
    if inventory.entries.len() > options.max_entries {
        let omitted = inventory.entries.len() - options.max_entries;
        inventory.entries.truncate(options.max_entries);
        inventory.skipped.push(InventorySkip {
            path: None,
            reason: format!("inventory entry limit reached; {omitted} entries omitted"),
        });
    }
    Ok(inventory)
}

fn ignore_error_path(error: &ignore::Error) -> Option<PathBuf> {
    match error {
        ignore::Error::WithPath { path, .. } => Some(path.clone()),
        ignore::Error::WithLineNumber { err, .. } | ignore::Error::WithDepth { err, .. } => {
            ignore_error_path(err)
        }
        ignore::Error::Loop { child, .. } => Some(child.clone()),
        ignore::Error::Partial(errors) => errors.iter().find_map(ignore_error_path),
        ignore::Error::Io(_)
        | ignore::Error::Glob { .. }
        | ignore::Error::UnrecognizedFileType(_)
        | ignore::Error::InvalidDefinition => None,
    }
}

/// Reads at most `max_text_file_bytes + 1` bytes without following any symlink component.
pub fn read_bounded_text(
    root: &Path,
    relative: &RepoRelativePath,
    max_text_file_bytes: u64,
) -> Result<BoundedText, InventoryError> {
    reject_symlink_components(root, relative.as_path())?;
    let path = root.join(relative.as_path());
    let file = File::open(&path).map_err(|source| InventoryError::Io {
        path: path.clone(),
        source,
    })?;
    let read_limit = max_text_file_bytes.saturating_add(1);
    let mut bytes = Vec::new();
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|source| InventoryError::Io {
            path: path.clone(),
            source,
        })?;
    let truncated = bytes.len() as u64 > max_text_file_bytes;
    if truncated {
        let retained = match usize::try_from(max_text_file_bytes) {
            Ok(retained) => retained,
            Err(_) => usize::MAX,
        };
        bytes.truncate(retained);
    }
    let binary = bytes.contains(&0);
    Ok(BoundedText {
        bytes,
        truncated,
        binary,
    })
}

fn reject_symlink_components(root: &Path, relative: &Path) -> Result<(), InventoryError> {
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        let metadata = fs::symlink_metadata(&current).map_err(|source| InventoryError::Io {
            path: current.clone(),
            source,
        })?;
        if metadata.file_type().is_symlink() {
            return Err(InventoryError::Symlink(current));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use forge_core::RepoRelativePath;
    use tempfile::tempdir;

    use super::{InventoryKind, InventoryOptions, build_inventory, read_bounded_text};

    #[test]
    fn inventory_respects_gitignore_and_generated_directory_boundaries()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        fs::write(directory.path().join(".gitignore"), "ignored.txt\n")?;
        fs::write(directory.path().join("kept.txt"), "kept")?;
        fs::write(directory.path().join("ignored.txt"), "ignored")?;
        fs::create_dir(directory.path().join("target"))?;
        fs::write(directory.path().join("target/generated"), "generated")?;

        let inventory = build_inventory(directory.path(), InventoryOptions::default())?;
        let paths: Vec<_> = inventory
            .entries
            .iter()
            .map(|entry| entry.path.as_path())
            .collect();

        assert!(paths.contains(&std::path::Path::new("kept.txt")));
        assert!(!paths.contains(&std::path::Path::new("ignored.txt")));
        assert!(!paths.iter().any(|path| path.starts_with("target")));
        Ok(())
    }

    #[test]
    fn bounded_text_reports_truncation_and_binary_content() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempdir()?;
        fs::write(directory.path().join("data.bin"), b"abc\0def")?;
        let relative = RepoRelativePath::new("data.bin")?;

        let text = read_bounded_text(directory.path(), &relative, 5)?;

        assert_eq!(text.bytes, b"abc\0d");
        assert!(text.truncated);
        assert!(text.binary);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlink_is_inventoried_but_never_followed() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let directory = tempdir()?;
        let outside = tempdir()?;
        fs::write(outside.path().join("secret"), "do not read")?;
        symlink(outside.path(), directory.path().join("link"))?;

        let inventory = build_inventory(directory.path(), InventoryOptions::default())?;
        let link = inventory
            .entries
            .iter()
            .find(|entry| entry.path == std::path::Path::new("link"));
        assert!(link.is_some_and(|entry| entry.kind == InventoryKind::Symlink));
        assert!(
            !inventory
                .entries
                .iter()
                .any(|entry| entry.path != std::path::Path::new("link")
                    && entry.path.starts_with("link"))
        );
        Ok(())
    }
}
