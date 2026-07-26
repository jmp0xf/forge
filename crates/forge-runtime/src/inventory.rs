//! Read-only repository inventory with standard ignore handling.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};

use forge_core::ports::GitPort;
use forge_core::{GitFileSet, RepoRelativePath};
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use ignore::{Match, WalkBuilder};
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
    #[error("Git-backed repository inventory failed: {0}")]
    Git(#[source] io::Error),
    #[error(
        "repository inventory contains {observed} entries, exceeding the configured {max_entries}-entry bound"
    )]
    EntryLimit { max_entries: usize, observed: usize },
}

/// Builds a Git-backed inventory from the index plus untracked, non-Git-ignored paths.
///
/// Git owns tracked, `.gitignore`, info-exclude, and global-exclude semantics. Supplementary
/// `.ignore` files are applied only to untracked candidates, so a tracked file can never disappear
/// merely because a later ignore rule matches it. Git lists paths without traversing generated
/// directories; tracked paths in such directories remain authoritative. No symlink is followed.
pub fn build_git_inventory<G>(
    root: &Path,
    git: &G,
    options: InventoryOptions,
) -> Result<Inventory, InventoryError>
where
    G: GitPort,
{
    validate_root(root)?;
    let file_set = git.file_set(root).map_err(InventoryError::Git)?;
    build_inventory_from_git_file_set(root, &file_set, options)
}

fn build_inventory_from_git_file_set(
    root: &Path,
    file_set: &GitFileSet,
    options: InventoryOptions,
) -> Result<Inventory, InventoryError> {
    let mut inventory = Inventory::default();
    let dot_ignore_matchers = load_dot_ignore_matchers(
        root,
        file_set,
        options.max_text_file_bytes,
        &mut inventory.skipped,
    );
    let mut seen = BTreeSet::new();

    for path in &file_set.tracked {
        if seen.insert(path.clone()) {
            inventory_path(root, path, &mut inventory);
        }
    }
    for path in &file_set.untracked {
        if seen.contains(path) || dot_ignore_match(&dot_ignore_matchers, root, path).is_ignore() {
            continue;
        }
        seen.insert(path.clone());
        inventory_path(root, path, &mut inventory);
    }

    finish_inventory(inventory, options)
}

/// Filesystem-only fallback for callers that have explicitly established a non-Git context.
///
/// Unlike [`build_git_inventory`], this walker cannot distinguish tracked files from ignored
/// untracked files. It must therefore never be used as the inventory source for a Git repository.
pub fn build_non_git_filesystem_inventory(
    root: &Path,
    options: InventoryOptions,
) -> Result<Inventory, InventoryError> {
    validate_root(root)?;
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

    finish_inventory(inventory, options)
}

fn validate_root(root: &Path) -> Result<(), InventoryError> {
    let root_metadata = fs::symlink_metadata(root).map_err(|source| InventoryError::Io {
        path: root.to_path_buf(),
        source,
    })?;
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
        return Err(InventoryError::InvalidRoot(root.to_path_buf()));
    }
    Ok(())
}

fn finish_inventory(
    mut inventory: Inventory,
    options: InventoryOptions,
) -> Result<Inventory, InventoryError> {
    inventory.entries.sort();
    inventory.skipped.sort();
    if inventory.entries.len() > options.max_entries {
        return Err(InventoryError::EntryLimit {
            max_entries: options.max_entries,
            observed: inventory.entries.len(),
        });
    }
    Ok(inventory)
}

fn inventory_path(root: &Path, relative: &RepoRelativePath, inventory: &mut Inventory) {
    if let Err(error) = reject_symlink_ancestors(root, relative.as_path()) {
        inventory.skipped.push(InventorySkip {
            path: Some(relative.as_path().to_path_buf()),
            reason: error.to_string(),
        });
        return;
    }
    let path = root.join(relative.as_path());
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) => {
            inventory.skipped.push(InventorySkip {
                path: Some(relative.as_path().to_path_buf()),
                reason: error.to_string(),
            });
            return;
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
        path: relative.as_path().to_path_buf(),
        kind,
        size_bytes: metadata.len(),
    });
}

#[derive(Debug)]
struct DotIgnoreMatcher {
    directory: PathBuf,
    matcher: Gitignore,
}

fn load_dot_ignore_matchers(
    root: &Path,
    file_set: &GitFileSet,
    max_text_file_bytes: u64,
    skipped: &mut Vec<InventorySkip>,
) -> Vec<DotIgnoreMatcher> {
    let mut ignore_paths: Vec<_> = file_set
        .tracked
        .iter()
        .chain(&file_set.untracked)
        .filter(|path| path.as_path().file_name() == Some(OsStr::new(".ignore")))
        .cloned()
        .collect();
    ignore_paths.sort_by(|left, right| {
        left.as_path()
            .components()
            .count()
            .cmp(&right.as_path().components().count())
            .then_with(|| left.cmp(right))
    });
    ignore_paths.dedup();

    let mut matchers = Vec::new();
    for relative in ignore_paths {
        if dot_ignore_match(&matchers, root, &relative).is_ignore() {
            continue;
        }
        let text = match read_bounded_text(root, &relative, max_text_file_bytes) {
            Ok(text) => text,
            Err(error) => {
                push_dot_ignore_skip(
                    skipped,
                    &relative,
                    format!("the file is unreadable: {error}"),
                );
                continue;
            }
        };
        if text.truncated {
            push_dot_ignore_skip(
                skipped,
                &relative,
                format!("the file exceeds the {max_text_file_bytes}-byte text bound"),
            );
            continue;
        }
        if text.binary {
            push_dot_ignore_skip(
                skipped,
                &relative,
                String::from("the file contains NUL bytes"),
            );
            continue;
        }
        let contents = match std::str::from_utf8(&text.bytes) {
            Ok(contents) => contents,
            Err(_) => {
                push_dot_ignore_skip(
                    skipped,
                    &relative,
                    String::from("the file is not valid UTF-8"),
                );
                continue;
            }
        };

        let directory = relative
            .as_path()
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .to_path_buf();
        let absolute = root.join(relative.as_path());
        let mut builder = GitignoreBuilder::new(root.join(&directory));
        let mut invalid_rules = 0_usize;
        for (index, line) in contents.lines().enumerate() {
            let line = if index == 0 {
                line.trim_start_matches('\u{feff}')
            } else {
                line
            };
            if builder.add_line(Some(absolute.clone()), line).is_err() {
                invalid_rules = invalid_rules.saturating_add(1);
            }
        }
        let matcher = match builder.build() {
            Ok(matcher) => matcher,
            Err(_) => {
                push_dot_ignore_skip(
                    skipped,
                    &relative,
                    String::from("the bounded rule set could not be compiled"),
                );
                continue;
            }
        };
        if invalid_rules > 0 {
            skipped.push(InventorySkip {
                path: Some(relative.as_path().to_path_buf()),
                reason: format!(
                    "partially applied .ignore rules; {invalid_rules} invalid rule(s) were skipped"
                ),
            });
        }
        matchers.push(DotIgnoreMatcher { directory, matcher });
    }
    matchers
}

fn push_dot_ignore_skip(
    skipped: &mut Vec<InventorySkip>,
    relative: &RepoRelativePath,
    reason: String,
) {
    skipped.push(InventorySkip {
        path: Some(relative.as_path().to_path_buf()),
        reason: format!("ignored .ignore rules because {reason}"),
    });
}

fn dot_ignore_match<'a>(
    matchers: &'a [DotIgnoreMatcher],
    root: &Path,
    relative: &RepoRelativePath,
) -> Match<&'a ignore::gitignore::Glob> {
    let absolute = root.join(relative.as_path());
    for matcher in matchers.iter().rev() {
        if !relative.as_path().starts_with(&matcher.directory) {
            continue;
        }
        let matched = matcher
            .matcher
            .matched_path_or_any_parents(&absolute, false);
        if !matched.is_none() {
            return matched;
        }
    }
    Match::None
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

fn reject_symlink_ancestors(root: &Path, relative: &Path) -> Result<(), InventoryError> {
    let mut current = root.to_path_buf();
    let mut components = relative.components().peekable();
    while let Some(component) = components.next() {
        if components.peek().is_none() {
            break;
        }
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

    use super::{
        InventoryKind, InventoryOptions, build_non_git_filesystem_inventory, read_bounded_text,
    };

    #[test]
    fn inventory_respects_gitignore_and_generated_directory_boundaries()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        fs::write(directory.path().join(".gitignore"), "ignored.txt\n")?;
        fs::write(directory.path().join("kept.txt"), "kept")?;
        fs::write(directory.path().join("ignored.txt"), "ignored")?;
        fs::create_dir(directory.path().join("target"))?;
        fs::write(directory.path().join("target/generated"), "generated")?;

        let inventory =
            build_non_git_filesystem_inventory(directory.path(), InventoryOptions::default())?;
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

        let inventory =
            build_non_git_filesystem_inventory(directory.path(), InventoryOptions::default())?;
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
