//! Side-effect ports implemented by `forge-runtime`.

use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::domain::CommandSpec;
use crate::git::{GitFileSet, PorcelainV2Status};
use crate::inventory::{BoundedText, Inventory, InventoryError, InventoryOptions, PathKind};
use crate::path::RepoRelativePath;
use forge_schema::Digest;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessObservation {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_total_bytes: u64,
    pub stderr_total_bytes: u64,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub duration: Duration,
    pub timed_out: bool,
    pub interrupted: bool,
}

pub trait ProcessPort {
    fn run(&self, spec: &CommandSpec) -> io::Result<ProcessObservation>;
}

pub trait FileSystemPort {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>>;
    /// Inventories a repository using an explicit authority for candidate paths.
    ///
    /// `Some(file_set)` preserves every Git-tracked path, applies Git ignore semantics only to
    /// untracked candidates, and applies supplementary `.ignore` rules only to those untracked
    /// candidates. `None` selects the filesystem-walking fallback and must only be used after the
    /// caller has established that the root is not a Git repository.
    fn inventory(
        &self,
        root: &Path,
        file_set: Option<&GitFileSet>,
        options: InventoryOptions,
    ) -> Result<Inventory, InventoryError>;
    /// Reads a repository-relative text candidate up to the configured byte bound.
    fn read_bounded_text(
        &self,
        root: &Path,
        path: &RepoRelativePath,
        max_text_file_bytes: u64,
    ) -> Result<BoundedText, InventoryError>;
    /// Inspects one repository-relative path without following symbolic links.
    ///
    /// Missing paths are represented explicitly; permission and other I/O failures remain errors.
    fn path_kind(&self, root: &Path, path: &RepoRelativePath) -> io::Result<PathKind>;
    fn write_atomic(&self, path: &Path, bytes: &[u8]) -> io::Result<()>;
    fn exists(&self, path: &Path) -> bool;
}

pub trait GitPort {
    fn repository_root(&self, start: &Path) -> io::Result<PathBuf>;
    fn git_dir(&self, start: &Path) -> io::Result<PathBuf>;
    fn git_common_dir(&self, start: &Path) -> io::Result<PathBuf>;
    fn status(&self, root: &Path) -> io::Result<PorcelainV2Status>;
    fn file_set(&self, root: &Path) -> io::Result<GitFileSet>;
}

pub trait StateStore {
    fn load(&self, key: &str) -> io::Result<Option<Vec<u8>>>;
    fn store_atomic(&self, key: &str, bytes: &[u8]) -> io::Result<()>;
}

pub trait Clock {
    fn now(&self) -> SystemTime;
}

pub trait Hasher {
    fn digest(&self, chunks: &[&[u8]]) -> Digest;
}
