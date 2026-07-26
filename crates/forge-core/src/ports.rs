//! Side-effect ports implemented by `forge-runtime`.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::domain::CommandSpec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessObservation {
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub duration: Duration,
    pub timed_out: bool,
}

pub trait ProcessPort {
    fn run(&self, spec: &CommandSpec) -> io::Result<ProcessObservation>;
}

pub trait FileSystemPort {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>>;
    fn write_atomic(&self, path: &Path, bytes: &[u8]) -> io::Result<()>;
    fn exists(&self, path: &Path) -> bool;
}

pub trait GitPort {
    fn repository_root(&self, start: &Path) -> io::Result<PathBuf>;
    fn git_dir(&self, start: &Path) -> io::Result<PathBuf>;
    fn git_common_dir(&self, start: &Path) -> io::Result<PathBuf>;
    fn status_porcelain_v2_z(&self, root: &Path) -> io::Result<Vec<u8>>;
}

pub trait StateStore {
    fn load(&self, key: &str) -> io::Result<Option<Vec<u8>>>;
    fn store_atomic(&self, key: &str, bytes: &[u8]) -> io::Result<()>;
}

pub trait Clock {
    fn now(&self) -> SystemTime;
}

pub trait Hasher {
    fn digest(&self, chunks: &[&[u8]]) -> OsString;
}
