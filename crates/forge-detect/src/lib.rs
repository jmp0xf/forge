//! Repository detection and language providers.

#![forbid(unsafe_code)]

pub mod assets;
pub mod config;
pub mod go;
pub mod inventory_cache;
pub mod model;
pub mod policy;
pub mod repository;
pub mod resolution;
pub mod runner;
pub mod rust;
pub mod script;
pub mod workflow;

#[cfg(test)]
pub(crate) mod test_support {
    use std::path::{Path, PathBuf};

    pub(crate) fn repository_root() -> &'static Path {
        #[cfg(windows)]
        {
            Path::new(r"C:\repo")
        }
        #[cfg(not(windows))]
        {
            Path::new("/repo")
        }
    }

    pub(crate) fn repository_path(path: impl AsRef<Path>) -> PathBuf {
        repository_root().join(path)
    }

    pub(crate) fn absolute_path(path: impl AsRef<Path>) -> PathBuf {
        #[cfg(windows)]
        let root = Path::new(r"C:\");
        #[cfg(not(windows))]
        let root = Path::new("/");

        root.join(path)
    }
}
