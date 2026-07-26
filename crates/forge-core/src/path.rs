//! Pure validation for repository-relative native paths.

use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

use thiserror::Error;

/// A normalized native path that cannot escape its repository root lexically.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RepoRelativePath(PathBuf);

impl RepoRelativePath {
    /// Repository root, represented without an absolute host path.
    #[must_use]
    pub fn root() -> Self {
        Self(PathBuf::from("."))
    }

    pub fn new(path: impl AsRef<Path>) -> Result<Self, RelativePathError> {
        let path = path.as_ref();
        if contains_nul(path.as_os_str()) {
            return Err(RelativePathError::Nul);
        }

        let mut normalized = PathBuf::new();
        for component in path.components() {
            match component {
                Component::CurDir => {}
                Component::Normal(value) => normalized.push(value),
                Component::ParentDir => return Err(RelativePathError::ParentTraversal),
                Component::RootDir | Component::Prefix(_) => {
                    return Err(RelativePathError::Absolute);
                }
            }
        }
        if normalized.as_os_str().is_empty() {
            normalized.push(".");
        }
        Ok(Self(normalized))
    }

    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    #[must_use]
    pub fn into_path_buf(self) -> PathBuf {
        self.0
    }
}

impl AsRef<Path> for RepoRelativePath {
    fn as_ref(&self) -> &Path {
        self.as_path()
    }
}

/// A lexical repository-relative path violation.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RelativePathError {
    #[error("repository-relative paths must not be absolute")]
    Absolute,
    #[error("repository-relative paths must not contain `..`")]
    ParentTraversal,
    #[error("repository-relative paths must not contain NUL")]
    Nul,
}

#[cfg(unix)]
fn contains_nul(value: &OsStr) -> bool {
    use std::os::unix::ffi::OsStrExt as _;

    value.as_bytes().contains(&0)
}

#[cfg(windows)]
fn contains_nul(value: &OsStr) -> bool {
    use std::os::windows::ffi::OsStrExt as _;

    value.encode_wide().any(|unit| unit == 0)
}

#[cfg(not(any(unix, windows)))]
fn contains_nul(value: &OsStr) -> bool {
    value.to_string_lossy().contains('\0')
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{RelativePathError, RepoRelativePath};

    #[test]
    fn root_and_normal_paths_are_normalized() -> Result<(), RelativePathError> {
        assert_eq!(RepoRelativePath::new(".")?.as_path(), Path::new("."));
        assert_eq!(
            RepoRelativePath::new("./crates/forge-core")?.as_path(),
            Path::new("crates/forge-core")
        );
        Ok(())
    }

    #[test]
    fn escape_paths_are_rejected() {
        assert_eq!(
            RepoRelativePath::new("../outside"),
            Err(RelativePathError::ParentTraversal)
        );
        assert_eq!(
            RepoRelativePath::new("/outside"),
            Err(RelativePathError::Absolute)
        );
    }
}
