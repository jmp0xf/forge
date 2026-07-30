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
        Self::validate(path)?;

        let mut normalized = PathBuf::new();
        for component in path.components() {
            match component {
                Component::CurDir => {}
                Component::Normal(value) => normalized.push(value),
                // Keep construction defensive even though `validate` just checked the same
                // components. A future validation refactor must not turn malformed input into a
                // production panic.
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

    /// Validates the repository-relative lexical contract without allocating a normalized path.
    ///
    /// Inventory classifiers use this when most paths will not be retained as typed values.
    pub fn validate(path: impl AsRef<Path>) -> Result<(), RelativePathError> {
        let path = path.as_ref();
        if contains_nul(path.as_os_str()) {
            return Err(RelativePathError::Nul);
        }

        for component in path.components() {
            match component {
                Component::CurDir => {}
                Component::Normal(_) => {}
                Component::ParentDir => return Err(RelativePathError::ParentTraversal),
                Component::RootDir | Component::Prefix(_) => {
                    return Err(RelativePathError::Absolute);
                }
            }
        }
        Ok(())
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

/// Projects one native repository-relative path into the portable UTF-8 grammar used by
/// configuration patterns and generated text.
///
/// Native paths remain authoritative for filesystem access, wire round-trips, and evidence
/// fingerprints. This projection changes only separators: each native normal component is joined
/// with `/`, while absolute, parent-traversing, and non-UTF-8 paths fail closed. The repository
/// root is represented as `.`.
#[must_use]
pub fn portable_relative_utf8_path(path: &Path) -> Option<String> {
    let mut rendered = String::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(component) => {
                let component = component.to_str()?;
                if !rendered.is_empty() {
                    rendered.push('/');
                }
                rendered.push_str(component);
            }
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(if rendered.is_empty() {
        String::from(".")
    } else {
        rendered
    })
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
    use std::path::{Path, PathBuf};

    use super::{RelativePathError, RepoRelativePath, portable_relative_utf8_path};

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

    #[test]
    fn portable_projection_joins_native_components_with_forward_slashes() {
        let native = PathBuf::from_iter([".github", "workflows", "verify.yml"]);
        assert_eq!(
            portable_relative_utf8_path(&native).as_deref(),
            Some(".github/workflows/verify.yml")
        );
        assert_eq!(
            portable_relative_utf8_path(Path::new(".")).as_deref(),
            Some(".")
        );
    }
}
