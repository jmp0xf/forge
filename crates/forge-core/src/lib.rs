//! Pure domain model for Forge.
//!
//! This crate must not perform filesystem, Git, process, clock, or network I/O.

#![forbid(unsafe_code)]

pub mod branding;
pub mod domain;
pub mod error;
pub mod path;
pub mod ports;

pub use domain::{
    CommandSource, CommandSpec, Confidence, CoverageDimension, Intent, Mutability, NetworkIntent,
    ProjectModel, ProjectUnit, SuccessPredicate,
};
pub use error::{AppError, ExitCode};
pub use path::{RelativePathError, RepoRelativePath};
