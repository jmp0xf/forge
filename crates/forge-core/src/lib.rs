//! Pure domain model for Forge.
//!
//! This crate must not perform filesystem, Git, process, clock, or network I/O.

#![forbid(unsafe_code)]

pub mod branding;
pub mod domain;
pub mod error;
pub mod git;
pub mod path;
pub mod ports;

pub use domain::{
    CommandSource, CommandSpec, Confidence, CoverageDimension, Intent, Mutability, NetworkIntent,
    ProjectModel, ProjectUnit, SuccessPredicate,
};
pub use error::{AppError, ExitCode};
pub use forge_schema::Digest;
pub use git::{
    AheadBehind, BranchHead, BranchOid, BranchStatus, ChangeKind, GitMode, GitObjectFormat,
    GitObjectId, GitRefName, OrdinaryEntry, PorcelainV2ParseError, PorcelainV2ParseErrorKind,
    PorcelainV2ReadError, PorcelainV2Status, RenameOrCopy, RenamedOrCopiedEntry, StatusEntry,
    SubmoduleState, UnmergedEntry, XyStatus, parse_status_porcelain_v2,
    parse_status_porcelain_v2_reader,
};
pub use path::{RelativePathError, RepoRelativePath};
