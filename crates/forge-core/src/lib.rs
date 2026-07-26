//! Pure domain model for Forge.
//!
//! This crate must not perform filesystem, Git, process, clock, or network I/O.

#![forbid(unsafe_code)]

pub mod branding;
pub mod domain;
pub mod error;
pub mod git;
pub mod inventory;
pub mod path;
pub mod ports;

pub use domain::{
    AdapterInfo, AdapterInventory, AssetInfo, AssetInventory, Assumption, CommandResolution,
    CommandSource, CommandSpec, CommitId, Confidence, CoverageDimension, EffectivePolicy, Intent,
    InvalidCommandResolution, InvalidTextRange, Mutability, NetworkIntent, ProjectKind,
    ProjectModel, ProjectUnit, Provenance, RepoFacts, ResolvedCommandSet, SuccessPredicate,
    TextRange, ToolchainInfo, UnitEdge, UpstreamState, WorkState,
};
pub use error::{AppError, ExitCode};
pub use forge_schema::{Diagnostic, Digest, Severity};
pub use git::{
    AheadBehind, BranchHead, BranchOid, BranchStatus, ChangeKind, GitError, GitErrorKind,
    GitFileSet, GitMode, GitObjectFormat, GitObjectId, GitPathListReadError, GitRefName,
    OrdinaryEntry, PorcelainV2ParseError, PorcelainV2ParseErrorKind, PorcelainV2ReadError,
    PorcelainV2Status, RenameOrCopy, RenamedOrCopiedEntry, StatusEntry, SubmoduleState,
    UnmergedEntry, XyStatus, parse_git_path_list_reader, parse_status_porcelain_v2,
    parse_status_porcelain_v2_reader,
};
pub use inventory::{
    BoundedText, Inventory, InventoryEntry, InventoryError, InventoryKind, InventoryOptions,
    InventorySkip, PathKind,
};
pub use path::{RelativePathError, RepoRelativePath};
