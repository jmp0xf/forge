//! Pure domain model for Forge.
//!
//! This crate must not perform filesystem, Git, process, clock, or network I/O.

#![forbid(unsafe_code)]

pub mod branding;
pub mod context;
pub mod doctor;
pub mod domain;
pub mod error;
pub mod evidence;
pub mod fingerprint;
pub mod git;
pub mod inventory;
pub mod navigation;
pub mod path;
pub mod policy;
pub mod ports;
pub mod risk;
pub mod scope;
pub mod wire;

pub use domain::{
    AdapterInfo, AdapterInventory, AssetInfo, AssetInventory, Assumption, CommandResolution,
    CommandSource, CommandSpec, CommitId, Confidence, CoverageDimension, EffectivePolicy, Intent,
    InvalidCommandResolution, InvalidTextRange, Mutability, NetworkIntent, ProjectKind,
    ProjectModel, ProjectModelError, ProjectModelInputs, ProjectUnit, Provenance, RepoFacts,
    ResolvedCommandSet, SuccessPredicate, TextRange, ToolchainInfo, UnitEdge, UpstreamState,
    WorkState,
};
pub use error::{AppError, ExitCode};
pub use forge_schema::{Diagnostic, Digest, RepoId, Severity};
pub use git::{
    AheadBehind, BranchHead, BranchOid, BranchStatus, ChangeKind, GitError, GitErrorKind,
    GitFileSet, GitIndexEntry, GitIndexReadError, GitIndexTag, GitMode, GitObjectFormat,
    GitObjectId, GitPathListReadError, GitRefName, OrdinaryEntry, PorcelainV2ParseError,
    PorcelainV2ParseErrorKind, PorcelainV2ReadError, PorcelainV2Status, RenameOrCopy,
    RenamedOrCopiedEntry, StatusEntry, SubmoduleState, UnmergedEntry, XyStatus,
    parse_git_index_reader, parse_git_path_list_reader, parse_status_porcelain_v2,
    parse_status_porcelain_v2_reader,
};
pub use inventory::{
    BoundedText, Inventory, InventoryEntry, InventoryError, InventoryKind, InventoryOptions,
    InventorySkip, PathKind,
};
pub use path::{RelativePathError, RepoRelativePath};
pub use policy::{
    EffectivePolicyContent, EvidenceRequirements, PathPattern, PolicyError, RiskLevel, RiskRule,
};
pub use risk::{RiskAssessment, RiskMatch, assess_risk, built_in_policy};
pub use wire::{
    ProjectModelWireError, command_detail_v2_to_wire, comparison_basis_v2_to_wire,
    coverage_dimension_name, evidence_outcome_to_wire, intent_to_wire,
    local_evidence_state_to_wire, non_satisfying_receipt_validity_v2_to_wire,
    project_model_to_wire, receipt_dependencies_v2_to_wire,
};
