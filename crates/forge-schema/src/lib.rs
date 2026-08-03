//! Versioned machine-readable contracts for Forge.

#![forbid(unsafe_code)]

mod contracts;
mod diagnostic;
pub mod exact_json;
mod ids;
mod path;

pub use contracts::*;
pub use diagnostic::{ArtifactRef, Diagnostic, Severity};
pub use ids::{
    CommandId, DiagnosticCode, Digest, EvidenceId, LanguageId, ManagedBlockId, ReceiptId, RepoId,
    UnitId,
};
pub use path::{PathEncoding, WirePath, WirePathError};

/// The public wire namespace.
pub const SCHEMA_NAMESPACE: &str = "forge";
