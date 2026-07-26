//! Versioned machine-readable contracts for Forge.
//!
//! The bootstrap intentionally avoids serialization dependencies. M0 adds `serde` and
//! `schemars` after the dependency compatibility spike, while preserving these names.

#![forbid(unsafe_code)]

/// The public wire namespace.
pub const SCHEMA_NAMESPACE: &str = "forge";

/// Machine-readable contracts planned for the first implementation stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SchemaKind {
    InitPlan,
    Doctor,
    Next,
    ProjectModel,
    Receipt,
    Evidence,
    Adapters,
    Diagnostic,
}

impl SchemaKind {
    /// Returns the stable schema identifier for the first major version.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::InitPlan => "forge.init-plan/v1",
            Self::Doctor => "forge.doctor/v1",
            Self::Next => "forge.next/v1",
            Self::ProjectModel => "forge.model/v1",
            Self::Receipt => "forge.receipt/v1",
            Self::Evidence => "forge.evidence/v1",
            Self::Adapters => "forge.adapters/v1",
            Self::Diagnostic => "forge.diagnostic/v1",
        }
    }

    /// Returns every schema kind in a deterministic order.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::InitPlan,
            Self::Doctor,
            Self::Next,
            Self::ProjectModel,
            Self::Receipt,
            Self::Evidence,
            Self::Adapters,
            Self::Diagnostic,
        ]
    }
}

/// A semantic schema version independent from the Forge binary version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SchemaVersion {
    pub domain: &'static str,
    pub major: u16,
}

impl SchemaVersion {
    #[must_use]
    pub const fn new(domain: &'static str, major: u16) -> Self {
        Self { domain, major }
    }
}

#[cfg(test)]
mod tests {
    use super::SchemaKind;

    #[test]
    fn schema_ids_are_namespaced_and_versioned() {
        for kind in SchemaKind::all() {
            let id = kind.id();
            assert!(id.starts_with("forge."));
            assert!(id.ends_with("/v1"));
        }
    }
}
