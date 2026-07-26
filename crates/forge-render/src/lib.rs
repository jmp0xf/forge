//! Deterministic rendering primitives for Forge.

#![forbid(unsafe_code)]

pub mod managed_block;

/// A planned working-tree edit. Application and preimage validation arrive in M4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileEdit {
    Create { path: String, content: Vec<u8> },
    ReplaceManagedBlock {
        path: String,
        block_id: String,
        expected_preimage: String,
        content: Vec<u8>,
    },
}

/// A deterministic, reviewable set of edits.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChangePlan {
    pub edits: Vec<FileEdit>,
    pub assumptions: Vec<String>,
}
