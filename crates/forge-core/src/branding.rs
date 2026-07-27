//! Product identity is centralized so names do not leak through business logic.

/// CLI binary name.
pub const CLI_NAME: &str = "forge";
/// Human-readable product name.
pub const DISPLAY_NAME: &str = "Forge";
/// Optional repository-root configuration file.
pub const CONFIG_FILE: &str = "forge.toml";
/// Runtime state namespace below the per-worktree Git directory.
pub const STATE_NAMESPACE: &str = "forge";
/// Managed-block marker namespace.
pub const BLOCK_NAMESPACE: &str = "forge";
/// Machine-contract namespace.
pub const SCHEMA_NAMESPACE: &str = "forge";
