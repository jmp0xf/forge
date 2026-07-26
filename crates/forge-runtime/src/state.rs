//! Per-worktree state runtime placeholder.

/// State is placed below the worktree-specific Git directory.
pub const STATE_LAYOUT_VERSION: u16 = 1;

/// Shared cache is allowed only for immutable, content-addressed entries.
pub const SHARED_CACHE_LAYOUT_VERSION: u16 = 1;
