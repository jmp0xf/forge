//! Synchronous subprocess runtime placeholder.

/// Marker for the argv-only synchronous executor added in M1.
#[derive(Debug, Default, Clone, Copy)]
pub struct SynchronousProcessRunner;
