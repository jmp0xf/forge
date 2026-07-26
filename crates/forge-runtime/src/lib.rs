//! Concrete side-effect boundary for Forge.
//!
//! M1 implements typed Git porcelain calls, atomic files, state locking, bounded output,
//! timeout handling, and cross-platform process-tree termination here.

#![forbid(unsafe_code)]

pub mod fs;
pub mod git;
pub mod process;
pub mod state;

/// Production runtime composition marker.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealRuntime;
