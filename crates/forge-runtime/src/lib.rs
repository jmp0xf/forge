//! Concrete side-effect boundary for Forge.
//!
//! M1 implements typed Git porcelain calls, atomic files, state locking, bounded output,
//! timeout handling, and cross-platform process-tree termination here.

// Windows Job Objects require a small, isolated FFI module. Keep unsafe denied everywhere
// else; the platform module must opt in locally and document each invariant.
#![deny(unsafe_code)]

pub mod clock;
pub mod fs;
pub mod git;
pub mod hash;
pub mod interrupt;
pub mod inventory;
pub mod process;
pub mod scope;
pub mod state;

/// Production runtime composition marker.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealRuntime;
