//! Deterministic rendering primitives for Forge.

#![forbid(unsafe_code)]

pub mod adapters;
pub mod apply;
pub mod digest;
pub mod managed_block;
pub mod plan;

pub use adapters::{AGENTS_MAX_BYTES, AGENTS_MAX_LINES};
pub use apply::{ApplyError, ApplyErrorKind, ApplyReport, WrittenFile, apply_change_plan};
pub use digest::repository_file_digest;
pub use plan::{
    AdapterTarget, ChangePlan, DesiredManagedBlock, FileEdit, FileEditKind, InitPlanOptions,
    ManagedBlockKind, PlanError, RollbackPlan, SkippedChange, SkippedReason, plan_init,
};
