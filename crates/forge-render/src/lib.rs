//! Deterministic rendering primitives for Forge.

#![forbid(unsafe_code)]

pub mod adapter_registry;
pub mod adapters;
pub mod apply;
pub mod digest;
pub mod inspection;
pub mod managed_block;
pub mod plan;

pub use adapter_registry::{
    AdapterRenderer, AdapterSelection, AdapterSpec, adapter_spec, adapter_specs,
    managed_adapter_spec, managed_adapter_spec_for_path,
};
pub use adapters::{AGENTS_MAX_BYTES, AGENTS_MAX_LINES};
pub use apply::{ApplyError, ApplyErrorKind, ApplyReport, WrittenFile, apply_change_plan};
pub use digest::repository_file_digest;
pub use inspection::{
    ADAPTER_FILE_MAX_BYTES, AdapterInspectionError, AdapterInspectionKind, AdapterInspectionReport,
    AdapterInspectionRequest, AdapterInspectionState, AdapterTargetInspection, FileEditReason,
    InspectedFileEdit, inspect_adapter_targets,
};
pub use plan::{
    AdapterFileLimitStage, AdapterTarget, ChangePlan, DesiredManagedBlock, FileEdit, FileEditKind,
    InitAdapterInspection, InitAdapterTargetInspection, InitPlanOptions, ManagedBlockKind,
    PlanError, ReusedAdapter, RollbackPlan, SatisfiedManagedBlock, SkippedChange, SkippedReason,
    inspect_init_targets, plan_init,
};
