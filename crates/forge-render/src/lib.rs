//! Deterministic rendering primitives for Forge.

#![forbid(unsafe_code)]

pub mod adapter_registry;
pub mod adapters;
pub mod apply;
pub mod ci;
pub mod digest;
pub mod inspection;
pub mod managed_block;
pub mod plan;
pub mod runners;

pub use adapter_registry::{
    AdapterRenderer, AdapterSelection, AdapterSpec, adapter_spec, adapter_specs,
    managed_adapter_spec, managed_adapter_spec_for_path,
};
pub use adapters::{AGENTS_MAX_BYTES, AGENTS_MAX_LINES};
pub use apply::{ApplyError, ApplyErrorKind, ApplyReport, WrittenFile, apply_change_plan};
pub use ci::{CiEquivalence, CiRenderError, CiTarget};
pub use digest::repository_file_digest;
pub use inspection::{
    ADAPTER_FILE_MAX_BYTES, AdapterInspectionError, AdapterInspectionKind, AdapterInspectionReport,
    AdapterInspectionRequest, AdapterInspectionState, AdapterTargetInspection, FileEditReason,
    InspectedFileEdit, inspect_adapter_targets,
};
pub use plan::{
    AdapterFileLimitStage, AdapterSelectionOverrides, AdapterTarget, ChangePlan, DesiredFile,
    DesiredManagedBlock, FileEdit, FileEditKind, GapKind, InitAdapterInspection,
    InitAdapterTargetInspection, InitGap, InitPlanOptions, InitWholeFileTargetInspection,
    ManagedBlockKind, PlanError, ReusedAdapter, RollbackPlan, SatisfiedManagedBlock, SkippedChange,
    SkippedReason, WholeFileInspectionState, inspect_init_targets, plan_init,
};
pub use runners::{RunnerRenderError, RunnerTarget};
