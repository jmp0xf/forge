//! Pure, read-only planning for repository host adapters.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::io;

use forge_core::domain::{
    AssetInfo, Assumption, CommandResolution, CommandSource, Confidence, Intent, ProjectModel,
    ProjectModelError, Provenance,
};
use forge_core::ports::{Hasher, RepositoryFilePort};
use forge_core::{
    Digest, RelativePathError, RepoId, RepoRelativePath,
    branding::{CONFIG_FILE, DISPLAY_NAME},
};

use crate::adapter_registry::{AdapterSelection, adapter_specs, managed_adapter_spec};
use crate::adapters::{AGENTS_MAX_BYTES, AGENTS_MAX_LINES, AdapterRenderError};
use crate::ci::{
    CiEquivalence, CiRenderError, CiTarget, classify_github_workflow, render_github_workflow,
};
use crate::inspection::{
    AdapterInspectionError, AdapterInspectionKind, AdapterInspectionRequest,
    AdapterInspectionState, FileEditReason, inspect_adapter_targets,
};
use crate::managed_block::{
    LineEnding, ManagedBlock, ManagedBlockError, ManagedBlockSyntax, contains_managed_block_begin,
};
use crate::repository_file_digest;
use crate::runners::{RunnerRenderError, RunnerTarget, project_runner_model, render_runner_body};

const PLAN_SCHEMA: u16 = 1;
const MODEL_PROJECTION_DOMAIN: &[u8] = b"forge.init-model-projection/v1";
const GITATTRIBUTES_MAX_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdapterTarget {
    Claude,
    Cursor,
    Codex,
}

/// Explicit tri-state overrides for automatic host-adapter selection.
///
/// A direct CLI adapter request remains authoritative; these values only replace detection,
/// defaults, and private-manifest adoption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AdapterSelectionOverrides {
    pub agents: Option<bool>,
    pub claude: Option<bool>,
}

impl AdapterSelectionOverrides {
    #[must_use]
    pub const fn for_target(self, target: AdapterTarget) -> Option<bool> {
        match target {
            AdapterTarget::Codex => self.agents,
            AdapterTarget::Claude => self.claude,
            AdapterTarget::Cursor => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InitPlanOptions {
    /// Adapters directly requested by the caller; these override automatic-selection settings.
    pub adapters: Vec<AdapterTarget>,
    /// Adapters previously adopted in private state and eligible for default synchronization.
    pub adopted_adapters: Vec<AdapterTarget>,
    pub adapter_selection: AdapterSelectionOverrides,
    pub force_blocks: Vec<ManagedBlockKind>,
    pub runner: Option<RunnerTarget>,
    pub ci: Option<CiTarget>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ManagedBlockKind {
    ProjectIndex,
    ClaudePointer,
    RunnerMakeVerify,
    RunnerJustVerify,
    RunnerTaskVerify,
}

impl ManagedBlockKind {
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::ProjectIndex => "project-index",
            Self::ClaudePointer => "claude-pointer",
            Self::RunnerMakeVerify => "runner-make-verify",
            Self::RunnerJustVerify => "runner-just-verify",
            Self::RunnerTaskVerify => "runner-task-verify",
        }
    }

    #[must_use]
    pub const fn syntax(self) -> ManagedBlockSyntax {
        match self {
            Self::ProjectIndex | Self::ClaudePointer => ManagedBlockSyntax::Markdown,
            Self::RunnerMakeVerify | Self::RunnerJustVerify | Self::RunnerTaskVerify => {
                ManagedBlockSyntax::HashComment
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredManagedBlock {
    pub kind: ManagedBlockKind,
    pub body: String,
}

/// The generation strategy authorized for one planned file edit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DesiredFile {
    ManagedBlock(DesiredManagedBlock),
    /// A complete opt-in asset that can only be created, never replaced.
    WholeFile(CiTarget),
}

impl DesiredFile {
    #[must_use]
    pub const fn id(&self) -> &'static str {
        match self {
            Self::ManagedBlock(block) => block.kind.id(),
            Self::WholeFile(target) => target.id(),
        }
    }

    #[must_use]
    pub const fn managed_block(&self) -> Option<&DesiredManagedBlock> {
        match self {
            Self::ManagedBlock(block) => Some(block),
            Self::WholeFile(_) => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileEditKind {
    Create,
    ReplaceManagedBlock,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEdit {
    pub kind: FileEditKind,
    /// Observed repository fact that made this edit necessary.
    pub reason: FileEditReason,
    /// Reviewed fallback for a new file or an existing target with no reliable uniform style.
    pub fallback_line_ending: LineEnding,
    pub path: RepoRelativePath,
    pub desired: DesiredFile,
    pub expected_preimage: Option<Digest>,
    pub preview_postimage: Vec<u8>,
    pub expected_postimage: Digest,
    /// Explicit authorization to replace a user-edited block; never evidence that it was edited.
    pub force: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RollbackPlan {
    pub remove_created: Vec<RepoRelativePath>,
    pub restore_modified: Vec<RepoRelativePath>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SkippedReason {
    AlreadySatisfied,
    EquivalentUnmanaged,
    ReusesAgents(AdapterTarget),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SkippedChange {
    pub path: RepoRelativePath,
    pub reason: SkippedReason,
    pub satisfied_managed: Option<SatisfiedManagedBlock>,
}

/// The exact managed output proven satisfied during planning.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SatisfiedManagedBlock {
    pub kind: ManagedBlockKind,
    /// Digest of the complete satisfied file, including surrounding user-owned bytes.
    pub full_postimage_digest: Digest,
}

/// One desired init target coupled to its read-only repository observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitAdapterTargetInspection {
    pub path: RepoRelativePath,
    pub desired: DesiredManagedBlock,
    pub state: AdapterInspectionState,
}

impl InitAdapterTargetInspection {
    #[must_use]
    pub const fn kind(&self) -> AdapterInspectionKind {
        self.state.kind()
    }
}

/// Complete high-level init inspection before any write authorization is considered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitAdapterInspection {
    pub repository: RepoId,
    pub model_digest: Digest,
    pub assumptions: Vec<Assumption>,
    pub gaps: Vec<InitGap>,
    pub targets: Vec<InitAdapterTargetInspection>,
    pub whole_file_targets: Vec<InitWholeFileTargetInspection>,
    pub reused_adapters: Vec<ReusedAdapter>,
}

/// One explicitly requested whole-file target after conservative equivalence inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitWholeFileTargetInspection {
    pub path: RepoRelativePath,
    pub target: CiTarget,
    pub content: Vec<u8>,
    pub state: WholeFileInspectionState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WholeFileInspectionState {
    Missing,
    Equivalent,
}

/// A requested host that consumes an already planned canonical adapter path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReusedAdapter {
    pub target: AdapterTarget,
    pub path: RepoRelativePath,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterFileLimitStage {
    Existing,
    Resulting,
}

/// Typed init gaps from the accepted v0 classification stage.
///
/// Classification is separate from edit authorization: a gap can remain diagnostic only,
/// require an explicit option, or justify one of the small managed projections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum GapKind {
    MissingProjectCommand,
    MissingHostIndex,
    MissingHostPointer,
    AmbiguousCommand,
    AdapterDrift,
    OptionalRunner,
    OptionalCiDraft,
    ConfigurationRequired,
}

/// One classified gap with the narrowest stable subject Forge can name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct InitGap {
    pub kind: GapKind,
    pub path: Option<RepoRelativePath>,
    pub intent: Option<Intent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangePlan {
    pub schema: u16,
    pub repository: RepoId,
    pub model_digest: Digest,
    pub edits: Vec<FileEdit>,
    /// Classified repository gaps retained for diagnostics and review.
    ///
    /// These observations are not write authorization. Versioned wire projections choose which
    /// gaps, if any, belong in their existing top-level diagnostic channel.
    pub gaps: Vec<InitGap>,
    pub assumptions: Vec<Assumption>,
    pub skipped: Vec<SkippedChange>,
    pub rollback: RollbackPlan,
}

#[derive(Debug)]
pub enum PlanError {
    NoProjectFacts,
    DuplicateAdapterRequest(AdapterTarget),
    AdapterDependencyConflict {
        adapter: AdapterTarget,
        required: AdapterTarget,
    },
    DuplicateForceBlock(ManagedBlockKind),
    DuplicateTarget(RepoRelativePath),
    InvalidTarget(RelativePathError),
    InvalidModel(ProjectModelError),
    Read {
        path: RepoRelativePath,
        source: io::Error,
    },
    ManagedBlock {
        path: RepoRelativePath,
        source: ManagedBlockError,
    },
    GeneratedBlockLimit {
        lines: usize,
        bytes: usize,
    },
    AdapterFileLimit {
        path: RepoRelativePath,
        stage: AdapterFileLimitStage,
        observed_bytes: Option<usize>,
        max_bytes: usize,
    },
    AttributesFileLimit {
        path: RepoRelativePath,
        max_bytes: usize,
    },
    RunnerRender {
        path: RepoRelativePath,
        source: RunnerRenderError,
    },
    RunnerConflict {
        path: RepoRelativePath,
        detail: String,
    },
    CiRender {
        path: RepoRelativePath,
        source: CiRenderError,
    },
    CiConflict {
        path: RepoRelativePath,
        equivalence: CiEquivalence,
    },
    InspectionInvariant {
        path: RepoRelativePath,
        detail: String,
    },
}

impl fmt::Display for PlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoProjectFacts => formatter.write_str("no project facts found"),
            Self::DuplicateAdapterRequest(adapter) => {
                write!(
                    formatter,
                    "adapter {adapter:?} was requested more than once"
                )
            }
            Self::AdapterDependencyConflict { adapter, required } => write!(
                formatter,
                "adapter {adapter:?} was enabled while its required {required:?} projection was disabled"
            ),
            Self::DuplicateForceBlock(block) => {
                write!(
                    formatter,
                    "managed block {block:?} was forced more than once"
                )
            }
            Self::DuplicateTarget(path) => {
                write!(
                    formatter,
                    "planned target `{}` occurs more than once",
                    path.as_path().display()
                )
            }
            Self::InvalidTarget(source) => write!(formatter, "invalid planned target: {source}"),
            Self::InvalidModel(source) => write!(formatter, "invalid project model: {source}"),
            Self::Read { path, source } => {
                write!(
                    formatter,
                    "cannot read planned target `{}`: {source}",
                    path.as_path().display()
                )
            }
            Self::ManagedBlock { path, source } => write!(
                formatter,
                "cannot plan managed block for `{}`: {source}",
                path.as_path().display()
            ),
            Self::GeneratedBlockLimit { lines, bytes } => write!(
                formatter,
                "generated AGENTS block exceeds its limit ({lines} lines, {bytes} bytes)"
            ),
            Self::AdapterFileLimit {
                path,
                stage,
                observed_bytes,
                max_bytes,
            } => {
                let observed = observed_bytes.map_or_else(
                    || String::from("an unknown oversized length"),
                    |bytes| format!("{bytes} bytes"),
                );
                write!(
                    formatter,
                    "{:?} adapter file `{}` is {observed}, above the {max_bytes}-byte limit",
                    stage,
                    path.as_path().display()
                )
            }
            Self::AttributesFileLimit { path, max_bytes } => write!(
                formatter,
                "root attributes file `{}` exceeds the {max_bytes}-byte read limit",
                path.as_path().display()
            ),
            Self::RunnerRender { path, source } => write!(
                formatter,
                "cannot render explicit runner `{}`: {source}",
                path.as_path().display()
            ),
            Self::RunnerConflict { path, detail } => write!(
                formatter,
                "cannot add explicit runner `{}` safely: {detail}",
                path.as_path().display()
            ),
            Self::CiRender { path, source } => write!(
                formatter,
                "cannot render explicit CI workflow `{}`: {source}",
                path.as_path().display()
            ),
            Self::CiConflict { path, equivalence } => write!(
                formatter,
                "existing CI workflow `{}` is {equivalence}; create-only generation will not overwrite it",
                path.as_path().display()
            ),
            Self::InspectionInvariant { path, detail } => write!(
                formatter,
                "adapter inspection invariant failed for `{}`: {detail}",
                path.as_path().display()
            ),
        }
    }
}

impl Error for PlanError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidTarget(source) => Some(source),
            Self::InvalidModel(source) => Some(source),
            Self::Read { source, .. } => Some(source),
            Self::ManagedBlock { source, .. } => Some(source),
            Self::RunnerRender { source, .. } => Some(source),
            Self::CiRender { source, .. } => Some(source),
            _ => None,
        }
    }
}

pub fn plan_init<F, H>(
    model: &ProjectModel,
    filesystem: &F,
    hasher: &H,
    options: &InitPlanOptions,
) -> Result<ChangePlan, PlanError>
where
    F: RepositoryFilePort + ?Sized,
    H: Hasher + ?Sized,
{
    let forced = unique_forced_blocks(options)?;
    let inspection = inspect_init_targets(model, filesystem, hasher, options)?;
    let target_gaps = inspection
        .gaps
        .iter()
        .filter_map(|gap| gap.path.as_ref().map(|path| (path.clone(), gap.kind)))
        .collect::<BTreeMap<_, _>>();
    let mut edits = Vec::new();
    let mut skipped = Vec::new();
    for adapter in &inspection.reused_adapters {
        skipped.push(SkippedChange {
            path: adapter.path.clone(),
            reason: SkippedReason::ReusesAgents(adapter.target),
            satisfied_managed: None,
        });
    }
    for target in inspection.targets {
        match target.state {
            AdapterInspectionState::Satisfied {
                full_postimage_digest,
            } => {
                // The private generated manifest tracks host projections only. An opt-in runner is
                // a project-native asset and intentionally stays outside adapter drift state.
                if managed_adapter_spec(&target.path, target.desired.kind).is_some() {
                    skipped.push(SkippedChange {
                        path: target.path,
                        reason: SkippedReason::AlreadySatisfied,
                        satisfied_managed: Some(SatisfiedManagedBlock {
                            kind: target.desired.kind,
                            full_postimage_digest,
                        }),
                    });
                }
            }
            AdapterInspectionState::EquivalentUnmanaged { .. } => {
                skipped.push(SkippedChange {
                    path: target.path,
                    reason: SkippedReason::EquivalentUnmanaged,
                    satisfied_managed: None,
                });
            }
            AdapterInspectionState::Edit(observed_edit) => {
                if !matches!(
                    target_gaps.get(&target.path),
                    Some(
                        GapKind::MissingHostIndex
                            | GapKind::MissingHostPointer
                            | GapKind::AdapterDrift
                            | GapKind::OptionalRunner
                    )
                ) {
                    return Err(PlanError::InspectionInvariant {
                        path: target.path,
                        detail: String::from(
                            "an editable target has no matching classified init gap",
                        ),
                    });
                }
                let force = forced.contains(&target.desired.kind);
                if observed_edit.reason == FileEditReason::UserEdited && !force {
                    return Err(PlanError::ManagedBlock {
                        path: target.path,
                        source: ManagedBlockError::UserEdited {
                            id: target.desired.kind.id().to_owned(),
                        },
                    });
                }
                edits.push(FileEdit {
                    kind: edit_kind(observed_edit.reason),
                    reason: observed_edit.reason,
                    fallback_line_ending: observed_edit.fallback_line_ending,
                    path: target.path,
                    desired: DesiredFile::ManagedBlock(target.desired),
                    expected_preimage: observed_edit.expected_preimage,
                    expected_postimage: observed_edit.full_postimage_digest,
                    preview_postimage: observed_edit.preview_postimage,
                    force,
                });
            }
        }
    }
    for target in inspection.whole_file_targets {
        match target.state {
            WholeFileInspectionState::Missing => {
                if target_gaps.get(&target.path) != Some(&GapKind::OptionalCiDraft) {
                    return Err(PlanError::InspectionInvariant {
                        path: target.path,
                        detail: String::from(
                            "an editable whole-file target has no matching classified init gap",
                        ),
                    });
                }
                let expected_postimage = repository_file_digest(hasher, &target.content);
                edits.push(FileEdit {
                    kind: FileEditKind::Create,
                    reason: FileEditReason::MissingFile,
                    fallback_line_ending: LineEnding::Lf,
                    path: target.path,
                    desired: DesiredFile::WholeFile(target.target),
                    expected_preimage: None,
                    preview_postimage: target.content,
                    expected_postimage,
                    force: false,
                });
            }
            WholeFileInspectionState::Equivalent => skipped.push(SkippedChange {
                path: target.path,
                reason: SkippedReason::EquivalentUnmanaged,
                satisfied_managed: None,
            }),
        }
    }
    edits.sort_by(|left, right| left.path.cmp(&right.path));
    skipped.sort();
    let rollback = rollback_plan(&edits);
    Ok(ChangePlan {
        schema: PLAN_SCHEMA,
        repository: inspection.repository,
        model_digest: inspection.model_digest,
        edits,
        gaps: inspection.gaps,
        assumptions: inspection.assumptions,
        skipped,
        rollback,
    })
}

/// Renders and inspects every selected init target without considering force authorization.
pub fn inspect_init_targets<F, H>(
    model: &ProjectModel,
    filesystem: &F,
    hasher: &H,
    options: &InitPlanOptions,
) -> Result<InitAdapterInspection, PlanError>
where
    F: RepositoryFilePort + ?Sized,
    H: Hasher + ?Sized,
{
    let model = model.clone().finalize().map_err(PlanError::InvalidModel)?;
    if model.units.is_empty() && !has_resolved_command(&model) {
        return Err(PlanError::NoProjectFacts);
    }
    let requested = unique_options(options)?;
    let adopted = unique_adopted_options(options)?;
    let expanded_requests = expand_explicit_requests(&requested);
    let _ = unique_forced_blocks(options)?;
    let runner = plan_runner_target(&model, filesystem, options.runner)?;
    let runner_model = runner.projected_model.as_ref().unwrap_or(&model);
    let whole_file_targets = inspect_ci_target(runner_model, filesystem, options.ci)?;
    let ci_model = options
        .ci
        .map(|target| project_ci_model(runner_model, target))
        .transpose()?;
    let render_model = ci_model.as_ref().unwrap_or(runner_model);
    let mut desired_targets = Vec::new();
    let mut reused_adapters = Vec::new();
    let mut selected = adapter_specs()
        .iter()
        .filter(|spec| {
            spec.selected(
                render_model,
                expanded_requests.contains(&spec.target),
                adopted.contains(&spec.target),
                options.adapter_selection.for_target(spec.target),
            )
        })
        .map(|spec| spec.target)
        .collect::<BTreeSet<_>>();
    suppress_adapters_with_disabled_dependencies(
        &mut selected,
        &requested,
        options.adapter_selection,
    )?;
    for spec in adapter_specs() {
        let explicitly_requested = requested.contains(&spec.target);
        if spec.reports_reuse(explicitly_requested) {
            reused_adapters.push(ReusedAdapter {
                target: spec.target,
                path: target_path(spec.path)?,
            });
        }
        if !selected.contains(&spec.target) {
            continue;
        }
        let Some(body) = spec.render_body(render_model).map_err(map_render_error)? else {
            continue;
        };
        desired_targets.push((
            target_path(spec.path)?,
            DesiredManagedBlock {
                kind: spec.block,
                body,
            },
        ));
    }
    if let Some(target) = runner.desired {
        desired_targets.push(target);
    }
    desired_targets.sort_by(|left, right| left.0.cmp(&right.0));
    reject_duplicate_targets(&desired_targets)?;
    let root_attributes = if desired_targets.is_empty() {
        None
    } else {
        read_root_attributes(&model.repository.root, filesystem)?
    };
    for (path, desired) in &desired_targets {
        let block = ManagedBlock {
            id: desired.kind.id(),
            body: &desired.body,
        };
        let fallback_line_ending = root_attributes
            .as_deref()
            .and_then(|attributes| root_attribute_line_ending(attributes, path))
            .unwrap_or(LineEnding::Lf);
        if desired.kind == ManagedBlockKind::ProjectIndex {
            enforce_complete_agents_limit(path, &block, fallback_line_ending, hasher)?;
        }
    }
    let requests = desired_targets
        .iter()
        .map(|(path, desired)| AdapterInspectionRequest {
            path,
            block_id: desired.kind.id(),
            desired_body: &desired.body,
            syntax: desired.kind.syntax(),
            fallback_line_ending: root_attributes
                .as_deref()
                .and_then(|attributes| root_attribute_line_ending(attributes, path))
                .unwrap_or(LineEnding::Lf),
            equivalent_unmanaged: managed_adapter_spec(path, desired.kind)
                .and_then(|spec| spec.equivalent_unmanaged),
        })
        .collect::<Vec<_>>();
    let model_digest = adapter_projection_digest(hasher, &model.repository.id, &desired_targets);
    let report = inspect_adapter_targets(&model.repository.root, &requests, filesystem, hasher)
        .map_err(map_inspection_error)?;
    let mut targets = Vec::with_capacity(desired_targets.len());
    for ((path, desired), observed) in desired_targets.into_iter().zip(report.targets) {
        if observed.path != path || observed.block_id != desired.kind.id() {
            return Err(PlanError::InspectionInvariant {
                path,
                detail: String::from("inspection result identity differs from its request"),
            });
        }
        targets.push(InitAdapterTargetInspection {
            path: observed.path,
            desired,
            state: observed.state,
        });
    }
    let mut gaps = classify_init_gaps(render_model, &targets);
    for target in &whole_file_targets {
        if target.state == WholeFileInspectionState::Missing {
            gaps.push(InitGap {
                kind: GapKind::OptionalCiDraft,
                path: Some(target.path.clone()),
                intent: None,
            });
        }
    }
    gaps.sort();
    gaps.dedup();
    let mut assumptions = model.assumptions;
    if let Some(assumption) = runner.assumption {
        assumptions.push(assumption);
    }
    if let Some(target) = options.ci {
        assumptions.push(ci_assumption(target)?);
    }
    for gap in gaps
        .iter()
        .filter(|gap| gap.kind == GapKind::ConfigurationRequired)
    {
        let Some(intent) = gap.intent else {
            continue;
        };
        let Some(commands) = model.commands.get(&intent) else {
            continue;
        };
        assumptions.push(Assumption::new(
            format!(
                "The `{}` command remains unknown and requires an explicit repository decision in {CONFIG_FILE} before use.",
                intent_name(intent),
            ),
            commands.provenance.clone(),
            Confidence::Unknown,
        ));
    }
    assumptions.sort_by(|left, right| {
        left.statement
            .cmp(&right.statement)
            .then_with(|| left.confidence.cmp(&right.confidence))
            .then_with(|| left.provenance.cmp(&right.provenance))
    });
    assumptions.dedup();
    Ok(InitAdapterInspection {
        repository: model.repository.id,
        model_digest,
        assumptions,
        gaps,
        targets,
        whole_file_targets,
        reused_adapters,
    })
}

fn inspect_ci_target<F>(
    model: &ProjectModel,
    filesystem: &F,
    target: Option<CiTarget>,
) -> Result<Vec<InitWholeFileTargetInspection>, PlanError>
where
    F: RepositoryFilePort + ?Sized,
{
    let Some(target) = target else {
        return Ok(Vec::new());
    };
    let path = target_path(target.path())?;
    let content = match target {
        CiTarget::Github => render_github_workflow(model),
    }
    .map_err(|source| PlanError::CiRender {
        path: path.clone(),
        source,
    })?;
    let existing = filesystem
        .read_confined_bounded(
            &model.repository.root,
            &path,
            crate::inspection::ADAPTER_FILE_MAX_BYTES,
        )
        .map_err(|source| {
            if source.kind() == io::ErrorKind::InvalidData {
                PlanError::CiConflict {
                    path: path.clone(),
                    equivalence: CiEquivalence::Unknown,
                }
            } else {
                PlanError::Read {
                    path: path.clone(),
                    source,
                }
            }
        })?;
    let state = match existing {
        None => WholeFileInspectionState::Missing,
        Some(existing) => match classify_github_workflow(&existing, &content) {
            CiEquivalence::Equivalent => WholeFileInspectionState::Equivalent,
            equivalence @ (CiEquivalence::NotEquivalent | CiEquivalence::Unknown) => {
                return Err(PlanError::CiConflict { path, equivalence });
            }
        },
    };
    Ok(vec![InitWholeFileTargetInspection {
        path,
        target,
        content,
        state,
    }])
}

fn ci_assumption(target: CiTarget) -> Result<Assumption, PlanError> {
    let path = target_path(target.path())?;
    Ok(Assumption::new(
        format!(
            "`{}` is an explicit opt-in, create-only GitHub Actions workflow; delete the complete file to remove it, and {DISPLAY_NAME} will never replace an existing non-equivalent or unknown workflow.",
            target.path(),
        ),
        vec![ci_provenance(
            &path,
            "the CI provider came from the explicit --with-ci github request",
        )],
        Confidence::High,
    ))
}

fn project_ci_model(model: &ProjectModel, target: CiTarget) -> Result<ProjectModel, PlanError> {
    let path = target_path(target.path())?;
    let mut projected = model.clone();
    if !projected
        .assets
        .entries
        .iter()
        .any(|asset| asset.kind == "ci.github-actions" && asset.path == path)
    {
        projected.assets.entries.push(AssetInfo::new(
            "ci.github-actions",
            path.clone(),
            vec![ci_provenance(
                &path,
                "the explicitly selected workflow will exist after the reviewed init plan",
            )],
            Confidence::Medium,
        ));
    }
    projected.finalize().map_err(PlanError::InvalidModel)
}

fn ci_provenance(path: &RepoRelativePath, detail: &str) -> Provenance {
    Provenance {
        rule_id: String::from("init.ci.github.explicit-opt-in.v1"),
        source_path: Some(path.as_path().into()),
        source_range: None,
        detail: detail.to_owned(),
    }
}

/// Purely classifies model and target observations; it never chooses or writes a file.
fn classify_init_gaps(
    model: &ProjectModel,
    targets: &[InitAdapterTargetInspection],
) -> Vec<InitGap> {
    let mut gaps = Vec::new();
    for intent in Intent::ALL {
        let Some(commands) = model.commands.get(&intent) else {
            gaps.push(InitGap {
                kind: GapKind::ConfigurationRequired,
                path: None,
                intent: Some(intent),
            });
            continue;
        };
        let kind = match commands.resolution() {
            CommandResolution::Resolved => None,
            CommandResolution::Absent => Some(GapKind::MissingProjectCommand),
            CommandResolution::Ambiguous => Some(GapKind::AmbiguousCommand),
            CommandResolution::Unknown => Some(GapKind::ConfigurationRequired),
        };
        if let Some(kind) = kind {
            gaps.push(InitGap {
                kind,
                path: None,
                intent: Some(intent),
            });
        }
    }

    for target in targets {
        let AdapterInspectionState::Edit(edit) = &target.state else {
            continue;
        };
        let kind = match target.desired.kind {
            ManagedBlockKind::ProjectIndex if edit.reason == FileEditReason::MissingFile => {
                GapKind::MissingHostIndex
            }
            ManagedBlockKind::ClaudePointer if edit.reason == FileEditReason::MissingFile => {
                GapKind::MissingHostPointer
            }
            ManagedBlockKind::RunnerMakeVerify
            | ManagedBlockKind::RunnerJustVerify
            | ManagedBlockKind::RunnerTaskVerify => GapKind::OptionalRunner,
            ManagedBlockKind::ProjectIndex | ManagedBlockKind::ClaudePointer => {
                GapKind::AdapterDrift
            }
        };
        gaps.push(InitGap {
            kind,
            path: Some(target.path.clone()),
            intent: None,
        });
    }
    gaps.sort();
    gaps.dedup();
    gaps
}

struct RunnerPlanning {
    desired: Option<(RepoRelativePath, DesiredManagedBlock)>,
    projected_model: Option<ProjectModel>,
    assumption: Option<Assumption>,
}

fn plan_runner_target<F>(
    model: &ProjectModel,
    filesystem: &F,
    runner: Option<RunnerTarget>,
) -> Result<RunnerPlanning, PlanError>
where
    F: RepositoryFilePort + ?Sized,
{
    let Some(runner) = runner else {
        return Ok(RunnerPlanning {
            desired: None,
            projected_model: None,
            assumption: None,
        });
    };
    let path = target_path(runner.path())?;
    let existing = filesystem
        .read_confined_bounded(
            &model.repository.root,
            &path,
            crate::inspection::ADAPTER_FILE_MAX_BYTES,
        )
        .map_err(|source| {
            if source.kind() == io::ErrorKind::InvalidData {
                PlanError::AdapterFileLimit {
                    path: path.clone(),
                    stage: AdapterFileLimitStage::Existing,
                    observed_bytes: None,
                    max_bytes: crate::inspection::ADAPTER_FILE_MAX_BYTES,
                }
            } else {
                PlanError::Read {
                    path: path.clone(),
                    source,
                }
            }
        })?;
    let kind = runner_block_kind(runner);
    if existing.as_deref().is_some_and(|bytes| {
        !contains_managed_block_begin(bytes, ManagedBlockSyntax::HashComment, kind.id())
    }) {
        return Ok(RunnerPlanning {
            desired: None,
            projected_model: None,
            assumption: Some(runner_assumption(
                &path,
                format!(
                    "Existing `{}` remains authoritative and was not modified because it has no Forge-owned `{}` block.",
                    runner.path(),
                    kind.id()
                ),
            )),
        });
    }
    if existing.is_none() {
        ensure_verify_target_can_be_added(model, &path)?;
    } else {
        ensure_owned_runner_can_be_projected(model, &path)?;
    }
    let body = render_runner_body(model, runner).map_err(|source| PlanError::RunnerRender {
        path: path.clone(),
        source,
    })?;
    let projected_model =
        project_runner_model(model, runner).map_err(|source| PlanError::RunnerRender {
            path: path.clone(),
            source,
        })?;
    Ok(RunnerPlanning {
        desired: Some((path.clone(), DesiredManagedBlock { kind, body })),
        projected_model: Some(projected_model),
        assumption: Some(runner_assumption(
            &path,
            format!(
                "`{}` is an explicit opt-in project runner; deleting only its Forge-managed `{}` block removes the generated `verify` entry.",
                runner.path(),
                kind.id()
            ),
        )),
    })
}

fn ensure_owned_runner_can_be_projected(
    model: &ProjectModel,
    path: &RepoRelativePath,
) -> Result<(), PlanError> {
    let Some(verify) = model.commands.get(&Intent::Verify) else {
        return Err(PlanError::RunnerConflict {
            path: path.clone(),
            detail: String::from("the verify intent is missing from the finalized project model"),
        });
    };
    match verify.resolution() {
        CommandResolution::Absent => Ok(()),
        CommandResolution::Resolved
            if verify.executable_commands().is_some_and(|commands| {
                matches!(
                    commands,
                    [command]
                        if matches!(
                            &command.source,
                            CommandSource::ExistingProjectTarget {
                                path: source_path,
                                target,
                            } if source_path == path && target == "verify"
                        )
                )
            }) =>
        {
            Ok(())
        }
        CommandResolution::Resolved => Err(PlanError::RunnerConflict {
            path: path.clone(),
            detail: String::from(
                "the existing verify intent resolves through a different project interface",
            ),
        }),
        CommandResolution::Ambiguous | CommandResolution::Unknown => {
            Err(PlanError::RunnerConflict {
                path: path.clone(),
                detail: String::from(
                    "the existing verify intent is ambiguous or incomplete, so the selected managed runner cannot be published as authoritative",
                ),
            })
        }
    }
}

fn ensure_verify_target_can_be_added(
    model: &ProjectModel,
    path: &RepoRelativePath,
) -> Result<(), PlanError> {
    let Some(verify) = model.commands.get(&Intent::Verify) else {
        return Err(PlanError::RunnerConflict {
            path: path.clone(),
            detail: String::from("the verify intent is missing from the finalized project model"),
        });
    };
    match verify.resolution() {
        CommandResolution::Absent => Ok(()),
        CommandResolution::Resolved => {
            let source = verify
                .executable_commands()
                .and_then(|commands| commands.first())
                .map_or("another project command", |command| match &command.source {
                    CommandSource::ExistingProjectTarget { path, target } => {
                        if target == "verify" {
                            return path.as_path().to_str().unwrap_or("another runner");
                        }
                        "another project target"
                    }
                    CommandSource::ExplicitConfig => "explicit Forge configuration",
                    CommandSource::LanguageDefault { .. } => "a language provider",
                });
            Err(PlanError::RunnerConflict {
                path: path.clone(),
                detail: format!(
                    "the repository already resolves `verify` through {source}; adding a second runner target would create competing project interfaces"
                ),
            })
        }
        CommandResolution::Ambiguous | CommandResolution::Unknown => {
            Err(PlanError::RunnerConflict {
                path: path.clone(),
                detail: String::from(
                    "the existing runner surface is ambiguous or incomplete, so absence of a conflicting `verify` target is not proven",
                ),
            })
        }
    }
}

const fn runner_block_kind(runner: RunnerTarget) -> ManagedBlockKind {
    match runner {
        RunnerTarget::Make => ManagedBlockKind::RunnerMakeVerify,
        RunnerTarget::Just => ManagedBlockKind::RunnerJustVerify,
        RunnerTarget::Task => ManagedBlockKind::RunnerTaskVerify,
    }
}

fn runner_assumption(path: &RepoRelativePath, statement: String) -> Assumption {
    Assumption::new(
        statement,
        vec![Provenance {
            rule_id: String::from("init.runner.explicit-opt-in.v1"),
            source_path: Some(path.as_path().into()),
            source_range: None,
            detail: String::from("the runner choice came from the explicit --with-runner request"),
        }],
        Confidence::High,
    )
}

fn has_resolved_command(model: &ProjectModel) -> bool {
    model.commands.values().any(|commands| {
        commands.resolution() == CommandResolution::Resolved
            && commands
                .executable_commands()
                .is_some_and(|value| !value.is_empty())
    })
}

const fn intent_name(intent: Intent) -> &'static str {
    match intent {
        Intent::Setup => "setup",
        Intent::FormatCheck => "format-check",
        Intent::Format => "format",
        Intent::Check => "check",
        Intent::Fix => "fix",
        Intent::Test => "test",
        Intent::Verify => "verify",
        Intent::Build => "build",
    }
}

fn unique_options(options: &InitPlanOptions) -> Result<BTreeSet<AdapterTarget>, PlanError> {
    let mut unique = BTreeSet::new();
    for adapter in &options.adapters {
        if !unique.insert(*adapter) {
            return Err(PlanError::DuplicateAdapterRequest(*adapter));
        }
    }
    Ok(unique)
}

fn unique_adopted_options(options: &InitPlanOptions) -> Result<BTreeSet<AdapterTarget>, PlanError> {
    let mut unique = BTreeSet::new();
    for adapter in &options.adopted_adapters {
        if !unique.insert(*adapter) || options.adapters.contains(adapter) {
            return Err(PlanError::DuplicateAdapterRequest(*adapter));
        }
    }
    Ok(unique)
}

fn expand_explicit_requests(requested: &BTreeSet<AdapterTarget>) -> BTreeSet<AdapterTarget> {
    let mut expanded = requested.clone();
    loop {
        let previous_len = expanded.len();
        for spec in adapter_specs() {
            if !expanded.contains(&spec.target) {
                continue;
            }
            if let AdapterSelection::ExplicitReuse { source } = spec.selection {
                expanded.insert(source);
            }
            if let Some(required) = spec.requires {
                expanded.insert(required);
            }
        }
        if expanded.len() == previous_len {
            return expanded;
        }
    }
}

fn suppress_adapters_with_disabled_dependencies(
    selected: &mut BTreeSet<AdapterTarget>,
    explicitly_requested: &BTreeSet<AdapterTarget>,
    overrides: AdapterSelectionOverrides,
) -> Result<(), PlanError> {
    loop {
        let mut removed = false;
        for spec in adapter_specs() {
            let Some(required) = spec.requires else {
                continue;
            };
            if !selected.contains(&spec.target) || selected.contains(&required) {
                continue;
            }
            if explicitly_requested.contains(&spec.target) {
                return Err(PlanError::AdapterDependencyConflict {
                    adapter: spec.target,
                    required,
                });
            }
            if overrides.for_target(spec.target) == Some(true) {
                return Err(PlanError::AdapterDependencyConflict {
                    adapter: spec.target,
                    required,
                });
            }
            selected.remove(&spec.target);
            removed = true;
        }
        if !removed {
            return Ok(());
        }
    }
}

fn unique_forced_blocks(
    options: &InitPlanOptions,
) -> Result<BTreeSet<ManagedBlockKind>, PlanError> {
    let mut unique = BTreeSet::new();
    for block in &options.force_blocks {
        if !unique.insert(*block) {
            return Err(PlanError::DuplicateForceBlock(*block));
        }
    }
    Ok(unique)
}

fn reject_duplicate_targets(
    targets: &[(RepoRelativePath, DesiredManagedBlock)],
) -> Result<(), PlanError> {
    for pair in targets.windows(2) {
        if pair[0].0 == pair[1].0 {
            return Err(PlanError::DuplicateTarget(pair[0].0.clone()));
        }
    }
    Ok(())
}

fn rollback_plan(edits: &[FileEdit]) -> RollbackPlan {
    let mut plan = RollbackPlan::default();
    for edit in edits {
        if edit.expected_preimage.is_some() {
            plan.restore_modified.push(edit.path.clone());
        } else {
            plan.remove_created.push(edit.path.clone());
        }
    }
    plan
}

fn target_path(value: &str) -> Result<RepoRelativePath, PlanError> {
    RepoRelativePath::new(value).map_err(PlanError::InvalidTarget)
}

fn read_root_attributes<F>(
    repository_root: &std::path::Path,
    filesystem: &F,
) -> Result<Option<Vec<u8>>, PlanError>
where
    F: RepositoryFilePort + ?Sized,
{
    let path = target_path(".gitattributes")?;
    filesystem
        .read_confined_bounded(repository_root, &path, GITATTRIBUTES_MAX_BYTES)
        .map_err(|source| {
            if source.kind() == io::ErrorKind::InvalidData {
                PlanError::AttributesFileLimit {
                    path,
                    max_bytes: GITATTRIBUTES_MAX_BYTES,
                }
            } else {
                PlanError::Read { path, source }
            }
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EolResolution {
    Unspecified,
    Known(LineEnding),
    Ambiguous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PatternMatch {
    Yes,
    No,
    Indeterminate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EolDirective {
    None,
    Known(LineEnding),
    Other,
    Ambiguous,
}

/// Resolves only the root-attributes subset whose Git meaning is unambiguous here.
///
/// Exact paths and basename patterns containing only `*` are sufficient for the usual
/// `AGENTS.md eol=...` and `*.md eol=...` policies. Quoting, escaping, bracket expressions,
/// `?`, `**`, macros, and malformed or conflicting directives deliberately fall back to the
/// default instead of approximating Git's complete attribute language.
fn root_attribute_line_ending(attributes: &[u8], path: &RepoRelativePath) -> Option<LineEnding> {
    let text = std::str::from_utf8(attributes).ok()?;
    let target = git_attribute_path(path)?;
    let mut resolution = EolResolution::Unspecified;
    for raw_line in text.lines() {
        let line = raw_line.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        let Some(pattern) = fields.first().copied() else {
            continue;
        };
        let directive = direct_eol_directive(&fields[1..]);
        if directive == EolDirective::None {
            continue;
        }
        match root_pattern_matches(pattern, &target) {
            PatternMatch::No => {}
            PatternMatch::Indeterminate => resolution = EolResolution::Ambiguous,
            PatternMatch::Yes => {
                resolution = match directive {
                    EolDirective::Known(line_ending) if resolution != EolResolution::Ambiguous => {
                        EolResolution::Known(line_ending)
                    }
                    EolDirective::Known(_) => EolResolution::Ambiguous,
                    EolDirective::Other | EolDirective::Ambiguous => EolResolution::Ambiguous,
                    EolDirective::None => resolution,
                };
            }
        }
    }
    match resolution {
        EolResolution::Known(line_ending) => Some(line_ending),
        EolResolution::Unspecified | EolResolution::Ambiguous => None,
    }
}

fn direct_eol_directive(attributes: &[&str]) -> EolDirective {
    let mut directive = EolDirective::None;
    let mut has_unresolved_attribute = false;
    for attribute in attributes {
        let current = match *attribute {
            "eol=lf" => Some(EolDirective::Known(LineEnding::Lf)),
            "eol=crlf" => Some(EolDirective::Known(LineEnding::CrLf)),
            "eol" | "-eol" | "!eol" => Some(EolDirective::Other),
            value if value.starts_with("eol=") => Some(EolDirective::Other),
            "text" | "text=auto" => None,
            _ => {
                has_unresolved_attribute = true;
                None
            }
        };
        let Some(current) = current else {
            continue;
        };
        if directive != EolDirective::None {
            return EolDirective::Ambiguous;
        }
        directive = current;
    }
    if has_unresolved_attribute {
        EolDirective::Ambiguous
    } else {
        directive
    }
}

fn git_attribute_path(path: &RepoRelativePath) -> Option<String> {
    let mut result = String::new();
    for component in path.as_path().components() {
        let std::path::Component::Normal(component) = component else {
            return None;
        };
        if !result.is_empty() {
            result.push('/');
        }
        result.push_str(component.to_str()?);
    }
    Some(result)
}

fn root_pattern_matches(pattern: &str, target: &str) -> PatternMatch {
    if pattern.is_empty()
        || pattern.starts_with(['!', '/'])
        || pattern.ends_with('/')
        || pattern.contains(['\\', '"', '[', ']', '?'])
        || pattern.contains("**")
    {
        return PatternMatch::Indeterminate;
    }
    if pattern.contains('/') {
        return if pattern.contains('*') {
            PatternMatch::Indeterminate
        } else if pattern == target {
            PatternMatch::Yes
        } else {
            PatternMatch::No
        };
    }
    let basename = target.rsplit('/').next().unwrap_or(target);
    if star_pattern_matches(pattern.as_bytes(), basename.as_bytes()) {
        PatternMatch::Yes
    } else {
        PatternMatch::No
    }
}

fn star_pattern_matches(pattern: &[u8], value: &[u8]) -> bool {
    let (mut pattern_index, mut value_index) = (0, 0);
    let (mut star_index, mut star_value_index) = (None, 0);
    while value_index < value.len() {
        if pattern.get(pattern_index) == value.get(value_index) {
            pattern_index += 1;
            value_index += 1;
        } else if pattern.get(pattern_index) == Some(&b'*') {
            star_index = Some(pattern_index);
            pattern_index += 1;
            star_value_index = value_index;
        } else if let Some(star) = star_index {
            pattern_index = star + 1;
            star_value_index += 1;
            value_index = star_value_index;
        } else {
            return false;
        }
    }
    while pattern.get(pattern_index) == Some(&b'*') {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}

const fn edit_kind(reason: FileEditReason) -> FileEditKind {
    match reason {
        FileEditReason::MissingFile => FileEditKind::Create,
        FileEditReason::MissingManagedBlock
        | FileEditReason::AssetChanged
        | FileEditReason::UserEdited => FileEditKind::ReplaceManagedBlock,
    }
}

fn map_inspection_error(error: AdapterInspectionError) -> PlanError {
    match error {
        AdapterInspectionError::DuplicateTarget(path) => PlanError::DuplicateTarget(path),
        AdapterInspectionError::Read { path, source } => PlanError::Read { path, source },
        AdapterInspectionError::ManagedBlock { path, source } => {
            PlanError::ManagedBlock { path, source }
        }
        AdapterInspectionError::ExistingFileTooLarge { path, max_bytes } => {
            PlanError::AdapterFileLimit {
                path,
                stage: AdapterFileLimitStage::Existing,
                observed_bytes: None,
                max_bytes,
            }
        }
        AdapterInspectionError::ResultingFileTooLarge {
            path,
            bytes,
            max_bytes,
        } => PlanError::AdapterFileLimit {
            path,
            stage: AdapterFileLimitStage::Resulting,
            observed_bytes: Some(bytes),
            max_bytes,
        },
        AdapterInspectionError::InconsistentMergeAction {
            path,
            action,
            existing,
        } => PlanError::InspectionInvariant {
            path,
            detail: format!("merge returned {action:?} with existing={existing}"),
        },
    }
}

fn adapter_projection_digest<H>(
    hasher: &H,
    repository: &RepoId,
    targets: &[(RepoRelativePath, DesiredManagedBlock)],
) -> Digest
where
    H: Hasher + ?Sized,
{
    let mut projection = repository.as_str().as_bytes().to_vec();
    for (path, desired) in targets
        .iter()
        .filter(|(path, desired)| managed_adapter_spec(path, desired.kind).is_some())
    {
        projection.push(0);
        projection.extend_from_slice(path.as_path().to_string_lossy().as_bytes());
        projection.push(0);
        projection.extend_from_slice(desired.kind.id().as_bytes());
        projection.push(0);
        projection.extend_from_slice(desired.body.as_bytes());
    }
    hasher.digest(&[MODEL_PROJECTION_DOMAIN, &projection])
}

fn map_render_error(error: AdapterRenderError) -> PlanError {
    match error {
        AdapterRenderError::LimitExceeded { lines, bytes } => {
            PlanError::GeneratedBlockLimit { lines, bytes }
        }
    }
}

fn enforce_complete_agents_limit<H>(
    path: &RepoRelativePath,
    block: &ManagedBlock<'_>,
    line_ending: LineEnding,
    hasher: &H,
) -> Result<(), PlanError>
where
    H: Hasher + ?Sized,
{
    let rendered = block
        .render_with_line_ending(ManagedBlockSyntax::Markdown, line_ending, hasher)
        .map_err(|source| PlanError::ManagedBlock {
            path: path.clone(),
            source,
        })?;
    let lines = rendered.iter().filter(|byte| **byte == b'\n').count();
    let bytes = rendered.len();
    if lines > AGENTS_MAX_LINES || bytes > AGENTS_MAX_BYTES {
        Err(PlanError::GeneratedBlockLimit { lines, bytes })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;
    use std::error::Error;
    use std::ffi::OsString;
    use std::io;
    use std::path::{Path, PathBuf};

    use forge_core::domain::{
        AdapterInfo, AdapterInventory, AssetInfo, AssetInventory, Assumption, CommandSource,
        CommandSpec, Confidence, EffectivePolicy, Intent, ProjectModel, ProjectModelInputs,
        Provenance, RepoFacts, ResolvedCommandSet, WorkState,
    };
    use forge_core::ports::{Hasher, RepositoryFilePort};
    use forge_core::{Digest, RelativePathError, RepoId, RepoRelativePath};

    use crate::adapter_registry::{AdapterSelection, adapter_specs};
    use crate::ci::{CiEquivalence, CiTarget, GITHUB_WORKFLOW_PATH};
    use crate::inspection::{ADAPTER_FILE_MAX_BYTES, AdapterInspectionKind, FileEditReason};
    use crate::managed_block::{LineEnding, ManagedBlock, ManagedBlockError};
    use crate::runners::{RunnerTarget, project_runner_model};

    use super::{
        AdapterFileLimitStage, AdapterSelectionOverrides, AdapterTarget, DesiredFile, FileEditKind,
        GITATTRIBUTES_MAX_BYTES, GapKind, InitPlanOptions, ManagedBlockKind, PlanError,
        SkippedReason, inspect_init_targets, plan_init,
    };

    #[derive(Debug, Default)]
    struct MemoryFiles {
        files: RefCell<BTreeMap<PathBuf, Vec<u8>>>,
        writes: Cell<usize>,
    }

    impl MemoryFiles {
        fn with(path: &str, content: impl Into<Vec<u8>>) -> Self {
            Self {
                files: RefCell::new(BTreeMap::from([(PathBuf::from(path), content.into())])),
                writes: Cell::new(0),
            }
        }

        fn from_files(files: impl IntoIterator<Item = (&'static str, Vec<u8>)>) -> Self {
            Self {
                files: RefCell::new(
                    files
                        .into_iter()
                        .map(|(path, content)| (PathBuf::from(path), content))
                        .collect(),
                ),
                writes: Cell::new(0),
            }
        }
    }

    impl RepositoryFilePort for MemoryFiles {
        fn read_confined(
            &self,
            _repository_root: &Path,
            _path: &RepoRelativePath,
        ) -> io::Result<Option<Vec<u8>>> {
            Err(io::Error::other("planner fixture forbids unbounded reads"))
        }

        fn read_confined_bounded(
            &self,
            _repository_root: &Path,
            path: &RepoRelativePath,
            max_bytes: usize,
        ) -> io::Result<Option<Vec<u8>>> {
            let files = self.files.borrow();
            match files.get(path.as_path()) {
                Some(bytes) if bytes.len() > max_bytes => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "fixture file exceeds read limit",
                )),
                Some(bytes) => Ok(Some(bytes.clone())),
                None => Ok(None),
            }
        }

        fn write_atomic_confined(
            &self,
            _repository_root: &Path,
            _path: &RepoRelativePath,
            _bytes: &[u8],
        ) -> io::Result<()> {
            self.writes.set(self.writes.get() + 1);
            Err(io::Error::other("planner must not write"))
        }
    }

    #[derive(Debug)]
    struct FixtureHasher;

    impl Hasher for FixtureHasher {
        fn digest(&self, chunks: &[&[u8]]) -> Digest {
            let mut hash = 0xcbf2_9ce4_8422_2325_u64;
            for chunk in chunks {
                hash ^= chunk.len() as u64;
                hash = hash.wrapping_mul(0x100_0000_01b3);
                for byte in *chunk {
                    hash ^= u64::from(*byte);
                    hash = hash.wrapping_mul(0x100_0000_01b3);
                }
            }
            Digest::new(format!("fixture:{hash:016x}"))
        }
    }

    fn provenance(rule_id: &str) -> Provenance {
        Provenance {
            rule_id: rule_id.to_owned(),
            source_path: None,
            source_range: None,
            detail: format!("evidence for {rule_id}"),
        }
    }

    fn model_with_command() -> Result<ProjectModel, Box<dyn Error>> {
        let repository = RepoFacts {
            id: RepoId::from("local:fixture"),
            root: PathBuf::from("/repo"),
            git_dir: PathBuf::from("/repo/.git"),
            git_common_dir: PathBuf::from("/repo/.git"),
            is_linked_worktree: false,
            head: None,
            branch: None,
            upstream: None,
            work_state: WorkState::Clean,
        };
        let mut model = ProjectModel::new(ProjectModelInputs {
            repository,
            repository_provenance: vec![provenance("repository")],
            repository_confidence: Confidence::High,
            unit_inventory_provenance: vec![provenance("units")],
            unit_inventory_confidence: Confidence::High,
            assets: AssetInventory::new(
                vec![AssetInfo::new(
                    "documentation.readme",
                    RepoRelativePath::new("README.md")?,
                    vec![provenance("asset/readme")],
                    Confidence::High,
                )],
                vec![provenance("assets")],
                Confidence::High,
            ),
            adapters: AdapterInventory::new(
                Vec::new(),
                vec![provenance("adapters")],
                Confidence::High,
            ),
            policy: EffectivePolicy::new(None, vec![provenance("policy")], Confidence::High),
        });
        for intent in Intent::ALL {
            model.commands.insert(
                intent,
                ResolvedCommandSet::absent(
                    vec![provenance(&format!("commands/{intent:?}"))],
                    Confidence::High,
                ),
            );
        }
        let mut command = CommandSpec::new(
            "cargo.test",
            Intent::Test,
            "cargo",
            RepoRelativePath::root(),
            CommandSource::ExistingProjectTarget {
                path: RepoRelativePath::new("Makefile")?,
                target: "test".into(),
            },
        )
        .with_args(["test", "--workspace"]);
        command.confidence = Confidence::High;
        command.mutability = forge_core::Mutability::ExternalSideEffect;
        model.commands.insert(
            Intent::Test,
            ResolvedCommandSet::resolved(
                vec![command],
                vec![provenance("commands/test")],
                Confidence::High,
                Confidence::Medium,
            )?,
        );
        Ok(model)
    }

    fn no_project_facts() -> Result<ProjectModel, Box<dyn Error>> {
        let mut model = model_with_command()?;
        model.commands.insert(
            Intent::Test,
            ResolvedCommandSet::absent(vec![provenance("commands/test/absent")], Confidence::High),
        );
        Ok(model)
    }

    #[test]
    fn missing_agents_plans_one_create_without_writing() -> Result<(), Box<dyn Error>> {
        let files = MemoryFiles::default();
        let plan = plan_init(
            &model_with_command()?,
            &files,
            &FixtureHasher,
            &InitPlanOptions::default(),
        )?;

        assert_eq!(plan.edits.len(), 1);
        assert_eq!(plan.edits[0].kind, FileEditKind::Create);
        assert_eq!(plan.edits[0].path.as_path(), Path::new("AGENTS.md"));
        assert_eq!(plan.edits[0].expected_preimage, None);
        assert_eq!(
            plan.rollback.remove_created,
            vec![plan.edits[0].path.clone()]
        );
        assert!(plan.rollback.restore_modified.is_empty());
        assert_eq!(files.writes.get(), 0);
        let preview = std::str::from_utf8(&plan.edits[0].preview_postimage)?;
        for heading in [
            "## Authoritative paths",
            "## Project-native commands",
            "## Optional local Receipts",
            "## Completion evidence",
            "## Stop boundaries",
        ] {
            assert!(preview.contains(heading));
        }
        assert!(preview.contains("`forge evidence run test`"));
        assert!(preview.contains("`cargo` `test` `--workspace`"));
        assert!(!preview.contains("/repo"));
        Ok(())
    }

    #[test]
    fn init_classifies_gaps_before_authorizing_edits() -> Result<(), Box<dyn Error>> {
        let files = MemoryFiles::default();
        let mut model = model_with_command()?;
        model.commands.insert(
            Intent::Check,
            ResolvedCommandSet::unknown(Vec::new(), vec![provenance("commands/check/unknown")]),
        );

        let inspection =
            inspect_init_targets(&model, &files, &FixtureHasher, &InitPlanOptions::default())?;

        assert!(inspection.gaps.iter().any(|gap| {
            gap.kind == GapKind::MissingHostIndex
                && gap
                    .path
                    .as_ref()
                    .is_some_and(|path| path.as_path() == Path::new("AGENTS.md"))
                && gap.intent.is_none()
        }));
        assert!(inspection.gaps.iter().any(|gap| {
            gap.kind == GapKind::ConfigurationRequired
                && gap.path.is_none()
                && gap.intent == Some(Intent::Check)
        }));
        assert!(inspection.gaps.iter().any(|gap| {
            gap.kind == GapKind::MissingProjectCommand
                && gap.path.is_none()
                && gap.intent == Some(Intent::Setup)
        }));
        assert!(inspection.assumptions.iter().any(|assumption| {
            assumption.statement.contains("`check`")
                && assumption.statement.contains("forge.toml")
                && assumption.confidence == Confidence::Unknown
        }));
        assert_eq!(files.writes.get(), 0);
        Ok(())
    }

    #[test]
    fn brownfield_plan_preserves_every_byte_outside_the_block() -> Result<(), Box<dyn Error>> {
        let existing = b"# Human guidance\r\nkeep this\r\n".to_vec();
        let files = MemoryFiles::with("AGENTS.md", existing.clone());
        let plan = plan_init(
            &model_with_command()?,
            &files,
            &FixtureHasher,
            &InitPlanOptions::default(),
        )?;

        assert_eq!(plan.edits.len(), 1);
        assert_eq!(plan.edits[0].kind, FileEditKind::ReplaceManagedBlock);
        assert!(plan.edits[0].expected_preimage.is_some());
        assert!(plan.edits[0].preview_postimage.starts_with(&existing));
        assert_eq!(plan.edits[0].fallback_line_ending, LineEnding::Lf);
        assert_has_only_crlf(&plan.edits[0].preview_postimage);
        assert_eq!(
            plan.rollback.restore_modified,
            vec![plan.edits[0].path.clone()]
        );
        assert!(plan.rollback.remove_created.is_empty());
        Ok(())
    }

    #[test]
    fn root_gitattributes_direct_crlf_rule_controls_new_markdown() -> Result<(), Box<dyn Error>> {
        let files = MemoryFiles::with(".gitattributes", b"*.md text eol=crlf\n".to_vec());
        let plan = plan_init(
            &model_with_command()?,
            &files,
            &FixtureHasher,
            &InitPlanOptions::default(),
        )?;
        let edit = plan
            .edits
            .iter()
            .find(|edit| edit.path.as_path() == Path::new("AGENTS.md"))
            .ok_or("missing AGENTS.md edit")?;

        assert_eq!(edit.fallback_line_ending, LineEnding::CrLf);
        assert_has_only_crlf(&edit.preview_postimage);
        assert!(edit.preview_postimage.ends_with(b"\r\n"));
        Ok(())
    }

    #[test]
    fn root_gitattributes_later_exact_rule_overrides_a_supported_wildcard()
    -> Result<(), Box<dyn Error>> {
        let files = MemoryFiles::with(
            ".gitattributes",
            b"*.md text eol=crlf\nAGENTS.md text eol=lf\n".to_vec(),
        );
        let plan = plan_init(
            &model_with_command()?,
            &files,
            &FixtureHasher,
            &InitPlanOptions::default(),
        )?;
        let edit = &plan.edits[0];

        assert_eq!(edit.fallback_line_ending, LineEnding::Lf);
        assert!(edit.preview_postimage.contains(&b'\n'));
        assert!(
            !edit
                .preview_postimage
                .windows(2)
                .any(|pair| pair == b"\r\n")
        );
        Ok(())
    }

    #[test]
    fn indeterminate_attribute_rules_fall_back_to_lf_without_approximating_git()
    -> Result<(), Box<dyn Error>> {
        for attributes in [
            b"**/AGENTS.md eol=crlf\n".as_slice(),
            b"*.md -text eol=crlf\n".as_slice(),
            b"*.md eol=crlf\n*.md -text\n".as_slice(),
            b"*.md custom-macro\n*.md eol=crlf\n".as_slice(),
        ] {
            let files = MemoryFiles::with(".gitattributes", attributes.to_vec());
            let plan = plan_init(
                &model_with_command()?,
                &files,
                &FixtureHasher,
                &InitPlanOptions::default(),
            )?;
            let edit = &plan.edits[0];

            assert_eq!(edit.fallback_line_ending, LineEnding::Lf);
            assert!(
                !edit
                    .preview_postimage
                    .windows(2)
                    .any(|pair| pair == b"\r\n")
            );
        }
        Ok(())
    }

    #[test]
    fn existing_crlf_block_wins_over_a_conflicting_lf_attribute_on_replace()
    -> Result<(), Box<dyn Error>> {
        let original_model = model_with_command()?;
        let original = plan_init(
            &original_model,
            &MemoryFiles::with(".gitattributes", b"*.md eol=crlf\n".to_vec()),
            &FixtureHasher,
            &InitPlanOptions::default(),
        )?;
        let original_agents = original.edits[0].preview_postimage.clone();
        assert_has_only_crlf(&original_agents);

        let mut changed_model = original_model;
        changed_model.assets = AssetInventory::new(
            vec![
                AssetInfo::new(
                    "documentation.readme",
                    RepoRelativePath::new("README.md")?,
                    vec![provenance("asset/readme")],
                    Confidence::High,
                ),
                AssetInfo::new(
                    "documentation.design",
                    RepoRelativePath::new("docs/design.md")?,
                    vec![provenance("asset/design")],
                    Confidence::High,
                ),
            ],
            vec![provenance("assets/changed")],
            Confidence::High,
        );
        let files = MemoryFiles::from_files([
            (".gitattributes", b"*.md eol=lf\n".to_vec()),
            ("AGENTS.md", original_agents),
        ]);
        let changed = plan_init(
            &changed_model,
            &files,
            &FixtureHasher,
            &InitPlanOptions::default(),
        )?;
        let edit = &changed.edits[0];

        assert_eq!(edit.kind, FileEditKind::ReplaceManagedBlock);
        assert_eq!(edit.fallback_line_ending, LineEnding::Lf);
        assert_has_only_crlf(&edit.preview_postimage);
        Ok(())
    }

    #[test]
    fn second_plan_is_empty_for_the_first_preview() -> Result<(), Box<dyn Error>> {
        let model = model_with_command()?;
        let first = plan_init(
            &model,
            &MemoryFiles::default(),
            &FixtureHasher,
            &InitPlanOptions::default(),
        )?;
        let files = MemoryFiles::with("AGENTS.md", first.edits[0].preview_postimage.clone());
        let second = plan_init(&model, &files, &FixtureHasher, &InitPlanOptions::default())?;

        assert!(second.edits.is_empty());
        assert!(second.rollback.remove_created.is_empty());
        assert!(second.rollback.restore_modified.is_empty());
        assert!(second.skipped.iter().any(|skipped| {
            skipped.path.as_path() == Path::new("AGENTS.md")
                && skipped.reason == SkippedReason::AlreadySatisfied
        }));
        Ok(())
    }

    #[test]
    fn explicit_runner_create_projects_post_apply_agents_and_then_converges()
    -> Result<(), Box<dyn Error>> {
        let model = model_with_command()?;
        let options = InitPlanOptions {
            adapters: Vec::new(),
            adopted_adapters: Vec::new(),
            adapter_selection: AdapterSelectionOverrides::default(),
            force_blocks: Vec::new(),
            runner: Some(RunnerTarget::Task),
            ci: None,
        };
        let first = plan_init(&model, &MemoryFiles::default(), &FixtureHasher, &options)?;
        assert_eq!(
            first
                .edits
                .iter()
                .map(|edit| edit.path.as_path())
                .collect::<Vec<_>>(),
            [Path::new("AGENTS.md"), Path::new("Taskfile.yml")]
        );
        let runner = first
            .edits
            .iter()
            .find(|edit| edit.path.as_path() == Path::new("Taskfile.yml"))
            .ok_or("runner edit is missing")?;
        let runner_text = std::str::from_utf8(&runner.preview_postimage)?;
        assert!(runner_text.contains("# forge:begin block=runner-task-verify"));
        assert!(runner_text.contains("cmd: '''cargo'' ''test'' ''--workspace'''"));
        assert!(!runner_text.contains("forge evidence"));
        assert!(!first.gaps.iter().any(|gap| {
            gap.kind == GapKind::MissingProjectCommand && gap.intent == Some(Intent::Verify)
        }));
        for intent in [Intent::Setup, Intent::Build] {
            assert!(first.gaps.iter().any(|gap| {
                gap.kind == GapKind::MissingProjectCommand && gap.intent == Some(intent)
            }));
        }

        let files = MemoryFiles::from_files(first.edits.iter().map(|edit| {
            (
                if edit.path.as_path() == Path::new("AGENTS.md") {
                    "AGENTS.md"
                } else {
                    "Taskfile.yml"
                },
                edit.preview_postimage.clone(),
            )
        }));
        let post_model = project_runner_model(&model, RunnerTarget::Task)?;
        let second = plan_init(&post_model, &files, &FixtureHasher, &options)?;

        assert!(second.edits.is_empty());
        assert_eq!(second.model_digest, first.model_digest);
        Ok(())
    }

    #[test]
    fn explicit_github_ci_is_create_only_and_semantically_idempotent() -> Result<(), Box<dyn Error>>
    {
        let model = model_with_command()?;
        let options = InitPlanOptions {
            ci: Some(CiTarget::Github),
            ..InitPlanOptions::default()
        };
        let first = plan_init(&model, &MemoryFiles::default(), &FixtureHasher, &options)?;
        let workflow = first
            .edits
            .iter()
            .find(|edit| edit.path.as_path() == Path::new(GITHUB_WORKFLOW_PATH))
            .ok_or_else(|| io::Error::other("missing GitHub workflow edit"))?;
        assert_eq!(workflow.kind, FileEditKind::Create);
        assert!(matches!(
            &workflow.desired,
            DesiredFile::WholeFile(CiTarget::Github)
        ));
        let workflow_bytes = workflow.preview_postimage.clone();
        let agents_bytes = first
            .edits
            .iter()
            .find(|edit| edit.path.as_path() == Path::new("AGENTS.md"))
            .ok_or_else(|| io::Error::other("missing AGENTS.md edit"))?
            .preview_postimage
            .clone();

        let exact = MemoryFiles::from_files([
            ("AGENTS.md", agents_bytes.clone()),
            (GITHUB_WORKFLOW_PATH, workflow_bytes.clone()),
        ]);
        let second = plan_init(&model, &exact, &FixtureHasher, &options)?;
        assert!(second.edits.is_empty());
        assert!(second.skipped.iter().any(|skipped| {
            skipped.path.as_path() == Path::new(GITHUB_WORKFLOW_PATH)
                && skipped.reason == SkippedReason::EquivalentUnmanaged
        }));

        let mut commented = b"# repository-owned comment\n".to_vec();
        commented.extend_from_slice(&workflow_bytes);
        let semantic = MemoryFiles::from_files([
            ("AGENTS.md", agents_bytes),
            (GITHUB_WORKFLOW_PATH, commented),
        ]);
        let third = plan_init(&model, &semantic, &FixtureHasher, &options)?;
        assert!(third.edits.is_empty());
        assert_eq!(semantic.writes.get(), 0);
        Ok(())
    }

    #[test]
    fn existing_non_equivalent_or_unknown_ci_is_never_overwritten() -> Result<(), Box<dyn Error>> {
        let model = model_with_command()?;
        let options = InitPlanOptions {
            ci: Some(CiTarget::Github),
            ..InitPlanOptions::default()
        };
        let first = plan_init(&model, &MemoryFiles::default(), &FixtureHasher, &options)?;
        let workflow = first
            .edits
            .iter()
            .find(|edit| edit.path.as_path() == Path::new(GITHUB_WORKFLOW_PATH))
            .ok_or_else(|| io::Error::other("missing GitHub workflow edit"))?;
        let different = String::from_utf8(workflow.preview_postimage.clone())?
            .replace("runs-on: ubuntu-24.04", "runs-on: ubuntu-latest");

        for (content, expected) in [
            (different.into_bytes(), CiEquivalence::NotEquivalent),
            (b"jobs: [\n".to_vec(), CiEquivalence::Unknown),
        ] {
            let files = MemoryFiles::with(GITHUB_WORKFLOW_PATH, content);
            assert!(matches!(
                plan_init(&model, &files, &FixtureHasher, &options),
                Err(PlanError::CiConflict { equivalence, .. }) if equivalence == expected
            ));
            assert_eq!(files.writes.get(), 0);
        }
        Ok(())
    }

    #[test]
    fn explicit_runner_preserves_an_existing_human_owned_file() -> Result<(), Box<dyn Error>> {
        let existing = b"# human runner\nverify:\n    cargo test\n".to_vec();
        let options = InitPlanOptions {
            adapters: Vec::new(),
            adopted_adapters: Vec::new(),
            adapter_selection: AdapterSelectionOverrides::default(),
            force_blocks: Vec::new(),
            runner: Some(RunnerTarget::Task),
            ci: None,
        };
        let plan = plan_init(
            &model_with_command()?,
            &MemoryFiles::with("Taskfile.yml", existing),
            &FixtureHasher,
            &options,
        )?;

        assert!(
            plan.edits
                .iter()
                .all(|edit| edit.path.as_path() != Path::new("Taskfile.yml"))
        );
        assert!(
            plan.assumptions
                .iter()
                .any(|assumption| assumption.statement.contains("was not modified"))
        );
        Ok(())
    }

    #[test]
    fn similar_marker_id_does_not_claim_a_human_runner() -> Result<(), Box<dyn Error>> {
        let existing = ManagedBlock {
            id: "runner-task-verify-old",
            body: "verify-old:\n    cargo test",
        }
        .render_hash_comment(&FixtureHasher)?;
        let options = InitPlanOptions {
            adapters: Vec::new(),
            adopted_adapters: Vec::new(),
            adapter_selection: AdapterSelectionOverrides::default(),
            force_blocks: Vec::new(),
            runner: Some(RunnerTarget::Task),
            ci: None,
        };
        let plan = plan_init(
            &model_with_command()?,
            &MemoryFiles::with("Taskfile.yml", existing),
            &FixtureHasher,
            &options,
        )?;

        assert!(
            plan.edits
                .iter()
                .all(|edit| edit.path.as_path() != Path::new("Taskfile.yml"))
        );
        Ok(())
    }

    #[test]
    fn owned_runner_does_not_hide_an_ambiguous_verify_interface() -> Result<(), Box<dyn Error>> {
        let model = model_with_command()?;
        let options = InitPlanOptions {
            adapters: Vec::new(),
            adopted_adapters: Vec::new(),
            adapter_selection: AdapterSelectionOverrides::default(),
            force_blocks: Vec::new(),
            runner: Some(RunnerTarget::Task),
            ci: None,
        };
        let first = plan_init(&model, &MemoryFiles::default(), &FixtureHasher, &options)?;
        let files = MemoryFiles::from_files(first.edits.iter().map(|edit| {
            (
                if edit.path.as_path() == Path::new("AGENTS.md") {
                    "AGENTS.md"
                } else {
                    "Taskfile.yml"
                },
                edit.preview_postimage.clone(),
            )
        }));
        let mut ambiguous = project_runner_model(&model, RunnerTarget::Task)?;
        let selected = ambiguous
            .commands
            .get(&Intent::Verify)
            .and_then(ResolvedCommandSet::executable_commands)
            .and_then(|commands| commands.first())
            .cloned()
            .ok_or("projected verify command is missing")?;
        let mut competing = CommandSpec::new(
            "runner.make.verify",
            Intent::Verify,
            "make",
            RepoRelativePath::root(),
            CommandSource::ExistingProjectTarget {
                path: RepoRelativePath::new("Makefile")?,
                target: String::from("verify"),
            },
        )
        .with_args(["--file", "Makefile", "verify"]);
        competing.confidence = Confidence::Medium;
        ambiguous.commands.insert(
            Intent::Verify,
            ResolvedCommandSet::ambiguous(
                vec![selected, competing],
                vec![provenance("commands/verify/ambiguous")],
                Confidence::Medium,
            ),
        );
        ambiguous = ambiguous.finalize()?;

        assert!(matches!(
            plan_init(&ambiguous, &files, &FixtureHasher, &options),
            Err(PlanError::RunnerConflict { .. })
        ));
        Ok(())
    }

    #[test]
    fn explicit_runner_user_edit_is_a_named_managed_block_conflict() -> Result<(), Box<dyn Error>> {
        let model = model_with_command()?;
        let options = InitPlanOptions {
            adapters: Vec::new(),
            adopted_adapters: Vec::new(),
            adapter_selection: AdapterSelectionOverrides::default(),
            force_blocks: Vec::new(),
            runner: Some(RunnerTarget::Task),
            ci: None,
        };
        let first = plan_init(&model, &MemoryFiles::default(), &FixtureHasher, &options)?;
        let mut files = first
            .edits
            .iter()
            .map(|edit| {
                (
                    if edit.path.as_path() == Path::new("AGENTS.md") {
                        "AGENTS.md"
                    } else {
                        "Taskfile.yml"
                    },
                    edit.preview_postimage.clone(),
                )
            })
            .collect::<Vec<_>>();
        let runner = files
            .iter_mut()
            .find(|(path, _)| *path == "Taskfile.yml")
            .ok_or("runner fixture is missing")?;
        runner.1 = String::from_utf8(runner.1.clone())?
            .replace("'cargo'", "'human-edit'")
            .into_bytes();
        let post_model = project_runner_model(&model, RunnerTarget::Task)?;

        assert!(matches!(
            plan_init(
                &post_model,
                &MemoryFiles::from_files(files),
                &FixtureHasher,
                &options
            ),
            Err(PlanError::ManagedBlock {
                source: ManagedBlockError::UserEdited { ref id },
                ..
            }) if id == "runner-task-verify"
        ));
        Ok(())
    }

    #[test]
    fn user_edited_and_future_markers_fail_closed() -> Result<(), Box<dyn Error>> {
        let model = model_with_command()?;
        let first = plan_init(
            &model,
            &MemoryFiles::default(),
            &FixtureHasher,
            &InitPlanOptions::default(),
        )?;
        let edited = String::from_utf8(first.edits[0].preview_postimage.clone())?
            .replace("## Authoritative paths", "## Human edit");
        let edited_error = plan_init(
            &model,
            &MemoryFiles::with("AGENTS.md", edited),
            &FixtureHasher,
            &InitPlanOptions::default(),
        );
        assert!(matches!(
            edited_error,
            Err(PlanError::ManagedBlock {
                source: ManagedBlockError::UserEdited { .. },
                ..
            })
        ));

        let future = concat!(
            "<!-- forge:begin block=project-index schema=2 hash=future -->\n",
            "future\n",
            "<!-- forge:end block=project-index -->\n"
        );
        let future_error = plan_init(
            &model,
            &MemoryFiles::with("AGENTS.md", future),
            &FixtureHasher,
            &InitPlanOptions::default(),
        );
        assert!(matches!(
            future_error,
            Err(PlanError::ManagedBlock {
                source: ManagedBlockError::UnsupportedSchema { schema: 2, .. },
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn high_level_inspection_aggregates_user_edits_before_force_authorizes_a_plan()
    -> Result<(), Box<dyn Error>> {
        let model = model_with_command()?;
        let inspect_options = InitPlanOptions {
            adapters: vec![AdapterTarget::Claude],
            adopted_adapters: Vec::new(),
            adapter_selection: AdapterSelectionOverrides::default(),
            force_blocks: Vec::new(),
            runner: None,
            ci: None,
        };
        let initial = plan_init(
            &model,
            &MemoryFiles::default(),
            &FixtureHasher,
            &inspect_options,
        )?;
        let agents = initial
            .edits
            .iter()
            .find(|edit| edit.path.as_path() == Path::new("AGENTS.md"))
            .ok_or_else(|| io::Error::other("missing initial AGENTS.md edit"))?;
        let claude = initial
            .edits
            .iter()
            .find(|edit| edit.path.as_path() == Path::new("CLAUDE.md"))
            .ok_or_else(|| io::Error::other("missing initial CLAUDE.md edit"))?;
        let edited_agents = String::from_utf8(agents.preview_postimage.clone())?
            .replace("## Authoritative paths", "## Human-owned paths")
            .into_bytes();
        let edited_claude = String::from_utf8(claude.preview_postimage.clone())?
            .replace("@AGENTS.md", "@HUMAN.md")
            .into_bytes();
        let files =
            MemoryFiles::from_files([("AGENTS.md", edited_agents), ("CLAUDE.md", edited_claude)]);

        let inspection = inspect_init_targets(&model, &files, &FixtureHasher, &inspect_options)?;
        assert_eq!(inspection.targets.len(), 2);
        assert!(inspection.targets.iter().all(|target| {
            target.kind() == AdapterInspectionKind::UserEdited
                && matches!(
                    &target.state,
                    crate::inspection::AdapterInspectionState::Edit(edit)
                        if edit.reason == FileEditReason::UserEdited
                            && !edit.preview_postimage.is_empty()
                )
        }));
        assert_eq!(files.writes.get(), 0);

        assert!(matches!(
            plan_init(&model, &files, &FixtureHasher, &inspect_options),
            Err(PlanError::ManagedBlock {
                source: ManagedBlockError::UserEdited { .. },
                ..
            })
        ));

        let forced_options = InitPlanOptions {
            adapters: vec![AdapterTarget::Claude],
            adopted_adapters: Vec::new(),
            adapter_selection: AdapterSelectionOverrides::default(),
            force_blocks: vec![
                ManagedBlockKind::ProjectIndex,
                ManagedBlockKind::ClaudePointer,
            ],
            runner: None,
            ci: None,
        };
        let forced_inspection =
            inspect_init_targets(&model, &files, &FixtureHasher, &forced_options)?;
        assert_eq!(forced_inspection.targets, inspection.targets);
        let forced = plan_init(&model, &files, &FixtureHasher, &forced_options)?;
        assert_eq!(forced.edits.len(), 2);
        assert!(
            forced
                .edits
                .iter()
                .all(|edit| { edit.reason == FileEditReason::UserEdited && edit.force })
        );
        assert_eq!(files.writes.get(), 0);
        Ok(())
    }

    #[test]
    fn claude_gets_a_pointer_while_cursor_and_codex_reuse_agents() -> Result<(), Box<dyn Error>> {
        let options = InitPlanOptions {
            adapters: vec![
                AdapterTarget::Cursor,
                AdapterTarget::Claude,
                AdapterTarget::Codex,
            ],
            adopted_adapters: Vec::new(),
            adapter_selection: AdapterSelectionOverrides::default(),
            force_blocks: Vec::new(),
            runner: None,
            ci: None,
        };
        let plan = plan_init(
            &model_with_command()?,
            &MemoryFiles::default(),
            &FixtureHasher,
            &options,
        )?;

        assert_eq!(
            plan.edits
                .iter()
                .map(|edit| edit.path.as_path())
                .collect::<Vec<_>>(),
            vec![Path::new("AGENTS.md"), Path::new("CLAUDE.md")]
        );
        let claude = plan
            .edits
            .iter()
            .find(|edit| edit.path.as_path() == Path::new("CLAUDE.md"))
            .ok_or_else(|| io::Error::other("missing CLAUDE.md edit"))?;
        assert!(std::str::from_utf8(&claude.preview_postimage)?.contains("@AGENTS.md"));
        assert_eq!(
            plan.skipped
                .iter()
                .filter(|skipped| matches!(skipped.reason, SkippedReason::ReusesAgents(_)))
                .count(),
            2
        );
        for spec in adapter_specs() {
            if spec.owns_managed_projection() {
                assert!(plan.edits.iter().any(|edit| {
                    edit.path.as_path() == Path::new(spec.path)
                        && edit
                            .desired
                            .managed_block()
                            .is_some_and(|desired| desired.kind == spec.block)
                }));
            }
            if let AdapterSelection::ExplicitReuse { source } = spec.selection {
                assert!(
                    plan.skipped.iter().any(|skipped| {
                        skipped.reason == SkippedReason::ReusesAgents(spec.target)
                    })
                );
                let source_spec = adapter_specs()
                    .iter()
                    .find(|candidate| candidate.target == source)
                    .ok_or_else(|| io::Error::other("reuse source is not registered"))?;
                assert!(source_spec.owns_managed_projection());
                assert_eq!(spec.path, source_spec.path);
                assert_eq!(spec.block, source_spec.block);
            }
        }
        Ok(())
    }

    #[test]
    fn detected_claude_generates_the_same_minimal_pointer() -> Result<(), Box<dyn Error>> {
        let mut model = model_with_command()?;
        model.adapters = AdapterInventory::new(
            vec![AdapterInfo::new(
                "claude",
                RepoRelativePath::new("CLAUDE.md")?,
                vec![provenance("adapter/claude")],
                Confidence::High,
            )],
            vec![provenance("adapters")],
            Confidence::High,
        );
        let plan = plan_init(
            &model,
            &MemoryFiles::default(),
            &FixtureHasher,
            &InitPlanOptions::default(),
        )?;

        assert_eq!(plan.edits.len(), 2);
        assert!(plan.edits.iter().any(|edit| {
            edit.path.as_path() == Path::new("CLAUDE.md")
                && edit
                    .desired
                    .managed_block()
                    .is_some_and(|desired| desired.body == "@AGENTS.md")
        }));
        Ok(())
    }

    #[test]
    fn false_overrides_suppress_detected_adapters_and_preserve_existing_blocks()
    -> Result<(), Box<dyn Error>> {
        let mut model = model_with_command()?;
        model.adapters = AdapterInventory::new(
            vec![AdapterInfo::new(
                "claude",
                RepoRelativePath::new("CLAUDE.md")?,
                vec![provenance("adapter/claude")],
                Confidence::High,
            )],
            vec![provenance("adapters")],
            Confidence::High,
        );
        let initial = plan_init(
            &model,
            &MemoryFiles::default(),
            &FixtureHasher,
            &InitPlanOptions::default(),
        )?;
        let agents = initial
            .edits
            .iter()
            .find(|edit| edit.path.as_path() == Path::new("AGENTS.md"))
            .ok_or_else(|| io::Error::other("missing AGENTS.md fixture"))?
            .preview_postimage
            .clone();
        let claude = initial
            .edits
            .iter()
            .find(|edit| edit.path.as_path() == Path::new("CLAUDE.md"))
            .ok_or_else(|| io::Error::other("missing CLAUDE.md fixture"))?
            .preview_postimage
            .clone();
        let files = MemoryFiles::from_files([
            ("AGENTS.md", agents.clone()),
            ("CLAUDE.md", claude.clone()),
            (".gitattributes", vec![b'x'; GITATTRIBUTES_MAX_BYTES + 1]),
        ]);
        let options = InitPlanOptions {
            adapter_selection: AdapterSelectionOverrides {
                agents: Some(false),
                claude: Some(false),
            },
            ..InitPlanOptions::default()
        };

        let inspection = inspect_init_targets(&model, &files, &FixtureHasher, &options)?;
        let plan = plan_init(&model, &files, &FixtureHasher, &options)?;

        assert!(inspection.targets.is_empty());
        assert!(plan.edits.is_empty());
        assert_eq!(files.writes.get(), 0);
        let observed = files.files.borrow();
        assert_eq!(observed.get(Path::new("AGENTS.md")), Some(&agents));
        assert_eq!(observed.get(Path::new("CLAUDE.md")), Some(&claude));
        Ok(())
    }

    #[test]
    fn true_overrides_enable_adapters_while_direct_requests_override_false()
    -> Result<(), Box<dyn Error>> {
        let model = model_with_command()?;
        let configured = InitPlanOptions {
            adapter_selection: AdapterSelectionOverrides {
                agents: Some(true),
                claude: Some(true),
            },
            ..InitPlanOptions::default()
        };
        let configured_plan =
            plan_init(&model, &MemoryFiles::default(), &FixtureHasher, &configured)?;
        assert_eq!(configured_plan.edits.len(), 2);

        let explicit = InitPlanOptions {
            adapters: vec![AdapterTarget::Claude],
            adapter_selection: AdapterSelectionOverrides {
                agents: Some(false),
                claude: Some(false),
            },
            ..InitPlanOptions::default()
        };
        let explicit_plan = plan_init(&model, &MemoryFiles::default(), &FixtureHasher, &explicit)?;
        assert_eq!(explicit_plan.edits.len(), 2);
        assert!(explicit_plan.edits.iter().any(|edit| {
            edit.path.as_path() == Path::new("AGENTS.md")
                && edit
                    .desired
                    .managed_block()
                    .is_some_and(|desired| desired.kind == ManagedBlockKind::ProjectIndex)
        }));
        assert!(explicit_plan.edits.iter().any(|edit| {
            edit.path.as_path() == Path::new("CLAUDE.md")
                && edit
                    .desired
                    .managed_block()
                    .is_some_and(|desired| desired.kind == ManagedBlockKind::ClaudePointer)
        }));
        Ok(())
    }

    #[test]
    fn enabled_dependent_adapter_rejects_a_disabled_canonical_projection()
    -> Result<(), Box<dyn Error>> {
        let options = InitPlanOptions {
            adapter_selection: AdapterSelectionOverrides {
                agents: Some(false),
                claude: Some(true),
            },
            ..InitPlanOptions::default()
        };

        assert!(matches!(
            plan_init(
                &model_with_command()?,
                &MemoryFiles::default(),
                &FixtureHasher,
                &options,
            ),
            Err(PlanError::AdapterDependencyConflict {
                adapter: AdapterTarget::Claude,
                required: AdapterTarget::Codex,
            })
        ));
        Ok(())
    }

    #[test]
    fn unmanaged_claude_pointer_is_equivalent_without_appending_a_block()
    -> Result<(), Box<dyn Error>> {
        let options = InitPlanOptions {
            adapters: vec![AdapterTarget::Claude],
            adopted_adapters: Vec::new(),
            adapter_selection: AdapterSelectionOverrides::default(),
            force_blocks: Vec::new(),
            runner: None,
            ci: None,
        };
        let plan = plan_init(
            &model_with_command()?,
            &MemoryFiles::with("CLAUDE.md", "@AGENTS.md\r\n\r\n"),
            &FixtureHasher,
            &options,
        )?;

        assert_eq!(plan.edits.len(), 1);
        assert_eq!(plan.edits[0].path.as_path(), Path::new("AGENTS.md"));
        assert!(plan.skipped.iter().any(|skipped| {
            skipped.path.as_path() == Path::new("CLAUDE.md")
                && skipped.reason == SkippedReason::EquivalentUnmanaged
        }));
        Ok(())
    }

    #[test]
    fn plan_keeps_all_assumptions_but_agents_only_renders_proven_facts()
    -> Result<(), Box<dyn Error>> {
        let mut model = model_with_command()?;
        model.assumptions = vec![
            Assumption::new(
                "low-confidence review fact",
                vec![provenance("assumption/low")],
                Confidence::Low,
            ),
            Assumption::new(
                "unknown deployment fact",
                vec![provenance("assumption/unknown")],
                Confidence::Unknown,
            ),
        ];
        let plan = plan_init(
            &model,
            &MemoryFiles::default(),
            &FixtureHasher,
            &InitPlanOptions::default(),
        )?;

        assert_eq!(plan.assumptions.len(), 2);
        let preview = std::str::from_utf8(&plan.edits[0].preview_postimage)?;
        assert!(!preview.contains("low-confidence review fact"));
        assert!(!preview.contains("unknown deployment fact"));
        Ok(())
    }

    #[test]
    fn safe_environment_is_rendered_without_host_paths_and_secrets_are_omitted()
    -> Result<(), Box<dyn Error>> {
        let mut model = model_with_command()?;
        let mut safe = CommandSpec::new(
            "go.test",
            Intent::Test,
            "go",
            RepoRelativePath::root(),
            CommandSource::LanguageDefault {
                provider: "go".into(),
                rule: "test".into(),
            },
        )
        .with_args(["test", "./..."]);
        safe.confidence = Confidence::High;
        safe.env
            .insert(OsString::from("GOWORK"), OsString::from("/repo/go.work"));
        safe.env
            .insert(OsString::from("GOFLAGS"), OsString::from("-mod=readonly"));
        model.commands.insert(
            Intent::Test,
            ResolvedCommandSet::resolved(
                vec![safe],
                vec![provenance("commands/go-test")],
                Confidence::High,
                Confidence::Medium,
            )?,
        );
        let safe_plan = plan_init(
            &model,
            &MemoryFiles::default(),
            &FixtureHasher,
            &InitPlanOptions::default(),
        )?;
        let safe_preview = std::str::from_utf8(&safe_plan.edits[0].preview_postimage)?;
        assert!(safe_preview.contains("`GOWORK=<repo>/go.work`"));
        assert!(safe_preview.contains("`GOFLAGS=-mod=readonly`"));
        assert!(!safe_preview.contains("/repo/go.work"));

        let mut secret = CommandSpec::new(
            "secret.test",
            Intent::Test,
            "tool",
            RepoRelativePath::root(),
            CommandSource::ExplicitConfig,
        );
        secret.confidence = Confidence::High;
        secret.env.insert(
            OsString::from("API_TOKEN"),
            OsString::from("must-not-render"),
        );
        model.commands.insert(
            Intent::Test,
            ResolvedCommandSet::resolved(
                vec![secret],
                vec![provenance("commands/secret-test")],
                Confidence::High,
                Confidence::Unknown,
            )?,
        );
        let secret_plan = plan_init(
            &model,
            &MemoryFiles::default(),
            &FixtureHasher,
            &InitPlanOptions::default(),
        )?;
        let secret_preview = std::str::from_utf8(&secret_plan.edits[0].preview_postimage)?;
        assert!(!secret_preview.contains("API_TOKEN"));
        assert!(!secret_preview.contains("must-not-render"));
        Ok(())
    }

    #[test]
    fn empty_project_and_duplicate_requests_are_rejected() -> Result<(), Box<dyn Error>> {
        assert!(matches!(
            plan_init(
                &no_project_facts()?,
                &MemoryFiles::default(),
                &FixtureHasher,
                &InitPlanOptions::default(),
            ),
            Err(PlanError::NoProjectFacts)
        ));

        let duplicates = InitPlanOptions {
            adapters: vec![AdapterTarget::Claude, AdapterTarget::Claude],
            adopted_adapters: Vec::new(),
            adapter_selection: AdapterSelectionOverrides::default(),
            force_blocks: Vec::new(),
            runner: None,
            ci: None,
        };
        assert!(matches!(
            plan_init(
                &model_with_command()?,
                &MemoryFiles::default(),
                &FixtureHasher,
                &duplicates,
            ),
            Err(PlanError::DuplicateAdapterRequest(AdapterTarget::Claude))
        ));
        Ok(())
    }

    #[test]
    fn planning_is_deterministic_and_enforces_the_agents_limit() -> Result<(), Box<dyn Error>> {
        let model = model_with_command()?;
        let first = plan_init(
            &model,
            &MemoryFiles::default(),
            &FixtureHasher,
            &InitPlanOptions::default(),
        )?;
        let second = plan_init(
            &model,
            &MemoryFiles::default(),
            &FixtureHasher,
            &InitPlanOptions::default(),
        )?;
        assert_eq!(first, second);

        let mut oversized = model;
        oversized.assets = AssetInventory::new(
            (0..130)
                .map(|index| {
                    Ok(AssetInfo::new(
                        "documentation.runbook",
                        // Keep each path at the repository root so this fixture exercises the
                        // hard adapter limit itself rather than the directory-family compactor.
                        RepoRelativePath::new(format!("runbook-{index:03}.md"))?,
                        vec![provenance(&format!("asset/{index:03}"))],
                        Confidence::High,
                    ))
                })
                .collect::<Result<Vec<_>, RelativePathError>>()?,
            vec![provenance("assets")],
            Confidence::High,
        );
        assert!(matches!(
            plan_init(
                &oversized,
                &MemoryFiles::default(),
                &FixtureHasher,
                &InitPlanOptions::default(),
            ),
            Err(PlanError::GeneratedBlockLimit { .. })
        ));
        Ok(())
    }

    #[test]
    fn oversized_adapter_file_maps_to_a_typed_plan_error_without_writing()
    -> Result<(), Box<dyn Error>> {
        let files = MemoryFiles::with("AGENTS.md", vec![b'x'; ADAPTER_FILE_MAX_BYTES + 1]);

        assert!(matches!(
            inspect_init_targets(
                &model_with_command()?,
                &files,
                &FixtureHasher,
                &InitPlanOptions::default(),
            ),
            Err(PlanError::AdapterFileLimit {
                stage: AdapterFileLimitStage::Existing,
                observed_bytes: None,
                max_bytes: ADAPTER_FILE_MAX_BYTES,
                ..
            })
        ));
        assert_eq!(files.writes.get(), 0);
        Ok(())
    }

    #[test]
    fn oversized_root_attributes_file_is_rejected_by_the_bounded_read() -> Result<(), Box<dyn Error>>
    {
        let files = MemoryFiles::with(".gitattributes", vec![b'x'; GITATTRIBUTES_MAX_BYTES + 1]);

        assert!(matches!(
            plan_init(
                &model_with_command()?,
                &files,
                &FixtureHasher,
                &InitPlanOptions::default(),
            ),
            Err(PlanError::AttributesFileLimit {
                max_bytes: GITATTRIBUTES_MAX_BYTES,
                ..
            })
        ));
        assert_eq!(files.writes.get(), 0);
        Ok(())
    }

    #[test]
    fn force_is_recorded_but_apply_is_not_performed() -> Result<(), Box<dyn Error>> {
        let model = model_with_command()?;
        let first = plan_init(
            &model,
            &MemoryFiles::default(),
            &FixtureHasher,
            &InitPlanOptions::default(),
        )?;
        let edited = String::from_utf8(first.edits[0].preview_postimage.clone())?
            .replace("## Authoritative paths", "## Human edit");
        let files = MemoryFiles::with("AGENTS.md", edited);
        let options = InitPlanOptions {
            adapters: Vec::new(),
            adopted_adapters: Vec::new(),
            adapter_selection: AdapterSelectionOverrides::default(),
            force_blocks: vec![ManagedBlockKind::ProjectIndex],
            runner: None,
            ci: None,
        };
        let forced = plan_init(&model, &files, &FixtureHasher, &options)?;

        assert_eq!(forced.edits.len(), 1);
        assert_eq!(forced.edits[0].reason, FileEditReason::UserEdited);
        assert!(forced.edits[0].force);
        assert_eq!(files.writes.get(), 0);
        Ok(())
    }

    fn assert_has_only_crlf(content: &[u8]) {
        for (index, byte) in content.iter().enumerate() {
            if *byte == b'\n' {
                assert!(index > 0 && content[index - 1] == b'\r');
            }
        }
    }
}
