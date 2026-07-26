//! Pure, read-only planning for repository host adapters.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::io;

use forge_core::domain::{Assumption, CommandResolution, ProjectModel, ProjectModelError};
use forge_core::ports::{Hasher, RepositoryFilePort};
use forge_core::{Digest, RelativePathError, RepoId, RepoRelativePath};

use crate::adapter_registry::{adapter_specs, managed_adapter_spec};
use crate::adapters::{AGENTS_MAX_BYTES, AGENTS_MAX_LINES, AdapterRenderError};
use crate::inspection::{
    AdapterInspectionError, AdapterInspectionKind, AdapterInspectionRequest,
    AdapterInspectionState, FileEditReason, inspect_adapter_targets,
};
use crate::managed_block::{ManagedBlock, ManagedBlockError};

const PLAN_SCHEMA: u16 = 1;
const MODEL_PROJECTION_DOMAIN: &[u8] = b"forge.init-model-projection/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdapterTarget {
    Claude,
    Cursor,
    Codex,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InitPlanOptions {
    pub adapters: Vec<AdapterTarget>,
    pub force_blocks: Vec<ManagedBlockKind>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ManagedBlockKind {
    ProjectIndex,
    ClaudePointer,
}

impl ManagedBlockKind {
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::ProjectIndex => "project-index",
            Self::ClaudePointer => "claude-pointer",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredManagedBlock {
    pub kind: ManagedBlockKind,
    pub body: String,
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
    pub path: RepoRelativePath,
    pub desired: DesiredManagedBlock,
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
    pub targets: Vec<InitAdapterTargetInspection>,
    pub reused_adapters: Vec<ReusedAdapter>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangePlan {
    pub schema: u16,
    pub repository: RepoId,
    pub model_digest: Digest,
    pub edits: Vec<FileEdit>,
    pub assumptions: Vec<Assumption>,
    pub skipped: Vec<SkippedChange>,
    pub rollback: RollbackPlan,
}

#[derive(Debug)]
pub enum PlanError {
    NoProjectFacts,
    DuplicateAdapterRequest(AdapterTarget),
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
            } => skipped.push(SkippedChange {
                path: target.path,
                reason: SkippedReason::AlreadySatisfied,
                satisfied_managed: Some(SatisfiedManagedBlock {
                    kind: target.desired.kind,
                    full_postimage_digest,
                }),
            }),
            AdapterInspectionState::EquivalentUnmanaged { .. } => {
                skipped.push(SkippedChange {
                    path: target.path,
                    reason: SkippedReason::EquivalentUnmanaged,
                    satisfied_managed: None,
                });
            }
            AdapterInspectionState::Edit(observed_edit) => {
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
                    path: target.path,
                    desired: target.desired,
                    expected_preimage: observed_edit.expected_preimage,
                    expected_postimage: observed_edit.full_postimage_digest,
                    preview_postimage: observed_edit.preview_postimage,
                    force,
                });
            }
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
    let _ = unique_forced_blocks(options)?;
    let mut desired_targets = Vec::new();
    let mut reused_adapters = Vec::new();
    for spec in adapter_specs() {
        let explicitly_requested = requested.contains(&spec.target);
        if spec.reports_reuse(explicitly_requested) {
            reused_adapters.push(ReusedAdapter {
                target: spec.target,
                path: target_path(spec.path)?,
            });
        }
        if !spec.selected(&model, explicitly_requested) {
            continue;
        }
        let Some(body) = spec.render_body(&model).map_err(map_render_error)? else {
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
    desired_targets.sort_by(|left, right| left.0.cmp(&right.0));
    reject_duplicate_targets(&desired_targets)?;
    for (path, desired) in &desired_targets {
        let block = ManagedBlock {
            id: desired.kind.id(),
            body: &desired.body,
        };
        if desired.kind == ManagedBlockKind::ProjectIndex {
            enforce_complete_agents_limit(path, &block, hasher)?;
        }
    }
    let requests = desired_targets
        .iter()
        .map(|(path, desired)| AdapterInspectionRequest {
            path,
            block_id: desired.kind.id(),
            desired_body: &desired.body,
            equivalent_unmanaged: managed_adapter_spec(path, desired.kind)
                .and_then(|spec| spec.equivalent_unmanaged),
        })
        .collect::<Vec<_>>();
    let model_digest = projection_digest(hasher, &model.repository.id, &desired_targets);
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
    Ok(InitAdapterInspection {
        repository: model.repository.id,
        model_digest,
        assumptions: model.assumptions,
        targets,
        reused_adapters,
    })
}

fn has_resolved_command(model: &ProjectModel) -> bool {
    model.commands.values().any(|commands| {
        commands.resolution() == CommandResolution::Resolved
            && commands
                .executable_commands()
                .is_some_and(|value| !value.is_empty())
    })
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

fn projection_digest<H>(
    hasher: &H,
    repository: &RepoId,
    targets: &[(RepoRelativePath, DesiredManagedBlock)],
) -> Digest
where
    H: Hasher + ?Sized,
{
    let mut projection = repository.as_str().as_bytes().to_vec();
    for (path, desired) in targets {
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
    hasher: &H,
) -> Result<(), PlanError>
where
    H: Hasher + ?Sized,
{
    let rendered = block
        .render_markdown(hasher)
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
    use crate::inspection::{ADAPTER_FILE_MAX_BYTES, AdapterInspectionKind, FileEditReason};
    use crate::managed_block::ManagedBlockError;

    use super::{
        AdapterFileLimitStage, AdapterTarget, FileEditKind, InitPlanOptions, ManagedBlockKind,
        PlanError, SkippedReason, inspect_init_targets, plan_init,
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
            "## Completion evidence",
            "## Stop boundaries",
        ] {
            assert!(preview.contains(heading));
        }
        assert!(preview.contains("`cargo` `test` `--workspace`"));
        assert!(!preview.contains("/repo"));
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
        assert_eq!(
            plan.rollback.restore_modified,
            vec![plan.edits[0].path.clone()]
        );
        assert!(plan.rollback.remove_created.is_empty());
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
            force_blocks: Vec::new(),
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
            force_blocks: vec![
                ManagedBlockKind::ProjectIndex,
                ManagedBlockKind::ClaudePointer,
            ],
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
            force_blocks: Vec::new(),
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
                    edit.path.as_path() == Path::new(spec.path) && edit.desired.kind == spec.block
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
            edit.path.as_path() == Path::new("CLAUDE.md") && edit.desired.body == "@AGENTS.md"
        }));
        Ok(())
    }

    #[test]
    fn unmanaged_claude_pointer_is_equivalent_without_appending_a_block()
    -> Result<(), Box<dyn Error>> {
        let options = InitPlanOptions {
            adapters: vec![AdapterTarget::Claude],
            force_blocks: Vec::new(),
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
            force_blocks: Vec::new(),
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
                        RepoRelativePath::new(format!("docs/runbooks/{index:03}.md"))?,
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
            force_blocks: vec![ManagedBlockKind::ProjectIndex],
        };
        let forced = plan_init(&model, &files, &FixtureHasher, &options)?;

        assert_eq!(forced.edits.len(), 1);
        assert_eq!(forced.edits[0].reason, FileEditReason::UserEdited);
        assert!(forced.edits[0].force);
        assert_eq!(files.writes.get(), 0);
        Ok(())
    }
}
