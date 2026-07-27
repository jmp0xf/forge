//! Deterministic, offline-safe Go workspace and module detection.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use forge_core::domain::CommandEnforcement;
use forge_core::ports::{ExecSpec, FileSystemPort, Hasher, ProcessPort};
use forge_core::{
    CommandSource, CommandSpec, Confidence, CoverageDimension, GitFileSet, Intent, Inventory,
    InventoryKind, Mutability, NetworkIntent, OperationControl, OperationControlError, PathKind,
    ProjectKind, ProjectUnit, Provenance, RepoRelativePath, SuccessPredicate, ToolchainInfo,
    UnlimitedOperationControl,
};
use serde::Deserialize;

use crate::resolution::{CommandPlanCandidate, InvalidCommandPlanCandidate};

const PROVIDER_ID: &str = "go";
const MAX_GENERATED_SCAN_BYTES: u64 = 1024 * 1024;
const MAX_FORMAT_BATCH_FILES: usize = 256;
const MAX_FORMAT_BATCH_ARG_BYTES: usize = 24 * 1024;

#[derive(Debug, Default, Clone, Copy)]
pub struct GoProvider;

/// Read-only inputs required to derive Go units and project-owned command plans.
pub struct GoProviderContext<'a> {
    pub repository_root: &'a Path,
    pub inventory: &'a Inventory,
    pub git_files: &'a GitFileSet,
    /// Complete changed-path set from typed Git status, when available.
    ///
    /// `GitFileSet` intentionally cannot prove which tracked files changed. Mutating format plans
    /// are therefore omitted when this value is `None`.
    pub changed_files: Option<&'a [RepoRelativePath]>,
    pub file_system: &'a dyn FileSystemPort,
    pub process: &'a dyn ProcessPort,
    pub hasher: &'a dyn Hasher,
    pub metadata_timeout: Duration,
}

impl fmt::Debug for GoProviderContext<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GoProviderContext")
            .field("repository_root", &self.repository_root)
            .field("inventory", &self.inventory)
            .field("git_files", &self.git_files)
            .field("changed_files", &self.changed_files)
            .field("metadata_timeout", &self.metadata_timeout)
            .finish_non_exhaustive()
    }
}

/// A bounded degradation retained instead of guessing a Go workspace or mutation scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum GoProviderIssueKind {
    InvalidRepositoryRoot,
    InventoryIncomplete,
    InvalidInventoryPath,
    InvalidManifestKind,
    ManifestProbeFailed,
    InvalidUsePath,
    UseTargetNotDirectory,
    UseManifestNotRegular,
    MetadataUnavailable,
    MetadataTimedOut,
    MetadataInterrupted,
    MetadataOutputLimit,
    MetadataCommandFailed,
    MetadataInvalid,
    DuplicateWorkspaceMembership,
    OverlappingWorkspace,
    ChangedScopeUnavailable,
    ChangedPathUnknown,
    GeneratedStatusUnknown,
    ImpactScopeBroadened,
}

impl GoProviderIssueKind {
    /// Whether this observation prevents the provider from claiming a complete result.
    ///
    /// Conservative impact broadening is the safe v0 answer to an imprecise mapping: the full
    /// validated module or workspace remains covered. The other variants mean some unit, command,
    /// or mutation boundary could not be proven and therefore keep the provider incomplete.
    const fn prevents_completion(self) -> bool {
        !matches!(self, Self::ImpactScopeBroadened)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct GoProviderIssue {
    pub kind: GoProviderIssueKind,
    pub path: Option<RepoRelativePath>,
    pub detail: String,
}

/// Complete provider output. `complete=false` means callers must preserve the recorded unknowns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoProviderResult {
    pub units: Vec<ProjectUnit>,
    pub plans: Vec<CommandPlanCandidate>,
    pub provenance: Vec<Provenance>,
    pub issues: Vec<GoProviderIssue>,
    pub confidence: Confidence,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoProviderError {
    InvalidCommandPlan(InvalidCommandPlanCandidate),
}

impl fmt::Display for GoProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCommandPlan(error) => {
                write!(formatter, "invalid Go command plan: {error}")
            }
        }
    }
}

impl Error for GoProviderError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidCommandPlan(error) => Some(error),
        }
    }
}

impl From<InvalidCommandPlanCandidate> for GoProviderError {
    fn from(value: InvalidCommandPlanCandidate) -> Self {
        Self::InvalidCommandPlan(value)
    }
}

impl GoProvider {
    /// Detects Go units and derives commands without running package targets or dependency
    /// resolution. The only subprocess permitted here is bounded `go work edit -json` metadata.
    pub fn analyze(
        &self,
        context: GoProviderContext<'_>,
    ) -> Result<GoProviderResult, GoProviderError> {
        self.analyze_controlled(context, &UnlimitedOperationControl)
    }

    /// Detects Go units while sharing one operation-wide deadline with earlier providers.
    pub fn analyze_controlled(
        &self,
        context: GoProviderContext<'_>,
        control: &dyn OperationControl,
    ) -> Result<GoProviderResult, GoProviderError> {
        analyze_go(context, control)
    }
}

#[derive(Debug, Deserialize)]
struct GoWorkMetadata {
    #[serde(rename = "Use", default)]
    uses: Vec<GoWorkUse>,
}

#[derive(Debug, Deserialize)]
struct GoWorkUse {
    #[serde(rename = "DiskPath")]
    disk_path: String,
}

#[derive(Debug)]
struct WorkspaceCandidate {
    manifest: RepoRelativePath,
    root: RepoRelativePath,
    modules: Vec<RepoRelativePath>,
    valid: bool,
}

#[derive(Debug)]
struct CommandScope {
    unit_identity: String,
    manifest: RepoRelativePath,
    root: RepoRelativePath,
    module_roots: Vec<RepoRelativePath>,
    workspace_manifest: Option<RepoRelativePath>,
    tracked_go_files: Vec<RepoRelativePath>,
    changed_go_files: Vec<RepoRelativePath>,
}

fn analyze_go(
    context: GoProviderContext<'_>,
    control: &dyn OperationControl,
) -> Result<GoProviderResult, GoProviderError> {
    let mut issues = inventory_issues(context.inventory);
    let mut provenance = vec![Provenance {
        rule_id: String::from("go.inventory.v1"),
        source_path: None,
        source_range: None,
        detail: String::from(
            "Go manifest candidates and formatting inputs come from the bounded repository inventory and Git file set",
        ),
    }];
    let mut units = Vec::new();

    if let Err(error) = control.checkpoint() {
        return Ok(control_stopped_go_result(
            units, provenance, issues, error, None,
        ));
    }

    if !context.repository_root.is_absolute() {
        issues.push(issue(
            GoProviderIssueKind::InvalidRepositoryRoot,
            None,
            "Go detection requires an absolute repository root",
        ));
        return Ok(finalize_result(Vec::new(), Vec::new(), provenance, issues));
    }

    let inventory_kinds = match inventory_kind_map_controlled(context.inventory, control) {
        Ok(kinds) => kinds,
        Err(error) => {
            return Ok(control_stopped_go_result(
                units, provenance, issues, error, None,
            ));
        }
    };
    let (work_manifests, module_manifests) =
        match manifest_candidates_controlled(context.inventory, &mut issues, control) {
            Ok(manifests) => manifests,
            Err(error) => {
                return Ok(control_stopped_go_result(
                    units, provenance, issues, error, None,
                ));
            }
        };
    let mut workspaces = Vec::new();
    for manifest in work_manifests {
        if let Err(error) = control.checkpoint() {
            return Ok(control_stopped_go_result(
                units,
                provenance,
                issues,
                error,
                Some(manifest),
            ));
        }
        let workspace = match inspect_workspace(
            &context,
            &inventory_kinds,
            manifest.clone(),
            &mut issues,
            &mut provenance,
            control,
        ) {
            Ok(workspace) => workspace,
            Err(error) => {
                return Ok(control_stopped_go_result(
                    units,
                    provenance,
                    issues,
                    error,
                    Some(manifest),
                ));
            }
        };
        workspaces.push(workspace);
    }

    mark_ambiguous_workspaces(&mut workspaces, &mut issues);
    if let Err(error) = control.checkpoint() {
        return Ok(control_stopped_go_result(
            units, provenance, issues, error, None,
        ));
    }
    let mut covered_modules = BTreeSet::new();
    for workspace in &workspaces {
        for module in &workspace.modules {
            if let Err(error) = control.checkpoint() {
                return Ok(control_stopped_go_result(
                    units,
                    provenance,
                    issues,
                    error,
                    Some(workspace.manifest.clone()),
                ));
            }
            covered_modules.insert(module.clone());
        }
    }
    let blocked_roots = workspaces
        .iter()
        .filter(|workspace| !workspace.valid)
        .map(|workspace| workspace.root.clone())
        .collect::<Vec<_>>();

    let mut all_module_roots = BTreeSet::new();
    for manifest in &module_manifests {
        if let Err(error) = control.checkpoint() {
            return Ok(control_stopped_go_result(
                units,
                provenance,
                issues,
                error,
                Some(manifest.clone()),
            ));
        }
        if let Some(root) = parent_path(manifest) {
            all_module_roots.insert(root);
        }
    }
    let mut scopes = Vec::new();

    for workspace in workspaces {
        if let Err(error) = control.checkpoint() {
            return Ok(control_stopped_go_result(
                units,
                provenance,
                issues,
                error,
                Some(workspace.manifest),
            ));
        }
        let workspace_identity = unit_identity(context.hasher, "workspace", &workspace.manifest);
        let unit_provenance = vec![manifest_provenance(
            "go.workspace.metadata.v1",
            &workspace.manifest,
            if workspace.valid {
                "go.work metadata and every use target were validated without overlapping ownership"
            } else {
                "go.work was observed but its complete, non-overlapping module ownership was not proven"
            },
        )];
        let member_ids = if workspace.valid {
            workspace
                .modules
                .iter()
                .map(|module| unit_identity(context.hasher, "module", module).into())
                .collect()
        } else {
            Vec::new()
        };
        units.push(ProjectUnit {
            id: workspace_identity.clone().into(),
            display_name: display_path(&workspace.manifest),
            language: PROVIDER_ID.into(),
            kind: ProjectKind::GoWorkspace,
            root: workspace.root.clone(),
            manifest: workspace.manifest.clone(),
            workspace_root: Some(workspace.root.clone()),
            members: member_ids,
            dependencies: Vec::new(),
            toolchain: ToolchainInfo::unknown(unit_provenance.clone()),
            provenance: unit_provenance,
            confidence: if workspace.valid {
                Confidence::High
            } else {
                Confidence::Unknown
            },
        });
        if workspace.valid {
            for module in &workspace.modules {
                if let Err(error) = control.checkpoint() {
                    return Ok(control_stopped_go_result(
                        units,
                        provenance,
                        issues,
                        error,
                        Some(module.clone()),
                    ));
                }
                let Some(module_root) = parent_path(module) else {
                    continue;
                };
                let member_provenance = vec![manifest_provenance(
                    "go.workspace-member.v1",
                    module,
                    "regular go.mod is a validated member of exactly one go.work",
                )];
                units.push(ProjectUnit {
                    id: unit_identity(context.hasher, "module", module).into(),
                    display_name: display_path(module),
                    language: PROVIDER_ID.into(),
                    kind: ProjectKind::GoModule,
                    root: module_root,
                    manifest: module.clone(),
                    workspace_root: Some(workspace.root.clone()),
                    members: Vec::new(),
                    dependencies: Vec::new(),
                    toolchain: ToolchainInfo::unknown(member_provenance.clone()),
                    provenance: member_provenance,
                    confidence: Confidence::High,
                });
            }
            scopes.push(CommandScope {
                unit_identity: workspace_identity,
                manifest: workspace.manifest.clone(),
                // A go.work may legally use modules outside its own directory. Repository-root
                // cwd keeps every gofmt argv repository-confined without introducing `..`.
                root: RepoRelativePath::root(),
                module_roots: workspace.modules.iter().filter_map(parent_path).collect(),
                workspace_manifest: Some(workspace.manifest),
                tracked_go_files: Vec::new(),
                changed_go_files: Vec::new(),
            });
        }
    }

    for manifest in module_manifests {
        if let Err(error) = control.checkpoint() {
            return Ok(control_stopped_go_result(
                units,
                provenance,
                issues,
                error,
                Some(manifest),
            ));
        }
        if covered_modules.contains(&manifest)
            || blocked_roots
                .iter()
                .any(|root| path_is_within(&manifest, root))
        {
            continue;
        }
        if !manifest_is_regular(&context, &inventory_kinds, &manifest, &mut issues) {
            continue;
        }
        let Some(root) = parent_path(&manifest) else {
            issues.push(issue(
                GoProviderIssueKind::InvalidInventoryPath,
                Some(manifest),
                "go.mod did not have a repository-relative parent",
            ));
            continue;
        };
        let unit_identity = unit_identity(context.hasher, "module", &manifest);
        let unit_provenance = vec![manifest_provenance(
            "go.module.inventory.v1",
            &manifest,
            "go.mod is a regular repository file not owned by a validated go.work",
        )];
        units.push(ProjectUnit {
            id: unit_identity.clone().into(),
            display_name: display_path(&manifest),
            language: PROVIDER_ID.into(),
            kind: ProjectKind::GoModule,
            root: root.clone(),
            manifest: manifest.clone(),
            workspace_root: None,
            members: Vec::new(),
            dependencies: Vec::new(),
            toolchain: ToolchainInfo::unknown(unit_provenance.clone()),
            provenance: unit_provenance,
            confidence: Confidence::High,
        });
        scopes.push(CommandScope {
            unit_identity,
            manifest,
            root: root.clone(),
            module_roots: vec![root],
            workspace_manifest: None,
            tracked_go_files: Vec::new(),
            changed_go_files: Vec::new(),
        });
    }

    units.sort_by(|left, right| left.manifest.cmp(&right.manifest));
    scopes.sort_by(|left, right| left.manifest.cmp(&right.manifest));
    if let Err(error) = control.checkpoint() {
        return Ok(control_stopped_go_result(
            units, provenance, issues, error, None,
        ));
    }
    if let Err(error) = assign_tracked_go_files(
        &mut scopes,
        context.git_files,
        &inventory_kinds,
        &all_module_roots,
        control,
    ) {
        return Ok(control_stopped_go_result(
            units, provenance, issues, error, None,
        ));
    }
    let mutation_scope_complete = match assign_changed_go_files(
        &context,
        &mut scopes,
        &inventory_kinds,
        &all_module_roots,
        &mut issues,
        control,
    ) {
        Ok(complete) => complete,
        Err(error) => {
            return Ok(control_stopped_go_result(
                units, provenance, issues, error, None,
            ));
        }
    };
    if let Err(error) = record_conservative_impact(&context, &scopes, &mut issues, control) {
        return Ok(control_stopped_go_result(
            units, provenance, issues, error, None,
        ));
    }

    let complete = issues.iter().all(|issue| !issue.kind.prevents_completion());
    let plans = match build_plans(
        context.repository_root,
        &scopes,
        mutation_scope_complete,
        if complete {
            Confidence::High
        } else {
            Confidence::Unknown
        },
        control,
    ) {
        Ok(plans) => plans,
        Err(GoPlanBuildError::Control(error)) => {
            return Ok(control_stopped_go_result(
                units, provenance, issues, error, None,
            ));
        }
        Err(GoPlanBuildError::Invalid(error)) => {
            return Err(GoProviderError::InvalidCommandPlan(error));
        }
    };
    for scope in &scopes {
        if let Err(error) = control.checkpoint() {
            return Ok(control_stopped_go_result(
                units,
                provenance,
                issues,
                error,
                Some(scope.manifest.clone()),
            ));
        }
        provenance.push(manifest_provenance(
            "go.command-scope.v1",
            &scope.manifest,
            "Go commands use the full validated module scope; unknown impact is widened rather than excluded",
        ));
    }

    let mut result = finalize_result(units, plans, provenance, issues);
    if let Err(error) = control.checkpoint() {
        result.plans.clear();
        result.issues.push(control_issue(error, None));
        result.confidence = Confidence::Unknown;
        result.complete = false;
    }
    Ok(result)
}

fn finalize_result(
    units: Vec<ProjectUnit>,
    plans: Vec<CommandPlanCandidate>,
    mut provenance: Vec<Provenance>,
    mut issues: Vec<GoProviderIssue>,
) -> GoProviderResult {
    provenance.sort();
    provenance.dedup();
    issues.sort();
    issues.dedup();
    let complete = issues.iter().all(|issue| !issue.kind.prevents_completion());
    GoProviderResult {
        units,
        plans,
        provenance,
        issues,
        confidence: if complete {
            Confidence::High
        } else {
            Confidence::Unknown
        },
        complete,
    }
}

fn control_stopped_go_result(
    units: Vec<ProjectUnit>,
    provenance: Vec<Provenance>,
    mut issues: Vec<GoProviderIssue>,
    error: OperationControlError,
    path: Option<RepoRelativePath>,
) -> GoProviderResult {
    issues.push(control_issue(error, path));
    GoProviderResult {
        units,
        plans: Vec::new(),
        provenance,
        issues,
        confidence: Confidence::Unknown,
        complete: false,
    }
}

fn inventory_issues(inventory: &Inventory) -> Vec<GoProviderIssue> {
    inventory
        .skipped
        .iter()
        .map(|skipped| {
            let path = skipped
                .path
                .as_ref()
                .and_then(|path| RepoRelativePath::new(path).ok());
            issue(
                GoProviderIssueKind::InventoryIncomplete,
                path,
                format!("repository inventory skipped input: {}", skipped.reason),
            )
        })
        .collect()
}

fn inventory_kind_map_controlled(
    inventory: &Inventory,
    control: &dyn OperationControl,
) -> Result<BTreeMap<RepoRelativePath, InventoryKind>, OperationControlError> {
    let mut kinds = BTreeMap::new();
    for entry in &inventory.entries {
        control.checkpoint()?;
        if let Ok(path) = RepoRelativePath::new(&entry.path) {
            kinds.insert(path, entry.kind);
        }
    }
    Ok(kinds)
}

fn manifest_candidates_controlled(
    inventory: &Inventory,
    issues: &mut Vec<GoProviderIssue>,
    control: &dyn OperationControl,
) -> Result<(Vec<RepoRelativePath>, Vec<RepoRelativePath>), OperationControlError> {
    let mut work = BTreeSet::new();
    let mut modules = BTreeSet::new();
    for entry in &inventory.entries {
        control.checkpoint()?;
        let Some(file_name) = entry.path.file_name() else {
            continue;
        };
        if file_name != OsStr::new("go.work") && file_name != OsStr::new("go.mod") {
            continue;
        }
        match RepoRelativePath::new(&entry.path) {
            Ok(path) if file_name == OsStr::new("go.work") => {
                work.insert(path);
            }
            Ok(path) => {
                if !contains_component(path.as_path(), OsStr::new("vendor")) {
                    modules.insert(path);
                }
            }
            Err(error) => issues.push(issue(
                GoProviderIssueKind::InvalidInventoryPath,
                None,
                format!("Go manifest candidate is not repository-relative: {error}"),
            )),
        }
    }
    control.checkpoint()?;
    Ok((work.into_iter().collect(), modules.into_iter().collect()))
}

fn inspect_workspace(
    context: &GoProviderContext<'_>,
    inventory_kinds: &BTreeMap<RepoRelativePath, InventoryKind>,
    manifest: RepoRelativePath,
    issues: &mut Vec<GoProviderIssue>,
    provenance: &mut Vec<Provenance>,
    control: &dyn OperationControl,
) -> Result<WorkspaceCandidate, OperationControlError> {
    control.checkpoint()?;
    let root = parent_path(&manifest).unwrap_or_else(RepoRelativePath::root);
    if !manifest_is_regular(context, inventory_kinds, &manifest, issues) {
        return Ok(WorkspaceCandidate {
            manifest,
            root,
            modules: Vec::new(),
            valid: false,
        });
    }
    let Some(metadata) = read_workspace_metadata(context, &manifest, &root, issues, control) else {
        control.checkpoint()?;
        return Ok(WorkspaceCandidate {
            manifest,
            root,
            modules: Vec::new(),
            valid: false,
        });
    };
    control.checkpoint()?;

    let mut modules = Vec::new();
    let mut seen = BTreeSet::new();
    let mut valid = true;
    for use_entry in metadata.uses {
        control.checkpoint()?;
        let module_root = match resolve_use_path(
            context.repository_root,
            &root,
            Path::new(&use_entry.disk_path),
        ) {
            Ok(path) => path,
            Err(detail) => {
                issues.push(issue(
                    GoProviderIssueKind::InvalidUsePath,
                    Some(manifest.clone()),
                    detail,
                ));
                valid = false;
                continue;
            }
        };
        let Some(module_manifest) = join_relative(&module_root, Path::new("go.mod")) else {
            issues.push(issue(
                GoProviderIssueKind::InvalidUsePath,
                Some(module_root),
                "go.work use target could not be joined to go.mod without violating repository-relative path rules",
            ));
            valid = false;
            continue;
        };
        if !seen.insert(module_manifest.clone()) {
            issues.push(issue(
                GoProviderIssueKind::DuplicateWorkspaceMembership,
                Some(manifest.clone()),
                format!(
                    "go.work repeats module use target {}",
                    display_path(&module_manifest)
                ),
            ));
            valid = false;
            continue;
        }
        match context
            .file_system
            .path_kind(context.repository_root, &module_root)
        {
            Ok(PathKind::Directory) => {}
            Ok(_) => {
                issues.push(issue(
                    GoProviderIssueKind::UseTargetNotDirectory,
                    Some(module_root),
                    "go.work use target is not a regular repository directory",
                ));
                valid = false;
                continue;
            }
            Err(error) => {
                issues.push(issue(
                    GoProviderIssueKind::ManifestProbeFailed,
                    Some(module_root),
                    format!("failed to inspect go.work use directory: {error}"),
                ));
                valid = false;
                continue;
            }
        }
        if inventory_kinds.get(&module_manifest) != Some(&InventoryKind::File)
            || !matches!(
                context
                    .file_system
                    .path_kind(context.repository_root, &module_manifest),
                Ok(PathKind::File)
            )
        {
            issues.push(issue(
                GoProviderIssueKind::UseManifestNotRegular,
                Some(module_manifest),
                "go.work use target does not resolve to an inventoried regular go.mod",
            ));
            valid = false;
            continue;
        }
        modules.push(module_manifest);
    }
    control.checkpoint()?;
    modules.sort();
    if module_roots_overlap(&modules) {
        issues.push(issue(
            GoProviderIssueKind::OverlappingWorkspace,
            Some(manifest.clone()),
            "go.work contains nested module roots whose package ownership cannot be treated as one unambiguous scope",
        ));
        valid = false;
    }
    provenance.push(manifest_provenance(
        "go.work.edit-json.v1",
        &manifest,
        "bounded argv-only go work edit metadata was parsed with network and user Go configuration disabled",
    ));
    control.checkpoint()?;
    Ok(WorkspaceCandidate {
        manifest,
        root,
        modules,
        valid,
    })
}

fn manifest_is_regular(
    context: &GoProviderContext<'_>,
    inventory_kinds: &BTreeMap<RepoRelativePath, InventoryKind>,
    manifest: &RepoRelativePath,
    issues: &mut Vec<GoProviderIssue>,
) -> bool {
    if inventory_kinds.get(manifest) != Some(&InventoryKind::File) {
        issues.push(issue(
            GoProviderIssueKind::InvalidManifestKind,
            Some(manifest.clone()),
            "Go manifest candidate is not an inventoried regular file",
        ));
        return false;
    }
    match context
        .file_system
        .path_kind(context.repository_root, manifest)
    {
        Ok(PathKind::File) => true,
        Ok(_) => {
            issues.push(issue(
                GoProviderIssueKind::InvalidManifestKind,
                Some(manifest.clone()),
                "Go manifest changed to a non-regular file or symlink",
            ));
            false
        }
        Err(error) => {
            issues.push(issue(
                GoProviderIssueKind::ManifestProbeFailed,
                Some(manifest.clone()),
                format!("failed to inspect Go manifest: {error}"),
            ));
            false
        }
    }
}

fn read_workspace_metadata(
    context: &GoProviderContext<'_>,
    manifest: &RepoRelativePath,
    root: &RepoRelativePath,
    issues: &mut Vec<GoProviderIssue>,
    control: &dyn OperationControl,
) -> Option<GoWorkMetadata> {
    let permit = match control.checkpoint() {
        Ok(permit) => permit,
        Err(error) => {
            issues.push(control_issue(error, Some(manifest.clone())));
            return None;
        }
    };
    let file_name = manifest.as_path().file_name()?.to_os_string();
    let mut command = CommandSpec::new(
        format!(
            "go.metadata.{}",
            unit_identity(context.hasher, "workspace", manifest)
        ),
        Intent::Check,
        "go",
        root.clone(),
        CommandSource::LanguageDefault {
            provider: String::from(PROVIDER_ID),
            rule: String::from("go-work-edit-json"),
        },
    )
    .with_args([
        OsString::from("work"),
        OsString::from("edit"),
        OsString::from("-json"),
        file_name,
    ]);
    command.timeout = permit.cap(context.metadata_timeout);
    command.mutability = Mutability::ReadOnly;
    command.network = NetworkIntent::OfflineRequested;
    command.confidence = Confidence::High;
    command.env = isolated_go_environment(OsStr::new("off"), true);
    let execution = ExecSpec::from_project_command(&command);
    let observation = match context.process.run(&execution) {
        Ok(observation) => observation,
        Err(error) => {
            issues.push(issue(
                GoProviderIssueKind::MetadataUnavailable,
                Some(manifest.clone()),
                format!(
                    "go work metadata process could not start ({:?}): {error}",
                    error.kind()
                ),
            ));
            return None;
        }
    };
    if observation.timed_out {
        issues.push(issue(
            GoProviderIssueKind::MetadataTimedOut,
            Some(manifest.clone()),
            "go work edit metadata exceeded its configured timeout",
        ));
        return None;
    }
    if observation.interrupted {
        issues.push(issue(
            GoProviderIssueKind::MetadataInterrupted,
            Some(manifest.clone()),
            "go work edit metadata was interrupted",
        ));
        return None;
    }
    if observation.stdout_truncated || observation.stderr_truncated {
        issues.push(issue(
            GoProviderIssueKind::MetadataOutputLimit,
            Some(manifest.clone()),
            format!(
                "go work edit metadata exceeded a bounded stream (stdout {}, stderr {} bytes)",
                observation.stdout_total_bytes, observation.stderr_total_bytes
            ),
        ));
        return None;
    }
    if observation.exit_code != Some(0) {
        issues.push(issue(
            GoProviderIssueKind::MetadataCommandFailed,
            Some(manifest.clone()),
            format!(
                "go work edit metadata exited with code {:?} and signal {:?}",
                observation.exit_code, observation.signal
            ),
        ));
        return None;
    }
    match serde_json::from_slice(&observation.stdout) {
        Ok(metadata) => Some(metadata),
        Err(error) => {
            issues.push(issue(
                GoProviderIssueKind::MetadataInvalid,
                Some(manifest.clone()),
                format!("go work edit returned invalid JSON metadata: {error}"),
            ));
            None
        }
    }
}

fn control_issue(error: OperationControlError, path: Option<RepoRelativePath>) -> GoProviderIssue {
    issue(
        match error {
            OperationControlError::TimedOut => GoProviderIssueKind::MetadataTimedOut,
            OperationControlError::Interrupted => GoProviderIssueKind::MetadataInterrupted,
        },
        path,
        error.to_string(),
    )
}

fn mark_ambiguous_workspaces(
    workspaces: &mut [WorkspaceCandidate],
    issues: &mut Vec<GoProviderIssue>,
) {
    let mut memberships = BTreeMap::<RepoRelativePath, Vec<usize>>::new();
    for (index, workspace) in workspaces.iter().enumerate() {
        for module in &workspace.modules {
            memberships.entry(module.clone()).or_default().push(index);
        }
    }
    for (module, owners) in memberships {
        if owners.len() <= 1 {
            continue;
        }
        for owner in &owners {
            workspaces[*owner].valid = false;
        }
        issues.push(issue(
            GoProviderIssueKind::DuplicateWorkspaceMembership,
            Some(module),
            "one go.mod is referenced by more than one go.work",
        ));
    }
    for left in 0..workspaces.len() {
        for right in (left + 1)..workspaces.len() {
            if path_is_within(&workspaces[left].root, &workspaces[right].root)
                || path_is_within(&workspaces[right].root, &workspaces[left].root)
            {
                workspaces[left].valid = false;
                workspaces[right].valid = false;
                issues.push(issue(
                    GoProviderIssueKind::OverlappingWorkspace,
                    Some(workspaces[right].manifest.clone()),
                    format!(
                        "workspace root overlaps {}",
                        display_path(&workspaces[left].manifest)
                    ),
                ));
            }
        }
    }
}

fn assign_tracked_go_files(
    scopes: &mut [CommandScope],
    git_files: &GitFileSet,
    inventory_kinds: &BTreeMap<RepoRelativePath, InventoryKind>,
    all_module_roots: &BTreeSet<RepoRelativePath>,
    control: &dyn OperationControl,
) -> Result<(), OperationControlError> {
    for scope in scopes {
        control.checkpoint()?;
        let mut tracked = Vec::new();
        for path in &git_files.tracked {
            control.checkpoint()?;
            if is_go_source(path)
                && inventory_kinds.get(path) == Some(&InventoryKind::File)
                && scope
                    .module_roots
                    .iter()
                    .any(|module_root| belongs_to_module(path, module_root, all_module_roots))
                && !scope.module_roots.iter().any(|root| {
                    relative_to(path, root)
                        .is_some_and(|relative| contains_component(&relative, OsStr::new("vendor")))
                })
            {
                tracked.push(path.clone());
            }
        }
        control.checkpoint()?;
        tracked.sort();
        tracked.dedup();
        scope.tracked_go_files = tracked;
    }
    control.checkpoint()?;
    Ok(())
}

fn assign_changed_go_files(
    context: &GoProviderContext<'_>,
    scopes: &mut [CommandScope],
    inventory_kinds: &BTreeMap<RepoRelativePath, InventoryKind>,
    all_module_roots: &BTreeSet<RepoRelativePath>,
    issues: &mut Vec<GoProviderIssue>,
    control: &dyn OperationControl,
) -> Result<bool, OperationControlError> {
    control.checkpoint()?;
    let Some(changed_files) = context.changed_files else {
        if !scopes.is_empty() {
            issues.push(issue(
                GoProviderIssueKind::ChangedScopeUnavailable,
                None,
                "typed Git status did not provide a complete changed-path set; mutating Go format plans were omitted",
            ));
        }
        return Ok(false);
    };
    let mut authoritative = BTreeSet::new();
    for path in context
        .git_files
        .tracked
        .iter()
        .chain(&context.git_files.untracked)
    {
        control.checkpoint()?;
        authoritative.insert(path.clone());
    }
    let mut complete = true;
    for changed in changed_files {
        control.checkpoint()?;
        if !authoritative.contains(changed) {
            issues.push(issue(
                GoProviderIssueKind::ChangedPathUnknown,
                Some(changed.clone()),
                "changed path was not present in the Git-authoritative file set; Go impact remains full-unit",
            ));
            complete = false;
            continue;
        }
        if !is_go_source(changed) {
            continue;
        }
        let Some(scope) = scopes.iter_mut().find(|scope| {
            scope.module_roots.iter().any(|module_root| {
                belongs_to_module(changed, module_root, all_module_roots)
                    && relative_to(changed, module_root).is_some_and(|relative| {
                        !contains_component(&relative, OsStr::new("vendor"))
                    })
            })
        }) else {
            issues.push(issue(
                GoProviderIssueKind::ChangedPathUnknown,
                Some(changed.clone()),
                "changed Go file could not be mapped to one validated module; test scope remains conservatively broad",
            ));
            complete = false;
            continue;
        };
        if inventory_kinds.get(changed) != Some(&InventoryKind::File) {
            if inventory_kinds.get(changed).is_none() {
                continue;
            }
            issues.push(issue(
                GoProviderIssueKind::GeneratedStatusUnknown,
                Some(changed.clone()),
                "changed Go path is not a regular inventoried file; all mutating Go format plans were omitted",
            ));
            complete = false;
            continue;
        }
        match context
            .file_system
            .path_kind(context.repository_root, changed)
        {
            Ok(PathKind::File) => {}
            Ok(PathKind::Missing) => continue,
            Ok(_) => {
                issues.push(issue(
                    GoProviderIssueKind::GeneratedStatusUnknown,
                    Some(changed.clone()),
                    "changed Go path became a non-regular file or symlink; all mutating Go format plans were omitted",
                ));
                complete = false;
                continue;
            }
            Err(error) => {
                issues.push(issue(
                    GoProviderIssueKind::GeneratedStatusUnknown,
                    Some(changed.clone()),
                    format!(
                        "failed to verify changed Go path before building a mutating plan: {error}"
                    ),
                ));
                complete = false;
                continue;
            }
        }
        control.checkpoint()?;
        let text = match context.file_system.read_bounded_text(
            context.repository_root,
            changed,
            MAX_GENERATED_SCAN_BYTES,
        ) {
            Ok(text) if !text.truncated && !text.binary => text,
            Ok(_) => {
                issues.push(issue(
                    GoProviderIssueKind::GeneratedStatusUnknown,
                    Some(changed.clone()),
                    "changed Go file could not be classified for the generated-code marker within the bounded text policy",
                ));
                complete = false;
                continue;
            }
            Err(error) => {
                issues.push(issue(
                    GoProviderIssueKind::GeneratedStatusUnknown,
                    Some(changed.clone()),
                    format!("failed to inspect changed Go file for generated-code marker: {error}"),
                ));
                complete = false;
                continue;
            }
        };
        control.checkpoint()?;
        if !has_standard_generated_marker(&text.bytes) {
            scope.changed_go_files.push(changed.clone());
        }
    }
    for scope in scopes {
        control.checkpoint()?;
        scope.changed_go_files.sort();
        scope.changed_go_files.dedup();
    }
    control.checkpoint()?;
    Ok(complete)
}

fn record_conservative_impact(
    context: &GoProviderContext<'_>,
    scopes: &[CommandScope],
    issues: &mut Vec<GoProviderIssue>,
    control: &dyn OperationControl,
) -> Result<(), OperationControlError> {
    control.checkpoint()?;
    let Some(changed_files) = context.changed_files else {
        return Ok(());
    };
    let mut changed_non_go = Vec::new();
    for path in changed_files {
        control.checkpoint()?;
        if !is_go_source(path) {
            changed_non_go.push(path);
        }
    }
    if changed_non_go.is_empty() {
        return Ok(());
    }
    let mut has_unmapped_change = false;
    for path in &changed_non_go {
        control.checkpoint()?;
        let mut mapped = false;
        for scope in scopes {
            control.checkpoint()?;
            if scope
                .module_roots
                .iter()
                .any(|root| path_is_within(path, root))
            {
                mapped = true;
                break;
            }
        }
        if !mapped {
            has_unmapped_change = true;
            break;
        }
    }
    for scope in scopes {
        control.checkpoint()?;
        let relevant_change = has_unmapped_change
            || changed_non_go.iter().any(|path| {
                scope
                    .module_roots
                    .iter()
                    .any(|root| path_is_within(path, root))
            });
        if !relevant_change {
            continue;
        }
        let mut embed_observed = false;
        for path in &scope.tracked_go_files {
            control.checkpoint()?;
            if context
                .file_system
                .read_bounded_text(context.repository_root, path, MAX_GENERATED_SCAN_BYTES)
                .ok()
                .is_some_and(|text| bytes_contains(&text.bytes, b"//go:embed"))
            {
                embed_observed = true;
                break;
            }
        }
        issues.push(issue(
            GoProviderIssueKind::ImpactScopeBroadened,
            Some(scope.manifest.clone()),
            if embed_observed {
                "a non-Go change may affect //go:embed; test and vet remain widened to the complete module scope"
            } else {
                "a non-Go change was not mapped with an AST/package graph; test and vet remain widened to the complete module scope"
            },
        ));
    }
    control.checkpoint()?;
    Ok(())
}

#[derive(Debug)]
enum GoPlanBuildError {
    Control(OperationControlError),
    Invalid(InvalidCommandPlanCandidate),
}

impl From<OperationControlError> for GoPlanBuildError {
    fn from(error: OperationControlError) -> Self {
        Self::Control(error)
    }
}

impl From<InvalidCommandPlanCandidate> for GoPlanBuildError {
    fn from(error: InvalidCommandPlanCandidate) -> Self {
        Self::Invalid(error)
    }
}

fn build_plans(
    repository_root: &Path,
    scopes: &[CommandScope],
    mutation_scope_complete: bool,
    coverage_confidence: Confidence,
    control: &dyn OperationControl,
) -> Result<Vec<CommandPlanCandidate>, GoPlanBuildError> {
    let mut commands = BTreeMap::<Intent, Vec<CommandSpec>>::new();
    let mut plan_provenance = Vec::new();
    for scope in scopes {
        control.checkpoint()?;
        plan_provenance.push(manifest_provenance(
            "go.default-command.v1",
            &scope.manifest,
            "Forge derived bounded argv-only gofmt, go test, and advisory go vet commands for this validated Go scope",
        ));
        let format_check = format_commands(
            repository_root,
            scope,
            Intent::FormatCheck,
            "format-check",
            "-l",
            &scope.tracked_go_files,
            Mutability::ReadOnly,
        );
        control.checkpoint()?;
        commands
            .entry(Intent::FormatCheck)
            .or_default()
            .extend(format_check.clone());
        commands
            .entry(Intent::Check)
            .or_default()
            .extend(retarget_commands(
                &format_check,
                Intent::Check,
                "check-format",
            ));
        commands
            .entry(Intent::Verify)
            .or_default()
            .extend(retarget_commands(
                &format_check,
                Intent::Verify,
                "verify-format",
            ));

        let tests = go_module_commands(repository_root, scope, Intent::Test, "test", false);
        control.checkpoint()?;
        commands
            .entry(Intent::Test)
            .or_default()
            .extend(tests.clone());
        commands
            .entry(Intent::Check)
            .or_default()
            .extend(retarget_commands(&tests, Intent::Check, "check-test"));
        commands
            .entry(Intent::Verify)
            .or_default()
            .extend(retarget_commands(&tests, Intent::Verify, "verify-test"));

        let vet = go_module_commands(repository_root, scope, Intent::Verify, "vet", true);
        control.checkpoint()?;
        commands
            .entry(Intent::Check)
            .or_default()
            .extend(retarget_commands(&vet, Intent::Check, "check-vet"));
        commands.entry(Intent::Verify).or_default().extend(vet);

        if mutation_scope_complete {
            let format = format_commands(
                repository_root,
                scope,
                Intent::Format,
                "format",
                "-w",
                &scope.changed_go_files,
                Mutability::WorkingTreeWrite,
            );
            control.checkpoint()?;
            commands
                .entry(Intent::Format)
                .or_default()
                .extend(format.clone());
            commands
                .entry(Intent::Fix)
                .or_default()
                .extend(retarget_commands(&format, Intent::Fix, "fix-format"));
        }
    }

    let mut plans = Vec::new();
    for intent in Intent::ALL {
        control.checkpoint()?;
        let Some(intent_commands) = commands.remove(&intent) else {
            continue;
        };
        if intent_commands.is_empty() {
            continue;
        }
        plans.push(CommandPlanCandidate::new(
            intent_commands,
            plan_provenance.clone(),
            coverage_confidence,
        )?);
    }
    control.checkpoint()?;
    Ok(plans)
}

fn format_commands(
    repository_root: &Path,
    scope: &CommandScope,
    intent: Intent,
    id_action: &str,
    flag: &str,
    files: &[RepoRelativePath],
    mutability: Mutability,
) -> Vec<CommandSpec> {
    let arguments = files
        .iter()
        .filter_map(|path| relative_to(path, &scope.root))
        .map(PathBuf::into_os_string)
        .collect::<Vec<_>>();
    batch_arguments(arguments)
        .into_iter()
        .enumerate()
        .map(|(index, batch)| {
            let mut args = Vec::with_capacity(batch.len() + 1);
            args.push(OsString::from(flag));
            args.extend(batch);
            let mut command = CommandSpec::new(
                format!("go.{id_action}.{}.{}", scope.unit_identity, index + 1),
                intent,
                "gofmt",
                scope.root.clone(),
                CommandSource::LanguageDefault {
                    provider: String::from(PROVIDER_ID),
                    rule: format!("gofmt-{id_action}"),
                },
            )
            .with_args(args);
            command.env = command_environment(scope, Some(repository_root));
            command.mutability = mutability;
            command.network = NetworkIntent::OfflineRequested;
            command.confidence = Confidence::High;
            command.success = if flag == "-l" {
                SuccessPredicate::ExitZeroAndStdoutEmpty
            } else {
                SuccessPredicate::ExitZero
            };
            command.coverage.insert(CoverageDimension::Format);
            command
        })
        .collect()
}

fn go_module_commands(
    repository_root: &Path,
    scope: &CommandScope,
    intent: Intent,
    action: &str,
    advisory: bool,
) -> Vec<CommandSpec> {
    scope
        .module_roots
        .iter()
        .enumerate()
        .map(|(module_index, module_root)| {
            let (subcommand, args): (&str, &[&str]) = if action == "vet" {
                ("vet", &["-json", "./..."])
            } else {
                ("test", &["-json", "./..."])
            };
            let mut command = CommandSpec::new(
                format!("go.{action}.{}.{}", scope.unit_identity, module_index + 1),
                intent,
                "go",
                module_root.clone(),
                CommandSource::LanguageDefault {
                    provider: String::from(PROVIDER_ID),
                    rule: format!("go-{action}-full-module"),
                },
            )
            .with_args(std::iter::once(subcommand).chain(args.iter().copied()));
            command.env = command_environment(scope, Some(repository_root));
            // Test executes project code, while vet traverses project-controlled build inputs.
            // Keep both behind the external-side-effect authorization boundary.
            command.mutability = Mutability::ExternalSideEffect;
            command.network = NetworkIntent::Inherit;
            command.enforcement = if advisory {
                CommandEnforcement::Advisory
            } else {
                CommandEnforcement::Required
            };
            command.confidence = Confidence::High;
            if advisory {
                command.coverage.insert(CoverageDimension::Lint);
            } else {
                command.coverage.insert(CoverageDimension::UnitTest);
                command.coverage.insert(CoverageDimension::IntegrationTest);
            }
            command
        })
        .collect()
}

fn retarget_commands(
    commands: &[CommandSpec],
    intent: Intent,
    id_action: &str,
) -> Vec<CommandSpec> {
    commands
        .iter()
        .enumerate()
        .map(|(index, command)| {
            let mut command = command.clone();
            command.intent = intent;
            command.id = format!("go.{id_action}.{}.{}", command.id.as_str(), index + 1).into();
            command
        })
        .collect()
}

fn command_environment(
    scope: &CommandScope,
    repository_root: Option<&Path>,
) -> BTreeMap<OsString, OsString> {
    let gowork = match (&scope.workspace_manifest, repository_root) {
        (Some(manifest), Some(root)) => root.join(manifest.as_path()).into_os_string(),
        (Some(_), None) => OsString::from("off"),
        (None, _) => OsString::from("off"),
    };
    isolated_go_environment(&gowork, false)
}

fn isolated_go_environment(gowork: &OsStr, metadata_offline: bool) -> BTreeMap<OsString, OsString> {
    let mut environment = BTreeMap::from([
        (OsString::from("GOWORK"), gowork.to_os_string()),
        (OsString::from("GOENV"), OsString::from("off")),
        (OsString::from("GOTOOLCHAIN"), OsString::from("local")),
        (OsString::from("GOFLAGS"), OsString::new()),
    ]);
    if metadata_offline {
        environment.insert(OsString::from("GOPROXY"), OsString::from("off"));
        environment.insert(OsString::from("GOSUMDB"), OsString::from("off"));
    }
    environment
}

fn batch_arguments(arguments: Vec<OsString>) -> Vec<Vec<OsString>> {
    let mut batches = Vec::new();
    let mut current = Vec::new();
    let mut current_bytes = 0_usize;
    for argument in arguments {
        let bytes = native_argument_bytes(&argument).saturating_add(1);
        if !current.is_empty()
            && (current.len() >= MAX_FORMAT_BATCH_FILES
                || current_bytes.saturating_add(bytes) > MAX_FORMAT_BATCH_ARG_BYTES)
        {
            batches.push(std::mem::take(&mut current));
            current_bytes = 0;
        }
        current_bytes = current_bytes.saturating_add(bytes);
        current.push(argument);
    }
    if !current.is_empty() {
        batches.push(current);
    }
    batches
}

#[cfg(unix)]
fn native_argument_bytes(argument: &OsStr) -> usize {
    use std::os::unix::ffi::OsStrExt as _;
    argument.as_bytes().len()
}

#[cfg(windows)]
fn native_argument_bytes(argument: &OsStr) -> usize {
    use std::os::windows::ffi::OsStrExt as _;
    argument.encode_wide().count().saturating_mul(2)
}

#[cfg(not(any(unix, windows)))]
fn native_argument_bytes(argument: &OsStr) -> usize {
    argument.to_string_lossy().len()
}

fn resolve_use_path(
    repository_root: &Path,
    work_root: &RepoRelativePath,
    disk_path: &Path,
) -> Result<RepoRelativePath, String> {
    let (base, path) = if disk_path.is_absolute() {
        let relative = disk_path.strip_prefix(repository_root).map_err(|_| {
            String::from("absolute go.work use target is outside the repository root")
        })?;
        (Path::new("."), relative)
    } else {
        (work_root.as_path(), disk_path)
    };
    let mut normalized = Vec::<OsString>::new();
    for component in base.components().chain(path.components()) {
        match component {
            Component::CurDir => {}
            Component::Normal(value) => normalized.push(value.to_os_string()),
            Component::ParentDir => {
                if normalized.pop().is_none() {
                    return Err(String::from(
                        "relative go.work use target escapes the repository root",
                    ));
                }
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(String::from(
                    "go.work use target could not be normalized as a repository-relative path",
                ));
            }
        }
    }
    let path = normalized.iter().collect::<PathBuf>();
    RepoRelativePath::new(path).map_err(|error| error.to_string())
}

fn module_roots_overlap(modules: &[RepoRelativePath]) -> bool {
    let roots = modules.iter().filter_map(parent_path).collect::<Vec<_>>();
    roots.iter().enumerate().any(|(left_index, left)| {
        roots
            .iter()
            .skip(left_index + 1)
            .any(|right| path_is_within(left, right) || path_is_within(right, left))
    })
}

fn belongs_to_module(
    path: &RepoRelativePath,
    module_root: &RepoRelativePath,
    all_module_roots: &BTreeSet<RepoRelativePath>,
) -> bool {
    if !path_is_within(path, module_root) {
        return false;
    }
    !all_module_roots.iter().any(|other| {
        other != module_root && path_is_within(path, other) && path_is_within(other, module_root)
    })
}

fn path_is_within(path: &RepoRelativePath, root: &RepoRelativePath) -> bool {
    relative_to(path, root).is_some()
}

fn relative_to(path: &RepoRelativePath, root: &RepoRelativePath) -> Option<PathBuf> {
    if root.as_path() == Path::new(".") {
        return Some(path.as_path().to_path_buf());
    }
    path.as_path()
        .strip_prefix(root.as_path())
        .ok()
        .and_then(|path| {
            if path.as_os_str().is_empty() {
                None
            } else {
                Some(path.to_path_buf())
            }
        })
}

fn parent_path(path: &RepoRelativePath) -> Option<RepoRelativePath> {
    let parent = path.as_path().parent().unwrap_or_else(|| Path::new("."));
    RepoRelativePath::new(parent).ok()
}

fn join_relative(root: &RepoRelativePath, suffix: &Path) -> Option<RepoRelativePath> {
    RepoRelativePath::new(root.as_path().join(suffix)).ok()
}

fn is_go_source(path: &RepoRelativePath) -> bool {
    path.as_path().extension() == Some(OsStr::new("go"))
}

fn contains_component(path: &Path, component: &OsStr) -> bool {
    path.components()
        .any(|candidate| matches!(candidate, Component::Normal(value) if value == component))
}

fn has_standard_generated_marker(bytes: &[u8]) -> bool {
    bytes.split(|byte| *byte == b'\n').any(|line| {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        line.starts_with(b"// Code generated ") && line.ends_with(b" DO NOT EDIT.")
    })
}

fn bytes_contains(bytes: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && bytes.windows(needle.len()).any(|window| window == needle)
}

fn unit_identity(hasher: &dyn Hasher, kind: &str, path: &RepoRelativePath) -> String {
    let (encoding, bytes) = native_path_bytes(path.as_path().as_os_str());
    let digest = hasher.digest(&[b"forge.unit-id/go/v1", kind.as_bytes(), encoding, &bytes]);
    format!("go:{}", digest.as_str())
}

#[cfg(unix)]
fn native_path_bytes(path: &OsStr) -> (&'static [u8], Vec<u8>) {
    use std::os::unix::ffi::OsStrExt as _;
    (b"unix-bytes", path.as_bytes().to_vec())
}

#[cfg(windows)]
fn native_path_bytes(path: &OsStr) -> (&'static [u8], Vec<u8>) {
    use std::os::windows::ffi::OsStrExt as _;
    let bytes = path
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    (b"windows-wide", bytes)
}

#[cfg(not(any(unix, windows)))]
fn native_path_bytes(path: &OsStr) -> (&'static [u8], Vec<u8>) {
    (b"utf8-lossy", path.to_string_lossy().as_bytes().to_vec())
}

fn manifest_provenance(rule_id: &str, path: &RepoRelativePath, detail: &str) -> Provenance {
    Provenance {
        rule_id: String::from(rule_id),
        source_path: Some(path.as_path().into()),
        source_range: None,
        detail: String::from(detail),
    }
}

fn issue(
    kind: GoProviderIssueKind,
    path: Option<RepoRelativePath>,
    detail: impl Into<String>,
) -> GoProviderIssue {
    GoProviderIssue {
        kind,
        path,
        detail: detail.into(),
    }
}

fn display_path(path: &RepoRelativePath) -> String {
    path.as_path().to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::{BTreeMap, BTreeSet, VecDeque};
    use std::error::Error;
    use std::ffi::{OsStr, OsString};
    use std::io;
    use std::path::{Path, PathBuf};
    use std::rc::Rc;
    use std::time::Duration;

    use forge_core::ports::{
        ExecSpec, FileSystemPort, Hasher, ProcessError, ProcessErrorKind, ProcessObservation,
        ProcessPort,
    };
    use forge_core::{
        BoundedText, Confidence, Digest, GitFileSet, Intent, Inventory, InventoryEntry,
        InventoryError, InventoryKind, InventoryOptions, InventorySkip, Mutability,
        OperationControl, OperationControlError, OperationPermit, PathKind, ProjectKind,
        RepoRelativePath,
    };

    use super::{
        GoProvider, GoProviderContext, GoProviderIssueKind, MAX_FORMAT_BATCH_FILES, batch_arguments,
    };

    #[derive(Debug)]
    struct FakeFileSystem {
        inventory: Inventory,
        kinds: BTreeMap<RepoRelativePath, PathKind>,
        texts: BTreeMap<RepoRelativePath, BoundedText>,
        writes: Cell<usize>,
    }

    impl FakeFileSystem {
        fn new(inventory: Inventory) -> Self {
            let mut kinds = BTreeMap::from([(RepoRelativePath::root(), PathKind::Directory)]);
            for entry in &inventory.entries {
                if let Ok(path) = RepoRelativePath::new(&entry.path) {
                    let kind = match entry.kind {
                        InventoryKind::Directory => PathKind::Directory,
                        InventoryKind::File => PathKind::File,
                        InventoryKind::Symlink => PathKind::Symlink,
                        InventoryKind::Other => PathKind::Other,
                    };
                    kinds.insert(path, kind);
                }
            }
            Self {
                inventory,
                kinds,
                texts: BTreeMap::new(),
                writes: Cell::new(0),
            }
        }

        fn with_text(mut self, path: &str, bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
            self.texts.insert(
                RepoRelativePath::new(path)?,
                BoundedText {
                    bytes: bytes.to_vec(),
                    truncated: false,
                    binary: false,
                },
            );
            Ok(self)
        }

        fn set_kind(&mut self, path: &str, kind: PathKind) -> Result<(), Box<dyn Error>> {
            self.kinds.insert(RepoRelativePath::new(path)?, kind);
            Ok(())
        }
    }

    impl FileSystemPort for FakeFileSystem {
        fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("unexpected unbounded read: {}", path.display()),
            ))
        }

        fn inventory(
            &self,
            _root: &Path,
            _file_set: Option<&GitFileSet>,
            _options: InventoryOptions,
        ) -> Result<Inventory, InventoryError> {
            Ok(self.inventory.clone())
        }

        fn read_bounded_text(
            &self,
            root: &Path,
            path: &RepoRelativePath,
            _max_text_file_bytes: u64,
        ) -> Result<BoundedText, InventoryError> {
            if let Some(text) = self.texts.get(path) {
                return Ok(text.clone());
            }
            if self.kinds.get(path) == Some(&PathKind::File) {
                return Ok(BoundedText {
                    bytes: Vec::new(),
                    truncated: false,
                    binary: false,
                });
            }
            Err(InventoryError::Io {
                path: root.join(path.as_path()),
                source: io::Error::new(io::ErrorKind::NotFound, "fixture path is missing"),
            })
        }

        fn path_kind(&self, _root: &Path, path: &RepoRelativePath) -> io::Result<PathKind> {
            Ok(self.kinds.get(path).copied().unwrap_or(PathKind::Missing))
        }

        fn write_atomic(&self, _path: &Path, _bytes: &[u8]) -> io::Result<()> {
            self.writes.set(self.writes.get() + 1);
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Go detection must not write",
            ))
        }

        fn exists(&self, path: &Path) -> bool {
            RepoRelativePath::new(path)
                .ok()
                .is_some_and(|path| self.kinds.contains_key(&path))
        }
    }

    #[derive(Debug, Default)]
    struct FakeProcess {
        responses: RefCell<VecDeque<ProcessObservation>>,
        calls: RefCell<Vec<ExecSpec>>,
        stop_after_run: Option<Rc<Cell<bool>>>,
    }

    impl FakeProcess {
        fn with_responses(responses: Vec<ProcessObservation>) -> Self {
            Self {
                responses: RefCell::new(responses.into()),
                calls: RefCell::new(Vec::new()),
                stop_after_run: None,
            }
        }

        fn with_stop_after_run(mut self, stop: Rc<Cell<bool>>) -> Self {
            self.stop_after_run = Some(stop);
            self
        }
    }

    impl ProcessPort for FakeProcess {
        fn run(&self, spec: &ExecSpec) -> Result<ProcessObservation, ProcessError> {
            self.calls.borrow_mut().push(spec.clone());
            let result = self.responses.borrow_mut().pop_front().ok_or_else(|| {
                ProcessError::new(
                    ProcessErrorKind::Spawn,
                    "fixture process response",
                    io::Error::other("unexpected process execution"),
                )
            });
            if let Some(stop) = &self.stop_after_run {
                stop.set(true);
            }
            result
        }
    }

    struct EventControl {
        stop: Rc<Cell<bool>>,
        error: OperationControlError,
    }

    impl OperationControl for EventControl {
        fn checkpoint(&self) -> Result<OperationPermit, OperationControlError> {
            if self.stop.get() {
                Err(self.error)
            } else {
                Ok(OperationPermit::unlimited())
            }
        }
    }

    #[derive(Debug, Default)]
    struct FakeHasher;

    impl Hasher for FakeHasher {
        fn digest(&self, chunks: &[&[u8]]) -> Digest {
            let mut state = 0xcbf2_9ce4_8422_2325_u64;
            for chunk in chunks {
                state ^= chunk.len() as u64;
                state = state.wrapping_mul(0x100_0000_01b3);
                for byte in *chunk {
                    state ^= u64::from(*byte);
                    state = state.wrapping_mul(0x100_0000_01b3);
                }
            }
            Digest::new(format!("fixture:{state:016x}"))
        }
    }

    fn inventory(entries: &[(&str, InventoryKind)]) -> Inventory {
        Inventory {
            entries: entries
                .iter()
                .map(|(path, kind)| InventoryEntry {
                    path: PathBuf::from(path),
                    kind: *kind,
                    size_bytes: Some(if *kind == InventoryKind::File { 1 } else { 0 }),
                })
                .collect(),
            skipped: Vec::new(),
        }
    }

    fn git_files(tracked: &[&str], untracked: &[&str]) -> Result<GitFileSet, Box<dyn Error>> {
        Ok(GitFileSet {
            tracked: tracked
                .iter()
                .map(RepoRelativePath::new)
                .collect::<Result<_, _>>()?,
            untracked: untracked
                .iter()
                .map(RepoRelativePath::new)
                .collect::<Result<_, _>>()?,
        })
    }

    fn paths(values: &[&str]) -> Result<Vec<RepoRelativePath>, Box<dyn Error>> {
        values
            .iter()
            .map(RepoRelativePath::new)
            .collect::<Result<_, _>>()
            .map_err(Into::into)
    }

    /// Opaque placeholder: these Go-provider tests do not consume process-output digests.
    fn ignored_process_digest(stream: &str) -> Digest {
        Digest::new(format!("fixture:non-canonical-go-{stream}"))
    }

    fn observation(stdout: &[u8]) -> ProcessObservation {
        ProcessObservation {
            exit_code: Some(0),
            signal: None,
            stdout: stdout.to_vec(),
            stderr: Vec::new(),
            stdout_digest: ignored_process_digest("stdout"),
            stderr_digest: ignored_process_digest("stderr"),
            stdout_total_bytes: stdout.len() as u64,
            stderr_total_bytes: 0,
            stdout_truncated: false,
            stderr_truncated: false,
            duration: Duration::from_millis(1),
            timed_out: false,
            interrupted: false,
        }
    }

    fn plan(
        result: &super::GoProviderResult,
        intent: Intent,
    ) -> Result<&crate::resolution::CommandPlanCandidate, Box<dyn Error>> {
        result
            .plans
            .iter()
            .find(|plan| plan.intent() == intent)
            .ok_or_else(|| io::Error::other(format!("missing {intent:?} plan")).into())
    }

    #[test]
    fn control_event_after_first_workspace_prevents_later_workspace_work()
    -> Result<(), Box<dyn Error>> {
        let repository = inventory(&[
            ("a/go.work", InventoryKind::File),
            ("b/go.work", InventoryKind::File),
        ]);
        let file_system = FakeFileSystem::new(repository.clone());
        let git = git_files(&["a/go.work", "b/go.work"], &[])?;
        let stop = Rc::new(Cell::new(false));
        let process = FakeProcess::with_responses(vec![
            observation(br#"{"Use":[]}"#),
            observation(br#"{"Use":[]}"#),
        ])
        .with_stop_after_run(Rc::clone(&stop));
        let control = EventControl {
            stop,
            error: OperationControlError::Interrupted,
        };

        let result = GoProvider.analyze_controlled(
            GoProviderContext {
                repository_root: Path::new("/repo"),
                inventory: &repository,
                git_files: &git,
                changed_files: None,
                file_system: &file_system,
                process: &process,
                hasher: &FakeHasher,
                metadata_timeout: Duration::from_secs(2),
            },
            &control,
        )?;

        assert_eq!(process.calls.borrow().len(), 1);
        assert!(result.units.is_empty());
        assert!(result.plans.is_empty());
        assert!(!result.complete);
        assert!(result.issues.iter().any(|issue| {
            issue.kind == GoProviderIssueKind::MetadataInterrupted
                && issue
                    .path
                    .as_ref()
                    .is_some_and(|path| path.as_path() == Path::new("a/go.work"))
        }));
        Ok(())
    }

    #[test]
    fn single_module_plans_are_bounded_ordered_and_generated_safe() -> Result<(), Box<dyn Error>> {
        let repository = inventory(&[
            ("go.mod", InventoryKind::File),
            ("main.go", InventoryKind::File),
            ("generated.go", InventoryKind::File),
            ("asset.txt", InventoryKind::File),
            ("vendor", InventoryKind::Directory),
            ("vendor/ignored.go", InventoryKind::File),
        ]);
        let file_system = FakeFileSystem::new(repository.clone())
            .with_text("main.go", b"package main\n")?
            .with_text(
                "generated.go",
                b"// Code generated by fixture. DO NOT EDIT.\npackage main\n",
            )?;
        let git = git_files(
            &[
                "go.mod",
                "main.go",
                "generated.go",
                "asset.txt",
                "vendor/ignored.go",
            ],
            &[],
        )?;
        let changed = paths(&["main.go", "generated.go", "asset.txt"])?;
        let process = FakeProcess::default();
        let result = GoProvider.analyze(GoProviderContext {
            repository_root: Path::new("/repo"),
            inventory: &repository,
            git_files: &git,
            changed_files: Some(&changed),
            file_system: &file_system,
            process: &process,
            hasher: &FakeHasher,
            metadata_timeout: Duration::from_secs(2),
        })?;

        assert_eq!(result.units.len(), 1);
        assert_eq!(result.units[0].kind, ProjectKind::GoModule);
        assert!(process.calls.borrow().is_empty());
        assert_eq!(file_system.writes.get(), 0);
        assert!(
            !result
                .plans
                .iter()
                .any(|plan| { matches!(plan.intent(), Intent::Setup | Intent::Build) })
        );

        let format_check = plan(&result, Intent::FormatCheck)?;
        assert_eq!(format_check.commands().len(), 1);
        assert_eq!(
            format_check.commands()[0].args,
            ["-l", "generated.go", "main.go"].map(OsString::from)
        );
        assert_eq!(format_check.commands()[0].mutability, Mutability::ReadOnly);
        let format = plan(&result, Intent::Format)?;
        assert_eq!(format.commands()[0].args, ["-w", "main.go"]);
        assert_eq!(
            format.commands()[0].mutability,
            Mutability::WorkingTreeWrite
        );
        let fix = plan(&result, Intent::Fix)?;
        assert_eq!(fix.commands()[0].args, ["-w", "main.go"]);
        assert_eq!(fix.commands()[0].mutability, Mutability::WorkingTreeWrite);

        let test = plan(&result, Intent::Test)?;
        assert_eq!(test.commands().len(), 1);
        assert_eq!(test.commands()[0].args, ["test", "-json", "./..."]);
        assert_eq!(
            test.commands()[0].mutability,
            Mutability::ExternalSideEffect
        );

        let check = plan(&result, Intent::Check)?;
        assert_eq!(check.commands().len(), 3);
        assert_eq!(check.commands()[1].args, ["test", "-json", "./..."]);
        assert_eq!(check.commands()[2].args, ["vet", "-json", "./..."]);
        assert_eq!(check.commands()[0].mutability, Mutability::ReadOnly);
        assert!(
            check.commands()[1..]
                .iter()
                .all(|command| command.mutability == Mutability::ExternalSideEffect)
        );
        assert_eq!(
            check.commands()[2].enforcement,
            forge_core::domain::CommandEnforcement::Advisory
        );
        assert_eq!(
            check.commands()[1].env.get(OsStr::new("GOWORK")),
            Some(&OsString::from("off"))
        );

        let verify = plan(&result, Intent::Verify)?;
        assert_eq!(verify.commands().len(), 3);
        assert_eq!(verify.commands()[1].args, ["test", "-json", "./..."]);
        assert_eq!(verify.commands()[2].args, ["vet", "-json", "./..."]);
        assert_eq!(verify.commands()[0].mutability, Mutability::ReadOnly);
        assert!(
            verify.commands()[1..]
                .iter()
                .all(|command| command.mutability == Mutability::ExternalSideEffect)
        );
        assert!(
            result
                .issues
                .iter()
                .any(|issue| issue.kind == GoProviderIssueKind::ImpactScopeBroadened)
        );
        assert!(result.complete);
        assert_eq!(result.confidence, Confidence::High);
        Ok(())
    }

    #[test]
    fn workspace_members_are_real_units_and_all_go_execution_is_isolated()
    -> Result<(), Box<dyn Error>> {
        let repository = inventory(&[
            ("go.work", InventoryKind::File),
            ("a", InventoryKind::Directory),
            ("a/go.mod", InventoryKind::File),
            ("a/a.go", InventoryKind::File),
            ("b", InventoryKind::Directory),
            ("b/go.mod", InventoryKind::File),
            ("b/b.go", InventoryKind::File),
        ]);
        let file_system = FakeFileSystem::new(repository.clone())
            .with_text("a/a.go", b"package a\n")?
            .with_text("b/b.go", b"package b\n")?;
        let git = git_files(
            &["go.work", "a/go.mod", "a/a.go", "b/go.mod", "b/b.go"],
            &[],
        )?;
        let changed = Vec::new();
        let process = FakeProcess::with_responses(vec![observation(
            br#"{"Go":"1.22","Use":[{"DiskPath":"./a"},{"DiskPath":"./b"}]}"#,
        )]);
        let result = GoProvider.analyze(GoProviderContext {
            repository_root: Path::new("/repo"),
            inventory: &repository,
            git_files: &git,
            changed_files: Some(&changed),
            file_system: &file_system,
            process: &process,
            hasher: &FakeHasher,
            metadata_timeout: Duration::from_secs(2),
        })?;

        assert!(result.complete);
        assert_eq!(result.units.len(), 3);
        let unit_ids = result
            .units
            .iter()
            .map(|unit| unit.id.clone())
            .collect::<BTreeSet<_>>();
        let workspace = result
            .units
            .iter()
            .find(|unit| unit.kind == ProjectKind::GoWorkspace)
            .ok_or_else(|| io::Error::other("workspace unit is missing"))?;
        assert_eq!(workspace.members.len(), 2);
        assert!(
            workspace
                .members
                .iter()
                .all(|member| unit_ids.contains(member))
        );
        assert!(
            result
                .units
                .iter()
                .filter(|unit| {
                    unit.kind == ProjectKind::GoModule && unit.workspace_root.is_some()
                })
                .count()
                == 2
        );

        let calls = process.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].cwd, RepoRelativePath::root());
        assert_eq!(calls[0].args, ["work", "edit", "-json", "go.work"]);
        assert_eq!(calls[0].mutability, Mutability::ReadOnly);
        for (key, value) in [
            ("GOWORK", "off"),
            ("GOENV", "off"),
            ("GOTOOLCHAIN", "local"),
            ("GOFLAGS", ""),
            ("GOPROXY", "off"),
            ("GOSUMDB", "off"),
        ] {
            assert_eq!(
                calls[0].env.overrides.get(OsStr::new(key)),
                Some(&OsString::from(value))
            );
        }
        drop(calls);

        let tests = plan(&result, Intent::Test)?;
        assert_eq!(tests.commands().len(), 2);
        assert_eq!(tests.commands()[0].cwd, RepoRelativePath::new("a")?);
        assert_eq!(tests.commands()[1].cwd, RepoRelativePath::new("b")?);
        for command in tests.commands() {
            assert_eq!(
                command.env.get(OsStr::new("GOWORK")),
                Some(&Path::new("/repo/go.work").as_os_str().to_os_string())
            );
            assert_eq!(
                command.env.get(OsStr::new("GOENV")),
                Some(&OsString::from("off"))
            );
        }
        assert_eq!(file_system.writes.get(), 0);
        Ok(())
    }

    #[test]
    fn workspace_and_uncovered_module_form_a_mixed_model() -> Result<(), Box<dyn Error>> {
        let repository = inventory(&[
            ("work", InventoryKind::Directory),
            ("work/go.work", InventoryKind::File),
            ("a", InventoryKind::Directory),
            ("a/go.mod", InventoryKind::File),
            ("a/a.go", InventoryKind::File),
            ("c", InventoryKind::Directory),
            ("c/go.mod", InventoryKind::File),
            ("c/c.go", InventoryKind::File),
        ]);
        let file_system = FakeFileSystem::new(repository.clone());
        let git = git_files(
            &["work/go.work", "a/go.mod", "a/a.go", "c/go.mod", "c/c.go"],
            &[],
        )?;
        let changed = Vec::new();
        let process =
            FakeProcess::with_responses(vec![observation(br#"{"Use":[{"DiskPath":"../a"}]}"#)]);
        let result = GoProvider.analyze(GoProviderContext {
            repository_root: Path::new("/repo"),
            inventory: &repository,
            git_files: &git,
            changed_files: Some(&changed),
            file_system: &file_system,
            process: &process,
            hasher: &FakeHasher,
            metadata_timeout: Duration::from_secs(2),
        })?;

        assert_eq!(result.units.len(), 3);
        assert_eq!(
            result
                .units
                .iter()
                .filter(|unit| unit.kind == ProjectKind::GoWorkspace)
                .count(),
            1
        );
        assert_eq!(
            result
                .units
                .iter()
                .filter(|unit| unit.kind == ProjectKind::GoModule)
                .count(),
            2
        );
        let tests = plan(&result, Intent::Test)?;
        assert_eq!(tests.commands().len(), 2);
        let workspace_root = RepoRelativePath::new("a")?;
        let independent_root = RepoRelativePath::new("c")?;
        let workspace_command = tests
            .commands()
            .iter()
            .find(|command| command.cwd == workspace_root)
            .ok_or_else(|| io::Error::other("workspace member test command is missing"))?;
        let independent_command = tests
            .commands()
            .iter()
            .find(|command| command.cwd == independent_root)
            .ok_or_else(|| io::Error::other("independent module test command is missing"))?;
        assert_eq!(
            workspace_command.env.get(OsStr::new("GOWORK")),
            Some(&OsString::from("/repo/work/go.work"))
        );
        assert_eq!(
            independent_command.env.get(OsStr::new("GOWORK")),
            Some(&OsString::from("off"))
        );
        Ok(())
    }

    #[test]
    fn escape_symlink_duplicate_and_overlapping_workspaces_remain_unknown()
    -> Result<(), Box<dyn Error>> {
        let repository = inventory(&[
            ("go.work", InventoryKind::File),
            ("nested", InventoryKind::Directory),
            ("nested/go.work", InventoryKind::File),
            ("a", InventoryKind::Directory),
            ("a/go.mod", InventoryKind::File),
            ("link", InventoryKind::Symlink),
            ("link/go.mod", InventoryKind::File),
        ]);
        let mut file_system = FakeFileSystem::new(repository.clone());
        file_system.set_kind("link", PathKind::Symlink)?;
        let git = git_files(&["go.work", "nested/go.work", "a/go.mod"], &[])?;
        let changed = Vec::new();
        let process = FakeProcess::with_responses(vec![
            observation(
                br#"{"Use":[{"DiskPath":"../escape"},{"DiskPath":"./link"},{"DiskPath":"./a"}]}"#,
            ),
            observation(br#"{"Use":[{"DiskPath":"../a"}]}"#),
        ]);
        let result = GoProvider.analyze(GoProviderContext {
            repository_root: Path::new("/repo"),
            inventory: &repository,
            git_files: &git,
            changed_files: Some(&changed),
            file_system: &file_system,
            process: &process,
            hasher: &FakeHasher,
            metadata_timeout: Duration::from_secs(2),
        })?;

        assert!(!result.complete);
        assert_eq!(result.confidence, Confidence::Unknown);
        assert!(result.plans.is_empty());
        assert!(
            result
                .issues
                .iter()
                .any(|issue| { issue.kind == GoProviderIssueKind::InvalidUsePath })
        );
        assert!(
            result
                .issues
                .iter()
                .any(|issue| { issue.kind == GoProviderIssueKind::UseTargetNotDirectory })
        );
        assert!(result.issues.iter().any(|issue| {
            matches!(
                issue.kind,
                GoProviderIssueKind::DuplicateWorkspaceMembership
                    | GoProviderIssueKind::OverlappingWorkspace
            )
        }));
        assert!(result.units.iter().all(|unit| unit.members.is_empty()));
        Ok(())
    }

    #[test]
    fn metadata_timeout_and_interrupt_do_not_fall_back_to_independent_modules()
    -> Result<(), Box<dyn Error>> {
        let mut repository = inventory(&[
            ("go.work", InventoryKind::File),
            ("nested", InventoryKind::Directory),
            ("nested/go.work", InventoryKind::File),
            ("a", InventoryKind::Directory),
            ("a/go.mod", InventoryKind::File),
            ("nested/b", InventoryKind::Directory),
            ("nested/b/go.mod", InventoryKind::File),
        ]);
        repository.skipped.push(InventorySkip {
            path: None,
            reason: String::from("fixture incomplete tail"),
        });
        let file_system = FakeFileSystem::new(repository.clone());
        let git = git_files(
            &["go.work", "nested/go.work", "a/go.mod", "nested/b/go.mod"],
            &[],
        )?;
        let changed = Vec::new();
        let mut timed_out = observation(b"");
        timed_out.timed_out = true;
        timed_out.exit_code = None;
        let mut interrupted = observation(b"");
        interrupted.interrupted = true;
        interrupted.exit_code = None;
        let process = FakeProcess::with_responses(vec![timed_out, interrupted]);
        let result = GoProvider.analyze(GoProviderContext {
            repository_root: Path::new("/repo"),
            inventory: &repository,
            git_files: &git,
            changed_files: Some(&changed),
            file_system: &file_system,
            process: &process,
            hasher: &FakeHasher,
            metadata_timeout: Duration::from_millis(5),
        })?;

        assert!(result.plans.is_empty());
        assert!(
            result
                .units
                .iter()
                .all(|unit| unit.kind == ProjectKind::GoWorkspace)
        );
        assert!(
            result
                .issues
                .iter()
                .any(|issue| { issue.kind == GoProviderIssueKind::MetadataTimedOut })
        );
        assert!(
            result
                .issues
                .iter()
                .any(|issue| { issue.kind == GoProviderIssueKind::MetadataInterrupted })
        );
        assert!(
            result
                .issues
                .iter()
                .any(|issue| { issue.kind == GoProviderIssueKind::InventoryIncomplete })
        );
        Ok(())
    }

    #[test]
    fn embed_and_missing_changed_scope_preserve_full_tests_but_no_mutation()
    -> Result<(), Box<dyn Error>> {
        let repository = inventory(&[
            ("go.mod", InventoryKind::File),
            ("main.go", InventoryKind::File),
            ("assets/data.txt", InventoryKind::File),
        ]);
        let file_system = FakeFileSystem::new(repository.clone())
            .with_text("main.go", b"package main\n//go:embed assets/data.txt\n")?;
        let git = git_files(&["go.mod", "main.go", "assets/data.txt"], &[])?;
        let process = FakeProcess::default();
        let result = GoProvider.analyze(GoProviderContext {
            repository_root: Path::new("/repo"),
            inventory: &repository,
            git_files: &git,
            changed_files: None,
            file_system: &file_system,
            process: &process,
            hasher: &FakeHasher,
            metadata_timeout: Duration::from_secs(1),
        })?;

        assert!(
            result
                .plans
                .iter()
                .any(|plan| plan.intent() == Intent::Test)
        );
        assert!(
            !result
                .plans
                .iter()
                .any(|plan| { matches!(plan.intent(), Intent::Format | Intent::Fix) })
        );
        assert!(
            result
                .issues
                .iter()
                .any(|issue| { issue.kind == GoProviderIssueKind::ChangedScopeUnavailable })
        );
        Ok(())
    }

    #[test]
    fn format_arguments_are_stably_batched() {
        let arguments = (0..=MAX_FORMAT_BATCH_FILES)
            .map(|index| OsString::from(format!("file-{index:04}.go")))
            .collect::<Vec<_>>();
        let batches = batch_arguments(arguments.clone());

        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].len(), MAX_FORMAT_BATCH_FILES);
        assert_eq!(batches[1], arguments[MAX_FORMAT_BATCH_FILES..]);
    }
}
