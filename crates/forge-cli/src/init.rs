//! Side-effect-bounded orchestration for `forge init`.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Write as _};
use std::path::Path;

use forge_core::branding::CLI_NAME;
use forge_core::{
    AppError, ExitCode, Intent, OperationControl as _, ProjectModel, Provenance, WorkState,
};
use forge_detect::config::ForgeConfig;
use forge_detect::model::ModelDetectionCompletion;
use forge_render::managed_block::ManagedBlockError;
use forge_render::{
    AdapterSelectionOverrides, AdapterTarget, ApplyError, ApplyErrorKind, ApplyReport, ChangePlan,
    FileEditKind, GapKind, InitPlanOptions, ManagedBlockKind, PlanError, RunnerRenderError,
    RunnerTarget, SkippedReason, apply_change_plan, plan_init,
};
use forge_runtime::control::OperationBudget;
use forge_runtime::fs::NativeFileSystem;
use forge_runtime::hash::Blake3Hasher;
use forge_runtime::state::{AtomicStateStore, GitStateLayout, StateError};
use forge_schema::{Diagnostic, DoctorData, InitPlanData, Severity};

use crate::adapter_manifest::{
    AdapterManifest, AdapterManifestError, GeneratedManifestError, load_adapter_manifest,
    manifest_from_converged_plan, store_adapter_manifest,
};
use crate::args::{AdapterChoice, CiChoice, Cli, InitArgs, RunnerChoice};
use crate::init_wire::{InitPlanWireError, project_init_plan_to_wire};
use crate::{doctor, explain};

/// A completed init request. The plan remains the pre-apply artifact that the user reviewed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InitOutcome {
    pub(crate) plan: ChangePlan,
    pub(crate) wire: InitPlanData,
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) applied: bool,
    pub(crate) apply_report: Option<ApplyReport>,
    pub(crate) completion: ModelDetectionCompletion,
    pub(crate) postcheck_completion: Option<ModelDetectionCompletion>,
    pub(crate) postcheck_plan: Option<ChangePlan>,
    pub(crate) manifest: Option<AdapterManifest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AdapterManifestPrecondition {
    Unchecked,
    Expected(Option<AdapterManifest>),
}

/// An init failure coupled to any writes that completed before the failure was observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InitFailure {
    app_error: AppError,
    apply_report: Option<ApplyReport>,
}

impl InitFailure {
    #[must_use]
    pub(crate) fn into_parts(self) -> (AppError, Option<ApplyReport>) {
        (self.app_error, self.apply_report)
    }

    fn plain(app_error: AppError) -> Self {
        Self {
            app_error,
            apply_report: None,
        }
    }

    fn after_apply(app_error: AppError, apply_report: ApplyReport) -> Self {
        let app_error = with_apply_report(app_error, Some(&apply_report));
        Self {
            app_error,
            apply_report: Some(apply_report),
        }
    }
}

/// Adds authoritative write progress to a terminal error observed after init returned.
pub(crate) fn with_apply_report(
    app_error: AppError,
    apply_report: Option<&ApplyReport>,
) -> AppError {
    let Some(apply_report) = apply_report else {
        return app_error;
    };
    let diagnostic = app_error.diagnostic();
    AppError::new(
        app_error.exit_code(),
        Diagnostic::new(
            diagnostic.code.clone(),
            diagnostic.severity,
            diagnostic.what.clone(),
            diagnostic.location.clone(),
            format!("{}; {}", diagnostic.why, apply_report_summary(apply_report)),
            format!(
                "{}; treat the reported write progress as authoritative when reviewing or rolling back",
                diagnostic.next
            ),
        ),
    )
}

impl fmt::Display for InitFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.app_error.fmt(formatter)
    }
}

impl Error for InitFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.app_error)
    }
}

impl From<AppError> for InitFailure {
    fn from(error: AppError) -> Self {
        Self::plain(error)
    }
}

pub(crate) fn execute_controlled(
    cli: &Cli,
    args: &InitArgs,
    control: &OperationBudget,
) -> Result<InitOutcome, InitFailure> {
    execute_with_manifest_precondition_controlled(
        cli,
        args,
        control,
        AdapterManifestPrecondition::Unchecked,
    )
}

pub(crate) fn execute_with_manifest_precondition_controlled(
    cli: &Cli,
    args: &InitArgs,
    control: &OperationBudget,
    manifest_precondition: AdapterManifestPrecondition,
) -> Result<InitOutcome, InitFailure> {
    validate_request(args)?;
    let detected = explain::detect_controlled(cli, control)?;
    checkpoint(control, "init plan")?;
    let options = init_plan_options(args, detected.navigation.config.as_ref())?;

    if args.apply {
        ensure_detection_can_apply(detected.completion)?;
        ensure_work_state_can_apply(detected.model.repository.work_state, args.allow_dirty)?;
    }

    let filesystem = NativeFileSystem;
    let hasher = Blake3Hasher;
    let repository_root = detected.model.repository.root.clone();
    let plan =
        plan_init(&detected.model, &filesystem, &hasher, &options).map_err(map_plan_error)?;
    let wire =
        project_init_plan_to_wire(&plan, &repository_root).map_err(map_wire_projection_error)?;
    let diagnostics = project_gap_diagnostics(&plan, &detected.model);

    if !args.apply {
        return Ok(InitOutcome {
            plan,
            wire,
            diagnostics,
            applied: false,
            apply_report: None,
            completion: detected.completion,
            postcheck_completion: None,
            postcheck_plan: None,
            manifest: None,
        });
    }

    // Re-detect every input that authorized the reviewed plan immediately before writing. Target
    // preimages protect managed files; this second model also closes races in manifests, runners,
    // work state, and other inputs that can change the generated bytes without touching a target.
    checkpoint(control, "init pre-apply detection")?;
    let preapply = explain::detect_controlled(cli, control)?;
    ensure_detection_can_apply(preapply.completion)?;
    ensure_work_state_can_apply(preapply.model.repository.work_state, args.allow_dirty)?;
    if preapply.model.repository.id != plan.repository
        || preapply.model.repository.root != repository_root
    {
        return Err(InitFailure::plain(AppError::new(
            ExitCode::Temporary,
            Diagnostic::new(
                "FGE2213",
                Severity::Error,
                "repository selection changed before init apply",
                "init pre-apply check",
                "the repository identity or root no longer matches the reviewed plan",
                "review a fresh dry-run in the intended repository before applying",
            ),
        )));
    }
    let current_options = init_plan_options(args, preapply.navigation.config.as_ref())?;
    checkpoint(control, "init pre-apply plan")?;
    let current_plan = plan_init(&preapply.model, &filesystem, &hasher, &current_options)
        .map_err(|error| InitFailure::plain(map_plan_error_app(error, "init pre-apply check")))?;
    if current_options != options || current_plan != plan {
        return Err(InitFailure::plain(AppError::new(
            ExitCode::Temporary,
            Diagnostic::new(
                "FGE2214",
                Severity::Error,
                "repository inputs changed after the init plan was produced",
                "init pre-apply check",
                "a fresh plan is not byte-for-byte equal to the reviewed plan; no files were written",
                "rerun the dry-run, review the new plan, then request `--apply` again",
            ),
        )));
    }

    checkpoint(control, "init apply state")?;
    let state_store = AtomicStateStore::new(GitStateLayout::new(
        &preapply.model.repository.git_dir,
        &preapply.model.repository.git_common_dir,
    ))
    .map_err(|error| InitFailure::plain(map_state_error(error, "init apply state")))?;
    let _state_lock = state_store
        .try_lock()
        .map_err(|error| InitFailure::plain(map_state_error(error, "init apply lock")))?;
    if let AdapterManifestPrecondition::Expected(expected) = &manifest_precondition {
        let current = load_adapter_manifest(&state_store, &preapply.model.repository.id).map_err(
            |error| {
                InitFailure::plain(map_manifest_read_error(error, "init manifest precondition"))
            },
        )?;
        if &current != expected {
            return Err(InitFailure::plain(AppError::new(
                ExitCode::Temporary,
                Diagnostic::new(
                    "FGE2224",
                    Severity::Error,
                    "adapter manifest changed before synchronization",
                    "init manifest precondition",
                    "the locked private manifest no longer matches the state used to select adapter targets",
                    "rerun adapters sync, review the fresh preview, then request --apply again",
                ),
            )));
        }
    }
    checkpoint(control, "init apply")?;
    let report = apply_change_plan(&repository_root, &plan, &filesystem, &hasher)
        .map_err(map_apply_error)?;
    checkpoint_after_apply(control, "init post-check", &report)?;
    let postcheck = explain::detect_controlled(cli, control)
        .map_err(|error| InitFailure::after_apply(error, report.clone()))?;
    ensure_postcheck_completed(postcheck.completion, &report)?;
    if postcheck.model.repository.id != plan.repository
        || postcheck.model.repository.root != repository_root
        || postcheck.model.repository.git_dir != preapply.model.repository.git_dir
        || postcheck.model.repository.git_common_dir != preapply.model.repository.git_common_dir
    {
        return Err(InitFailure::after_apply(
            AppError::internal(
                "FGE0210",
                "post-apply detection resolved a different repository state layout",
                "init post-check",
                format!(
                    "the reviewed repository was `{}` at `{}`, but its post-check identity, root, or Git state layout no longer matched `{}` at `{}`",
                    plan.repository.as_str(),
                    display_repository_path(&repository_root),
                    postcheck.model.repository.id.as_str(),
                    display_repository_path(&postcheck.model.repository.root),
                ),
                "inspect the written paths and repository selection before retrying; use the reported rollback guidance if recovery is required",
            ),
            report,
        ));
    }
    let post_options =
        init_plan_options(args, postcheck.navigation.config.as_ref()).map_err(|failure| {
            let (error, _) = failure.into_parts();
            InitFailure::after_apply(error, report.clone())
        })?;
    if post_options != options {
        return Err(InitFailure::after_apply(
            AppError::new(
                ExitCode::Temporary,
                Diagnostic::new(
                    "FGE2231",
                    Severity::Error,
                    "adapter selection changed during init post-check",
                    "init post-check",
                    "forge.toml no longer selects the adapters authorized by the reviewed plan",
                    "review the written paths and rerun a fresh dry-run before applying again",
                ),
            ),
            report,
        ));
    }
    checkpoint_after_apply(control, "init post-check plan", &report)?;
    let post_plan =
        plan_init(&postcheck.model, &filesystem, &hasher, &post_options).map_err(|error| {
            InitFailure::after_apply(map_plan_error_app(error, "init post-check"), report.clone())
        })?;
    if !post_plan.edits.is_empty() {
        let remaining = post_plan
            .edits
            .iter()
            .map(|edit| display_repository_path(edit.path.as_path()))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(InitFailure::after_apply(
            AppError::internal(
                "FGE0211",
                "applied init output did not converge to a no-op",
                "init post-check",
                format!("a fresh detection still planned edits for [{remaining}]",),
                "inspect the written files and rerun a dry-run; roll back the reported paths if the generated state is not acceptable",
            ),
            report,
        ));
    }
    checkpoint_after_apply(control, "init adapter manifest", &report)?;
    let manifest = manifest_from_converged_plan(&post_plan, &repository_root, &filesystem, &hasher)
        .map_err(|error| {
            InitFailure::after_apply(
                map_generated_manifest_error(error, "init adapter manifest"),
                report.clone(),
            )
        })?;
    store_adapter_manifest(&state_store, &post_plan.repository, &manifest).map_err(|error| {
        InitFailure::after_apply(
            map_manifest_error(error, "init adapter manifest"),
            report.clone(),
        )
    })?;
    drop(_state_lock);
    checkpoint_after_apply(control, "init post-apply doctor", &report)?;
    let postdoctor = doctor::execute_postcheck_controlled(cli, &postcheck, control)
        .map_err(|error| InitFailure::after_apply(error, report.clone()))?;
    ensure_generated_state_postdoctor(&postdoctor.wire, &report)?;
    if control.checkpoint().is_ok() {
        explain::publish_inventory_cache_after_state_write(&preapply);
    }

    Ok(InitOutcome {
        plan,
        wire,
        diagnostics,
        applied: true,
        apply_report: Some(report),
        completion: detected.completion,
        postcheck_completion: Some(postcheck.completion),
        postcheck_plan: Some(post_plan),
        manifest: Some(manifest),
    })
}

fn checkpoint(control: &OperationBudget, location: &str) -> Result<(), InitFailure> {
    control
        .checkpoint()
        .map(|_| ())
        .map_err(|error| InitFailure::plain(explain::map_operation_control_error(error, location)))
}

fn checkpoint_after_apply(
    control: &OperationBudget,
    location: &str,
    report: &ApplyReport,
) -> Result<(), InitFailure> {
    control.checkpoint().map(|_| ()).map_err(|error| {
        InitFailure::after_apply(
            explain::map_operation_control_error(error, location),
            report.clone(),
        )
    })
}

/// Projects diagnostic-only command gaps through the envelope channel shared by human and JSON
/// output. The versioned `InitPlanData` payload deliberately remains unchanged.
fn project_gap_diagnostics(plan: &ChangePlan, model: &ProjectModel) -> Vec<Diagnostic> {
    Intent::ALL
        .into_iter()
        .filter_map(|intent| {
            let gap = plan.gaps.iter().find(|gap| {
                gap.intent == Some(intent)
                    && matches!(
                        gap.kind,
                        GapKind::MissingProjectCommand
                            | GapKind::AmbiguousCommand
                            | GapKind::ConfigurationRequired
                    )
            })?;
            let commands = model.commands.get(&intent);
            let intent_label = intent_name(intent);
            let evidence = commands.map_or_else(
                || String::from("no command-resolution record was available"),
                |commands| provenance_summary(&commands.provenance),
            );
            match gap.kind {
                GapKind::MissingProjectCommand => commands.map(|_| {
                    Diagnostic::new(
                        "FGE2232",
                        Severity::Warning,
                        format!("project command `{intent_label}` is absent"),
                        format!("project command `{intent_label}`"),
                        format!(
                            "command resolution completed without a project-owned candidate; {evidence}"
                        ),
                        format!(
                            "add a project-owned `{intent_label}` entry point or define `[commands.{intent_label}]` in forge.toml, then rerun forge init"
                        ),
                    )
                }),
                GapKind::AmbiguousCommand => commands.map(|commands| {
                    Diagnostic::new(
                        "FGE2233",
                        Severity::Warning,
                        format!("project command `{intent_label}` is ambiguous"),
                        format!("project command `{intent_label}`"),
                        format!(
                            "command resolution retained {} equally authoritative candidates and will not choose one arbitrarily; {evidence}",
                            commands.commands().len()
                        ),
                        format!(
                            "select one authoritative `{intent_label}` interface or define `[commands.{intent_label}]` in forge.toml, then rerun forge init"
                        ),
                    )
                }),
                GapKind::ConfigurationRequired => Some(Diagnostic::new(
                    "FGE2234",
                    Severity::Warning,
                    format!("project command `{intent_label}` cannot be inferred safely"),
                    format!("project command `{intent_label}`"),
                    format!("command resolution remains unknown; {evidence}"),
                    format!(
                        "choose the repository's authoritative `{intent_label}` argv, define it in `[commands.{intent_label}]` in forge.toml, then rerun forge init; Forge will not guess this decision"
                    ),
                )),
                GapKind::MissingHostIndex
                | GapKind::MissingHostPointer
                | GapKind::AdapterDrift
                | GapKind::OptionalRunner
                | GapKind::OptionalCiDraft => None,
            }
        })
        .collect()
}

fn provenance_summary(provenance: &[Provenance]) -> String {
    const DISPLAY_LIMIT: usize = 4;

    if provenance.is_empty() {
        return String::from("no resolution provenance was retained");
    }
    let mut sources = provenance
        .iter()
        .take(DISPLAY_LIMIT)
        .map(|source| {
            let rule = sanitize_text(&source.rule_id);
            source.source_path.as_ref().map_or(rule.clone(), |path| {
                format!("{rule}@{}", sanitize_text(&path.display))
            })
        })
        .collect::<Vec<_>>();
    if provenance.len() > DISPLAY_LIMIT {
        sources.push(format!(
            "{} additional source(s)",
            provenance.len() - DISPLAY_LIMIT
        ));
    }
    format!("resolution provenance: {}", sources.join(", "))
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

fn ensure_generated_state_postdoctor(
    outcome: &DoctorData,
    report: &ApplyReport,
) -> Result<(), InitFailure> {
    let failed = outcome
        .checks
        .iter()
        .filter(|check| {
            matches!(
                check.id.as_str(),
                "state.layout" | "adapters.drift" | "path.safety"
            ) && check.status == forge_schema::CheckStatusData::Fail
        })
        .map(|check| check.id.as_str())
        .collect::<Vec<_>>();
    if failed.is_empty() {
        return Ok(());
    }
    Err(InitFailure::after_apply(
        AppError::internal(
            "FGE0215",
            "generated repository integration failed its post-doctor checks",
            "init post-doctor",
            format!("failed checks: {}", failed.join(", ")),
            "inspect the generated state and reported write set before retrying or rolling back",
        ),
        report.clone(),
    ))
}

fn map_state_error(error: StateError, location: &str) -> AppError {
    let exit_code = crate::state_diagnostic::state_error_exit_code(&error);
    AppError::new(
        exit_code,
        Diagnostic::new(
            "FGE2217",
            Severity::Error,
            "Forge private state is unavailable for adapter persistence",
            location,
            sanitize_text(&error.to_string()),
            "fix the Git private-state path, permissions, or competing Forge process, then rerun init --apply",
        ),
    )
}

fn map_generated_manifest_error(error: GeneratedManifestError, location: &str) -> AppError {
    let detail = sanitize_text(&error.to_string());
    if error.io_kind().is_some() {
        AppError::environment_unmet(
            "FGE2219",
            "generated adapter state could not be derived",
            location,
            detail,
            "fix the generated target path or permissions, then rerun init --apply",
        )
    } else {
        AppError::internal(
            "FGE0219",
            "generated adapter state violated its post-check contract",
            location,
            detail,
            "report this as a Forge implementation defect",
        )
    }
}

fn map_manifest_error(error: AdapterManifestError, location: &str) -> AppError {
    let detail = sanitize_text(&error.to_string());
    if error.io_kind().is_some() {
        AppError::environment_unmet(
            "FGE2218",
            "the adapter manifest could not be persisted",
            location,
            detail,
            "fix the Git private-state path or permissions, then rerun init --apply",
        )
    } else {
        AppError::internal(
            "FGE0218",
            "the generated adapter manifest violated its state contract",
            location,
            detail,
            "report this as a Forge implementation defect",
        )
    }
}

fn map_manifest_read_error(error: AdapterManifestError, location: &str) -> AppError {
    let detail = sanitize_text(&error.to_string());
    if error.io_kind().is_some() {
        AppError::environment_unmet(
            "FGE2225",
            "the adapter manifest precondition could not be read",
            location,
            detail,
            "fix the Git private-state path or permissions, then rerun adapters sync",
        )
    } else {
        AppError::data(
            "FGE1212",
            "the adapter manifest precondition is invalid",
            location,
            detail,
            "upgrade Forge or delete this rebuildable private state, then rerun forge init --apply",
        )
    }
}

fn validate_request(args: &InitArgs) -> Result<(), InitFailure> {
    if args.apply && args.dry_run {
        return Err(InitFailure::plain(AppError::usage(
            "FGE1201",
            "init cannot select both preview and apply modes",
            "--dry-run / --apply",
            "the two modes have different side-effect contracts",
            "select at most one mode; omitting both is a dry-run",
        )));
    }
    if let Some(provider) = args.with_ci {
        return Err(InitFailure::plain(unavailable_ci_error(provider)));
    }
    Ok(())
}

fn unavailable_ci_error(provider: CiChoice) -> AppError {
    AppError::environment_unmet(
        "FGE2202",
        format!(
            "explicit `{}` CI draft generation is not available in this build",
            ci_name(provider)
        ),
        "--with-ci",
        "Forge cannot yet render and verify this opt-in asset, so it will not silently ignore the request",
        format!(
            "remove `--with-ci {}` or use a Forge build that implements explicit CI draft generation",
            ci_name(provider)
        ),
    )
}

const fn ci_name(provider: CiChoice) -> &'static str {
    match provider {
        CiChoice::Github => "github",
    }
}

fn init_plan_options(
    args: &InitArgs,
    config: Option<&ForgeConfig>,
) -> Result<InitPlanOptions, InitFailure> {
    let adapters = args
        .adapter
        .iter()
        .copied()
        .map(|adapter| match adapter {
            AdapterChoice::Claude => AdapterTarget::Claude,
            AdapterChoice::Cursor => AdapterTarget::Cursor,
        })
        .collect();
    let force_blocks = parse_force_blocks(&args.force_block)?;
    Ok(InitPlanOptions {
        adapters,
        adopted_adapters: Vec::new(),
        adapter_selection: adapter_selection_overrides(config),
        force_blocks,
        runner: args.with_runner.map(|runner| match runner {
            RunnerChoice::Make => RunnerTarget::Make,
            RunnerChoice::Just => RunnerTarget::Just,
            RunnerChoice::Task => RunnerTarget::Task,
        }),
    })
}

pub(crate) fn adapter_selection_overrides(
    config: Option<&ForgeConfig>,
) -> AdapterSelectionOverrides {
    config.map_or_else(AdapterSelectionOverrides::default, |config| {
        AdapterSelectionOverrides {
            agents: config.adapters.agents,
            claude: config.adapters.claude,
        }
    })
}

fn parse_force_blocks(values: &[String]) -> Result<Vec<ManagedBlockKind>, InitFailure> {
    let mut blocks = Vec::with_capacity(values.len());
    let mut unique = BTreeSet::new();
    for value in values {
        let block = match value.as_str() {
            "project-index" => ManagedBlockKind::ProjectIndex,
            "claude-pointer" => ManagedBlockKind::ClaudePointer,
            "runner-make-verify" => ManagedBlockKind::RunnerMakeVerify,
            "runner-just-verify" => ManagedBlockKind::RunnerJustVerify,
            "runner-task-verify" => ManagedBlockKind::RunnerTaskVerify,
            _ => {
                return Err(InitFailure::plain(AppError::usage(
                    "FGE1202",
                    "unknown managed block selected for replacement",
                    "--force-block",
                    format!("`{value}` is not one of the managed blocks owned by this Forge build"),
                    "use one block id printed by the init preview",
                )));
            }
        };
        if !unique.insert(block) {
            return Err(InitFailure::plain(AppError::usage(
                "FGE1203",
                "the same managed block was selected more than once",
                "--force-block",
                format!("`{value}` occurs more than once"),
                "remove the duplicate option",
            )));
        }
        blocks.push(block);
    }
    Ok(blocks)
}

fn ensure_detection_can_apply(completion: ModelDetectionCompletion) -> Result<(), InitFailure> {
    let (exit_code, code, what, why, next) = match completion {
        ModelDetectionCompletion::Complete | ModelDetectionCompletion::Partial => return Ok(()),
        ModelDetectionCompletion::TimedOut => (
            ExitCode::Timeout,
            "FGE2203",
            "init detection timed out before apply",
            "the partial model is reviewable but is not a safe write authority",
            "increase `--timeout`, address the slow metadata source, then rerun the dry-run before applying",
        ),
        ModelDetectionCompletion::Interrupted => (
            ExitCode::Interrupted,
            "FGE2204",
            "init detection was interrupted before apply",
            "the partial model is reviewable but is not a safe write authority",
            "rerun the dry-run when ready, review the plan, then request `--apply` again",
        ),
    };
    Err(InitFailure::plain(AppError::new(
        exit_code,
        Diagnostic::new(code, Severity::Error, what, "init detection", why, next),
    )))
}

fn ensure_work_state_can_apply(state: WorkState, allow_dirty: bool) -> Result<(), InitFailure> {
    match state {
        WorkState::Clean => Ok(()),
        WorkState::Dirty | WorkState::Unborn if allow_dirty => Ok(()),
        WorkState::Dirty | WorkState::Unborn => {
            Err(InitFailure::plain(AppError::environment_unmet(
                "FGE2205",
                "init apply requires a clean worktree",
                "Git worktree",
                format!(
                    "the initial repository state is `{}` and `--allow-dirty` was not selected",
                    work_state_name(state)
                ),
                "commit, stash, or otherwise preserve existing work; alternatively rerun with `--allow-dirty` after reviewing the rollback limitations",
            )))
        }
        WorkState::Conflicted
        | WorkState::Merging
        | WorkState::Rebasing
        | WorkState::Corrupt
        | WorkState::Unknown => Err(InitFailure::plain(AppError::environment_unmet(
            "FGE2206",
            "init apply is unsafe in the current repository state",
            "Git worktree",
            format!(
                "the initial repository state is `{}`; `--allow-dirty` cannot override unresolved or untrusted repository state",
                work_state_name(state)
            ),
            "finish or abort the Git operation, resolve conflicts, or repair repository inspection before rerunning the dry-run",
        ))),
    }
}

fn ensure_postcheck_completed(
    completion: ModelDetectionCompletion,
    report: &ApplyReport,
) -> Result<(), InitFailure> {
    let (exit_code, code, what, why, next) = match completion {
        ModelDetectionCompletion::Complete | ModelDetectionCompletion::Partial => return Ok(()),
        ModelDetectionCompletion::TimedOut => (
            ExitCode::Timeout,
            "FGE2207",
            "init wrote its plan but the post-apply detection timed out",
            String::from("idempotence could not be verified"),
            "inspect the reported written paths, rerun a dry-run with a larger timeout, and use the rollback guidance if verification does not converge",
        ),
        ModelDetectionCompletion::Interrupted => (
            ExitCode::Interrupted,
            "FGE2208",
            "init wrote its plan but the post-apply detection was interrupted",
            String::from("idempotence could not be verified"),
            "inspect the reported written paths, rerun a dry-run when ready, and use the rollback guidance if verification does not converge",
        ),
    };
    Err(InitFailure::after_apply(
        AppError::new(
            exit_code,
            Diagnostic::new(code, Severity::Error, what, "init post-check", why, next),
        ),
        report.clone(),
    ))
}

const fn work_state_name(state: WorkState) -> &'static str {
    match state {
        WorkState::Clean => "clean",
        WorkState::Dirty => "dirty",
        WorkState::Conflicted => "conflicted",
        WorkState::Merging => "merging",
        WorkState::Rebasing => "rebasing",
        WorkState::Unborn => "unborn",
        WorkState::Corrupt => "corrupt",
        WorkState::Unknown => "unknown",
    }
}

fn map_plan_error(error: PlanError) -> InitFailure {
    InitFailure::plain(map_plan_error_app(error, "init plan"))
}

pub(crate) fn map_plan_error_app(error: PlanError, location: &str) -> AppError {
    let detail = error.to_string();
    match error {
        PlanError::NoProjectFacts => AppError::environment_unmet(
            "FGE2209",
            "no project commands or units could be established for init",
            location,
            "the repository does not contain enough trusted facts to generate a useful host index",
            "establish the project with its ecosystem's normal tools or add an explicit Forge command configuration, then rerun the dry-run",
        ),
        PlanError::DuplicateAdapterRequest(adapter) => AppError::usage(
            "FGE1204",
            "the same host adapter was requested more than once",
            "--adapter",
            format!("adapter `{}` occurs more than once", adapter_name(adapter)),
            "remove the duplicate adapter option",
        ),
        PlanError::AdapterDependencyConflict { adapter, required } => AppError::data(
            "FGE1215",
            "adapter configuration cannot be satisfied safely",
            "forge.toml [adapters]",
            format!(
                "adapter `{}` requires `{}`, but the required projection is disabled",
                adapter_name(adapter),
                adapter_name(required)
            ),
            "enable the required adapter, disable the dependent adapter, or request the dependent adapter explicitly for this init",
        ),
        PlanError::DuplicateForceBlock(block) => AppError::usage(
            "FGE1203",
            "the same managed block was selected more than once",
            "--force-block",
            format!("`{}` occurs more than once", block.id()),
            "remove the duplicate option",
        ),
        PlanError::Read { path, source } => AppError::environment_unmet(
            "FGE2210",
            "a planned adapter target could not be read safely",
            display_repository_path(path.as_path()),
            sanitize_text(&source.to_string()),
            "fix the path, permissions, or symbolic-link boundary, then rerun the dry-run",
        ),
        PlanError::ManagedBlock { path, source } => {
            let next = managed_block_recovery(&source);
            AppError::data(
                "FGE1205",
                "managed adapter content cannot be updated safely",
                display_repository_path(path.as_path()),
                sanitize_text(&source.to_string()),
                next,
            )
        }
        PlanError::AdapterFileLimit {
            path,
            stage,
            observed_bytes,
            max_bytes,
        } => AppError::environment_unmet(
            "FGE2226",
            "an adapter target is too large for bounded planning",
            display_repository_path(path.as_path()),
            observed_bytes.map_or_else(
                || format!(
                    "the {stage:?} complete file exceeds the {max_bytes}-byte review limit"
                ),
                |bytes| format!(
                    "the {stage:?} complete file is {bytes} bytes, above the {max_bytes}-byte review limit"
                ),
            ),
            "reduce or split the user-owned file before asking Forge to append a managed block",
        ),
        PlanError::AttributesFileLimit { path, max_bytes } => AppError::environment_unmet(
            "FGE2226",
            "the root attributes file is too large for bounded init planning",
            display_repository_path(path.as_path()),
            format!("the complete file exceeds the {max_bytes}-byte review limit"),
            "reduce or split the root .gitattributes file, then rerun the dry-run",
        ),
        PlanError::RunnerRender { path, source } => {
            let (what, next) = if matches!(&source, RunnerRenderError::UnsupportedPlatform { .. }) {
                (
                    "the explicit runner is not supported on this platform",
                    "select --with-runner task on Windows, or keep using the reported project-native commands",
                )
            } else {
                (
                    "the explicit runner cannot preserve the resolved project command contract",
                    "keep using the reported project-native commands, or make their argv, cwd, and environment portable before retrying --with-runner",
                )
            };
            AppError::environment_unmet(
                "FGE2229",
                what,
                display_repository_path(path.as_path()),
                sanitize_text(&source.to_string()),
                next,
            )
        }
        PlanError::RunnerConflict { path, detail } => AppError::environment_unmet(
            "FGE2230",
            "the explicit runner would conflict with an existing project interface",
            display_repository_path(path.as_path()),
            sanitize_text(&detail),
            "keep the existing runner or verify command; remove the competing interface explicitly before selecting a different runner",
        ),
        PlanError::InvalidTarget(_)
        | PlanError::DuplicateTarget(_)
        | PlanError::InvalidModel(_)
        | PlanError::GeneratedBlockLimit { .. }
        | PlanError::InspectionInvariant { .. } => AppError::internal(
            "FGE0212",
            "init planning violated a rendering invariant",
            location,
            sanitize_text(&detail),
            format!(
                "report this as a {CLI_NAME} implementation defect with the repository shape and command"
            ),
        ),
    }
}

fn managed_block_recovery(error: &ManagedBlockError) -> String {
    match error {
        ManagedBlockError::UserEdited { id } => format!(
            "move durable requirements outside the managed block, rerun the dry-run, or explicitly select `--force-block {id}` after reviewing the replacement"
        ),
        ManagedBlockError::UnsupportedSchema { .. } => {
            String::from("upgrade Forge before changing a block written by a newer marker schema")
        }
        ManagedBlockError::InvalidUtf8
        | ManagedBlockError::InvalidBlockId(_)
        | ManagedBlockError::MalformedMarker { .. }
        | ManagedBlockError::NestedBlock { .. }
        | ManagedBlockError::OrphanEnd { .. }
        | ManagedBlockError::MismatchedEnd { .. }
        | ManagedBlockError::UnterminatedBlock { .. }
        | ManagedBlockError::DuplicateBlock { .. } => String::from(
            "repair the malformed or duplicate managed markers without changing unrelated file bytes, then rerun the dry-run",
        ),
    }
}

fn map_wire_projection_error(error: InitPlanWireError) -> InitFailure {
    InitFailure::plain(AppError::internal(
        "FGE0213",
        "the init plan cannot be represented by the public contract",
        "forge.init-plan/v1",
        sanitize_text(&error.to_string()),
        format!(
            "report this as a {CLI_NAME} implementation defect with the dry-run command and repository shape"
        ),
    ))
}

fn map_apply_error(error: ApplyError) -> InitFailure {
    let report = error.report().clone();
    let location = error.path().map_or_else(
        || String::from("init apply"),
        |path| display_repository_path(path.as_path()),
    );
    let detail = sanitize_text(&error.to_string());
    let app_error = match error.kind() {
        ApplyErrorKind::PreimagePresenceMismatch
        | ApplyErrorKind::PreimageDigestMismatch
        | ApplyErrorKind::PrewriteDrift => AppError::new(
            ExitCode::Temporary,
            Diagnostic::new(
                "FGE2211",
                Severity::Error,
                "the repository changed after the init plan was produced",
                location,
                detail,
                "review a fresh dry-run and apply that new plan; inspect any reported written paths before retrying",
            ),
        ),
        ApplyErrorKind::ManagedBlockConflict => AppError::data(
            "FGE1206",
            "managed adapter content conflicted during apply preflight",
            location,
            detail,
            "review a fresh dry-run and resolve the managed block conflict; force only the named block when replacement is intentional",
        ),
        ApplyErrorKind::ReadPreimage
        | ApplyErrorKind::ExistingFileTooLarge
        | ApplyErrorKind::ReadBeforeWrite
        | ApplyErrorKind::Write
        | ApplyErrorKind::ReadAfterWrite
        | ApplyErrorKind::PostwriteMissing
        | ApplyErrorKind::PostwriteMismatch => AppError::environment_unmet(
            "FGE2212",
            "init could not complete or verify its confined writes",
            location,
            detail,
            "inspect the reported written and unwritten paths, restore the listed preimages with Git when needed, then rerun a dry-run",
        ),
        ApplyErrorKind::UnsupportedPlanSchema
        | ApplyErrorKind::DuplicateTarget
        | ApplyErrorKind::InvalidEdit
        | ApplyErrorKind::PostimageTooLarge
        | ApplyErrorKind::UnexpectedMergeAction
        | ApplyErrorKind::PostimageDigestMismatch => AppError::internal(
            "FGE0214",
            "the reviewed init plan violated an apply invariant",
            location,
            detail,
            format!(
                "inspect any reported writes, then report this as a {CLI_NAME} implementation defect"
            ),
        ),
    };
    InitFailure::after_apply(app_error, report)
}

fn apply_report_summary(report: &ApplyReport) -> String {
    let written = report
        .written
        .iter()
        .map(|file| {
            format!(
                "{}(kind={},preimage={},postimage={},verified={})",
                display_repository_path(file.path.as_path()),
                edit_kind_name(file.kind),
                file.preimage
                    .as_ref()
                    .map_or("none", |digest| digest.as_str()),
                file.postimage.as_str(),
                file.verified,
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let unwritten = report
        .unwritten
        .iter()
        .map(|path| display_repository_path(path.as_path()))
        .collect::<Vec<_>>()
        .join(",");
    format!("apply report: written=[{written}], unwritten=[{unwritten}]")
}

const fn edit_kind_name(kind: FileEditKind) -> &'static str {
    match kind {
        FileEditKind::Create => "create",
        FileEditKind::ReplaceManagedBlock => "replace-managed-block",
    }
}

const fn adapter_name(adapter: AdapterTarget) -> &'static str {
    match adapter {
        AdapterTarget::Claude => "claude",
        AdapterTarget::Cursor => "cursor",
        AdapterTarget::Codex => "codex",
    }
}

const fn completion_name(completion: ModelDetectionCompletion) -> &'static str {
    match completion {
        ModelDetectionCompletion::Complete => "complete",
        ModelDetectionCompletion::Partial => "partial",
        ModelDetectionCompletion::TimedOut => "timed-out",
        ModelDetectionCompletion::Interrupted => "interrupted",
    }
}

const fn skipped_reason_name(reason: &SkippedReason) -> &'static str {
    match reason {
        SkippedReason::AlreadySatisfied => "already-satisfied",
        SkippedReason::EquivalentUnmanaged => "equivalent-unmanaged",
        SkippedReason::ReusesAgents(AdapterTarget::Claude) => "reuses-agents:claude",
        SkippedReason::ReusesAgents(AdapterTarget::Cursor) => "reuses-agents:cursor",
        SkippedReason::ReusesAgents(AdapterTarget::Codex) => "reuses-agents:codex",
    }
}

/// Renders the exact plan artifact without rescanning the repository or performing writes.
pub(crate) fn render_human(outcome: &InitOutcome) -> String {
    let mut output = String::new();
    let mode = if outcome.applied {
        "applied"
    } else {
        "dry-run"
    };
    let _ = writeln!(output, "repository: {}", outcome.plan.repository.as_str());
    let _ = writeln!(output, "mode: {mode}");
    let _ = writeln!(output, "detection: {}", completion_name(outcome.completion));
    if let Some(completion) = outcome.postcheck_completion {
        let _ = writeln!(output, "post-check: {}", completion_name(completion));
    }
    let _ = writeln!(output, "planned edits: {}", outcome.plan.edits.len());
    for edit in &outcome.plan.edits {
        let _ = writeln!(
            output,
            "  - {}: {} (block {}, preimage {}, postimage {})",
            edit_kind_name(edit.kind),
            display_repository_path(edit.path.as_path()),
            edit.desired.kind.id(),
            edit.expected_preimage
                .as_ref()
                .map_or("none", |digest| digest.as_str()),
            edit.expected_postimage.as_str(),
        );
        let _ = writeln!(
            output,
            "    UTF-8 postimage preview ({} bytes; control characters escaped):",
            edit.preview_postimage.len()
        );
        render_postimage(&mut output, &edit.preview_postimage);
    }
    let assumptions = outcome
        .plan
        .assumptions
        .iter()
        .map(|assumption| sanitize_text(&assumption.statement))
        .collect::<BTreeSet<_>>();
    if assumptions.len() == outcome.plan.assumptions.len() {
        let _ = writeln!(output, "assumptions: {}", assumptions.len());
    } else {
        let _ = writeln!(
            output,
            "assumptions: {} distinct ({} source observations)",
            assumptions.len(),
            outcome.plan.assumptions.len(),
        );
    }
    for assumption in assumptions {
        let _ = writeln!(output, "  - {assumption}");
    }
    let _ = writeln!(output, "warnings: {}", outcome.diagnostics.len());
    for diagnostic in &outcome.diagnostics {
        let _ = writeln!(
            output,
            "  - {}[{}]: {}",
            diagnostic.severity,
            diagnostic.code,
            sanitize_text(&diagnostic.what),
        );
        let _ = writeln!(output, "    where: {}", sanitize_text(&diagnostic.location));
        let _ = writeln!(output, "    why: {}", sanitize_text(&diagnostic.why));
        let _ = writeln!(output, "    next: {}", sanitize_text(&diagnostic.next));
    }
    let _ = writeln!(output, "skipped: {}", outcome.plan.skipped.len());
    for skipped in &outcome.plan.skipped {
        let _ = writeln!(
            output,
            "  - {} ({})",
            display_repository_path(skipped.path.as_path()),
            skipped_reason_name(&skipped.reason),
        );
    }
    if let Some(report) = &outcome.apply_report {
        let _ = writeln!(output, "{}", apply_report_summary(report));
    }
    output.push_str("rollback:\n");
    for path in &outcome.plan.rollback.restore_modified {
        let _ = writeln!(
            output,
            "  restore modified: {}",
            display_repository_path(path.as_path())
        );
    }
    for path in &outcome.plan.rollback.remove_created {
        let _ = writeln!(
            output,
            "  remove created: {}",
            display_repository_path(path.as_path())
        );
    }
    let _ = writeln!(output, "  {}", outcome.wire.rollback.guidance);
    output
}

fn render_postimage(output: &mut String, bytes: &[u8]) {
    match std::str::from_utf8(bytes) {
        Ok(text) => {
            for segment in text.split_inclusive('\n') {
                let _ = writeln!(output, "      | {}", sanitize_text(segment));
            }
            if text.is_empty() {
                output.push_str("      | <empty>\n");
            }
        }
        Err(_) => {
            let _ = writeln!(output, "      <non-UTF-8 postimage: {} bytes>", bytes.len());
        }
    }
}

pub(crate) fn display_repository_path(path: &Path) -> String {
    sanitize_text(&path.as_os_str().to_string_lossy())
}

pub(crate) fn sanitize_text(value: &str) -> String {
    let mut sanitized = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            let _ = write!(sanitized, "\\u{{{:x}}}", u32::from(character));
        } else {
            sanitized.push(character);
        }
    }
    sanitized
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Instant;

    use forge_core::{AppError, ExitCode, RepoRelativePath, WorkState};
    use forge_detect::model::ModelDetectionCompletion;
    use forge_render::{ApplyReport, ManagedBlockKind, PlanError, RunnerRenderError, RunnerTarget};
    use forge_runtime::control::OperationBudget;
    use forge_schema::{CheckStatusData, Diagnostic, DoctorCheckData, DoctorData, Severity};

    use super::{
        checkpoint_after_apply, display_repository_path, ensure_generated_state_postdoctor,
        ensure_postcheck_completed, ensure_work_state_can_apply, map_plan_error_app,
        parse_force_blocks, render_postimage, sanitize_text, validate_request, with_apply_report,
    };
    use crate::args::{CiChoice, InitArgs, RunnerChoice};

    #[test]
    fn post_apply_terminal_error_retains_typed_exit_and_apply_report() -> Result<(), Box<dyn Error>>
    {
        let report = ApplyReport {
            written: Vec::new(),
            unwritten: vec![RepoRelativePath::new("AGENTS.md")?],
        };
        let error = AppError::new(
            ExitCode::Interrupted,
            Diagnostic::new(
                "FGE2005",
                Severity::Error,
                "fixture interruption",
                "init result",
                "fixture reason",
                "retry",
            ),
        );

        let error = with_apply_report(error, Some(&report));

        assert_eq!(error.exit_code(), ExitCode::Interrupted);
        assert_eq!(error.diagnostic().code.as_str(), "FGE2005");
        assert!(error.diagnostic().why.contains("apply report:"));
        assert!(error.diagnostic().why.contains("unwritten=[AGENTS.md]"));
        Ok(())
    }

    #[test]
    fn generated_state_postdoctor_rejects_only_critical_generated_checks()
    -> Result<(), Box<dyn Error>> {
        let report = apply_report_fixture()?;
        for id in ["state.layout", "adapters.drift", "path.safety"] {
            let doctor = doctor_data(vec![doctor_check(id, CheckStatusData::Fail)]);
            let failure = match ensure_generated_state_postdoctor(&doctor, &report) {
                Ok(()) => {
                    return Err(format!("critical post-doctor failure `{id}` was accepted").into());
                }
                Err(failure) => failure,
            };
            let (error, observed_report) = failure.into_parts();
            assert_eq!(error.exit_code(), ExitCode::Internal);
            assert_eq!(error.diagnostic().code.as_str(), "FGE0215");
            assert_eq!(error.diagnostic().location, "init post-doctor");
            assert!(
                error
                    .diagnostic()
                    .why
                    .contains(&format!("failed checks: {id}"))
            );
            assert_eq!(observed_report, Some(report.clone()));
        }

        let non_terminal = doctor_data(vec![
            doctor_check("state.layout", CheckStatusData::Pass),
            doctor_check("adapters.drift", CheckStatusData::Unknown),
            doctor_check("path.safety", CheckStatusData::Pass),
            doctor_check("ci.visible", CheckStatusData::Fail),
        ]);
        ensure_generated_state_postdoctor(&non_terminal, &report)?;

        let ordered = doctor_data(vec![
            doctor_check("state.layout", CheckStatusData::Fail),
            doctor_check("adapters.drift", CheckStatusData::Fail),
            doctor_check("path.safety", CheckStatusData::Fail),
        ]);
        let failure = match ensure_generated_state_postdoctor(&ordered, &report) {
            Ok(()) => return Err("multiple critical post-doctor failures were accepted".into()),
            Err(failure) => failure,
        };
        assert!(
            failure
                .into_parts()
                .0
                .diagnostic()
                .why
                .contains("failed checks: state.layout, adapters.drift, path.safety")
        );
        Ok(())
    }

    #[test]
    fn post_apply_completion_and_checkpoints_preserve_write_progress() -> Result<(), Box<dyn Error>>
    {
        let report = apply_report_fixture()?;
        ensure_postcheck_completed(ModelDetectionCompletion::Complete, &report)?;
        ensure_postcheck_completed(ModelDetectionCompletion::Partial, &report)?;

        for (completion, exit_code, code) in [
            (
                ModelDetectionCompletion::TimedOut,
                ExitCode::Timeout,
                "FGE2207",
            ),
            (
                ModelDetectionCompletion::Interrupted,
                ExitCode::Interrupted,
                "FGE2208",
            ),
        ] {
            let failure = match ensure_postcheck_completed(completion, &report) {
                Ok(()) => {
                    return Err(format!("terminal post-check `{completion:?}` was accepted").into());
                }
                Err(failure) => failure,
            };
            assert_post_apply_failure(failure, &report, exit_code, code)?;
        }

        let expired = OperationBudget::until(Instant::now(), Arc::new(AtomicBool::new(false)));
        let failure = match checkpoint_after_apply(&expired, "fixture checkpoint", &report) {
            Ok(()) => return Err("expired post-apply checkpoint was accepted".into()),
            Err(failure) => failure,
        };
        assert_post_apply_failure(failure, &report, ExitCode::Timeout, "FGE2004")?;

        let cancellation = Arc::new(AtomicBool::new(false));
        let interrupted = OperationBudget::unlimited(Arc::clone(&cancellation));
        cancellation.store(true, Ordering::Release);
        let failure = match checkpoint_after_apply(&interrupted, "fixture checkpoint", &report) {
            Ok(()) => return Err("interrupted post-apply checkpoint was accepted".into()),
            Err(failure) => failure,
        };
        assert_post_apply_failure(failure, &report, ExitCode::Interrupted, "FGE2005")?;
        Ok(())
    }

    fn assert_post_apply_failure(
        failure: super::InitFailure,
        report: &ApplyReport,
        exit_code: ExitCode,
        code: &str,
    ) -> Result<(), Box<dyn Error>> {
        let (error, observed_report) = failure.into_parts();
        assert_eq!(error.exit_code(), exit_code);
        assert_eq!(error.diagnostic().code.as_str(), code);
        assert!(error.diagnostic().why.contains("apply report:"));
        assert_eq!(observed_report.as_ref(), Some(report));
        Ok(())
    }

    fn apply_report_fixture() -> Result<ApplyReport, Box<dyn Error>> {
        Ok(ApplyReport {
            written: Vec::new(),
            unwritten: vec![RepoRelativePath::new("AGENTS.md")?],
        })
    }

    fn doctor_data(checks: Vec<DoctorCheckData>) -> DoctorData {
        DoctorData {
            overall: CheckStatusData::Unknown,
            checks,
            tool_versions: std::collections::BTreeMap::new(),
            assumptions: Vec::new(),
        }
    }

    fn doctor_check(id: &str, status: CheckStatusData) -> DoctorCheckData {
        DoctorCheckData {
            id: String::from(id),
            status,
            skip_reason: None,
            detail: String::from("fixture detail"),
            next: String::from("fixture next action"),
        }
    }

    #[test]
    fn force_blocks_accept_only_owned_ids_and_reject_duplicates() -> Result<(), Box<dyn Error>> {
        let values = vec![
            String::from("project-index"),
            String::from("claude-pointer"),
        ];
        let parsed = parse_force_blocks(&values)?;
        assert_eq!(
            parsed,
            [
                ManagedBlockKind::ProjectIndex,
                ManagedBlockKind::ClaudePointer
            ]
        );

        let unknown = parse_force_blocks(&[String::from("agents-index")]);
        match unknown {
            Ok(_) => return Err("unknown block id was accepted".into()),
            Err(error) => assert_eq!(error.into_parts().0.exit_code(), ExitCode::Usage),
        }
        let duplicate =
            parse_force_blocks(&[String::from("project-index"), String::from("project-index")]);
        match duplicate {
            Ok(_) => return Err("duplicate block id was accepted".into()),
            Err(error) => assert_eq!(error.into_parts().0.exit_code(), ExitCode::Usage),
        }
        Ok(())
    }

    #[test]
    fn apply_state_gate_allows_only_explicit_safe_cases() -> Result<(), Box<dyn Error>> {
        ensure_work_state_can_apply(WorkState::Clean, false)?;
        ensure_work_state_can_apply(WorkState::Dirty, true)?;
        ensure_work_state_can_apply(WorkState::Unborn, true)?;

        for state in [WorkState::Dirty, WorkState::Unborn] {
            match ensure_work_state_can_apply(state, false) {
                Ok(()) => return Err(format!("{state:?} was accepted without opt-in").into()),
                Err(error) => {
                    assert_eq!(error.into_parts().0.exit_code(), ExitCode::EnvironmentUnmet);
                }
            }
        }
        for state in [
            WorkState::Conflicted,
            WorkState::Merging,
            WorkState::Rebasing,
            WorkState::Corrupt,
            WorkState::Unknown,
        ] {
            match ensure_work_state_can_apply(state, true) {
                Ok(()) => return Err(format!("unsafe state {state:?} was accepted").into()),
                Err(error) => {
                    assert_eq!(error.into_parts().0.exit_code(), ExitCode::EnvironmentUnmet);
                }
            }
        }
        Ok(())
    }

    #[test]
    fn runner_is_available_while_unavailable_ci_is_not_ignored() -> Result<(), Box<dyn Error>> {
        let mut args = init_args();
        args.with_runner = Some(RunnerChoice::Just);
        validate_request(&args)?;

        args.with_ci = Some(CiChoice::Github);
        match validate_request(&args) {
            Ok(()) => return Err("unavailable CI generation was ignored".into()),
            Err(error) => {
                assert_eq!(error.into_parts().0.exit_code(), ExitCode::EnvironmentUnmet);
            }
        }
        Ok(())
    }

    #[test]
    fn unsupported_runner_has_an_actionable_platform_diagnostic() -> Result<(), Box<dyn Error>> {
        let error = map_plan_error_app(
            PlanError::RunnerRender {
                path: RepoRelativePath::new("Makefile")?,
                source: RunnerRenderError::UnsupportedPlatform {
                    runner: RunnerTarget::Make,
                },
            },
            "init plan",
        );
        let diagnostic = error.diagnostic();

        assert_eq!(error.exit_code(), ExitCode::EnvironmentUnmet);
        assert_eq!(diagnostic.code.as_str(), "FGE2229");
        assert_eq!(
            diagnostic.what,
            "the explicit runner is not supported on this platform"
        );
        assert_eq!(diagnostic.location, "Makefile");
        assert_eq!(
            diagnostic.why,
            "the explicit `make` runner recipe is not portable on this platform"
        );
        assert_eq!(
            diagnostic.next,
            "select --with-runner task on Windows, or keep using the reported project-native commands"
        );
        Ok(())
    }

    #[test]
    fn human_text_escapes_terminal_control_characters() {
        assert_eq!(sanitize_text("safe\u{1b}[31m"), "safe\\u{1b}[31m");
        assert_eq!(
            display_repository_path(std::path::Path::new("dir/\u{1b}[31m")),
            "dir/\\u{1b}[31m"
        );
    }

    #[test]
    fn postimage_preview_represents_trailing_newlines() {
        let mut output = String::new();
        render_postimage(&mut output, b"first\nsecond\n");

        assert_eq!(output, "      | first\\u{a}\n      | second\\u{a}\n");
    }

    fn init_args() -> InitArgs {
        InitArgs {
            dry_run: false,
            apply: false,
            allow_dirty: false,
            with_runner: None,
            with_ci: None,
            adapter: Vec::new(),
            force_block: Vec::new(),
        }
    }
}
