//! Bounded, argv-only Rust workspace detection and conservative default command plans.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use forge_core::domain::CommandEnforcement;
use forge_core::ports::{
    EnvPolicy, ExecSpec, FileSystemPort, Hasher, OutputPolicy, ProcessErrorKind,
    ProcessObservation, ProcessPort, StdinPolicy,
};
use forge_core::{
    BoundedText, CommandSource, CommandSpec, Confidence, CoverageDimension, Intent, Inventory,
    InventoryKind, Mutability, NetworkIntent, OperationControl, OperationControlError, PathKind,
    ProjectKind, ProjectModel, ProjectUnit, Provenance, RelativePathError, RepoRelativePath,
    ToolchainInfo, UnitEdge, UnlimitedOperationControl,
};
use serde::Deserialize;
use serde_json::Value;

use crate::resolution::{CommandPlanCandidate, InvalidCommandPlanCandidate};

const RUST_UNIT_ID_DOMAIN: &[u8] = b"forge.rust-unit-id/v1";
const RUST_PACKAGE_ID_KIND: &[u8] = b"package";
const RUST_WORKSPACE_ID_KIND: &[u8] = b"workspace";
const CARGO_METADATA_CAPTURE_LIMIT_BYTES: usize = 4 * 1024 * 1024;
const RUST_LINT_SIGNAL_MAX_BYTES: u64 = forge_core::inventory::DEFAULT_MAX_TEXT_FILE_BYTES;
const RUST_FORMAT_COVERAGE: &str = "rust-format";
const RUST_COMPILE_COVERAGE: &str = "rust-compile";
const RUST_LINT_COVERAGE: &str = "rust-lint";
const RUST_UNIT_TEST_COVERAGE: &str = "rust-unit-test";
const RUST_LOCAL_INTEGRATION_TEST_COVERAGE: &str = "rust-integration-test-local";
const RUST_BUILD_COVERAGE: &str = "rust-build";
const RUST_EXAMPLES_COMPILE_COVERAGE: &str = "rust-examples-compile";
const RUST_BENCHES_COMPILE_COVERAGE: &str = "rust-benches-compile";
const RUST_CROSS_TARGET_COVERAGE: &str = "rust-cross-target";
const RUST_PERFORMANCE_COVERAGE: &str = "rust-performance";

#[cfg(unix)]
const NATIVE_PATH_ENCODING: &[u8] = b"unix-bytes";
#[cfg(windows)]
const NATIVE_PATH_ENCODING: &[u8] = b"windows-wide";
#[cfg(not(any(unix, windows)))]
const NATIVE_PATH_ENCODING: &[u8] = b"utf8-lossy";

#[derive(Debug, Default, Clone, Copy)]
pub struct RustProvider;

/// Declares the complete Rust-provider coverage surface for a detected project model.
///
/// Standard dimensions preserve the cross-language summary. Provider-qualified custom dimensions
/// prevent a passing Go command in a mixed repository from being mistaken for Rust coverage. A
/// model without a detected Rust unit has no Rust expectations; incomplete detection remains
/// represented by the model's existing typed completion and assumptions rather than filename
/// inference here.
#[must_use]
pub fn rust_coverage_expectations(model: &ProjectModel) -> BTreeSet<CoverageDimension> {
    rust_coverage_expectations_for_units(&model.units)
}

fn rust_coverage_expectations_for_units(units: &[ProjectUnit]) -> BTreeSet<CoverageDimension> {
    let has_rust_unit = units.iter().any(|unit| {
        unit.language.as_str() == "rust"
            && matches!(
                &unit.kind,
                ProjectKind::RustPackage | ProjectKind::CargoWorkspace
            )
    });
    if !has_rust_unit {
        return BTreeSet::new();
    }
    BTreeSet::from([
        CoverageDimension::Format,
        CoverageDimension::Compile,
        CoverageDimension::Lint,
        CoverageDimension::UnitTest,
        CoverageDimension::IntegrationTest,
        CoverageDimension::Build,
        rust_custom_coverage(RUST_FORMAT_COVERAGE),
        rust_custom_coverage(RUST_COMPILE_COVERAGE),
        rust_custom_coverage(RUST_LINT_COVERAGE),
        rust_custom_coverage(RUST_UNIT_TEST_COVERAGE),
        rust_custom_coverage(RUST_LOCAL_INTEGRATION_TEST_COVERAGE),
        rust_custom_coverage(RUST_BUILD_COVERAGE),
        rust_custom_coverage(RUST_EXAMPLES_COMPILE_COVERAGE),
        rust_custom_coverage(RUST_BENCHES_COMPILE_COVERAGE),
        rust_custom_coverage(RUST_CROSS_TARGET_COVERAGE),
        rust_custom_coverage(RUST_PERFORMANCE_COVERAGE),
    ])
}

fn rust_custom_coverage(name: &str) -> CoverageDimension {
    CoverageDimension::Custom(name.to_owned())
}

/// Port-bearing inputs required for one read-only Rust discovery pass.
pub struct RustDetectionContext<'a> {
    pub repository_root: &'a Path,
    pub inventory: &'a Inventory,
    pub filesystem: &'a dyn FileSystemPort,
    pub process: &'a dyn ProcessPort,
    pub hasher: &'a dyn Hasher,
    pub metadata_timeout: Duration,
}

impl fmt::Debug for RustDetectionContext<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RustDetectionContext")
            .field("repository_root", &self.repository_root)
            .field("inventory_entries", &self.inventory.entries.len())
            .field("inventory_skips", &self.inventory.skipped.len())
            .field("metadata_timeout", &self.metadata_timeout)
            .finish_non_exhaustive()
    }
}

/// Result of Rust discovery, including every metadata probe's typed completion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustDetectionResult {
    pub units: Vec<ProjectUnit>,
    pub command_plan_fragments: Vec<CommandPlanCandidate>,
    pub metadata_completions: Vec<CargoMetadataCompletion>,
    pub provenance: Vec<Provenance>,
    pub confidence: Confidence,
    /// Provider-level stop observed outside any one Cargo process completion.
    pub control_error: Option<OperationControlError>,
}

/// Stable outcome category for one Cargo metadata probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CargoMetadataOutcome {
    Succeeded,
    ManifestNotRegular {
        kind: PathKind,
    },
    ManifestProbeFailed {
        io_kind: io::ErrorKind,
    },
    ProcessFailed {
        kind: ProcessErrorKind,
        io_kind: io::ErrorKind,
    },
    ExitFailure,
    TimedOut,
    Interrupted,
    OutputTruncated,
    InvalidOutput(CargoMetadataInvalidReason),
}

/// Validation failure for untrusted `cargo metadata` JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CargoMetadataInvalidReason {
    Json {
        line: usize,
        column: usize,
    },
    UnsupportedFormatVersion {
        found: u32,
    },
    ResolveWasNotNull,
    PathWasNotAbsolute {
        field: &'static str,
    },
    PathEscapedRepository {
        field: &'static str,
    },
    InvalidRelativePath {
        field: &'static str,
        source: RelativePathError,
    },
    MetadataManifestNotRegular {
        field: &'static str,
        kind: PathKind,
    },
    MetadataManifestProbeFailed {
        field: &'static str,
        io_kind: io::ErrorKind,
    },
    EmptyWorkspace,
    DuplicatePackageId,
    DuplicatePackageManifest,
    DuplicateWorkspaceMember,
    MissingWorkspaceMember,
    PackageWasNotWorkspaceMember,
    DefaultMemberWasNotWorkspaceMember,
    CandidateWasNotInWorkspace,
    ConflictingDuplicateWorkspace,
}

/// Process facts retained without storing potentially sensitive subprocess output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoMetadataCompletion {
    pub manifest: RepoRelativePath,
    pub outcome: CargoMetadataOutcome,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub interrupted: bool,
    pub stdout_total_bytes: u64,
    pub stderr_total_bytes: u64,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub duration: Duration,
}

/// Fatal provider input or internal plan-construction error.
#[derive(Debug)]
pub enum RustDetectionError {
    RepositoryRootNotAbsolute(PathBuf),
    RepositoryRootNotNormalized(PathBuf),
    InvalidInventoryPath {
        path: PathBuf,
        source: RelativePathError,
    },
    InvalidCommandPlan(InvalidCommandPlanCandidate),
    UnitIdCollision {
        unit_id: String,
    },
}

impl fmt::Display for RustDetectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RepositoryRootNotAbsolute(path) => {
                write!(
                    formatter,
                    "Rust detection repository root is not absolute: {path:?}"
                )
            }
            Self::RepositoryRootNotNormalized(path) => write!(
                formatter,
                "Rust detection repository root is not lexically normalized: {path:?}"
            ),
            Self::InvalidInventoryPath { path, source } => write!(
                formatter,
                "Rust manifest inventory path {path:?} is invalid: {source}"
            ),
            Self::InvalidCommandPlan(error) => error.fmt(formatter),
            Self::UnitIdCollision { unit_id } => {
                write!(formatter, "Rust unit identifier collision for {unit_id}")
            }
        }
    }
}

impl Error for RustDetectionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidInventoryPath { source, .. } => Some(source),
            Self::InvalidCommandPlan(error) => Some(error),
            Self::RepositoryRootNotAbsolute(_)
            | Self::RepositoryRootNotNormalized(_)
            | Self::UnitIdCollision { .. } => None,
        }
    }
}

impl RustProvider {
    /// Detects Rust units through bounded Cargo metadata probes and static fallback.
    pub fn detect_project(
        self,
        context: &RustDetectionContext<'_>,
    ) -> Result<RustDetectionResult, RustDetectionError> {
        detect_rust_project(context)
    }

    /// Detects Rust units while sharing one operation-wide deadline with later providers.
    pub fn detect_project_controlled(
        self,
        context: &RustDetectionContext<'_>,
        control: &dyn OperationControl,
    ) -> Result<RustDetectionResult, RustDetectionError> {
        detect_rust_project_controlled(context, control)
    }
}

/// Detects every inventoried `Cargo.toml` without invoking a shell or losing failed manifests.
pub fn detect_rust_project(
    context: &RustDetectionContext<'_>,
) -> Result<RustDetectionResult, RustDetectionError> {
    detect_rust_project_controlled(context, &UnlimitedOperationControl)
}

/// Detects every manifest under one total budget without inventing facts for unstarted probes.
pub fn detect_rust_project_controlled(
    context: &RustDetectionContext<'_>,
    control: &dyn OperationControl,
) -> Result<RustDetectionResult, RustDetectionError> {
    validate_repository_root(context.repository_root)?;
    let manifests = cargo_manifest_candidates(context.inventory)?;
    let mut completions = Vec::with_capacity(manifests.len());
    let mut workspaces = BTreeMap::<RepoRelativePath, ValidatedWorkspace>::new();
    let mut fallback_manifests = BTreeSet::new();
    let mut completed_units = Vec::new();

    for manifest in manifests {
        let permit = match control.checkpoint() {
            Ok(permit) => permit,
            Err(error) => {
                return Ok(control_stopped_rust_result(
                    completed_units,
                    completions,
                    error,
                ));
            }
        };
        let fallback_unit = static_package_unit(&manifest, context.hasher);
        let (mut completion, workspace) =
            probe_manifest(context, &manifest, permit.cap(context.metadata_timeout));
        if workspace.is_none() {
            completed_units.push(fallback_unit.clone());
        }
        if let Err(error) = control.checkpoint() {
            completions.push(completion);
            return Ok(control_stopped_rust_result(
                completed_units,
                completions,
                error,
            ));
        }
        if let Some(workspace) = workspace {
            match workspaces.get(&workspace.root) {
                Some(existing) if existing != &workspace => {
                    completion.outcome = CargoMetadataOutcome::InvalidOutput(
                        CargoMetadataInvalidReason::ConflictingDuplicateWorkspace,
                    );
                    fallback_manifests.insert(manifest.clone());
                    completed_units.push(fallback_unit);
                }
                Some(_) => {}
                None => {
                    completed_units.extend(units_from_workspace(&workspace, context.hasher));
                    workspaces.insert(workspace.root.clone(), workspace);
                }
            }
        } else {
            fallback_manifests.insert(manifest.clone());
        }
        completions.push(completion);
    }

    let mut retained_fallbacks = BTreeSet::new();
    for manifest in fallback_manifests {
        if let Err(error) = control.checkpoint() {
            return Ok(control_stopped_rust_result(
                completed_units,
                completions,
                error,
            ));
        }
        let mut covered = false;
        for workspace in workspaces.values() {
            if let Err(error) = control.checkpoint() {
                return Ok(control_stopped_rust_result(
                    completed_units,
                    completions,
                    error,
                ));
            }
            if workspace.manifest == manifest {
                covered = true;
                break;
            }
            for package in &workspace.packages {
                if let Err(error) = control.checkpoint() {
                    return Ok(control_stopped_rust_result(
                        completed_units,
                        completions,
                        error,
                    ));
                }
                if package.manifest == manifest {
                    covered = true;
                    break;
                }
            }
            if covered {
                break;
            }
        }
        if !covered {
            retained_fallbacks.insert(manifest);
        }
    }
    let fallback_manifests = retained_fallbacks;

    let mut units = Vec::new();
    for workspace in workspaces.values() {
        if let Err(error) = control.checkpoint() {
            return Ok(control_stopped_rust_result(units, completions, error));
        }
        units.extend(units_from_workspace(workspace, context.hasher));
    }
    for manifest in &fallback_manifests {
        if let Err(error) = control.checkpoint() {
            return Ok(control_stopped_rust_result(units, completions, error));
        }
        units.push(static_package_unit(manifest, context.hasher));
    }
    if let Err(error) = control.checkpoint() {
        return Ok(control_stopped_rust_result(units, completions, error));
    }
    ensure_unique_unit_ids(&units)?;
    units.sort_by(|left, right| {
        left.root
            .cmp(&right.root)
            .then_with(|| left.manifest.cmp(&right.manifest))
            .then_with(|| left.id.cmp(&right.id))
    });
    if let Err(error) = control.checkpoint() {
        return Ok(control_stopped_rust_result(units, completions, error));
    }

    let command_plan_fragments =
        match rust_default_plan_fragments_with_lint_signals_controlled(&units, context, control) {
            Ok(plans) => plans,
            Err(RustPlanBuildError::Control(error)) => {
                return Ok(control_stopped_rust_result(units, completions, error));
            }
            Err(RustPlanBuildError::Invalid(error)) => {
                return Err(RustDetectionError::InvalidCommandPlan(error));
            }
        };
    let confidence = provider_confidence(context.inventory, &completions);
    let mut provenance = vec![Provenance {
        rule_id: String::from("rust.inventory-and-metadata.v1"),
        source_path: None,
        source_range: None,
        detail: format!(
            "inspected {} unique Cargo manifests; {} metadata probes succeeded and {} used static fallback",
            completions.len(),
            completions
                .iter()
                .filter(|completion| completion.outcome == CargoMetadataOutcome::Succeeded)
                .count(),
            fallback_manifests.len()
        ),
    }];
    if !context.inventory.skipped.is_empty() {
        provenance.push(Provenance {
            rule_id: String::from("rust.inventory-partial.v1"),
            source_path: None,
            source_range: None,
            detail: String::from(
                "repository inventory was partial, so absence of additional Cargo manifests is unknown",
            ),
        });
    }
    provenance.sort();

    Ok(RustDetectionResult {
        units,
        command_plan_fragments,
        metadata_completions: completions,
        provenance,
        confidence,
        control_error: None,
    })
}

fn control_stopped_rust_result(
    units: Vec<ProjectUnit>,
    metadata_completions: Vec<CargoMetadataCompletion>,
    error: OperationControlError,
) -> RustDetectionResult {
    RustDetectionResult {
        units,
        command_plan_fragments: Vec::new(),
        provenance: vec![Provenance {
            rule_id: String::from("rust.operation-control.v1"),
            source_path: None,
            source_range: None,
            detail: format!(
                "Rust provider stopped after {} completed Cargo metadata probe(s): {error}",
                metadata_completions.len()
            ),
        }],
        metadata_completions,
        confidence: Confidence::Unknown,
        control_error: Some(error),
    }
}

fn validate_repository_root(root: &Path) -> Result<(), RustDetectionError> {
    if !root.is_absolute() {
        return Err(RustDetectionError::RepositoryRootNotAbsolute(
            root.to_path_buf(),
        ));
    }
    if root
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(RustDetectionError::RepositoryRootNotNormalized(
            root.to_path_buf(),
        ));
    }
    Ok(())
}

fn cargo_manifest_candidates(
    inventory: &Inventory,
) -> Result<Vec<RepoRelativePath>, RustDetectionError> {
    let mut manifests = BTreeSet::new();
    for entry in &inventory.entries {
        if entry.path.file_name() != Some(OsStr::new("Cargo.toml")) {
            continue;
        }
        let path = RepoRelativePath::new(&entry.path).map_err(|source| {
            RustDetectionError::InvalidInventoryPath {
                path: entry.path.clone(),
                source,
            }
        })?;
        manifests.insert(path);
    }
    Ok(manifests.into_iter().collect())
}

fn probe_manifest(
    context: &RustDetectionContext<'_>,
    manifest: &RepoRelativePath,
    timeout: Duration,
) -> (CargoMetadataCompletion, Option<ValidatedWorkspace>) {
    match context
        .filesystem
        .path_kind(context.repository_root, manifest)
    {
        Ok(PathKind::File) => {}
        Ok(kind) => {
            return (
                empty_completion(manifest, CargoMetadataOutcome::ManifestNotRegular { kind }),
                None,
            );
        }
        Err(error) => {
            return (
                empty_completion(
                    manifest,
                    CargoMetadataOutcome::ManifestProbeFailed {
                        io_kind: error.kind(),
                    },
                ),
                None,
            );
        }
    }

    let spec = cargo_metadata_exec_spec(manifest, timeout);
    match context.process.run(&spec) {
        Ok(observation) => completion_from_observation(context, manifest, observation),
        Err(error) => (
            empty_completion(
                manifest,
                CargoMetadataOutcome::ProcessFailed {
                    kind: error.kind(),
                    io_kind: error.io_kind(),
                },
            ),
            None,
        ),
    }
}

fn cargo_metadata_exec_spec(manifest: &RepoRelativePath, timeout: Duration) -> ExecSpec {
    let cwd = manifest
        .as_path()
        .parent()
        .and_then(|parent| RepoRelativePath::new(parent).ok())
        .unwrap_or_else(RepoRelativePath::root);
    let manifest_argument = manifest
        .as_path()
        .file_name()
        .map_or_else(|| OsString::from("Cargo.toml"), OsString::from);
    let env = EnvPolicy::minimal_with_overrides(BTreeMap::from([
        (OsString::from("RUSTUP_AUTO_INSTALL"), OsString::from("0")),
        (OsString::from("CARGO_NET_OFFLINE"), OsString::from("true")),
    ]));
    ExecSpec {
        program: OsString::from("cargo"),
        args: vec![
            OsString::from("metadata"),
            OsString::from("--format-version=1"),
            OsString::from("--no-deps"),
            OsString::from("--manifest-path"),
            manifest_argument,
        ],
        cwd,
        env,
        timeout,
        stdin: StdinPolicy::Closed,
        stdout: OutputPolicy::CaptureBounded {
            max_bytes: CARGO_METADATA_CAPTURE_LIMIT_BYTES,
        },
        stderr: OutputPolicy::CaptureBounded {
            max_bytes: CARGO_METADATA_CAPTURE_LIMIT_BYTES,
        },
        mutability: Mutability::ReadOnly,
        network: NetworkIntent::OfflineRequested,
        concurrency_key: Some(String::from("cargo-metadata")),
    }
}

fn completion_from_observation(
    context: &RustDetectionContext<'_>,
    manifest: &RepoRelativePath,
    observation: ProcessObservation,
) -> (CargoMetadataCompletion, Option<ValidatedWorkspace>) {
    let outcome = if observation.timed_out {
        CargoMetadataOutcome::TimedOut
    } else if observation.interrupted {
        CargoMetadataOutcome::Interrupted
    } else if observation.exit_code != Some(0) || observation.signal.is_some() {
        CargoMetadataOutcome::ExitFailure
    } else if observation.stdout_truncated {
        CargoMetadataOutcome::OutputTruncated
    } else {
        match parse_and_validate_metadata(
            &observation.stdout,
            context.repository_root,
            manifest,
            context.filesystem,
        ) {
            Ok(workspace) => {
                let completion =
                    observed_completion(manifest, CargoMetadataOutcome::Succeeded, &observation);
                return (completion, Some(workspace));
            }
            Err(reason) => CargoMetadataOutcome::InvalidOutput(reason),
        }
    };
    (observed_completion(manifest, outcome, &observation), None)
}

fn empty_completion(
    manifest: &RepoRelativePath,
    outcome: CargoMetadataOutcome,
) -> CargoMetadataCompletion {
    CargoMetadataCompletion {
        manifest: manifest.clone(),
        outcome,
        exit_code: None,
        signal: None,
        timed_out: false,
        interrupted: false,
        stdout_total_bytes: 0,
        stderr_total_bytes: 0,
        stdout_truncated: false,
        stderr_truncated: false,
        duration: Duration::ZERO,
    }
}

fn observed_completion(
    manifest: &RepoRelativePath,
    outcome: CargoMetadataOutcome,
    observation: &ProcessObservation,
) -> CargoMetadataCompletion {
    CargoMetadataCompletion {
        manifest: manifest.clone(),
        outcome,
        exit_code: observation.exit_code,
        signal: observation.signal,
        timed_out: observation.timed_out,
        interrupted: observation.interrupted,
        stdout_total_bytes: observation.stdout_total_bytes,
        stderr_total_bytes: observation.stderr_total_bytes,
        stdout_truncated: observation.stdout_truncated,
        stderr_truncated: observation.stderr_truncated,
        duration: observation.duration,
    }
}

#[derive(Debug, Deserialize)]
struct CargoMetadataDocument {
    packages: Vec<CargoPackageDocument>,
    workspace_members: Vec<String>,
    workspace_default_members: Vec<String>,
    resolve: Value,
    workspace_root: PathBuf,
    #[serde(rename = "version")]
    format_version: u32,
}

#[derive(Debug, Deserialize)]
struct CargoPackageDocument {
    name: String,
    id: String,
    manifest_path: PathBuf,
    #[serde(default)]
    dependencies: Vec<CargoDependencyDocument>,
}

#[derive(Debug, Deserialize)]
struct CargoDependencyDocument {
    path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedWorkspace {
    root: RepoRelativePath,
    manifest: RepoRelativePath,
    packages: Vec<ValidatedPackage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedPackage {
    cargo_id: String,
    name: String,
    root: RepoRelativePath,
    manifest: RepoRelativePath,
    dependency_roots: Vec<RepoRelativePath>,
}

fn parse_and_validate_metadata(
    bytes: &[u8],
    repository_root: &Path,
    candidate: &RepoRelativePath,
    filesystem: &dyn FileSystemPort,
) -> Result<ValidatedWorkspace, CargoMetadataInvalidReason> {
    let document: CargoMetadataDocument =
        serde_json::from_slice(bytes).map_err(|error| CargoMetadataInvalidReason::Json {
            line: error.line(),
            column: error.column(),
        })?;
    if document.format_version != 1 {
        return Err(CargoMetadataInvalidReason::UnsupportedFormatVersion {
            found: document.format_version,
        });
    }
    if document.resolve != Value::Null {
        return Err(CargoMetadataInvalidReason::ResolveWasNotNull);
    }
    if document.packages.is_empty() || document.workspace_members.is_empty() {
        return Err(CargoMetadataInvalidReason::EmptyWorkspace);
    }

    let workspace_root = repository_relative_absolute_path(
        repository_root,
        &document.workspace_root,
        "workspace_root",
    )?;
    let workspace_manifest = RepoRelativePath::new(
        workspace_root.as_path().join(OsStr::new("Cargo.toml")),
    )
    .map_err(|source| CargoMetadataInvalidReason::InvalidRelativePath {
        field: "workspace_root/Cargo.toml",
        source,
    })?;
    validate_metadata_manifest(
        filesystem,
        repository_root,
        &workspace_manifest,
        "workspace_root/Cargo.toml",
    )?;

    let mut cargo_ids = BTreeSet::new();
    let mut manifests = BTreeSet::new();
    let mut packages = Vec::with_capacity(document.packages.len());
    for package in document.packages {
        if !cargo_ids.insert(package.id.clone()) {
            return Err(CargoMetadataInvalidReason::DuplicatePackageId);
        }
        let manifest = repository_relative_absolute_path(
            repository_root,
            &package.manifest_path,
            "packages[].manifest_path",
        )?;
        if !manifests.insert(manifest.clone()) {
            return Err(CargoMetadataInvalidReason::DuplicatePackageManifest);
        }
        validate_metadata_manifest(
            filesystem,
            repository_root,
            &manifest,
            "packages[].manifest_path",
        )?;
        let root = manifest
            .as_path()
            .parent()
            .and_then(|parent| RepoRelativePath::new(parent).ok())
            .unwrap_or_else(RepoRelativePath::root);
        let mut dependency_roots = Vec::new();
        for dependency in package.dependencies {
            if let Some(path) = dependency.path {
                dependency_roots.push(repository_relative_absolute_path(
                    repository_root,
                    &path,
                    "packages[].dependencies[].path",
                )?);
            }
        }
        dependency_roots.sort();
        dependency_roots.dedup();
        packages.push(ValidatedPackage {
            cargo_id: package.id,
            name: package.name,
            root,
            manifest,
            dependency_roots,
        });
    }

    let workspace_members: BTreeSet<_> = document.workspace_members.iter().collect();
    if workspace_members.len() != document.workspace_members.len() {
        return Err(CargoMetadataInvalidReason::DuplicateWorkspaceMember);
    }
    if workspace_members
        .iter()
        .any(|member| !cargo_ids.contains(member.as_str()))
    {
        return Err(CargoMetadataInvalidReason::MissingWorkspaceMember);
    }
    if cargo_ids
        .iter()
        .any(|package| !workspace_members.contains(package))
    {
        return Err(CargoMetadataInvalidReason::PackageWasNotWorkspaceMember);
    }
    if document
        .workspace_default_members
        .iter()
        .any(|member| !workspace_members.contains(member))
    {
        return Err(CargoMetadataInvalidReason::DefaultMemberWasNotWorkspaceMember);
    }
    if candidate != &workspace_manifest
        && !packages
            .iter()
            .any(|package| &package.manifest == candidate)
    {
        return Err(CargoMetadataInvalidReason::CandidateWasNotInWorkspace);
    }
    packages.sort_by(|left, right| left.manifest.cmp(&right.manifest));

    Ok(ValidatedWorkspace {
        root: workspace_root,
        manifest: workspace_manifest,
        packages,
    })
}

fn repository_relative_absolute_path(
    repository_root: &Path,
    absolute: &Path,
    field: &'static str,
) -> Result<RepoRelativePath, CargoMetadataInvalidReason> {
    if !absolute.is_absolute() {
        return Err(CargoMetadataInvalidReason::PathWasNotAbsolute { field });
    }
    let relative = absolute
        .strip_prefix(repository_root)
        .map_err(|_| CargoMetadataInvalidReason::PathEscapedRepository { field })?;
    RepoRelativePath::new(relative)
        .map_err(|source| CargoMetadataInvalidReason::InvalidRelativePath { field, source })
}

fn validate_metadata_manifest(
    filesystem: &dyn FileSystemPort,
    repository_root: &Path,
    manifest: &RepoRelativePath,
    field: &'static str,
) -> Result<(), CargoMetadataInvalidReason> {
    match filesystem.path_kind(repository_root, manifest) {
        Ok(PathKind::File) => Ok(()),
        Ok(kind) => Err(CargoMetadataInvalidReason::MetadataManifestNotRegular { field, kind }),
        Err(error) => Err(CargoMetadataInvalidReason::MetadataManifestProbeFailed {
            field,
            io_kind: error.kind(),
        }),
    }
}

fn units_from_workspace(workspace: &ValidatedWorkspace, hasher: &dyn Hasher) -> Vec<ProjectUnit> {
    let aggregate = workspace.packages.len() > 1
        || workspace
            .packages
            .first()
            .is_some_and(|package| package.manifest != workspace.manifest);
    let package_unit_ids: BTreeMap<_, _> = workspace
        .packages
        .iter()
        .map(|package| {
            (
                package.cargo_id.clone(),
                rust_unit_id_value(RUST_PACKAGE_ID_KIND, &package.manifest, hasher),
            )
        })
        .collect();
    let package_roots: BTreeMap<_, _> = workspace
        .packages
        .iter()
        .filter_map(|package| {
            package_unit_ids
                .get(&package.cargo_id)
                .map(|unit_id| (package.root.clone(), unit_id.clone()))
        })
        .collect();
    let mut units = Vec::new();

    if aggregate {
        let provenance = metadata_provenance(
            &workspace.manifest,
            "validated Cargo metadata grouped repository-confined workspace members",
        );
        units.push(ProjectUnit {
            id: rust_unit_id_value(RUST_WORKSPACE_ID_KIND, &workspace.manifest, hasher).into(),
            display_name: format!("Cargo workspace at {}", workspace.root.as_path().display()),
            language: "rust".into(),
            kind: ProjectKind::CargoWorkspace,
            root: workspace.root.clone(),
            manifest: workspace.manifest.clone(),
            workspace_root: None,
            members: package_unit_ids.values().cloned().map(Into::into).collect(),
            dependencies: Vec::new(),
            toolchain: ToolchainInfo::unknown(vec![toolchain_unknown_provenance(
                &workspace.manifest,
            )]),
            provenance: vec![provenance],
            confidence: Confidence::High,
        });
    }

    for package in &workspace.packages {
        let provenance = metadata_provenance(
            &package.manifest,
            "validated Cargo metadata identified this Rust package",
        );
        let dependencies = package
            .dependency_roots
            .iter()
            .filter_map(|root| package_roots.get(root))
            .map(|dependency| {
                UnitEdge::new(
                    dependency.clone().into(),
                    vec![metadata_provenance(
                        &package.manifest,
                        "Cargo metadata declared an in-repository path dependency",
                    )],
                    Confidence::High,
                )
            })
            .collect();
        units.push(ProjectUnit {
            id: package_unit_ids[&package.cargo_id].clone().into(),
            display_name: package.name.clone(),
            language: "rust".into(),
            kind: ProjectKind::RustPackage,
            root: package.root.clone(),
            manifest: package.manifest.clone(),
            workspace_root: aggregate.then(|| workspace.root.clone()),
            members: Vec::new(),
            dependencies,
            toolchain: ToolchainInfo::unknown(vec![toolchain_unknown_provenance(
                &package.manifest,
            )]),
            provenance: vec![provenance],
            confidence: Confidence::High,
        });
    }
    units
}

fn static_package_unit(manifest: &RepoRelativePath, hasher: &dyn Hasher) -> ProjectUnit {
    let root = manifest
        .as_path()
        .parent()
        .and_then(|parent| RepoRelativePath::new(parent).ok())
        .unwrap_or_else(RepoRelativePath::root);
    let display_name = if root == RepoRelativePath::root() {
        String::from("Rust package at repository root")
    } else {
        format!("Rust package at {}", root.as_path().display())
    };
    let provenance = Provenance {
        rule_id: String::from("rust.cargo-manifest-static-fallback.v1"),
        source_path: Some(manifest.as_path().into()),
        source_range: None,
        detail: String::from(
            "Cargo.toml was inventoried, but validated metadata was unavailable; workspace and dependency scope remain unknown",
        ),
    };
    ProjectUnit {
        id: rust_unit_id_value(RUST_PACKAGE_ID_KIND, manifest, hasher).into(),
        display_name,
        language: "rust".into(),
        kind: ProjectKind::RustPackage,
        root,
        manifest: manifest.clone(),
        workspace_root: None,
        members: Vec::new(),
        dependencies: Vec::new(),
        toolchain: ToolchainInfo::unknown(vec![toolchain_unknown_provenance(manifest)]),
        provenance: vec![provenance],
        confidence: Confidence::Low,
    }
}

fn metadata_provenance(manifest: &RepoRelativePath, detail: &str) -> Provenance {
    Provenance {
        rule_id: String::from("rust.cargo-metadata-v1"),
        source_path: Some(manifest.as_path().into()),
        source_range: None,
        detail: detail.to_owned(),
    }
}

fn toolchain_unknown_provenance(manifest: &RepoRelativePath) -> Provenance {
    Provenance {
        rule_id: String::from("rust.toolchain-unprobed.v1"),
        source_path: Some(manifest.as_path().into()),
        source_range: None,
        detail: String::from(
            "Cargo metadata does not prove cargo, rustc, target, or project toolchain versions",
        ),
    }
}

fn ensure_unique_unit_ids(units: &[ProjectUnit]) -> Result<(), RustDetectionError> {
    let mut ids = BTreeSet::new();
    for unit in units {
        if !ids.insert(unit.id.as_str()) {
            return Err(RustDetectionError::UnitIdCollision {
                unit_id: unit.id.to_string(),
            });
        }
    }
    Ok(())
}

#[cfg(unix)]
fn rust_unit_id_value(kind: &[u8], path: &RepoRelativePath, hasher: &dyn Hasher) -> String {
    use std::os::unix::ffi::OsStrExt as _;

    rust_unit_id_from_native_path(kind, path.as_path().as_os_str().as_bytes(), hasher)
}

#[cfg(windows)]
fn rust_unit_id_value(kind: &[u8], path: &RepoRelativePath, hasher: &dyn Hasher) -> String {
    use std::os::windows::ffi::OsStrExt as _;

    let native_path: Vec<u8> = path
        .as_path()
        .as_os_str()
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect();
    rust_unit_id_from_native_path(kind, &native_path, hasher)
}

#[cfg(not(any(unix, windows)))]
fn rust_unit_id_value(kind: &[u8], path: &RepoRelativePath, hasher: &dyn Hasher) -> String {
    rust_unit_id_from_native_path(kind, path.as_path().to_string_lossy().as_bytes(), hasher)
}

fn rust_unit_id_from_native_path(kind: &[u8], native_path: &[u8], hasher: &dyn Hasher) -> String {
    let digest = hasher.digest(&[RUST_UNIT_ID_DOMAIN, kind, NATIVE_PATH_ENCODING, native_path]);
    format!("rust:{digest}")
}

fn provider_confidence(
    inventory: &Inventory,
    completions: &[CargoMetadataCompletion],
) -> Confidence {
    if !inventory.skipped.is_empty() {
        return Confidence::Unknown;
    }
    if completions
        .iter()
        .any(|completion| completion.outcome != CargoMetadataOutcome::Succeeded)
    {
        Confidence::Low
    } else {
        Confidence::High
    }
}

/// Builds unit-only Rust defaults while conservatively keeping Clippy advisory.
///
/// The port-bearing detection path can upgrade Clippy to required from bounded repository facts.
/// This compatibility entry point has no filesystem authority and therefore cannot make that
/// stronger claim.
pub fn rust_default_plan_fragments(
    units: &[ProjectUnit],
) -> Result<Vec<CommandPlanCandidate>, InvalidCommandPlanCandidate> {
    rust_plans_for_scopes(rust_command_scopes(units))
}

#[derive(Debug)]
enum RustPlanBuildError {
    Control(OperationControlError),
    Invalid(InvalidCommandPlanCandidate),
}

impl From<OperationControlError> for RustPlanBuildError {
    fn from(error: OperationControlError) -> Self {
        Self::Control(error)
    }
}

impl From<InvalidCommandPlanCandidate> for RustPlanBuildError {
    fn from(error: InvalidCommandPlanCandidate) -> Self {
        Self::Invalid(error)
    }
}

fn rust_default_plan_fragments_with_lint_signals_controlled(
    units: &[ProjectUnit],
    context: &RustDetectionContext<'_>,
    control: &dyn OperationControl,
) -> Result<Vec<CommandPlanCandidate>, RustPlanBuildError> {
    let mut scopes = rust_command_scopes_controlled(units, control)?;
    for scope in &mut scopes {
        control.checkpoint()?;
        scope.clippy = inspect_clippy_signal(context, scope, control)?;
    }
    rust_plans_for_scopes_controlled(&scopes, control)
}

fn rust_command_scopes(units: &[ProjectUnit]) -> Vec<RustCommandScope> {
    let mut scopes: Vec<_> = units
        .iter()
        .filter(|unit| {
            unit.language.as_str() == "rust"
                && (unit.kind == ProjectKind::CargoWorkspace
                    || (unit.kind == ProjectKind::RustPackage && unit.workspace_root.is_none()))
        })
        .map(RustCommandScope::from)
        .collect();
    scopes.sort_by(|left, right| {
        left.root
            .cmp(&right.root)
            .then_with(|| left.unit_id.cmp(&right.unit_id))
    });
    scopes.dedup_by(|left, right| left.unit_id == right.unit_id);
    scopes
}

fn rust_command_scopes_controlled(
    units: &[ProjectUnit],
    control: &dyn OperationControl,
) -> Result<Vec<RustCommandScope>, OperationControlError> {
    let mut scopes = Vec::new();
    for unit in units {
        control.checkpoint()?;
        if unit.language.as_str() == "rust"
            && (unit.kind == ProjectKind::CargoWorkspace
                || (unit.kind == ProjectKind::RustPackage && unit.workspace_root.is_none()))
        {
            scopes.push(RustCommandScope::from(unit));
        }
    }
    control.checkpoint()?;
    scopes.sort_by(|left, right| {
        left.root
            .cmp(&right.root)
            .then_with(|| left.unit_id.cmp(&right.unit_id))
    });
    control.checkpoint()?;
    scopes.dedup_by(|left, right| left.unit_id == right.unit_id);
    Ok(scopes)
}

fn rust_plans_for_scopes(
    scopes: Vec<RustCommandScope>,
) -> Result<Vec<CommandPlanCandidate>, InvalidCommandPlanCandidate> {
    if scopes.is_empty() {
        return Ok(Vec::new());
    }

    [
        Intent::FormatCheck,
        Intent::Format,
        Intent::Check,
        Intent::Test,
    ]
    .into_iter()
    .map(|intent| rust_plan_for_intent(intent, &scopes))
    .collect()
}

fn rust_plans_for_scopes_controlled(
    scopes: &[RustCommandScope],
    control: &dyn OperationControl,
) -> Result<Vec<CommandPlanCandidate>, RustPlanBuildError> {
    if scopes.is_empty() {
        return Ok(Vec::new());
    }
    let mut plans = Vec::new();
    for intent in [
        Intent::FormatCheck,
        Intent::Format,
        Intent::Check,
        Intent::Test,
    ] {
        control.checkpoint()?;
        plans.push(rust_plan_for_intent_controlled(intent, scopes, control)?);
    }
    control.checkpoint()?;
    Ok(plans)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RustClippySignal {
    enforcement: CommandEnforcement,
    decision_complete: bool,
    provenance: Vec<Provenance>,
}

impl RustClippySignal {
    fn compatibility_advisory(manifest: &RepoRelativePath) -> Self {
        Self {
            enforcement: CommandEnforcement::Advisory,
            decision_complete: false,
            provenance: vec![clippy_provenance(
                "rust.clippy-signal.compatibility-advisory.v1",
                Some(manifest),
                "the unit-only compatibility API has no bounded repository facts with which to prove a project Clippy requirement; Clippy remains advisory",
            )],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RustCommandScope {
    unit_id: String,
    root: RepoRelativePath,
    manifest: RepoRelativePath,
    workspace: bool,
    confidence: Confidence,
    clippy: RustClippySignal,
}

impl From<&ProjectUnit> for RustCommandScope {
    fn from(unit: &ProjectUnit) -> Self {
        Self {
            unit_id: unit.id.to_string(),
            root: unit.root.clone(),
            manifest: unit.manifest.clone(),
            workspace: unit.kind == ProjectKind::CargoWorkspace,
            confidence: unit.confidence,
            clippy: RustClippySignal::compatibility_advisory(&unit.manifest),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClippyDeclaration {
    Required,
    NotRequired,
    Unknown,
}

fn inspect_clippy_signal(
    context: &RustDetectionContext<'_>,
    scope: &RustCommandScope,
    control: &dyn OperationControl,
) -> Result<RustClippySignal, OperationControlError> {
    control.checkpoint()?;
    let mut required = false;
    let mut complete = context.inventory.skipped.is_empty();
    let mut provenance = Vec::new();

    match read_lint_signal_text(context, &scope.manifest) {
        Ok(text) => match cargo_manifest_clippy_declaration(&text.bytes) {
            ClippyDeclaration::Required => {
                required = true;
                provenance.push(clippy_provenance(
                    "rust.clippy-signal.cargo-lints.v1",
                    Some(&scope.manifest),
                    "Cargo.toml declares at least one non-allow Clippy lint level, so the default Clippy command is required",
                ));
            }
            ClippyDeclaration::NotRequired => {}
            ClippyDeclaration::Unknown => {
                complete = false;
                provenance.push(clippy_provenance(
                    "rust.clippy-signal.manifest-unknown.v1",
                    Some(&scope.manifest),
                    "Cargo.toml could not be interpreted completely for Clippy enforcement; Clippy remains advisory unless another explicit signal requires it",
                ));
            }
        },
        Err(reason) => {
            complete = false;
            provenance.push(clippy_provenance(
                "rust.clippy-signal.manifest-unknown.v1",
                Some(&scope.manifest),
                reason,
            ));
        }
    }
    control.checkpoint()?;

    let (config_paths, config_inventory_complete) =
        scoped_clippy_config_paths_controlled(context.inventory, &scope.root, control)?;
    complete &= config_inventory_complete;
    for path in config_paths {
        control.checkpoint()?;
        match read_lint_signal_text(context, &path) {
            Ok(text)
                if std::str::from_utf8(&text.bytes)
                    .is_ok_and(|value| value.parse::<toml::Table>().is_ok()) =>
            {
                required = true;
                provenance.push(clippy_provenance(
                    "rust.clippy-signal.config.v1",
                    Some(&path),
                    "a regular, bounded, valid Clippy configuration file is present in this Rust scope, so the default Clippy command is required",
                ));
            }
            Ok(_) => {
                complete = false;
                provenance.push(clippy_provenance(
                    "rust.clippy-signal.config-unknown.v1",
                    Some(&path),
                    "a Clippy configuration candidate was not valid UTF-8 TOML; it does not make the default Clippy command required",
                ));
            }
            Err(reason) => {
                complete = false;
                provenance.push(clippy_provenance(
                    "rust.clippy-signal.config-unknown.v1",
                    Some(&path),
                    reason,
                ));
            }
        }
        control.checkpoint()?;
    }
    if !context.inventory.skipped.is_empty() {
        provenance.push(clippy_provenance(
            "rust.clippy-signal.inventory-unknown.v1",
            None,
            "repository inventory was partial, so absence of additional Clippy configuration is unknown; Clippy remains advisory unless a complete explicit signal requires it",
        ));
    }

    if !required && complete {
        provenance.push(clippy_provenance(
            "rust.clippy-signal.default-advisory.v1",
            Some(&scope.manifest),
            "no complete project fact requires Clippy, so the default Clippy command remains advisory",
        ));
    }
    provenance.sort();
    provenance.dedup();
    control.checkpoint()?;
    Ok(RustClippySignal {
        enforcement: if required {
            CommandEnforcement::Required
        } else {
            CommandEnforcement::Advisory
        },
        // Once one complete positive signal exists, unknown additional candidates cannot weaken
        // the decision that Clippy is required.
        decision_complete: required || complete,
        provenance,
    })
}

fn scoped_clippy_config_paths_controlled(
    inventory: &Inventory,
    scope_root: &RepoRelativePath,
    control: &dyn OperationControl,
) -> Result<(Vec<RepoRelativePath>, bool), OperationControlError> {
    let mut paths = BTreeSet::new();
    let mut complete = true;
    for entry in &inventory.entries {
        control.checkpoint()?;
        if !matches!(
            entry.path.file_name().and_then(OsStr::to_str),
            Some("clippy.toml" | ".clippy.toml")
        ) {
            continue;
        }
        match RepoRelativePath::new(&entry.path) {
            Ok(path)
                if scope_root.as_path() == Path::new(".")
                    || path.as_path().starts_with(scope_root.as_path()) =>
            {
                paths.insert(path);
            }
            Ok(_) => {}
            Err(_) => complete = false,
        }
    }
    control.checkpoint()?;
    Ok((paths.into_iter().collect(), complete))
}

fn read_lint_signal_text(
    context: &RustDetectionContext<'_>,
    path: &RepoRelativePath,
) -> Result<BoundedText, &'static str> {
    let Some(entry) = context
        .inventory
        .entries
        .iter()
        .find(|entry| entry.path == path.as_path())
    else {
        return Err(
            "the lint-signal path was absent from the bounded repository inventory; Clippy remains advisory unless another explicit signal requires it",
        );
    };
    if entry.kind != InventoryKind::File {
        return Err(
            "the lint-signal path was not an inventoried regular file; symbolic links are not followed and Clippy remains advisory unless another explicit signal requires it",
        );
    }
    match context.filesystem.path_kind(context.repository_root, path) {
        Ok(PathKind::File) => {}
        Ok(_) => {
            return Err(
                "the lint-signal path was no longer a regular file; symbolic links are not followed and Clippy remains advisory unless another explicit signal requires it",
            );
        }
        Err(_) => {
            return Err(
                "the lint-signal path kind could not be verified without following links; Clippy remains advisory unless another explicit signal requires it",
            );
        }
    }
    match context.filesystem.read_bounded_text(
        context.repository_root,
        path,
        RUST_LINT_SIGNAL_MAX_BYTES,
    ) {
        Ok(text) if text.truncated => Err(
            "the lint-signal file exceeded the bounded read limit; Clippy remains advisory unless another explicit signal requires it",
        ),
        Ok(text) if text.binary => Err(
            "the lint-signal file was binary; Clippy remains advisory unless another explicit signal requires it",
        ),
        Ok(text) => Ok(text),
        Err(_) => Err(
            "the lint-signal file could not be read through the bounded no-follow filesystem port; Clippy remains advisory unless another explicit signal requires it",
        ),
    }
}

fn cargo_manifest_clippy_declaration(bytes: &[u8]) -> ClippyDeclaration {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return ClippyDeclaration::Unknown;
    };
    let Ok(document) = text.parse::<toml::Table>() else {
        return ClippyDeclaration::Unknown;
    };
    let mut result = ClippyDeclaration::NotRequired;
    for path in [
        &["lints", "clippy"][..],
        &["workspace", "lints", "clippy"][..],
    ] {
        let mut value = None;
        let mut table = &document;
        for (index, key) in path.iter().enumerate() {
            let Some(candidate) = table.get(*key) else {
                break;
            };
            if index + 1 == path.len() {
                value = Some(candidate);
                break;
            }
            let Some(candidate_table) = candidate.as_table() else {
                return ClippyDeclaration::Unknown;
            };
            table = candidate_table;
        }
        let Some(value) = value else {
            continue;
        };
        match clippy_lint_table_declaration(value) {
            ClippyDeclaration::Required => return ClippyDeclaration::Required,
            ClippyDeclaration::Unknown => result = ClippyDeclaration::Unknown,
            ClippyDeclaration::NotRequired => {}
        }
    }
    result
}

fn clippy_lint_table_declaration(value: &toml::Value) -> ClippyDeclaration {
    let Some(table) = value.as_table() else {
        return ClippyDeclaration::Unknown;
    };
    let mut result = ClippyDeclaration::NotRequired;
    for setting in table.values() {
        let level = setting
            .as_str()
            .or_else(|| setting.as_table()?.get("level")?.as_str());
        match level {
            Some("warn" | "deny" | "forbid" | "force-warn") => {
                return ClippyDeclaration::Required;
            }
            Some("allow") => {}
            Some(_) | None => result = ClippyDeclaration::Unknown,
        }
    }
    result
}

fn clippy_provenance(
    rule_id: &str,
    source_path: Option<&RepoRelativePath>,
    detail: &str,
) -> Provenance {
    Provenance {
        rule_id: rule_id.to_owned(),
        source_path: source_path.map(|path| path.as_path().into()),
        source_range: None,
        detail: detail.to_owned(),
    }
}

fn rust_plan_for_intent(
    intent: Intent,
    scopes: &[RustCommandScope],
) -> Result<CommandPlanCandidate, InvalidCommandPlanCandidate> {
    let phases: &[RustCommandPhase] = match intent {
        Intent::FormatCheck => &[RustCommandPhase::FormatCheck],
        Intent::Format => &[RustCommandPhase::Format],
        Intent::Check => &[
            RustCommandPhase::FormatCheck,
            RustCommandPhase::Check,
            RustCommandPhase::Clippy,
        ],
        Intent::Test => &[
            RustCommandPhase::FormatCheck,
            RustCommandPhase::Check,
            RustCommandPhase::Clippy,
            RustCommandPhase::Test,
        ],
        Intent::Setup | Intent::Fix | Intent::Verify | Intent::Build => &[],
    };
    let commands = scopes
        .iter()
        .flat_map(|scope| {
            phases
                .iter()
                .map(move |phase| rust_command(intent, *phase, scope))
        })
        .collect();
    let mut provenance: Vec<_> = scopes
        .iter()
        .map(|scope| Provenance {
            rule_id: format!("rust.default-plan.{}.v1", intent_name(intent)),
            source_path: Some(scope.manifest.as_path().into()),
            source_range: None,
            detail: String::from(
                "Rust default plan follows the validated top-level package or workspace scope",
            ),
        })
        .collect();
    if phases.contains(&RustCommandPhase::Clippy) {
        provenance.extend(
            scopes
                .iter()
                .flat_map(|scope| scope.clippy.provenance.clone()),
        );
    }
    let mut coverage_confidence = if scopes
        .iter()
        .all(|scope| scope.confidence == Confidence::High)
    {
        Confidence::High
    } else {
        Confidence::Unknown
    };
    if intent == Intent::Test {
        coverage_confidence = coverage_confidence.min(Confidence::Medium);
    }
    if phases.contains(&RustCommandPhase::Clippy)
        && scopes.iter().any(|scope| !scope.clippy.decision_complete)
    {
        coverage_confidence = Confidence::Unknown;
    }
    CommandPlanCandidate::new(commands, provenance, coverage_confidence)
}

fn rust_plan_for_intent_controlled(
    intent: Intent,
    scopes: &[RustCommandScope],
    control: &dyn OperationControl,
) -> Result<CommandPlanCandidate, RustPlanBuildError> {
    let phases: &[RustCommandPhase] = match intent {
        Intent::FormatCheck => &[RustCommandPhase::FormatCheck],
        Intent::Format => &[RustCommandPhase::Format],
        Intent::Check => &[
            RustCommandPhase::FormatCheck,
            RustCommandPhase::Check,
            RustCommandPhase::Clippy,
        ],
        Intent::Test => &[
            RustCommandPhase::FormatCheck,
            RustCommandPhase::Check,
            RustCommandPhase::Clippy,
            RustCommandPhase::Test,
        ],
        Intent::Setup | Intent::Fix | Intent::Verify | Intent::Build => &[],
    };
    let mut commands = Vec::new();
    let mut provenance = Vec::new();
    let mut every_scope_high_confidence = true;
    let mut clippy_decision_complete = true;
    for scope in scopes {
        control.checkpoint()?;
        every_scope_high_confidence &= scope.confidence == Confidence::High;
        clippy_decision_complete &= scope.clippy.decision_complete;
        for phase in phases {
            control.checkpoint()?;
            commands.push(rust_command(intent, *phase, scope));
        }
        provenance.push(Provenance {
            rule_id: format!("rust.default-plan.{}.v1", intent_name(intent)),
            source_path: Some(scope.manifest.as_path().into()),
            source_range: None,
            detail: String::from(
                "Rust default plan follows the validated top-level package or workspace scope",
            ),
        });
        if phases.contains(&RustCommandPhase::Clippy) {
            for source in &scope.clippy.provenance {
                control.checkpoint()?;
                provenance.push(source.clone());
            }
        }
    }
    let mut coverage_confidence = if every_scope_high_confidence {
        Confidence::High
    } else {
        Confidence::Unknown
    };
    if intent == Intent::Test {
        coverage_confidence = coverage_confidence.min(Confidence::Medium);
    }
    if phases.contains(&RustCommandPhase::Clippy) && !clippy_decision_complete {
        coverage_confidence = Confidence::Unknown;
    }
    control.checkpoint()?;
    Ok(CommandPlanCandidate::new(
        commands,
        provenance,
        coverage_confidence,
    )?)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RustCommandPhase {
    FormatCheck,
    Format,
    Check,
    Clippy,
    Test,
}

impl RustCommandPhase {
    const fn rule_name(self) -> &'static str {
        match self {
            Self::FormatCheck => "cargo-fmt-check",
            Self::Format => "cargo-fmt",
            Self::Check => "cargo-check",
            Self::Clippy => "cargo-clippy",
            Self::Test => "cargo-test",
        }
    }
}

fn rust_command(intent: Intent, phase: RustCommandPhase, scope: &RustCommandScope) -> CommandSpec {
    let mut args = match phase {
        RustCommandPhase::FormatCheck => vec!["fmt", "--all", "--", "--check"],
        RustCommandPhase::Format => vec!["fmt", "--all"],
        RustCommandPhase::Check => vec!["check"],
        RustCommandPhase::Clippy => vec!["clippy"],
        RustCommandPhase::Test => vec!["test"],
    };
    if scope.workspace
        && matches!(
            phase,
            RustCommandPhase::Check | RustCommandPhase::Clippy | RustCommandPhase::Test
        )
    {
        args.push("--workspace");
    }
    match phase {
        RustCommandPhase::Check | RustCommandPhase::Clippy => args.push("--all-targets"),
        RustCommandPhase::Test => args.push("--no-fail-fast"),
        RustCommandPhase::FormatCheck | RustCommandPhase::Format => {}
    }

    let mut command = CommandSpec::new(
        format!(
            "rust.{}.{}.{}",
            intent_name(intent),
            phase.rule_name(),
            scope.unit_id
        ),
        intent,
        "cargo",
        scope.root.clone(),
        CommandSource::LanguageDefault {
            provider: String::from("rust"),
            rule: phase.rule_name().to_owned(),
        },
    )
    .with_args(args);
    command
        .env
        .insert(OsString::from("RUSTUP_AUTO_INSTALL"), OsString::from("0"));
    command.mutability = match phase {
        RustCommandPhase::FormatCheck => Mutability::ReadOnly,
        RustCommandPhase::Format => Mutability::WorkingTreeWrite,
        // Cargo compile, lint, and test phases can execute project build scripts or proc macros;
        // tests additionally execute project code. Keep all behind the external-side-effect
        // authorization boundary.
        RustCommandPhase::Check | RustCommandPhase::Clippy | RustCommandPhase::Test => {
            Mutability::ExternalSideEffect
        }
    };
    command.network = NetworkIntent::Inherit;
    if phase == RustCommandPhase::Clippy {
        command.enforcement = scope.clippy.enforcement;
    }
    command.confidence = scope.confidence;
    command.coverage = match phase {
        RustCommandPhase::FormatCheck | RustCommandPhase::Format => BTreeSet::from([
            CoverageDimension::Format,
            rust_custom_coverage(RUST_FORMAT_COVERAGE),
        ]),
        RustCommandPhase::Check => BTreeSet::from([
            CoverageDimension::Compile,
            rust_custom_coverage(RUST_COMPILE_COVERAGE),
        ]),
        RustCommandPhase::Clippy => BTreeSet::from([
            CoverageDimension::Lint,
            rust_custom_coverage(RUST_LINT_COVERAGE),
        ]),
        RustCommandPhase::Test => BTreeSet::from([
            CoverageDimension::UnitTest,
            CoverageDimension::IntegrationTest,
            rust_custom_coverage(RUST_UNIT_TEST_COVERAGE),
            rust_custom_coverage(RUST_LOCAL_INTEGRATION_TEST_COVERAGE),
        ]),
    };
    command
}

fn intent_name(intent: Intent) -> &'static str {
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

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::{BTreeMap, VecDeque};
    use std::io;
    use std::path::{Path, PathBuf};

    use forge_core::ports::{FileSystemPort, Hasher, ProcessError, ProcessPort};
    use forge_core::{
        BoundedText, Digest, GitFileSet, InventoryEntry, InventoryError, InventoryKind,
        InventoryOptions, OperationControl, OperationControlError, OperationPermit, PathKind,
    };
    use serde_json::{Value, json};

    use super::*;

    #[derive(Debug, Default)]
    struct FakeFileSystem {
        kinds: BTreeMap<PathBuf, PathKind>,
        failures: BTreeMap<PathBuf, io::ErrorKind>,
        texts: BTreeMap<PathBuf, BoundedText>,
        bounded_reads: RefCell<Vec<(PathBuf, u64)>>,
    }

    impl FileSystemPort for FakeFileSystem {
        fn read(&self, _path: &Path) -> io::Result<Vec<u8>> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "read is outside this fake",
            ))
        }

        fn inventory(
            &self,
            _root: &Path,
            _file_set: Option<&GitFileSet>,
            _options: InventoryOptions,
        ) -> Result<Inventory, InventoryError> {
            Err(InventoryError::InvalidRoot(PathBuf::from("fake")))
        }

        fn read_bounded_text(
            &self,
            _root: &Path,
            path: &RepoRelativePath,
            max_text_file_bytes: u64,
        ) -> Result<BoundedText, InventoryError> {
            self.bounded_reads
                .borrow_mut()
                .push((path.as_path().to_path_buf(), max_text_file_bytes));
            Ok(self
                .texts
                .get(path.as_path())
                .cloned()
                .unwrap_or(BoundedText {
                    bytes: Vec::new(),
                    truncated: false,
                    binary: false,
                }))
        }

        fn path_kind(&self, _root: &Path, path: &RepoRelativePath) -> io::Result<PathKind> {
            if let Some(kind) = self.failures.get(path.as_path()) {
                return Err(io::Error::new(*kind, "injected path probe failure"));
            }
            Ok(self
                .kinds
                .get(path.as_path())
                .copied()
                .unwrap_or(PathKind::File))
        }

        fn write_atomic(&self, _path: &Path, _bytes: &[u8]) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "write is outside this fake",
            ))
        }

        fn exists(&self, _path: &Path) -> bool {
            false
        }
    }

    #[derive(Debug)]
    struct FakeProcess {
        specs: RefCell<Vec<ExecSpec>>,
        responses: RefCell<VecDeque<Result<ProcessObservation, ProcessError>>>,
    }

    impl FakeProcess {
        fn new(responses: Vec<Result<ProcessObservation, ProcessError>>) -> Self {
            Self {
                specs: RefCell::new(Vec::new()),
                responses: RefCell::new(responses.into()),
            }
        }
    }

    impl ProcessPort for FakeProcess {
        fn run(&self, spec: &ExecSpec) -> Result<ProcessObservation, ProcessError> {
            self.specs.borrow_mut().push(spec.clone());
            match self.responses.borrow_mut().pop_front() {
                Some(response) => response,
                None => Err(ProcessError::new(
                    ProcessErrorKind::Spawn,
                    "missing fake process response",
                    io::Error::new(io::ErrorKind::UnexpectedEof, "missing response"),
                )),
            }
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct StableTestHasher;

    impl Hasher for StableTestHasher {
        fn digest(&self, chunks: &[&[u8]]) -> Digest {
            let mut hash = 0xcbf2_9ce4_8422_2325_u64;
            for chunk in chunks {
                for byte in *chunk {
                    hash ^= u64::from(*byte);
                    hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
                }
                hash ^= 0xff;
            }
            Digest::new(format!("test:{hash:016x}"))
        }
    }

    #[derive(Debug)]
    struct ScriptedControl {
        steps: RefCell<VecDeque<Result<OperationPermit, OperationControlError>>>,
        terminal: RefCell<Option<OperationControlError>>,
    }

    impl ScriptedControl {
        fn new(
            steps: impl IntoIterator<Item = Result<OperationPermit, OperationControlError>>,
        ) -> Self {
            Self {
                steps: RefCell::new(steps.into_iter().collect()),
                terminal: RefCell::new(None),
            }
        }
    }

    impl OperationControl for ScriptedControl {
        fn checkpoint(&self) -> Result<OperationPermit, OperationControlError> {
            if let Some(error) = *self.terminal.borrow() {
                return Err(error);
            }
            let result = self
                .steps
                .borrow_mut()
                .pop_front()
                .unwrap_or_else(|| Ok(OperationPermit::unlimited()));
            if let Err(error) = result {
                *self.terminal.borrow_mut() = Some(error);
            }
            result
        }
    }

    fn inventory(paths: &[&str]) -> Inventory {
        Inventory {
            entries: paths
                .iter()
                .map(|path| InventoryEntry {
                    path: PathBuf::from(path),
                    kind: InventoryKind::File,
                    size_bytes: Some(1),
                })
                .collect(),
            skipped: Vec::new(),
        }
    }

    /// Opaque placeholder: these Rust-provider tests do not consume process-output digests.
    fn ignored_process_digest(stream: &str) -> Digest {
        Digest::new(format!("fixture:non-canonical-rust-{stream}"))
    }

    fn metadata_observation(document: Value) -> Result<ProcessObservation, serde_json::Error> {
        let stdout = serde_json::to_vec(&document)?;
        Ok(ProcessObservation {
            exit_code: Some(0),
            signal: None,
            stdout_total_bytes: stdout.len() as u64,
            stderr_total_bytes: 0,
            stdout,
            stderr: Vec::new(),
            stdout_digest: ignored_process_digest("stdout"),
            stderr_digest: ignored_process_digest("stderr"),
            stdout_truncated: false,
            stderr_truncated: false,
            duration: Duration::from_millis(12),
            timed_out: false,
            interrupted: false,
        })
    }

    fn failed_observation() -> ProcessObservation {
        ProcessObservation {
            exit_code: Some(101),
            signal: None,
            stdout: Vec::new(),
            stderr: b"redacted by provider result".to_vec(),
            stdout_digest: ignored_process_digest("stdout"),
            stderr_digest: ignored_process_digest("stderr"),
            stdout_total_bytes: 0,
            stderr_total_bytes: 27,
            stdout_truncated: false,
            stderr_truncated: false,
            duration: Duration::from_millis(8),
            timed_out: false,
            interrupted: false,
        }
    }

    fn package_document(root: &str, name: &str, cargo_id: &str) -> Value {
        json!({
            "packages": [{
                "name": name,
                "id": cargo_id,
                "manifest_path": format!("{root}/Cargo.toml"),
                "dependencies": []
            }],
            "workspace_members": [cargo_id],
            "workspace_default_members": [cargo_id],
            "resolve": null,
            "workspace_root": root,
            "version": 1
        })
    }

    fn workspace_document() -> Value {
        json!({
            "packages": [
                {
                    "name": "a",
                    "id": "path+file:///repo/a#0.1.0",
                    "manifest_path": "/repo/a/Cargo.toml",
                    "dependencies": []
                },
                {
                    "name": "b",
                    "id": "path+file:///repo/b#0.1.0",
                    "manifest_path": "/repo/b/Cargo.toml",
                    "dependencies": [{"path": "/repo/a"}]
                }
            ],
            "workspace_members": [
                "path+file:///repo/a#0.1.0",
                "path+file:///repo/b#0.1.0"
            ],
            "workspace_default_members": [
                "path+file:///repo/a#0.1.0",
                "path+file:///repo/b#0.1.0"
            ],
            "resolve": null,
            "workspace_root": "/repo",
            "version": 1
        })
    }

    fn context<'a>(
        inventory: &'a Inventory,
        filesystem: &'a FakeFileSystem,
        process: &'a FakeProcess,
    ) -> RustDetectionContext<'a> {
        RustDetectionContext {
            repository_root: Path::new("/repo"),
            inventory,
            filesystem,
            process,
            hasher: &StableTestHasher,
            metadata_timeout: Duration::from_secs(17),
        }
    }

    fn bounded_text(bytes: impl Into<Vec<u8>>) -> BoundedText {
        BoundedText {
            bytes: bytes.into(),
            truncated: false,
            binary: false,
        }
    }

    fn detect_lint_fixture(
        manifest_text: &str,
        config_files: &[(&str, InventoryKind, BoundedText)],
    ) -> Result<(RustDetectionResult, FakeFileSystem), Box<dyn Error>> {
        let mut entries = vec![InventoryEntry {
            path: PathBuf::from("Cargo.toml"),
            kind: InventoryKind::File,
            size_bytes: Some(manifest_text.len() as u64),
        }];
        let mut filesystem = FakeFileSystem::default();
        filesystem.texts.insert(
            PathBuf::from("Cargo.toml"),
            bounded_text(manifest_text.as_bytes()),
        );
        for (path, kind, text) in config_files {
            entries.push(InventoryEntry {
                path: PathBuf::from(path),
                kind: *kind,
                size_bytes: Some(text.bytes.len() as u64),
            });
            filesystem.kinds.insert(
                PathBuf::from(path),
                match kind {
                    InventoryKind::File => PathKind::File,
                    InventoryKind::Directory => PathKind::Directory,
                    InventoryKind::Symlink => PathKind::Symlink,
                    InventoryKind::Other => PathKind::Other,
                },
            );
            filesystem.texts.insert(PathBuf::from(path), text.clone());
        }
        let inventory = Inventory {
            entries,
            skipped: Vec::new(),
        };
        let process = FakeProcess::new(vec![Ok(metadata_observation(package_document(
            "/repo",
            "root-package",
            "path+file:///repo#root-package@0.1.0",
        ))?)]);
        let result = detect_rust_project(&context(&inventory, &filesystem, &process))?;
        Ok((result, filesystem))
    }

    fn clippy_command(
        result: &RustDetectionResult,
        intent: Intent,
    ) -> Result<&CommandSpec, Box<dyn Error>> {
        result
            .command_plan_fragments
            .iter()
            .find(|plan| plan.intent() == intent)
            .and_then(|plan| {
                plan.commands().iter().find(|command| {
                    command.args.first().and_then(|argument| argument.to_str()) == Some("clippy")
                })
            })
            .ok_or_else(|| io::Error::other(format!("missing {intent:?} Clippy command")).into())
    }

    #[test]
    fn standalone_package_uses_safe_metadata_argv_and_non_workspace_plans()
    -> Result<(), Box<dyn Error>> {
        let inventory = inventory(&["Cargo.toml"]);
        let filesystem = FakeFileSystem::default();
        let process = FakeProcess::new(vec![Ok(metadata_observation(package_document(
            "/repo",
            "root-package",
            "path+file:///repo#root-package@0.1.0",
        ))?)]);

        let result = detect_rust_project(&context(&inventory, &filesystem, &process))?;

        assert_eq!(result.units.len(), 1);
        assert_eq!(result.units[0].kind, ProjectKind::RustPackage);
        assert_eq!(result.units[0].confidence, Confidence::High);
        assert_eq!(result.units[0].workspace_root, None);
        assert_eq!(
            result.metadata_completions[0].outcome,
            CargoMetadataOutcome::Succeeded
        );
        assert_eq!(result.command_plan_fragments.len(), 4);

        let specs = process.specs.borrow();
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].program, "cargo");
        assert_eq!(
            specs[0].args,
            [
                "metadata",
                "--format-version=1",
                "--no-deps",
                "--manifest-path",
                "Cargo.toml"
            ]
        );
        assert_eq!(specs[0].cwd, RepoRelativePath::root());
        assert_eq!(specs[0].timeout, Duration::from_secs(17));
        assert_eq!(specs[0].stdin, StdinPolicy::Closed);
        assert_eq!(specs[0].network, NetworkIntent::OfflineRequested);
        assert_eq!(specs[0].mutability, Mutability::ReadOnly);
        assert_eq!(
            specs[0]
                .env
                .overrides
                .get(OsStr::new("RUSTUP_AUTO_INSTALL")),
            Some(&OsString::from("0"))
        );
        assert_eq!(
            specs[0].env.overrides.get(OsStr::new("CARGO_NET_OFFLINE")),
            Some(&OsString::from("true"))
        );

        let check = result
            .command_plan_fragments
            .iter()
            .find(|plan| plan.intent() == Intent::Check)
            .ok_or("missing check plan")?;
        assert_eq!(check.commands().len(), 3);
        assert_eq!(check.commands()[0].args, ["fmt", "--all", "--", "--check"]);
        assert_eq!(check.commands()[1].args, ["check", "--all-targets"]);
        assert_eq!(check.commands()[2].args, ["clippy", "--all-targets"]);
        assert_eq!(check.commands()[0].mutability, Mutability::ReadOnly);
        assert_eq!(
            check.commands()[1].mutability,
            Mutability::ExternalSideEffect
        );
        assert_eq!(
            check.commands()[2].mutability,
            Mutability::ExternalSideEffect
        );
        assert_eq!(
            check.commands()[2].enforcement,
            CommandEnforcement::Advisory
        );
        assert_eq!(
            check.commands()[0].coverage,
            BTreeSet::from([
                CoverageDimension::Format,
                CoverageDimension::Custom(String::from(RUST_FORMAT_COVERAGE)),
            ])
        );
        assert_eq!(
            check.commands()[1].coverage,
            BTreeSet::from([
                CoverageDimension::Compile,
                CoverageDimension::Custom(String::from(RUST_COMPILE_COVERAGE)),
            ])
        );
        assert_eq!(
            check.commands()[2].coverage,
            BTreeSet::from([
                CoverageDimension::Lint,
                CoverageDimension::Custom(String::from(RUST_LINT_COVERAGE)),
            ])
        );
        assert!(check.commands().iter().all(|command| {
            command.network == NetworkIntent::Inherit
                && command.env.get(OsStr::new("RUSTUP_AUTO_INSTALL")) == Some(&OsString::from("0"))
                && !command.args.iter().any(|arg| {
                    matches!(
                        arg.to_str(),
                        Some("-D" | "warnings" | "--all-features" | "--locked" | "nextest")
                    )
                })
        }));
        let test = result
            .command_plan_fragments
            .iter()
            .find(|plan| plan.intent() == Intent::Test)
            .ok_or("missing test plan")?;
        assert_eq!(test.commands()[0].mutability, Mutability::ReadOnly);
        assert!(
            test.commands()[1..]
                .iter()
                .all(|command| command.mutability == Mutability::ExternalSideEffect)
        );
        assert_eq!(test.coverage_confidence(), Confidence::Medium);
        let cargo_test = test
            .commands()
            .iter()
            .find(|command| command.args.first().and_then(|arg| arg.to_str()) == Some("test"))
            .ok_or("missing Cargo test command")?;
        assert_eq!(
            cargo_test.coverage,
            BTreeSet::from([
                CoverageDimension::UnitTest,
                CoverageDimension::IntegrationTest,
                CoverageDimension::Custom(String::from(RUST_UNIT_TEST_COVERAGE)),
                CoverageDimension::Custom(String::from(RUST_LOCAL_INTEGRATION_TEST_COVERAGE)),
            ])
        );
        assert!(
            !cargo_test
                .coverage
                .contains(&CoverageDimension::Custom(String::from(
                    RUST_EXAMPLES_COMPILE_COVERAGE
                )))
        );

        let compatibility = rust_default_plan_fragments(&result.units)?;
        let compatibility_check = compatibility
            .iter()
            .find(|plan| plan.intent() == Intent::Check)
            .ok_or("missing compatibility check plan")?;
        assert_eq!(
            compatibility_check
                .commands()
                .iter()
                .find(|command| {
                    command.args.first().and_then(|argument| argument.to_str()) == Some("clippy")
                })
                .ok_or("missing compatibility Clippy command")?
                .enforcement,
            CommandEnforcement::Advisory
        );
        assert_eq!(
            compatibility_check.coverage_confidence(),
            Confidence::Unknown
        );
        assert!(
            compatibility_check
                .provenance()
                .iter()
                .any(|source| { source.rule_id == "rust.clippy-signal.compatibility-advisory.v1" })
        );
        Ok(())
    }

    #[test]
    fn required_feature_targets_remain_explicit_coverage_gaps() -> Result<(), Box<dyn Error>> {
        let manifest = r#"
[package]
name = "feature-gated-targets"
version = "0.1.0"
edition = "2024"

[features]
gated = []

[[example]]
name = "gated-example"
path = "examples/gated.rs"
required-features = ["gated"]

[[bench]]
name = "gated-bench"
path = "benches/gated.rs"
required-features = ["gated"]
"#;
        let (result, _) = detect_lint_fixture(manifest, &[])?;
        let check = result
            .command_plan_fragments
            .iter()
            .find(|plan| plan.intent() == Intent::Check)
            .ok_or("missing check plan")?;
        let cargo_check = check
            .commands()
            .iter()
            .find(|command| {
                command.args.first().and_then(|argument| argument.to_str()) == Some("check")
            })
            .ok_or("missing Cargo check command")?;

        assert_eq!(cargo_check.args, ["check", "--all-targets"]);
        assert_eq!(
            cargo_check.coverage,
            BTreeSet::from([
                CoverageDimension::Compile,
                CoverageDimension::Custom(String::from(RUST_COMPILE_COVERAGE)),
            ])
        );
        let expected = rust_coverage_expectations_for_units(&result.units);
        assert!(expected.contains(&CoverageDimension::Custom(String::from(
            RUST_EXAMPLES_COMPILE_COVERAGE
        ))));
        assert!(expected.contains(&CoverageDimension::Custom(String::from(
            RUST_BENCHES_COMPILE_COVERAGE
        ))));
        Ok(())
    }

    #[test]
    fn rust_coverage_expectations_are_namespaced_deduplicated_and_mixed_safe()
    -> Result<(), Box<dyn Error>> {
        let inventory = inventory(&["Cargo.toml"]);
        let filesystem = FakeFileSystem::default();
        let process = FakeProcess::new(vec![Ok(metadata_observation(package_document(
            "/repo",
            "root-package",
            "path+file:///repo#root-package@0.1.0",
        ))?)]);
        let result = detect_rust_project(&context(&inventory, &filesystem, &process))?;
        let rust_unit = result.units[0].clone();
        let expected = rust_coverage_expectations_for_units(std::slice::from_ref(&rust_unit));

        assert_eq!(expected.len(), 16);
        for dimension in [
            CoverageDimension::Format,
            CoverageDimension::Compile,
            CoverageDimension::Lint,
            CoverageDimension::UnitTest,
            CoverageDimension::IntegrationTest,
            CoverageDimension::Build,
            CoverageDimension::Custom(String::from(RUST_FORMAT_COVERAGE)),
            CoverageDimension::Custom(String::from(RUST_COMPILE_COVERAGE)),
            CoverageDimension::Custom(String::from(RUST_LINT_COVERAGE)),
            CoverageDimension::Custom(String::from(RUST_UNIT_TEST_COVERAGE)),
            CoverageDimension::Custom(String::from(RUST_LOCAL_INTEGRATION_TEST_COVERAGE)),
            CoverageDimension::Custom(String::from(RUST_BUILD_COVERAGE)),
            CoverageDimension::Custom(String::from(RUST_EXAMPLES_COMPILE_COVERAGE)),
            CoverageDimension::Custom(String::from(RUST_BENCHES_COMPILE_COVERAGE)),
            CoverageDimension::Custom(String::from(RUST_CROSS_TARGET_COVERAGE)),
            CoverageDimension::Custom(String::from(RUST_PERFORMANCE_COVERAGE)),
        ] {
            assert!(expected.contains(&dimension), "missing {dimension:?}");
        }

        let mut go_unit = rust_unit.clone();
        go_unit.language = "go".into();
        go_unit.kind = ProjectKind::GoModule;
        assert!(rust_coverage_expectations_for_units(std::slice::from_ref(&go_unit)).is_empty());
        assert_eq!(
            rust_coverage_expectations_for_units(&[go_unit, rust_unit.clone()]),
            expected
        );
        assert_eq!(
            rust_coverage_expectations_for_units(&[rust_unit.clone(), rust_unit]),
            expected
        );
        Ok(())
    }

    #[test]
    fn cargo_clippy_lint_tables_make_clippy_required_without_inventing_flags()
    -> Result<(), Box<dyn Error>> {
        for manifest in [
            "[lints.clippy]\npedantic = \"warn\"\n",
            "[workspace.lints.clippy]\nall = { level = \"deny\", priority = -1 }\n",
        ] {
            let (result, filesystem) = detect_lint_fixture(manifest, &[])?;
            for intent in [Intent::Check, Intent::Test] {
                let clippy = clippy_command(&result, intent)?;
                assert_eq!(clippy.enforcement, CommandEnforcement::Required);
                assert_eq!(
                    clippy.coverage,
                    BTreeSet::from([
                        CoverageDimension::Lint,
                        CoverageDimension::Custom(String::from(RUST_LINT_COVERAGE)),
                    ])
                );
                assert_eq!(clippy.args, ["clippy", "--all-targets"]);
                assert!(!clippy.args.iter().any(|argument| {
                    matches!(
                        argument.to_str(),
                        Some("-D" | "warnings" | "--all-features" | "--locked")
                    )
                }));
            }
            assert!(
                result
                    .command_plan_fragments
                    .iter()
                    .filter(|plan| matches!(plan.intent(), Intent::Check | Intent::Test))
                    .flat_map(CommandPlanCandidate::provenance)
                    .any(|source| source.rule_id == "rust.clippy-signal.cargo-lints.v1")
            );
            assert!(
                filesystem
                    .bounded_reads
                    .borrow()
                    .iter()
                    .all(|(_, limit)| *limit == RUST_LINT_SIGNAL_MAX_BYTES)
            );
        }
        Ok(())
    }

    #[test]
    fn allow_only_clippy_lints_leave_the_default_command_advisory() -> Result<(), Box<dyn Error>> {
        let (result, _) = detect_lint_fixture("[lints.clippy]\npedantic = \"allow\"\n", &[])?;

        assert_eq!(
            clippy_command(&result, Intent::Check)?.enforcement,
            CommandEnforcement::Advisory
        );
        let check = result
            .command_plan_fragments
            .iter()
            .find(|plan| plan.intent() == Intent::Check)
            .ok_or("missing check plan")?;
        assert_eq!(check.coverage_confidence(), Confidence::High);
        assert!(
            check
                .provenance()
                .iter()
                .any(|source| source.rule_id == "rust.clippy-signal.default-advisory.v1")
        );
        Ok(())
    }

    #[test]
    fn regular_bounded_scope_clippy_configs_make_clippy_required() -> Result<(), Box<dyn Error>> {
        for path in ["clippy.toml", ".clippy.toml", "nested/clippy.toml"] {
            let config = bounded_text(b"avoid-breaking-exported-api = false".to_vec());
            let (result, filesystem) =
                detect_lint_fixture("", &[(path, InventoryKind::File, config)])?;

            assert_eq!(
                clippy_command(&result, Intent::Check)?.enforcement,
                CommandEnforcement::Required
            );
            assert!(
                result
                    .command_plan_fragments
                    .iter()
                    .filter(|plan| matches!(plan.intent(), Intent::Check | Intent::Test))
                    .flat_map(CommandPlanCandidate::provenance)
                    .any(|source| source.rule_id == "rust.clippy-signal.config.v1")
            );
            assert!(
                filesystem
                    .bounded_reads
                    .borrow()
                    .iter()
                    .any(|(read, limit)| {
                        read == Path::new(path) && *limit == RUST_LINT_SIGNAL_MAX_BYTES
                    })
            );
        }
        Ok(())
    }

    #[test]
    fn uncertain_or_unsafe_clippy_configs_never_become_required() -> Result<(), Box<dyn Error>> {
        let cases = [
            (
                "symlink",
                InventoryKind::Symlink,
                bounded_text(b"avoid-breaking-exported-api = false".to_vec()),
                false,
            ),
            (
                "truncated",
                InventoryKind::File,
                BoundedText {
                    bytes: b"avoid-breaking-exported-api = false".to_vec(),
                    truncated: true,
                    binary: false,
                },
                true,
            ),
            (
                "binary",
                InventoryKind::File,
                BoundedText {
                    bytes: b"key = \"value\"\0".to_vec(),
                    truncated: false,
                    binary: true,
                },
                true,
            ),
            (
                "malformed",
                InventoryKind::File,
                bounded_text(b"[".to_vec()),
                true,
            ),
        ];

        for (label, kind, text, should_read) in cases {
            let path = format!("{label}/clippy.toml");
            let (result, filesystem) = detect_lint_fixture("", &[(path.as_str(), kind, text)])?;
            assert_eq!(
                clippy_command(&result, Intent::Check)?.enforcement,
                CommandEnforcement::Advisory,
                "unsafe case {label} unexpectedly became required"
            );
            let check = result
                .command_plan_fragments
                .iter()
                .find(|plan| plan.intent() == Intent::Check)
                .ok_or("missing check plan")?;
            assert_eq!(check.coverage_confidence(), Confidence::Unknown);
            assert!(
                check
                    .provenance()
                    .iter()
                    .any(|source| { source.rule_id == "rust.clippy-signal.config-unknown.v1" })
            );
            assert_eq!(
                filesystem
                    .bounded_reads
                    .borrow()
                    .iter()
                    .any(|(read, _)| read == Path::new(&path)),
                should_read,
                "unexpected no-follow read behavior for {label}"
            );
        }
        Ok(())
    }

    #[test]
    fn workspace_is_deduplicated_across_root_and_member_probes() -> Result<(), Box<dyn Error>> {
        let inventory = inventory(&["Cargo.toml", "a/Cargo.toml", "b/Cargo.toml"]);
        let filesystem = FakeFileSystem::default();
        let document = workspace_document();
        let process = FakeProcess::new(vec![
            Ok(metadata_observation(document.clone())?),
            Ok(metadata_observation(document.clone())?),
            Ok(metadata_observation(document)?),
        ]);

        let result = detect_rust_project(&context(&inventory, &filesystem, &process))?;

        assert_eq!(process.specs.borrow().len(), 3);
        assert_eq!(result.units.len(), 3);
        let workspace = result
            .units
            .iter()
            .find(|unit| unit.kind == ProjectKind::CargoWorkspace)
            .ok_or("missing workspace")?;
        assert_eq!(workspace.members.len(), 2);
        assert_eq!(
            result
                .units
                .iter()
                .filter(|unit| unit.kind == ProjectKind::RustPackage)
                .count(),
            2
        );
        assert!(
            result
                .units
                .iter()
                .filter(|unit| unit.kind == ProjectKind::RustPackage)
                .all(|unit| unit.workspace_root == Some(RepoRelativePath::root()))
        );
        let b = result
            .units
            .iter()
            .find(|unit| unit.display_name == "b")
            .ok_or("missing b package")?;
        assert_eq!(b.dependencies.len(), 1);

        let test = result
            .command_plan_fragments
            .iter()
            .find(|plan| plan.intent() == Intent::Test)
            .ok_or("missing test plan")?;
        assert_eq!(test.commands().len(), 4);
        assert_eq!(test.commands()[0].args, ["fmt", "--all", "--", "--check"]);
        assert_eq!(
            test.commands()[1].args,
            ["check", "--workspace", "--all-targets"]
        );
        assert_eq!(
            test.commands()[2].args,
            ["clippy", "--workspace", "--all-targets"]
        );
        assert_eq!(
            test.commands()[3].args,
            ["test", "--workspace", "--no-fail-fast"]
        );
        Ok(())
    }

    #[test]
    fn multiple_independent_packages_remain_separate_and_ordered() -> Result<(), Box<dyn Error>> {
        let inventory = inventory(&["b/Cargo.toml", "a/Cargo.toml"]);
        let filesystem = FakeFileSystem::default();
        let process = FakeProcess::new(vec![
            Ok(metadata_observation(package_document(
                "/repo/a",
                "a",
                "a 0.1.0 (path+file:///repo/a)",
            ))?),
            Ok(metadata_observation(package_document(
                "/repo/b",
                "b",
                "b 0.1.0 (path+file:///repo/b)",
            ))?),
        ]);

        let result = detect_rust_project(&context(&inventory, &filesystem, &process))?;

        assert_eq!(result.units.len(), 2);
        assert!(
            result
                .units
                .iter()
                .all(|unit| unit.kind == ProjectKind::RustPackage)
        );
        let check = result
            .command_plan_fragments
            .iter()
            .find(|plan| plan.intent() == Intent::Check)
            .ok_or("missing check plan")?;
        assert_eq!(check.commands().len(), 6);
        assert_eq!(check.commands()[0].cwd.as_path(), Path::new("a"));
        assert_eq!(check.commands()[3].cwd.as_path(), Path::new("b"));
        assert!(
            check
                .commands()
                .iter()
                .all(|command| !command.args.iter().any(|arg| arg == "--workspace"))
        );
        Ok(())
    }

    #[test]
    fn shared_budget_stops_before_later_manifests_without_inventing_facts()
    -> Result<(), Box<dyn Error>> {
        let inventory = inventory(&["a/Cargo.toml", "b/Cargo.toml"]);
        let filesystem = FakeFileSystem::default();
        let process = FakeProcess::new(vec![Ok(failed_observation())]);
        let control = ScriptedControl::new([
            Ok(OperationPermit::limited(Duration::from_millis(25))),
            Err(OperationControlError::TimedOut),
        ]);

        let result =
            detect_rust_project_controlled(&context(&inventory, &filesystem, &process), &control)?;

        let specs = process.specs.borrow();
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].timeout, Duration::from_millis(25));
        assert_eq!(result.units.len(), 1);
        assert_eq!(
            result.units[0].manifest.as_path(),
            Path::new("a/Cargo.toml")
        );
        assert!(result.command_plan_fragments.is_empty());
        assert_eq!(result.metadata_completions.len(), 1);
        assert_eq!(
            result.metadata_completions[0].outcome,
            CargoMetadataOutcome::ExitFailure
        );
        assert_eq!(result.control_error, Some(OperationControlError::TimedOut));
        Ok(())
    }

    #[test]
    fn metadata_failure_keeps_a_low_confidence_static_unit() -> Result<(), Box<dyn Error>> {
        let inventory = inventory(&["broken/Cargo.toml"]);
        let filesystem = FakeFileSystem::default();
        let process = FakeProcess::new(vec![Ok(failed_observation())]);

        let result = detect_rust_project(&context(&inventory, &filesystem, &process))?;

        assert_eq!(result.units.len(), 1);
        assert_eq!(result.units[0].confidence, Confidence::Low);
        assert_eq!(
            result.units[0].manifest.as_path(),
            Path::new("broken/Cargo.toml")
        );
        assert_eq!(result.confidence, Confidence::Low);
        assert_eq!(
            result.metadata_completions[0].outcome,
            CargoMetadataOutcome::ExitFailure
        );
        assert_eq!(result.metadata_completions[0].stderr_total_bytes, 27);
        assert!(
            result
                .command_plan_fragments
                .iter()
                .all(|plan| plan.coverage_confidence() == Confidence::Unknown)
        );
        Ok(())
    }

    #[test]
    fn timeout_and_interrupt_facts_survive_static_fallback() -> Result<(), Box<dyn Error>> {
        let inventory = inventory(&["slow/Cargo.toml"]);
        let filesystem = FakeFileSystem::default();
        let mut observation = failed_observation();
        observation.exit_code = None;
        observation.timed_out = true;
        observation.interrupted = true;
        observation.signal = Some(15);
        let process = FakeProcess::new(vec![Ok(observation)]);

        let result = detect_rust_project(&context(&inventory, &filesystem, &process))?;

        let completion = &result.metadata_completions[0];
        assert_eq!(completion.outcome, CargoMetadataOutcome::TimedOut);
        assert!(completion.timed_out);
        assert!(completion.interrupted);
        assert_eq!(completion.signal, Some(15));
        assert_eq!(result.units[0].confidence, Confidence::Low);
        Ok(())
    }

    #[test]
    fn escaping_metadata_paths_are_rejected_without_losing_the_manifest()
    -> Result<(), Box<dyn Error>> {
        let inventory = inventory(&["Cargo.toml"]);
        let filesystem = FakeFileSystem::default();
        let process = FakeProcess::new(vec![Ok(metadata_observation(package_document(
            "/outside",
            "escape",
            "escape 0.1.0 (path+file:///outside)",
        ))?)]);

        let result = detect_rust_project(&context(&inventory, &filesystem, &process))?;

        assert_eq!(result.units.len(), 1);
        assert_eq!(result.units[0].manifest.as_path(), Path::new("Cargo.toml"));
        assert_eq!(result.units[0].confidence, Confidence::Low);
        assert!(matches!(
            result.metadata_completions[0].outcome,
            CargoMetadataOutcome::InvalidOutput(
                CargoMetadataInvalidReason::PathEscapedRepository { .. }
            )
        ));
        Ok(())
    }

    #[test]
    fn duplicate_inventory_manifest_is_probed_and_emitted_once() -> Result<(), Box<dyn Error>> {
        let inventory = inventory(&["Cargo.toml", "Cargo.toml"]);
        let filesystem = FakeFileSystem::default();
        let process = FakeProcess::new(vec![Ok(metadata_observation(package_document(
            "/repo",
            "root",
            "root 0.1.0 (path+file:///repo)",
        ))?)]);

        let result = detect_rust_project(&context(&inventory, &filesystem, &process))?;

        assert_eq!(process.specs.borrow().len(), 1);
        assert_eq!(result.metadata_completions.len(), 1);
        assert_eq!(result.units.len(), 1);
        Ok(())
    }

    #[test]
    fn unit_id_hashes_the_unit_kind_and_repository_relative_path() -> Result<(), Box<dyn Error>> {
        let manifest = RepoRelativePath::new("member/Cargo.toml")?;

        let package = rust_unit_id_value(RUST_PACKAGE_ID_KIND, &manifest, &StableTestHasher);
        let repeated = rust_unit_id_value(RUST_PACKAGE_ID_KIND, &manifest, &StableTestHasher);
        let workspace = rust_unit_id_value(RUST_WORKSPACE_ID_KIND, &manifest, &StableTestHasher);

        assert_eq!(package, repeated);
        assert_ne!(package, workspace);
        assert_ne!(
            package,
            rust_unit_id_value(
                RUST_PACKAGE_ID_KIND,
                &RepoRelativePath::new("other/Cargo.toml")?,
                &StableTestHasher
            )
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn unit_id_preserves_non_utf8_native_path_bytes() -> Result<(), Box<dyn Error>> {
        use std::os::unix::ffi::OsStringExt as _;

        let mut left = PathBuf::from(OsString::from_vec(b"member-\xff".to_vec()));
        left.push("Cargo.toml");
        let mut right = PathBuf::from(OsString::from_vec(b"member-\xfe".to_vec()));
        right.push("Cargo.toml");

        assert_ne!(
            rust_unit_id_value(
                RUST_PACKAGE_ID_KIND,
                &RepoRelativePath::new(left)?,
                &StableTestHasher
            ),
            rust_unit_id_value(
                RUST_PACKAGE_ID_KIND,
                &RepoRelativePath::new(right)?,
                &StableTestHasher
            )
        );
        Ok(())
    }

    #[test]
    fn format_resolve_and_member_invariants_fail_closed() -> Result<(), Box<dyn Error>> {
        let inventory = inventory(&[
            "format/Cargo.toml",
            "members/Cargo.toml",
            "resolve/Cargo.toml",
        ]);
        let filesystem = FakeFileSystem::default();
        let mut format = package_document(
            "/repo/format",
            "format",
            "format 0.1.0 (path+file:///repo/format)",
        );
        format["version"] = json!(2);
        let mut members = package_document(
            "/repo/members",
            "members",
            "members 0.1.0 (path+file:///repo/members)",
        );
        members["workspace_members"] = json!(["missing"]);
        let mut resolve = package_document(
            "/repo/resolve",
            "resolve",
            "resolve 0.1.0 (path+file:///repo/resolve)",
        );
        resolve["resolve"] = json!({"nodes": []});
        let process = FakeProcess::new(vec![
            Ok(metadata_observation(format)?),
            Ok(metadata_observation(members)?),
            Ok(metadata_observation(resolve)?),
        ]);

        let result = detect_rust_project(&context(&inventory, &filesystem, &process))?;

        assert_eq!(result.units.len(), 3);
        assert!(
            result
                .units
                .iter()
                .all(|unit| unit.confidence == Confidence::Low)
        );
        assert!(matches!(
            result.metadata_completions[0].outcome,
            CargoMetadataOutcome::InvalidOutput(
                CargoMetadataInvalidReason::UnsupportedFormatVersion { found: 2 }
            )
        ));
        assert!(matches!(
            result.metadata_completions[1].outcome,
            CargoMetadataOutcome::InvalidOutput(CargoMetadataInvalidReason::MissingWorkspaceMember)
        ));
        assert!(matches!(
            result.metadata_completions[2].outcome,
            CargoMetadataOutcome::InvalidOutput(CargoMetadataInvalidReason::ResolveWasNotNull)
        ));
        Ok(())
    }
}
