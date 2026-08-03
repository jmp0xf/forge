//! Deterministic, candidate-controlled assembly of reviewable release assets.
//!
//! These tasks deliberately stop before provenance, signing, upload, or release authorization.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, File};
use std::io::{Cursor, Read};
use std::path::{Component as PathComponent, Path, PathBuf};
use std::time::Duration;

use forge_core::ports::{
    EnvPolicy, ExecSpec, OutputPolicy, ProcessObservation, ProcessPort, StdinPolicy,
};
use forge_core::{
    GitIndexEntry, GitIndexTag, GitObjectFormat, Mutability, NetworkIntent, RepoRelativePath,
    parse_git_index_reader,
};
use forge_runtime::fs::RepositoryWriter;
use forge_runtime::git::{GitCli, HARDENED_GIT_ENV, HARDENED_GIT_GLOBAL_ARGS};
use forge_runtime::process::SynchronousProcessRunner;
use forge_schema::{
    GitObjectIdV2Data, GitSha1ObjectIdV2Data, GitSha256ObjectIdV2Data, ReleaseArtifactKindV2Data,
    ReleaseArtifactV2Data, ReleaseAuthorityStatusData, ReleaseBuildInputCargoCommandData,
    ReleaseBuildInputNativeStringData, ReleaseBuildInputObservationData,
    ReleaseBuildInputObservationPhaseData, ReleaseBuildInputObservationPurposeData,
    ReleaseBuildInputTargetData, ReleaseBuildInputValueData,
    ReleaseBuildInputWindowsMsvcEnvironmentData, ReleaseCandidateStatusData, ReleaseChannelData,
    ReleaseDescriptorData, ReleaseDistributionData, ReleaseManifestV2Data,
    ReleasePredicateTypeData, ReleaseProvenanceStatusData, ReleaseProvenanceV2Data,
    ReleaseRollbackData, ReleaseRollbackStatusData, ReleaseSha256Data, ReleaseSigningData,
    ReleaseSubjectSetData, SchemaKind,
};
use serde::{Deserialize, Serialize};

use crate::cargo_env::{
    CargoCompilationTarget, CargoNetworkMode, prepared_cargo_environment, windows_msvc_build_inputs,
};
use sha2::{Digest, Sha256};
use tempfile::{TempDir, tempdir};

const RELEASE_VERSION: &str = env!("CARGO_PKG_VERSION");
const LICENSE_NOTICES_FILE: &str = "THIRD-PARTY-LICENSES.txt";
const LICENSE_BASELINE_FILE: &str = "licenses/release-baseline.json";
const LICENSE_POLICY_FILE: &str = "licenses/release-policy.json";
const LICENSE_BASELINE_SCHEMA: &str = "forge.license-bundle-baseline/v1";
const LICENSE_POLICY_SCHEMA: &str = "forge.license-bundle-exceptions/v1";
const EXPECTED_LICENSE_PACKAGES: usize = 96;
const EXPECTED_WORKSPACE_LICENSE_PACKAGES: usize = 6;
const EXPECTED_REGISTRY_LICENSE_PACKAGES: usize = 90;
const EXPECTED_LEGAL_FILES: usize = 198;
const MAX_LICENSE_POLICY_BYTES: u64 = 1024 * 1024;
const MAX_LICENSE_BASELINE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_CARGO_TREE_BYTES: usize = 32 * 1024 * 1024;
const MAX_CARGO_TREE_LINES: usize = 1_000_000;
const MAX_CARGO_BUILD_MESSAGES: usize = 1_000_000;
const MAX_LEGAL_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_LICENSE_SCAN_ENTRIES_PER_PACKAGE: usize = 100_000;
const MAX_LEGAL_FILES_PER_PACKAGE: usize = 4_096;
const MAX_TOTAL_LEGAL_FILE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_REGISTRY_CRATE_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_REGISTRY_CACHE_ENTRIES: usize = 1_000_000;
const MANIFEST_FILE: &str = "release-manifest.json";
const CHECKSUMS_FILE: &str = "SHA256SUMS";
const MAX_BINARY_BYTES: u64 = 256 * 1024 * 1024;
const MAX_SOURCE_FILE_BYTES: usize = 256 * 1024 * 1024;
const MAX_SOURCE_TREE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_METADATA_BYTES: usize = 32 * 1024 * 1024;
const MAX_GIT_INDEX_RECORD_BYTES: usize = 1024 * 1024;
const MAX_GIT_INDEX_ENTRIES: usize = 200_000;
const MAX_HASH_OBJECT_ARGUMENT_UNITS: usize = 16 * 1024;
const MAX_DIAGNOSTIC_BYTES: usize = 16 * 1024;
const MAX_BUILD_STREAM_BYTES: usize = 4 * 1024 * 1024;
const MAX_BUILD_INPUT_OBSERVATION_BYTES: usize = 512 * 1024;
const BUILD_INPUT_OBSERVATION_PREFIX: &str = "release-build-input-observation-";
const FINALIZED_ASSET_COUNT: u16 = 13;
const GIT_TIMEOUT: Duration = Duration::from_secs(120);
const CARGO_METADATA_TIMEOUT: Duration = Duration::from_secs(300);
const CARGO_BUILD_TIMEOUT: Duration = Duration::from_secs(1_800);
const REJECTED_RELEASE_GIT_ENV: &[&str] = &[
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_NAMESPACE",
    "GIT_SHALLOW_FILE",
    "GIT_REPLACE_REF_BASE",
    "GIT_EXEC_PATH",
];

pub(crate) const BUILD_HELP: &str = "usage: xtask release-build --target <TRIPLE> --output-dir <DIR> [--build-input-observation-dir <DIR>]\n\nBuilds one accepted target from a clean Git checkout in a fresh temporary Cargo target directory, then stages the binary and its source-bound CycloneDX 1.6 SBOM. The optional observation is a private, diagnostic-only pre-build record that can contain local toolchain paths; it is not a release asset or evidence and must not be uploaded raw. Run the compiled xtask directly when a nested `cargo run` is unsuitable.";
pub(crate) const FINALIZE_HELP: &str = "usage: xtask release-finalize --output-dir <DIR>\n\nRequires all five target binaries and SBOMs, then copies the source-bound license notices and writes release-manifest.json and SHA256SUMS without overwriting different bytes.";
pub(crate) const CHECK_HELP: &str = "usage: xtask release-check --output-dir <DIR>\n\nRecomputes the complete local asset set, binary formats, SBOMs, manifest, and SHA-256 checksums. Success is local consistency evidence, not provenance, signature, approval, upload, or publication.";
pub(crate) const LICENSE_CHECK_HELP: &str = "usage: xtask release-license-check\n\nRecomputes the reviewed five-target scoped Cargo tree graph, legal-file inventory, policy, and deterministic THIRD-PARTY-LICENSES.txt fixed point. Fetched .crate archive bytes must match Cargo.lock SHA-256; legal text is separately read and hashed from current unpacked sources, without claiming the archive check proves those unpacked bytes. Each native release-build must independently prove compiler-artifact parity before staging.";
pub(crate) const LICENSE_GENERATE_HELP: &str = "usage: xtask release-license-generate\n\nMaintainer-only regeneration of licenses/release-baseline.json and THIRD-PARTY-LICENSES.txt from the reviewed scoped Cargo tree graph. The reviewed policy is never modified. Generated evidence requires human review before commit and is never called by release-finalize.";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BinaryFormat {
    ElfX86_64Static,
    ElfAarch64Static,
    MachOX86_64,
    MachOAarch64,
    PeX86_64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReleaseTarget {
    triple: &'static str,
    executable_name: &'static str,
    format: BinaryFormat,
}

const RELEASE_TARGETS: [ReleaseTarget; 5] = [
    ReleaseTarget {
        triple: "x86_64-unknown-linux-musl",
        executable_name: "forge",
        format: BinaryFormat::ElfX86_64Static,
    },
    ReleaseTarget {
        triple: "aarch64-unknown-linux-musl",
        executable_name: "forge",
        format: BinaryFormat::ElfAarch64Static,
    },
    ReleaseTarget {
        triple: "x86_64-apple-darwin",
        executable_name: "forge",
        format: BinaryFormat::MachOX86_64,
    },
    ReleaseTarget {
        triple: "aarch64-apple-darwin",
        executable_name: "forge",
        format: BinaryFormat::MachOAarch64,
    },
    ReleaseTarget {
        triple: "x86_64-pc-windows-msvc",
        executable_name: "forge.exe",
        format: BinaryFormat::PeX86_64,
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReleaseErrorKind {
    Negative,
    Usage,
    Environment,
    Internal,
}

#[derive(Debug)]
pub(crate) struct ReleaseError {
    kind: ReleaseErrorKind,
    message: String,
}

impl ReleaseError {
    pub(crate) fn kind(&self) -> ReleaseErrorKind {
        self.kind
    }

    fn negative(message: impl Into<String>) -> Self {
        Self {
            kind: ReleaseErrorKind::Negative,
            message: message.into(),
        }
    }

    fn usage(message: impl Into<String>) -> Self {
        Self {
            kind: ReleaseErrorKind::Usage,
            message: message.into(),
        }
    }

    fn environment(message: impl Into<String>) -> Self {
        Self {
            kind: ReleaseErrorKind::Environment,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            kind: ReleaseErrorKind::Internal,
            message: message.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReleaseLicenseReport {
    pub(crate) package_count: usize,
    pub(crate) legal_file_count: usize,
}

impl fmt::Display for ReleaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ReleaseError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ReleaseCommandOutput {
    Help(&'static str),
    Completed(String),
}

#[derive(Debug)]
struct BuildRequest {
    target: &'static ReleaseTarget,
    output_directory: PathBuf,
    build_input_observation_directory: Option<PathBuf>,
}

#[derive(Debug)]
struct BuildInputObservationOutput {
    writer: RepositoryWriter,
    file_name: String,
}

#[derive(Debug)]
struct PreparedCargoInvocation {
    program: OsString,
    arguments: Vec<OsString>,
    working_directory: PathBuf,
    environment: EnvPolicy,
}

// This argv belongs only to the convenient local one-command path. A qualification plan must not
// carry it; the external release authority constructs and executes its own Cargo invocation from
// policy.
fn local_release_build_arguments(target: &ReleaseTarget, target_directory: &Path) -> Vec<OsString> {
    let mut arguments = [
        "build",
        "--release",
        "--locked",
        "--offline",
        "-p",
        "forge-cli",
        "--bin",
        "forge",
        "--message-format=json-render-diagnostics",
        "--target",
        target.triple,
        "--target-dir",
    ]
    .into_iter()
    .map(OsString::from)
    .collect::<Vec<_>>();
    arguments.push(target_directory.as_os_str().to_owned());
    arguments
}

fn release_build_completed_message(target: &ReleaseTarget, output_directory: &Path) -> String {
    format!(
        "built and staged {} with its CycloneDX SBOM in {}; local candidate only, not signed or published",
        binary_asset_name(target),
        output_directory.display()
    )
}

pub(crate) fn run_build(arguments: &[String]) -> Result<ReleaseCommandOutput, ReleaseError> {
    if is_help(arguments) {
        return Ok(ReleaseCommandOutput::Help(BUILD_HELP));
    }
    let request = parse_build_request(arguments)?;
    let repository = repository_root()?;
    let output = open_command_output_directory(&repository, &request.output_directory)?;
    let build_input_observation = request
        .build_input_observation_directory
        .as_deref()
        .map(|directory| {
            open_build_input_observation_output(&repository, &output, request.target, directory)
        })
        .transpose()?;
    let targets = std::slice::from_ref(request.target);
    let mut output_roots = vec![output.root()];
    if let Some(observation) = &build_input_observation {
        output_roots.push(observation.writer.root());
    }
    let source = ReleaseSource::prepare(&repository, targets, &output_roots)?;
    let build_directory = tempdir().map_err(|error| {
        ReleaseError::environment(format!(
            "failed to create a fresh temporary Cargo target directory: {error}"
        ))
    })?;
    let build_output = RepositoryWriter::new(build_directory.path()).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to pin the fresh Cargo target directory before building: {error}"
        ))
    })?;
    let built_packages = cargo_build(
        source.repository(),
        request.target,
        build_directory.path(),
        build_input_observation.as_ref(),
        &source.snapshot().source_commit,
    )?;
    source.require_unchanged(targets, "Cargo release build")?;
    let metadata: CargoMetadata =
        serde_json::from_slice(source.snapshot().metadata(request.target)?).map_err(|error| {
            ReleaseError::environment(format!(
                "Cargo metadata for {} is not valid JSON after the native release build: {error}",
                request.target.triple
            ))
        })?;
    let scoped_graph = parse_scoped_cargo_tree_graph(
        &metadata,
        source.snapshot().tree(request.target)?,
        request.target.triple,
    )?;
    require_native_build_graph_parity(
        &scoped_graph.package_ids,
        &built_packages,
        request.target.triple,
    )?;
    let binary = read_built_binary(&build_output, request.target)?;
    validate_binary_format(request.target, &binary)?;
    stage_built(&output, request.target, &binary, source.snapshot())?;
    source.require_unchanged(targets, "release asset staging")?;
    Ok(ReleaseCommandOutput::Completed(
        release_build_completed_message(request.target, output.root()),
    ))
}

fn parse_build_request(arguments: &[String]) -> Result<BuildRequest, ReleaseError> {
    let options = parse_options(
        arguments,
        &["--target", "--output-dir", "--build-input-observation-dir"],
    )?;
    Ok(BuildRequest {
        target: parse_target(required_option(&options, "--target")?)?,
        output_directory: PathBuf::from(required_option(&options, "--output-dir")?),
        build_input_observation_directory: options
            .get("--build-input-observation-dir")
            .map(PathBuf::from),
    })
}

pub(crate) fn run_finalize(arguments: &[String]) -> Result<ReleaseCommandOutput, ReleaseError> {
    if is_help(arguments) {
        return Ok(ReleaseCommandOutput::Help(FINALIZE_HELP));
    }
    let options = parse_options(arguments, &["--output-dir"])?;
    let output = PathBuf::from(required_option(&options, "--output-dir")?);
    let repository = repository_root()?;
    let output_writer = open_command_output_directory(&repository, &output)?;
    let source = ReleaseSource::prepare(&repository, &RELEASE_TARGETS, &[output_writer.root()])?;
    finalize(&output_writer, source.snapshot())?;
    source.require_unchanged(&RELEASE_TARGETS, "release finalization")?;
    Ok(ReleaseCommandOutput::Completed(format!(
        "finalized the complete local {} asset set in {}; external provenance, signature, approval, upload, and publication remain required",
        RELEASE_VERSION,
        output_writer.root().display()
    )))
}

pub(crate) fn run_check(arguments: &[String]) -> Result<ReleaseCommandOutput, ReleaseError> {
    if is_help(arguments) {
        return Ok(ReleaseCommandOutput::Help(CHECK_HELP));
    }
    let options = parse_options(arguments, &["--output-dir"])?;
    let output = PathBuf::from(required_option(&options, "--output-dir")?);
    let repository = repository_root()?;
    let output_writer = open_command_output_directory(&repository, &output)?;
    let source = ReleaseSource::prepare(&repository, &RELEASE_TARGETS, &[output_writer.root()])?;
    check(&output_writer, source.snapshot())?;
    source.require_unchanged(&RELEASE_TARGETS, "release verification")?;
    Ok(ReleaseCommandOutput::Completed(format!(
        "verified the complete local {} asset set in {}; this does not verify provenance, signature, approval, upload, or publication",
        RELEASE_VERSION,
        output_writer.root().display()
    )))
}

pub(crate) fn run_license_check(
    arguments: &[String],
) -> Result<ReleaseCommandOutput, ReleaseError> {
    if is_help(arguments) {
        return Ok(ReleaseCommandOutput::Help(LICENSE_CHECK_HELP));
    }
    if !arguments.is_empty() {
        return Err(ReleaseError::usage(
            "release-license-check accepts no options",
        ));
    }
    let repository = repository_root()?;
    let report = check_release_licenses(&repository)?;
    Ok(ReleaseCommandOutput::Completed(format!(
        "verified a scoped Cargo tree fixed point of {} release-license packages and {} legal files; fetched .crate archives match Cargo.lock SHA-256, unpacked legal files are separately hashed, and each native release-build must pass compiler-artifact parity before staging",
        report.package_count, report.legal_file_count
    )))
}

pub(crate) fn run_license_generate(
    arguments: &[String],
) -> Result<ReleaseCommandOutput, ReleaseError> {
    if is_help(arguments) {
        return Ok(ReleaseCommandOutput::Help(LICENSE_GENERATE_HELP));
    }
    if !arguments.is_empty() {
        return Err(ReleaseError::usage(
            "release-license-generate accepts no options",
        ));
    }
    let repository = repository_root()?;
    let report = generate_release_licenses(&repository, &repository)?;
    Ok(ReleaseCommandOutput::Completed(format!(
        "WARNING: regenerated a scoped Cargo tree fixed point of {} release-license packages and {} legal files without changing {}; review the complete baseline and notice diff before commit; this command is never release authority",
        report.package_count, report.legal_file_count, LICENSE_POLICY_FILE
    )))
}

fn is_help(arguments: &[String]) -> bool {
    matches!(arguments, [argument] if argument == "--help" || argument == "help")
}

fn parse_options(
    arguments: &[String],
    allowed: &[&str],
) -> Result<BTreeMap<String, String>, ReleaseError> {
    if arguments.is_empty() || arguments.len() % 2 != 0 {
        return Err(ReleaseError::usage(
            "release command options must be explicit `--name value` pairs",
        ));
    }
    let allowed: BTreeSet<&str> = allowed.iter().copied().collect();
    let mut options = BTreeMap::new();
    for pair in arguments.chunks_exact(2) {
        let name = &pair[0];
        let value = &pair[1];
        if !allowed.contains(name.as_str()) {
            return Err(ReleaseError::usage(format!(
                "unknown release option `{name}`"
            )));
        }
        if value.is_empty() || value.starts_with("--") {
            return Err(ReleaseError::usage(format!(
                "release option `{name}` requires a value"
            )));
        }
        if options.insert(name.clone(), value.clone()).is_some() {
            return Err(ReleaseError::usage(format!(
                "release option `{name}` was provided more than once"
            )));
        }
    }
    Ok(options)
}

fn required_option<'a>(
    options: &'a BTreeMap<String, String>,
    name: &str,
) -> Result<&'a str, ReleaseError> {
    options
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| ReleaseError::usage(format!("missing required release option `{name}`")))
}

fn parse_target(triple: &str) -> Result<&'static ReleaseTarget, ReleaseError> {
    RELEASE_TARGETS
        .iter()
        .find(|target| target.triple == triple)
        .ok_or_else(|| {
            ReleaseError::usage(format!(
                "unsupported release target `{triple}`; accepted targets: {}",
                RELEASE_TARGETS
                    .iter()
                    .map(|target| target.triple)
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })
}

fn repository_root() -> Result<PathBuf, ReleaseError> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| ReleaseError::internal("xtask manifest directory has no repository parent"))
}

fn cargo_program() -> OsString {
    env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WorktreeGuard {
    source_commit: String,
    status: Vec<u8>,
    index: Vec<u8>,
    raw_index: Vec<u8>,
    cargo_lock: Vec<u8>,
}

impl WorktreeGuard {
    fn capture(repository: &Path) -> Result<Self, ReleaseError> {
        require_expected_git_worktree(repository)?;
        require_safe_local_git_config(repository)?;
        let source_commit = git_head(repository)?;
        let raw_index = git_raw_index_snapshot(repository)?;
        let index = git_index_snapshot(repository, &source_commit)?;
        let status = git_status(repository)?;
        require_clean_status(&status)?;
        let cargo_lock = read_bounded(
            &repository.join("Cargo.lock"),
            MAX_METADATA_BYTES as u64,
            "Cargo.lock",
        )?;

        require_expected_git_worktree(repository)?;
        let later_lock = read_bounded(
            &repository.join("Cargo.lock"),
            MAX_METADATA_BYTES as u64,
            "Cargo.lock",
        )?;
        let later_status = git_status(repository)?;
        require_clean_status(&later_status)?;
        let later_commit = git_head(repository)?;
        let later_raw_index = git_raw_index_snapshot(repository)?;
        let later_index = git_index_snapshot(repository, &later_commit)?;
        if source_commit != later_commit
            || status != later_status
            || index != later_index
            || raw_index != later_raw_index
            || cargo_lock != later_lock
        {
            return Err(ReleaseError::environment(
                "repository HEAD, complete Git status, Git index projection, or Cargo.lock changed while the release snapshot was captured",
            ));
        }

        Ok(Self {
            source_commit,
            status,
            index,
            raw_index,
            cargo_lock,
        })
    }

    fn require_same(&self, later: &Self, operation: &str) -> Result<(), ReleaseError> {
        if self == later {
            Ok(())
        } else {
            Err(ReleaseError::environment(format!(
                "repository HEAD, complete Git status, semantic or raw Git index, or Cargo.lock changed during {operation}"
            )))
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RepositorySnapshot {
    source_commit: String,
    cargo_lock: Vec<u8>,
    license_notices: Vec<u8>,
    metadata_by_target: BTreeMap<String, Vec<u8>>,
    tree_by_target: BTreeMap<String, Vec<u8>>,
}

impl RepositorySnapshot {
    fn metadata(&self, target: &ReleaseTarget) -> Result<&[u8], ReleaseError> {
        self.metadata_by_target
            .get(target.triple)
            .map(Vec::as_slice)
            .ok_or_else(|| {
                ReleaseError::internal(format!(
                    "release snapshot omitted target-filtered Cargo metadata for {}",
                    target.triple
                ))
            })
    }

    fn tree(&self, target: &ReleaseTarget) -> Result<&[u8], ReleaseError> {
        self.tree_by_target
            .get(target.triple)
            .map(Vec::as_slice)
            .ok_or_else(|| {
                ReleaseError::internal(format!(
                    "release snapshot omitted scoped Cargo tree graph for {}",
                    target.triple
                ))
            })
    }

    fn require_same(&self, later: &Self, operation: &str) -> Result<(), ReleaseError> {
        if self == later {
            Ok(())
        } else {
            Err(ReleaseError::environment(format!(
                "isolated source commit, Cargo.lock, license notices, target-filtered Cargo metadata, or scoped Cargo tree graph changed during {operation}"
            )))
        }
    }
}

struct ReleaseSource {
    original_repository: PathBuf,
    original_guard: WorktreeGuard,
    _checkout_directory: TempDir,
    checkout: RepositoryWriter,
    snapshot: RepositorySnapshot,
    source_tree: SourceTreeSnapshot,
}

impl ReleaseSource {
    fn prepare(
        repository: &Path,
        targets: &[ReleaseTarget],
        forbidden_temporary_roots: &[&Path],
    ) -> Result<Self, ReleaseError> {
        let original_repository = fs::canonicalize(repository).map_err(|error| {
            ReleaseError::environment(format!(
                "failed to resolve release source repository {}: {error}",
                repository.display()
            ))
        })?;
        let original_guard = WorktreeGuard::capture(&original_repository)?;
        let (checkout_directory, checkout_path) = materialize_isolated_checkout(
            &original_repository,
            &original_guard.source_commit,
            forbidden_temporary_roots,
        )?;
        let isolated_guard = WorktreeGuard::capture(&checkout_path)?;
        if isolated_guard.source_commit != original_guard.source_commit
            || isolated_guard.index != original_guard.index
            || isolated_guard.cargo_lock != original_guard.cargo_lock
        {
            return Err(ReleaseError::environment(
                "isolated source checkout does not match the accepted commit, Git index projection, or Cargo.lock",
            ));
        }
        require_no_non_index_files(&checkout_path)?;
        detach_isolated_git_control(&checkout_directory, &checkout_path)?;
        let checkout = RepositoryWriter::new(&checkout_path).map_err(|error| {
            ReleaseError::environment(format!(
                "failed to pin the isolated source checkout {}: {error}",
                checkout_path.display()
            ))
        })?;
        validate_visible_root(&checkout, "isolated source checkout")?;
        let source_tree = capture_source_tree(&checkout)?;
        let license_notices = read_candidate_license_notices(&checkout)?;
        let metadata_by_target = capture_cargo_metadata(checkout.root(), targets)?;
        let tree_by_target = capture_cargo_trees(checkout.root(), targets)?;
        validate_cargo_metadata_source_boundaries(
            checkout.root(),
            targets,
            &metadata_by_target,
            &source_tree,
        )?;
        validate_scoped_cargo_tree_graphs(
            targets,
            &metadata_by_target,
            &tree_by_target,
            &isolated_guard.cargo_lock,
        )?;
        let snapshot = RepositorySnapshot {
            source_commit: isolated_guard.source_commit,
            cargo_lock: isolated_guard.cargo_lock,
            license_notices,
            metadata_by_target,
            tree_by_target,
        };
        if capture_source_tree(&checkout)? != source_tree {
            return Err(ReleaseError::environment(
                "Cargo metadata changed the detached isolated source tree",
            ));
        }
        original_guard.require_same(
            &WorktreeGuard::capture(&original_repository)?,
            "isolated source checkout materialization",
        )?;

        Ok(Self {
            original_repository,
            original_guard,
            _checkout_directory: checkout_directory,
            checkout,
            snapshot,
            source_tree,
        })
    }

    fn repository(&self) -> &Path {
        self.checkout.root()
    }

    fn snapshot(&self) -> &RepositorySnapshot {
        &self.snapshot
    }

    fn require_unchanged(
        &self,
        targets: &[ReleaseTarget],
        operation: &str,
    ) -> Result<(), ReleaseError> {
        validate_visible_root(&self.checkout, "isolated source checkout")?;
        if capture_source_tree(&self.checkout)? != self.source_tree {
            return Err(ReleaseError::environment(format!(
                "detached isolated source tree changed during {operation}"
            )));
        }
        let metadata_by_target = capture_cargo_metadata(self.checkout.root(), targets)?;
        let tree_by_target = capture_cargo_trees(self.checkout.root(), targets)?;
        validate_cargo_metadata_source_boundaries(
            self.checkout.root(),
            targets,
            &metadata_by_target,
            &self.source_tree,
        )?;
        validate_scoped_cargo_tree_graphs(
            targets,
            &metadata_by_target,
            &tree_by_target,
            &self.snapshot.cargo_lock,
        )?;
        self.snapshot.require_same(
            &RepositorySnapshot {
                source_commit: self.snapshot.source_commit.clone(),
                cargo_lock: self.snapshot.cargo_lock.clone(),
                license_notices: read_candidate_license_notices(&self.checkout)?,
                metadata_by_target,
                tree_by_target,
            },
            operation,
        )?;
        if capture_source_tree(&self.checkout)? != self.source_tree {
            return Err(ReleaseError::environment(format!(
                "detached isolated source tree changed while metadata was checked during {operation}"
            )));
        }
        self.original_guard.require_same(
            &WorktreeGuard::capture(&self.original_repository)?,
            operation,
        )?;
        validate_visible_root(&self.checkout, "isolated source checkout")
    }
}

fn read_candidate_license_notices(source: &RepositoryWriter) -> Result<Vec<u8>, ReleaseError> {
    validate_visible_root(source, "isolated source checkout")?;
    let notices = source
        .read_optional_bounded(LICENSE_NOTICES_FILE, MAX_SOURCE_FILE_BYTES)
        .map_err(|error| {
            ReleaseError::environment(format!(
                "failed to read source-bound {LICENSE_NOTICES_FILE}: {error}"
            ))
        })?
        .ok_or_else(|| {
            ReleaseError::environment(format!(
                "release source is missing required {LICENSE_NOTICES_FILE}"
            ))
        })?;
    validate_visible_root(source, "isolated source checkout")?;
    if notices.is_empty() {
        return Err(ReleaseError::environment(format!(
            "release source {LICENSE_NOTICES_FILE} must not be empty"
        )));
    }
    Ok(notices)
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SourceTreeEntry {
    Directory {
        permissions: u32,
    },
    File {
        length: u64,
        sha256: String,
        permissions: u32,
    },
}

type SourceTreeSnapshot = BTreeMap<RepoRelativePath, SourceTreeEntry>;

fn git_output(
    repository: &Path,
    arguments: &[&str],
    label: &str,
    stdout_limit: usize,
) -> Result<Vec<u8>, ReleaseError> {
    git_output_os(
        repository,
        arguments.iter().map(OsString::from).collect(),
        label,
        stdout_limit,
    )
}

fn git_output_os(
    repository: &Path,
    arguments: Vec<OsString>,
    label: &str,
    stdout_limit: usize,
) -> Result<Vec<u8>, ReleaseError> {
    reject_git_redirect_environment(env::vars_os().map(|(key, _)| key))?;
    let canonical_repository = fs::canonicalize(repository).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to resolve release source repository {}: {error}",
            repository.display()
        ))
    })?;
    let mut worktree_argument = OsString::from("--work-tree=");
    worktree_argument.push(canonical_repository.as_os_str());
    let mut argv: Vec<OsString> = HARDENED_GIT_GLOBAL_ARGS
        .iter()
        .map(OsString::from)
        .collect();
    argv.push(worktree_argument);
    argv.extend(arguments);
    let observation = run_bounded_process(
        repository,
        OsString::from("git"),
        argv,
        hardened_git_environment(),
        GIT_TIMEOUT,
        stdout_limit,
        MAX_DIAGNOSTIC_BYTES,
        Mutability::ReadOnly,
        NetworkIntent::Unknown,
        &format!("Git {label}"),
    )?;
    require_process_success(observation, &format!("Git {label}"))
}

fn hardened_git_environment() -> EnvPolicy {
    let mut environment = EnvPolicy::minimal();
    environment.overrides.extend(
        HARDENED_GIT_ENV
            .iter()
            .map(|(key, value)| (OsString::from(key), OsString::from(value))),
    );
    environment.overrides.extend([
        (
            OsString::from("GIT_CONFIG_GLOBAL"),
            OsString::from(empty_git_config_path()),
        ),
        (OsString::from("GIT_CONFIG_NOSYSTEM"), OsString::from("1")),
        (OsString::from("GIT_ATTR_NOSYSTEM"), OsString::from("1")),
        (OsString::from("GIT_LFS_SKIP_SMUDGE"), OsString::from("1")),
    ]);
    environment
}

#[cfg(windows)]
const fn empty_git_config_path() -> &'static str {
    "NUL"
}

#[cfg(not(windows))]
const fn empty_git_config_path() -> &'static str {
    "/dev/null"
}

fn materialize_isolated_checkout(
    repository: &Path,
    source_commit: &str,
    forbidden_temporary_roots: &[&Path],
) -> Result<(TempDir, PathBuf), ReleaseError> {
    reject_git_redirect_environment(env::vars_os().map(|(key, _)| key))?;
    let checkout_directory = tempdir().map_err(|error| {
        ReleaseError::environment(format!(
            "failed to create a private isolated source directory: {error}"
        ))
    })?;
    require_isolated_temp_boundary(
        repository,
        checkout_directory.path(),
        forbidden_temporary_roots,
    )?;
    let empty_git_config = checkout_directory.path().join("empty-gitconfig");
    File::create(&empty_git_config).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to create the isolated checkout Git config: {error}"
        ))
    })?;
    let isolated_home = checkout_directory.path().join("home");
    let isolated_xdg = checkout_directory.path().join("xdg");
    let isolated_hooks = checkout_directory.path().join("hooks");
    let isolated_template = checkout_directory.path().join("template");
    for directory in [
        &isolated_home,
        &isolated_xdg,
        &isolated_hooks,
        &isolated_template,
    ] {
        fs::create_dir(directory).map_err(|error| {
            ReleaseError::environment(format!(
                "failed to create isolated Git environment directory {}: {error}",
                directory.display()
            ))
        })?;
    }
    let checkout = checkout_directory.path().join("source");
    let git_control = checkout_directory.path().join("git-control");
    let mut environment = hardened_git_environment();
    environment.overrides.extend([
        (
            OsString::from("GIT_CONFIG_GLOBAL"),
            empty_git_config.as_os_str().to_owned(),
        ),
        (OsString::from("GIT_CONFIG_NOSYSTEM"), OsString::from("1")),
        (OsString::from("GIT_ATTR_NOSYSTEM"), OsString::from("1")),
        (OsString::from("GIT_LFS_SKIP_SMUDGE"), OsString::from("1")),
        (OsString::from("HOME"), isolated_home.as_os_str().to_owned()),
        (
            OsString::from("USERPROFILE"),
            isolated_home.as_os_str().to_owned(),
        ),
        (
            OsString::from("XDG_CONFIG_HOME"),
            isolated_xdg.as_os_str().to_owned(),
        ),
        (
            OsString::from("APPDATA"),
            isolated_xdg.as_os_str().to_owned(),
        ),
        (
            OsString::from("LOCALAPPDATA"),
            isolated_xdg.as_os_str().to_owned(),
        ),
    ]);

    let mut hooks_config = OsString::from("core.hooksPath=");
    hooks_config.push(isolated_hooks.as_os_str());
    let mut separate_git_directory = OsString::from("--separate-git-dir=");
    separate_git_directory.push(git_control.as_os_str());
    let mut template_directory = OsString::from("--template=");
    template_directory.push(isolated_template.as_os_str());

    let mut clone_arguments: Vec<OsString> = HARDENED_GIT_GLOBAL_ARGS
        .iter()
        .map(OsString::from)
        .collect();
    clone_arguments.extend([
        OsString::from("-c"),
        hooks_config.clone(),
        OsString::from("-c"),
        OsString::from("protocol.allow=never"),
        OsString::from("-c"),
        OsString::from("protocol.file.allow=always"),
    ]);
    clone_arguments.extend([
        OsString::from("clone"),
        OsString::from("--quiet"),
        OsString::from("--no-local"),
        OsString::from("--no-checkout"),
        OsString::from("--no-tags"),
        OsString::from("--no-recurse-submodules"),
        separate_git_directory,
        template_directory,
        OsString::from("--"),
        // Rust canonicalizes Windows paths to a verbatim spelling such as `\\?\C:\...`, which
        // Git can reinterpret as scp-style SSH. The runner pins this repository as its cwd, so
        // `.` names the same local source without translating native path bytes.
        OsString::from("."),
        checkout.as_os_str().to_owned(),
    ]);
    let clone = run_bounded_process(
        repository,
        OsString::from("git"),
        clone_arguments,
        environment.clone(),
        GIT_TIMEOUT,
        MAX_DIAGNOSTIC_BYTES,
        MAX_DIAGNOSTIC_BYTES,
        Mutability::WorkingTreeWrite,
        NetworkIntent::OfflineRequested,
        "isolated local Git clone",
    )?;
    let _ = require_process_success(clone, "isolated local Git clone")?;

    let mut checkout_arguments: Vec<OsString> = HARDENED_GIT_GLOBAL_ARGS
        .iter()
        .map(OsString::from)
        .collect();
    checkout_arguments.extend([
        OsString::from("-c"),
        hooks_config.clone(),
        OsString::from("-c"),
        OsString::from("core.autocrlf=false"),
        OsString::from("-C"),
        checkout.as_os_str().to_owned(),
        OsString::from("checkout"),
        OsString::from("--quiet"),
        OsString::from("--detach"),
        OsString::from("--force"),
        OsString::from(source_commit),
        OsString::from("--"),
    ]);
    let checkout_observation = run_bounded_process(
        checkout_directory.path(),
        OsString::from("git"),
        checkout_arguments,
        environment.clone(),
        GIT_TIMEOUT,
        MAX_DIAGNOSTIC_BYTES,
        MAX_DIAGNOSTIC_BYTES,
        Mutability::WorkingTreeWrite,
        NetworkIntent::OfflineRequested,
        "isolated Git checkout",
    )?;
    let _ = require_process_success(checkout_observation, "isolated Git checkout")?;

    let mut fsck_arguments: Vec<OsString> = HARDENED_GIT_GLOBAL_ARGS
        .iter()
        .map(OsString::from)
        .collect();
    fsck_arguments.extend([
        OsString::from("-c"),
        hooks_config,
        OsString::from("-C"),
        checkout.as_os_str().to_owned(),
        OsString::from("fsck"),
        OsString::from("--full"),
        OsString::from("--strict"),
        OsString::from("--no-dangling"),
        OsString::from("--no-progress"),
        OsString::from("--no-reflogs"),
        OsString::from(source_commit),
    ]);
    let fsck = run_bounded_process(
        checkout_directory.path(),
        OsString::from("git"),
        fsck_arguments,
        environment,
        GIT_TIMEOUT,
        MAX_DIAGNOSTIC_BYTES,
        MAX_DIAGNOSTIC_BYTES,
        Mutability::ReadOnly,
        NetworkIntent::OfflineRequested,
        "isolated Git object verification",
    )?;
    let _ = require_process_success(fsck, "isolated Git object verification")?;
    let alternates = git_control.join("objects").join("info").join("alternates");
    match fs::symlink_metadata(&alternates) {
        Ok(_) => {
            return Err(ReleaseError::environment(format!(
                "isolated Git clone retained an external object alternate at {}",
                alternates.display()
            )));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(ReleaseError::environment(format!(
                "failed to inspect isolated Git alternate path {}: {error}",
                alternates.display()
            )));
        }
    }
    require_checkout_matches_index(&checkout, source_commit)?;
    Ok((checkout_directory, checkout))
}

fn require_isolated_temp_boundary(
    repository: &Path,
    temporary_root: &Path,
    additional_forbidden_roots: &[&Path],
) -> Result<(), ReleaseError> {
    let temporary_root = fs::canonicalize(temporary_root).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to resolve isolated source temporary directory {}: {error}",
            temporary_root.display()
        ))
    })?;
    let repository = fs::canonicalize(repository).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to resolve release source repository {}: {error}",
            repository.display()
        ))
    })?;
    let private_directories = git_private_directories(repository.as_path())?;
    let mut forbidden_roots = vec![(repository, "source repository")];
    forbidden_roots.extend(private_directories);
    for root in additional_forbidden_roots {
        let root = fs::canonicalize(root).map_err(|error| {
            ReleaseError::environment(format!(
                "failed to resolve forbidden release temporary root {}: {error}",
                root.display()
            ))
        })?;
        forbidden_roots.push((root, "release output"));
    }
    for (root, label) in forbidden_roots {
        if temporary_root == root || temporary_root.starts_with(&root) {
            return Err(ReleaseError::environment(format!(
                "isolated source temporary directory must be outside the {label}: {}",
                temporary_root.display()
            )));
        }
    }
    Ok(())
}

fn require_no_non_index_files(repository: &Path) -> Result<(), ReleaseError> {
    let paths = git_output(
        repository,
        &["ls-files", "--others", "--directory", "-z", "--"],
        "non-index worktree read",
        MAX_METADATA_BYTES,
    )?;
    if paths.is_empty() {
        Ok(())
    } else {
        Err(ReleaseError::environment(
            "isolated source checkout contains files absent from the exact commit index, including ignored files",
        ))
    }
}

fn detach_isolated_git_control(
    checkout_directory: &TempDir,
    checkout: &Path,
) -> Result<(), ReleaseError> {
    let expected =
        fs::canonicalize(checkout_directory.path().join("git-control")).map_err(|error| {
            ReleaseError::environment(format!(
                "failed to resolve isolated Git control directory: {error}"
            ))
        })?;
    let reported = git_path_from_output(&git_output(
        checkout,
        &["rev-parse", "--path-format=absolute", "--git-dir"],
        "isolated Git control directory read",
        64 * 1024,
    )?)?;
    let reported = fs::canonicalize(&reported).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to resolve Git-reported isolated control directory {}: {error}",
            reported.display()
        ))
    })?;
    if reported != expected {
        return Err(ReleaseError::environment(format!(
            "isolated checkout Git control directory {} does not match expected {}",
            reported.display(),
            expected.display()
        )));
    }

    let marker = checkout.join(".git");
    let metadata = fs::symlink_metadata(&marker).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to inspect isolated checkout Git marker {}: {error}",
            marker.display()
        ))
    })?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(ReleaseError::environment(format!(
            "isolated checkout Git marker is not a real regular file: {}",
            marker.display()
        )));
    }
    fs::remove_file(&marker).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to detach Git control metadata from isolated source {}: {error}",
            marker.display()
        ))
    })?;
    if fs::symlink_metadata(&marker).is_ok() {
        return Err(ReleaseError::environment(format!(
            "isolated source still exposes Git control metadata at {}",
            marker.display()
        )));
    }
    Ok(())
}

fn capture_cargo_metadata(
    repository: &Path,
    targets: &[ReleaseTarget],
) -> Result<BTreeMap<String, Vec<u8>>, ReleaseError> {
    targets
        .iter()
        .map(|target| {
            Ok((
                target.triple.to_owned(),
                cargo_metadata(repository, target)?,
            ))
        })
        .collect()
}

fn capture_cargo_trees(
    repository: &Path,
    targets: &[ReleaseTarget],
) -> Result<BTreeMap<String, Vec<u8>>, ReleaseError> {
    targets
        .iter()
        .map(|target| Ok((target.triple.to_owned(), cargo_tree(repository, target)?)))
        .collect()
}

fn validate_scoped_cargo_tree_graphs(
    targets: &[ReleaseTarget],
    metadata_by_target: &BTreeMap<String, Vec<u8>>,
    tree_by_target: &BTreeMap<String, Vec<u8>>,
    cargo_lock: &[u8],
) -> Result<(), ReleaseError> {
    let lock = parse_cargo_lock(cargo_lock)?;
    let lock_packages = cargo_lock_packages(&lock)?;
    for target in targets {
        let metadata_bytes = metadata_by_target.get(target.triple).ok_or_else(|| {
            ReleaseError::internal(format!(
                "release snapshot omitted Cargo metadata for {}",
                target.triple
            ))
        })?;
        let tree_bytes = tree_by_target.get(target.triple).ok_or_else(|| {
            ReleaseError::internal(format!(
                "release snapshot omitted scoped Cargo tree graph for {}",
                target.triple
            ))
        })?;
        let metadata: CargoMetadata = serde_json::from_slice(metadata_bytes).map_err(|error| {
            ReleaseError::environment(format!(
                "Cargo metadata for {} is not valid JSON: {error}",
                target.triple
            ))
        })?;
        let graph = parse_scoped_cargo_tree_graph(&metadata, tree_bytes, target.triple)?;
        let packages: BTreeMap<_, _> = metadata
            .packages
            .iter()
            .map(|package| (package.id.as_str(), package))
            .collect();
        for package_id in &graph.package_ids {
            let package = packages.get(package_id.as_str()).ok_or_else(|| {
                ReleaseError::internal("scoped Cargo tree package disappeared from metadata")
            })?;
            if let Some(checksum) = release_package_lock_checksum(package, &lock_packages)? {
                let manifest = package.manifest_path.as_deref().ok_or_else(|| {
                    ReleaseError::environment(format!(
                        "registry dependency {} omitted manifest_path",
                        release_license_package_id(package)
                    ))
                })?;
                let package_root = manifest.parent().ok_or_else(|| {
                    ReleaseError::environment(format!(
                        "registry dependency {} has no package root",
                        release_license_package_id(package)
                    ))
                })?;
                verify_registry_crate_archive(package, package_root, &checksum)?;
            }
        }
    }
    Ok(())
}

fn validate_cargo_metadata_source_boundaries(
    repository: &Path,
    targets: &[ReleaseTarget],
    metadata_by_target: &BTreeMap<String, Vec<u8>>,
    source_tree: &SourceTreeSnapshot,
) -> Result<(), ReleaseError> {
    let repository = fs::canonicalize(repository).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to resolve isolated Cargo workspace root {}: {error}",
            repository.display()
        ))
    })?;
    for target in targets {
        let bytes = metadata_by_target.get(target.triple).ok_or_else(|| {
            ReleaseError::internal(format!(
                "release snapshot omitted target-filtered Cargo metadata for {}",
                target.triple
            ))
        })?;
        let metadata: CargoMetadata = serde_json::from_slice(bytes).map_err(|error| {
            ReleaseError::environment(format!(
                "Cargo metadata for {} is not valid JSON: {error}",
                target.triple
            ))
        })?;
        let workspace_root = metadata.workspace_root.as_deref().ok_or_else(|| {
            ReleaseError::environment(format!(
                "Cargo metadata for {} omitted workspace_root",
                target.triple
            ))
        })?;
        let workspace_root = fs::canonicalize(workspace_root).map_err(|error| {
            ReleaseError::environment(format!(
                "failed to resolve Cargo workspace_root {} for {}: {error}",
                workspace_root.display(),
                target.triple
            ))
        })?;
        if workspace_root != repository {
            return Err(ReleaseError::environment(format!(
                "Cargo workspace_root {} for {} escapes isolated source root {}",
                workspace_root.display(),
                target.triple,
                repository.display()
            )));
        }

        let workspace_members: BTreeSet<_> = metadata
            .workspace_members
            .iter()
            .map(String::as_str)
            .collect();
        for package in metadata
            .packages
            .iter()
            .filter(|package| package.source.is_none())
        {
            if !workspace_members.contains(package.id.as_str()) {
                return Err(ReleaseError::environment(format!(
                    "source-bound release metadata rejects local package outside the exact workspace: `{}`",
                    package.id
                )));
            }
            let manifest = package.manifest_path.as_deref().ok_or_else(|| {
                ReleaseError::environment(format!(
                    "local workspace package `{}` omitted manifest_path",
                    package.id
                ))
            })?;
            validate_cargo_source_file(
                &repository,
                source_tree,
                manifest,
                &format!("manifest for local workspace package `{}`", package.id),
            )?;
            if package.targets.is_empty() {
                return Err(ReleaseError::environment(format!(
                    "local workspace package `{}` has no declared Cargo targets",
                    package.id
                )));
            }
            for cargo_target in &package.targets {
                let source = cargo_target.src_path.as_deref().ok_or_else(|| {
                    ReleaseError::environment(format!(
                        "a target for local workspace package `{}` omitted src_path",
                        package.id
                    ))
                })?;
                validate_cargo_source_file(
                    &repository,
                    source_tree,
                    source,
                    &format!("target source for local workspace package `{}`", package.id),
                )?;
            }
        }
    }
    Ok(())
}

fn validate_cargo_source_file(
    repository: &Path,
    source_tree: &SourceTreeSnapshot,
    path: &Path,
    label: &str,
) -> Result<(), ReleaseError> {
    if !path.is_absolute() {
        return Err(ReleaseError::environment(format!(
            "{label} is not an absolute Cargo metadata path: {}",
            path.display()
        )));
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to inspect {label} {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.is_file() || source_entry_is_link_or_reparse(&metadata) {
        return Err(ReleaseError::environment(format!(
            "{label} is not a real regular file: {}",
            path.display()
        )));
    }
    let canonical = fs::canonicalize(path).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to resolve {label} {}: {error}",
            path.display()
        ))
    })?;
    let relative = canonical.strip_prefix(repository).map_err(|_| {
        ReleaseError::environment(format!(
            "{label} {} escapes isolated source root {}",
            canonical.display(),
            repository.display()
        ))
    })?;
    let relative = RepoRelativePath::new(relative).map_err(|error| {
        ReleaseError::environment(format!(
            "{label} has an invalid isolated source path {}: {error}",
            relative.display()
        ))
    })?;
    if !matches!(
        source_tree.get(&relative),
        Some(SourceTreeEntry::File { .. })
    ) {
        return Err(ReleaseError::environment(format!(
            "{label} is not covered by the detached source tree snapshot: {}",
            canonical.display()
        )));
    }
    Ok(())
}

fn capture_source_tree(writer: &RepositoryWriter) -> Result<SourceTreeSnapshot, ReleaseError> {
    validate_visible_root(writer, "isolated source checkout")?;
    let mut snapshot = BTreeMap::new();
    let mut total_bytes = 0_u64;
    capture_source_directory(writer, Path::new(""), &mut snapshot, &mut total_bytes)?;
    validate_visible_root(writer, "isolated source checkout")?;
    Ok(snapshot)
}

fn capture_source_directory(
    writer: &RepositoryWriter,
    relative_directory: &Path,
    snapshot: &mut SourceTreeSnapshot,
    total_bytes: &mut u64,
) -> Result<(), ReleaseError> {
    let directory = writer.root().join(relative_directory);
    let entries =
        read_bounded_source_directory_entries(&directory, snapshot.len(), MAX_GIT_INDEX_ENTRIES)?;
    for entry in entries {
        if snapshot.len() >= MAX_GIT_INDEX_ENTRIES {
            return Err(ReleaseError::environment(format!(
                "isolated source contains more than {MAX_GIT_INDEX_ENTRIES} filesystem entries"
            )));
        }
        let relative = relative_directory.join(entry.file_name());
        if relative == Path::new(".git") {
            return Err(ReleaseError::environment(
                "isolated source unexpectedly exposes Git control metadata",
            ));
        }
        let relative = RepoRelativePath::new(&relative).map_err(|error| {
            ReleaseError::environment(format!(
                "isolated source contains an invalid repository path {}: {error}",
                relative.display()
            ))
        })?;
        let path = writer.root().join(relative.as_path());
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            ReleaseError::environment(format!(
                "failed to inspect isolated source entry {}: {error}",
                path.display()
            ))
        })?;
        if source_entry_is_link_or_reparse(&metadata) {
            return Err(ReleaseError::environment(format!(
                "isolated source entry is a symbolic link or reparse point: {}",
                relative.as_path().display()
            )));
        }
        if metadata.is_dir() {
            snapshot.insert(
                relative.clone(),
                SourceTreeEntry::Directory {
                    permissions: source_entry_permissions(&metadata),
                },
            );
            capture_source_directory(writer, relative.as_path(), snapshot, total_bytes)?;
            continue;
        }
        if !metadata.is_file() {
            return Err(ReleaseError::environment(format!(
                "isolated source entry is not a regular file or directory: {}",
                relative.as_path().display()
            )));
        }
        let bytes = writer
            .read_optional_bounded(relative.as_path(), MAX_SOURCE_FILE_BYTES)
            .map_err(|error| {
                ReleaseError::environment(format!(
                    "failed to read isolated source file {}: {error}",
                    relative.as_path().display()
                ))
            })?
            .ok_or_else(|| {
                ReleaseError::environment(format!(
                    "isolated source file disappeared while being read: {}",
                    relative.as_path().display()
                ))
            })?;
        let length = u64::try_from(bytes.len()).map_err(|_| {
            ReleaseError::environment("isolated source file length is not representable")
        })?;
        *total_bytes = total_bytes.checked_add(length).ok_or_else(|| {
            ReleaseError::environment("isolated source tree byte length overflowed")
        })?;
        if *total_bytes > MAX_SOURCE_TREE_BYTES {
            return Err(ReleaseError::environment(format!(
                "isolated source tree exceeds the {MAX_SOURCE_TREE_BYTES}-byte bound"
            )));
        }
        snapshot.insert(
            relative,
            SourceTreeEntry::File {
                length,
                sha256: sha256_hex(&bytes),
                permissions: source_entry_permissions(&metadata),
            },
        );
    }
    Ok(())
}

fn read_bounded_source_directory_entries(
    directory: &Path,
    existing_entries: usize,
    max_entries: usize,
) -> Result<Vec<fs::DirEntry>, ReleaseError> {
    let reader = fs::read_dir(directory).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to enumerate isolated source directory {}: {error}",
            directory.display()
        ))
    })?;
    let mut entries = Vec::new();
    for entry in reader {
        if existing_entries
            .checked_add(entries.len())
            .is_none_or(|count| count >= max_entries)
        {
            return Err(ReleaseError::environment(format!(
                "isolated source contains more than {max_entries} filesystem entries"
            )));
        }
        entries.push(entry.map_err(|error| {
            ReleaseError::environment(format!(
                "failed to enumerate isolated source directory {}: {error}",
                directory.display()
            ))
        })?);
    }
    entries.sort_by_key(fs::DirEntry::file_name);
    Ok(entries)
}

#[cfg(unix)]
fn source_entry_permissions(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;

    metadata.permissions().mode() & 0o7777
}

#[cfg(windows)]
fn source_entry_permissions(metadata: &fs::Metadata) -> u32 {
    use std::os::windows::fs::MetadataExt as _;

    metadata.file_attributes()
}

#[cfg(not(any(unix, windows)))]
fn source_entry_permissions(metadata: &fs::Metadata) -> u32 {
    u32::from(metadata.permissions().readonly())
}

#[cfg(windows)]
fn source_entry_is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn source_entry_is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

fn reject_git_redirect_environment<I>(keys: I) -> Result<(), ReleaseError>
where
    I: IntoIterator<Item = OsString>,
{
    for key in keys {
        if let Some(rejected) = REJECTED_RELEASE_GIT_ENV
            .iter()
            .find(|candidate| git_environment_key_eq(&key, candidate))
        {
            return Err(ReleaseError::environment(format!(
                "ambient Git environment variable `{rejected}` could redirect the release source snapshot; unset it"
            )));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn git_environment_key_eq(key: &std::ffi::OsStr, expected: &str) -> bool {
    key.to_string_lossy().eq_ignore_ascii_case(expected)
}

#[cfg(not(windows))]
fn git_environment_key_eq(key: &std::ffi::OsStr, expected: &str) -> bool {
    key == std::ffi::OsStr::new(expected)
}

fn git_head(repository: &Path) -> Result<String, ReleaseError> {
    let bytes = git_output(
        repository,
        &["rev-parse", "--verify", "HEAD^{commit}"],
        "HEAD read",
        128,
    )?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| ReleaseError::environment("Git HEAD output was not UTF-8"))?
        .trim_end_matches(['\r', '\n']);
    if !matches!(text.len(), 40 | 64)
        || !text
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(ReleaseError::environment(
            "Git HEAD was not one canonical SHA-1 or SHA-256 commit object ID",
        ));
    }
    Ok(text.to_owned())
}

fn git_status(repository: &Path) -> Result<Vec<u8>, ReleaseError> {
    git_output(
        repository,
        &[
            "status",
            "--porcelain=v2",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ],
        "complete status read",
        MAX_METADATA_BYTES,
    )
}

fn require_safe_local_git_config(repository: &Path) -> Result<(), ReleaseError> {
    for (scope, label) in [
        ("--local", "local configuration key read"),
        ("--worktree", "worktree configuration key read"),
    ] {
        let keys = git_output(
            repository,
            &[
                "config",
                "--no-includes",
                scope,
                "--name-only",
                "--null",
                "--list",
            ],
            label,
            MAX_METADATA_BYTES,
        )?;
        for raw in keys.split(|byte| *byte == 0).filter(|raw| !raw.is_empty()) {
            let key = std::str::from_utf8(raw).map_err(|_| {
                ReleaseError::environment("Git configuration contains a non-UTF-8 key")
            })?;
            let key = key.to_ascii_lowercase();
            if key.starts_with("filter.")
                || key.starts_with("include.")
                || key.starts_with("includeif.")
                || key == "uploadpack.packobjectshook"
                || key == "core.alternaterefscommand"
            {
                return Err(ReleaseError::environment(format!(
                    "release assembly rejects executable or externally included {scope} Git configuration key `{key}`"
                )));
            }
        }
    }
    Ok(())
}

fn git_raw_index_snapshot(repository: &Path) -> Result<Vec<u8>, ReleaseError> {
    GitCli::new()
        .with_timeout(GIT_TIMEOUT)
        .index_snapshot_bytes(repository, MAX_METADATA_BYTES)
        .map_err(|error| {
            ReleaseError::environment(format!(
                "failed to capture the bounded raw Git index without links, locks, or split-index omissions: {error}"
            ))
        })
}

fn git_index_snapshot(repository: &Path, source_commit: &str) -> Result<Vec<u8>, ReleaseError> {
    let bytes = git_output(
        repository,
        &["ls-files", "--stage", "-v", "-z", "--"],
        "complete index read",
        MAX_METADATA_BYTES,
    )?;
    let _ = validated_git_index_entries(&bytes, source_commit)?;
    Ok(bytes)
}

fn validated_git_index_entries(
    bytes: &[u8],
    source_commit: &str,
) -> Result<Vec<GitIndexEntry>, ReleaseError> {
    let object_format = match source_commit.len() {
        40 => GitObjectFormat::Sha1,
        64 => GitObjectFormat::Sha256,
        _ => {
            return Err(ReleaseError::internal(
                "validated Git commit has an unsupported object ID width",
            ));
        }
    };
    let entries = parse_git_index_reader(
        Cursor::new(&bytes),
        object_format,
        MAX_GIT_INDEX_RECORD_BYTES,
        MAX_GIT_INDEX_ENTRIES,
    )
    .map_err(|error| {
        ReleaseError::environment(format!(
            "failed to parse the complete Git index projection: {error}"
        ))
    })?;
    for entry in &entries {
        if entry.tag != GitIndexTag::Cached || entry.stage != 0 {
            return Err(ReleaseError::environment(format!(
                "release assembly rejects non-ordinary Git index state for {}; clear skip-worktree, assume-unchanged, sparse, removed, killed, or unmerged state before retrying",
                entry.path.as_path().display()
            )));
        }
        if !matches!(entry.mode.as_bytes(), b"100644" | b"100755") {
            return Err(ReleaseError::environment(format!(
                "release assembly supports only regular tracked files, but {} has Git mode {}",
                entry.path.as_path().display(),
                String::from_utf8_lossy(entry.mode.as_bytes())
            )));
        }
    }
    Ok(entries)
}

fn require_checkout_matches_index(
    repository: &Path,
    source_commit: &str,
) -> Result<(), ReleaseError> {
    let index = git_index_snapshot(repository, source_commit)?;
    let entries = validated_git_index_entries(&index, source_commit)?;
    let object_id_width = source_commit.len();
    let mut start = 0;
    while start < entries.len() {
        let mut arguments = vec![
            OsString::from("hash-object"),
            OsString::from("--no-filters"),
            OsString::from("--"),
        ];
        let mut argument_units = arguments
            .iter()
            .map(|argument| command_argument_units(argument.as_os_str()).saturating_add(1))
            .sum::<usize>();
        let mut end = start;
        while end < entries.len() {
            let path = entries[end].path.as_path();
            let path_units = command_argument_units(path.as_os_str()).saturating_add(1);
            let next_units = argument_units.checked_add(path_units).ok_or_else(|| {
                ReleaseError::environment("Git hash-object command length overflowed")
            })?;
            if next_units > MAX_HASH_OBJECT_ARGUMENT_UNITS {
                if end == start {
                    return Err(ReleaseError::environment(format!(
                        "tracked source path is too long for bounded exact-byte verification: {}",
                        path.display()
                    )));
                }
                break;
            }
            let absolute = repository.join(path);
            let metadata = fs::symlink_metadata(&absolute).map_err(|error| {
                ReleaseError::environment(format!(
                    "failed to inspect checked-out source file {}: {error}",
                    path.display()
                ))
            })?;
            if !metadata.is_file() || source_entry_is_link_or_reparse(&metadata) {
                return Err(ReleaseError::environment(format!(
                    "checked-out source entry is not a real regular file: {}",
                    path.display()
                )));
            }
            arguments.push(path.as_os_str().to_owned());
            argument_units = next_units;
            end += 1;
        }

        let batch_len = end - start;
        let stdout_limit = batch_len
            .checked_mul(object_id_width.saturating_add(2))
            .ok_or_else(|| ReleaseError::environment("Git hash output bound overflowed"))?;
        let hashes = git_output_os(
            repository,
            arguments,
            "exact checked-out blob byte verification",
            stdout_limit,
        )?;
        require_expected_hash_lines(&entries[start..end], &hashes)?;
        start = end;
    }
    Ok(())
}

fn require_expected_hash_lines(
    entries: &[GitIndexEntry],
    output: &[u8],
) -> Result<(), ReleaseError> {
    let mut lines = output.split(|byte| *byte == b'\n');
    for entry in entries {
        let raw = lines.next().ok_or_else(|| {
            ReleaseError::environment("Git hash-object omitted a checked-out source hash")
        })?;
        let actual = raw.strip_suffix(b"\r").unwrap_or(raw);
        if actual != entry.object_id.as_bytes() {
            return Err(ReleaseError::environment(format!(
                "checked-out bytes for {} do not match the exact commit blob; Git attributes or a concurrent mutation changed the worktree representation",
                entry.path.as_path().display()
            )));
        }
    }
    if lines.next() != Some(&[][..]) || lines.next().is_some() {
        return Err(ReleaseError::environment(
            "Git hash-object emitted an unexpected number of source hashes",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn command_argument_units(value: &OsStr) -> usize {
    use std::os::unix::ffi::OsStrExt as _;

    value.as_bytes().len()
}

#[cfg(windows)]
fn command_argument_units(value: &OsStr) -> usize {
    use std::os::windows::ffi::OsStrExt as _;

    value.encode_wide().count()
}

#[cfg(not(any(unix, windows)))]
fn command_argument_units(value: &OsStr) -> usize {
    value.to_string_lossy().len()
}

fn require_expected_git_worktree(repository: &Path) -> Result<(), ReleaseError> {
    let bytes = git_output(
        repository,
        &["rev-parse", "--path-format=absolute", "--show-toplevel"],
        "worktree boundary read",
        64 * 1024,
    )?;
    let reported = git_path_from_output(&bytes)?;
    let expected = fs::canonicalize(repository).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to resolve expected release worktree {}: {error}",
            repository.display()
        ))
    })?;
    let actual = fs::canonicalize(&reported).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to resolve Git-reported worktree {}: {error}",
            reported.display()
        ))
    })?;
    if actual == expected {
        Ok(())
    } else {
        Err(ReleaseError::environment(format!(
            "Git worktree boundary {} does not match the release source repository {}",
            actual.display(),
            expected.display()
        )))
    }
}

fn git_path_from_output(bytes: &[u8]) -> Result<PathBuf, ReleaseError> {
    let end = bytes
        .iter()
        .rposition(|byte| !matches!(byte, b'\r' | b'\n'))
        .map_or(0, |index| index + 1);
    let path = &bytes[..end];
    if path.is_empty() || path.contains(&0) || path.contains(&b'\n') || path.contains(&b'\r') {
        return Err(ReleaseError::environment(
            "Git worktree output was empty or contained multiple paths",
        ));
    }
    git_path_from_native_bytes(path)
}

#[cfg(unix)]
fn git_path_from_native_bytes(bytes: &[u8]) -> Result<PathBuf, ReleaseError> {
    use std::os::unix::ffi::OsStringExt as _;

    Ok(PathBuf::from(OsString::from_vec(bytes.to_vec())))
}

#[cfg(not(unix))]
fn git_path_from_native_bytes(bytes: &[u8]) -> Result<PathBuf, ReleaseError> {
    let path = std::str::from_utf8(bytes)
        .map_err(|_| ReleaseError::environment("Git worktree output was not UTF-8"))?;
    Ok(PathBuf::from(path))
}

fn require_clean_status(status: &[u8]) -> Result<(), ReleaseError> {
    if status.is_empty() {
        Ok(())
    } else {
        Err(ReleaseError::environment(
            "release assembly requires a clean Git checkout with no tracked, untracked, or submodule changes",
        ))
    }
}

fn cargo_build(
    repository: &Path,
    target: &ReleaseTarget,
    target_directory: &Path,
    build_input_observation: Option<&BuildInputObservationOutput>,
    source_commit: &str,
) -> Result<BTreeSet<String>, ReleaseError> {
    require_no_external_cargo_configuration(repository)?;
    let arguments = local_release_build_arguments(target, target_directory);
    let label = format!("Cargo release build for {}", target.triple);
    let environment = prepared_release_cargo_environment(
        repository,
        CargoNetworkMode::Offline,
        CargoCompilationTarget::Target(target.triple),
        &label,
    )?;
    let invocation = PreparedCargoInvocation {
        program: cargo_program(),
        arguments,
        working_directory: repository.to_path_buf(),
        environment,
    };
    if let Some(output) = build_input_observation {
        write_build_input_observation(output, source_commit, target, &invocation)?;
    }
    let PreparedCargoInvocation {
        program,
        arguments,
        working_directory,
        environment,
    } = invocation;
    let observation = run_bounded_process(
        &working_directory,
        program,
        arguments,
        environment,
        CARGO_BUILD_TIMEOUT,
        MAX_BUILD_STREAM_BYTES,
        MAX_BUILD_STREAM_BYTES,
        Mutability::Unknown,
        NetworkIntent::OfflineRequested,
        &label,
    );
    let later_configuration_boundary = require_no_external_cargo_configuration(repository);
    let observation = observation?;
    later_configuration_boundary?;
    let stdout = require_process_success(observation, &label)?;
    parse_cargo_build_artifacts(&stdout, target.triple)
}

fn write_build_input_observation(
    output: &BuildInputObservationOutput,
    source_commit: &str,
    target: &ReleaseTarget,
    invocation: &PreparedCargoInvocation,
) -> Result<(), ReleaseError> {
    let document = build_input_observation(source_commit, target, invocation)?;
    let bytes = to_pretty_json(&document, "release-build input observation")?;
    if bytes.len() > MAX_BUILD_INPUT_OBSERVATION_BYTES {
        return Err(ReleaseError::environment(format!(
            "release-build input observation exceeds the {MAX_BUILD_INPUT_OBSERVATION_BYTES}-byte limit"
        )));
    }
    validate_visible_root(&output.writer, "build input observation output")?;
    output
        .writer
        .write_atomic_private_new(&output.file_name, &bytes)
        .map_err(|error| {
            ReleaseError::environment(format!(
                "failed to create the private build input observation: {error}"
            ))
        })?;
    let readback = output
        .writer
        .read_bounded(&output.file_name, MAX_BUILD_INPUT_OBSERVATION_BYTES)
        .map_err(|error| {
            ReleaseError::environment(format!(
                "failed to read back the private build input observation: {error}"
            ))
        })?;
    if readback != bytes {
        return Err(ReleaseError::environment(
            "private build input observation changed during exact readback",
        ));
    }
    validate_visible_root(&output.writer, "build input observation output")
}

fn build_input_observation(
    source_commit: &str,
    target: &ReleaseTarget,
    invocation: &PreparedCargoInvocation,
) -> Result<ReleaseBuildInputObservationData, ReleaseError> {
    let windows_msvc_environment = windows_msvc_build_inputs(
        &invocation.environment,
        CargoCompilationTarget::Target(target.triple),
    )
    .map_err(|error| {
        ReleaseError::environment(format!(
            "failed to project bounded MSVC build inputs for diagnostic observation: {error}"
        ))
    })?
    .map(|[path, lib, include]| {
        Ok(ReleaseBuildInputWindowsMsvcEnvironmentData::Observed {
            path: encode_windows_msvc_input(&path)?,
            lib: encode_windows_msvc_input(&lib)?,
            include: encode_windows_msvc_input(&include)?,
        })
    })
    .transpose()?
    .unwrap_or(ReleaseBuildInputWindowsMsvcEnvironmentData::NotApplicable);

    if invocation.arguments.is_empty() || invocation.arguments.len() > 32 {
        return Err(ReleaseError::internal(
            "prepared Cargo argument count is outside the observation contract",
        ));
    }
    let cargo_command = ReleaseBuildInputCargoCommandData {
        program: encode_release_build_native_string(&invocation.program)?,
        arguments: invocation
            .arguments
            .iter()
            .map(|argument| encode_release_build_native_string(argument))
            .collect::<Result<Vec<_>, _>>()?,
        working_directory: encode_release_build_native_string(
            invocation.working_directory.as_os_str(),
        )?,
    };

    Ok(ReleaseBuildInputObservationData {
        schema: SchemaKind::ReleaseBuildInputObservation.id(),
        purpose: ReleaseBuildInputObservationPurposeData::DiagnosticOnlyNotReleaseEvidence,
        phase:
            ReleaseBuildInputObservationPhaseData::AfterEnvironmentPreparationBeforeCargoReleaseBuild,
        source_commit: release_build_source_commit(source_commit)?,
        target: release_build_input_target(target)?,
        cargo_command,
        windows_msvc_environment,
    })
}

fn encode_release_build_native_string(
    value: &OsStr,
) -> Result<ReleaseBuildInputNativeStringData, ReleaseError> {
    encode_release_build_native_string_for_host(value)
}

#[cfg(unix)]
fn encode_release_build_native_string_for_host(
    value: &OsStr,
) -> Result<ReleaseBuildInputNativeStringData, ReleaseError> {
    use std::os::unix::ffi::OsStrExt as _;

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use forge_schema::ReleaseBuildInputRawBytesBase64Data;

    let raw_base64 = ReleaseBuildInputRawBytesBase64Data::new(STANDARD.encode(value.as_bytes()))
        .map_err(|_| {
            ReleaseError::environment(
                "prepared Cargo invocation contains an empty, NUL, or oversized Unix-native value",
            )
        })?;
    Ok(ReleaseBuildInputNativeStringData::UnixBytes { raw_base64 })
}

#[cfg(windows)]
fn encode_release_build_native_string_for_host(
    value: &OsStr,
) -> Result<ReleaseBuildInputNativeStringData, ReleaseError> {
    use std::os::windows::ffi::OsStrExt as _;

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use forge_schema::ReleaseBuildInputRawBase64Data;

    let bytes = value
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    let raw_base64 = ReleaseBuildInputRawBase64Data::new(STANDARD.encode(bytes)).map_err(|_| {
        ReleaseError::environment(
            "prepared Cargo invocation contains an empty, NUL, or oversized Windows-native value",
        )
    })?;
    Ok(ReleaseBuildInputNativeStringData::WindowsWide { raw_base64 })
}

#[cfg(not(any(unix, windows)))]
fn encode_release_build_native_string_for_host(
    _value: &OsStr,
) -> Result<ReleaseBuildInputNativeStringData, ReleaseError> {
    Err(ReleaseError::environment(
        "prepared Cargo invocation uses a native value on an unsupported host",
    ))
}

fn release_build_source_commit(value: &str) -> Result<GitObjectIdV2Data, ReleaseError> {
    match value.len() {
        40 => GitSha1ObjectIdV2Data::new(value).map(|oid| GitObjectIdV2Data::Sha1 { oid }),
        64 => GitSha256ObjectIdV2Data::new(value).map(|oid| GitObjectIdV2Data::Sha256 { oid }),
        _ => Err(forge_schema::InvalidGitObjectIdV2Data),
    }
    .map_err(|_| ReleaseError::internal("release source commit lost its validated object identity"))
}

fn release_build_input_target(
    target: &ReleaseTarget,
) -> Result<ReleaseBuildInputTargetData, ReleaseError> {
    match target.triple {
        "x86_64-unknown-linux-musl" => Ok(ReleaseBuildInputTargetData::X8664UnknownLinuxMusl),
        "aarch64-unknown-linux-musl" => Ok(ReleaseBuildInputTargetData::Aarch64UnknownLinuxMusl),
        "x86_64-apple-darwin" => Ok(ReleaseBuildInputTargetData::X8664AppleDarwin),
        "aarch64-apple-darwin" => Ok(ReleaseBuildInputTargetData::Aarch64AppleDarwin),
        "x86_64-pc-windows-msvc" => Ok(ReleaseBuildInputTargetData::X8664PcWindowsMsvc),
        _ => Err(ReleaseError::internal(
            "accepted release target has no input-observation wire identity",
        )),
    }
}

#[cfg(windows)]
fn encode_windows_msvc_input(value: &OsStr) -> Result<ReleaseBuildInputValueData, ReleaseError> {
    use std::os::windows::ffi::OsStrExt as _;

    encode_windows_utf16_input(value.encode_wide())
}

#[cfg(not(windows))]
fn encode_windows_msvc_input(_value: &OsStr) -> Result<ReleaseBuildInputValueData, ReleaseError> {
    Err(ReleaseError::internal(
        "non-Windows build unexpectedly produced MSVC input values",
    ))
}

#[cfg(any(windows, test))]
fn encode_windows_utf16_input(
    units: impl IntoIterator<Item = u16>,
) -> Result<ReleaseBuildInputValueData, ReleaseError> {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use forge_schema::{ReleaseBuildInputRawBase64Data, ReleaseBuildInputValueEncodingData};

    let units = units.into_iter().collect::<Vec<_>>();
    if units.is_empty() || units.len() > 32_766 || units.contains(&0) {
        return Err(ReleaseError::environment(
            "prepared MSVC build input is empty, contains NUL, or exceeds the Windows value limit",
        ));
    }
    let bytes = units
        .into_iter()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    let raw_base64 = ReleaseBuildInputRawBase64Data::new(STANDARD.encode(bytes)).map_err(|_| {
        ReleaseError::internal("failed to encode a validated MSVC build input losslessly")
    })?;
    Ok(ReleaseBuildInputValueData {
        encoding: ReleaseBuildInputValueEncodingData::WindowsUtf16leBase64,
        raw_base64,
    })
}

fn parse_cargo_build_artifacts(
    stdout: &[u8],
    target_label: &str,
) -> Result<BTreeSet<String>, ReleaseError> {
    let text = std::str::from_utf8(stdout).map_err(|error| {
        ReleaseError::environment(format!(
            "Cargo release build messages for {target_label} are not UTF-8: {error}"
        ))
    })?;
    if text.is_empty() || text.contains('\r') || !text.ends_with('\n') || text.ends_with("\n\n") {
        return Err(ReleaseError::environment(format!(
            "Cargo release build messages for {target_label} are not non-empty JSON lines with one LF terminator"
        )));
    }

    let mut package_ids = BTreeSet::new();
    let mut build_finished = false;
    for (index, line) in text.lines().enumerate() {
        if index >= MAX_CARGO_BUILD_MESSAGES {
            return Err(ReleaseError::environment(format!(
                "Cargo release build for {target_label} exceeds the {MAX_CARGO_BUILD_MESSAGES}-message bound"
            )));
        }
        if build_finished {
            return Err(ReleaseError::environment(format!(
                "Cargo release build for {target_label} emitted a message after build-finished"
            )));
        }
        let message: CargoBuildMessage = serde_json::from_str(line).map_err(|error| {
            ReleaseError::environment(format!(
                "Cargo release build for {target_label} emitted invalid JSON at message {}: {error}",
                index + 1
            ))
        })?;
        match message.reason.as_str() {
            "compiler-artifact" => {
                let package_id = message.package_id.ok_or_else(|| {
                    ReleaseError::environment(format!(
                        "Cargo compiler-artifact for {target_label} omitted package_id"
                    ))
                })?;
                if package_id.is_empty()
                    || package_id.contains('\0')
                    || package_id.contains(['\r', '\n'])
                {
                    return Err(ReleaseError::environment(format!(
                        "Cargo compiler-artifact for {target_label} has an invalid package_id"
                    )));
                }
                package_ids.insert(package_id);
            }
            "compiler-message" | "build-script-executed" => {}
            "build-finished" => {
                if message.success != Some(true) {
                    return Err(ReleaseError::environment(format!(
                        "Cargo release build message for {target_label} did not report success"
                    )));
                }
                build_finished = true;
            }
            reason => {
                return Err(ReleaseError::environment(format!(
                    "Cargo release build for {target_label} emitted unsupported message reason `{reason}`"
                )));
            }
        }
    }
    if !build_finished || package_ids.is_empty() {
        return Err(ReleaseError::environment(format!(
            "Cargo release build for {target_label} omitted successful completion or compiler artifacts"
        )));
    }
    Ok(package_ids)
}

fn require_native_build_graph_parity(
    scoped_package_ids: &BTreeSet<String>,
    built_package_ids: &BTreeSet<String>,
    target_label: &str,
) -> Result<(), ReleaseError> {
    if scoped_package_ids == built_package_ids {
        return Ok(());
    }
    let missing: Vec<_> = scoped_package_ids
        .difference(built_package_ids)
        .take(8)
        .cloned()
        .collect();
    let unexpected: Vec<_> = built_package_ids
        .difference(scoped_package_ids)
        .take(8)
        .cloned()
        .collect();
    Err(ReleaseError::environment(format!(
        "native Cargo release build for {target_label} disagrees with the scoped Cargo tree graph: graph={} artifacts={}, missing artifact package IDs (up to 8)=[{}], unexpected artifact package IDs (up to 8)=[{}]",
        scoped_package_ids.len(),
        built_package_ids.len(),
        missing.join(", "),
        unexpected.join(", ")
    )))
}

fn read_built_binary(
    build_output: &RepositoryWriter,
    target: &ReleaseTarget,
) -> Result<Vec<u8>, ReleaseError> {
    validate_visible_root(build_output, "temporary Cargo target")?;
    let relative = Path::new(target.triple)
        .join("release")
        .join(target.executable_name);
    let bytes = build_output
        .read_optional_bounded(&relative, MAX_BINARY_BYTES as usize)
        .map_err(|error| {
            ReleaseError::environment(format!(
                "failed to read the built release binary through the pinned temporary target handle for {}: {error}",
                target.triple
            ))
        })?
        .ok_or_else(|| {
            ReleaseError::environment(format!(
                "Cargo reported success but the pinned temporary target contains no release binary for {}",
                target.triple
            ))
        })?;
    validate_visible_root(build_output, "temporary Cargo target")?;
    Ok(bytes)
}

fn cargo_metadata(repository: &Path, target: &ReleaseTarget) -> Result<Vec<u8>, ReleaseError> {
    require_no_external_cargo_configuration(repository)?;
    let label = format!("Cargo metadata for {}", target.triple);
    let environment = prepared_release_cargo_environment(
        repository,
        CargoNetworkMode::Offline,
        CargoCompilationTarget::Target(target.triple),
        &label,
    )?;
    let observation = run_bounded_process(
        repository,
        cargo_program(),
        [
            "metadata",
            "--locked",
            "--offline",
            "--format-version",
            "1",
            "--filter-platform",
            target.triple,
        ]
        .into_iter()
        .map(OsString::from)
        .collect(),
        environment,
        CARGO_METADATA_TIMEOUT,
        MAX_METADATA_BYTES,
        MAX_DIAGNOSTIC_BYTES,
        Mutability::Unknown,
        NetworkIntent::OfflineRequested,
        &label,
    );
    let later_configuration_boundary = require_no_external_cargo_configuration(repository);
    let observation = observation?;
    later_configuration_boundary?;
    require_process_success(observation, &label)
}

fn cargo_tree(repository: &Path, target: &ReleaseTarget) -> Result<Vec<u8>, ReleaseError> {
    require_no_external_cargo_configuration(repository)?;
    let label = format!("scoped Cargo tree graph for {}", target.triple);
    let environment = prepared_release_cargo_environment(
        repository,
        CargoNetworkMode::Offline,
        CargoCompilationTarget::Target(target.triple),
        &label,
    )?;
    let observation = run_bounded_process(
        repository,
        cargo_program(),
        [
            "tree",
            "--locked",
            "--offline",
            "-p",
            "forge-cli",
            "--target",
            target.triple,
            "-e",
            "normal,build",
            "--prefix",
            "depth",
            "--format",
            "@@{p}@@",
            "--no-dedupe",
        ]
        .into_iter()
        .map(OsString::from)
        .collect(),
        environment,
        CARGO_METADATA_TIMEOUT,
        MAX_CARGO_TREE_BYTES,
        MAX_DIAGNOSTIC_BYTES,
        Mutability::Unknown,
        NetworkIntent::OfflineRequested,
        &label,
    );
    let later_configuration_boundary = require_no_external_cargo_configuration(repository);
    let observation = observation?;
    later_configuration_boundary?;
    require_process_success(observation, &label)
}

fn prepared_release_cargo_environment(
    repository: &Path,
    network: CargoNetworkMode,
    compilation_target: CargoCompilationTarget<'_>,
    label: &str,
) -> Result<EnvPolicy, ReleaseError> {
    let runner = SynchronousProcessRunner::new(repository).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to initialize the MSVC environment probe before {label}: {error}"
        ))
    })?;
    prepared_cargo_environment(&runner, network, compilation_target).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to prepare the Cargo environment before {label}: {error}"
        ))
    })
}

fn require_no_external_cargo_configuration(repository: &Path) -> Result<(), ReleaseError> {
    let repository = fs::canonicalize(repository).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to resolve Cargo source boundary {}: {error}",
            repository.display()
        ))
    })?;
    let mut configuration_roots = BTreeSet::new();
    for ancestor in repository.parent().into_iter().flat_map(Path::ancestors) {
        configuration_roots.insert(ancestor.join(".cargo"));
    }
    if let Some(cargo_home) = env::var_os("CARGO_HOME") {
        let cargo_home = PathBuf::from(cargo_home);
        if !cargo_home.is_absolute() {
            return Err(ReleaseError::environment(format!(
                "release assembly requires an absolute CARGO_HOME, got {}",
                cargo_home.display()
            )));
        }
        configuration_roots.insert(cargo_home);
    } else {
        for home_key in ["HOME", "USERPROFILE"] {
            if let Some(home) = env::var_os(home_key) {
                let home = PathBuf::from(home);
                if !home.is_absolute() {
                    return Err(ReleaseError::environment(format!(
                        "release assembly requires an absolute {home_key}, got {}",
                        home.display()
                    )));
                }
                configuration_roots.insert(home.join(".cargo"));
            }
        }
    }
    for root in configuration_roots {
        for name in ["config", "config.toml"] {
            let path = root.join(name);
            match fs::symlink_metadata(&path) {
                Ok(_) => {
                    return Err(ReleaseError::environment(format!(
                        "release assembly rejects external Cargo configuration discovered at {}; only configuration inside the exact isolated source tree is source-bound",
                        path.display()
                    )));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(ReleaseError::environment(format!(
                        "failed to inspect external Cargo configuration path {}: {error}",
                        path.display()
                    )));
                }
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_bounded_process(
    repository: &Path,
    program: OsString,
    args: Vec<OsString>,
    env: EnvPolicy,
    timeout: Duration,
    stdout_limit: usize,
    stderr_limit: usize,
    mutability: Mutability,
    network: NetworkIntent,
    label: &str,
) -> Result<ProcessObservation, ReleaseError> {
    let runner = SynchronousProcessRunner::new(repository).map_err(|error| {
        ReleaseError::environment(format!("failed to prepare {label}: {error}"))
    })?;
    runner
        .run(&ExecSpec {
            program,
            args,
            cwd: RepoRelativePath::root(),
            env,
            timeout,
            stdin: StdinPolicy::Closed,
            stdout: OutputPolicy::CaptureBounded {
                max_bytes: stdout_limit,
            },
            stderr: OutputPolicy::CaptureBounded {
                max_bytes: stderr_limit,
            },
            mutability,
            network,
            concurrency_key: None,
        })
        .map_err(|error| ReleaseError::environment(format!("failed to run {label}: {error}")))
}

fn require_process_success(
    observation: ProcessObservation,
    label: &str,
) -> Result<Vec<u8>, ReleaseError> {
    if observation.timed_out {
        return Err(ReleaseError::environment(format!("{label} timed out")));
    }
    if observation.interrupted {
        return Err(ReleaseError::environment(format!(
            "{label} was interrupted"
        )));
    }
    if observation.stdout_truncated || observation.stderr_truncated {
        return Err(ReleaseError::environment(format!(
            "{label} exceeded its bounded output policy: stdout={} bytes, stderr={} bytes",
            observation.stdout_total_bytes, observation.stderr_total_bytes
        )));
    }
    if observation.exit_code != Some(0) || observation.signal.is_some() {
        return Err(ReleaseError::environment(format!(
            "{label} failed with exit={:?}, signal={:?}: {}",
            observation.exit_code,
            observation.signal,
            bounded_lossy(&observation.stderr)
        )));
    }
    Ok(observation.stdout)
}

fn bounded_lossy(bytes: &[u8]) -> String {
    let end = bytes.len().min(MAX_DIAGNOSTIC_BYTES);
    let suffix = if bytes.len() > end {
        "…<truncated>"
    } else {
        ""
    };
    format!("{}{suffix}", String::from_utf8_lossy(&bytes[..end]))
}

fn stage_built(
    output: &RepositoryWriter,
    target: &ReleaseTarget,
    binary: &[u8],
    snapshot: &RepositorySnapshot,
) -> Result<(), ReleaseError> {
    validate_stage_directory(output)?;
    validate_binary_format(target, binary)?;
    let sbom = render_sbom(
        target,
        snapshot.metadata(target)?,
        snapshot.tree(target)?,
        &snapshot.cargo_lock,
        &snapshot.source_commit,
        binary,
    )?;
    preflight_write_once_or_same(output, &binary_asset_name(target), binary)?;
    preflight_write_once_or_same(output, &sbom_asset_name(target), &sbom)?;
    write_once_or_same(output, &binary_asset_name(target), binary)?;
    write_once_or_same(output, &sbom_asset_name(target), &sbom)?;
    validate_visible_root(output, "release output")?;
    Ok(())
}

fn finalize(output: &RepositoryWriter, snapshot: &RepositorySnapshot) -> Result<(), ReleaseError> {
    validate_finalize_directory(output)?;
    validate_staged_assets(output, snapshot)?;
    let manifest = render_manifest(output, &snapshot.license_notices)?;
    let checksums = render_checksums(output, &snapshot.license_notices, &manifest)?;
    preflight_write_once_or_same(output, LICENSE_NOTICES_FILE, &snapshot.license_notices)?;
    preflight_write_once_or_same(output, MANIFEST_FILE, &manifest)?;
    preflight_write_once_or_same(output, CHECKSUMS_FILE, &checksums)?;
    write_once_or_same(output, LICENSE_NOTICES_FILE, &snapshot.license_notices)?;
    write_once_or_same(output, MANIFEST_FILE, &manifest)?;
    write_once_or_same(output, CHECKSUMS_FILE, &checksums)?;
    validate_complete_assets(output, snapshot)?;
    validate_visible_root(output, "release output")?;
    Ok(())
}

fn check(output: &RepositoryWriter, snapshot: &RepositorySnapshot) -> Result<(), ReleaseError> {
    validate_complete_assets(output, snapshot)?;
    validate_visible_root(output, "release output")
}

fn validate_complete_assets(
    output: &RepositoryWriter,
    snapshot: &RepositorySnapshot,
) -> Result<(), ReleaseError> {
    validate_exact_asset_set(output)?;
    validate_staged_assets(output, snapshot)?;
    require_exact_bytes(
        output,
        LICENSE_NOTICES_FILE,
        &snapshot.license_notices,
        "third-party license notices",
    )?;

    let manifest = render_manifest(output, &snapshot.license_notices)?;
    require_exact_bytes(output, MANIFEST_FILE, &manifest, "release manifest")?;
    require_exact_bytes(
        output,
        CHECKSUMS_FILE,
        &render_checksums(output, &snapshot.license_notices, &manifest)?,
        "release checksums",
    )?;
    validate_exact_asset_set(output)?;
    Ok(())
}

fn validate_staged_assets(
    output: &RepositoryWriter,
    snapshot: &RepositorySnapshot,
) -> Result<(), ReleaseError> {
    for target in &RELEASE_TARGETS {
        let binary_name = binary_asset_name(target);
        let binary = read_output_required(
            output,
            &binary_name,
            MAX_BINARY_BYTES,
            "staged release binary",
        )?;
        validate_binary_format(target, &binary)?;
        let expected_sbom = render_sbom(
            target,
            snapshot.metadata(target)?,
            snapshot.tree(target)?,
            &snapshot.cargo_lock,
            &snapshot.source_commit,
            &binary,
        )?;
        require_exact_bytes(
            output,
            &sbom_asset_name(target),
            &expected_sbom,
            "CycloneDX SBOM",
        )?;
    }
    Ok(())
}

fn absolute_clean_path(path: &Path) -> Result<PathBuf, ReleaseError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .map_err(|error| {
                ReleaseError::environment(format!("failed to read current directory: {error}"))
            })?
            .join(path)
    };
    for component in absolute.components() {
        if matches!(component, PathComponent::ParentDir) {
            return Err(ReleaseError::environment(format!(
                "release path must not contain `..`: {}",
                path.display()
            )));
        }
    }

    Ok(absolute)
}

#[cfg(test)]
fn open_output_directory(repository: &Path, path: &Path) -> Result<RepositoryWriter, ReleaseError> {
    open_labeled_output_directory(repository, path, "release output")
}

fn open_labeled_output_directory(
    repository: &Path,
    path: &Path,
    label: &str,
) -> Result<RepositoryWriter, ReleaseError> {
    let absolute = absolute_clean_path(path)?;
    let output = RepositoryWriter::new(&absolute).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to pin the existing {label} directory {}: {error}",
            absolute.display()
        ))
    })?;
    let repository = fs::canonicalize(repository).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to resolve the source repository boundary {}: {error}",
            repository.display()
        ))
    })?;
    if output.root() == repository || output.root().starts_with(&repository) {
        return Err(ReleaseError::environment(format!(
            "{label} must be outside the source repository: {}",
            output.root().display()
        )));
    }
    validate_visible_root(&output, label)?;
    Ok(output)
}

fn open_command_output_directory(
    repository: &Path,
    path: &Path,
) -> Result<RepositoryWriter, ReleaseError> {
    open_labeled_command_output_directory(repository, path, "release output")
}

fn open_labeled_command_output_directory(
    repository: &Path,
    path: &Path,
    label: &str,
) -> Result<RepositoryWriter, ReleaseError> {
    let output = open_labeled_output_directory(repository, path, label)?;
    for (private_directory, private_label) in git_private_directories(repository)? {
        if output.root() == private_directory || output.root().starts_with(&private_directory) {
            return Err(ReleaseError::environment(format!(
                "{label} must be outside the {private_label}: {}",
                output.root().display()
            )));
        }
    }
    validate_visible_root(&output, label)?;
    Ok(output)
}

fn open_build_input_observation_output(
    repository: &Path,
    release_output: &RepositoryWriter,
    target: &ReleaseTarget,
    path: &Path,
) -> Result<BuildInputObservationOutput, ReleaseError> {
    let writer =
        open_labeled_command_output_directory(repository, path, "build input observation output")?;
    require_disjoint_output_roots(release_output.root(), writer.root())?;
    require_observation_does_not_contain_source(repository, writer.root())?;
    let file_name = format!("{BUILD_INPUT_OBSERVATION_PREFIX}{}.json", target.triple);
    match writer.read_optional_bounded(&file_name, MAX_BUILD_INPUT_OBSERVATION_BYTES) {
        Ok(None) => {}
        Ok(Some(_)) => {
            return Err(ReleaseError::environment(format!(
                "build input observation already exists; use a fresh destination for `{file_name}`"
            )));
        }
        Err(error) => {
            return Err(ReleaseError::environment(format!(
                "failed to inspect the build input observation destination: {error}"
            )));
        }
    }
    validate_visible_root(&writer, "build input observation output")?;
    Ok(BuildInputObservationOutput { writer, file_name })
}

fn require_observation_does_not_contain_source(
    repository: &Path,
    observation_output: &Path,
) -> Result<(), ReleaseError> {
    let repository = fs::canonicalize(repository).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to resolve the source repository boundary {}: {error}",
            repository.display()
        ))
    })?;
    if repository.starts_with(observation_output) {
        return Err(ReleaseError::environment(
            "build input observation output must not contain the source repository",
        ));
    }
    for (private_directory, _) in git_private_directories(&repository)? {
        if private_directory.starts_with(observation_output) {
            return Err(ReleaseError::environment(
                "build input observation output must not contain a Git private directory",
            ));
        }
    }
    Ok(())
}

fn require_disjoint_output_roots(
    release_output: &Path,
    observation_output: &Path,
) -> Result<(), ReleaseError> {
    if release_output == observation_output
        || release_output.starts_with(observation_output)
        || observation_output.starts_with(release_output)
    {
        return Err(ReleaseError::environment(
            "release output and build input observation output must be disjoint directories",
        ));
    }
    Ok(())
}

fn git_private_directories(
    repository: &Path,
) -> Result<Vec<(PathBuf, &'static str)>, ReleaseError> {
    [
        (
            ["rev-parse", "--path-format=absolute", "--git-dir"],
            "worktree-specific Git directory",
        ),
        (
            ["rev-parse", "--path-format=absolute", "--git-common-dir"],
            "shared Git directory",
        ),
    ]
    .into_iter()
    .map(|(arguments, label)| {
        let bytes = git_output(repository, &arguments, label, 64 * 1024)?;
        let reported = git_path_from_output(&bytes)?;
        let private_directory = fs::canonicalize(&reported).map_err(|error| {
            ReleaseError::environment(format!(
                "failed to resolve {label} {}: {error}",
                reported.display()
            ))
        })?;
        Ok((private_directory, label))
    })
    .collect()
}

fn validate_visible_root(writer: &RepositoryWriter, label: &str) -> Result<(), ReleaseError> {
    writer.validate_visible_root().map_err(|error| {
        ReleaseError::environment(format!(
            "visible {label} path no longer names the pinned directory: {error}"
        ))
    })
}

fn require_regular_file(path: &Path, label: &str) -> Result<PathBuf, ReleaseError> {
    let absolute = absolute_clean_path(path)?;
    let metadata = fs::symlink_metadata(&absolute).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to inspect {label} {}: {error}",
            absolute.display()
        ))
    })?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(ReleaseError::environment(format!(
            "{label} is not a real regular file: {}",
            absolute.display()
        )));
    }
    Ok(absolute)
}

fn read_bounded(path: &Path, limit: u64, label: &str) -> Result<Vec<u8>, ReleaseError> {
    let path = require_regular_file(path, label)?;
    let metadata = fs::metadata(&path).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to inspect {label} {}: {error}",
            path.display()
        ))
    })?;
    if metadata.len() > limit {
        return Err(ReleaseError::environment(format!(
            "{label} {} is {} bytes, above the {limit} byte limit",
            path.display(),
            metadata.len()
        )));
    }
    let file = File::open(&path).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to open {label} {}: {error}",
            path.display()
        ))
    })?;
    let capacity = usize::try_from(metadata.len()).map_err(|_| {
        ReleaseError::environment(format!("{label} length is not representable in memory"))
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| {
            ReleaseError::environment(format!(
                "failed to read {label} {}: {error}",
                path.display()
            ))
        })?;
    if bytes.len() as u64 > limit {
        return Err(ReleaseError::environment(format!(
            "{label} {} grew above the {limit} byte limit while being read",
            path.display()
        )));
    }
    if bytes.len() as u64 != metadata.len() {
        return Err(ReleaseError::environment(format!(
            "{label} changed while being read: {}",
            path.display()
        )));
    }
    Ok(bytes)
}

fn read_output_optional(
    output: &RepositoryWriter,
    name: &str,
    max_bytes: u64,
    label: &str,
) -> Result<Option<Vec<u8>>, ReleaseError> {
    let max_bytes = usize::try_from(max_bytes).map_err(|_| {
        ReleaseError::internal(format!(
            "{label} byte limit is not representable on this host"
        ))
    })?;
    validate_visible_root(output, "release output")?;
    let bytes = output
        .read_optional_bounded(name, max_bytes)
        .map_err(|error| {
            ReleaseError::environment(format!(
                "failed to read pinned release {label} `{name}`: {error}"
            ))
        })?;
    validate_visible_root(output, "release output")?;
    Ok(bytes)
}

fn read_output_required(
    output: &RepositoryWriter,
    name: &str,
    max_bytes: u64,
    label: &str,
) -> Result<Vec<u8>, ReleaseError> {
    read_output_optional(output, name, max_bytes, label)?
        .ok_or_else(|| ReleaseError::environment(format!("release {label} is missing: `{name}`")))
}

fn write_once_or_same(
    output: &RepositoryWriter,
    name: &str,
    bytes: &[u8],
) -> Result<(), ReleaseError> {
    write_once_or_same_with_precreate(output, name, bytes, || Ok(()))
}

fn write_once_or_same_with_precreate(
    output: &RepositoryWriter,
    name: &str,
    bytes: &[u8],
    before_create: impl FnOnce() -> Result<(), ReleaseError>,
) -> Result<(), ReleaseError> {
    if let Some(current) =
        read_output_optional(output, name, MAX_BINARY_BYTES, "asset destination")?
    {
        if current != bytes {
            return Err(ReleaseError::environment(format!(
                "release asset already exists with different bytes: `{name}`"
            )));
        }
        return require_exact_bytes(output, name, bytes, "existing release asset");
    }

    // Keeping this boundary explicit makes the read/create race reproducible in tests.
    before_create()?;
    match output.write_atomic_new(name, bytes) {
        Ok(()) => {}
        Err(error) if error.io_kind() == std::io::ErrorKind::AlreadyExists => {
            return require_exact_bytes(output, name, bytes, "concurrently created release asset");
        }
        Err(error) => {
            return Err(ReleaseError::environment(format!(
                "failed to atomically create pinned release asset `{name}`: {error}"
            )));
        }
    }
    require_exact_bytes(output, name, bytes, "newly created release asset")
}

fn preflight_write_once_or_same(
    output: &RepositoryWriter,
    name: &str,
    bytes: &[u8],
) -> Result<(), ReleaseError> {
    if let Some(current) = read_output_optional(
        output,
        name,
        MAX_BINARY_BYTES,
        "asset destination preflight",
    )? {
        if current != bytes {
            return Err(ReleaseError::environment(format!(
                "release asset already exists with different bytes: `{name}`"
            )));
        }
    }
    Ok(())
}

fn require_exact_bytes(
    output: &RepositoryWriter,
    name: &str,
    expected: &[u8],
    label: &str,
) -> Result<(), ReleaseError> {
    let actual = read_output_required(output, name, MAX_BINARY_BYTES, label)?;
    if actual == expected {
        Ok(())
    } else {
        Err(ReleaseError::environment(format!(
            "{label} differs from deterministic release content: `{name}`"
        )))
    }
}

fn known_stage_names() -> BTreeSet<String> {
    RELEASE_TARGETS
        .iter()
        .flat_map(|target| [binary_asset_name(target), sbom_asset_name(target)])
        .collect()
}

fn manifest_artifact_names() -> BTreeSet<String> {
    let mut names = known_stage_names();
    names.insert(LICENSE_NOTICES_FILE.to_owned());
    names
}

fn finalized_asset_names() -> BTreeSet<String> {
    let mut names = manifest_artifact_names();
    names.insert(MANIFEST_FILE.to_owned());
    names.insert(CHECKSUMS_FILE.to_owned());
    names
}

fn validate_stage_directory(output: &RepositoryWriter) -> Result<(), ReleaseError> {
    require_directory_subset(output, &known_stage_names(), "staged release")
}

fn validate_finalize_directory(output: &RepositoryWriter) -> Result<(), ReleaseError> {
    require_directory_subset(output, &finalized_asset_names(), "release finalization")?;
    let mut missing = Vec::new();
    for name in known_stage_names() {
        if read_output_optional(output, &name, MAX_BINARY_BYTES, "staged asset")?.is_none() {
            missing.push(name);
        }
    }
    if !missing.is_empty() {
        return Err(ReleaseError::environment(format!(
            "release output is missing required staged assets: {}",
            missing.join(", ")
        )));
    }
    Ok(())
}

fn validate_exact_asset_set(output: &RepositoryWriter) -> Result<(), ReleaseError> {
    let expected = finalized_asset_names();
    let actual = visible_output_asset_names(output, expected.len())?;
    if actual == expected {
        Ok(())
    } else {
        let missing = expected.difference(&actual).cloned().collect::<Vec<_>>();
        let unexpected = actual.difference(&expected).cloned().collect::<Vec<_>>();
        Err(ReleaseError::environment(format!(
            "release output does not contain the exact finalized asset set; missing=[{}], unexpected=[{}]",
            missing.join(", "),
            unexpected.join(", ")
        )))
    }
}

fn require_directory_subset(
    output: &RepositoryWriter,
    allowed: &BTreeSet<String>,
    label: &str,
) -> Result<(), ReleaseError> {
    let actual = visible_output_asset_names(output, allowed.len())?;
    let unexpected = actual.difference(allowed).cloned().collect::<Vec<_>>();
    if unexpected.is_empty() {
        Ok(())
    } else {
        Err(ReleaseError::environment(format!(
            "{label} output contains unexpected entries: [{}]",
            unexpected.join(", ")
        )))
    }
}

fn visible_output_asset_names(
    output: &RepositoryWriter,
    max_entries: usize,
) -> Result<BTreeSet<String>, ReleaseError> {
    validate_visible_root(output, "release output")?;
    let entries = fs::read_dir(output.root()).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to enumerate pinned release output {}: {error}",
            output.root().display()
        ))
    })?;
    let mut names = BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            ReleaseError::environment(format!(
                "failed to enumerate a release output entry: {error}"
            ))
        })?;
        if names.len() == max_entries {
            return Err(ReleaseError::environment(format!(
                "release output contains more than {max_entries} allowed entries"
            )));
        }
        let file_type = entry.file_type().map_err(|error| {
            ReleaseError::environment(format!(
                "failed to inspect release output entry {}: {error}",
                entry.path().display()
            ))
        })?;
        if !file_type.is_file() || file_type.is_symlink() {
            return Err(ReleaseError::environment(format!(
                "release output entry is not a real regular file: {}",
                entry.path().display()
            )));
        }
        let name = entry.file_name().into_string().map_err(|_| {
            ReleaseError::environment("release output contains a non-UTF-8 entry name")
        })?;
        if !names.insert(name.clone()) {
            return Err(ReleaseError::environment(format!(
                "release output enumerated duplicate entry `{name}`"
            )));
        }
    }
    validate_visible_root(output, "release output")?;
    Ok(names)
}

fn binary_asset_name(target: &ReleaseTarget) -> String {
    let suffix = if target.executable_name.ends_with(".exe") {
        ".exe"
    } else {
        ""
    };
    format!("forge-{RELEASE_VERSION}-{}{suffix}", target.triple)
}

fn sbom_asset_name(target: &ReleaseTarget) -> String {
    format!("{}.cdx.json", binary_asset_name(target))
}

fn validate_binary_format(target: &ReleaseTarget, bytes: &[u8]) -> Result<(), ReleaseError> {
    match target.format {
        BinaryFormat::ElfX86_64Static => validate_elf(bytes, 62, target.triple),
        BinaryFormat::ElfAarch64Static => validate_elf(bytes, 183, target.triple),
        BinaryFormat::MachOX86_64 => validate_macho(bytes, 0x0100_0007, target.triple),
        BinaryFormat::MachOAarch64 => validate_macho(bytes, 0x0100_000c, target.triple),
        BinaryFormat::PeX86_64 => validate_pe(bytes, target.triple),
    }
}

fn validate_elf(bytes: &[u8], expected_machine: u16, triple: &str) -> Result<(), ReleaseError> {
    if bytes.len() < 64
        || bytes.get(0..4) != Some(b"\x7fELF")
        || bytes[4] != 2
        || bytes[5] != 1
        || bytes[6] != 1
    {
        return Err(ReleaseError::environment(format!(
            "binary for {triple} is not a 64-bit little-endian ELF executable"
        )));
    }
    if read_u16(bytes, 18)? != expected_machine {
        return Err(ReleaseError::environment(format!(
            "binary architecture does not match release target {triple}"
        )));
    }
    if !matches!(read_u16(bytes, 16)?, 2 | 3) {
        return Err(ReleaseError::environment(format!(
            "ELF file type is not executable or position-independent executable for {triple}"
        )));
    }
    if read_u16(bytes, 52)? < 64 {
        return Err(ReleaseError::environment(format!(
            "ELF header size is invalid for {triple}"
        )));
    }
    let entry = read_u64(bytes, 24)?;
    if entry == 0 {
        return Err(ReleaseError::environment(format!(
            "ELF executable entry point is missing for {triple}"
        )));
    }
    let program_offset = usize::try_from(read_u64(bytes, 32)?).map_err(|_| {
        ReleaseError::environment(format!("ELF program header offset overflows for {triple}"))
    })?;
    let entry_size = usize::from(read_u16(bytes, 54)?);
    let entry_count = usize::from(read_u16(bytes, 56)?);
    if entry_count == 0 || entry_size < 56 {
        return Err(ReleaseError::environment(format!(
            "ELF executable program-header table is missing or invalid for {triple}"
        )));
    }
    let mut executable_entry_segment = false;
    for index in 0..entry_count {
        let offset = program_offset
            .checked_add(index.checked_mul(entry_size).ok_or_else(|| {
                ReleaseError::environment(format!("ELF program headers overflow for {triple}"))
            })?)
            .ok_or_else(|| {
                ReleaseError::environment(format!("ELF program headers overflow for {triple}"))
            })?;
        let end = offset.checked_add(entry_size).ok_or_else(|| {
            ReleaseError::environment(format!("ELF program headers overflow for {triple}"))
        })?;
        if end > bytes.len() {
            return Err(ReleaseError::environment(format!(
                "ELF program headers are truncated for {triple}"
            )));
        }
        let segment_type = read_u32(bytes, offset)?;
        if segment_type == 3 {
            return Err(ReleaseError::environment(format!(
                "Linux release binary for {triple} has a PT_INTERP loader and is not static-compatible"
            )));
        }
        let flags = read_u32(bytes, offset + 4)?;
        if segment_type == 1 {
            let file_offset = read_u64(bytes, offset + 8)?;
            let virtual_address = read_u64(bytes, offset + 16)?;
            let file_size = read_u64(bytes, offset + 32)?;
            let memory_size = read_u64(bytes, offset + 40)?;
            let alignment = read_u64(bytes, offset + 48)?;
            if file_size > memory_size
                || (alignment > 1
                    && (!alignment.is_power_of_two()
                        || file_offset % alignment != virtual_address % alignment))
            {
                return Err(ReleaseError::environment(format!(
                    "ELF load segment has invalid file, memory, or alignment bounds for {triple}"
                )));
            }
            let file_end = file_offset.checked_add(file_size).ok_or_else(|| {
                ReleaseError::environment(format!("ELF file segment overflows for {triple}"))
            })?;
            if file_end > bytes.len() as u64 {
                return Err(ReleaseError::environment(format!(
                    "ELF load segment exceeds the binary bytes for {triple}"
                )));
            }
            let segment_end = virtual_address.checked_add(memory_size).ok_or_else(|| {
                ReleaseError::environment(format!(
                    "ELF executable segment range overflows for {triple}"
                ))
            })?;
            if flags & 1 != 0 && memory_size > 0 && entry >= virtual_address && entry < segment_end
            {
                let entry_delta = entry - virtual_address;
                let entry_file_offset = file_offset.checked_add(entry_delta).ok_or_else(|| {
                    ReleaseError::environment(format!(
                        "ELF entry file offset overflows for {triple}"
                    ))
                })?;
                if entry_delta < file_size && entry_file_offset < bytes.len() as u64 {
                    executable_entry_segment = true;
                }
            }
        }
    }
    if executable_entry_segment {
        Ok(())
    } else {
        Err(ReleaseError::environment(format!(
            "ELF entry point is not covered by an executable PT_LOAD segment for {triple}"
        )))
    }
}

fn validate_macho(bytes: &[u8], expected_cpu: u32, triple: &str) -> Result<(), ReleaseError> {
    if bytes.len() < 32 || bytes.get(0..4) != Some(&[0xcf, 0xfa, 0xed, 0xfe]) {
        return Err(ReleaseError::environment(format!(
            "binary for {triple} is not a 64-bit little-endian Mach-O executable"
        )));
    }
    if read_u32(bytes, 4)? != expected_cpu {
        return Err(ReleaseError::environment(format!(
            "binary architecture does not match release target {triple}"
        )));
    }
    if read_u32(bytes, 12)? != 2 {
        return Err(ReleaseError::environment(format!(
            "Mach-O file type is not MH_EXECUTE for {triple}"
        )));
    }
    let command_count = usize::try_from(read_u32(bytes, 16)?).map_err(|_| {
        ReleaseError::environment(format!("Mach-O load-command count overflows for {triple}"))
    })?;
    let command_bytes = usize::try_from(read_u32(bytes, 20)?).map_err(|_| {
        ReleaseError::environment(format!("Mach-O load-command bytes overflow for {triple}"))
    })?;
    if command_count == 0 || command_bytes == 0 {
        return Err(ReleaseError::environment(format!(
            "Mach-O executable has no load commands for {triple}"
        )));
    }
    let commands_end = 32_usize.checked_add(command_bytes).ok_or_else(|| {
        ReleaseError::environment(format!("Mach-O load commands overflow for {triple}"))
    })?;
    if commands_end > bytes.len() {
        return Err(ReleaseError::environment(format!(
            "Mach-O load commands are truncated for {triple}"
        )));
    }
    let mut offset = 32_usize;
    let mut executable_file_ranges = Vec::new();
    let mut main_entry = None;
    for _ in 0..command_count {
        let command = read_u32(bytes, offset)?;
        let command_size = usize::try_from(read_u32(bytes, offset + 4)?).map_err(|_| {
            ReleaseError::environment(format!("Mach-O load command overflows for {triple}"))
        })?;
        if command_size < 8 || command_size % 8 != 0 {
            return Err(ReleaseError::environment(format!(
                "Mach-O load command is too short for {triple}"
            )));
        }
        let end = offset.checked_add(command_size).ok_or_else(|| {
            ReleaseError::environment(format!("Mach-O load commands overflow for {triple}"))
        })?;
        if end > commands_end {
            return Err(ReleaseError::environment(format!(
                "Mach-O load command exceeds the declared table for {triple}"
            )));
        }
        if command == 0x19 {
            if command_size < 72 {
                return Err(ReleaseError::environment(format!(
                    "Mach-O LC_SEGMENT_64 is too short for {triple}"
                )));
            }
            let section_count = usize::try_from(read_u32(bytes, offset + 64)?).map_err(|_| {
                ReleaseError::environment(format!("Mach-O section count overflows for {triple}"))
            })?;
            let minimum_size = 72_usize
                .checked_add(section_count.checked_mul(80).ok_or_else(|| {
                    ReleaseError::environment(format!(
                        "Mach-O section table overflows for {triple}"
                    ))
                })?)
                .ok_or_else(|| {
                    ReleaseError::environment(format!(
                        "Mach-O section table overflows for {triple}"
                    ))
                })?;
            if command_size < minimum_size {
                return Err(ReleaseError::environment(format!(
                    "Mach-O LC_SEGMENT_64 section table is truncated for {triple}"
                )));
            }
            let virtual_size = read_u64(bytes, offset + 32)?;
            let file_offset = read_u64(bytes, offset + 40)?;
            let file_size = read_u64(bytes, offset + 48)?;
            let maximum_protection = read_u32(bytes, offset + 56)?;
            let initial_protection = read_u32(bytes, offset + 60)?;
            if initial_protection & 4 != 0 {
                let file_end = file_offset.checked_add(file_size).ok_or_else(|| {
                    ReleaseError::environment(format!(
                        "Mach-O executable segment overflows for {triple}"
                    ))
                })?;
                if maximum_protection & 4 == 0
                    || virtual_size == 0
                    || file_size == 0
                    || file_size > virtual_size
                    || file_end > bytes.len() as u64
                {
                    return Err(ReleaseError::environment(format!(
                        "Mach-O executable segment has invalid file or memory bounds for {triple}"
                    )));
                }
                executable_file_ranges.push((file_offset, file_end));
            }
        } else if command == 0x8000_0028 {
            if command_size < 24 || main_entry.is_some() {
                return Err(ReleaseError::environment(format!(
                    "Mach-O LC_MAIN is duplicated or too short for {triple}"
                )));
            }
            main_entry = Some(read_u64(bytes, offset + 8)?);
        }
        offset = end;
    }
    let Some(main_entry) = main_entry else {
        return Err(ReleaseError::environment(format!(
            "Mach-O executable has no LC_MAIN entry point for {triple}"
        )));
    };
    let entry_is_file_backed = main_entry >= commands_end as u64
        && executable_file_ranges
            .iter()
            .any(|(start, end)| main_entry >= *start && main_entry < *end);
    if offset != commands_end || !entry_is_file_backed {
        return Err(ReleaseError::environment(format!(
            "Mach-O executable has an inconsistent table or LC_MAIN is not file-backed by an executable LC_SEGMENT_64 for {triple}"
        )));
    }
    Ok(())
}

fn validate_pe(bytes: &[u8], triple: &str) -> Result<(), ReleaseError> {
    if bytes.len() < 64 || bytes.get(0..2) != Some(b"MZ") {
        return Err(ReleaseError::environment(format!(
            "binary for {triple} is not a PE executable"
        )));
    }
    let header = usize::try_from(read_u32(bytes, 0x3c)?).map_err(|_| {
        ReleaseError::environment(format!("PE header offset overflows for {triple}"))
    })?;
    let coff_end = header.checked_add(24).ok_or_else(|| {
        ReleaseError::environment(format!("PE header offset overflows for {triple}"))
    })?;
    if coff_end > bytes.len() || bytes.get(header..header + 4) != Some(b"PE\0\0") {
        return Err(ReleaseError::environment(format!(
            "binary for {triple} has an invalid PE header"
        )));
    }
    if read_u16(bytes, header + 4)? != 0x8664 {
        return Err(ReleaseError::environment(format!(
            "binary architecture does not match release target {triple}"
        )));
    }
    let section_count = usize::from(read_u16(bytes, header + 6)?);
    let optional_size = usize::from(read_u16(bytes, header + 20)?);
    let characteristics = read_u16(bytes, header + 22)?;
    if characteristics & 0x0002 == 0 || characteristics & 0x2000 != 0 {
        return Err(ReleaseError::environment(format!(
            "PE image for {triple} is not an executable non-DLL image"
        )));
    }
    if section_count == 0 || optional_size < 0x70 {
        return Err(ReleaseError::environment(format!(
            "PE image for {triple} has no sections or an undersized PE32+ optional header"
        )));
    }
    let optional = header + 24;
    let optional_end = optional.checked_add(optional_size).ok_or_else(|| {
        ReleaseError::environment(format!("PE optional header overflows for {triple}"))
    })?;
    if optional_end > bytes.len() || read_u16(bytes, optional)? != 0x020b {
        return Err(ReleaseError::environment(format!(
            "PE image for {triple} has an invalid PE32+ optional header"
        )));
    }
    let entry = read_u32(bytes, optional + 16)?;
    if entry == 0 {
        return Err(ReleaseError::environment(format!(
            "PE executable entry point is missing for {triple}"
        )));
    }
    let section_bytes = section_count.checked_mul(40).ok_or_else(|| {
        ReleaseError::environment(format!("PE section table overflows for {triple}"))
    })?;
    let sections_end = optional_end.checked_add(section_bytes).ok_or_else(|| {
        ReleaseError::environment(format!("PE section table overflows for {triple}"))
    })?;
    if sections_end > bytes.len() {
        return Err(ReleaseError::environment(format!(
            "PE section table is truncated for {triple}"
        )));
    }
    let size_of_image = read_u32(bytes, optional + 56)?;
    let size_of_headers = usize::try_from(read_u32(bytes, optional + 60)?)
        .map_err(|_| ReleaseError::environment(format!("PE header size overflows for {triple}")))?;
    if size_of_image == 0
        || entry >= size_of_image
        || size_of_headers < sections_end
        || size_of_headers > bytes.len()
    {
        return Err(ReleaseError::environment(format!(
            "PE image or header bounds are invalid for {triple}"
        )));
    }
    let mut executable_entry_section = false;
    for index in 0..section_count {
        let offset = optional_end + index * 40;
        let virtual_size = read_u32(bytes, offset + 8)?;
        let virtual_address = read_u32(bytes, offset + 12)?;
        let raw_size = read_u32(bytes, offset + 16)?;
        let raw_offset = read_u32(bytes, offset + 20)?;
        let section_characteristics = read_u32(bytes, offset + 36)?;
        let mapped_size = virtual_size.max(raw_size);
        let section_end = virtual_address.checked_add(mapped_size).ok_or_else(|| {
            ReleaseError::environment(format!("PE executable section overflows for {triple}"))
        })?;
        let raw_end = raw_offset.checked_add(raw_size).ok_or_else(|| {
            ReleaseError::environment(format!("PE raw section range overflows for {triple}"))
        })?;
        if raw_size > 0 && raw_end > bytes.len() as u32 {
            return Err(ReleaseError::environment(format!(
                "PE raw section exceeds the binary bytes for {triple}"
            )));
        }
        if section_characteristics & 0x2000_0000 != 0
            && mapped_size > 0
            && entry >= virtual_address
            && entry < section_end
        {
            let entry_delta = entry - virtual_address;
            let entry_file_offset = raw_offset.checked_add(entry_delta).ok_or_else(|| {
                ReleaseError::environment(format!("PE entry file offset overflows for {triple}"))
            })?;
            if entry_delta < raw_size
                && raw_offset >= size_of_headers as u32
                && entry_file_offset < bytes.len() as u32
            {
                executable_entry_section = true;
            }
        }
    }
    if executable_entry_section {
        Ok(())
    } else {
        Err(ReleaseError::environment(format!(
            "PE entry point is not covered by an executable section for {triple}"
        )))
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, ReleaseError> {
    let raw: [u8; 2] = bytes
        .get(offset..offset.saturating_add(2))
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| ReleaseError::environment("release binary header is truncated"))?;
    Ok(u16::from_le_bytes(raw))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ReleaseError> {
    let raw: [u8; 4] = bytes
        .get(offset..offset.saturating_add(4))
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| ReleaseError::environment("release binary header is truncated"))?;
    Ok(u32::from_le_bytes(raw))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, ReleaseError> {
    let raw: [u8; 8] = bytes
        .get(offset..offset.saturating_add(8))
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| ReleaseError::environment("release binary header is truncated"))?;
    Ok(u64::from_le_bytes(raw))
}

#[derive(Debug, Deserialize)]
struct CargoMetadata {
    packages: Vec<CargoPackage>,
    workspace_members: Vec<String>,
    #[serde(default)]
    workspace_root: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize)]
struct CargoPackage {
    id: String,
    name: String,
    version: String,
    license: Option<String>,
    source: Option<String>,
    #[serde(default)]
    manifest_path: Option<PathBuf>,
    #[serde(default)]
    targets: Vec<CargoTarget>,
}

#[derive(Clone, Debug, Deserialize)]
struct CargoTarget {
    #[serde(default)]
    src_path: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct CargoBuildMessage {
    reason: String,
    #[serde(default)]
    package_id: Option<String>,
    #[serde(default)]
    success: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDxBom {
    bom_format: &'static str,
    spec_version: &'static str,
    version: u8,
    metadata: BomMetadata,
    components: Vec<BomComponent>,
    dependencies: Vec<BomDependency>,
}

#[derive(Debug, Serialize)]
struct BomMetadata {
    component: BomComponent,
}

#[derive(Debug, Serialize)]
struct BomComponent {
    #[serde(rename = "type")]
    component_type: &'static str,
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    name: String,
    version: String,
    licenses: Vec<BomLicenseChoice>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    hashes: Vec<BomHash>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    properties: Vec<BomProperty>,
}

#[derive(Debug, Serialize)]
struct BomLicenseChoice {
    expression: String,
}

#[derive(Debug, Serialize)]
struct BomHash {
    alg: &'static str,
    content: String,
}

#[derive(Debug, Serialize)]
struct BomProperty {
    name: &'static str,
    value: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BomDependency {
    #[serde(rename = "ref")]
    reference: String,
    depends_on: Vec<String>,
}

fn package_license_expression(package: &CargoPackage) -> Result<String, ReleaseError> {
    let raw_expression = package.license.as_deref().ok_or_else(|| {
        ReleaseError::environment(format!(
            "release dependency {} {} has no Cargo package.license expression",
            package.name, package.version
        ))
    })?;
    let expression = match (
        package.name.as_str(),
        package.version.as_str(),
        raw_expression,
    ) {
        // These five published crates predate Cargo's SPDX `OR` spelling. Bind each compatibility
        // rewrite to the exact package version reviewed for the frozen five-target closure.
        ("ctrlc", "3.4.7", "MIT/Apache-2.0")
        | ("fs2", "0.4.3", "MIT/Apache-2.0")
        | ("winapi", "0.3.9", "MIT/Apache-2.0") => "MIT OR Apache-2.0",
        ("same-file", "1.0.6", "Unlicense/MIT") | ("walkdir", "2.5.0", "Unlicense/MIT") => {
            "Unlicense OR MIT"
        }
        // Keep the machine expression surface closed over the audited release closure. A new
        // expression therefore requires an explicit dependency-license review instead of silently
        // becoming release evidence merely because it is syntactically plausible.
        (
            _,
            _,
            expression @ ("(MIT OR Apache-2.0) AND Unicode-3.0"
            | "Apache-2.0"
            | "Apache-2.0 OR BSL-1.0"
            | "Apache-2.0 OR MIT"
            | "Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT"
            | "BSD-2-Clause"
            | "BSD-2-Clause OR Apache-2.0 OR MIT"
            | "CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception"
            | "CC0-1.0 OR MIT-0 OR Apache-2.0"
            | "MIT"
            | "MIT OR Apache-2.0"
            | "MIT-0"
            | "Unicode-3.0"
            | "Unlicense OR MIT"
            | "Zlib"),
        ) => expression,
        _ => {
            return Err(ReleaseError::environment(format!(
                "release dependency {} {} has an invalid, unrecognized, or unreviewed Cargo package.license expression",
                package.name, package.version
            )));
        }
    };
    Ok(expression.to_owned())
}

#[derive(Debug)]
struct ScopedCargoTreeGraph {
    root_id: String,
    package_ids: BTreeSet<String>,
    edges: BTreeMap<String, BTreeSet<String>>,
}

fn parse_scoped_cargo_tree_graph(
    metadata: &CargoMetadata,
    tree_bytes: &[u8],
    target_label: &str,
) -> Result<ScopedCargoTreeGraph, ReleaseError> {
    if tree_bytes.len() > MAX_CARGO_TREE_BYTES {
        return Err(ReleaseError::environment(format!(
            "scoped Cargo tree graph for {target_label} exceeds the {MAX_CARGO_TREE_BYTES}-byte bound"
        )));
    }
    let tree = std::str::from_utf8(tree_bytes).map_err(|error| {
        ReleaseError::environment(format!(
            "scoped Cargo tree graph for {target_label} is not UTF-8: {error}"
        ))
    })?;
    if tree.is_empty() || tree.contains('\r') || !tree.ends_with('\n') || tree.ends_with("\n\n") {
        return Err(ReleaseError::environment(format!(
            "scoped Cargo tree graph for {target_label} is not non-empty text with one LF terminator"
        )));
    }
    let mut identities: BTreeMap<(&str, &str), Vec<&CargoPackage>> = BTreeMap::new();
    for package in &metadata.packages {
        identities
            .entry((package.name.as_str(), package.version.as_str()))
            .or_default()
            .push(package);
    }
    let workspace_members: BTreeSet<_> = metadata
        .workspace_members
        .iter()
        .map(String::as_str)
        .collect();
    let mut stack: Vec<String> = Vec::new();
    let mut selected = BTreeSet::new();
    let mut edges: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut root_id = None;
    let mut line_count = 0_usize;
    for line in tree.lines() {
        line_count = line_count
            .checked_add(1)
            .ok_or_else(|| ReleaseError::environment("scoped Cargo tree line count overflowed"))?;
        if line_count > MAX_CARGO_TREE_LINES {
            return Err(ReleaseError::environment(format!(
                "scoped Cargo tree graph for {target_label} exceeds the {MAX_CARGO_TREE_LINES}-line bound"
            )));
        }
        let marker = line.find("@@").ok_or_else(|| {
            ReleaseError::environment(format!(
                "scoped Cargo tree graph for {target_label} has a line without the package sentinel"
            ))
        })?;
        let (depth, display) = line.split_at(marker);
        if depth.is_empty()
            || (depth.len() > 1 && depth.starts_with('0'))
            || !depth.as_bytes().iter().all(u8::is_ascii_digit)
        {
            return Err(ReleaseError::environment(format!(
                "scoped Cargo tree graph for {target_label} has an invalid depth prefix"
            )));
        }
        let depth: usize = depth.parse().map_err(|error| {
            ReleaseError::environment(format!(
                "scoped Cargo tree graph for {target_label} has an unrepresentable depth: {error}"
            ))
        })?;
        let display = display
            .strip_prefix("@@")
            .and_then(|value| value.strip_suffix("@@"))
            .filter(|value| !value.contains("@@"))
            .ok_or_else(|| {
                ReleaseError::environment(format!(
                    "scoped Cargo tree graph for {target_label} has malformed package sentinels"
                ))
            })?;
        let mut words = display.split_ascii_whitespace();
        let name = words.next().ok_or_else(|| {
            ReleaseError::environment(format!(
                "scoped Cargo tree graph for {target_label} omitted a package name"
            ))
        })?;
        let version = words
            .next()
            .and_then(|value| value.strip_prefix('v'))
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                ReleaseError::environment(format!(
                    "scoped Cargo tree graph for {target_label} omitted a package version"
                ))
            })?;
        let candidates = identities.get(&(name, version)).ok_or_else(|| {
            ReleaseError::environment(format!(
                "scoped Cargo tree package {name}@{version} is absent from target-filtered metadata"
            ))
        })?;
        let [package] = candidates.as_slice() else {
            return Err(ReleaseError::environment(format!(
                "scoped Cargo tree package {name}@{version} maps to {} metadata identities; source-qualified disambiguation is required",
                candidates.len()
            )));
        };
        let suffix = words.collect::<Vec<_>>().join(" ");
        let suffix_is_valid = if suffix.is_empty() || suffix == "(proc-macro)" {
            true
        } else if package.source.is_none() {
            let displayed_path = suffix
                .strip_prefix('(')
                .and_then(|value| value.strip_suffix(')'));
            let manifest_parent = package
                .manifest_path
                .as_deref()
                .and_then(Path::parent)
                .and_then(Path::to_str);
            displayed_path.is_some() && displayed_path == manifest_parent
        } else {
            false
        };
        if !suffix_is_valid {
            return Err(ReleaseError::environment(format!(
                "scoped Cargo tree package {name}@{version} has an unexpected display suffix"
            )));
        }
        if package.source.is_none() && !workspace_members.contains(package.id.as_str()) {
            return Err(ReleaseError::environment(format!(
                "scoped Cargo tree graph for {target_label} selected local package {name}@{version} outside the workspace"
            )));
        }
        if depth > stack.len() {
            return Err(ReleaseError::environment(format!(
                "scoped Cargo tree graph for {target_label} has a depth discontinuity"
            )));
        }
        if line_count == 1 {
            if depth != 0
                || package.name != "forge-cli"
                || package.version != RELEASE_VERSION
                || package.source.is_some()
            {
                return Err(ReleaseError::environment(format!(
                    "scoped Cargo tree graph for {target_label} does not start at workspace forge-cli {RELEASE_VERSION}"
                )));
            }
            root_id = Some(package.id.clone());
        } else if depth == 0 {
            return Err(ReleaseError::environment(format!(
                "scoped Cargo tree graph for {target_label} contains more than one root"
            )));
        }
        stack.truncate(depth);
        if let Some(parent) = stack.last() {
            if parent == &package.id {
                return Err(ReleaseError::environment(format!(
                    "scoped Cargo tree graph for {target_label} contains a self edge"
                )));
            }
            edges
                .entry(parent.clone())
                .or_default()
                .insert(package.id.clone());
        }
        selected.insert(package.id.clone());
        edges.entry(package.id.clone()).or_default();
        stack.push(package.id.clone());
    }
    if line_count == 0 {
        return Err(ReleaseError::environment(format!(
            "scoped Cargo tree graph for {target_label} is empty"
        )));
    }
    Ok(ScopedCargoTreeGraph {
        root_id: root_id.ok_or_else(|| {
            ReleaseError::internal("scoped Cargo tree parser omitted its validated root")
        })?,
        package_ids: selected,
        edges,
    })
}

fn render_sbom(
    target: &ReleaseTarget,
    metadata_bytes: &[u8],
    tree_bytes: &[u8],
    cargo_lock: &[u8],
    source_commit: &str,
    binary: &[u8],
) -> Result<Vec<u8>, ReleaseError> {
    let metadata: CargoMetadata = serde_json::from_slice(metadata_bytes).map_err(|error| {
        ReleaseError::environment(format!(
            "Cargo metadata for {} is not valid JSON: {error}",
            target.triple
        ))
    })?;
    let lock = parse_cargo_lock(cargo_lock)?;
    let lock_packages = cargo_lock_packages(&lock)?;
    let packages: BTreeMap<_, _> = metadata
        .packages
        .iter()
        .map(|package| (package.id.as_str(), package))
        .collect();
    let selection = parse_scoped_cargo_tree_graph(&metadata, tree_bytes, target.triple)?;
    let root = packages
        .get(selection.root_id.as_str())
        .copied()
        .ok_or_else(|| ReleaseError::internal("selected Cargo root disappeared"))?;
    let selected = &selection.package_ids;

    let root_ref = format!("pkg:cargo/forge@{RELEASE_VERSION}");
    let mut references = BTreeMap::new();
    for id in selected {
        let package = packages.get(id.as_str()).ok_or_else(|| {
            ReleaseError::environment(format!("Cargo metadata has no package for `{id}`"))
        })?;
        let reference = if package.id == root.id {
            root_ref.clone()
        } else {
            format!(
                "urn:forge:cargo:blake3:{}",
                blake3::hash(
                    format!(
                        "{}\0{}\0{}",
                        package.name,
                        package.version,
                        package.source.as_deref().unwrap_or("workspace")
                    )
                    .as_bytes()
                )
                .to_hex()
            )
        };
        references.insert(id.clone(), reference);
    }

    let mut component_ids: Vec<_> = selected
        .iter()
        .filter(|id| id.as_str() != root.id)
        .cloned()
        .collect();
    component_ids.sort_by(|left, right| {
        let left = packages.get(left.as_str());
        let right = packages.get(right.as_str());
        left.map(|package| (&package.name, &package.version, &package.source))
            .cmp(&right.map(|package| (&package.name, &package.version, &package.source)))
    });
    let mut components = Vec::with_capacity(component_ids.len());
    for id in &component_ids {
        let package = packages.get(id.as_str()).ok_or_else(|| {
            ReleaseError::internal(format!("selected Cargo package disappeared: `{id}`"))
        })?;
        let lock_checksum = release_package_lock_checksum(package, &lock_packages)?;
        let hashes = match lock_checksum {
            Some(checksum) => vec![BomHash {
                alg: "SHA-256",
                content: checksum,
            }],
            None => Vec::new(),
        };
        let properties = package
            .source
            .as_ref()
            .map(|source| {
                vec![BomProperty {
                    name: "forge:cargo-source",
                    value: source.clone(),
                }]
            })
            .unwrap_or_default();
        components.push(BomComponent {
            component_type: "library",
            bom_ref: references.get(id).cloned().ok_or_else(|| {
                ReleaseError::internal(format!("selected Cargo package has no reference: `{id}`"))
            })?,
            name: package.name.clone(),
            version: package.version.clone(),
            licenses: vec![BomLicenseChoice {
                expression: package_license_expression(package)?,
            }],
            hashes,
            properties,
        });
    }

    let mut dependencies = Vec::with_capacity(selected.len());
    for id in selected {
        let mut depends_on: Vec<_> = selection
            .edges
            .get(id)
            .ok_or_else(|| ReleaseError::internal("selected scoped Cargo tree node disappeared"))?
            .iter()
            .map(|dependency| {
                references.get(dependency).cloned().ok_or_else(|| {
                    ReleaseError::internal("scoped Cargo tree edge target has no SBOM reference")
                })
            })
            .collect::<Result<Vec<_>, ReleaseError>>()?;
        depends_on.sort();
        depends_on.dedup();
        dependencies.push(BomDependency {
            reference: references.get(id).cloned().ok_or_else(|| {
                ReleaseError::internal(format!("selected Cargo node has no reference: `{id}`"))
            })?,
            depends_on,
        });
    }
    dependencies.sort_by(|left, right| left.reference.cmp(&right.reference));

    let binary_sha256 = sha256_hex(binary);
    let bom = CycloneDxBom {
        bom_format: "CycloneDX",
        spec_version: "1.6",
        version: 1,
        metadata: BomMetadata {
            component: BomComponent {
                component_type: "application",
                bom_ref: root_ref,
                name: "forge".to_owned(),
                version: RELEASE_VERSION.to_owned(),
                licenses: vec![BomLicenseChoice {
                    expression: package_license_expression(root)?,
                }],
                hashes: vec![BomHash {
                    alg: "SHA-256",
                    content: binary_sha256.clone(),
                }],
                properties: vec![
                    BomProperty {
                        name: "forge:target-triple",
                        value: target.triple.to_owned(),
                    },
                    BomProperty {
                        name: "forge:cargo-lock-sha256",
                        value: sha256_hex(cargo_lock),
                    },
                    BomProperty {
                        name: "forge:source-commit",
                        value: source_commit.to_owned(),
                    },
                    BomProperty {
                        name: "forge:binary-sha256",
                        value: binary_sha256,
                    },
                    BomProperty {
                        name: "forge:binary-length",
                        value: binary.len().to_string(),
                    },
                ],
            },
        },
        components,
        dependencies,
    };
    to_pretty_json(&bom, "CycloneDX SBOM")
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseLicenseBaseline {
    packages: Vec<ReleaseLicensePackage>,
    schema: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseLicensePackage {
    id: String,
    legal_files: Vec<ReleaseLegalFile>,
    license_expression: String,
    lock_checksum: Option<String>,
    name: String,
    sbom_license_expression: String,
    source: String,
    targets: Vec<String>,
    version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseLegalFile {
    path: String,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ReleaseLicensePolicy {
    schema: String,
    cargo_about: CargoAboutLicensePolicy,
    spdx_expression_normalizations: BTreeMap<String, LicenseExpressionNormalization>,
    required_registry_legal_files: BTreeMap<String, Vec<String>>,
    required_workspace_legal_files: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct CargoAboutLicensePolicy {
    assessed_version: String,
    known_selected_packages_absent_from_custom_json: Vec<String>,
    decision: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct LicenseExpressionNormalization {
    upstream_declared: String,
    normalized_for_sbom: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CargoLockFile {
    version: u32,
    package: Vec<CargoLockPackage>,
}

#[derive(Debug, Deserialize)]
struct CargoLockPackage {
    name: String,
    version: String,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    checksum: Option<String>,
    #[serde(default)]
    #[serde(rename = "dependencies")]
    _dependencies: Vec<toml::Value>,
}

#[derive(Clone, Debug)]
struct LicensePackageSeed {
    package: CargoPackage,
    targets: BTreeSet<String>,
}

#[derive(Debug)]
struct ReleaseLicenseEvidence {
    baseline: ReleaseLicenseBaseline,
    legal_text_by_package: BTreeMap<String, BTreeMap<String, Vec<u8>>>,
}

pub(crate) fn check_release_licenses(
    repository: &Path,
) -> Result<ReleaseLicenseReport, ReleaseError> {
    let baseline_bytes = read_bounded(
        &repository.join(LICENSE_BASELINE_FILE),
        MAX_LICENSE_BASELINE_BYTES,
        "release-license baseline",
    )?;
    let policy_bytes = read_bounded(
        &repository.join(LICENSE_POLICY_FILE),
        MAX_LICENSE_POLICY_BYTES,
        "release-license policy",
    )?;
    let checked_bundle = read_bounded(
        &repository.join(LICENSE_NOTICES_FILE),
        MAX_SOURCE_FILE_BYTES as u64,
        "release-license bundle",
    )?;
    let expected: ReleaseLicenseBaseline =
        serde_json::from_slice(&baseline_bytes).map_err(|error| {
            ReleaseError::negative(format!(
                "{LICENSE_BASELINE_FILE} is not valid release-license baseline JSON: {error}"
            ))
        })?;
    let policy = parse_release_license_policy(&policy_bytes)?;
    let evidence = collect_release_license_evidence(repository, &policy)?;
    require_release_license_baseline_matches(&expected, &evidence.baseline)?;
    let rendered_baseline = to_pretty_json(&evidence.baseline, "release-license baseline")?;
    if baseline_bytes != rendered_baseline {
        return Err(ReleaseError::negative(format!(
            "{LICENSE_BASELINE_FILE} is semantically current but not in canonical deterministic form; run release-license-generate and review the diff"
        )));
    }
    let rendered_bundle = render_release_license_bundle(&evidence)?;
    require_portable_release_license_output(LICENSE_BASELINE_FILE, &rendered_baseline)?;
    require_portable_release_license_output(LICENSE_NOTICES_FILE, &rendered_bundle)?;
    if checked_bundle != rendered_bundle {
        return Err(ReleaseError::negative(format!(
            "{LICENSE_NOTICES_FILE} differs from the locked release dependency graph, reviewed policy, or legal-file bytes; run release-license-generate and review the diff"
        )));
    }
    Ok(release_license_report(&evidence))
}

fn generate_release_licenses(
    repository: &Path,
    output_root: &Path,
) -> Result<ReleaseLicenseReport, ReleaseError> {
    let policy_path = repository.join(LICENSE_POLICY_FILE);
    let policy_before = read_bounded(
        &policy_path,
        MAX_LICENSE_POLICY_BYTES,
        "release-license policy",
    )?;
    let policy = parse_release_license_policy(&policy_before)?;
    let evidence = collect_release_license_evidence(repository, &policy)?;
    let baseline = to_pretty_json(&evidence.baseline, "release-license baseline")?;
    let bundle = render_release_license_bundle(&evidence)?;
    require_portable_release_license_output(LICENSE_BASELINE_FILE, &baseline)?;
    require_portable_release_license_output(LICENSE_NOTICES_FILE, &bundle)?;
    if baseline.len() > MAX_LICENSE_BASELINE_BYTES as usize {
        return Err(ReleaseError::negative(format!(
            "generated {LICENSE_BASELINE_FILE} exceeds its {MAX_LICENSE_BASELINE_BYTES}-byte reader bound"
        )));
    }
    if bundle.len() > MAX_SOURCE_FILE_BYTES {
        return Err(ReleaseError::negative(format!(
            "generated {LICENSE_NOTICES_FILE} exceeds its {MAX_SOURCE_FILE_BYTES}-byte reader bound"
        )));
    }

    let output = RepositoryWriter::new(output_root).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to pin release-license output root before generation: {error}"
        ))
    })?;
    output
        .write_atomic(LICENSE_BASELINE_FILE, &baseline)
        .map_err(|error| {
            ReleaseError::environment(format!(
                "failed to atomically write generated {LICENSE_BASELINE_FILE}: {error}"
            ))
        })?;
    output
        .write_atomic(LICENSE_NOTICES_FILE, &bundle)
        .map_err(|error| {
            ReleaseError::environment(format!(
                "failed to atomically write generated {LICENSE_NOTICES_FILE}: {error}"
            ))
        })?;
    let policy_after = read_bounded(
        &policy_path,
        MAX_LICENSE_POLICY_BYTES,
        "release-license policy",
    )?;
    if policy_before != policy_after {
        return Err(ReleaseError::environment(format!(
            "{LICENSE_POLICY_FILE} changed during generation; generated evidence must be reviewed from a stable policy"
        )));
    }
    Ok(release_license_report(&evidence))
}

fn release_license_report(evidence: &ReleaseLicenseEvidence) -> ReleaseLicenseReport {
    ReleaseLicenseReport {
        package_count: evidence.baseline.packages.len(),
        legal_file_count: evidence
            .baseline
            .packages
            .iter()
            .map(|package| package.legal_files.len())
            .sum(),
    }
}

fn parse_release_license_policy(bytes: &[u8]) -> Result<ReleaseLicensePolicy, ReleaseError> {
    let policy: ReleaseLicensePolicy = serde_json::from_slice(bytes).map_err(|error| {
        ReleaseError::negative(format!(
            "{LICENSE_POLICY_FILE} is not valid release-license policy JSON: {error}"
        ))
    })?;
    if policy.schema != LICENSE_POLICY_SCHEMA {
        return Err(ReleaseError::negative(format!(
            "{LICENSE_POLICY_FILE} has unsupported schema `{}`",
            policy.schema
        )));
    }
    if policy.cargo_about.assessed_version != "0.9.1"
        || policy.cargo_about.decision
            != "locked-crate-archive-sha256-verification-and-separate-unpacked-source-legal-file-aggregation"
    {
        return Err(ReleaseError::negative(format!(
            "{LICENSE_POLICY_FILE} changed the reviewed cargo-about advisory decision"
        )));
    }
    let expected_about_omissions = BTreeSet::new();
    let actual_about_omissions: BTreeSet<_> = policy
        .cargo_about
        .known_selected_packages_absent_from_custom_json
        .iter()
        .cloned()
        .collect();
    if actual_about_omissions != expected_about_omissions
        || actual_about_omissions.len()
            != policy
                .cargo_about
                .known_selected_packages_absent_from_custom_json
                .len()
    {
        return Err(ReleaseError::negative(format!(
            "{LICENSE_POLICY_FILE} changed or duplicated the reviewed cargo-about omission set"
        )));
    }
    let expected_workspace_files = ["LICENSE-APACHE", "LICENSE-MIT"];
    if policy.required_workspace_legal_files != expected_workspace_files.map(str::to_owned).to_vec()
    {
        return Err(ReleaseError::negative(format!(
            "{LICENSE_POLICY_FILE} changed the exact Forge workspace license-file set"
        )));
    }
    if policy.spdx_expression_normalizations.len() != 5 {
        return Err(ReleaseError::negative(format!(
            "{LICENSE_POLICY_FILE} must contain exactly five reviewed slash-expression mappings"
        )));
    }
    if policy.required_registry_legal_files.len() != 4 {
        return Err(ReleaseError::negative(format!(
            "{LICENSE_POLICY_FILE} must contain exactly four special registry legal-file requirements"
        )));
    }
    Ok(policy)
}

fn collect_release_license_evidence(
    repository: &Path,
    policy: &ReleaseLicensePolicy,
) -> Result<ReleaseLicenseEvidence, ReleaseError> {
    let repository_root = fs::canonicalize(repository).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to resolve repository root before release-license collection: {error}"
        ))
    })?;
    let lock_bytes = read_bounded(
        &repository.join("Cargo.lock"),
        MAX_METADATA_BYTES as u64,
        "Cargo.lock",
    )?;
    let lock = parse_cargo_lock(&lock_bytes)?;
    let lock_packages = cargo_lock_packages(&lock)?;
    let mut seeds: BTreeMap<String, LicensePackageSeed> = BTreeMap::new();

    for target in &RELEASE_TARGETS {
        let metadata_bytes = cargo_metadata(repository, target)?;
        let tree_bytes = cargo_tree(repository, target)?;
        let metadata: CargoMetadata = serde_json::from_slice(&metadata_bytes).map_err(|error| {
            ReleaseError::environment(format!(
                "Cargo metadata for {} is not valid JSON: {error}",
                target.triple
            ))
        })?;
        require_release_license_workspace_root(&repository_root, &metadata, target)?;
        let selection = parse_scoped_cargo_tree_graph(&metadata, &tree_bytes, target.triple)?;
        let packages: BTreeMap<_, _> = metadata
            .packages
            .iter()
            .map(|package| (package.id.as_str(), package))
            .collect();
        for raw_id in selection.package_ids {
            let package = packages.get(raw_id.as_str()).copied().ok_or_else(|| {
                ReleaseError::internal(format!(
                    "selected package disappeared from Cargo metadata for {}",
                    target.triple
                ))
            })?;
            let id = release_license_package_id(package);
            match seeds.get_mut(&id) {
                Some(seed) => {
                    if !same_release_license_package(&seed.package, package) {
                        return Err(ReleaseError::environment(format!(
                            "Cargo metadata disagrees between release targets for {id}"
                        )));
                    }
                    seed.targets.insert(target.triple.to_owned());
                }
                None => {
                    seeds.insert(
                        id,
                        LicensePackageSeed {
                            package: package.clone(),
                            targets: BTreeSet::from([target.triple.to_owned()]),
                        },
                    );
                }
            }
        }
    }

    let workspace_count = seeds
        .values()
        .filter(|seed| seed.package.source.is_none())
        .count();
    let registry_count = seeds.len().saturating_sub(workspace_count);
    if seeds.len() != EXPECTED_LICENSE_PACKAGES
        || workspace_count != EXPECTED_WORKSPACE_LICENSE_PACKAGES
        || registry_count != EXPECTED_REGISTRY_LICENSE_PACKAGES
    {
        return Err(ReleaseError::negative(format!(
            "scoped Cargo tree release-license union contains {} packages ({workspace_count} workspace, {registry_count} registry), expected {EXPECTED_LICENSE_PACKAGES} ({EXPECTED_WORKSPACE_LICENSE_PACKAGES} workspace, {EXPECTED_REGISTRY_LICENSE_PACKAGES} registry)",
            seeds.len()
        )));
    }

    let workspace_legal_text = read_workspace_legal_files(repository, policy)?;
    let mut used_normalizations = BTreeSet::new();
    let mut total_legal_bytes = 0_u64;
    let mut baseline_packages = Vec::with_capacity(seeds.len());
    let mut legal_text_by_package = BTreeMap::new();
    for (id, seed) in &seeds {
        let package = &seed.package;
        let source = package
            .source
            .clone()
            .unwrap_or_else(|| "workspace".to_owned());
        let raw_expression = package.license.clone().ok_or_else(|| {
            ReleaseError::negative(format!(
                "release dependency {id} has no Cargo package.license expression"
            ))
        })?;
        let normalized_expression =
            reviewed_package_license_expression(package, policy, &mut used_normalizations)?;
        let lock_checksum = release_package_lock_checksum(package, &lock_packages)?;
        let legal_text = if package.source.is_none() {
            workspace_legal_text.clone()
        } else {
            let manifest = package.manifest_path.as_deref().ok_or_else(|| {
                ReleaseError::environment(format!(
                    "registry release dependency {id} omitted manifest_path"
                ))
            })?;
            let package_root = manifest.parent().ok_or_else(|| {
                ReleaseError::environment(format!(
                    "registry release dependency {id} has no package root"
                ))
            })?;
            verify_registry_crate_archive(
                package,
                package_root,
                lock_checksum.as_deref().ok_or_else(|| {
                    ReleaseError::internal("registry package omitted its validated lock checksum")
                })?,
            )?;
            scan_registry_legal_files(package_root, id)?
        };
        for bytes in legal_text.values() {
            total_legal_bytes = total_legal_bytes
                .checked_add(u64::try_from(bytes.len()).map_err(|_| {
                    ReleaseError::environment("legal-file size is not representable")
                })?)
                .ok_or_else(|| ReleaseError::environment("legal-file byte count overflowed"))?;
            if total_legal_bytes > MAX_TOTAL_LEGAL_FILE_BYTES {
                return Err(ReleaseError::environment(format!(
                    "release-license legal text exceeds the {MAX_TOTAL_LEGAL_FILE_BYTES}-byte bound"
                )));
            }
        }
        let legal_files = legal_text
            .iter()
            .map(|(path, bytes)| ReleaseLegalFile {
                path: path.clone(),
                sha256: sha256_hex(bytes),
            })
            .collect();
        baseline_packages.push(ReleaseLicensePackage {
            id: id.clone(),
            legal_files,
            license_expression: raw_expression,
            lock_checksum,
            name: package.name.clone(),
            sbom_license_expression: normalized_expression,
            source,
            targets: seed.targets.iter().cloned().collect(),
            version: package.version.clone(),
        });
        legal_text_by_package.insert(id.clone(), legal_text);
    }
    let configured_normalizations: BTreeSet<_> = policy
        .spdx_expression_normalizations
        .keys()
        .cloned()
        .collect();
    if used_normalizations != configured_normalizations {
        let stale: Vec<_> = configured_normalizations
            .difference(&used_normalizations)
            .cloned()
            .collect();
        return Err(ReleaseError::negative(format!(
            "{LICENSE_POLICY_FILE} contains stale slash-expression mappings: {}",
            stale.join(", ")
        )));
    }

    let baseline = ReleaseLicenseBaseline {
        packages: baseline_packages,
        schema: LICENSE_BASELINE_SCHEMA.to_owned(),
    };
    validate_required_legal_files(&baseline, policy)?;
    let legal_file_count: usize = baseline
        .packages
        .iter()
        .map(|package| package.legal_files.len())
        .sum();
    if legal_file_count != EXPECTED_LEGAL_FILES {
        return Err(ReleaseError::negative(format!(
            "scoped Cargo tree release-license union contains {legal_file_count} legal files, expected {EXPECTED_LEGAL_FILES}"
        )));
    }
    Ok(ReleaseLicenseEvidence {
        baseline,
        legal_text_by_package,
    })
}

fn parse_cargo_lock(bytes: &[u8]) -> Result<CargoLockFile, ReleaseError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| ReleaseError::negative(format!("Cargo.lock is not UTF-8: {error}")))?;
    let lock: CargoLockFile = toml::from_str(text)
        .map_err(|error| ReleaseError::negative(format!("Cargo.lock is invalid TOML: {error}")))?;
    if lock.version != 4 {
        return Err(ReleaseError::negative(format!(
            "Cargo.lock format {} is not the reviewed format 4",
            lock.version
        )));
    }
    Ok(lock)
}

type CargoLockPackageKey = (String, String, Option<String>);

fn cargo_lock_packages(
    lock: &CargoLockFile,
) -> Result<BTreeMap<CargoLockPackageKey, Option<String>>, ReleaseError> {
    let mut packages = BTreeMap::new();
    for package in &lock.package {
        let key = (
            package.name.clone(),
            package.version.clone(),
            package.source.clone(),
        );
        if packages.insert(key, package.checksum.clone()).is_some() {
            return Err(ReleaseError::negative(format!(
                "Cargo.lock contains duplicate package identity {}@{}",
                package.name, package.version
            )));
        }
    }
    Ok(packages)
}

fn require_release_license_workspace_root(
    repository: &Path,
    metadata: &CargoMetadata,
    target: &ReleaseTarget,
) -> Result<(), ReleaseError> {
    let reported = metadata.workspace_root.as_deref().ok_or_else(|| {
        ReleaseError::environment(format!(
            "Cargo metadata for {} omitted workspace_root",
            target.triple
        ))
    })?;
    let reported = fs::canonicalize(reported).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to resolve Cargo workspace_root for {}: {error}",
            target.triple
        ))
    })?;
    if reported == repository {
        Ok(())
    } else {
        Err(ReleaseError::environment(format!(
            "Cargo metadata workspace_root for {} does not match the Forge repository",
            target.triple
        )))
    }
}

fn same_release_license_package(left: &CargoPackage, right: &CargoPackage) -> bool {
    left.name == right.name
        && left.version == right.version
        && left.license == right.license
        && left.source == right.source
        && left.manifest_path == right.manifest_path
}

fn release_license_package_id(package: &CargoPackage) -> String {
    let package_key = release_license_package_key(package);
    match &package.source {
        Some(source) => format!("{source}#{package_key}"),
        None => format!("workspace:{package_key}"),
    }
}

fn release_license_package_key(package: &CargoPackage) -> String {
    format!("{}@{}", package.name, package.version)
}

fn release_package_lock_checksum(
    package: &CargoPackage,
    lock_packages: &BTreeMap<CargoLockPackageKey, Option<String>>,
) -> Result<Option<String>, ReleaseError> {
    let key = (
        package.name.clone(),
        package.version.clone(),
        package.source.clone(),
    );
    let checksum = lock_packages.get(&key).ok_or_else(|| {
        ReleaseError::negative(format!(
            "selected release dependency {} is absent from Cargo.lock",
            release_license_package_id(package)
        ))
    })?;
    if package.source.is_none() {
        if checksum.is_some() {
            return Err(ReleaseError::negative(format!(
                "workspace release dependency {} unexpectedly has a Cargo.lock checksum",
                release_license_package_id(package)
            )));
        }
        return Ok(None);
    }
    let checksum = checksum.as_deref().ok_or_else(|| {
        ReleaseError::negative(format!(
            "registry release dependency {} has no Cargo.lock checksum",
            release_license_package_id(package)
        ))
    })?;
    if checksum.len() != 64
        || !checksum
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(ReleaseError::negative(format!(
            "registry release dependency {} has a malformed Cargo.lock checksum",
            release_license_package_id(package)
        )));
    }
    Ok(Some(checksum.to_owned()))
}

fn verify_registry_crate_archive(
    package: &CargoPackage,
    package_root: &Path,
    lock_checksum: &str,
) -> Result<(), ReleaseError> {
    if !package
        .source
        .as_deref()
        .is_some_and(|source| source.starts_with("registry+"))
    {
        return Err(ReleaseError::negative(format!(
            "release dependency {} has a lock checksum but is not a registry package",
            release_license_package_id(package)
        )));
    }
    let expected_package_directory = format!("{}-{}", package.name, package.version);
    if package_root.file_name() != Some(OsStr::new(&expected_package_directory)) {
        return Err(ReleaseError::environment(format!(
            "unpacked registry source directory does not match package identity for {}",
            release_license_package_id(package)
        )));
    }
    let source_bucket = package_root.parent().ok_or_else(|| {
        ReleaseError::environment("unpacked registry source root has no source bucket")
    })?;
    let source_bucket_name = source_bucket
        .file_name()
        .ok_or_else(|| ReleaseError::environment("unpacked registry source bucket has no name"))?;
    let source_root = source_bucket.parent().ok_or_else(|| {
        ReleaseError::environment("unpacked registry source bucket has no src parent")
    })?;
    if source_root.file_name() != Some(OsStr::new("src")) {
        return Err(ReleaseError::environment(format!(
            "unpacked registry source for {} is outside Cargo's unambiguous registry/src layout",
            release_license_package_id(package)
        )));
    }
    let registry_root = source_root.parent().ok_or_else(|| {
        ReleaseError::environment("Cargo registry src directory has no registry parent")
    })?;
    let cache_root = registry_root.join("cache");
    let cache_bucket = cache_root.join(source_bucket_name);
    for (directory, label) in [
        (registry_root, "Cargo registry root"),
        (source_root, "Cargo registry source root"),
        (source_bucket, "Cargo registry source bucket"),
        (package_root, "unpacked registry package root"),
        (cache_root.as_path(), "Cargo registry cache root"),
        (cache_bucket.as_path(), "Cargo registry cache bucket"),
    ] {
        let metadata = fs::symlink_metadata(directory).map_err(|error| {
            ReleaseError::environment(format!(
                "failed to inspect {label} for {}: {error}",
                release_license_package_id(package)
            ))
        })?;
        if source_entry_is_link_or_reparse(&metadata) || !metadata.is_dir() {
            return Err(ReleaseError::environment(format!(
                "{label} for {} is not a real non-reparse directory",
                release_license_package_id(package)
            )));
        }
    }

    let expected_archive_name = format!("{expected_package_directory}.crate");
    let mut matching_archive = None;
    let entries = fs::read_dir(&cache_bucket).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to enumerate Cargo registry cache for {}: {error}",
            release_license_package_id(package)
        ))
    })?;
    for (index, entry) in entries.enumerate() {
        if index >= MAX_REGISTRY_CACHE_ENTRIES {
            return Err(ReleaseError::environment(format!(
                "Cargo registry cache exceeds the {MAX_REGISTRY_CACHE_ENTRIES}-entry bound"
            )));
        }
        let entry = entry.map_err(|error| {
            ReleaseError::environment(format!(
                "failed to read Cargo registry cache entry for {}: {error}",
                release_license_package_id(package)
            ))
        })?;
        let name = entry.file_name().into_string().map_err(|_| {
            ReleaseError::environment("Cargo registry cache contains a non-UTF-8 entry name")
        })?;
        if name.eq_ignore_ascii_case(&expected_archive_name) {
            if name != expected_archive_name || matching_archive.is_some() {
                return Err(ReleaseError::environment(format!(
                    "Cargo registry cache archive identity is ambiguous for {}",
                    release_license_package_id(package)
                )));
            }
            matching_archive = Some(entry.path());
        }
    }
    let archive = matching_archive.ok_or_else(|| {
        ReleaseError::environment(format!(
            "Cargo registry cache archive is missing for {}; run the explicit locked target fetch before the offline release-license check",
            release_license_package_id(package)
        ))
    })?;
    let bytes = read_bounded_registry_archive(&archive, package)?;
    let actual_checksum = sha256_hex(&bytes);
    if actual_checksum != lock_checksum {
        return Err(ReleaseError::negative(format!(
            "Cargo registry cache archive SHA-256 disagrees with Cargo.lock for {}",
            release_license_package_id(package)
        )));
    }
    Ok(())
}

fn read_bounded_registry_archive(
    path: &Path,
    package: &CargoPackage,
) -> Result<Vec<u8>, ReleaseError> {
    let before = fs::symlink_metadata(path).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to inspect Cargo registry archive for {}: {error}",
            release_license_package_id(package)
        ))
    })?;
    if source_entry_is_link_or_reparse(&before) || !before.is_file() {
        return Err(ReleaseError::environment(format!(
            "Cargo registry archive for {} is not a real non-reparse regular file",
            release_license_package_id(package)
        )));
    }
    if before.len() > MAX_REGISTRY_CRATE_ARCHIVE_BYTES {
        return Err(ReleaseError::environment(format!(
            "Cargo registry archive for {} exceeds the {MAX_REGISTRY_CRATE_ARCHIVE_BYTES}-byte bound",
            release_license_package_id(package)
        )));
    }
    let file = File::open(path).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to open Cargo registry archive for {}: {error}",
            release_license_package_id(package)
        ))
    })?;
    let mut bytes = Vec::with_capacity(usize::try_from(before.len()).map_err(|_| {
        ReleaseError::environment("Cargo registry archive size is not representable")
    })?);
    file.take(MAX_REGISTRY_CRATE_ARCHIVE_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| {
            ReleaseError::environment(format!(
                "failed to read Cargo registry archive for {}: {error}",
                release_license_package_id(package)
            ))
        })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_REGISTRY_CRATE_ARCHIVE_BYTES {
        return Err(ReleaseError::environment(format!(
            "Cargo registry archive for {} grew above the {MAX_REGISTRY_CRATE_ARCHIVE_BYTES}-byte bound",
            release_license_package_id(package)
        )));
    }
    let after = fs::symlink_metadata(path).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to re-inspect Cargo registry archive for {}: {error}",
            release_license_package_id(package)
        ))
    })?;
    if source_entry_is_link_or_reparse(&after)
        || !after.is_file()
        || before.len() != after.len()
        || after.len() != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
    {
        return Err(ReleaseError::environment(format!(
            "Cargo registry archive changed while it was read for {}",
            release_license_package_id(package)
        )));
    }
    Ok(bytes)
}

fn reviewed_package_license_expression(
    package: &CargoPackage,
    policy: &ReleaseLicensePolicy,
    used_normalizations: &mut BTreeSet<String>,
) -> Result<String, ReleaseError> {
    let declared = package.license.as_deref().ok_or_else(|| {
        ReleaseError::negative(format!(
            "release dependency {} has no Cargo package.license expression",
            release_license_package_id(package)
        ))
    })?;
    let key = release_license_package_key(package);
    let mapping = policy.spdx_expression_normalizations.get(&key);
    let policy_expression = if declared.contains('/') {
        let mapping = mapping.ok_or_else(|| {
            ReleaseError::negative(format!(
                "release dependency {key} has an unknown slash-separated license expression"
            ))
        })?;
        if package.source.is_none() || mapping.upstream_declared != declared {
            return Err(ReleaseError::negative(format!(
                "reviewed slash-expression mapping does not exactly match {key}"
            )));
        }
        if mapping.normalized_for_sbom.contains('/')
            || mapping.normalized_for_sbom.trim().is_empty()
        {
            return Err(ReleaseError::negative(format!(
                "reviewed slash-expression mapping for {key} has an invalid normalized expression"
            )));
        }
        used_normalizations.insert(key.clone());
        mapping.normalized_for_sbom.clone()
    } else {
        if mapping.is_some() {
            return Err(ReleaseError::negative(format!(
                "{LICENSE_POLICY_FILE} contains a stale slash-expression mapping for {key}"
            )));
        }
        declared.to_owned()
    };
    let code_expression = package_license_expression(package)?;
    if policy_expression != code_expression {
        return Err(ReleaseError::negative(format!(
            "reviewed policy and release SBOM normalization disagree for {key}"
        )));
    }
    Ok(policy_expression)
}

fn read_workspace_legal_files(
    repository: &Path,
    policy: &ReleaseLicensePolicy,
) -> Result<BTreeMap<String, Vec<u8>>, ReleaseError> {
    let mut files = BTreeMap::new();
    for relative in &policy.required_workspace_legal_files {
        if !is_single_safe_component(relative) || !is_legal_basename(relative) {
            return Err(ReleaseError::negative(format!(
                "{LICENSE_POLICY_FILE} contains an unsafe workspace legal-file path"
            )));
        }
        let bytes =
            read_bounded_legal_file(&repository.join(relative), "Forge workspace", relative)?;
        files.insert(relative.clone(), bytes);
    }
    Ok(files)
}

fn scan_registry_legal_files(
    package_root: &Path,
    package_id: &str,
) -> Result<BTreeMap<String, Vec<u8>>, ReleaseError> {
    let root_metadata = fs::symlink_metadata(package_root).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to inspect unpacked Cargo source root for {package_id}: {error}"
        ))
    })?;
    if source_entry_is_link_or_reparse(&root_metadata) || !root_metadata.file_type().is_dir() {
        return Err(ReleaseError::environment(format!(
            "unpacked Cargo source root for {package_id} is not a real non-reparse directory"
        )));
    }
    let mut pending = vec![(package_root.to_path_buf(), String::new())];
    let mut visited_entries = 0_usize;
    let mut files = BTreeMap::new();
    while let Some((directory, relative_directory)) = pending.pop() {
        let directory_metadata = fs::symlink_metadata(&directory).map_err(|error| {
            ReleaseError::environment(format!(
                "failed to re-inspect unpacked Cargo source directory for {package_id}: {error}"
            ))
        })?;
        if source_entry_is_link_or_reparse(&directory_metadata) || !directory_metadata.is_dir() {
            return Err(ReleaseError::environment(format!(
                "unpacked Cargo source directory is not a real non-reparse directory: {package_id}:{relative_directory}"
            )));
        }
        let entries = fs::read_dir(&directory).map_err(|error| {
            ReleaseError::environment(format!(
                "failed to enumerate unpacked Cargo source for {package_id}: {error}"
            ))
        })?;
        let mut entries = entries
            .map(|entry| {
                let entry = entry.map_err(|error| {
                    ReleaseError::environment(format!(
                        "failed to read an unpacked Cargo source entry for {package_id}: {error}"
                    ))
                })?;
                let name = entry.file_name().into_string().map_err(|_| {
                    ReleaseError::environment(format!(
                        "unpacked Cargo source for {package_id} contains a non-UTF-8 path"
                    ))
                })?;
                Ok((name, entry.path()))
            })
            .collect::<Result<Vec<_>, ReleaseError>>()?;
        entries.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
        for (name, path) in entries {
            visited_entries = visited_entries.checked_add(1).ok_or_else(|| {
                ReleaseError::environment("release-license scan entry count overflowed")
            })?;
            if visited_entries > MAX_LICENSE_SCAN_ENTRIES_PER_PACKAGE {
                return Err(ReleaseError::environment(format!(
                    "unpacked Cargo source for {package_id} exceeds the {MAX_LICENSE_SCAN_ENTRIES_PER_PACKAGE}-entry scan bound"
                )));
            }
            let relative = if relative_directory.is_empty() {
                name.clone()
            } else {
                format!("{relative_directory}/{name}")
            };
            let metadata = fs::symlink_metadata(&path).map_err(|error| {
                ReleaseError::environment(format!(
                    "failed to inspect unpacked Cargo source entry {package_id}:{relative}: {error}"
                ))
            })?;
            let file_type = metadata.file_type();
            if source_entry_is_link_or_reparse(&metadata) {
                return Err(ReleaseError::environment(format!(
                    "unpacked Cargo source contains a symbolic link or reparse point: {package_id}:{relative}"
                )));
            }
            if file_type.is_dir() {
                pending.push((path, relative));
            } else if file_type.is_file() {
                if is_legal_basename(&name) {
                    if files.len() >= MAX_LEGAL_FILES_PER_PACKAGE {
                        return Err(ReleaseError::environment(format!(
                            "unpacked Cargo source for {package_id} exceeds the {MAX_LEGAL_FILES_PER_PACKAGE}-legal-file bound"
                        )));
                    }
                    let bytes = read_bounded_legal_file(&path, package_id, &relative)?;
                    if files.insert(relative.clone(), bytes).is_some() {
                        return Err(ReleaseError::environment(format!(
                            "unpacked Cargo source repeated legal-file path {package_id}:{relative}"
                        )));
                    }
                }
            } else {
                return Err(ReleaseError::environment(format!(
                    "unpacked Cargo source contains a non-regular entry: {package_id}:{relative}"
                )));
            }
        }
    }
    if files.is_empty() {
        return Err(ReleaseError::negative(format!(
            "registry release dependency {package_id} has no detected legal files"
        )));
    }
    Ok(files)
}

fn is_single_safe_component(path: &str) -> bool {
    let mut components = Path::new(path).components();
    matches!(components.next(), Some(PathComponent::Normal(_))) && components.next().is_none()
}

fn is_legal_basename(name: &str) -> bool {
    const PREFIXES: [&str; 7] = [
        "license",
        "licence",
        "copying",
        "notice",
        "notices",
        "copyright",
        "unlicense",
    ];
    const CODE_SUFFIXES: [&str; 13] = [
        ".c", ".cc", ".cpp", ".go", ".h", ".hpp", ".java", ".js", ".py", ".rs", ".swift", ".ts",
        ".tsx",
    ];
    let name = name.to_ascii_lowercase();
    PREFIXES.iter().any(|prefix| {
        name == *prefix
            || name.starts_with(&format!("{prefix}-"))
            || name.starts_with(&format!("{prefix}_"))
            || (name.starts_with(&format!("{prefix}."))
                && !CODE_SUFFIXES.iter().any(|suffix| name.ends_with(suffix)))
    })
}

fn read_bounded_legal_file(
    path: &Path,
    package_id: &str,
    relative: &str,
) -> Result<Vec<u8>, ReleaseError> {
    let before = fs::symlink_metadata(path).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to inspect legal file {package_id}:{relative}: {error}"
        ))
    })?;
    if source_entry_is_link_or_reparse(&before) || !before.file_type().is_file() {
        return Err(ReleaseError::environment(format!(
            "legal file is not a real non-reparse regular file: {package_id}:{relative}"
        )));
    }
    if before.len() > MAX_LEGAL_FILE_BYTES {
        return Err(ReleaseError::environment(format!(
            "legal file {package_id}:{relative} exceeds the {MAX_LEGAL_FILE_BYTES}-byte bound"
        )));
    }
    let file = File::open(path).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to open legal file {package_id}:{relative}: {error}"
        ))
    })?;
    let mut bytes = Vec::with_capacity(usize::try_from(before.len()).map_err(|_| {
        ReleaseError::environment(format!(
            "legal file size is not representable for {package_id}:{relative}"
        ))
    })?);
    file.take(MAX_LEGAL_FILE_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| {
            ReleaseError::environment(format!(
                "failed to read legal file {package_id}:{relative}: {error}"
            ))
        })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_LEGAL_FILE_BYTES {
        return Err(ReleaseError::environment(format!(
            "legal file {package_id}:{relative} grew above the {MAX_LEGAL_FILE_BYTES}-byte bound"
        )));
    }
    let after = fs::symlink_metadata(path).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to re-inspect legal file {package_id}:{relative}: {error}"
        ))
    })?;
    if source_entry_is_link_or_reparse(&after)
        || !after.file_type().is_file()
        || before.len() != after.len()
        || after.len() != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
    {
        return Err(ReleaseError::environment(format!(
            "legal file changed while it was read: {package_id}:{relative}"
        )));
    }
    std::str::from_utf8(&bytes).map_err(|error| {
        ReleaseError::negative(format!(
            "legal file is not UTF-8: {package_id}:{relative}: {error}"
        ))
    })?;
    Ok(bytes)
}

fn validate_required_legal_files(
    baseline: &ReleaseLicenseBaseline,
    policy: &ReleaseLicensePolicy,
) -> Result<(), ReleaseError> {
    let mut by_key = BTreeMap::new();
    for package in &baseline.packages {
        let key = format!("{}@{}", package.name, package.version);
        if by_key.insert(key.clone(), package).is_some() {
            return Err(ReleaseError::negative(format!(
                "release-license closure contains duplicate package key {key}"
            )));
        }
    }
    for (key, required) in &policy.required_registry_legal_files {
        let package = by_key.get(key).copied().ok_or_else(|| {
            ReleaseError::negative(format!(
                "{LICENSE_POLICY_FILE} requires absent registry package {key}"
            ))
        })?;
        if package.source == "workspace" {
            return Err(ReleaseError::negative(format!(
                "{LICENSE_POLICY_FILE} classifies workspace package {key} as registry evidence"
            )));
        }
        let observed: BTreeSet<_> = package
            .legal_files
            .iter()
            .map(|file| file.path.as_str())
            .collect();
        let required_set: BTreeSet<_> = required.iter().map(String::as_str).collect();
        if required_set.len() != required.len() {
            return Err(ReleaseError::negative(format!(
                "{LICENSE_POLICY_FILE} duplicates a required legal-file path for {key}"
            )));
        }
        let missing: Vec<_> = required_set.difference(&observed).copied().collect();
        if !missing.is_empty() {
            return Err(ReleaseError::negative(format!(
                "required legal files are absent for {key}: {}",
                missing.join(", ")
            )));
        }
    }
    let workspace_required: BTreeSet<_> = policy
        .required_workspace_legal_files
        .iter()
        .map(String::as_str)
        .collect();
    for package in baseline
        .packages
        .iter()
        .filter(|package| package.source == "workspace")
    {
        let observed: BTreeSet<_> = package
            .legal_files
            .iter()
            .map(|file| file.path.as_str())
            .collect();
        if observed != workspace_required {
            return Err(ReleaseError::negative(format!(
                "workspace release dependency {} has a changed Forge license-file set",
                package.id
            )));
        }
    }
    Ok(())
}

fn require_release_license_baseline_matches(
    expected: &ReleaseLicenseBaseline,
    observed: &ReleaseLicenseBaseline,
) -> Result<(), ReleaseError> {
    if expected.schema != LICENSE_BASELINE_SCHEMA {
        return Err(ReleaseError::negative(format!(
            "{LICENSE_BASELINE_FILE} has unsupported schema `{}`",
            expected.schema
        )));
    }
    if observed.schema != LICENSE_BASELINE_SCHEMA {
        return Err(ReleaseError::internal(
            "generated release-license baseline used the wrong schema",
        ));
    }
    let expected_packages = unique_license_packages(&expected.packages, "checked-in baseline")?;
    let observed_packages = unique_license_packages(&observed.packages, "observed closure")?;
    let expected_ids: BTreeSet<_> = expected_packages.keys().copied().collect();
    let observed_ids: BTreeSet<_> = observed_packages.keys().copied().collect();
    let missing: Vec<_> = expected_ids.difference(&observed_ids).copied().collect();
    let extra: Vec<_> = observed_ids.difference(&expected_ids).copied().collect();
    if !missing.is_empty() || !extra.is_empty() {
        return Err(ReleaseError::negative(format!(
            "release-license package ID drift; missing [{}], extra [{}]",
            missing.join(", "),
            extra.join(", ")
        )));
    }
    for id in expected_ids {
        let expected_package = expected_packages.get(id).copied().ok_or_else(|| {
            ReleaseError::internal("expected release-license package disappeared")
        })?;
        let observed_package = observed_packages.get(id).copied().ok_or_else(|| {
            ReleaseError::internal("observed release-license package disappeared")
        })?;
        for (field, matches) in [
            ("name", expected_package.name == observed_package.name),
            (
                "version",
                expected_package.version == observed_package.version,
            ),
            ("source", expected_package.source == observed_package.source),
            (
                "Cargo.lock checksum",
                expected_package.lock_checksum == observed_package.lock_checksum,
            ),
            (
                "upstream license expression",
                expected_package.license_expression == observed_package.license_expression,
            ),
            (
                "normalized SBOM license expression",
                expected_package.sbom_license_expression
                    == observed_package.sbom_license_expression,
            ),
            (
                "target membership",
                expected_package.targets == observed_package.targets,
            ),
        ] {
            if !matches {
                return Err(ReleaseError::negative(format!(
                    "release-license baseline mismatch for {id}: {field} changed"
                )));
            }
        }
        let expected_files = unique_legal_files(id, &expected_package.legal_files)?;
        let observed_files = unique_legal_files(id, &observed_package.legal_files)?;
        let expected_paths: BTreeSet<_> = expected_files.keys().copied().collect();
        let observed_paths: BTreeSet<_> = observed_files.keys().copied().collect();
        let missing_files: Vec<_> = expected_paths
            .difference(&observed_paths)
            .copied()
            .collect();
        let extra_files: Vec<_> = observed_paths
            .difference(&expected_paths)
            .copied()
            .collect();
        if !missing_files.is_empty() || !extra_files.is_empty() {
            return Err(ReleaseError::negative(format!(
                "release-license legal-file path drift for {id}; missing [{}], extra [{}]",
                missing_files.join(", "),
                extra_files.join(", ")
            )));
        }
        for path in expected_paths {
            let expected_file = expected_files
                .get(path)
                .copied()
                .ok_or_else(|| ReleaseError::internal("expected legal file disappeared"))?;
            let observed_file = observed_files
                .get(path)
                .copied()
                .ok_or_else(|| ReleaseError::internal("observed legal file disappeared"))?;
            if expected_file.sha256 != observed_file.sha256 {
                return Err(ReleaseError::negative(format!(
                    "release-license legal-file SHA-256 changed for {id}:{path}"
                )));
            }
        }
    }
    Ok(())
}

fn unique_license_packages<'a>(
    packages: &'a [ReleaseLicensePackage],
    label: &str,
) -> Result<BTreeMap<&'a str, &'a ReleaseLicensePackage>, ReleaseError> {
    let mut by_id = BTreeMap::new();
    for package in packages {
        if by_id.insert(package.id.as_str(), package).is_some() {
            return Err(ReleaseError::negative(format!(
                "{label} contains duplicate release-license package ID {}",
                package.id
            )));
        }
    }
    Ok(by_id)
}

fn unique_legal_files<'a>(
    package_id: &str,
    files: &'a [ReleaseLegalFile],
) -> Result<BTreeMap<&'a str, &'a ReleaseLegalFile>, ReleaseError> {
    let mut by_path = BTreeMap::new();
    for file in files {
        if by_path.insert(file.path.as_str(), file).is_some() {
            return Err(ReleaseError::negative(format!(
                "release-license package {package_id} contains duplicate legal-file path {}",
                file.path
            )));
        }
    }
    Ok(by_path)
}

fn render_release_license_bundle(
    evidence: &ReleaseLicenseEvidence,
) -> Result<Vec<u8>, ReleaseError> {
    let workspace: Vec<_> = evidence
        .baseline
        .packages
        .iter()
        .filter(|package| package.source == "workspace")
        .collect();
    let registry: Vec<_> = evidence
        .baseline
        .packages
        .iter()
        .filter(|package| package.source != "workspace")
        .collect();
    let first_workspace = workspace.first().copied().ok_or_else(|| {
        ReleaseError::internal("release-license evidence has no workspace package")
    })?;
    if workspace.iter().any(|package| {
        package.license_expression != first_workspace.license_expression
            || package.sbom_license_expression != first_workspace.sbom_license_expression
            || package.legal_files != first_workspace.legal_files
    }) {
        return Err(ReleaseError::negative(
            "Forge workspace packages disagree on the shared project licenses",
        ));
    }
    let mut rendered = String::new();
    rendered.push_str("FORGE LICENSES AND THIRD-PARTY NOTICES\n\n");
    rendered.push_str(
        "Scope: the five-target union selected by the reviewed scoped Cargo tree command.\n",
    );
    rendered.push_str(
        "Development-only dependency edges are excluded. Each native release-build independently\n",
    );
    rendered.push_str(
        "requires its compiler-artifact package set to equal this scoped graph before staging.\n",
    );
    rendered.push_str("Registry package identity comes from Cargo.lock, and each fetched .crate\n");
    rendered.push_str(
        "archive is required to match its Cargo.lock SHA-256. Legal text is separately\n",
    );
    rendered
        .push_str("read from the current Cargo-unpacked source tree; the archive check is not\n");
    rendered.push_str(
        "claimed to prove those unpacked bytes, which are fixed by reviewed per-file SHA-256.\n",
    );
    rendered.push_str(
        "Every detected LICENSE, LICENCE, COPYING, NOTICE, COPYRIGHT, and UNLICENSE file is\n",
    );
    rendered.push_str("reproduced per package.\n\n");
    rendered.push_str(&format!(
        "Packages: {} total ({} workspace, {} registry).\n\n",
        evidence.baseline.packages.len(),
        workspace.len(),
        registry.len()
    ));
    rendered.push_str("== Forge workspace ==\n\nPackage IDs:\n");
    for package in &workspace {
        rendered.push_str("- ");
        rendered.push_str(&package.id);
        rendered.push('\n');
    }
    rendered.push_str("Upstream declared license expression: ");
    rendered.push_str(&first_workspace.license_expression);
    rendered.push('\n');
    rendered.push_str("Normalized SBOM license expression: ");
    rendered.push_str(&first_workspace.sbom_license_expression);
    rendered.push_str("\n\n");
    append_rendered_legal_files(&mut rendered, evidence, first_workspace)?;
    rendered.push_str("== Third-party registry packages ==\n\n");
    for package in registry {
        rendered.push_str("## ");
        rendered.push_str(&package.name);
        rendered.push(' ');
        rendered.push_str(&package.version);
        rendered.push('\n');
        rendered.push_str("Package ID: ");
        rendered.push_str(&package.id);
        rendered.push('\n');
        rendered.push_str("Verified .crate archive SHA-256 (Cargo.lock): ");
        rendered.push_str(package.lock_checksum.as_deref().ok_or_else(|| {
            ReleaseError::internal("registry release-license package omitted lock checksum")
        })?);
        rendered.push('\n');
        rendered.push_str("Upstream declared license expression: ");
        rendered.push_str(&package.license_expression);
        rendered.push('\n');
        rendered.push_str("Normalized SBOM license expression: ");
        rendered.push_str(&package.sbom_license_expression);
        rendered.push('\n');
        rendered.push_str("Release targets: ");
        rendered.push_str(&package.targets.join(", "));
        rendered.push_str("\n\n");
        append_rendered_legal_files(&mut rendered, evidence, package)?;
    }
    while rendered.ends_with("\n\n") {
        rendered.pop();
    }
    if !rendered.ends_with('\n') {
        rendered.push('\n');
    }
    Ok(rendered.into_bytes())
}

fn append_rendered_legal_files(
    rendered: &mut String,
    evidence: &ReleaseLicenseEvidence,
    package: &ReleaseLicensePackage,
) -> Result<(), ReleaseError> {
    let text_by_path = evidence
        .legal_text_by_package
        .get(&package.id)
        .ok_or_else(|| ReleaseError::internal("release-license legal text disappeared"))?;
    for file in &package.legal_files {
        let raw = text_by_path.get(&file.path).ok_or_else(|| {
            ReleaseError::internal("release-license legal-file bytes disappeared")
        })?;
        if sha256_hex(raw) != file.sha256 {
            return Err(ReleaseError::internal(
                "release-license legal-file bytes changed after collection",
            ));
        }
        rendered.push_str("---- ");
        rendered.push_str(&file.path);
        rendered.push_str(" (SHA-256 ");
        rendered.push_str(&file.sha256);
        rendered.push_str(") ----\n");
        rendered.push_str(&normalize_legal_text(raw, &package.id, &file.path)?);
        rendered.push('\n');
    }
    Ok(())
}

fn normalize_legal_text(raw: &[u8], package_id: &str, path: &str) -> Result<String, ReleaseError> {
    let raw = raw.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(raw);
    let text = std::str::from_utf8(raw).map_err(|error| {
        ReleaseError::negative(format!(
            "legal file is not UTF-8: {package_id}:{path}: {error}"
        ))
    })?;
    let mut normalized = text.replace("\r\n", "\n").replace('\r', "\n");
    while normalized.ends_with('\n') {
        normalized.pop();
    }
    normalized.push('\n');
    Ok(normalized)
}

fn require_portable_release_license_output(label: &str, bytes: &[u8]) -> Result<(), ReleaseError> {
    let text = std::str::from_utf8(bytes).map_err(|error| {
        ReleaseError::internal(format!("generated {label} is not UTF-8: {error}"))
    })?;
    if bytes.contains(&b'\r')
        || !bytes.ends_with(b"\n")
        || (label == LICENSE_NOTICES_FILE && bytes.ends_with(b"\n\n"))
    {
        return Err(ReleaseError::internal(format!(
            "generated {label} is not canonical LF-terminated UTF-8"
        )));
    }
    for forbidden in [
        "/Users/",
        "/home/",
        "/private/tmp/",
        "/tmp/",
        "registry/src",
        "registry/cache",
        "registry\\src",
        "registry\\cache",
        "file:///",
    ] {
        if text.contains(forbidden) {
            return Err(ReleaseError::internal(format!(
                "generated {label} contains a machine-local path"
            )));
        }
    }
    if bytes
        .windows(3)
        .any(|window| window[0].is_ascii_alphabetic() && window[1] == b':' && window[2] == b'\\')
    {
        return Err(ReleaseError::internal(format!(
            "generated {label} contains a Windows absolute path"
        )));
    }
    if contains_rfc3339_timestamp(bytes) {
        return Err(ReleaseError::internal(format!(
            "generated {label} contains a generated timestamp"
        )));
    }
    Ok(())
}

fn contains_rfc3339_timestamp(bytes: &[u8]) -> bool {
    bytes.windows(11).any(|window| {
        window[0..4].iter().all(u8::is_ascii_digit)
            && window[4] == b'-'
            && window[5..7].iter().all(u8::is_ascii_digit)
            && window[7] == b'-'
            && window[8..10].iter().all(u8::is_ascii_digit)
            && window[10] == b'T'
    })
}

fn render_manifest(
    output: &RepositoryWriter,
    license_notices: &[u8],
) -> Result<Vec<u8>, ReleaseError> {
    let mut artifacts = Vec::with_capacity(RELEASE_TARGETS.len() * 2 + 1);
    for target in &RELEASE_TARGETS {
        for (name, kind) in [
            (binary_asset_name(target), ReleaseArtifactKindV2Data::Binary),
            (
                sbom_asset_name(target),
                ReleaseArtifactKindV2Data::CyclonedxSbom,
            ),
        ] {
            let bytes = read_output_required(output, &name, MAX_BINARY_BYTES, "release artifact")?;
            artifacts.push(ReleaseArtifactV2Data {
                name,
                kind,
                target: target.triple.to_owned(),
                length: bytes.len() as u64,
                sha256: ReleaseSha256Data::new(sha256_hex(&bytes)).map_err(|error| {
                    ReleaseError::internal(format!("generated invalid SHA-256 digest: {error}"))
                })?,
            });
        }
    }
    artifacts.push(ReleaseArtifactV2Data {
        name: LICENSE_NOTICES_FILE.to_owned(),
        kind: ReleaseArtifactKindV2Data::LicenseNotices,
        target: "all".to_owned(),
        length: license_notices.len() as u64,
        sha256: ReleaseSha256Data::new(sha256_hex(license_notices)).map_err(|error| {
            ReleaseError::internal(format!("generated invalid SHA-256 digest: {error}"))
        })?,
    });
    artifacts.sort_by(|left, right| left.name.cmp(&right.name));
    let subjects: Vec<_> = finalized_asset_names().into_iter().collect();
    if subjects.len() != usize::from(FINALIZED_ASSET_COUNT) {
        return Err(ReleaseError::internal(format!(
            "release subject allowlist has {} names, expected {FINALIZED_ASSET_COUNT}",
            subjects.len()
        )));
    }
    let artifacts: [ReleaseArtifactV2Data; 11] =
        artifacts.try_into().map_err(|artifacts: Vec<_>| {
            ReleaseError::internal(format!(
                "release artifact allowlist has {} entries, expected 11",
                artifacts.len()
            ))
        })?;
    let subjects: [String; 13] = subjects.try_into().map_err(|subjects: Vec<_>| {
        ReleaseError::internal(format!(
            "release subject allowlist has {} entries, expected 13",
            subjects.len()
        ))
    })?;
    to_pretty_json(
        &ReleaseManifestV2Data {
            schema: SchemaKind::ReleaseManifest.id(),
            release: ReleaseDescriptorData {
                version: RELEASE_VERSION.to_owned(),
                channel: ReleaseChannelData::ReleaseCandidate,
                distribution: ReleaseDistributionData::GithubRelease,
                status: ReleaseCandidateStatusData::LocalReviewCandidate,
            },
            artifacts,
            provenance: ReleaseProvenanceV2Data {
                status: ReleaseProvenanceStatusData::RequiredExternal,
                predicate_type: ReleasePredicateTypeData::SlsaProvenanceV1,
                signing: ReleaseSigningData::SigstoreKeylessOidc,
                authority_status: ReleaseAuthorityStatusData::UnassignedExternal,
                subject_set: ReleaseSubjectSetData::ExactFinalizedLocalAssets,
                subjects,
            },
            rollback: ReleaseRollbackData {
                retain_published_releases: 2,
                previous_release: None,
                status: ReleaseRollbackStatusData::FirstCandidateNoNMinusOne,
            },
        },
        "release manifest",
    )
}

fn render_checksums(
    output: &RepositoryWriter,
    license_notices: &[u8],
    manifest: &[u8],
) -> Result<Vec<u8>, ReleaseError> {
    let mut entries = Vec::with_capacity(RELEASE_TARGETS.len() * 2 + 2);
    for name in manifest_artifact_names() {
        let digest = if name == LICENSE_NOTICES_FILE {
            sha256_hex(license_notices)
        } else {
            let bytes = read_output_required(
                output,
                &name,
                MAX_BINARY_BYTES,
                "checksummed release artifact",
            )?;
            sha256_hex(&bytes)
        };
        entries.push((name, digest));
    }
    entries.push((MANIFEST_FILE.to_owned(), sha256_hex(manifest)));
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let mut rendered = String::new();
    for (name, digest) in entries {
        rendered.push_str(&digest);
        rendered.push_str("  ");
        rendered.push_str(&name);
        rendered.push('\n');
    }
    Ok(rendered.into_bytes())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn to_pretty_json<T: Serialize>(value: &T, label: &str) -> Result<Vec<u8>, ReleaseError> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| ReleaseError::internal(format!("failed to serialize {label}: {error}")))?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::ffi::{OsStr, OsString};
    use std::fs;
    use std::io::Write as _;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::Duration;

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use forge_core::ports::EnvPolicy;
    use forge_core::{Mutability, NetworkIntent};
    use tempfile::{TempDir, tempdir};

    use super::{
        BUILD_INPUT_OBSERVATION_PREFIX, BuildInputObservationOutput, CHECKSUMS_FILE,
        LICENSE_NOTICES_FILE, MANIFEST_FILE, PreparedCargoInvocation, RELEASE_TARGETS,
        ReleaseError, ReleaseErrorKind, RepositorySnapshot, WorktreeGuard, binary_asset_name,
        build_input_observation, check, encode_windows_utf16_input, finalize,
        finalized_asset_names, known_stage_names, local_release_build_arguments,
        parse_build_request, release_build_completed_message, render_sbom,
        require_disjoint_output_roots, sbom_asset_name, sha256_hex, stage_built,
        validate_binary_format, write_build_input_observation,
    };

    const METADATA: &str = r#"{
      "packages": [
        {"id":"path+file:///repo/crates/forge-cli#0.1.0-rc.2","name":"forge-cli","version":"0.1.0-rc.2","license":"MIT OR Apache-2.0","source":null,"manifest_path":"/repo/crates/forge-cli/Cargo.toml"},
        {"id":"registry+https://github.com/rust-lang/crates.io-index#serde@1.0.229","name":"serde","version":"1.0.229","license":"MIT OR Apache-2.0","source":"registry+https://github.com/rust-lang/crates.io-index"},
        {"id":"registry+https://github.com/rust-lang/crates.io-index#build-helper@1.2.3","name":"build-helper","version":"1.2.3","license":"Apache-2.0 OR MIT","source":"registry+https://github.com/rust-lang/crates.io-index"},
        {"id":"registry+https://github.com/rust-lang/crates.io-index#test-only@4.5.6","name":"test-only","version":"4.5.6","license":"MIT","source":"registry+https://github.com/rust-lang/crates.io-index"}
      ],
      "workspace_members": ["path+file:///repo/crates/forge-cli#0.1.0-rc.2"],
      "resolve": {"nodes": [
        {"id":"path+file:///repo/crates/forge-cli#0.1.0-rc.2","deps":[
          {"pkg":"registry+https://github.com/rust-lang/crates.io-index#serde@1.0.229","dep_kinds":[{"kind":null,"target":null}]},
          {"pkg":"registry+https://github.com/rust-lang/crates.io-index#build-helper@1.2.3","dep_kinds":[{"kind":"build","target":null}]},
          {"pkg":"registry+https://github.com/rust-lang/crates.io-index#test-only@4.5.6","dep_kinds":[{"kind":"dev","target":null}]}
        ]},
        {"id":"registry+https://github.com/rust-lang/crates.io-index#serde@1.0.229","deps":[]},
        {"id":"registry+https://github.com/rust-lang/crates.io-index#build-helper@1.2.3","deps":[]},
        {"id":"registry+https://github.com/rust-lang/crates.io-index#test-only@4.5.6","deps":[]}
      ]}
    }"#;
    const TREE: &str = "0@@forge-cli v0.1.0-rc.2 (/repo/crates/forge-cli)@@\n1@@serde v1.0.229@@\n1@@build-helper v1.2.3@@\n";
    const CARGO_LOCK: &str = concat!(
        "version = 4\n\n",
        "[[package]]\nname = \"forge-cli\"\nversion = \"0.1.0-rc.2\"\n\n",
        "[[package]]\nname = \"serde\"\nversion = \"1.0.229\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"dafc30efc5f0fda1a660d7c0b0b3e2b8ddf0d7b3f05803e9f4b206f50807fd8c\"\n\n",
        "[[package]]\nname = \"build-helper\"\nversion = \"1.2.3\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"\n",
    );
    const BUILD_MESSAGES: &str = concat!(
        "{\"reason\":\"compiler-artifact\",\"package_id\":\"registry+https://github.com/rust-lang/crates.io-index#serde@1.0.229\"}\n",
        "{\"reason\":\"build-script-executed\",\"package_id\":\"registry+https://github.com/rust-lang/crates.io-index#build-helper@1.2.3\"}\n",
        "{\"reason\":\"compiler-artifact\",\"package_id\":\"registry+https://github.com/rust-lang/crates.io-index#build-helper@1.2.3\"}\n",
        "{\"reason\":\"compiler-message\",\"package_id\":\"path+file:///repo/crates/forge-cli#0.1.0-rc.2\"}\n",
        "{\"reason\":\"compiler-artifact\",\"package_id\":\"path+file:///repo/crates/forge-cli#0.1.0-rc.2\"}\n",
        "{\"reason\":\"build-finished\",\"success\":true}\n",
    );

    fn prepared_test_cargo_invocation(environment: EnvPolicy) -> PreparedCargoInvocation {
        PreparedCargoInvocation {
            program: OsString::from("cargo-program-sentinel"),
            arguments: vec![
                OsString::from("build-argument-sentinel"),
                OsString::from("--locked"),
            ],
            working_directory: PathBuf::from("/working-directory-sentinel"),
            environment,
        }
    }

    #[cfg(unix)]
    fn assert_native_string_equals(
        actual: &forge_schema::ReleaseBuildInputNativeStringData,
        expected: &OsStr,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::ffi::OsStrExt as _;

        let forge_schema::ReleaseBuildInputNativeStringData::UnixBytes { raw_base64 } = actual
        else {
            return Err("Unix invocation value did not use Unix-native encoding".into());
        };
        assert_eq!(STANDARD.decode(raw_base64.as_str())?, expected.as_bytes());
        Ok(())
    }

    #[cfg(windows)]
    fn assert_native_string_equals(
        actual: &forge_schema::ReleaseBuildInputNativeStringData,
        expected: &OsStr,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use std::os::windows::ffi::OsStrExt as _;

        let forge_schema::ReleaseBuildInputNativeStringData::WindowsWide { raw_base64 } = actual
        else {
            return Err("Windows invocation value did not use Windows-native encoding".into());
        };
        let expected = expected
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        assert_eq!(STANDARD.decode(raw_base64.as_str())?, expected);
        Ok(())
    }

    #[test]
    fn release_build_request_keeps_observation_explicit_and_optional() -> Result<(), ReleaseError> {
        let default = parse_build_request(&[
            String::from("--target"),
            String::from("x86_64-unknown-linux-musl"),
            String::from("--output-dir"),
            String::from("/candidate"),
        ])?;
        assert_eq!(default.target, &RELEASE_TARGETS[0]);
        assert_eq!(default.output_directory, PathBuf::from("/candidate"));
        assert_eq!(default.build_input_observation_directory, None);

        let observed = parse_build_request(&[
            String::from("--build-input-observation-dir"),
            String::from("/private-observation"),
            String::from("--output-dir"),
            String::from("/candidate"),
            String::from("--target"),
            String::from("x86_64-pc-windows-msvc"),
        ])?;
        assert_eq!(observed.target, &RELEASE_TARGETS[4]);
        assert_eq!(
            observed.build_input_observation_directory,
            Some(PathBuf::from("/private-observation"))
        );

        let duplicate = parse_build_request(&[
            String::from("--target"),
            String::from("x86_64-unknown-linux-musl"),
            String::from("--output-dir"),
            String::from("/candidate"),
            String::from("--build-input-observation-dir"),
            String::from("/first"),
            String::from("--build-input-observation-dir"),
            String::from("/second"),
        ]);
        let Err(duplicate) = duplicate else {
            return Err(ReleaseError::internal(
                "duplicate observation destinations were accepted",
            ));
        };
        assert_eq!(duplicate.kind(), ReleaseErrorKind::Usage);
        Ok(())
    }

    #[test]
    fn observation_binds_the_exact_prepared_invocation_before_consumption()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut environment = EnvPolicy::minimal();
        environment
            .overrides
            .insert(OsString::from("BOUND_INPUT"), OsString::from("exact-value"));
        let invocation = prepared_test_cargo_invocation(environment);
        let document = build_input_observation(&"a".repeat(40), &RELEASE_TARGETS[0], &invocation)?;
        assert_native_string_equals(
            &document.cargo_command.program,
            OsStr::new("cargo-program-sentinel"),
        )?;
        assert_eq!(document.cargo_command.arguments.len(), 2);
        assert_native_string_equals(
            &document.cargo_command.arguments[0],
            OsStr::new("build-argument-sentinel"),
        )?;
        assert_native_string_equals(
            &document.cargo_command.working_directory,
            OsStr::new("/working-directory-sentinel"),
        )?;

        let PreparedCargoInvocation {
            program,
            arguments,
            working_directory,
            environment,
        } = invocation;
        assert_eq!(program, OsString::from("cargo-program-sentinel"));
        assert_eq!(arguments[0], OsString::from("build-argument-sentinel"));
        assert_eq!(
            working_directory,
            PathBuf::from("/working-directory-sentinel")
        );
        assert_eq!(
            environment.overrides.get(OsStr::new("BOUND_INPUT")),
            Some(&OsString::from("exact-value"))
        );
        Ok(())
    }

    #[test]
    fn windows_input_encoding_preserves_every_utf16_code_unit()
    -> Result<(), Box<dyn std::error::Error>> {
        let value = encode_windows_utf16_input([0x0041, 0xd800, 0x0042])?;
        assert_eq!(
            STANDARD.decode(value.raw_base64.as_str())?,
            [0x41, 0x00, 0x00, 0xd8, 0x42, 0x00]
        );
        for invalid in [Vec::new(), vec![0], vec![1; 32_767]] {
            assert!(encode_windows_utf16_input(invalid).is_err());
        }
        Ok(())
    }

    #[cfg(not(all(windows, target_env = "msvc")))]
    #[test]
    fn non_windows_observation_never_guesses_msvc_values() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut environment = EnvPolicy::minimal();
        for name in ["PATH", "LIB", "INCLUDE"] {
            environment.overrides.insert(
                OsString::from(name),
                OsString::from("private-path-sentinel"),
            );
        }
        let invocation = prepared_test_cargo_invocation(environment);
        let document = build_input_observation(&"a".repeat(40), &RELEASE_TARGETS[4], &invocation)?;
        let rendered = serde_json::to_string(&document)?;
        assert!(rendered.contains("\"status\":\"not-applicable\""));
        assert!(rendered.contains("diagnostic-only-not-release-evidence"));
        assert!(!rendered.contains("private-path-sentinel"));
        Ok(())
    }

    #[cfg(all(windows, target_env = "msvc"))]
    #[test]
    fn windows_observation_reads_the_prepared_policy_losslessly()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut environment = EnvPolicy::minimal();
        for (name, value) in [
            ("PATH", "prepared-path"),
            ("LIB", "prepared-lib"),
            ("INCLUDE", "prepared-include"),
        ] {
            environment
                .overrides
                .insert(OsString::from(name), OsString::from(value));
        }
        let invocation = prepared_test_cargo_invocation(environment);
        let document = build_input_observation(&"a".repeat(40), &RELEASE_TARGETS[4], &invocation)?;
        let forge_schema::ReleaseBuildInputWindowsMsvcEnvironmentData::Observed {
            path,
            lib,
            include,
        } = document.windows_msvc_environment
        else {
            return Err("Windows MSVC observation omitted the prepared values".into());
        };
        for (actual, expected) in [
            (path, "prepared-path"),
            (lib, "prepared-lib"),
            (include, "prepared-include"),
        ] {
            let expected = expected
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>();
            assert_eq!(STANDARD.decode(actual.raw_base64.as_str())?, expected);
        }
        Ok(())
    }

    #[test]
    fn build_input_observation_is_private_create_only_and_outside_release_assets()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempdir()?;
        let observation_directory = temporary.path().join("observation");
        fs::create_dir(&observation_directory)?;
        let writer = forge_runtime::fs::RepositoryWriter::new(&observation_directory)?;
        let file_name = format!(
            "{BUILD_INPUT_OBSERVATION_PREFIX}{}.json",
            RELEASE_TARGETS[0].triple
        );
        let output = BuildInputObservationOutput {
            writer,
            file_name: file_name.clone(),
        };
        let invocation = prepared_test_cargo_invocation(EnvPolicy::minimal());
        write_build_input_observation(&output, &"a".repeat(40), &RELEASE_TARGETS[0], &invocation)?;
        let first = output.writer.read_bounded(&file_name, 512 * 1024)?;
        assert!(
            write_build_input_observation(
                &output,
                &"b".repeat(40),
                &RELEASE_TARGETS[0],
                &invocation,
            )
            .is_err()
        );
        assert_eq!(output.writer.read_bounded(&file_name, 512 * 1024)?, first);
        assert!(
            known_stage_names()
                .iter()
                .all(|name| !name.starts_with(BUILD_INPUT_OBSERVATION_PREFIX))
        );
        assert!(
            finalized_asset_names()
                .iter()
                .all(|name| !name.starts_with(BUILD_INPUT_OBSERVATION_PREFIX))
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            assert_eq!(
                fs::metadata(observation_directory.join(file_name))?
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        Ok(())
    }

    #[test]
    fn release_and_observation_roots_must_be_disjoint() {
        let root = PathBuf::from("/tmp/forge-release-root-test");
        assert!(require_disjoint_output_roots(&root, &root).is_err());
        assert!(require_disjoint_output_roots(&root, &root.join("observation")).is_err());
        assert!(require_disjoint_output_roots(&root.join("candidate"), &root).is_err());
        assert!(
            require_disjoint_output_roots(&root.join("candidate"), &root.join("observation"))
                .is_ok()
        );
    }

    #[test]
    fn release_cargo_preparation_preserves_linker_authority_and_offline_policy()
    -> Result<(), ReleaseError> {
        let repository = tempdir().map_err(|error| ReleaseError::internal(error.to_string()))?;
        let environment = super::prepared_release_cargo_environment(
            repository.path(),
            crate::cargo_env::CargoNetworkMode::Offline,
            crate::cargo_env::CargoCompilationTarget::Target("x86_64-pc-windows-gnu"),
            "release Cargo environment test",
        )?;

        assert_eq!(
            environment
                .overrides
                .get(std::ffi::OsStr::new("CARGO_NET_OFFLINE")),
            Some(&OsString::from("true"))
        );
        assert_eq!(
            environment
                .overrides
                .get(std::ffi::OsStr::new("RUSTUP_AUTO_INSTALL")),
            Some(&OsString::from("0"))
        );
        assert!(!environment.overrides.contains_key(std::ffi::OsStr::new(
            "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER"
        )));
        Ok(())
    }

    #[test]
    fn sha256_uses_the_standard_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn source_snapshot_rejects_repository_redirect_environment() {
        for key in ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"] {
            assert!(
                super::reject_git_redirect_environment([OsString::from(key)]).is_err(),
                "{key} must not redirect the source snapshot"
            );
        }
        assert!(super::reject_git_redirect_environment([OsString::from("PATH")]).is_ok());
    }

    #[test]
    fn source_snapshot_rejects_an_untracked_file() -> Result<(), ReleaseError> {
        let temporary = tempdir().map_err(|error| ReleaseError::internal(error.to_string()))?;
        let repository = temporary.path().join("repository");
        fs::create_dir(&repository).map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::write(repository.join("tracked.txt"), b"tracked")
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        run_git(&repository, &["init"])?;
        run_git(&repository, &["add", "tracked.txt"])?;
        run_git(
            &repository,
            &[
                "-c",
                "user.name=Forge Test",
                "-c",
                "user.email=forge-test@example.invalid",
                "commit",
                "-m",
                "fixture",
            ],
        )?;
        fs::write(repository.join("untracked.txt"), b"dirty")
            .map_err(|error| ReleaseError::internal(error.to_string()))?;

        assert!(WorktreeGuard::capture(&repository).is_err());
        Ok(())
    }

    #[test]
    fn source_snapshot_rejects_hidden_index_flags() -> Result<(), ReleaseError> {
        let temporary = tempdir().map_err(|error| ReleaseError::internal(error.to_string()))?;
        let repository = temporary.path().join("repository");
        fs::create_dir(&repository).map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::write(repository.join("tracked.txt"), b"tracked")
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        run_git(&repository, &["init"])?;
        run_git(&repository, &["add", "tracked.txt"])?;
        run_git(
            &repository,
            &[
                "-c",
                "user.name=Forge Test",
                "-c",
                "user.email=forge-test@example.invalid",
                "commit",
                "-m",
                "fixture",
            ],
        )?;
        let head = super::git_head(&repository)?;

        run_git(
            &repository,
            &["update-index", "--assume-unchanged", "tracked.txt"],
        )?;
        assert!(super::git_index_snapshot(&repository, &head).is_err());
        run_git(
            &repository,
            &["update-index", "--no-assume-unchanged", "tracked.txt"],
        )?;
        run_git(
            &repository,
            &["update-index", "--skip-worktree", "tracked.txt"],
        )?;
        assert!(super::git_index_snapshot(&repository, &head).is_err());
        Ok(())
    }

    #[test]
    fn isolated_checkout_uses_committed_bytes_and_excludes_ignored_inputs()
    -> Result<(), ReleaseError> {
        let temporary = tempdir().map_err(|error| ReleaseError::internal(error.to_string()))?;
        let repository = temporary.path().join("repository");
        fs::create_dir(&repository).map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::write(repository.join(".gitignore"), b"ignored-input\n")
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::write(repository.join("tracked.txt"), b"committed")
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        run_git(&repository, &["init"])?;
        run_git(&repository, &["add", ".gitignore", "tracked.txt"])?;
        run_git(
            &repository,
            &[
                "-c",
                "user.name=Forge Test",
                "-c",
                "user.email=forge-test@example.invalid",
                "commit",
                "-m",
                "fixture",
            ],
        )?;
        let head = super::git_head(&repository)?;
        run_git(
            &repository,
            &["update-index", "--assume-unchanged", "tracked.txt"],
        )?;
        fs::write(repository.join("tracked.txt"), b"hidden worktree bytes")
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::write(repository.join("ignored-input"), b"ignored build input")
            .map_err(|error| ReleaseError::internal(error.to_string()))?;

        let (checkout_directory, checkout) =
            super::materialize_isolated_checkout(&repository, &head, &[])?;
        assert_eq!(
            fs::read(checkout.join("tracked.txt"))
                .map_err(|error| ReleaseError::internal(error.to_string()))?,
            b"committed"
        );
        assert!(!checkout.join("ignored-input").exists());
        super::require_no_non_index_files(&checkout)?;
        super::detach_isolated_git_control(&checkout_directory, &checkout)?;
        assert!(!checkout.join(".git").exists());
        assert!(run_git(&checkout, &["rev-parse", "--git-dir"]).is_err());

        let writer = forge_runtime::fs::RepositoryWriter::new(&checkout)
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        let baseline = super::capture_source_tree(&writer)?;
        fs::write(checkout.join("ignored-input"), b"late ignored input")
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        assert_ne!(super::capture_source_tree(&writer)?, baseline);
        fs::remove_file(checkout.join("ignored-input"))
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::create_dir(checkout.join("empty-untracked-directory"))
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        assert_ne!(super::capture_source_tree(&writer)?, baseline);
        Ok(())
    }

    #[test]
    fn isolated_checkout_rejects_git_attribute_byte_transforms() -> Result<(), ReleaseError> {
        let temporary = tempdir().map_err(|error| ReleaseError::internal(error.to_string()))?;
        let repository = temporary.path().join("repository");
        fs::create_dir(&repository).map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::write(
            repository.join(".gitattributes"),
            b"tracked.txt text eol=crlf\n",
        )
        .map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::write(repository.join("tracked.txt"), b"line one\nline two\n")
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        run_git(&repository, &["init"])?;
        run_git(&repository, &["add", ".gitattributes", "tracked.txt"])?;
        run_git(
            &repository,
            &[
                "-c",
                "user.name=Forge Test",
                "-c",
                "user.email=forge-test@example.invalid",
                "commit",
                "-m",
                "fixture",
            ],
        )?;
        let head = super::git_head(&repository)?;

        let error = super::materialize_isolated_checkout(&repository, &head, &[])
            .err()
            .ok_or_else(|| {
                ReleaseError::internal(
                    "attribute-transformed checkout unexpectedly passed exact-byte verification",
                )
            })?;
        assert!(
            error
                .to_string()
                .contains("do not match the exact commit blob")
        );
        Ok(())
    }

    #[test]
    fn isolated_temp_root_rejects_repository_and_output_descendants() -> Result<(), ReleaseError> {
        let temporary = tempdir().map_err(|error| ReleaseError::internal(error.to_string()))?;
        let repository = temporary.path().join("repository");
        let output = temporary.path().join("output");
        let repository_temp = repository.join("target/release-source");
        let output_temp = output.join("release-source");
        fs::create_dir_all(&repository_temp)
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::create_dir_all(&output_temp)
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        run_git(&repository, &["init"])?;

        assert!(super::require_isolated_temp_boundary(&repository, &repository_temp, &[]).is_err());
        assert!(
            super::require_isolated_temp_boundary(&repository, &output_temp, &[output.as_path()])
                .is_err()
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn isolated_checkout_rejects_ambient_temp_root_inside_repository() -> Result<(), ReleaseError> {
        let temporary = tempdir().map_err(|error| ReleaseError::internal(error.to_string()))?;
        let repository = temporary.path().join("repository");
        let ambient_temp = repository.join("target");
        fs::create_dir_all(&ambient_temp)
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::write(repository.join("tracked.txt"), b"tracked")
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        run_git(&repository, &["init"])?;
        run_git(&repository, &["add", "tracked.txt"])?;
        run_git(
            &repository,
            &[
                "-c",
                "user.name=Forge Test",
                "-c",
                "user.email=forge-test@example.invalid",
                "commit",
                "-m",
                "fixture",
            ],
        )?;

        let output = Command::new(
            env::current_exe().map_err(|error| ReleaseError::internal(error.to_string()))?,
        )
        .args([
            "--exact",
            "release::tests::bounded_release_process_test_helper",
            "--nocapture",
        ])
        .env("FORGE_RELEASE_PROCESS_TEST", "repository-temp-boundary")
        .env("FORGE_RELEASE_TEST_REPOSITORY", &repository)
        .env("TMPDIR", &ambient_temp)
        .output()
        .map_err(|error| ReleaseError::internal(error.to_string()))?;
        assert!(
            output.status.success(),
            "temp-boundary child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }

    #[test]
    fn source_directory_enumeration_rejects_the_next_entry_before_collecting_it()
    -> Result<(), ReleaseError> {
        let temporary = tempdir().map_err(|error| ReleaseError::internal(error.to_string()))?;
        for name in ["a", "b", "c"] {
            fs::write(temporary.path().join(name), b"")
                .map_err(|error| ReleaseError::internal(error.to_string()))?;
        }

        assert!(super::read_bounded_source_directory_entries(temporary.path(), 0, 2).is_err());
        assert_eq!(
            super::read_bounded_source_directory_entries(temporary.path(), 0, 3)?.len(),
            3
        );
        Ok(())
    }

    #[test]
    fn cargo_configuration_guard_rejects_a_temporary_ancestor_config() -> Result<(), ReleaseError> {
        let temporary = tempdir().map_err(|error| ReleaseError::internal(error.to_string()))?;
        let source = temporary.path().join("temporary-root/source");
        let config = temporary.path().join(".cargo/config.toml");
        fs::create_dir_all(&source).map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::create_dir_all(
            config
                .parent()
                .ok_or_else(|| ReleaseError::internal("temporary Cargo config had no parent"))?,
        )
        .map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::write(&config, b"[build]\nrustc-wrapper = \"false\"\n")
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        let canonical_config =
            fs::canonicalize(&config).map_err(|error| ReleaseError::internal(error.to_string()))?;

        let error = super::require_no_external_cargo_configuration(&source)
            .err()
            .ok_or_else(|| {
                ReleaseError::internal("external Cargo configuration was unexpectedly accepted")
            })?;
        assert_eq!(error.kind(), ReleaseErrorKind::Environment);
        assert!(
            error
                .to_string()
                .contains(&canonical_config.display().to_string())
        );
        Ok(())
    }

    #[test]
    fn source_snapshot_rejects_executable_local_git_configuration() -> Result<(), ReleaseError> {
        let temporary = tempdir().map_err(|error| ReleaseError::internal(error.to_string()))?;
        let repository = temporary.path().join("repository");
        let linked = temporary.path().join("linked");
        fs::create_dir(&repository).map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::write(repository.join("tracked.txt"), b"tracked")
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        run_git(&repository, &["init"])?;
        run_git(&repository, &["add", "tracked.txt"])?;
        run_git(
            &repository,
            &[
                "-c",
                "user.name=Forge Test",
                "-c",
                "user.email=forge-test@example.invalid",
                "commit",
                "-m",
                "fixture",
            ],
        )?;
        run_git(
            &repository,
            &["config", "filter.release-test.clean", "false"],
        )?;
        assert!(super::require_safe_local_git_config(&repository).is_err());
        run_git(
            &repository,
            &["config", "--unset", "filter.release-test.clean"],
        )?;

        run_git(
            &repository,
            &["config", "extensions.worktreeConfig", "true"],
        )?;
        let linked_argument = linked.to_str().ok_or_else(|| {
            ReleaseError::internal("temporary linked worktree path was not UTF-8")
        })?;
        run_git(
            &repository,
            &["worktree", "add", "--detach", linked_argument],
        )?;
        run_git(
            &linked,
            &["config", "--worktree", "filter.release-test.clean", "false"],
        )?;
        assert!(super::require_safe_local_git_config(&linked).is_err());
        Ok(())
    }

    #[test]
    fn raw_index_snapshot_rejects_locks_and_split_indexes() -> Result<(), ReleaseError> {
        let temporary = tempdir().map_err(|error| ReleaseError::internal(error.to_string()))?;
        let repository = temporary.path().join("repository");
        fs::create_dir(&repository).map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::write(repository.join("tracked.txt"), b"tracked")
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        run_git(&repository, &["init"])?;
        run_git(&repository, &["add", "tracked.txt"])?;

        let lock = repository.join(".git").join("index.lock");
        fs::write(&lock, b"lock").map_err(|error| ReleaseError::internal(error.to_string()))?;
        assert!(super::git_raw_index_snapshot(&repository).is_err());
        fs::remove_file(&lock).map_err(|error| ReleaseError::internal(error.to_string()))?;

        run_git(&repository, &["update-index", "--split-index"])?;
        assert!(super::git_raw_index_snapshot(&repository).is_err());
        Ok(())
    }

    #[test]
    fn release_source_runs_cargo_only_in_the_detached_commit_checkout() -> Result<(), ReleaseError>
    {
        let (temporary, repository) = minimal_release_repository()?;

        fs::create_dir(repository.join(".cargo"))
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::write(
            repository.join(".cargo/config.toml"),
            b"[build]\nrustc-wrapper = \"/definitely-not-a-real-wrapper\"\n",
        )
        .map_err(|error| ReleaseError::internal(error.to_string()))?;

        let source = super::ReleaseSource::prepare(&repository, &RELEASE_TARGETS[..1], &[])?;
        assert!(!source.repository().join(".git").exists());
        assert!(!source.repository().join(".cargo/config.toml").exists());
        source.require_unchanged(&RELEASE_TARGETS[..1], "test verification")?;

        let target = &RELEASE_TARGETS[0];
        let metadata: serde_json::Value =
            serde_json::from_slice(source.snapshot().metadata(target)?)
                .map_err(|error| ReleaseError::internal(error.to_string()))?;
        let outside_source = temporary.path().join("outside.rs");
        fs::write(&outside_source, b"fn outside() {}\n")
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        let validate = |value: serde_json::Value| -> Result<(), ReleaseError> {
            let bytes = serde_json::to_vec(&value)
                .map_err(|error| ReleaseError::internal(error.to_string()))?;
            super::validate_cargo_metadata_source_boundaries(
                source.repository(),
                std::slice::from_ref(target),
                &std::collections::BTreeMap::from([(target.triple.to_owned(), bytes)]),
                &source.source_tree,
            )
        };

        let mut escaped_workspace = metadata.clone();
        escaped_workspace["workspace_root"] = serde_json::json!(temporary.path().to_string_lossy());
        assert!(validate(escaped_workspace).is_err());

        let mut escaped_manifest = metadata.clone();
        escaped_manifest["packages"][0]["manifest_path"] =
            serde_json::json!(outside_source.to_string_lossy());
        assert!(validate(escaped_manifest).is_err());

        let mut escaped_target = metadata.clone();
        escaped_target["packages"][0]["targets"][0]["src_path"] =
            serde_json::json!(outside_source.to_string_lossy());
        assert!(validate(escaped_target).is_err());

        let mut external_path_dependency = metadata;
        external_path_dependency["packages"]
            .as_array_mut()
            .ok_or_else(|| ReleaseError::internal("metadata packages were not an array"))?
            .push(serde_json::json!({
                "id": "path+file:///outside#external@0.1.0",
                "name": "external",
                "version": "0.1.0",
                "source": null,
                "checksum": null,
                "manifest_path": outside_source,
                "targets": [{"src_path": outside_source}],
            }));
        assert!(validate(external_path_dependency).is_err());
        Ok(())
    }

    #[test]
    fn release_source_rejects_an_original_head_change_after_prepare() -> Result<(), ReleaseError> {
        let (_temporary, repository) = minimal_release_repository()?;
        let source = super::ReleaseSource::prepare(&repository, &RELEASE_TARGETS[..1], &[])?;

        run_git(
            &repository,
            &[
                "-c",
                "user.name=Forge Test",
                "-c",
                "user.email=forge-test@example.invalid",
                "commit",
                "--allow-empty",
                "-m",
                "advance HEAD",
            ],
        )?;

        match source.require_unchanged(&RELEASE_TARGETS[..1], "test verification") {
            Err(error) => {
                assert_eq!(error.kind(), ReleaseErrorKind::Environment);
                assert!(
                    error.to_string().contains(
                        "repository HEAD, complete Git status, semantic or raw Git index, or Cargo.lock changed during test verification"
                    ),
                    "{error}"
                );
            }
            Ok(()) => {
                return Err(ReleaseError::internal(
                    "release source accepted an original repository HEAD change",
                ));
            }
        }
        Ok(())
    }

    #[test]
    fn release_source_rejects_detached_source_and_lock_changes_after_prepare()
    -> Result<(), ReleaseError> {
        for (relative, replacement) in [
            (
                "forge-cli/src/main.rs",
                b"fn main() { println!(\"changed\"); }\n".as_slice(),
            ),
            (
                "Cargo.lock",
                b"# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n\n[[package]]\nname = \"forge-cli\"\nversion = \"0.1.0-rc.2\"\n# changed\n"
                    .as_slice(),
            ),
        ] {
            let (_temporary, repository) = minimal_release_repository()?;
            let source =
                super::ReleaseSource::prepare(&repository, &RELEASE_TARGETS[..1], &[])?;
            fs::write(source.repository().join(relative), replacement)
                .map_err(|error| ReleaseError::internal(error.to_string()))?;

            match source.require_unchanged(&RELEASE_TARGETS[..1], "test verification") {
                Err(error) => {
                    assert_eq!(error.kind(), ReleaseErrorKind::Environment, "{relative}");
                    assert!(
                        error.to_string().contains(
                            "detached isolated source tree changed during test verification"
                        ),
                        "{relative}: {error}"
                    );
                }
                Ok(()) => {
                    return Err(ReleaseError::internal(format!(
                        "release source accepted detached checkout change to {relative}"
                    )));
                }
            }
        }
        Ok(())
    }

    #[test]
    fn source_snapshot_binds_the_requested_worktree_despite_local_git_redirects()
    -> Result<(), ReleaseError> {
        let temporary = tempdir().map_err(|error| ReleaseError::internal(error.to_string()))?;
        let repository = temporary.path().join("repository");
        let alternate = temporary.path().join("alternate");
        fs::create_dir(&repository).map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::create_dir(&alternate).map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::write(repository.join("tracked.txt"), b"tracked")
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::write(alternate.join("tracked.txt"), b"tracked")
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        run_git(&repository, &["init"])?;
        run_git(&repository, &["add", "tracked.txt"])?;
        run_git(
            &repository,
            &[
                "-c",
                "user.name=Forge Test",
                "-c",
                "user.email=forge-test@example.invalid",
                "commit",
                "-m",
                "fixture",
            ],
        )?;
        let alternate = alternate.to_str().ok_or_else(|| {
            ReleaseError::internal("temporary alternate worktree path was not UTF-8")
        })?;
        run_git(&repository, &["config", "core.worktree", alternate])?;
        fs::write(repository.join("tracked.txt"), b"dirty source")
            .map_err(|error| ReleaseError::internal(error.to_string()))?;

        super::require_expected_git_worktree(&repository)?;
        assert!(!super::git_status(&repository)?.is_empty());
        assert!(WorktreeGuard::capture(&repository).is_err());
        Ok(())
    }

    #[test]
    fn bounded_release_process_rejects_output_above_the_retention_limit() -> Result<(), ReleaseError>
    {
        let temporary = tempdir().map_err(|error| ReleaseError::internal(error.to_string()))?;
        let executable = env::current_exe().map_err(|error| {
            ReleaseError::internal(format!("failed to locate release test executable: {error}"))
        })?;
        let mut environment = EnvPolicy::minimal();
        environment.overrides.insert(
            OsString::from("FORGE_RELEASE_PROCESS_TEST"),
            OsString::from("huge-output"),
        );
        let observation = super::run_bounded_process(
            temporary.path(),
            executable.into_os_string(),
            [
                "--exact",
                "release::tests::bounded_release_process_test_helper",
                "--nocapture",
            ]
            .into_iter()
            .map(OsString::from)
            .collect(),
            environment,
            Duration::from_secs(10),
            128,
            128,
            Mutability::ReadOnly,
            NetworkIntent::Unknown,
            "release process bound test",
        )?;
        assert!(observation.stdout_truncated);
        assert_eq!(observation.stdout.len(), 128);
        assert!(observation.stdout_total_bytes >= 8_192);
        assert!(super::require_process_success(observation, "release process bound test").is_err());
        Ok(())
    }

    #[test]
    fn bounded_release_process_test_helper() -> Result<(), ReleaseError> {
        match env::var_os("FORGE_RELEASE_PROCESS_TEST").as_deref() {
            Some(value) if value == std::ffi::OsStr::new("huge-output") => std::io::stdout()
                .lock()
                .write_all(&[b'x'; 8_192])
                .map_err(|error| ReleaseError::internal(error.to_string())),
            #[cfg(unix)]
            Some(value) if value == std::ffi::OsStr::new("repository-temp-boundary") => {
                let repository = env::var_os("FORGE_RELEASE_TEST_REPOSITORY")
                    .map(PathBuf::from)
                    .ok_or_else(|| {
                        ReleaseError::internal("temp-boundary child omitted repository path")
                    })?;
                let head = super::git_head(&repository)?;
                let error = super::materialize_isolated_checkout(&repository, &head, &[])
                    .err()
                    .ok_or_else(|| {
                        ReleaseError::internal(
                            "repository-local TMPDIR unexpectedly passed source isolation",
                        )
                    })?;
                if error.to_string().contains("outside the source repository") {
                    Ok(())
                } else {
                    Err(ReleaseError::internal(format!(
                        "temp-boundary child reported an unexpected error: {error}"
                    )))
                }
            }
            _ => Ok(()),
        }
    }

    #[test]
    fn snapshot_comparison_rejects_each_bound_source_input() {
        let before = snapshot();
        let mut changed_head = before.clone();
        changed_head.source_commit = "b".repeat(40);
        assert!(before.require_same(&changed_head, "test").is_err());

        let mut changed_lock = before.clone();
        changed_lock.cargo_lock.push(0);
        assert!(before.require_same(&changed_lock, "test").is_err());

        let mut changed_notices = before.clone();
        changed_notices.license_notices.push(0);
        assert!(before.require_same(&changed_notices, "test").is_err());

        let mut changed_metadata = before.clone();
        changed_metadata
            .metadata_by_target
            .insert(RELEASE_TARGETS[0].triple.to_owned(), b"different".to_vec());
        assert!(before.require_same(&changed_metadata, "test").is_err());

        let mut changed_tree = before.clone();
        changed_tree
            .tree_by_target
            .insert(RELEASE_TARGETS[0].triple.to_owned(), b"different".to_vec());
        assert!(before.require_same(&changed_tree, "test").is_err());

        let guard = worktree_guard();
        let mut changed_index = guard.clone();
        changed_index.index.push(0);
        assert!(guard.require_same(&changed_index, "test").is_err());

        let mut changed_raw_index = guard.clone();
        changed_raw_index.raw_index.push(0);
        assert!(guard.require_same(&changed_raw_index, "test").is_err());
    }

    #[test]
    fn target_asset_names_are_frozen() {
        assert_eq!(
            RELEASE_TARGETS
                .iter()
                .map(binary_asset_name)
                .collect::<Vec<_>>(),
            [
                "forge-0.1.0-rc.2-x86_64-unknown-linux-musl",
                "forge-0.1.0-rc.2-aarch64-unknown-linux-musl",
                "forge-0.1.0-rc.2-x86_64-apple-darwin",
                "forge-0.1.0-rc.2-aarch64-apple-darwin",
                "forge-0.1.0-rc.2-x86_64-pc-windows-msvc.exe",
            ]
        );
    }

    #[test]
    fn local_release_build_invocation_and_completion_text_are_frozen() {
        let target = &RELEASE_TARGETS[0];
        assert_eq!(
            local_release_build_arguments(target, Path::new("fresh-target")),
            [
                "build",
                "--release",
                "--locked",
                "--offline",
                "-p",
                "forge-cli",
                "--bin",
                "forge",
                "--message-format=json-render-diagnostics",
                "--target",
                "x86_64-unknown-linux-musl",
                "--target-dir",
                "fresh-target",
            ]
            .map(OsString::from)
        );
        assert_eq!(
            release_build_completed_message(target, Path::new("dist")),
            "built and staged forge-0.1.0-rc.2-x86_64-unknown-linux-musl with its CycloneDX SBOM in dist; local candidate only, not signed or published"
        );
    }

    #[test]
    fn scoped_cargo_tree_parser_is_strict_and_reconstructs_edges() -> Result<(), ReleaseError> {
        let metadata: super::CargoMetadata = serde_json::from_str(METADATA)
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        let selection =
            super::parse_scoped_cargo_tree_graph(&metadata, TREE.as_bytes(), "fixture")?;
        assert_eq!(selection.package_ids.len(), 3);
        assert_eq!(
            selection
                .edges
                .get(&selection.root_id)
                .ok_or_else(|| ReleaseError::internal("fixture root omitted its exact edges"))?
                .len(),
            2
        );

        let root = "0@@forge-cli v0.1.0-rc.2 (/repo/crates/forge-cli)@@\n";
        let malformed = [
            TREE.trim_end_matches('\n').to_owned(),
            format!("{TREE}\n"),
            TREE.replace('\n', "\r\n"),
            TREE.replacen('0', "00", 1),
            format!("{root}2@@serde v1.0.229@@\n"),
            format!("{root}0@@serde v1.0.229@@\n"),
            "0@forge-cli v0.1.0-rc.2@\n".to_owned(),
            TREE.replace("serde v1.0.229", "serde v1.0.229 bogus"),
            format!("{root}1@@forge-cli v0.1.0-rc.2 (/repo/crates/forge-cli)@@\n"),
        ];
        for tree in malformed {
            assert!(
                super::parse_scoped_cargo_tree_graph(&metadata, tree.as_bytes(), "fixture")
                    .is_err(),
                "malformed scoped Cargo tree graph was accepted: {tree:?}"
            );
        }

        let mut ambiguous: super::CargoMetadata = serde_json::from_str(METADATA)
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        let mut duplicate = ambiguous.packages[1].clone();
        duplicate.id = "git+https://example.invalid/serde#serde@1.0.229".to_owned();
        duplicate.source = Some("git+https://example.invalid/serde".to_owned());
        ambiguous.packages.push(duplicate);
        assert!(
            super::parse_scoped_cargo_tree_graph(&ambiguous, TREE.as_bytes(), "fixture").is_err()
        );
        Ok(())
    }

    #[test]
    fn cargo_build_message_parser_requires_scoped_graph_parity() -> Result<(), ReleaseError> {
        let metadata: super::CargoMetadata = serde_json::from_str(METADATA)
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        let graph = super::parse_scoped_cargo_tree_graph(&metadata, TREE.as_bytes(), "fixture")?;
        let artifacts = super::parse_cargo_build_artifacts(BUILD_MESSAGES.as_bytes(), "fixture")?;
        super::require_native_build_graph_parity(&graph.package_ids, &artifacts, "fixture")?;

        let mut missing = artifacts.clone();
        missing.remove("registry+https://github.com/rust-lang/crates.io-index#serde@1.0.229");
        assert!(
            super::require_native_build_graph_parity(&graph.package_ids, &missing, "fixture")
                .is_err()
        );
        let mut unexpected = artifacts;
        unexpected.insert("registry+https://example.invalid#extra@1.0.0".to_owned());
        assert!(
            super::require_native_build_graph_parity(&graph.package_ids, &unexpected, "fixture")
                .is_err()
        );

        for malformed in [
            BUILD_MESSAGES.trim_end_matches('\n').to_owned(),
            BUILD_MESSAGES.replace("\"success\":true", "\"success\":false"),
            BUILD_MESSAGES.replace(
                "\"compiler-artifact\",\"package_id\"",
                "\"compiler-artifact\",\"omitted\"",
            ),
            format!(
                "{BUILD_MESSAGES}{{\"reason\":\"compiler-artifact\",\"package_id\":\"late\"}}\n"
            ),
            BUILD_MESSAGES.replace("\"compiler-message\"", "\"future-message\""),
        ] {
            assert!(
                super::parse_cargo_build_artifacts(malformed.as_bytes(), "fixture").is_err(),
                "malformed Cargo build messages were accepted: {malformed:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn sbom_is_deterministic_and_target_bound() -> Result<(), ReleaseError> {
        let target = &RELEASE_TARGETS[0];
        let binary = fake_binary(target.triple);
        let source_commit = "a".repeat(40);
        let first = render_sbom(
            target,
            METADATA.as_bytes(),
            TREE.as_bytes(),
            CARGO_LOCK.as_bytes(),
            &source_commit,
            &binary,
        )?;
        let second = render_sbom(
            target,
            METADATA.as_bytes(),
            TREE.as_bytes(),
            CARGO_LOCK.as_bytes(),
            &source_commit,
            &binary,
        )?;
        assert_eq!(first, second);
        assert_eq!(
            first.as_slice(),
            include_bytes!(
                "../tests/golden/release-build/forge-0.1.0-rc.2-x86_64-unknown-linux-musl.cdx.json"
            )
        );
        let text = String::from_utf8(first)
            .map_err(|error| ReleaseError::internal(format!("test SBOM was not UTF-8: {error}")))?;
        assert!(text.contains("\"specVersion\": \"1.6\""));
        assert!(text.contains(target.triple));
        assert!(text.contains("serde"));
        assert!(text.contains("build-helper"));
        assert!(!text.contains("test-only"));
        assert!(text.contains("\"expression\": \"MIT OR Apache-2.0\""));
        assert!(text.contains("\"expression\": \"Apache-2.0 OR MIT\""));
        assert!(!text.contains("Apache-2.0/MIT"));
        assert!(!text.contains("file:///repo"));
        assert!(text.contains(&source_commit));
        assert!(text.contains(&sha256_hex(&binary)));
        assert!(text.contains(&binary.len().to_string()));

        assert_ne!(
            second,
            render_sbom(
                target,
                METADATA.as_bytes(),
                TREE.as_bytes(),
                format!("{CARGO_LOCK}\n").as_bytes(),
                &source_commit,
                &binary,
            )?
        );
        let mut different_binary = binary;
        different_binary.push(1);
        assert_ne!(
            second,
            render_sbom(
                target,
                METADATA.as_bytes(),
                TREE.as_bytes(),
                CARGO_LOCK.as_bytes(),
                &source_commit,
                &different_binary,
            )?
        );
        Ok(())
    }

    #[test]
    fn sbom_fails_closed_for_missing_or_invalid_release_license_expressions() {
        let target = &RELEASE_TARGETS[0];
        let render = |metadata: &str| {
            render_sbom(
                target,
                metadata.as_bytes(),
                TREE.as_bytes(),
                CARGO_LOCK.as_bytes(),
                &"a".repeat(40),
                &fake_binary(target.triple),
            )
        };
        let missing = METADATA.replacen("\"license\":\"MIT OR Apache-2.0\",", "", 1);
        assert!(render(&missing).is_err());

        let unknown = METADATA.replacen(
            "\"license\":\"MIT OR Apache-2.0\"",
            "\"license\":\"Not-A-License\"",
            1,
        );
        assert!(render(&unknown).is_err());

        let malformed = METADATA.replacen(
            "\"license\":\"MIT OR Apache-2.0\"",
            "\"license\":\"MIT OR\"",
            1,
        );
        assert!(render(&malformed).is_err());
    }

    #[test]
    fn legacy_slash_license_compatibility_is_bound_to_the_reviewed_package_versions()
    -> Result<(), ReleaseError> {
        let expression = |name: &str, version: &str, license: &str| {
            super::package_license_expression(&super::CargoPackage {
                id: format!("registry#{name}@{version}"),
                name: name.to_owned(),
                version: version.to_owned(),
                license: Some(license.to_owned()),
                source: Some("registry+https://github.com/rust-lang/crates.io-index".to_owned()),
                manifest_path: None,
                targets: Vec::new(),
            })
        };

        for (name, version) in [("ctrlc", "3.4.7"), ("fs2", "0.4.3"), ("winapi", "0.3.9")] {
            assert_eq!(
                expression(name, version, "MIT/Apache-2.0")?,
                "MIT OR Apache-2.0"
            );
        }
        for (name, version) in [("same-file", "1.0.6"), ("walkdir", "2.5.0")] {
            assert_eq!(
                expression(name, version, "Unlicense/MIT")?,
                "Unlicense OR MIT"
            );
        }
        assert!(expression("unknown", "3.4.7", "MIT/Apache-2.0").is_err());
        assert!(expression("ctrlc", "3.4.8", "MIT/Apache-2.0").is_err());
        assert!(expression("ctrlc", "3.4.7", "MIT/Zlib").is_err());
        Ok(())
    }

    #[test]
    fn release_license_baseline_rejects_package_and_field_drift() -> Result<(), ReleaseError> {
        let repository = super::repository_root()?;
        let bytes = fs::read(repository.join(super::LICENSE_BASELINE_FILE))
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        let expected: super::ReleaseLicenseBaseline = serde_json::from_slice(&bytes)
            .map_err(|error| ReleaseError::internal(error.to_string()))?;

        let mut missing = expected.clone();
        missing.packages.pop();
        assert!(super::require_release_license_baseline_matches(&expected, &missing).is_err());

        let mut extra = expected.clone();
        let mut extra_package = extra.packages[0].clone();
        extra_package.id.push_str("-unexpected");
        extra.packages.push(extra_package);
        assert!(super::require_release_license_baseline_matches(&expected, &extra).is_err());

        let mut changed_license = expected.clone();
        changed_license.packages[0].license_expression = "MIT".to_owned();
        assert!(
            super::require_release_license_baseline_matches(&expected, &changed_license).is_err()
        );

        let mut changed_target = expected.clone();
        changed_target.packages[0].targets.pop();
        assert!(
            super::require_release_license_baseline_matches(&expected, &changed_target).is_err()
        );

        let mut tampered_legal_file = expected.clone();
        tampered_legal_file.packages[0].legal_files[0].sha256 = "0".repeat(64);
        let error = match super::require_release_license_baseline_matches(
            &expected,
            &tampered_legal_file,
        ) {
            Err(error) => error,
            Ok(()) => {
                return Err(ReleaseError::internal(
                    "tampered legal-file hash unexpectedly passed",
                ));
            }
        };
        assert!(error.to_string().contains("legal-file SHA-256 changed"));
        Ok(())
    }

    #[test]
    fn release_license_policy_rejects_stale_or_inexact_slash_mappings() -> Result<(), ReleaseError>
    {
        let repository = super::repository_root()?;
        let bytes = fs::read(repository.join(super::LICENSE_POLICY_FILE))
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        let policy = super::parse_release_license_policy(&bytes)?;
        let package = |license: &str| super::CargoPackage {
            id: "registry+https://github.com/rust-lang/crates.io-index#ctrlc@3.4.7".to_owned(),
            name: "ctrlc".to_owned(),
            version: "3.4.7".to_owned(),
            license: Some(license.to_owned()),
            source: Some("registry+https://github.com/rust-lang/crates.io-index".to_owned()),
            manifest_path: None,
            targets: Vec::new(),
        };

        let mut missing_mapping = policy.clone();
        missing_mapping
            .spdx_expression_normalizations
            .remove("ctrlc@3.4.7");
        assert!(
            super::reviewed_package_license_expression(
                &package("MIT/Apache-2.0"),
                &missing_mapping,
                &mut std::collections::BTreeSet::new(),
            )
            .is_err()
        );

        let mut wrong_mapping = policy.clone();
        wrong_mapping
            .spdx_expression_normalizations
            .get_mut("ctrlc@3.4.7")
            .ok_or_else(|| ReleaseError::internal("test policy omitted ctrlc mapping"))?
            .normalized_for_sbom = "MIT AND Apache-2.0".to_owned();
        assert!(
            super::reviewed_package_license_expression(
                &package("MIT/Apache-2.0"),
                &wrong_mapping,
                &mut std::collections::BTreeSet::new(),
            )
            .is_err()
        );

        assert!(
            super::reviewed_package_license_expression(
                &package("MIT OR Apache-2.0"),
                &policy,
                &mut std::collections::BTreeSet::new(),
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn registry_crate_archive_is_required_unambiguous_and_lock_bound() -> Result<(), ReleaseError> {
        let temporary = tempdir().map_err(|error| ReleaseError::internal(error.to_string()))?;
        let package_root = temporary
            .path()
            .join("registry/src/index.example/fixture-1.0.0");
        let cache_bucket = temporary.path().join("registry/cache/index.example");
        fs::create_dir_all(&package_root)
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::create_dir_all(&cache_bucket)
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        let archive = cache_bucket.join("fixture-1.0.0.crate");
        let archive_bytes = b"fixture crate archive";
        fs::write(&archive, archive_bytes)
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        let checksum = sha256_hex(archive_bytes);
        let package = super::CargoPackage {
            id: "registry+https://github.com/rust-lang/crates.io-index#fixture@1.0.0".to_owned(),
            name: "fixture".to_owned(),
            version: "1.0.0".to_owned(),
            license: Some("MIT".to_owned()),
            source: Some("registry+https://github.com/rust-lang/crates.io-index".to_owned()),
            manifest_path: Some(package_root.join("Cargo.toml")),
            targets: Vec::new(),
        };
        let lock_packages = std::collections::BTreeMap::from([(
            (
                package.name.clone(),
                package.version.clone(),
                package.source.clone(),
            ),
            Some(checksum.clone()),
        )]);
        assert_eq!(
            super::release_package_lock_checksum(&package, &lock_packages)?,
            Some(checksum.clone())
        );
        super::verify_registry_crate_archive(&package, &package_root, &checksum)?;

        fs::write(&archive, b"tampered crate archive")
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        assert!(super::verify_registry_crate_archive(&package, &package_root, &checksum).is_err());
        fs::remove_file(&archive).map_err(|error| ReleaseError::internal(error.to_string()))?;
        assert!(super::verify_registry_crate_archive(&package, &package_root, &checksum).is_err());

        fs::write(cache_bucket.join("Fixture-1.0.0.crate"), archive_bytes)
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        assert!(super::verify_registry_crate_archive(&package, &package_root, &checksum).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn release_license_scan_rejects_symlinks_and_nonregular_entries() -> Result<(), ReleaseError> {
        use std::os::unix::fs::symlink;

        let temporary = tempdir().map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::write(temporary.path().join("LICENSE"), b"license\n")
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        symlink("LICENSE", temporary.path().join("linked-license"))
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        assert!(
            super::scan_registry_legal_files(temporary.path(), "registry#fixture@1.0.0").is_err()
        );

        fs::remove_file(temporary.path().join("linked-license"))
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        nix::unistd::mkfifo(
            &temporary.path().join("pipe"),
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .map_err(|error| ReleaseError::internal(error.to_string()))?;
        assert!(
            super::scan_registry_legal_files(temporary.path(), "registry#fixture@1.0.0").is_err()
        );
        Ok(())
    }

    #[test]
    #[ignore = "requires an explicit locked fetch for all five release targets"]
    fn scoped_release_graph_counts_and_errno_targets_are_frozen() -> Result<(), ReleaseError> {
        let repository = super::repository_root()?;
        let expected_counts = [86, 85, 86, 85, 88];
        let mut union = std::collections::BTreeSet::new();
        let mut workspace = std::collections::BTreeSet::new();
        let mut registry = std::collections::BTreeSet::new();
        let mut errno_targets = std::collections::BTreeSet::new();

        for (target, expected_count) in RELEASE_TARGETS.iter().zip(expected_counts) {
            let metadata_bytes = super::cargo_metadata(&repository, target)?;
            let tree_bytes = super::cargo_tree(&repository, target)?;
            let metadata: super::CargoMetadata = serde_json::from_slice(&metadata_bytes)
                .map_err(|error| ReleaseError::internal(error.to_string()))?;
            let selection =
                super::parse_scoped_cargo_tree_graph(&metadata, &tree_bytes, target.triple)?;
            assert_eq!(
                selection.package_ids.len(),
                expected_count,
                "{}",
                target.triple
            );
            let packages: std::collections::BTreeMap<_, _> = metadata
                .packages
                .iter()
                .map(|package| (package.id.as_str(), package))
                .collect();
            for id in selection.package_ids {
                let package = packages.get(id.as_str()).ok_or_else(|| {
                    ReleaseError::internal("scoped graph package disappeared from metadata")
                })?;
                union.insert(id.clone());
                if package.source.is_some() {
                    registry.insert(id.clone());
                } else {
                    workspace.insert(id.clone());
                }
                if package.name == "errno" && package.version == "0.3.14" {
                    errno_targets.insert(target.triple);
                }
            }
        }

        assert_eq!(union.len(), super::EXPECTED_LICENSE_PACKAGES);
        assert_eq!(workspace.len(), super::EXPECTED_WORKSPACE_LICENSE_PACKAGES);
        assert_eq!(registry.len(), super::EXPECTED_REGISTRY_LICENSE_PACKAGES);
        assert_eq!(
            errno_targets,
            std::collections::BTreeSet::from(["aarch64-apple-darwin", "x86_64-apple-darwin",])
        );
        Ok(())
    }

    #[test]
    #[ignore = "requires an explicit locked fetch for all five release targets"]
    fn checked_in_release_license_evidence_is_deterministic_and_generate_is_explicit()
    -> Result<(), ReleaseError> {
        let repository = super::repository_root()?;
        let policy_before = fs::read(repository.join(super::LICENSE_POLICY_FILE))
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        let policy = super::parse_release_license_policy(&policy_before)?;
        let evidence = super::collect_release_license_evidence(&repository, &policy)?;
        let first = super::render_release_license_bundle(&evidence)?;
        let second = super::render_release_license_bundle(&evidence)?;
        assert_eq!(first, second);
        assert_eq!(
            super::sha256_hex(&first),
            "82aee460ddacea87326b63f326bb62510e9e0df64ca79f41ca47c1a7ea68409d"
        );
        assert_eq!(
            super::check_release_licenses(&repository)?.package_count,
            96
        );

        let generated = tempdir().map_err(|error| ReleaseError::internal(error.to_string()))?;
        let report = super::generate_release_licenses(&repository, generated.path())?;
        assert_eq!(report.package_count, 96);
        assert_eq!(report.legal_file_count, 198);
        assert_eq!(
            fs::read(generated.path().join(super::LICENSE_BASELINE_FILE))
                .map_err(|error| ReleaseError::internal(error.to_string()))?,
            fs::read(repository.join(super::LICENSE_BASELINE_FILE))
                .map_err(|error| ReleaseError::internal(error.to_string()))?
        );
        assert_eq!(
            fs::read(generated.path().join(super::LICENSE_NOTICES_FILE))
                .map_err(|error| ReleaseError::internal(error.to_string()))?,
            first
        );
        assert!(!generated.path().join(super::LICENSE_POLICY_FILE).exists());
        assert_eq!(
            fs::read(repository.join(super::LICENSE_POLICY_FILE))
                .map_err(|error| ReleaseError::internal(error.to_string()))?,
            policy_before
        );

        let release_source = include_str!("release.rs");
        let finalize_body = release_source
            .split("pub(crate) fn run_finalize")
            .nth(1)
            .and_then(|tail| tail.split("pub(crate) fn run_check").next())
            .ok_or_else(|| ReleaseError::internal("could not isolate run_finalize source"))?;
        assert!(!finalize_body.contains("generate_release_licenses"));
        let main_source = include_str!("main.rs");
        let verify_body = main_source
            .split("fn run_verify")
            .nth(1)
            .and_then(|tail| tail.split("fn run_schema_export").next())
            .ok_or_else(|| ReleaseError::internal("could not isolate run_verify source"))?;
        assert!(verify_body.contains("check_release_licenses"));
        assert!(!verify_body.contains("run_license_generate"));
        Ok(())
    }

    #[test]
    fn complete_release_round_trip_is_deterministic_and_tamper_evident() -> Result<(), ReleaseError>
    {
        let temporary = tempdir().map_err(|error| ReleaseError::internal(error.to_string()))?;
        let repository = temporary.path().join("repository");
        let output = temporary.path().join("dist");
        fs::create_dir(&repository).map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::create_dir(&output).map_err(|error| ReleaseError::internal(error.to_string()))?;
        let output_writer = super::open_output_directory(&repository, &output)?;
        let snapshot = snapshot();

        for target in &RELEASE_TARGETS {
            stage_built(
                &output_writer,
                target,
                &fake_binary(target.triple),
                &snapshot,
            )?;
        }

        finalize(&output_writer, &snapshot)?;
        let manifest = fs::read(output.join(MANIFEST_FILE))
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        let checksums = fs::read(output.join(CHECKSUMS_FILE))
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        let manifest_json: serde_json::Value = serde_json::from_slice(&manifest)
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        let _: forge_schema::ReleaseManifestV2Data = serde_json::from_slice(&manifest)
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        assert_eq!(manifest_json["schema"], "forge.release-manifest/v2");
        let schema_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../docs/schemas/release-manifest-v2.schema.json");
        let checked_in_schema: serde_json::Value =
            serde_json::from_slice(&fs::read(&schema_path).map_err(|error| {
                ReleaseError::internal(format!(
                    "failed to read checked-in release manifest schema: {error}"
                ))
            })?)
            .map_err(|error| {
                ReleaseError::internal(format!(
                    "failed to parse checked-in release manifest schema: {error}"
                ))
            })?;
        assert_eq!(
            manifest_json.get("schema"),
            checked_in_schema.get("$id"),
            "rendered manifest and checked-in schema disagree: {}",
            schema_path.display()
        );
        let validator = jsonschema::validator_for(&checked_in_schema)
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        let schema_failures = validator
            .iter_errors(&manifest_json)
            .map(|error| error.to_string())
            .collect::<Vec<_>>();
        assert!(
            schema_failures.is_empty(),
            "rendered manifest did not satisfy {}: {schema_failures:#?}\n{}",
            schema_path.display(),
            String::from_utf8_lossy(&manifest)
        );
        assert_eq!(
            manifest_json["artifacts"].as_array().map(Vec::len),
            Some(11)
        );
        let subjects = manifest_json["provenance"]["subjects"]
            .as_array()
            .ok_or_else(|| ReleaseError::internal("manifest subjects were not an array"))?;
        assert_eq!(subjects.len(), 13);
        assert!(subjects.iter().any(|name| name == CHECKSUMS_FILE));
        assert!(subjects.iter().any(|name| name == LICENSE_NOTICES_FILE));
        assert!(subjects.iter().any(|name| name == MANIFEST_FILE));
        let artifact_names: Vec<_> = manifest_json["artifacts"]
            .as_array()
            .ok_or_else(|| ReleaseError::internal("manifest artifacts were not an array"))?
            .iter()
            .filter_map(|artifact| artifact["name"].as_str())
            .collect();
        assert!(artifact_names.windows(2).all(|pair| pair[0] < pair[1]));
        let notices = manifest_json["artifacts"]
            .as_array()
            .and_then(|artifacts| {
                artifacts
                    .iter()
                    .find(|artifact| artifact["name"] == LICENSE_NOTICES_FILE)
            })
            .ok_or_else(|| ReleaseError::internal("manifest omitted license notices"))?;
        assert_eq!(notices["kind"], "license-notices");
        assert_eq!(notices["target"], "all");
        assert_eq!(
            fs::read(output.join(LICENSE_NOTICES_FILE))
                .map_err(|error| ReleaseError::internal(error.to_string()))?,
            snapshot.license_notices
        );
        let checksum_text = String::from_utf8(checksums.clone())
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        let checksum_names = checksum_text
            .lines()
            .map(|line| line.split_once("  ").map(|(_, name)| name))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| ReleaseError::internal("checksum fixture line was malformed"))?;
        assert_eq!(checksum_names.len(), 12);
        assert!(checksum_names.windows(2).all(|pair| pair[0] < pair[1]));

        let mut invalid_manifest = manifest_json.clone();
        invalid_manifest["artifacts"][0]["sha256"] = serde_json::json!("not-a-digest");
        assert!(
            serde_json::from_value::<forge_schema::ReleaseManifestV2Data>(invalid_manifest)
                .is_err()
        );

        finalize(&output_writer, &snapshot)?;
        assert_eq!(
            manifest,
            fs::read(output.join(MANIFEST_FILE))
                .map_err(|error| ReleaseError::internal(error.to_string()))?
        );
        assert_eq!(
            checksums,
            fs::read(output.join(CHECKSUMS_FILE))
                .map_err(|error| ReleaseError::internal(error.to_string()))?
        );
        check(&output_writer, &snapshot)?;

        let mut future_compatible_manifest = manifest_json;
        future_compatible_manifest["future_optional_field"] = serde_json::json!(true);
        let mut future_compatible_bytes = serde_json::to_vec_pretty(&future_compatible_manifest)
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        future_compatible_bytes.push(b'\n');
        fs::write(output.join(MANIFEST_FILE), future_compatible_bytes)
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        assert!(
            check(&output_writer, &snapshot).is_err(),
            "the tolerant v2 reader must not weaken exact candidate checking"
        );
        fs::write(output.join(MANIFEST_FILE), &manifest)
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        check(&output_writer, &snapshot)?;

        let tampered = output.join(binary_asset_name(&RELEASE_TARGETS[0]));
        let mut bytes =
            fs::read(&tampered).map_err(|error| ReleaseError::internal(error.to_string()))?;
        bytes.push(0);
        fs::write(&tampered, bytes).map_err(|error| ReleaseError::internal(error.to_string()))?;
        assert!(check(&output_writer, &snapshot).is_err());

        fs::write(&tampered, fake_binary(RELEASE_TARGETS[0].triple))
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::write(output.join(LICENSE_NOTICES_FILE), b"tampered notices\n")
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        assert!(check(&output_writer, &snapshot).is_err());
        Ok(())
    }

    #[test]
    fn duplicate_target_is_same_bytes_only_and_never_overwritten() -> Result<(), ReleaseError> {
        let temporary = tempdir().map_err(|error| ReleaseError::internal(error.to_string()))?;
        let repository = temporary.path().join("repository");
        let output = temporary.path().join("dist");
        fs::create_dir(&repository).map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::create_dir(&output).map_err(|error| ReleaseError::internal(error.to_string()))?;
        let output_writer = super::open_output_directory(&repository, &output)?;
        let target = &RELEASE_TARGETS[0];
        let binary = fake_binary(target.triple);
        let snapshot = snapshot();

        stage_built(&output_writer, target, &binary, &snapshot)?;
        let binary_name = binary_asset_name(target);
        let sbom_name = sbom_asset_name(target);
        let mut names = fs::read_dir(&output)
            .map_err(|error| ReleaseError::internal(error.to_string()))?
            .map(|entry| {
                entry
                    .map(|entry| entry.file_name())
                    .map_err(|error| ReleaseError::internal(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        names.sort();
        assert_eq!(
            names,
            [OsString::from(&binary_name), OsString::from(&sbom_name)]
        );
        let first_binary = fs::read(output.join(&binary_name))
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        let first_sbom = fs::read(output.join(&sbom_name))
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        assert_eq!(first_binary, binary);
        assert_eq!(
            first_sbom.as_slice(),
            include_bytes!(
                "../tests/golden/release-build/forge-0.1.0-rc.2-x86_64-unknown-linux-musl.cdx.json"
            )
        );

        stage_built(&output_writer, target, &binary, &snapshot)?;
        assert_eq!(
            fs::read(output.join(&binary_name))
                .map_err(|error| ReleaseError::internal(error.to_string()))?,
            first_binary
        );
        assert_eq!(
            fs::read(output.join(&sbom_name))
                .map_err(|error| ReleaseError::internal(error.to_string()))?,
            first_sbom
        );
        let mut different = binary.clone();
        different.push(1);
        assert!(stage_built(&output_writer, target, &different, &snapshot).is_err());
        assert_eq!(
            fs::read(output.join(&binary_name))
                .map_err(|error| ReleaseError::internal(error.to_string()))?,
            binary
        );
        assert_eq!(
            fs::read(output.join(&sbom_name))
                .map_err(|error| ReleaseError::internal(error.to_string()))?,
            first_sbom
        );
        Ok(())
    }

    #[test]
    fn concurrent_create_is_recovered_only_when_the_winning_bytes_match() -> Result<(), ReleaseError>
    {
        let temporary = tempdir().map_err(|error| ReleaseError::internal(error.to_string()))?;
        let repository = temporary.path().join("repository");
        let output = temporary.path().join("dist");
        fs::create_dir(&repository).map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::create_dir(&output).map_err(|error| ReleaseError::internal(error.to_string()))?;
        let writer = super::open_output_directory(&repository, &output)?;
        let contender = writer.clone();

        super::write_once_or_same_with_precreate(&writer, "matching", b"expected", || {
            contender
                .write_atomic_new("matching", b"expected")
                .map_err(|error| ReleaseError::internal(error.to_string()))
        })?;
        assert_eq!(
            fs::read(output.join("matching"))
                .map_err(|error| ReleaseError::internal(error.to_string()))?,
            b"expected"
        );

        let contender = writer.clone();
        assert!(
            super::write_once_or_same_with_precreate(&writer, "different", b"expected", || {
                contender
                    .write_atomic_new("different", b"winner")
                    .map_err(|error| ReleaseError::internal(error.to_string()))
            },)
            .is_err()
        );
        assert_eq!(
            fs::read(output.join("different"))
                .map_err(|error| ReleaseError::internal(error.to_string()))?,
            b"winner"
        );
        Ok(())
    }

    #[test]
    fn paired_asset_preflight_avoids_deterministic_partial_writes() -> Result<(), ReleaseError> {
        let temporary = tempdir().map_err(|error| ReleaseError::internal(error.to_string()))?;
        let repository = temporary.path().join("repository");
        let stage_output = temporary.path().join("stage-output");
        let finalize_output = temporary.path().join("finalize-output");
        fs::create_dir(&repository).map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::create_dir(&stage_output).map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::create_dir(&finalize_output)
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        let stage_writer = super::open_output_directory(&repository, &stage_output)?;
        let finalize_writer = super::open_output_directory(&repository, &finalize_output)?;
        let snapshot = snapshot();
        let first_target = &RELEASE_TARGETS[0];

        fs::write(
            stage_output.join(super::sbom_asset_name(first_target)),
            b"conflicting SBOM",
        )
        .map_err(|error| ReleaseError::internal(error.to_string()))?;
        assert!(
            stage_built(
                &stage_writer,
                first_target,
                &fake_binary(first_target.triple),
                &snapshot,
            )
            .is_err()
        );
        assert!(!stage_output.join(binary_asset_name(first_target)).exists());

        for target in &RELEASE_TARGETS {
            stage_built(
                &finalize_writer,
                target,
                &fake_binary(target.triple),
                &snapshot,
            )?;
        }
        fs::write(
            finalize_output.join(CHECKSUMS_FILE),
            b"conflicting checksums",
        )
        .map_err(|error| ReleaseError::internal(error.to_string()))?;
        assert!(finalize(&finalize_writer, &snapshot).is_err());
        assert!(!finalize_output.join(LICENSE_NOTICES_FILE).exists());
        assert!(!finalize_output.join(MANIFEST_FILE).exists());
        Ok(())
    }

    #[test]
    fn non_candidate_files_are_rejected_from_the_exact_release_set() -> Result<(), ReleaseError> {
        let temporary = tempdir().map_err(|error| ReleaseError::internal(error.to_string()))?;
        let repository = temporary.path().join("repository");
        let output = temporary.path().join("dist");
        fs::create_dir(&repository).map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::create_dir(&output).map_err(|error| ReleaseError::internal(error.to_string()))?;
        let output_writer = super::open_output_directory(&repository, &output)?;
        let snapshot = snapshot();

        for target in &RELEASE_TARGETS {
            stage_built(
                &output_writer,
                target,
                &fake_binary(target.triple),
                &snapshot,
            )?;
        }
        finalize(&output_writer, &snapshot)?;
        check(&output_writer, &snapshot)?;
        fs::write(output.join("operator-notes.txt"), b"not a release asset")
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        assert!(check(&output_writer, &snapshot).is_err());
        assert!(finalize(&output_writer, &snapshot).is_err());

        let manifest = fs::read_to_string(output.join(MANIFEST_FILE))
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        let checksums = fs::read_to_string(output.join(CHECKSUMS_FILE))
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        assert!(!manifest.contains("operator-notes.txt"));
        assert!(!checksums.contains("operator-notes.txt"));
        Ok(())
    }

    #[test]
    fn output_directory_must_exist_and_must_not_be_a_symlink() -> Result<(), ReleaseError> {
        let temporary = tempdir().map_err(|error| ReleaseError::internal(error.to_string()))?;
        let repository = temporary.path().join("repository");
        fs::create_dir(&repository).map_err(|error| ReleaseError::internal(error.to_string()))?;
        let missing = temporary.path().join("missing");
        assert!(super::open_output_directory(&repository, &missing).is_err());

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let real = temporary.path().join("real");
            let linked = temporary.path().join("linked");
            fs::create_dir(&real).map_err(|error| ReleaseError::internal(error.to_string()))?;
            symlink(&real, &linked).map_err(|error| ReleaseError::internal(error.to_string()))?;
            assert!(super::open_output_directory(&repository, &linked).is_err());
        }
        Ok(())
    }

    #[test]
    fn output_directory_cannot_be_the_repository_or_any_descendant() -> Result<(), ReleaseError> {
        let temporary = tempdir().map_err(|error| ReleaseError::internal(error.to_string()))?;
        let repository = temporary.path().join("repository");
        let git_output = repository.join(".git").join("dist");
        fs::create_dir_all(&git_output)
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        let target = &RELEASE_TARGETS[0];
        let asset = binary_asset_name(target);

        for output in [&repository, &git_output] {
            assert!(super::open_output_directory(&repository, output).is_err());
            assert!(!output.join(&asset).exists());
        }
        Ok(())
    }

    #[test]
    fn command_output_cannot_use_linked_worktree_git_private_directories()
    -> Result<(), ReleaseError> {
        let temporary = tempdir().map_err(|error| ReleaseError::internal(error.to_string()))?;
        let repository = temporary.path().join("repository");
        let linked = temporary.path().join("linked");
        fs::create_dir(&repository).map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::write(repository.join("tracked.txt"), b"tracked")
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        run_git(&repository, &["init"])?;
        run_git(&repository, &["add", "tracked.txt"])?;
        run_git(
            &repository,
            &[
                "-c",
                "user.name=Forge Test",
                "-c",
                "user.email=forge-test@example.invalid",
                "commit",
                "-m",
                "fixture",
            ],
        )?;
        let linked_argument = linked.to_str().ok_or_else(|| {
            ReleaseError::internal("temporary linked worktree path was not UTF-8")
        })?;
        run_git(
            &repository,
            &["worktree", "add", "--detach", linked_argument],
        )?;

        let git_directory = super::git_path_from_output(&super::git_output(
            &linked,
            &["rev-parse", "--path-format=absolute", "--git-dir"],
            "test Git directory read",
            64 * 1024,
        )?)?;
        let common_directory = super::git_path_from_output(&super::git_output(
            &linked,
            &["rev-parse", "--path-format=absolute", "--git-common-dir"],
            "test Git common directory read",
            64 * 1024,
        )?)?;

        for private_directory in [git_directory, common_directory] {
            assert!(
                super::open_command_output_directory(&linked, &private_directory).is_err(),
                "release output must reject Git private directory {}",
                private_directory.display()
            );
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn check_rejects_a_visible_output_root_replacement_even_when_pinned_assets_are_valid()
    -> Result<(), ReleaseError> {
        let temporary = tempdir().map_err(|error| ReleaseError::internal(error.to_string()))?;
        let repository = temporary.path().join("repository");
        let output = temporary.path().join("dist");
        let displaced = temporary.path().join("displaced-dist");
        fs::create_dir(&repository).map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::create_dir(&output).map_err(|error| ReleaseError::internal(error.to_string()))?;
        let writer = super::open_output_directory(&repository, &output)?;
        let snapshot = snapshot();
        for target in &RELEASE_TARGETS {
            stage_built(&writer, target, &fake_binary(target.triple), &snapshot)?;
        }
        finalize(&writer, &snapshot)?;

        fs::rename(&output, &displaced)
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::create_dir(&output).map_err(|error| ReleaseError::internal(error.to_string()))?;
        assert!(check(&writer, &snapshot).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn built_binary_read_uses_the_prebuild_pinned_root_and_rejects_symlinks()
    -> Result<(), ReleaseError> {
        use std::os::unix::fs::symlink;

        let temporary = tempdir().map_err(|error| ReleaseError::internal(error.to_string()))?;
        let build_root = temporary.path().join("build-root");
        let displaced_root = temporary.path().join("displaced-root");
        let attacker_root = temporary.path().join("attacker-root");
        fs::create_dir(&build_root).map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::create_dir(&attacker_root)
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        let pinned = forge_runtime::fs::RepositoryWriter::new(&build_root)
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        let target = &RELEASE_TARGETS[0];
        let attacker_release = attacker_root.join(target.triple).join("release");
        fs::create_dir_all(&attacker_release)
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::write(
            attacker_release.join(target.executable_name),
            fake_binary(target.triple),
        )
        .map_err(|error| ReleaseError::internal(error.to_string()))?;

        fs::rename(&build_root, &displaced_root)
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        symlink(&attacker_root, &build_root)
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        assert!(super::read_built_binary(&pinned, target).is_err());

        let original_release = displaced_root.join(target.triple).join("release");
        fs::create_dir_all(&original_release)
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        symlink(
            attacker_release.join(target.executable_name),
            original_release.join(target.executable_name),
        )
        .map_err(|error| ReleaseError::internal(error.to_string()))?;
        assert!(super::read_built_binary(&pinned, target).is_err());
        Ok(())
    }

    #[test]
    fn executable_validators_reject_structurally_invalid_images() {
        for target in &RELEASE_TARGETS {
            assert!(validate_binary_format(target, &fake_binary(target.triple)).is_ok());
        }

        let mut dynamic = fake_elf(62);
        dynamic[64..68].copy_from_slice(&3_u32.to_le_bytes());
        assert!(validate_binary_format(&RELEASE_TARGETS[0], &dynamic).is_err());

        let mut wrong_type = fake_elf(62);
        wrong_type[16..18].copy_from_slice(&0_u16.to_le_bytes());
        assert!(validate_binary_format(&RELEASE_TARGETS[0], &wrong_type).is_err());

        let mut no_elf_entry = fake_elf(62);
        no_elf_entry[24..32].copy_from_slice(&0_u64.to_le_bytes());
        assert!(validate_binary_format(&RELEASE_TARGETS[0], &no_elf_entry).is_err());

        let mut non_executable_elf = fake_elf(62);
        non_executable_elf[68..72].copy_from_slice(&4_u32.to_le_bytes());
        assert!(validate_binary_format(&RELEASE_TARGETS[0], &non_executable_elf).is_err());

        let mut bss_entry_elf = fake_elf(62);
        bss_entry_elf[96..104].copy_from_slice(&32_u64.to_le_bytes());
        assert!(validate_binary_format(&RELEASE_TARGETS[0], &bss_entry_elf).is_err());

        let mut out_of_file_elf = fake_elf(62);
        out_of_file_elf[72..80].copy_from_slice(&100_u64.to_le_bytes());
        assert!(validate_binary_format(&RELEASE_TARGETS[0], &out_of_file_elf).is_err());

        let mut wrong_macho_type = fake_macho(0x0100_0007);
        wrong_macho_type[12..16].copy_from_slice(&1_u32.to_le_bytes());
        assert!(validate_binary_format(&RELEASE_TARGETS[2], &wrong_macho_type).is_err());

        let mut non_executable_macho = fake_macho(0x0100_0007);
        non_executable_macho[92..96].copy_from_slice(&0_u32.to_le_bytes());
        assert!(validate_binary_format(&RELEASE_TARGETS[2], &non_executable_macho).is_err());

        let mut no_macho_entry = fake_macho(0x0100_0007);
        no_macho_entry[104..108].copy_from_slice(&0_u32.to_le_bytes());
        assert!(validate_binary_format(&RELEASE_TARGETS[2], &no_macho_entry).is_err());

        let mut out_of_file_macho = fake_macho(0x0100_0007);
        out_of_file_macho[80..88].copy_from_slice(&1000_u64.to_le_bytes());
        assert!(validate_binary_format(&RELEASE_TARGETS[2], &out_of_file_macho).is_err());

        let mut pe_dll = fake_pe();
        pe_dll[0x56..0x58].copy_from_slice(&0x2002_u16.to_le_bytes());
        assert!(validate_binary_format(&RELEASE_TARGETS[4], &pe_dll).is_err());

        let mut no_pe_entry = fake_pe();
        no_pe_entry[0x68..0x6c].copy_from_slice(&0_u32.to_le_bytes());
        assert!(validate_binary_format(&RELEASE_TARGETS[4], &no_pe_entry).is_err());

        let mut non_executable_pe = fake_pe();
        non_executable_pe[0xec..0xf0].copy_from_slice(&0_u32.to_le_bytes());
        assert!(validate_binary_format(&RELEASE_TARGETS[4], &non_executable_pe).is_err());

        let mut bss_entry_pe = fake_pe();
        bss_entry_pe[0xd8..0xdc].copy_from_slice(&0_u32.to_le_bytes());
        assert!(validate_binary_format(&RELEASE_TARGETS[4], &bss_entry_pe).is_err());

        let mut out_of_file_pe = fake_pe();
        out_of_file_pe[0xdc..0xe0].copy_from_slice(&0x180_u32.to_le_bytes());
        assert!(validate_binary_format(&RELEASE_TARGETS[4], &out_of_file_pe).is_err());
    }

    #[test]
    fn sbom_requires_the_exact_workspace_root() {
        let metadata = METADATA.replace(
            "\"workspace_members\": [\"path+file:///repo/crates/forge-cli#0.1.0-rc.2\"]",
            "\"workspace_members\": []",
        );
        assert!(
            render_sbom(
                &RELEASE_TARGETS[0],
                metadata.as_bytes(),
                TREE.as_bytes(),
                CARGO_LOCK.as_bytes(),
                &"a".repeat(40),
                &fake_binary(RELEASE_TARGETS[0].triple),
            )
            .is_err()
        );
    }

    #[test]
    fn sbom_rejects_a_local_dependency_outside_the_workspace() {
        let metadata = METADATA.replacen(
            "\"source\":\"registry+https://github.com/rust-lang/crates.io-index\"",
            "\"source\":null",
            1,
        );
        assert!(
            render_sbom(
                &RELEASE_TARGETS[0],
                metadata.as_bytes(),
                TREE.as_bytes(),
                CARGO_LOCK.as_bytes(),
                &"a".repeat(40),
                &fake_binary(RELEASE_TARGETS[0].triple),
            )
            .is_err()
        );
    }

    fn snapshot() -> RepositorySnapshot {
        RepositorySnapshot {
            source_commit: "a".repeat(40),
            cargo_lock: CARGO_LOCK.as_bytes().to_vec(),
            license_notices: b"fixture third-party license notices\n".to_vec(),
            metadata_by_target: RELEASE_TARGETS
                .iter()
                .map(|target| (target.triple.to_owned(), METADATA.as_bytes().to_vec()))
                .collect(),
            tree_by_target: RELEASE_TARGETS
                .iter()
                .map(|target| (target.triple.to_owned(), TREE.as_bytes().to_vec()))
                .collect(),
        }
    }

    fn worktree_guard() -> WorktreeGuard {
        WorktreeGuard {
            source_commit: "a".repeat(40),
            status: Vec::new(),
            index: b"index".to_vec(),
            raw_index: b"raw-index".to_vec(),
            cargo_lock: b"lock".to_vec(),
        }
    }

    fn minimal_release_repository() -> Result<(TempDir, PathBuf), ReleaseError> {
        let temporary = tempdir().map_err(|error| ReleaseError::internal(error.to_string()))?;
        let repository = temporary.path().join("repository");
        fs::create_dir_all(repository.join("forge-cli/src"))
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::write(repository.join(".gitignore"), b".cargo/\ntarget/\n")
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::write(
            repository.join("Cargo.toml"),
            b"[workspace]\nmembers = [\"forge-cli\"]\nresolver = \"2\"\n",
        )
        .map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::write(
            repository.join("Cargo.lock"),
            b"# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n\n[[package]]\nname = \"forge-cli\"\nversion = \"0.1.0-rc.2\"\n",
        )
        .map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::write(
            repository.join("forge-cli/Cargo.toml"),
            b"[package]\nname = \"forge-cli\"\nversion = \"0.1.0-rc.2\"\nedition = \"2024\"\nlicense = \"MIT OR Apache-2.0\"\n\n[[bin]]\nname = \"forge\"\npath = \"src/main.rs\"\n",
        )
        .map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::write(repository.join("forge-cli/src/main.rs"), b"fn main() {}\n")
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::write(
            repository.join(LICENSE_NOTICES_FILE),
            b"fixture third-party license notices\n",
        )
        .map_err(|error| ReleaseError::internal(error.to_string()))?;
        run_git(&repository, &["init"])?;
        run_git(&repository, &["add", "."])?;
        run_git(
            &repository,
            &[
                "-c",
                "user.name=Forge Test",
                "-c",
                "user.email=forge-test@example.invalid",
                "commit",
                "-m",
                "fixture",
            ],
        )?;
        Ok((temporary, repository))
    }

    fn run_git(repository: &std::path::Path, arguments: &[&str]) -> Result<(), ReleaseError> {
        let mut command = Command::new("git");
        command.current_dir(repository).args(arguments);
        for key in super::REJECTED_RELEASE_GIT_ENV {
            command.env_remove(key);
        }
        let output = command
            .output()
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(ReleaseError::internal(format!(
                "test Git command failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )))
        }
    }

    fn fake_binary(triple: &str) -> Vec<u8> {
        match triple {
            "x86_64-unknown-linux-musl" => fake_elf(62),
            "aarch64-unknown-linux-musl" => fake_elf(183),
            "x86_64-apple-darwin" => fake_macho(0x0100_0007),
            "aarch64-apple-darwin" => fake_macho(0x0100_000c),
            "x86_64-pc-windows-msvc" => fake_pe(),
            _ => Vec::new(),
        }
    }

    fn fake_elf(machine: u16) -> Vec<u8> {
        let mut bytes = vec![0; 120];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&machine.to_le_bytes());
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x40_0040_u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
        bytes[68..72].copy_from_slice(&5_u32.to_le_bytes());
        bytes[80..88].copy_from_slice(&0x40_0000_u64.to_le_bytes());
        bytes[96..104].copy_from_slice(&120_u64.to_le_bytes());
        bytes[104..112].copy_from_slice(&120_u64.to_le_bytes());
        bytes[112..120].copy_from_slice(&4096_u64.to_le_bytes());
        bytes
    }

    fn fake_macho(cpu: u32) -> Vec<u8> {
        let mut bytes = vec![0; 160];
        bytes[0..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        bytes[4..8].copy_from_slice(&cpu.to_le_bytes());
        bytes[12..16].copy_from_slice(&2_u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&2_u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&96_u32.to_le_bytes());
        bytes[32..36].copy_from_slice(&0x19_u32.to_le_bytes());
        bytes[36..40].copy_from_slice(&72_u32.to_le_bytes());
        bytes[64..72].copy_from_slice(&160_u64.to_le_bytes());
        bytes[80..88].copy_from_slice(&160_u64.to_le_bytes());
        bytes[88..92].copy_from_slice(&7_u32.to_le_bytes());
        bytes[92..96].copy_from_slice(&5_u32.to_le_bytes());
        bytes[104..108].copy_from_slice(&0x8000_0028_u32.to_le_bytes());
        bytes[108..112].copy_from_slice(&24_u32.to_le_bytes());
        bytes[112..120].copy_from_slice(&136_u64.to_le_bytes());
        bytes
    }

    fn fake_pe() -> Vec<u8> {
        let mut bytes = vec![0; 0x200];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x40_u32.to_le_bytes());
        bytes[0x40..0x44].copy_from_slice(b"PE\0\0");
        bytes[0x44..0x46].copy_from_slice(&0x8664_u16.to_le_bytes());
        bytes[0x46..0x48].copy_from_slice(&1_u16.to_le_bytes());
        bytes[0x54..0x56].copy_from_slice(&0x70_u16.to_le_bytes());
        bytes[0x56..0x58].copy_from_slice(&0x0002_u16.to_le_bytes());
        bytes[0x58..0x5a].copy_from_slice(&0x020b_u16.to_le_bytes());
        bytes[0x68..0x6c].copy_from_slice(&0x1000_u32.to_le_bytes());
        bytes[0x90..0x94].copy_from_slice(&0x2000_u32.to_le_bytes());
        bytes[0x94..0x98].copy_from_slice(&0x100_u32.to_le_bytes());
        bytes[0xd0..0xd4].copy_from_slice(&0x100_u32.to_le_bytes());
        bytes[0xd4..0xd8].copy_from_slice(&0x1000_u32.to_le_bytes());
        bytes[0xd8..0xdc].copy_from_slice(&0x100_u32.to_le_bytes());
        bytes[0xdc..0xe0].copy_from_slice(&0x100_u32.to_le_bytes());
        bytes[0xec..0xf0].copy_from_slice(&0x2000_0000_u32.to_le_bytes());
        bytes
    }
}
