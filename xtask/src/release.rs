//! Deterministic, candidate-controlled assembly of reviewable release assets.
//!
//! These tasks deliberately stop before provenance, signing, upload, or release authorization.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
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
    ReleaseArtifactData, ReleaseArtifactKindData, ReleaseAuthorityStatusData,
    ReleaseCandidateStatusData, ReleaseChannelData, ReleaseDescriptorData, ReleaseDistributionData,
    ReleaseManifestData, ReleasePredicateTypeData, ReleaseProvenanceData,
    ReleaseProvenanceStatusData, ReleaseRollbackData, ReleaseRollbackStatusData, ReleaseSha256Data,
    ReleaseSigningData, ReleaseSubjectSetData, SchemaKind,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::{TempDir, tempdir};

const RELEASE_VERSION: &str = env!("CARGO_PKG_VERSION");
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
const FINALIZED_ASSET_COUNT: u16 = 12;
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

pub(crate) const BUILD_HELP: &str = "usage: xtask release-build --target <TRIPLE> --output-dir <DIR>\n\nBuilds one accepted target from a clean Git checkout in a fresh temporary Cargo target directory, then stages the binary and its source-bound CycloneDX 1.6 SBOM. Run the compiled xtask directly when a nested `cargo run` is unsuitable.";
pub(crate) const FINALIZE_HELP: &str = "usage: xtask release-finalize --output-dir <DIR>\n\nRequires all five target binaries and SBOMs, then writes release-manifest.json and SHA256SUMS without overwriting different bytes.";
pub(crate) const CHECK_HELP: &str = "usage: xtask release-check --output-dir <DIR>\n\nRecomputes the complete local asset set, binary formats, SBOMs, manifest, and SHA-256 checksums. Success is local consistency evidence, not provenance, signature, approval, upload, or publication.";

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
}

pub(crate) fn run_build(arguments: &[String]) -> Result<ReleaseCommandOutput, ReleaseError> {
    if is_help(arguments) {
        return Ok(ReleaseCommandOutput::Help(BUILD_HELP));
    }
    let options = parse_options(arguments, &["--target", "--output-dir"])?;
    let request = BuildRequest {
        target: parse_target(required_option(&options, "--target")?)?,
        output_directory: PathBuf::from(required_option(&options, "--output-dir")?),
    };
    let repository = repository_root()?;
    let output = open_command_output_directory(&repository, &request.output_directory)?;
    let targets = std::slice::from_ref(request.target);
    let source = ReleaseSource::prepare(&repository, targets, &[output.root()])?;
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
    cargo_build(source.repository(), request.target, build_directory.path())?;
    source.require_unchanged(targets, "Cargo release build")?;
    let binary = read_built_binary(&build_output, request.target)?;
    validate_binary_format(request.target, &binary)?;
    stage_built(&output, request.target, &binary, source.snapshot())?;
    source.require_unchanged(targets, "release asset staging")?;
    Ok(ReleaseCommandOutput::Completed(format!(
        "built and staged {} with its CycloneDX SBOM in {}; local candidate only, not signed or published",
        binary_asset_name(request.target),
        output.root().display()
    )))
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
    metadata_by_target: BTreeMap<String, Vec<u8>>,
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

    fn require_same(&self, later: &Self, operation: &str) -> Result<(), ReleaseError> {
        if self == later {
            Ok(())
        } else {
            Err(ReleaseError::environment(format!(
                "isolated source commit, Cargo.lock, or target-filtered Cargo metadata changed during {operation}"
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
        let metadata_by_target = capture_cargo_metadata(checkout.root(), targets)?;
        validate_cargo_metadata_source_boundaries(
            checkout.root(),
            targets,
            &metadata_by_target,
            &source_tree,
        )?;
        let snapshot = RepositorySnapshot {
            source_commit: isolated_guard.source_commit,
            cargo_lock: isolated_guard.cargo_lock,
            metadata_by_target,
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
        validate_cargo_metadata_source_boundaries(
            self.checkout.root(),
            targets,
            &metadata_by_target,
            &self.source_tree,
        )?;
        self.snapshot.require_same(
            &RepositorySnapshot {
                source_commit: self.snapshot.source_commit.clone(),
                cargo_lock: self.snapshot.cargo_lock.clone(),
                metadata_by_target,
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
        repository.as_os_str().to_owned(),
        checkout.as_os_str().to_owned(),
    ]);
    let clone = run_bounded_process(
        checkout_directory.path(),
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
) -> Result<(), ReleaseError> {
    require_no_external_cargo_configuration(repository)?;
    let mut arguments = [
        "build",
        "--release",
        "--locked",
        "--offline",
        "-p",
        "forge-cli",
        "--bin",
        "forge",
        "--target",
        target.triple,
        "--target-dir",
    ]
    .into_iter()
    .map(OsString::from)
    .collect::<Vec<_>>();
    arguments.push(target_directory.as_os_str().to_owned());
    let label = format!("Cargo release build for {}", target.triple);
    let observation = run_bounded_process(
        repository,
        cargo_program(),
        arguments,
        cargo_environment(),
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
    let _ = require_process_success(observation, &label)?;
    Ok(())
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
        cargo_environment(),
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

fn cargo_environment() -> EnvPolicy {
    let mut policy = EnvPolicy::minimal();
    policy.inherit.extend(
        env::vars_os()
            .map(|(key, _)| key)
            .filter(|key| is_cargo_build_environment_key(key)),
    );
    policy
        .overrides
        .insert(OsString::from("RUSTUP_AUTO_INSTALL"), OsString::from("0"));
    policy
        .overrides
        .insert(OsString::from("CARGO_NET_OFFLINE"), OsString::from("true"));
    policy
}

fn is_cargo_build_environment_key(key: &OsStr) -> bool {
    let Some(key) = key.to_str() else {
        return false;
    };
    if forge_core::fingerprint::is_secret_like_name(key) {
        return false;
    }
    let key = key.to_ascii_uppercase();
    matches!(
        key.as_str(),
        "AR" | "CC"
            | "CFLAGS"
            | "CPATH"
            | "CXX"
            | "CXXFLAGS"
            | "DEVELOPER_DIR"
            | "INCLUDE"
            | "LDFLAGS"
            | "LIB"
            | "LIBPATH"
            | "LIBRARY_PATH"
            | "MACOSX_DEPLOYMENT_TARGET"
            | "PKG_CONFIG_PATH"
            | "RANLIB"
            | "RUSTC"
            | "RUSTC_WRAPPER"
            | "RUSTC_WORKSPACE_WRAPPER"
            | "RUSTDOC"
            | "RUSTFLAGS"
            | "CARGO_ENCODED_RUSTFLAGS"
            | "RUSTUP_TOOLCHAIN"
            | "SDKROOT"
            | "UNIVERSALCRTSDKDIR"
            | "UCRTVERSION"
            | "VCINSTALLDIR"
            | "VCTOOLSINSTALLDIR"
            | "WINDOWSSDKDIR"
            | "WINDOWSSDKVERSION"
    ) || [
        "AR_",
        "CC_",
        "CFLAGS_",
        "CXX_",
        "CXXFLAGS_",
        "PKG_CONFIG_",
        "RANLIB_",
        "CARGO_TARGET_",
    ]
    .iter()
    .any(|prefix| key.starts_with(prefix))
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
    let manifest = render_manifest(output)?;
    let checksums = render_checksums(output, &manifest)?;
    preflight_write_once_or_same(output, MANIFEST_FILE, &manifest)?;
    preflight_write_once_or_same(output, CHECKSUMS_FILE, &checksums)?;
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

    let manifest = render_manifest(output)?;
    require_exact_bytes(output, MANIFEST_FILE, &manifest, "release manifest")?;
    require_exact_bytes(
        output,
        CHECKSUMS_FILE,
        &render_checksums(output, &manifest)?,
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

fn open_output_directory(repository: &Path, path: &Path) -> Result<RepositoryWriter, ReleaseError> {
    let absolute = absolute_clean_path(path)?;
    let output = RepositoryWriter::new(&absolute).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to pin the existing release output directory {}: {error}",
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
            "release output must be outside the source repository: {}",
            output.root().display()
        )));
    }
    validate_visible_root(&output, "release output")?;
    Ok(output)
}

fn open_command_output_directory(
    repository: &Path,
    path: &Path,
) -> Result<RepositoryWriter, ReleaseError> {
    let output = open_output_directory(repository, path)?;
    for (private_directory, label) in git_private_directories(repository)? {
        if output.root() == private_directory || output.root().starts_with(&private_directory) {
            return Err(ReleaseError::environment(format!(
                "release output must be outside the {label}: {}",
                output.root().display()
            )));
        }
    }
    validate_visible_root(&output, "release output")?;
    Ok(output)
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

fn finalized_asset_names() -> BTreeSet<String> {
    let mut names = known_stage_names();
    names.insert(MANIFEST_FILE.to_owned());
    names.insert(CHECKSUMS_FILE.to_owned());
    names
}

fn validate_stage_directory(output: &RepositoryWriter) -> Result<(), ReleaseError> {
    if read_output_optional(output, MANIFEST_FILE, MAX_BINARY_BYTES, "release manifest")?.is_some()
        || read_output_optional(
            output,
            CHECKSUMS_FILE,
            MAX_BINARY_BYTES,
            "release checksums",
        )?
        .is_some()
    {
        return Err(ReleaseError::environment(
            "release output is already finalized and cannot be restaged in place",
        ));
    }
    Ok(())
}

fn validate_finalize_directory(output: &RepositoryWriter) -> Result<(), ReleaseError> {
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
    let mut missing = Vec::new();
    for name in finalized_asset_names() {
        if read_output_optional(output, &name, MAX_BINARY_BYTES, "finalized asset")?.is_none() {
            missing.push(name);
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(ReleaseError::environment(format!(
            "release output is missing required finalized assets: [{}]",
            missing.join(", ")
        )))
    }
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
    resolve: Option<CargoResolve>,
}

#[derive(Debug, Deserialize)]
struct CargoPackage {
    id: String,
    name: String,
    version: String,
    source: Option<String>,
    checksum: Option<String>,
    #[serde(default)]
    manifest_path: Option<PathBuf>,
    #[serde(default)]
    targets: Vec<CargoTarget>,
}

#[derive(Debug, Deserialize)]
struct CargoTarget {
    #[serde(default)]
    src_path: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct CargoResolve {
    nodes: Vec<CargoNode>,
}

#[derive(Debug, Deserialize)]
struct CargoNode {
    id: String,
    deps: Vec<CargoDependency>,
}

#[derive(Debug, Deserialize)]
struct CargoDependency {
    pkg: String,
    dep_kinds: Vec<CargoDependencyKind>,
}

#[derive(Debug, Deserialize)]
struct CargoDependencyKind {
    kind: Option<String>,
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    hashes: Vec<BomHash>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    properties: Vec<BomProperty>,
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

fn render_sbom(
    target: &ReleaseTarget,
    metadata_bytes: &[u8],
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
    let resolve = metadata.resolve.as_ref().ok_or_else(|| {
        ReleaseError::environment(format!(
            "Cargo metadata for {} has no resolved dependency graph",
            target.triple
        ))
    })?;
    let packages: BTreeMap<_, _> = metadata
        .packages
        .iter()
        .map(|package| (package.id.as_str(), package))
        .collect();
    let workspace_members: BTreeSet<_> = metadata
        .workspace_members
        .iter()
        .map(String::as_str)
        .collect();
    let roots: Vec<_> = metadata
        .workspace_members
        .iter()
        .filter_map(|id| packages.get(id.as_str()).copied())
        .filter(|package| package.name == "forge-cli" && package.version == RELEASE_VERSION)
        .collect();
    let [root] = roots.as_slice() else {
        return Err(ReleaseError::environment(format!(
            "Cargo metadata must identify exactly one workspace-member forge-cli {RELEASE_VERSION}, found {}",
            roots.len()
        )));
    };
    let nodes: BTreeMap<_, _> = resolve
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), node))
        .collect();
    let mut selected = BTreeSet::new();
    let mut pending = VecDeque::from([root.id.as_str()]);
    while let Some(id) = pending.pop_front() {
        if !selected.insert(id.to_owned()) {
            continue;
        }
        let package = packages.get(id).ok_or_else(|| {
            ReleaseError::environment(format!("Cargo metadata has no package for `{id}`"))
        })?;
        if package.source.is_none() && !workspace_members.contains(id) {
            return Err(ReleaseError::environment(format!(
                "source-bound SBOM rejects local path dependency outside the exact workspace: `{id}`"
            )));
        }
        let node = nodes.get(id).ok_or_else(|| {
            ReleaseError::environment(format!("Cargo metadata has no resolve node for `{id}`"))
        })?;
        for dependency in &node.deps {
            if is_release_dependency(dependency) {
                pending.push_back(dependency.pkg.as_str());
            }
        }
    }

    let root_ref = format!("pkg:cargo/forge@{RELEASE_VERSION}");
    let mut references = BTreeMap::new();
    for id in &selected {
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
        let hashes = package
            .checksum
            .as_ref()
            .map(|checksum| {
                vec![BomHash {
                    alg: "SHA-256",
                    content: checksum.clone(),
                }]
            })
            .unwrap_or_default();
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
            hashes,
            properties,
        });
    }

    let mut dependencies = Vec::with_capacity(selected.len());
    for id in &selected {
        let node = nodes.get(id.as_str()).ok_or_else(|| {
            ReleaseError::internal(format!("selected Cargo node disappeared: `{id}`"))
        })?;
        let mut depends_on: Vec<_> = node
            .deps
            .iter()
            .filter(|dependency| is_release_dependency(dependency))
            .filter_map(|dependency| references.get(&dependency.pkg).cloned())
            .collect();
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

fn is_release_dependency(dependency: &CargoDependency) -> bool {
    dependency.dep_kinds.is_empty()
        || dependency
            .dep_kinds
            .iter()
            .any(|kind| kind.kind.as_deref() != Some("dev"))
}

fn render_manifest(output: &RepositoryWriter) -> Result<Vec<u8>, ReleaseError> {
    let mut artifacts = Vec::with_capacity(RELEASE_TARGETS.len() * 2);
    for target in &RELEASE_TARGETS {
        for (name, kind) in [
            (binary_asset_name(target), ReleaseArtifactKindData::Binary),
            (
                sbom_asset_name(target),
                ReleaseArtifactKindData::CyclonedxSbom,
            ),
        ] {
            let bytes = read_output_required(output, &name, MAX_BINARY_BYTES, "release artifact")?;
            artifacts.push(ReleaseArtifactData {
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
    artifacts.sort_by(|left, right| left.name.cmp(&right.name));
    let subjects: Vec<_> = finalized_asset_names().into_iter().collect();
    if subjects.len() != usize::from(FINALIZED_ASSET_COUNT) {
        return Err(ReleaseError::internal(format!(
            "release subject allowlist has {} names, expected {FINALIZED_ASSET_COUNT}",
            subjects.len()
        )));
    }
    let artifacts: [ReleaseArtifactData; 10] =
        artifacts.try_into().map_err(|artifacts: Vec<_>| {
            ReleaseError::internal(format!(
                "release artifact allowlist has {} entries, expected 10",
                artifacts.len()
            ))
        })?;
    let subjects: [String; 12] = subjects.try_into().map_err(|subjects: Vec<_>| {
        ReleaseError::internal(format!(
            "release subject allowlist has {} entries, expected 12",
            subjects.len()
        ))
    })?;
    to_pretty_json(
        &ReleaseManifestData {
            schema: SchemaKind::ReleaseManifest.id(),
            release: ReleaseDescriptorData {
                version: RELEASE_VERSION.to_owned(),
                channel: ReleaseChannelData::ReleaseCandidate,
                distribution: ReleaseDistributionData::GithubRelease,
                status: ReleaseCandidateStatusData::LocalReviewCandidate,
            },
            artifacts,
            provenance: ReleaseProvenanceData {
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

fn render_checksums(output: &RepositoryWriter, manifest: &[u8]) -> Result<Vec<u8>, ReleaseError> {
    let names = known_stage_names();
    let mut rendered = String::new();
    for name in names {
        let bytes = read_output_required(
            output,
            &name,
            MAX_BINARY_BYTES,
            "checksummed release artifact",
        )?;
        rendered.push_str(&sha256_hex(&bytes));
        rendered.push_str("  ");
        rendered.push_str(&name);
        rendered.push('\n');
    }
    rendered.push_str(&sha256_hex(manifest));
    rendered.push_str("  ");
    rendered.push_str(MANIFEST_FILE);
    rendered.push('\n');
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
    use std::ffi::OsString;
    use std::fs;
    use std::io::Write as _;
    use std::path::PathBuf;
    use std::process::Command;
    use std::time::Duration;

    use forge_core::ports::EnvPolicy;
    use forge_core::{Mutability, NetworkIntent};
    use tempfile::{TempDir, tempdir};

    use super::{
        CHECKSUMS_FILE, MANIFEST_FILE, RELEASE_TARGETS, ReleaseError, ReleaseErrorKind,
        RepositorySnapshot, WorktreeGuard, binary_asset_name, check, finalize, render_sbom,
        sha256_hex, stage_built, validate_binary_format,
    };

    const METADATA: &str = r#"{
      "packages": [
        {"id":"path+file:///repo/crates/forge-cli#0.1.0-rc.1","name":"forge-cli","version":"0.1.0-rc.1","source":null,"checksum":null},
        {"id":"registry+https://github.com/rust-lang/crates.io-index#serde@1.0.229","name":"serde","version":"1.0.229","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":"dafc30efc5f0fda1a660d7c0b0b3e2b8ddf0d7b3f05803e9f4b206f50807fd8c"},
        {"id":"registry+https://github.com/rust-lang/crates.io-index#build-helper@1.2.3","name":"build-helper","version":"1.2.3","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":null},
        {"id":"registry+https://github.com/rust-lang/crates.io-index#test-only@4.5.6","name":"test-only","version":"4.5.6","source":"registry+https://github.com/rust-lang/crates.io-index","checksum":null}
      ],
      "workspace_members": ["path+file:///repo/crates/forge-cli#0.1.0-rc.1"],
      "resolve": {"nodes": [
        {"id":"path+file:///repo/crates/forge-cli#0.1.0-rc.1","deps":[
          {"pkg":"registry+https://github.com/rust-lang/crates.io-index#serde@1.0.229","dep_kinds":[{"kind":null,"target":null}]},
          {"pkg":"registry+https://github.com/rust-lang/crates.io-index#build-helper@1.2.3","dep_kinds":[{"kind":"build","target":null}]},
          {"pkg":"registry+https://github.com/rust-lang/crates.io-index#test-only@4.5.6","dep_kinds":[{"kind":"dev","target":null}]}
        ]},
        {"id":"registry+https://github.com/rust-lang/crates.io-index#serde@1.0.229","deps":[]},
        {"id":"registry+https://github.com/rust-lang/crates.io-index#build-helper@1.2.3","deps":[]},
        {"id":"registry+https://github.com/rust-lang/crates.io-index#test-only@4.5.6","deps":[]}
      ]}
    }"#;

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

        let error = super::require_no_external_cargo_configuration(&source)
            .err()
            .ok_or_else(|| {
                ReleaseError::internal("external Cargo configuration was unexpectedly accepted")
            })?;
        assert!(error.to_string().contains(&config.display().to_string()));
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
                b"# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n\n[[package]]\nname = \"forge-cli\"\nversion = \"0.1.0-rc.1\"\n# changed\n"
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
    fn cargo_environment_allows_toolchain_controls_but_not_registry_tokens() {
        assert!(super::is_cargo_build_environment_key(std::ffi::OsStr::new(
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER"
        )));
        assert!(super::is_cargo_build_environment_key(std::ffi::OsStr::new(
            "RUSTC_WRAPPER"
        )));
        assert!(!super::is_cargo_build_environment_key(
            std::ffi::OsStr::new("CARGO_REGISTRIES_CRATES_IO_TOKEN")
        ));
        assert!(!super::is_cargo_build_environment_key(
            std::ffi::OsStr::new("CARGO_TARGET_PRIVATE_TOKEN")
        ));
        assert!(super::is_cargo_build_environment_key(std::ffi::OsStr::new(
            "LIB"
        )));
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

        let mut changed_metadata = before.clone();
        changed_metadata
            .metadata_by_target
            .insert(RELEASE_TARGETS[0].triple.to_owned(), b"different".to_vec());
        assert!(before.require_same(&changed_metadata, "test").is_err());

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
                "forge-0.1.0-rc.1-x86_64-unknown-linux-musl",
                "forge-0.1.0-rc.1-aarch64-unknown-linux-musl",
                "forge-0.1.0-rc.1-x86_64-apple-darwin",
                "forge-0.1.0-rc.1-aarch64-apple-darwin",
                "forge-0.1.0-rc.1-x86_64-pc-windows-msvc.exe",
            ]
        );
    }

    #[test]
    fn sbom_is_deterministic_and_target_bound() -> Result<(), ReleaseError> {
        let target = &RELEASE_TARGETS[0];
        let binary = fake_binary(target.triple);
        let source_commit = "a".repeat(40);
        let first = render_sbom(
            target,
            METADATA.as_bytes(),
            b"lock",
            &source_commit,
            &binary,
        )?;
        let second = render_sbom(
            target,
            METADATA.as_bytes(),
            b"lock",
            &source_commit,
            &binary,
        )?;
        assert_eq!(first, second);
        let text = String::from_utf8(first)
            .map_err(|error| ReleaseError::internal(format!("test SBOM was not UTF-8: {error}")))?;
        assert!(text.contains("\"specVersion\": \"1.6\""));
        assert!(text.contains(target.triple));
        assert!(text.contains("serde"));
        assert!(text.contains("build-helper"));
        assert!(!text.contains("test-only"));
        assert!(!text.contains("file:///repo"));
        assert!(text.contains(&source_commit));
        assert!(text.contains(&sha256_hex(&binary)));
        assert!(text.contains(&binary.len().to_string()));

        assert_ne!(
            second,
            render_sbom(
                target,
                METADATA.as_bytes(),
                b"different-lock",
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
                b"lock",
                &source_commit,
                &different_binary,
            )?
        );
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
        let _: forge_schema::ReleaseManifestData = serde_json::from_slice(&manifest)
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
        assert_eq!(manifest_json["schema"], "forge.release-manifest/v1");
        assert_eq!(
            manifest_json["artifacts"].as_array().map(Vec::len),
            Some(10)
        );
        let subjects = manifest_json["provenance"]["subjects"]
            .as_array()
            .ok_or_else(|| ReleaseError::internal("manifest subjects were not an array"))?;
        assert_eq!(subjects.len(), 12);
        assert!(subjects.iter().any(|name| name == CHECKSUMS_FILE));
        assert!(subjects.iter().any(|name| name == MANIFEST_FILE));
        let artifact_names: Vec<_> = manifest_json["artifacts"]
            .as_array()
            .ok_or_else(|| ReleaseError::internal("manifest artifacts were not an array"))?
            .iter()
            .filter_map(|artifact| artifact["name"].as_str())
            .collect();
        assert!(artifact_names.windows(2).all(|pair| pair[0] < pair[1]));

        let mut invalid_manifest = manifest_json.clone();
        invalid_manifest["artifacts"][0]["sha256"] = serde_json::json!("not-a-digest");
        assert!(
            serde_json::from_value::<forge_schema::ReleaseManifestData>(invalid_manifest).is_err()
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
            "the tolerant v1 reader must not weaken exact candidate checking"
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
        stage_built(&output_writer, target, &binary, &snapshot)?;
        let mut different = binary.clone();
        different.push(1);
        assert!(stage_built(&output_writer, target, &different, &snapshot).is_err());
        assert_eq!(
            fs::read(output.join(binary_asset_name(target)))
                .map_err(|error| ReleaseError::internal(error.to_string()))?,
            binary
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
        assert!(!finalize_output.join(MANIFEST_FILE).exists());
        Ok(())
    }

    #[test]
    fn non_candidate_files_are_never_manifest_or_checksum_inputs() -> Result<(), ReleaseError> {
        let temporary = tempdir().map_err(|error| ReleaseError::internal(error.to_string()))?;
        let repository = temporary.path().join("repository");
        let output = temporary.path().join("dist");
        fs::create_dir(&repository).map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::create_dir(&output).map_err(|error| ReleaseError::internal(error.to_string()))?;
        let output_writer = super::open_output_directory(&repository, &output)?;
        fs::write(output.join("operator-notes.txt"), b"not a release asset")
            .map_err(|error| ReleaseError::internal(error.to_string()))?;
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
            "\"workspace_members\": [\"path+file:///repo/crates/forge-cli#0.1.0-rc.1\"]",
            "\"workspace_members\": []",
        );
        assert!(
            render_sbom(
                &RELEASE_TARGETS[0],
                metadata.as_bytes(),
                b"lock",
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
                b"lock",
                &"a".repeat(40),
                &fake_binary(RELEASE_TARGETS[0].triple),
            )
            .is_err()
        );
    }

    fn snapshot() -> RepositorySnapshot {
        RepositorySnapshot {
            source_commit: "a".repeat(40),
            cargo_lock: b"lock".to_vec(),
            metadata_by_target: RELEASE_TARGETS
                .iter()
                .map(|target| (target.triple.to_owned(), METADATA.as_bytes().to_vec()))
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
            b"# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n\n[[package]]\nname = \"forge-cli\"\nversion = \"0.1.0-rc.1\"\n",
        )
        .map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::write(
            repository.join("forge-cli/Cargo.toml"),
            b"[package]\nname = \"forge-cli\"\nversion = \"0.1.0-rc.1\"\nedition = \"2024\"\n\n[[bin]]\nname = \"forge\"\npath = \"src/main.rs\"\n",
        )
        .map_err(|error| ReleaseError::internal(error.to_string()))?;
        fs::write(repository.join("forge-cli/src/main.rs"), b"fn main() {}\n")
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
