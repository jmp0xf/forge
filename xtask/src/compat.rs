//! Public N-1 compatibility self-check for candidate Forge binaries.
//!
//! This module deliberately stays in `xtask`: it compares public behavior, but it is not an
//! independent authority and must not become a product runtime dependency.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::Value;

const GENERATED_MANIFEST: &str = "manifest-v1.json";
const GENERATED_MANIFEST_SCHEMA: u32 = 1;
const GENERATOR_PROTOCOL: u32 = 1;
const MAX_MANIFEST_BYTES: u64 = 1_048_576;
const MAX_FIXTURE_FILE_BYTES: u64 = 1_048_576;
const MAX_FIXTURE_BYTES: u64 = 16_777_216;
const MAX_PUBLIC_FIXTURES: usize = 128;
const MAX_SUPPORTED_SCHEMAS: usize = 128;
const MAX_PROCESS_STREAM_BYTES: usize = 4 * 1_048_576;
const PROCESS_TIMEOUT: Duration = Duration::from_secs(30);
const PIPE_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Explicit inputs for one N-1 comparison.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DiffPlansRequest {
    baseline: PathBuf,
    candidate: PathBuf,
}

impl DiffPlansRequest {
    pub(crate) fn parse(arguments: &[String]) -> Result<Self, String> {
        let mut baseline = None;
        let mut candidate = None;
        let mut index = 0;
        while index < arguments.len() {
            let option = &arguments[index];
            let value = arguments
                .get(index + 1)
                .ok_or_else(|| format!("option `{option}` requires a binary path"))?;
            if value.starts_with('-') {
                return Err(format!("option `{option}` requires a binary path"));
            }
            match option.as_str() {
                "--baseline" if baseline.is_none() => baseline = Some(PathBuf::from(value)),
                "--candidate" if candidate.is_none() => candidate = Some(PathBuf::from(value)),
                "--baseline" | "--candidate" => {
                    return Err(format!("option `{option}` was provided more than once"));
                }
                _ => return Err(format!("unknown diff-plans option `{option}`")),
            }
            index += 2;
        }
        let baseline =
            baseline.ok_or_else(|| String::from("missing required `--baseline <BIN>`"))?;
        let candidate =
            candidate.ok_or_else(|| String::from("missing required `--candidate <BIN>`"))?;
        if baseline.as_os_str().is_empty() || candidate.as_os_str().is_empty() {
            return Err(String::from("binary paths must not be empty"));
        }
        Ok(Self {
            baseline,
            candidate,
        })
    }
}

/// One compact, review-oriented compatibility difference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Difference {
    pub(crate) subject: String,
    pub(crate) detail: String,
}

/// Complete comparison counts and differences.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ComparisonReport {
    pub(crate) fixture_count: usize,
    pub(crate) baseline_schema_count: usize,
    pub(crate) candidate_schema_count: usize,
    pub(crate) shared_schema_count: usize,
    pub(crate) differences: Vec<Difference>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ErrorClass {
    Environment,
    Internal,
}

/// A failure of the harness environment or one of its own invariants.
#[derive(Debug)]
pub(crate) struct CompatError {
    class: ErrorClass,
    message: String,
}

impl CompatError {
    fn environment(message: impl Into<String>) -> Self {
        Self {
            class: ErrorClass::Environment,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            class: ErrorClass::Internal,
            message: message.into(),
        }
    }

    pub(crate) const fn exit_code(&self) -> u8 {
        match self.class {
            ErrorClass::Environment => 2,
            ErrorClass::Internal => 70,
        }
    }
}

impl fmt::Display for CompatError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CompatError {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GeneratedManifest {
    schema: u32,
    generator_protocol: u32,
    source_manifest: String,
    source_manifest_identity: String,
    fixtures: Vec<GeneratedFixture>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GeneratedFixture {
    id: String,
    commands: Vec<Value>,
    files: Vec<GeneratedFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GeneratedFile {
    path: String,
    bytes: u64,
    blake3: String,
}

#[derive(Clone, Debug)]
struct FixtureCase {
    id: String,
    files: Vec<FixtureFile>,
}

#[derive(Clone, Debug)]
struct FixtureFile {
    relative: PathBuf,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
struct SubjectBinary {
    label: &'static str,
    program: OsString,
}

#[derive(Debug)]
struct VersionInspection {
    schemas: Option<BTreeSet<String>>,
    issue: Option<String>,
}

/// Compare public schemas and deterministic init plans for every checked-in fixture.
pub(crate) fn compare(
    request: &DiffPlansRequest,
    generated_root: &Path,
) -> Result<ComparisonReport, CompatError> {
    let baseline = SubjectBinary {
        label: "baseline",
        program: resolve_binary(&request.baseline, "baseline")?,
    };
    let candidate = SubjectBinary {
        label: "candidate",
        program: resolve_binary(&request.candidate, "candidate")?,
    };
    require_process_tree_containment()?;
    let fixtures = load_fixtures(generated_root)?;
    let metadata_sandbox = tempfile::Builder::new()
        .prefix("forge-public-compat-metadata-")
        .tempdir()
        .map_err(|error| {
            CompatError::environment(format!(
                "failed to create compatibility metadata sandbox: {error}"
            ))
        })?;
    let metadata_working_directory = metadata_sandbox.path().join("workspace");

    let mut differences = Vec::new();
    recreate_empty_directory(&metadata_working_directory, metadata_sandbox.path())?;
    let baseline_version = inspect_version(&baseline, &metadata_working_directory)?;
    recreate_empty_directory(&metadata_working_directory, metadata_sandbox.path())?;
    let candidate_version = inspect_version(&candidate, &metadata_working_directory)?;
    if let Some(issue) = baseline_version.issue.as_deref() {
        differences.push(Difference {
            subject: String::from("baseline version contract"),
            detail: issue.to_owned(),
        });
    }
    if let Some(issue) = candidate_version.issue.as_deref() {
        differences.push(Difference {
            subject: String::from("candidate version contract"),
            detail: issue.to_owned(),
        });
    }

    let baseline_schemas = baseline_version.schemas.unwrap_or_default();
    let candidate_schemas = candidate_version.schemas.unwrap_or_default();
    if baseline_schemas != candidate_schemas {
        let removed = baseline_schemas
            .difference(&candidate_schemas)
            .cloned()
            .collect::<Vec<_>>();
        let added = candidate_schemas
            .difference(&baseline_schemas)
            .cloned()
            .collect::<Vec<_>>();
        differences.push(Difference {
            subject: String::from("supported schema set"),
            detail: format!("baseline-only={removed:?}, candidate-only={added:?}"),
        });
    }
    let shared_schemas = baseline_schemas
        .intersection(&candidate_schemas)
        .cloned()
        .collect::<Vec<_>>();
    for schema in &shared_schemas {
        compare_schema_document(
            schema,
            &baseline,
            &candidate,
            &metadata_working_directory,
            metadata_sandbox.path(),
            &mut differences,
        )?;
    }

    for fixture in &fixtures {
        compare_fixture(fixture, &baseline, &candidate, &mut differences)?;
    }

    Ok(ComparisonReport {
        fixture_count: fixtures.len(),
        baseline_schema_count: baseline_schemas.len(),
        candidate_schema_count: candidate_schemas.len(),
        shared_schema_count: shared_schemas.len(),
        differences,
    })
}

#[cfg(unix)]
const fn require_process_tree_containment() -> Result<(), CompatError> {
    Ok(())
}

#[cfg(not(unix))]
fn require_process_tree_containment() -> Result<(), CompatError> {
    Err(CompatError::environment(
        "public compatibility comparison is fail-closed on this platform because xtask cannot yet contain subject descendants in a reviewed process-tree primitive; add Job Object containment before enabling it on Windows",
    ))
}

fn resolve_binary(path: &Path, label: &str) -> Result<OsString, CompatError> {
    if path.as_os_str().is_empty() {
        return Err(CompatError::environment(format!(
            "{label} binary path is empty"
        )));
    }
    let has_directory = path.is_absolute() || path.components().count() > 1;
    if !has_directory {
        return Ok(path.as_os_str().to_owned());
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .map_err(|error| {
                CompatError::environment(format!(
                    "failed to resolve the current directory for {label} binary: {error}"
                ))
            })?
            .join(path)
    };
    let metadata = fs::metadata(&absolute).map_err(|error| {
        CompatError::environment(format!(
            "cannot inspect {label} binary {}: {error}",
            absolute.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(CompatError::environment(format!(
            "{label} binary is not a file: {}",
            absolute.display()
        )));
    }
    Ok(absolute.into_os_string())
}

fn inspect_version(
    subject: &SubjectBinary,
    sandbox: &Path,
) -> Result<VersionInspection, CompatError> {
    let spec = subject_command(subject, sandbox, ["--json", "--color", "never", "version"]);
    let observation = run_process(spec)?;
    let value = match completed_json(&observation) {
        Ok(value) => value,
        Err(issue) => {
            return Ok(VersionInspection {
                schemas: None,
                issue: Some(issue),
            });
        }
    };
    if !observation.termination.successful() {
        return Ok(VersionInspection {
            schemas: None,
            issue: Some(format!(
                "{} version --json exited {}",
                subject.label,
                observation.termination.description()
            )),
        });
    }
    let Some(schemas) = value
        .get("data")
        .and_then(|data| data.get("supported_schemas"))
        .and_then(Value::as_array)
    else {
        return Ok(VersionInspection {
            schemas: None,
            issue: Some(format!(
                "{} version JSON omitted data.supported_schemas",
                subject.label
            )),
        });
    };
    if schemas.len() > MAX_SUPPORTED_SCHEMAS {
        return Ok(VersionInspection {
            schemas: None,
            issue: Some(format!(
                "{} version JSON exceeds the {MAX_SUPPORTED_SCHEMAS}-schema harness bound",
                subject.label
            )),
        });
    }
    let mut set = BTreeSet::new();
    for schema in schemas {
        let Some(schema) = schema.as_str() else {
            return Ok(VersionInspection {
                schemas: None,
                issue: Some(format!(
                    "{} version JSON contains a non-string supported schema",
                    subject.label
                )),
            });
        };
        if !valid_schema_argument(schema) {
            return Ok(VersionInspection {
                schemas: None,
                issue: Some(format!(
                    "{} version JSON contains an unsafe schema identifier",
                    subject.label
                )),
            });
        }
        if !set.insert(schema.to_owned()) {
            return Ok(VersionInspection {
                schemas: None,
                issue: Some(format!(
                    "{} version JSON repeats supported schema `{schema}`",
                    subject.label
                )),
            });
        }
    }
    Ok(VersionInspection {
        schemas: Some(set),
        issue: None,
    })
}

fn valid_schema_argument(schema: &str) -> bool {
    !schema.is_empty()
        && schema.len() <= 256
        && schema
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'/'))
}

fn compare_schema_document(
    schema: &str,
    baseline: &SubjectBinary,
    candidate: &SubjectBinary,
    working_directory: &Path,
    sandbox_root: &Path,
    differences: &mut Vec<Difference>,
) -> Result<(), CompatError> {
    recreate_empty_directory(working_directory, sandbox_root)?;
    let baseline_observation = run_process(subject_command(
        baseline,
        working_directory,
        ["--color", "never", "schema", schema],
    ))?;
    recreate_empty_directory(working_directory, sandbox_root)?;
    let candidate_observation = run_process(subject_command(
        candidate,
        working_directory,
        ["--color", "never", "schema", schema],
    ))?;
    let subject = format!("schema `{schema}`");
    compare_command_metadata(
        &subject,
        &baseline_observation,
        &candidate_observation,
        differences,
    );
    if !baseline_observation.termination.successful()
        || !candidate_observation.termination.successful()
    {
        differences.push(Difference {
            subject: subject.clone(),
            detail: format!(
                "a declared supported schema was not emitted successfully: baseline={}, candidate={}",
                baseline_observation.termination.description(),
                candidate_observation.termination.description()
            ),
        });
    }
    let baseline_json = completed_json(&baseline_observation);
    let candidate_json = completed_json(&candidate_observation);
    match (baseline_json, candidate_json) {
        (Ok(baseline_json), Ok(candidate_json)) => {
            if baseline_json != candidate_json {
                differences.push(digested_difference(
                    &subject,
                    "JSON Schema document differs",
                    &baseline_json,
                    &candidate_json,
                ));
            }
        }
        (Err(baseline_issue), Err(candidate_issue)) => {
            differences.push(Difference {
                subject,
                detail: format!(
                    "both documents were unusable; baseline={baseline_issue}; candidate={candidate_issue}"
                ),
            });
        }
        (Err(issue), Ok(_)) => differences.push(Difference {
            subject,
            detail: format!("baseline document was unusable: {issue}"),
        }),
        (Ok(_), Err(issue)) => differences.push(Difference {
            subject,
            detail: format!("candidate document was unusable: {issue}"),
        }),
    }
    Ok(())
}

fn compare_fixture(
    fixture: &FixtureCase,
    baseline: &SubjectBinary,
    candidate: &SubjectBinary,
    differences: &mut Vec<Difference>,
) -> Result<(), CompatError> {
    let sandbox = tempfile::Builder::new()
        .prefix(&format!("forge-public-compat-{}-", fixture.id))
        .tempdir()
        .map_err(|error| {
            CompatError::environment(format!(
                "failed to create sandbox for fixture `{}`: {error}",
                fixture.id
            ))
        })?;
    let repository = sandbox.path().join("repository");
    let support = sandbox.path().join("support");

    prepare_fixture(fixture, &repository, &support, sandbox.path())?;
    let baseline_observation = run_process(init_command(
        baseline,
        &repository,
        &support,
        sandbox.path(),
    ))?;

    reset_sandbox_path(&repository, sandbox.path())?;
    reset_sandbox_path(&support, sandbox.path())?;
    prepare_fixture(fixture, &repository, &support, sandbox.path())?;
    let candidate_observation = run_process(init_command(
        candidate,
        &repository,
        &support,
        sandbox.path(),
    ))?;

    compare_init_observations(
        &fixture.id,
        &baseline_observation,
        &candidate_observation,
        differences,
    );
    Ok(())
}

fn compare_init_observations(
    fixture_id: &str,
    baseline: &ProcessObservation,
    candidate: &ProcessObservation,
    differences: &mut Vec<Difference>,
) {
    let subject = format!("fixture `{fixture_id}` init");
    compare_command_metadata(&subject, baseline, candidate, differences);
    let baseline_json = completed_json(baseline);
    let candidate_json = completed_json(candidate);
    match (baseline_json, candidate_json) {
        (Ok(mut baseline_json), Ok(mut candidate_json)) => {
            normalize_root_tool_version(&mut baseline_json);
            normalize_root_tool_version(&mut candidate_json);
            compare_init_json_components(&subject, &baseline_json, &candidate_json, differences);
        }
        (Err(baseline_issue), Err(candidate_issue)) => {
            differences.push(Difference {
                subject,
                detail: format!(
                    "both JSON results were unusable; baseline={baseline_issue}; candidate={candidate_issue}"
                ),
            });
        }
        (Err(issue), Ok(_)) => differences.push(Difference {
            subject,
            detail: format!("baseline JSON result was unusable: {issue}"),
        }),
        (Ok(_), Err(issue)) => differences.push(Difference {
            subject,
            detail: format!("candidate JSON result was unusable: {issue}"),
        }),
    }
}

fn normalize_root_tool_version(value: &mut Value) {
    if let Some(tool_version) = value
        .as_object_mut()
        .and_then(|object| object.get_mut("tool_version"))
    {
        if tool_version.is_string() {
            *tool_version = Value::String(String::from("<ignored-tool-version>"));
        }
    }
}

fn compare_init_json_components(
    subject: &str,
    baseline: &Value,
    candidate: &Value,
    differences: &mut Vec<Difference>,
) {
    let (Some(baseline_object), Some(candidate_object)) =
        (baseline.as_object(), candidate.as_object())
    else {
        if baseline != candidate {
            differences.push(digested_difference(
                subject,
                "JSON document differs",
                baseline,
                candidate,
            ));
        }
        return;
    };
    for (field, label) in [
        ("schema", "schema differs"),
        ("diagnostics", "diagnostics differ"),
        ("data", "init plan differs"),
    ] {
        let baseline_value = baseline_object.get(field).unwrap_or(&Value::Null);
        let candidate_value = candidate_object.get(field).unwrap_or(&Value::Null);
        if baseline_value != candidate_value {
            differences.push(digested_difference(
                subject,
                label,
                baseline_value,
                candidate_value,
            ));
        }
    }

    let mut baseline_envelope = baseline_object.clone();
    let mut candidate_envelope = candidate_object.clone();
    for field in ["schema", "diagnostics", "data"] {
        baseline_envelope.remove(field);
        candidate_envelope.remove(field);
    }
    if baseline_envelope != candidate_envelope {
        differences.push(digested_difference(
            subject,
            "envelope metadata differs",
            &Value::Object(baseline_envelope),
            &Value::Object(candidate_envelope),
        ));
    }
}

fn compare_command_metadata(
    subject: &str,
    baseline: &ProcessObservation,
    candidate: &ProcessObservation,
    differences: &mut Vec<Difference>,
) {
    if baseline.termination != candidate.termination {
        differences.push(Difference {
            subject: subject.to_owned(),
            detail: format!(
                "exit status differs: baseline={}, candidate={}",
                baseline.termination.description(),
                candidate.termination.description()
            ),
        });
    }
    if baseline.timed_out || candidate.timed_out {
        differences.push(Difference {
            subject: subject.to_owned(),
            detail: format!(
                "bounded execution did not complete: baseline-timeout={}, candidate-timeout={}",
                baseline.timed_out, candidate.timed_out
            ),
        });
    }
    if baseline.descendants_terminated || candidate.descendants_terminated {
        differences.push(Difference {
            subject: subject.to_owned(),
            detail: format!(
                "a subject left descendant processes after its main process exited: baseline={}, candidate={}",
                baseline.descendants_terminated, candidate.descendants_terminated
            ),
        });
    }
    if baseline.stdout.truncated
        || candidate.stdout.truncated
        || baseline.stdout.incomplete
        || candidate.stdout.incomplete
    {
        differences.push(Difference {
            subject: subject.to_owned(),
            detail: format!(
                "stdout exceeded or outlived the capture boundary: baseline={}, candidate={}",
                baseline.stdout.description(),
                candidate.stdout.description()
            ),
        });
    }
    if baseline.stderr.truncated
        || candidate.stderr.truncated
        || baseline.stderr.incomplete
        || candidate.stderr.incomplete
    {
        differences.push(Difference {
            subject: subject.to_owned(),
            detail: format!(
                "stderr exceeded or outlived the capture boundary: baseline={}, candidate={}",
                baseline.stderr.description(),
                candidate.stderr.description()
            ),
        });
    } else if baseline.stderr.bytes != candidate.stderr.bytes {
        differences.push(Difference {
            subject: subject.to_owned(),
            detail: format!(
                "stderr differs: baseline={}, candidate={}",
                baseline.stderr.description(),
                candidate.stderr.description()
            ),
        });
    }
}

fn digested_difference(
    subject: &str,
    label: &str,
    baseline: &Value,
    candidate: &Value,
) -> Difference {
    Difference {
        subject: subject.to_owned(),
        detail: format!(
            "{label}: baseline={}, candidate={}",
            value_digest(baseline),
            value_digest(candidate)
        ),
    }
}

fn value_digest(value: &Value) -> String {
    match serde_json::to_vec(value) {
        Ok(bytes) => digest(&bytes),
        Err(_) => String::from("unserializable-json"),
    }
}

fn load_fixtures(generated_root: &Path) -> Result<Vec<FixtureCase>, CompatError> {
    require_real_directory(generated_root, "generated fixture root")?;
    let manifest_path = generated_root.join(GENERATED_MANIFEST);
    require_real_file(&manifest_path, "generated fixture manifest")?;
    let manifest_bytes = read_bounded(&manifest_path, MAX_MANIFEST_BYTES)?;
    let manifest: GeneratedManifest = serde_json::from_slice(&manifest_bytes).map_err(|error| {
        CompatError::internal(format!(
            "invalid generated fixture manifest {}: {error}",
            manifest_path.display()
        ))
    })?;
    if manifest.schema != GENERATED_MANIFEST_SCHEMA
        || manifest.generator_protocol != GENERATOR_PROTOCOL
    {
        return Err(CompatError::internal(format!(
            "unsupported generated fixture manifest schema/protocol {}/{}; expected {GENERATED_MANIFEST_SCHEMA}/{GENERATOR_PROTOCOL}",
            manifest.schema, manifest.generator_protocol
        )));
    }
    if manifest.fixtures.len() > MAX_PUBLIC_FIXTURES {
        return Err(CompatError::internal(format!(
            "generated fixture manifest exceeds the {MAX_PUBLIC_FIXTURES}-fixture harness bound"
        )));
    }
    if manifest.source_manifest.is_empty()
        || !manifest.source_manifest_identity.starts_with("blake3:")
    {
        return Err(CompatError::internal(
            "generated fixture manifest has an invalid source identity",
        ));
    }

    let mut fixture_ids = BTreeSet::new();
    let mut cases = Vec::new();
    let mut aggregate_bytes = 0_u64;
    for fixture in manifest.fixtures {
        validate_fixture_id(&fixture.id)?;
        if !fixture_ids.insert(fixture.id.clone()) {
            return Err(CompatError::internal(format!(
                "generated fixture manifest repeats fixture `{}`",
                fixture.id
            )));
        }
        // Commands are part of the generated public fixture contract even though diff-plans
        // intentionally executes only Forge's default init dry-run.
        let _declared_command_count = fixture.commands.len();
        let fixture_root = generated_root.join(&fixture.id);
        require_real_directory(&fixture_root, "generated fixture directory")?;
        let actual_paths = collect_regular_files(&fixture_root)?;
        let mut declared_paths = BTreeSet::new();
        let mut files = Vec::new();
        for file in fixture.files {
            validate_portable_relative_path(&file.path)?;
            if !declared_paths.insert(file.path.clone()) {
                return Err(CompatError::internal(format!(
                    "fixture `{}` repeats file `{}`",
                    fixture.id, file.path
                )));
            }
            if file.bytes > MAX_FIXTURE_FILE_BYTES {
                return Err(CompatError::internal(format!(
                    "fixture `{}` file `{}` exceeds the per-file bound",
                    fixture.id, file.path
                )));
            }
            aggregate_bytes = aggregate_bytes
                .checked_add(file.bytes)
                .ok_or_else(|| CompatError::internal("generated fixture byte count overflowed"))?;
            if aggregate_bytes > MAX_FIXTURE_BYTES {
                return Err(CompatError::internal(format!(
                    "generated fixture corpus exceeds the {MAX_FIXTURE_BYTES}-byte bound"
                )));
            }
            let relative = manifest_path_to_path(&file.path);
            let source = fixture_root.join(&relative);
            require_real_file(&source, "generated fixture file")?;
            let bytes = read_bounded(&source, MAX_FIXTURE_FILE_BYTES)?;
            let byte_count = u64::try_from(bytes.len()).map_err(|_| {
                CompatError::internal(format!(
                    "fixture `{}` file `{}` byte count is not representable",
                    fixture.id, file.path
                ))
            })?;
            if byte_count != file.bytes {
                return Err(CompatError::internal(format!(
                    "fixture `{}` file `{}` byte count differs from the manifest",
                    fixture.id, file.path
                )));
            }
            if digest(&bytes) != file.blake3 {
                return Err(CompatError::internal(format!(
                    "fixture `{}` file `{}` digest differs from the manifest",
                    fixture.id, file.path
                )));
            }
            files.push(FixtureFile { relative, bytes });
        }
        if actual_paths != declared_paths {
            let missing = declared_paths
                .difference(&actual_paths)
                .cloned()
                .collect::<Vec<_>>();
            let undeclared = actual_paths
                .difference(&declared_paths)
                .cloned()
                .collect::<Vec<_>>();
            return Err(CompatError::internal(format!(
                "fixture `{}` inventory differs from its generated manifest; missing={missing:?}, undeclared={undeclared:?}",
                fixture.id
            )));
        }
        files.sort_by(|left, right| left.relative.cmp(&right.relative));
        cases.push(FixtureCase {
            id: fixture.id,
            files,
        });
    }
    cases.sort_by(|left, right| left.id.cmp(&right.id));
    validate_generated_root_inventory(generated_root, &fixture_ids)?;
    if cases.is_empty() {
        return Err(CompatError::internal(
            "generated fixture manifest contains no public fixtures",
        ));
    }
    Ok(cases)
}

fn validate_generated_root_inventory(
    generated_root: &Path,
    expected_directories: &BTreeSet<String>,
) -> Result<(), CompatError> {
    let mut actual_directories = BTreeSet::new();
    let entries = sorted_entries(generated_root)?;
    for entry in entries {
        let path = entry.path();
        let file_type = entry.file_type().map_err(|error| {
            CompatError::internal(format!("failed to inspect {}: {error}", path.display()))
        })?;
        let name = entry.file_name().into_string().map_err(|_| {
            CompatError::internal("generated fixture root contains a non-UTF-8 entry")
        })?;
        if file_type.is_symlink() {
            return Err(CompatError::internal(format!(
                "generated fixture root contains a symlink: {}",
                path.display()
            )));
        }
        if file_type.is_dir() {
            actual_directories.insert(name);
        } else if !(file_type.is_file() && name == GENERATED_MANIFEST) {
            return Err(CompatError::internal(format!(
                "generated fixture root contains an undeclared entry: {}",
                path.display()
            )));
        }
    }
    if &actual_directories != expected_directories {
        let missing = expected_directories
            .difference(&actual_directories)
            .cloned()
            .collect::<Vec<_>>();
        let undeclared = actual_directories
            .difference(expected_directories)
            .cloned()
            .collect::<Vec<_>>();
        return Err(CompatError::internal(format!(
            "generated fixture directories differ from the manifest; missing={missing:?}, undeclared={undeclared:?}"
        )));
    }
    Ok(())
}

fn collect_regular_files(root: &Path) -> Result<BTreeSet<String>, CompatError> {
    let mut files = BTreeSet::new();
    collect_regular_files_at(root, root, &mut files)?;
    Ok(files)
}

fn collect_regular_files_at(
    root: &Path,
    directory: &Path,
    files: &mut BTreeSet<String>,
) -> Result<(), CompatError> {
    for entry in sorted_entries(directory)? {
        let path = entry.path();
        let file_type = entry.file_type().map_err(|error| {
            CompatError::internal(format!("failed to inspect {}: {error}", path.display()))
        })?;
        if file_type.is_symlink() {
            return Err(CompatError::internal(format!(
                "generated fixture tree contains a symlink: {}",
                path.display()
            )));
        }
        if file_type.is_dir() {
            collect_regular_files_at(root, &path, files)?;
        } else if file_type.is_file() {
            let relative = path.strip_prefix(root).map_err(|_| {
                CompatError::internal(format!(
                    "generated fixture path escaped its root: {}",
                    path.display()
                ))
            })?;
            files.insert(path_to_manifest_path(relative)?);
        } else {
            return Err(CompatError::internal(format!(
                "generated fixture entry is not a regular file: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn sorted_entries(directory: &Path) -> Result<Vec<fs::DirEntry>, CompatError> {
    let mut entries = fs::read_dir(directory)
        .map_err(|error| {
            CompatError::internal(format!("failed to read {}: {error}", directory.display()))
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            CompatError::internal(format!(
                "failed to enumerate {}: {error}",
                directory.display()
            ))
        })?;
    entries.sort_by_key(fs::DirEntry::file_name);
    Ok(entries)
}

fn path_to_manifest_path(path: &Path) -> Result<String, CompatError> {
    let mut components = Vec::new();
    for component in path.components() {
        let Component::Normal(component) = component else {
            return Err(CompatError::internal(format!(
                "generated fixture path is not relative: {}",
                path.display()
            )));
        };
        components.push(component.to_str().ok_or_else(|| {
            CompatError::internal(format!(
                "generated fixture path is not UTF-8: {}",
                path.display()
            ))
        })?);
    }
    Ok(components.join("/"))
}

fn manifest_path_to_path(path: &str) -> PathBuf {
    path.split('/').collect()
}

fn validate_fixture_id(id: &str) -> Result<(), CompatError> {
    if id.is_empty()
        || id.starts_with('-')
        || id.ends_with('-')
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(CompatError::internal(format!(
            "generated fixture has invalid id `{id}`"
        )));
    }
    Ok(())
}

fn validate_portable_relative_path(path: &str) -> Result<(), CompatError> {
    if path.is_empty()
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains('\\')
        || path.contains(':')
        || path.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(CompatError::internal(format!(
            "generated fixture path is not portable: `{path}`"
        )));
    }
    for component in path.split('/') {
        if component.is_empty()
            || matches!(component, "." | "..")
            || !component
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(CompatError::internal(format!(
                "generated fixture path is not portable: `{path}`"
            )));
        }
    }
    Ok(())
}

fn require_real_directory(path: &Path, label: &str) -> Result<(), CompatError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        CompatError::internal(format!(
            "failed to inspect {label} {}: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CompatError::internal(format!(
            "{label} must be a real directory: {}",
            path.display()
        )));
    }
    Ok(())
}

fn require_real_file(path: &Path, label: &str) -> Result<(), CompatError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        CompatError::internal(format!(
            "failed to inspect {label} {}: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(CompatError::internal(format!(
            "{label} must be a real file: {}",
            path.display()
        )));
    }
    Ok(())
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, CompatError> {
    let file = File::open(path).map_err(|error| {
        CompatError::internal(format!("failed to open {}: {error}", path.display()))
    })?;
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            CompatError::internal(format!("failed to read {}: {error}", path.display()))
        })?;
    if u64::try_from(bytes.len()).is_ok_and(|length| length > limit) {
        return Err(CompatError::internal(format!(
            "file exceeds the {limit}-byte compatibility bound: {}",
            path.display()
        )));
    }
    Ok(bytes)
}

fn digest(bytes: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(bytes).to_hex())
}

fn prepare_fixture(
    fixture: &FixtureCase,
    repository: &Path,
    support: &Path,
    sandbox_root: &Path,
) -> Result<(), CompatError> {
    fs::create_dir(repository).map_err(|error| {
        CompatError::environment(format!(
            "failed to create fixture repository {}: {error}",
            repository.display()
        ))
    })?;
    for file in &fixture.files {
        let destination = repository.join(&file.relative);
        if !destination.starts_with(repository) {
            return Err(CompatError::internal(format!(
                "fixture `{}` destination escaped its sandbox",
                fixture.id
            )));
        }
        let parent = destination.parent().ok_or_else(|| {
            CompatError::internal(format!(
                "fixture `{}` destination has no parent",
                fixture.id
            ))
        })?;
        fs::create_dir_all(parent).map_err(|error| {
            CompatError::environment(format!(
                "failed to create fixture destination {}: {error}",
                parent.display()
            ))
        })?;
        fs::write(&destination, &file.bytes).map_err(|error| {
            CompatError::environment(format!(
                "failed to materialize fixture file {}: {error}",
                destination.display()
            ))
        })?;
    }
    prepare_support(support)?;
    if fixture.id == "non-git" {
        return Ok(());
    }
    initialize_git_repository(repository, support, sandbox_root)?;
    if fixture.id == "dirty-worktree" {
        fs::write(
            repository.join("human-work-in-progress.txt"),
            b"deterministic uncommitted public fixture state\n",
        )
        .map_err(|error| {
            CompatError::environment(format!(
                "failed to create dirty fixture state in {}: {error}",
                repository.display()
            ))
        })?;
    }
    Ok(())
}

fn prepare_support(support: &Path) -> Result<(), CompatError> {
    fs::create_dir(support).map_err(|error| {
        CompatError::environment(format!(
            "failed to create compatibility support directory {}: {error}",
            support.display()
        ))
    })?;
    fs::create_dir(support.join("xdg")).map_err(|error| {
        CompatError::environment(format!(
            "failed to create isolated XDG directory under {}: {error}",
            support.display()
        ))
    })?;
    fs::write(support.join("global.gitconfig"), b"").map_err(|error| {
        CompatError::environment(format!(
            "failed to create isolated Git config under {}: {error}",
            support.display()
        ))
    })
}

fn initialize_git_repository(
    repository: &Path,
    support: &Path,
    sandbox_root: &Path,
) -> Result<(), CompatError> {
    run_required_git(
        repository,
        support,
        sandbox_root,
        ["-c", "init.defaultBranch=main", "init", "--quiet"],
        &[],
    )?;
    run_required_git(
        repository,
        support,
        sandbox_root,
        ["add", "--all", "--"],
        &[],
    )?;
    run_required_git(
        repository,
        support,
        sandbox_root,
        [
            "-c",
            "user.name=Forge compatibility harness",
            "-c",
            "user.email=forge-compat@example.invalid",
            "commit",
            "--quiet",
            "--no-gpg-sign",
            "-m",
            "public fixture baseline",
        ],
        &[
            ("GIT_AUTHOR_DATE", "2000-01-01T00:00:00Z"),
            ("GIT_COMMITTER_DATE", "2000-01-01T00:00:00Z"),
        ],
    )
}

fn run_required_git<const N: usize>(
    repository: &Path,
    support: &Path,
    sandbox_root: &Path,
    arguments: [&str; N],
    additional_environment: &[(&str, &str)],
) -> Result<(), CompatError> {
    let mut spec = ProcessSpec::new("git", repository);
    spec.args.extend([
        OsString::from("--no-pager"),
        OsString::from("--no-optional-locks"),
        OsString::from("--no-replace-objects"),
        OsString::from("--literal-pathspecs"),
        OsString::from("-c"),
        OsString::from("core.fsmonitor=false"),
    ]);
    spec.args.extend(arguments.into_iter().map(OsString::from));
    configure_isolated_environment(&mut spec, support, sandbox_root);
    for (name, value) in additional_environment {
        spec.set_environment(name, value);
    }
    let observation = run_process(spec)?;
    if observation.timed_out
        || observation.stdout.truncated
        || observation.stderr.truncated
        || observation.stdout.incomplete
        || observation.stderr.incomplete
    {
        return Err(CompatError::environment(format!(
            "bounded Git fixture setup did not complete: stdout={}, stderr={}",
            observation.stdout.description(),
            observation.stderr.description()
        )));
    }
    if !observation.termination.successful() {
        return Err(CompatError::environment(format!(
            "Git fixture setup failed with {}; stderr {}",
            observation.termination.description(),
            observation.stderr.description()
        )));
    }
    Ok(())
}

fn reset_sandbox_path(path: &Path, sandbox_root: &Path) -> Result<(), CompatError> {
    if path == sandbox_root || !path.starts_with(sandbox_root) {
        return Err(CompatError::internal(format!(
            "refusing to reset compatibility path outside its sandbox: {}",
            path.display()
        )));
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            Err(CompatError::internal(format!(
                "compatibility reset target is not a real directory: {}",
                path.display()
            )))
        }
        Ok(_) => fs::remove_dir_all(path).map_err(|error| {
            CompatError::environment(format!(
                "failed to reset compatibility path {}: {error}",
                path.display()
            ))
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(CompatError::environment(format!(
            "failed to inspect compatibility reset path {}: {error}",
            path.display()
        ))),
    }
}

fn recreate_empty_directory(path: &Path, sandbox_root: &Path) -> Result<(), CompatError> {
    match fs::symlink_metadata(path) {
        Ok(_) => reset_sandbox_path(path, sandbox_root)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(CompatError::environment(format!(
                "failed to inspect isolated compatibility directory {}: {error}",
                path.display()
            )));
        }
    }
    fs::create_dir(path).map_err(|error| {
        CompatError::environment(format!(
            "failed to create isolated compatibility directory {}: {error}",
            path.display()
        ))
    })
}

fn init_command(
    subject: &SubjectBinary,
    repository: &Path,
    support: &Path,
    sandbox_root: &Path,
) -> ProcessSpec {
    let mut spec = ProcessSpec::new(&subject.program, repository);
    spec.args.extend([
        OsString::from("--json"),
        OsString::from("--color"),
        OsString::from("never"),
        OsString::from("-C"),
        repository.as_os_str().to_owned(),
        OsString::from("init"),
    ]);
    configure_isolated_environment(&mut spec, support, sandbox_root);
    spec
}

fn subject_command<const N: usize>(
    subject: &SubjectBinary,
    cwd: &Path,
    arguments: [&str; N],
) -> ProcessSpec {
    let mut spec = ProcessSpec::new(&subject.program, cwd);
    spec.args.extend(arguments.into_iter().map(OsString::from));
    spec.set_environment("RUSTUP_AUTO_INSTALL", "0");
    spec.set_environment("CARGO_NET_OFFLINE", "true");
    spec.set_environment("GIT_TERMINAL_PROMPT", "0");
    spec
}

fn configure_isolated_environment(spec: &mut ProcessSpec, support: &Path, sandbox_root: &Path) {
    for name in [
        "GIT_CONFIG",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_SYSTEM",
        "GIT_CEILING_DIRECTORIES",
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
        "GIT_EXTERNAL_DIFF",
    ] {
        spec.remove_environment(name);
    }
    spec.set_environment("GIT_CONFIG_NOSYSTEM", "1");
    spec.set_environment("GIT_CONFIG_GLOBAL", support.join("global.gitconfig"));
    spec.set_environment("GIT_CEILING_DIRECTORIES", sandbox_root);
    spec.set_environment("GIT_ATTR_NOSYSTEM", "1");
    spec.set_environment("GIT_TERMINAL_PROMPT", "0");
    spec.set_environment("GIT_OPTIONAL_LOCKS", "0");
    spec.set_environment("GIT_NO_LAZY_FETCH", "1");
    spec.set_environment("GCM_INTERACTIVE", "Never");
    spec.set_environment("GIT_PAGER", "cat");
    spec.set_environment("XDG_CONFIG_HOME", support.join("xdg"));
    spec.set_environment("LC_ALL", "C");
    spec.set_environment("RUSTUP_AUTO_INSTALL", "0");
    spec.set_environment("CARGO_NET_OFFLINE", "true");
    spec.set_environment("GOPROXY", "off");
    spec.set_environment("GOSUMDB", "off");
}

#[derive(Debug)]
struct ProcessSpec {
    program: OsString,
    args: Vec<OsString>,
    cwd: PathBuf,
    environment: BTreeMap<OsString, Option<OsString>>,
    timeout: Duration,
    stream_limit: usize,
}

impl ProcessSpec {
    fn new(program: impl AsRef<OsStr>, cwd: &Path) -> Self {
        Self {
            program: program.as_ref().to_owned(),
            args: Vec::new(),
            cwd: cwd.to_path_buf(),
            environment: BTreeMap::new(),
            timeout: PROCESS_TIMEOUT,
            stream_limit: MAX_PROCESS_STREAM_BYTES,
        }
    }

    fn set_environment(&mut self, name: impl AsRef<OsStr>, value: impl AsRef<OsStr>) {
        self.environment
            .insert(name.as_ref().to_owned(), Some(value.as_ref().to_owned()));
    }

    fn remove_environment(&mut self, name: impl AsRef<OsStr>) {
        self.environment.insert(name.as_ref().to_owned(), None);
    }
}

#[derive(Debug)]
struct ProcessObservation {
    termination: ProcessTermination,
    timed_out: bool,
    descendants_terminated: bool,
    stdout: StreamCapture,
    stderr: StreamCapture,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessTermination {
    code: Option<i32>,
    #[cfg(unix)]
    signal: Option<i32>,
    #[cfg(unix)]
    core_dumped: bool,
}

impl ProcessTermination {
    fn from_status(status: ExitStatus) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt as _;

            Self {
                code: status.code(),
                signal: status.signal(),
                core_dumped: status.core_dumped(),
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                code: status.code(),
            }
        }
    }

    fn successful(self) -> bool {
        self.code == Some(0)
    }

    fn description(self) -> String {
        #[cfg(unix)]
        {
            format!(
                "code={:?}, signal={:?}, core-dumped={}",
                self.code, self.signal, self.core_dumped
            )
        }
        #[cfg(not(unix))]
        {
            format!("code={:?}", self.code)
        }
    }

    #[cfg(test)]
    const fn from_code(code: Option<i32>) -> Self {
        Self {
            code,
            #[cfg(unix)]
            signal: None,
            #[cfg(unix)]
            core_dumped: false,
        }
    }
}

#[derive(Debug)]
struct StreamCapture {
    bytes: Vec<u8>,
    total_bytes: u64,
    truncated: bool,
    incomplete: bool,
}

impl StreamCapture {
    fn description(&self) -> String {
        format!(
            "{} bytes{}{} ({})",
            self.total_bytes,
            if self.truncated { ", truncated" } else { "" },
            if self.incomplete { ", incomplete" } else { "" },
            digest(&self.bytes)
        )
    }
}

fn run_process(spec: ProcessSpec) -> Result<ProcessObservation, CompatError> {
    let mut command = Command::new(&spec.program);
    command
        .args(&spec.args)
        .current_dir(&spec.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in &spec.environment {
        match value {
            Some(value) => {
                command.env(name, value);
            }
            None => {
                command.env_remove(name);
            }
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;

        command.process_group(0);
    }

    let mut child = command.spawn().map_err(|error| {
        CompatError::environment(format!(
            "failed to start `{}` in {}: {error}",
            spec.program.to_string_lossy(),
            spec.cwd.display()
        ))
    })?;
    let stdout = child.stdout.take().ok_or_else(|| {
        terminate_after_setup_failure(&mut child);
        CompatError::internal("spawned process did not expose its configured stdout pipe")
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        terminate_after_setup_failure(&mut child);
        CompatError::internal("spawned process did not expose its configured stderr pipe")
    })?;
    let stdout_receiver = match spawn_capture(stdout, spec.stream_limit) {
        Ok(receiver) => receiver,
        Err(error) => {
            terminate_after_setup_failure(&mut child);
            return Err(error);
        }
    };
    let stderr_receiver = match spawn_capture(stderr, spec.stream_limit) {
        Ok(receiver) => receiver,
        Err(error) => {
            terminate_after_setup_failure(&mut child);
            return Err(error);
        }
    };

    let deadline = Instant::now().checked_add(spec.timeout).ok_or_else(|| {
        terminate_after_setup_failure(&mut child);
        CompatError::internal("process timeout overflowed the monotonic clock")
    })?;
    let (status, timed_out) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (status, false),
            Ok(None) if Instant::now() < deadline => thread::sleep(POLL_INTERVAL),
            Ok(None) => {
                terminate_process_tree(&mut child);
                let status = child.wait().map_err(|error| {
                    CompatError::environment(format!(
                        "failed to reap timed-out process `{}`: {error}",
                        spec.program.to_string_lossy()
                    ))
                })?;
                break (status, true);
            }
            Err(error) => {
                terminate_process_tree(&mut child);
                let _ = child.wait();
                return Err(CompatError::environment(format!(
                    "failed while waiting for process `{}`: {error}",
                    spec.program.to_string_lossy()
                )));
            }
        }
    };

    let descendants_terminated = terminate_remaining_process_group(child.id());
    let stdout = receive_capture(stdout_receiver, "stdout")?;
    if stdout.incomplete {
        terminate_process_tree(&mut child);
        return Err(CompatError::environment(format!(
            "process `{}` left stdout open after its main process exited; refusing to continue with a potentially contaminated sandbox",
            spec.program.to_string_lossy()
        )));
    }
    let stderr = receive_capture(stderr_receiver, "stderr")?;
    if stderr.incomplete {
        terminate_process_tree(&mut child);
        return Err(CompatError::environment(format!(
            "process `{}` left stderr open after its main process exited; refusing to continue with a potentially contaminated sandbox",
            spec.program.to_string_lossy()
        )));
    }
    Ok(ProcessObservation {
        termination: ProcessTermination::from_status(status),
        timed_out,
        descendants_terminated,
        stdout,
        stderr,
    })
}

fn spawn_capture(
    mut reader: impl Read + Send + 'static,
    limit: usize,
) -> Result<Receiver<io::Result<StreamCapture>>, CompatError> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name(String::from("forge-compat-stream-capture"))
        .spawn(move || {
            let result = capture_stream(&mut reader, limit);
            let _ = sender.send(result);
        })
        .map_err(|error| {
            CompatError::environment(format!("failed to start bounded stream reader: {error}"))
        })?;
    Ok(receiver)
}

fn capture_stream(reader: &mut dyn Read, limit: usize) -> io::Result<StreamCapture> {
    let mut bytes = Vec::with_capacity(limit.min(8192));
    let mut total_bytes = 0_u64;
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total_bytes = total_bytes.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        let remaining = limit.saturating_sub(bytes.len());
        let retained = remaining.min(read);
        bytes.extend_from_slice(&buffer[..retained]);
    }
    Ok(StreamCapture {
        truncated: total_bytes > u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        bytes,
        total_bytes,
        incomplete: false,
    })
}

fn receive_capture(
    receiver: Receiver<io::Result<StreamCapture>>,
    stream: &str,
) -> Result<StreamCapture, CompatError> {
    match receiver.recv_timeout(PIPE_DRAIN_TIMEOUT) {
        Ok(Ok(capture)) => Ok(capture),
        Ok(Err(error)) => Err(CompatError::environment(format!(
            "failed to read process {stream}: {error}"
        ))),
        Err(mpsc::RecvTimeoutError::Timeout) => Ok(StreamCapture {
            bytes: Vec::new(),
            total_bytes: 0,
            truncated: true,
            incomplete: true,
        }),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(CompatError::internal(format!(
            "bounded {stream} reader stopped without a result"
        ))),
    }
}

fn terminate_after_setup_failure(child: &mut std::process::Child) {
    terminate_process_tree(child);
    let _ = child.wait();
}

fn terminate_process_tree(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        use nix::sys::signal::{Signal, kill};
        use nix::unistd::Pid;

        if let Ok(pid) = i32::try_from(child.id()) {
            let _ = kill(Pid::from_raw(-pid), Signal::SIGKILL);
        }
    }
    let _ = child.kill();
}

#[cfg(unix)]
fn terminate_remaining_process_group(pid: u32) -> bool {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;

    i32::try_from(pid)
        .ok()
        .is_some_and(|pid| kill(Pid::from_raw(-pid), Signal::SIGKILL).is_ok())
}

#[cfg(not(unix))]
const fn terminate_remaining_process_group(_pid: u32) -> bool {
    false
}

fn completed_json(observation: &ProcessObservation) -> Result<Value, String> {
    if observation.timed_out {
        return Err(String::from("process timed out"));
    }
    if observation.descendants_terminated {
        return Err(String::from(
            "subject left descendant processes after its main process exited",
        ));
    }
    if observation.stdout.truncated || observation.stdout.incomplete {
        return Err(format!(
            "stdout was not completely captured ({})",
            observation.stdout.description()
        ));
    }
    serde_json::from_slice(&observation.stdout.bytes).map_err(|error| {
        format!(
            "stdout is not one JSON document ({error}; {})",
            observation.stdout.description()
        )
    })
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::io::{self, Write as _};
    use std::path::Path;
    use std::process::Command;
    use std::time::{Duration, Instant};

    use serde_json::json;

    use super::{
        DiffPlansRequest, Difference, ProcessObservation, ProcessSpec, ProcessTermination,
        StreamCapture, compare_init_observations, normalize_root_tool_version, run_process,
    };

    const HELPER_ENV: &str = "FORGE_XTASK_COMPAT_TEST_HELPER";

    #[test]
    fn request_requires_one_explicit_binary_for_each_side() -> Result<(), String> {
        let request = DiffPlansRequest::parse(&[
            String::from("--candidate"),
            String::from("candidate-forge"),
            String::from("--baseline"),
            String::from("baseline-forge"),
        ])?;
        assert_eq!(request.baseline, Path::new("baseline-forge"));
        assert_eq!(request.candidate, Path::new("candidate-forge"));
        assert!(DiffPlansRequest::parse(&[]).is_err());
        assert!(
            DiffPlansRequest::parse(&[
                String::from("--baseline"),
                String::from("one"),
                String::from("--baseline"),
                String::from("two"),
                String::from("--candidate"),
                String::from("candidate"),
            ])
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn normalization_ignores_only_a_string_root_tool_version() {
        let mut value = json!({
            "tool_version": "0.9.0",
            "data": {"tool_version": "domain-value"}
        });
        normalize_root_tool_version(&mut value);
        assert_eq!(value["tool_version"], "<ignored-tool-version>");
        assert_eq!(value["data"]["tool_version"], "domain-value");

        let mut wrong_type = json!({"tool_version": 9});
        normalize_root_tool_version(&mut wrong_type);
        assert_eq!(wrong_type["tool_version"], 9);
    }

    #[test]
    fn init_comparison_reports_exit_schema_diagnostics_plan_and_envelope() {
        let baseline = observation(
            Some(0),
            json!({
                "schema": "forge.init-plan/v1",
                "tool_version": "0.9.0",
                "ok": true,
                "data": {"plan": "baseline"},
                "diagnostics": [],
                "truncated": false,
                "artifacts": []
            }),
        );
        let candidate = observation(
            Some(1),
            json!({
                "schema": "forge.init-plan/v2",
                "tool_version": "1.0.0",
                "ok": false,
                "data": {"plan": "candidate"},
                "diagnostics": [{"code": "FGE9999"}],
                "truncated": false,
                "artifacts": []
            }),
        );
        let mut differences = Vec::new();
        compare_init_observations("fixture", &baseline, &candidate, &mut differences);
        let details = differences
            .iter()
            .map(|difference| difference.detail.as_str())
            .collect::<Vec<_>>();
        for required in [
            "exit status differs",
            "schema differs",
            "diagnostics differ",
            "init plan differs",
            "envelope metadata differs",
        ] {
            assert!(details.iter().any(|detail| detail.contains(required)));
        }
    }

    #[test]
    fn init_comparison_ignores_only_root_tool_version_value() {
        let baseline = observation(
            Some(0),
            json!({
                "schema": "forge.init-plan/v1",
                "tool_version": "0.9.0",
                "ok": true,
                "data": {"tool_version": "preserved"},
                "diagnostics": [],
                "truncated": false,
                "artifacts": []
            }),
        );
        let candidate = observation(
            Some(0),
            json!({
                "schema": "forge.init-plan/v1",
                "tool_version": "1.0.0",
                "ok": true,
                "data": {"tool_version": "preserved"},
                "diagnostics": [],
                "truncated": false,
                "artifacts": []
            }),
        );
        let mut differences = Vec::<Difference>::new();
        compare_init_observations("fixture", &baseline, &candidate, &mut differences);
        assert!(differences.is_empty());
    }

    #[test]
    fn subprocess_capture_is_bounded() -> Result<(), Box<dyn std::error::Error>> {
        let mut spec = helper_spec("output");
        spec.stream_limit = 128;
        let observation = run_process(spec)?;
        assert!(observation.termination.successful());
        assert_eq!(observation.stdout.bytes.len(), 128);
        assert!(observation.stdout.total_bytes >= 8192);
        assert!(observation.stdout.truncated);
        Ok(())
    }

    #[test]
    fn subprocess_timeout_is_enforced() -> Result<(), Box<dyn std::error::Error>> {
        let mut spec = helper_spec("sleep");
        spec.timeout = Duration::from_millis(50);
        let started = Instant::now();
        let observation = run_process(spec)?;
        assert!(observation.timed_out);
        assert!(started.elapsed() < Duration::from_secs(5));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn subprocess_descendants_are_terminated_after_the_main_process_exits()
    -> Result<(), Box<dyn std::error::Error>> {
        let observation = run_process(helper_spec("descendant"))?;
        assert!(observation.termination.successful());
        assert!(observation.descendants_terminated);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn distinct_unix_signals_are_distinct_exit_behavior() {
        let document = json!({
            "schema": "forge.init-plan/v1",
            "tool_version": "same",
            "ok": true,
            "data": {},
            "diagnostics": [],
            "truncated": false,
            "artifacts": []
        });
        let mut baseline = observation(None, document.clone());
        baseline.termination.signal = Some(11);
        let mut candidate = observation(None, document);
        candidate.termination.signal = Some(9);
        let mut differences = Vec::new();
        compare_init_observations("signals", &baseline, &candidate, &mut differences);
        assert!(
            differences
                .iter()
                .any(|difference| difference.detail.contains("exit status differs"))
        );
    }

    fn helper_spec(mode: &str) -> ProcessSpec {
        let executable = env::current_exe().unwrap_or_default();
        let mut spec = ProcessSpec::new(executable, Path::new("."));
        spec.args.extend([
            "--exact".into(),
            "compat::tests::subprocess_test_helper".into(),
            "--nocapture".into(),
        ]);
        spec.set_environment(HELPER_ENV, mode);
        spec
    }

    fn observation(exit_code: Option<i32>, value: serde_json::Value) -> ProcessObservation {
        ProcessObservation {
            termination: ProcessTermination::from_code(exit_code),
            timed_out: false,
            descendants_terminated: false,
            stdout: StreamCapture {
                bytes: serde_json::to_vec(&value).unwrap_or_default(),
                total_bytes: 0,
                truncated: false,
                incomplete: false,
            },
            stderr: StreamCapture {
                bytes: Vec::new(),
                total_bytes: 0,
                truncated: false,
                incomplete: false,
            },
        }
    }

    #[test]
    fn subprocess_test_helper() -> io::Result<()> {
        match env::var(HELPER_ENV).ok().as_deref() {
            Some("output") => io::stdout().lock().write_all(&vec![b'x'; 8192]),
            Some("sleep") => {
                std::thread::sleep(Duration::from_secs(10));
                Ok(())
            }
            Some("descendant") => {
                let executable = env::current_exe()?;
                Command::new(executable)
                    .args([
                        "--exact",
                        "compat::tests::subprocess_test_helper",
                        "--nocapture",
                    ])
                    .env(HELPER_ENV, "sleep")
                    .spawn()?;
                Ok(())
            }
            _ => Ok(()),
        }
    }
}
