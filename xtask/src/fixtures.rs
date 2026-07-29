//! Deterministic materialization for checked-in public fixture definitions.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

const SOURCE_MANIFEST_FILE: &str = "manifest-v1.json";
const MATERIALIZED_MANIFEST_FILE: &str = "manifest-v1.json";
const SOURCE_MANIFEST_SCHEMA: u32 = 1;
const GENERATOR_PROTOCOL: u32 = 1;
const MAX_MANIFEST_BYTES: u64 = 1_048_576;
const MAX_FIXTURE_FILE_BYTES: u64 = 1_048_576;
const MAX_TOTAL_FILE_BYTES: u64 = 16_777_216;

pub(crate) const REQUIRED_FIXTURE_IDS: &[&str] = &[
    "brownfield-adapters",
    "brownfield-just",
    "brownfield-make",
    "brownfield-task",
    "crlf",
    "dirty-worktree",
    "empty-repo",
    "go-embed",
    "go-generated",
    "go-module",
    "go-multi-module",
    "go-workspace",
    "huge-output",
    "large-repository",
    "linked-worktrees",
    "malicious-runner",
    "managed-block-conflict",
    "missing-tools",
    "mixed-rust-go",
    "non-git",
    "non-utf8-path",
    "rust-multi-workspace",
    "rust-no-lock",
    "rust-package",
    "rust-workspace",
    "submodule",
    "symlink-escape",
    "timeout-tree",
];

#[derive(Debug)]
pub(crate) struct FixturePaths {
    pub(crate) definitions: PathBuf,
    pub(crate) generated: PathBuf,
}

impl FixturePaths {
    pub(crate) fn repository_default() -> Result<Self, String> {
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .ok_or_else(|| String::from("xtask manifest directory has no repository parent"))?;
        let fixtures = repository.join("fixtures");
        Ok(Self {
            definitions: fixtures.join("definitions"),
            generated: fixtures.join("generated"),
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct GenerationReport {
    pub(crate) fixture_count: usize,
    pub(crate) written: usize,
    pub(crate) unchanged: usize,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct CheckReport {
    pub(crate) fixture_count: usize,
    pub(crate) file_count: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceManifest {
    schema: u32,
    fixtures: Vec<SourceFixture>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceFixture {
    id: String,
    commands: Vec<NativeCommand>,
    files: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeCommand {
    intent: String,
    program: String,
    args: Vec<String>,
    cwd: String,
}

#[derive(Debug, Serialize)]
struct MaterializedManifest {
    schema: u32,
    generator_protocol: u32,
    source_manifest: String,
    source_manifest_identity: String,
    fixtures: Vec<MaterializedFixture>,
}

#[derive(Debug, Serialize)]
struct MaterializedFixture {
    id: String,
    commands: Vec<NativeCommand>,
    files: Vec<MaterializedFile>,
}

#[derive(Debug, Serialize)]
struct MaterializedFile {
    path: String,
    bytes: u64,
    blake3: String,
}

#[derive(Debug)]
struct MaterializationPlan {
    fixture_count: usize,
    files: Vec<PlannedFile>,
    manifest: Vec<u8>,
}

#[derive(Debug)]
struct PlannedFile {
    output_relative: PathBuf,
    bytes: Vec<u8>,
}

pub(crate) fn generate(
    paths: &FixturePaths,
    required_fixture_ids: &[&str],
) -> Result<GenerationReport, String> {
    let plan = build_plan(paths, required_fixture_ids)?;
    validate_destination(paths, &plan)?;

    let mut written = 0;
    let mut unchanged = 0;
    for file in &plan.files {
        validate_planned_destination(&paths.generated, &file.output_relative)?;
        let path = paths.generated.join(&file.output_relative);
        match write_if_changed_without_following(&path, &file.bytes)? {
            WriteOutcome::Written => written += 1,
            WriteOutcome::Unchanged => unchanged += 1,
        }
    }

    // The root manifest is the completion record: it is updated only after
    // every project file has been materialized successfully.
    validate_planned_destination(&paths.generated, Path::new(MATERIALIZED_MANIFEST_FILE))?;
    let manifest_path = paths.generated.join(MATERIALIZED_MANIFEST_FILE);
    match write_if_changed_without_following(&manifest_path, &plan.manifest)? {
        WriteOutcome::Written => written += 1,
        WriteOutcome::Unchanged => unchanged += 1,
    }

    Ok(GenerationReport {
        fixture_count: plan.fixture_count,
        written,
        unchanged,
    })
}

pub(crate) fn check(
    paths: &FixturePaths,
    required_fixture_ids: &[&str],
) -> Result<CheckReport, String> {
    let plan = build_plan(paths, required_fixture_ids)?;
    validate_destination(paths, &plan)?;
    require_real_directory(&paths.generated, "generated fixture root")?;

    let mut expected = plan
        .files
        .iter()
        .map(|file| path_to_manifest_string(&file.output_relative))
        .collect::<Result<BTreeSet<_>, _>>()?;
    expected.insert(MATERIALIZED_MANIFEST_FILE.to_owned());
    let actual = collect_tree_files(&paths.generated, "generated fixture tree")?;
    if actual != expected {
        let missing: Vec<_> = expected.difference(&actual).cloned().collect();
        let unexpected: Vec<_> = actual.difference(&expected).cloned().collect();
        return Err(format!(
            "generated fixture inventory differs from the deterministic plan; missing={missing:?}, unexpected={unexpected:?}"
        ));
    }

    for file in &plan.files {
        let path = paths.generated.join(&file.output_relative);
        require_real_file(&path, "generated fixture file")?;
        let maximum = u64::try_from(file.bytes.len())
            .map_err(|_| format!("generated fixture size overflowed: {}", path.display()))?;
        let actual = read_bounded(&path, maximum)?;
        if actual != file.bytes {
            return Err(format!(
                "generated fixture content drifted: {}",
                file.output_relative.display()
            ));
        }
    }

    let manifest_path = paths.generated.join(MATERIALIZED_MANIFEST_FILE);
    require_real_file(&manifest_path, "generated fixture manifest")?;
    let manifest_maximum = u64::try_from(plan.manifest.len())
        .map_err(|_| String::from("generated fixture manifest size overflowed"))?;
    if read_bounded(&manifest_path, manifest_maximum)? != plan.manifest {
        return Err(String::from("generated fixture manifest content drifted"));
    }

    Ok(CheckReport {
        fixture_count: plan.fixture_count,
        file_count: expected.len(),
    })
}

fn build_plan(
    paths: &FixturePaths,
    required_fixture_ids: &[&str],
) -> Result<MaterializationPlan, String> {
    require_real_directory(&paths.definitions, "fixture definitions")?;
    let manifest_path = paths.definitions.join(SOURCE_MANIFEST_FILE);
    require_real_file(&manifest_path, "fixture source manifest")?;
    let manifest_bytes = read_bounded(&manifest_path, MAX_MANIFEST_BYTES)?;
    let manifest: SourceManifest = serde_json::from_slice(&manifest_bytes).map_err(|error| {
        format!(
            "invalid fixture source manifest {}: {error}",
            manifest_path.display()
        )
    })?;
    if manifest.schema != SOURCE_MANIFEST_SCHEMA {
        return Err(format!(
            "unsupported fixture source manifest schema {}; expected {SOURCE_MANIFEST_SCHEMA}",
            manifest.schema
        ));
    }

    let projects_root = paths.definitions.join("projects");
    require_real_directory(&projects_root, "fixture definition projects")?;
    let mut fixture_ids = BTreeSet::new();
    let mut sources = BTreeMap::new();
    for fixture in manifest.fixtures {
        validate_fixture_id(&fixture.id)?;
        if !fixture_ids.insert(fixture.id.clone()) {
            return Err(format!("duplicate fixture id `{}`", fixture.id));
        }
        sources.insert(fixture.id.clone(), fixture);
    }
    for required in required_fixture_ids {
        if !fixture_ids.contains(*required) {
            return Err(format!(
                "required fixture `{required}` is absent from the source manifest"
            ));
        }
    }
    validate_project_directories(&projects_root, &fixture_ids)?;

    let mut planned_files = Vec::new();
    let mut materialized_fixtures = Vec::new();
    let mut total_bytes = 0_u64;
    for (fixture_id, mut fixture) in sources {
        validate_commands(&fixture)?;
        fixture.files.sort();
        reject_duplicates(&fixture.files, &format!("fixture `{fixture_id}` file"))?;

        let fixture_source_root = projects_root.join(&fixture_id);
        let declared: BTreeSet<String> = fixture
            .files
            .iter()
            .map(|path| {
                validate_portable_relative_path(path, false)?;
                Ok(path.clone())
            })
            .collect::<Result<_, String>>()?;
        let actual = collect_tree_files(&fixture_source_root, "fixture definition tree")?;
        if actual != declared {
            let missing: Vec<_> = declared.difference(&actual).cloned().collect();
            let undeclared: Vec<_> = actual.difference(&declared).cloned().collect();
            return Err(format!(
                "fixture `{fixture_id}` source inventory differs from its manifest; missing={missing:?}, undeclared={undeclared:?}"
            ));
        }

        let mut materialized_files = Vec::new();
        for relative in &fixture.files {
            let source = fixture_source_root.join(relative);
            require_real_file(&source, "fixture source file")?;
            let bytes = read_bounded(&source, MAX_FIXTURE_FILE_BYTES)?;
            let byte_count = u64::try_from(bytes.len())
                .map_err(|_| format!("fixture source file is too large: {}", source.display()))?;
            total_bytes = total_bytes
                .checked_add(byte_count)
                .ok_or_else(|| String::from("fixture source byte count overflowed"))?;
            if total_bytes > MAX_TOTAL_FILE_BYTES {
                return Err(format!(
                    "fixture source files exceed the {MAX_TOTAL_FILE_BYTES}-byte aggregate limit"
                ));
            }
            planned_files.push(PlannedFile {
                output_relative: Path::new(&fixture_id).join(relative),
                bytes: bytes.clone(),
            });
            materialized_files.push(MaterializedFile {
                path: relative.clone(),
                bytes: byte_count,
                blake3: digest(&bytes),
            });
        }
        materialized_fixtures.push(MaterializedFixture {
            id: fixture_id,
            commands: fixture.commands,
            files: materialized_files,
        });
    }
    planned_files.sort_by(|left, right| left.output_relative.cmp(&right.output_relative));

    let output_manifest = MaterializedManifest {
        schema: SOURCE_MANIFEST_SCHEMA,
        generator_protocol: GENERATOR_PROTOCOL,
        source_manifest: String::from("../definitions/manifest-v1.json"),
        source_manifest_identity: digest(&manifest_bytes),
        fixtures: materialized_fixtures,
    };
    let mut rendered = serde_json::to_vec_pretty(&output_manifest)
        .map_err(|error| format!("failed to serialize materialized fixture manifest: {error}"))?;
    rendered.push(b'\n');

    Ok(MaterializationPlan {
        fixture_count: fixture_ids.len(),
        files: planned_files,
        manifest: rendered,
    })
}

fn validate_commands(fixture: &SourceFixture) -> Result<(), String> {
    let declared_files: BTreeSet<&str> = fixture.files.iter().map(String::as_str).collect();
    for command in &fixture.commands {
        if command.intent.is_empty()
            || !command
                .intent
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
        {
            return Err(format!(
                "fixture `{}` has invalid command intent `{}`",
                fixture.id, command.intent
            ));
        }
        if command.program.is_empty()
            || !command.program.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+')
            })
        {
            return Err(format!(
                "fixture `{}` command program must be a PATH executable name",
                fixture.id
            ));
        }
        if command.args.iter().any(|argument| argument.contains('\0')) {
            return Err(format!(
                "fixture `{}` command argument contains NUL",
                fixture.id
            ));
        }
        validate_portable_relative_path(&command.cwd, true)?;
        if command.cwd != "." {
            let prefix = format!("{}/", command.cwd);
            if !declared_files.iter().any(|path| path.starts_with(&prefix)) {
                return Err(format!(
                    "fixture `{}` command cwd `{}` contains no declared file",
                    fixture.id, command.cwd
                ));
            }
        }
    }
    Ok(())
}

fn validate_project_directories(
    projects_root: &Path,
    expected: &BTreeSet<String>,
) -> Result<(), String> {
    let mut actual = BTreeSet::new();
    for entry in sorted_entries(projects_root)? {
        let file_type = entry
            .file_type()
            .map_err(|error| format!("failed to inspect {}: {error}", entry.path().display()))?;
        if file_type.is_symlink() || !file_type.is_dir() {
            return Err(format!(
                "fixture project entry must be a real directory: {}",
                entry.path().display()
            ));
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| String::from("fixture project directory name is not UTF-8"))?;
        validate_fixture_id(&name)?;
        actual.insert(name);
    }
    if &actual != expected {
        let missing: Vec<_> = expected.difference(&actual).cloned().collect();
        let undeclared: Vec<_> = actual.difference(expected).cloned().collect();
        return Err(format!(
            "fixture project directories differ from the manifest; missing={missing:?}, undeclared={undeclared:?}"
        ));
    }
    Ok(())
}

fn collect_tree_files(root: &Path, label: &str) -> Result<BTreeSet<String>, String> {
    require_real_directory(root, label)?;
    let mut files = BTreeSet::new();
    collect_tree_files_at(root, root, label, &mut files)?;
    Ok(files)
}

fn collect_tree_files_at(
    root: &Path,
    directory: &Path,
    label: &str,
    files: &mut BTreeSet<String>,
) -> Result<(), String> {
    for entry in sorted_entries(directory)? {
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?;
        if file_type.is_symlink() {
            return Err(format!(
                "{label} must not contain symlinks: {}",
                path.display()
            ));
        }
        if file_type.is_dir() {
            collect_tree_files_at(root, &path, label, files)?;
        } else if file_type.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| format!("fixture source path escaped its root: {}", path.display()))?;
            files.insert(path_to_manifest_string(relative)?);
        } else {
            return Err(format!(
                "{label} contains a non-regular file: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn validate_destination(paths: &FixturePaths, plan: &MaterializationPlan) -> Result<(), String> {
    let fixtures_root = paths
        .generated
        .parent()
        .ok_or_else(|| String::from("generated fixture directory has no parent"))?;
    require_real_directory(fixtures_root, "fixtures root")?;
    if let Ok(metadata) = fs::symlink_metadata(&paths.generated) {
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(format!(
                "generated fixture root must be a real directory: {}",
                paths.generated.display()
            ));
        }
        reject_unsafe_destination_entries(&paths.generated)?;
    }

    for file in &plan.files {
        validate_planned_destination(&paths.generated, &file.output_relative)?;
    }
    validate_planned_destination(&paths.generated, Path::new(MATERIALIZED_MANIFEST_FILE))?;
    Ok(())
}

fn reject_unsafe_destination_entries(directory: &Path) -> Result<(), String> {
    for entry in sorted_entries(directory)? {
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?;
        if file_type.is_symlink() {
            return Err(format!(
                "generated fixture tree contains a symlink: {}",
                path.display()
            ));
        }
        if file_type.is_dir() {
            reject_unsafe_destination_entries(&path)?;
        } else if !file_type.is_file() {
            return Err(format!(
                "generated fixture tree contains a non-file entry: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn validate_planned_destination(root: &Path, relative: &Path) -> Result<(), String> {
    let relative_text = path_to_manifest_string(relative)?;
    validate_portable_relative_path(&relative_text, false)?;
    let destination = root.join(relative);
    if !destination.starts_with(root) {
        return Err(format!(
            "fixture output path escapes generated root: {relative_text}"
        ));
    }
    let mut cursor = root.to_path_buf();
    if let Some(parent) = relative.parent() {
        for component in parent.components() {
            let Component::Normal(component) = component else {
                return Err(format!("invalid fixture output path: {relative_text}"));
            };
            cursor.push(component);
            if let Ok(metadata) = fs::symlink_metadata(&cursor) {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(format!(
                        "fixture output parent must be a real directory: {}",
                        cursor.display()
                    ));
                }
            }
        }
    }
    if let Ok(metadata) = fs::symlink_metadata(&destination) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!(
                "fixture output must be a real file: {}",
                destination.display()
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WriteOutcome {
    Written,
    Unchanged,
}

fn write_if_changed_without_following(path: &Path, bytes: &[u8]) -> Result<WriteOutcome, String> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!(
                "fixture output must be a real file: {}",
                path.display()
            ));
        }
    }
    match fs::read(path) {
        Ok(current) if current == bytes => return Ok(WriteOutcome::Unchanged),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("failed to read {}: {error}", path.display())),
    }
    let parent = path
        .parent()
        .ok_or_else(|| format!("fixture output has no parent: {}", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    require_real_directory(parent, "fixture output parent")?;

    let (temporary_path, mut temporary) = create_temporary_file(parent)?;
    let write_result = (|| -> Result<(), String> {
        temporary
            .write_all(bytes)
            .map_err(|error| format!("failed to write {}: {error}", temporary_path.display()))?;
        temporary
            .sync_all()
            .map_err(|error| format!("failed to sync {}: {error}", temporary_path.display()))?;
        drop(temporary);
        replace_file(&temporary_path, path)
            .map_err(|error| format!("failed to replace {}: {error}", path.display()))?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    write_result?;
    Ok(WriteOutcome::Written)
}

fn create_temporary_file(parent: &Path) -> Result<(PathBuf, File), String> {
    for attempt in 0_u16..=u16::MAX {
        let name = format!(".fixture-write-{}-{attempt}", std::process::id());
        let path = parent.join(name);
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(format!(
                    "failed to create temporary fixture file in {}: {error}",
                    parent.display()
                ));
            }
        }
    }
    Err(format!(
        "could not allocate a temporary fixture file in {}",
        parent.display()
    ))
}

#[cfg(unix)]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(not(unix))]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    match fs::remove_file(destination) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    fs::rename(source, destination)
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?;
    if metadata.len() > maximum {
        return Err(format!(
            "{} exceeds the {maximum}-byte fixture input limit",
            path.display()
        ));
    }
    fs::read(path).map_err(|error| format!("failed to read {}: {error}", path.display()))
}

fn require_real_directory(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect {label} {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "{label} is not a real directory: {}",
            path.display()
        ));
    }
    Ok(())
}

fn require_real_file(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect {label} {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!("{label} is not a real file: {}", path.display()));
    }
    Ok(())
}

fn sorted_entries(path: &Path) -> Result<Vec<fs::DirEntry>, String> {
    let mut entries = fs::read_dir(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    entries.sort_by_key(fs::DirEntry::file_name);
    Ok(entries)
}

fn path_to_manifest_string(path: &Path) -> Result<String, String> {
    let mut components = Vec::new();
    for component in path.components() {
        let Component::Normal(component) = component else {
            return Err(format!(
                "path is not relative and normalized: {}",
                path.display()
            ));
        };
        components.push(
            component
                .to_str()
                .ok_or_else(|| format!("path is not UTF-8: {}", path.display()))?,
        );
    }
    Ok(components.join("/"))
}

fn validate_fixture_id(id: &str) -> Result<(), String> {
    if id.is_empty()
        || id.starts_with('-')
        || id.ends_with('-')
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(format!("invalid fixture id `{id}`"));
    }
    Ok(())
}

fn validate_portable_relative_path(path: &str, allow_dot: bool) -> Result<(), String> {
    if allow_dot && path == "." {
        return Ok(());
    }
    if path.is_empty()
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains('\\')
        || path.contains(':')
        || path.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(format!(
            "path is not a portable relative fixture path: `{path}`"
        ));
    }
    for component in path.split('/') {
        if component.is_empty()
            || matches!(component, "." | "..")
            || !component
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(format!(
                "path is not a portable relative fixture path: `{path}`"
            ));
        }
    }
    Ok(())
}

fn reject_duplicates(values: &[String], label: &str) -> Result<(), String> {
    for pair in values.windows(2) {
        if pair[0] == pair[1] {
            return Err(format!("duplicate {label} `{}`", pair[0]));
        }
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(bytes).to_hex())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use serde_json::Value;
    use tempfile::TempDir;

    use super::{
        FixturePaths, MATERIALIZED_MANIFEST_FILE, REQUIRED_FIXTURE_IDS, SOURCE_MANIFEST_FILE,
        build_plan, check, digest, generate,
    };

    #[test]
    fn checked_in_required_definitions_and_outputs_are_complete_and_current()
    -> Result<(), Box<dyn std::error::Error>> {
        let paths = FixturePaths::repository_default()?;
        let plan = build_plan(&paths, REQUIRED_FIXTURE_IDS)?;
        assert_eq!(plan.fixture_count, REQUIRED_FIXTURE_IDS.len());
        assert!(!plan.files.is_empty());
        for file in plan.files {
            assert_eq!(
                fs::read(paths.generated.join(&file.output_relative))?,
                file.bytes,
                "materialized fixture drifted: {}",
                file.output_relative.display()
            );
        }
        assert_eq!(
            fs::read(paths.generated.join(MATERIALIZED_MANIFEST_FILE))?,
            plan.manifest
        );
        Ok(())
    }

    #[test]
    fn materialization_order_is_lexical() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestDefinitions::new(&[
            TestFixture::new("zeta", &["z.txt", "a.txt"]),
            TestFixture::new("alpha", &["src/z.txt", "src/a.txt"]),
        ])?;
        let plan = build_plan(&setup.paths, &[])?;
        let paths: Vec<_> = plan
            .files
            .iter()
            .map(|file| file.output_relative.to_string_lossy().replace('\\', "/"))
            .collect();
        assert_eq!(
            paths,
            [
                "alpha/src/a.txt",
                "alpha/src/z.txt",
                "zeta/a.txt",
                "zeta/z.txt"
            ]
        );
        Ok(())
    }

    #[test]
    fn generation_is_idempotent_and_preserves_unowned_files()
    -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestDefinitions::new(&[TestFixture::new("alpha", &["src/lib.rs"])])?;
        let first = generate(&setup.paths, &[])?;
        assert!(first.written > 0);

        let unowned = setup.paths.generated.join("operator-notes.txt");
        fs::write(&unowned, b"do not replace\n")?;
        let before = snapshot(&setup.paths.generated)?;
        let second = generate(&setup.paths, &[])?;
        let after = snapshot(&setup.paths.generated)?;

        assert_eq!(second.written, 0);
        assert_eq!(before, after);
        assert_eq!(fs::read(unowned)?, b"do not replace\n");
        Ok(())
    }

    #[test]
    fn read_only_check_requires_exact_generated_inventory_and_content()
    -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestDefinitions::new(&[TestFixture::new("alpha", &["src/lib.rs"])])?;
        generate(&setup.paths, &[])?;

        let pristine = snapshot(&setup.paths.generated)?;
        let report = check(&setup.paths, &[])?;
        assert_eq!(report.fixture_count, 1);
        assert_eq!(report.file_count, 2);
        assert_eq!(snapshot(&setup.paths.generated)?, pristine);

        let generated = setup.paths.generated.join("alpha/src/lib.rs");
        fs::remove_file(&generated)?;
        let error = require_check_error(check(&setup.paths, &[]))?;
        assert!(error.contains("missing"));

        generate(&setup.paths, &[])?;
        fs::write(&generated, b"drifted\n")?;
        let error = require_check_error(check(&setup.paths, &[]))?;
        assert!(error.contains("content drifted"));

        generate(&setup.paths, &[])?;
        fs::write(setup.paths.generated.join("obsolete.txt"), b"obsolete\n")?;
        let error = require_check_error(check(&setup.paths, &[]))?;
        assert!(error.contains("unexpected"));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn read_only_check_rejects_a_generated_symlink_without_following_it()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let setup = TestDefinitions::new(&[TestFixture::new("alpha", &["src/lib.rs"])])?;
        generate(&setup.paths, &[])?;
        let generated = setup.paths.generated.join("alpha/src/lib.rs");
        let outside = setup._temporary.path().join("outside.txt");
        fs::write(&outside, b"outside\n")?;
        fs::remove_file(&generated)?;
        symlink(&outside, &generated)?;

        let error = require_check_error(check(&setup.paths, &[]))?;
        assert!(error.contains("symlink"));
        assert_eq!(fs::read(outside)?, b"outside\n");
        Ok(())
    }

    #[test]
    fn lexical_escape_is_rejected_before_any_output_is_written()
    -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestDefinitions::new(&[TestFixture::new("alpha", &["safe.txt"])])?;
        let manifest = setup.paths.definitions.join(SOURCE_MANIFEST_FILE);
        let bytes = fs::read(&manifest)?;
        let mut value: Value = serde_json::from_slice(&bytes)?;
        value["fixtures"][0]["files"] = serde_json::json!(["../outside.txt"]);
        fs::write(&manifest, serde_json::to_vec_pretty(&value)?)?;

        let error = require_generation_error(generate(&setup.paths, &[]))?;
        assert!(error.contains("portable relative fixture path"));
        assert!(!setup.paths.generated.exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn destination_symlink_is_rejected_without_touching_its_target()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let setup = TestDefinitions::new(&[TestFixture::new("alpha", &["safe.txt"])])?;
        fs::create_dir_all(setup.paths.generated.join("alpha"))?;
        let outside = setup._temporary.path().join("outside.txt");
        fs::write(&outside, b"outside\n")?;
        symlink(&outside, setup.paths.generated.join("alpha/safe.txt"))?;

        let error = require_generation_error(generate(&setup.paths, &[]))?;
        assert!(error.contains("symlink"));
        assert_eq!(fs::read(outside)?, b"outside\n");
        Ok(())
    }

    #[test]
    fn materialized_manifest_binds_exact_source_bytes_and_file_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestDefinitions::new(&[TestFixture::new("alpha", &["safe.txt"])])?;
        generate(&setup.paths, &[])?;
        let source = fs::read(setup.paths.definitions.join(SOURCE_MANIFEST_FILE))?;
        let output: Value =
            serde_json::from_slice(&fs::read(setup.paths.generated.join("manifest-v1.json"))?)?;
        assert_eq!(output["source_manifest_identity"], digest(&source));

        let file = fs::read(setup.paths.generated.join("alpha/safe.txt"))?;
        assert_eq!(output["fixtures"][0]["files"][0]["blake3"], digest(&file));
        Ok(())
    }

    #[test]
    fn undeclared_source_file_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let setup = TestDefinitions::new(&[TestFixture::new("alpha", &["safe.txt"])])?;
        fs::write(
            setup.paths.definitions.join("projects/alpha/hidden.txt"),
            b"undeclared\n",
        )?;
        let error = require_generation_error(generate(&setup.paths, &[]))?;
        assert!(error.contains("undeclared"));
        assert!(!setup.paths.generated.exists());
        Ok(())
    }

    #[derive(Clone, Copy)]
    struct TestFixture<'a> {
        id: &'a str,
        files: &'a [&'a str],
    }

    impl<'a> TestFixture<'a> {
        const fn new(id: &'a str, files: &'a [&'a str]) -> Self {
            Self { id, files }
        }
    }

    struct TestDefinitions {
        _temporary: TempDir,
        paths: FixturePaths,
    }

    impl TestDefinitions {
        fn new(fixtures: &[TestFixture<'_>]) -> Result<Self, Box<dyn std::error::Error>> {
            let temporary = tempfile::tempdir()?;
            let fixture_root = temporary.path().join("fixtures");
            let definitions = fixture_root.join("definitions");
            let generated = fixture_root.join("generated");
            fs::create_dir_all(definitions.join("projects"))?;

            let manifest_fixtures: Vec<_> = fixtures
                .iter()
                .map(|fixture| {
                    serde_json::json!({
                        "id": fixture.id,
                        "commands": [{
                            "intent": "test",
                            "program": "tool",
                            "args": ["test"],
                            "cwd": "."
                        }],
                        "files": fixture.files
                    })
                })
                .collect();
            let manifest = serde_json::json!({
                "schema": 1,
                "fixtures": manifest_fixtures
            });
            fs::write(
                definitions.join(SOURCE_MANIFEST_FILE),
                serde_json::to_vec_pretty(&manifest)?,
            )?;
            for fixture in fixtures {
                for path in fixture.files {
                    let output = definitions.join("projects").join(fixture.id).join(path);
                    if let Some(parent) = output.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    fs::write(output, format!("{}/{}\n", fixture.id, path))?;
                }
            }

            Ok(Self {
                _temporary: temporary,
                paths: FixturePaths {
                    definitions,
                    generated,
                },
            })
        }
    }

    type Snapshot = Vec<(String, Vec<u8>)>;

    fn require_generation_error(
        result: Result<super::GenerationReport, String>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        match result {
            Ok(report) => Err(format!("generation unexpectedly succeeded: {report:?}").into()),
            Err(error) => Ok(error),
        }
    }

    fn require_check_error(
        result: Result<super::CheckReport, String>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        match result {
            Ok(report) => Err(format!("fixture check unexpectedly succeeded: {report:?}").into()),
            Err(error) => Ok(error),
        }
    }

    fn snapshot(root: &Path) -> Result<Snapshot, Box<dyn std::error::Error>> {
        let mut output = Vec::new();
        snapshot_at(root, root, &mut output)?;
        output.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(output)
    }

    fn snapshot_at(
        root: &Path,
        directory: &Path,
        output: &mut Vec<(String, Vec<u8>)>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                snapshot_at(root, &path, output)?;
            } else {
                output.push((
                    path.strip_prefix(root)?
                        .to_string_lossy()
                        .replace('\\', "/"),
                    fs::read(path)?,
                ));
            }
        }
        Ok(())
    }
}
