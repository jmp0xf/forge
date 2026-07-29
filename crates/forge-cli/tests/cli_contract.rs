//! End-to-end stdout, stderr, and exit-code contracts for the bootstrap commands.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use forge_runtime::state::{AtomicStateStore, GitStateLayout};
use serde_json::Value;
#[cfg(unix)]
use std::process::Stdio;
#[cfg(unix)]
use std::time::{Duration, Instant};

const MODEL_INTENTS: [&str; 8] = [
    "setup",
    "format-check",
    "format",
    "check",
    "fix",
    "test",
    "verify",
    "build",
];

const STATIC_MAKEFILE: &str = r#".PHONY: setup format-check format check fix test verify build
setup:
	@printf invoked > explain-must-not-run
format-check:
	@printf invoked > explain-must-not-run
format:
	@printf invoked > explain-must-not-run
check:
	@printf invoked > explain-must-not-run
fix:
	@printf invoked > explain-must-not-run
test:
	@printf invoked > explain-must-not-run
verify:
	@printf invoked > explain-must-not-run
build:
	@printf invoked > explain-must-not-run
"#;

#[cfg(not(windows))]
const GENERATED_RUNNER_CASES: [(&str, &str, &str); 3] = [
    ("make", "Makefile", "runner-make-verify"),
    ("just", "justfile", "runner-just-verify"),
    ("task", "Taskfile.yml", "runner-task-verify"),
];
#[cfg(windows)]
const GENERATED_RUNNER_CASES: [(&str, &str, &str); 1] =
    [("task", "Taskfile.yml", "runner-task-verify")];

static NEXT_FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

#[cfg(unix)]
type PrivateStateSnapshot = Vec<(PathBuf, Vec<u8>)>;

#[cfg(unix)]
#[test]
fn timeout_is_one_command_budget_across_successive_git_stages()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = TestWorkspace::plain("command-wide-timeout")?;
    let wrapper_directory = fixture.root.join("support/budget-bin");
    fs::create_dir(&wrapper_directory)?;
    let wrapper = wrapper_directory.join("git");
    let counter = fixture.root.join("support/git-stage-count");
    let second_completed = fixture.root.join("support/second-git-stage-completed");
    let script = format!(
        "#!/bin/sh\nset -eu\ncount=0\nif [ -f {counter} ]; then count=$(/bin/cat {counter}); fi\ncount=$((count + 1))\nprintf '%s' \"$count\" > {counter}\nif [ \"$count\" -eq 1 ]; then\n  /bin/sleep 2\n  printf '%s\\n' {root}\n  exit 0\nfi\n/bin/sleep 3\nprintf completed > {second_completed}\nprintf '%s\\n' {git_dir}\n",
        counter = shell_single_quote(&counter)?,
        root = shell_single_quote(&fixture.worktree)?,
        second_completed = shell_single_quote(&second_completed)?,
        git_dir = shell_single_quote(&fixture.worktree.join(".git"))?,
    );
    fs::write(&wrapper, script)?;
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700))?;

    let output = fixture.run_forge_with_path_prefix(
        &["--timeout", "4s", "explain", "--json"],
        &wrapper_directory,
    )?;

    assert_eq!(
        output.status.code(),
        Some(124),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read_to_string(counter)?, "2");
    assert!(
        !second_completed.exists(),
        "the second Git stage completed after receiving a fresh per-stage timeout"
    );
    let document: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(structured_diagnostic_code(&document)?, "FGE2004");
    Ok(())
}

#[test]
fn overflowing_timeout_is_a_usage_error() -> Result<(), Box<dyn std::error::Error>> {
    let output = run(&["--timeout", "18446744073709551615h", "version", "--json"])?;

    assert_eq!(output.status.code(), Some(64));
    assert!(output.stderr.is_empty());
    let document: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(structured_diagnostic_code(&document)?, "FGE1002");
    Ok(())
}

#[derive(Debug)]
struct TestWorkspace {
    root: PathBuf,
    worktree: PathBuf,
    global_git_config: PathBuf,
    xdg_config_home: PathBuf,
}

impl TestWorkspace {
    fn plain(label: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let fixture_parent =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/cli-contract-fixtures");
        fs::create_dir_all(&fixture_parent)?;
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let fixture_id = NEXT_FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
        let root = fixture_parent.join(format!(
            "{label}-{}-{nonce}-{fixture_id}",
            std::process::id()
        ));
        fs::create_dir(&root)?;

        let worktree = root.join("worktree");
        let support = root.join("support");
        let xdg_config_home = support.join("xdg");
        fs::create_dir(&worktree)?;
        fs::create_dir(&support)?;
        fs::create_dir(&xdg_config_home)?;
        let global_git_config = support.join("global.gitconfig");
        fs::write(&global_git_config, b"")?;

        Ok(Self {
            root,
            worktree,
            global_git_config,
            xdg_config_home,
        })
    }

    fn zero_config_repository(label: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let fixture = Self::plain(label)?;
        fixture.run_git(&["init", "--quiet"])?;

        fs::write(fixture.worktree.join("Makefile"), STATIC_MAKEFILE)?;
        fixture.run_git(&["add", "--", "Makefile"])?;
        fs::write(
            fixture.worktree.join("Makefile"),
            format!("{STATIC_MAKEFILE}# tracked worktree change\n"),
        )?;
        fs::write(
            fixture.worktree.join("untracked-note.txt"),
            b"untracked fixture state\n",
        )?;
        Ok(fixture)
    }

    fn clean_runner_repository(label: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let fixture = Self::plain(label)?;
        fixture.run_git(&["init", "--quiet"])?;
        fs::write(fixture.worktree.join("Makefile"), STATIC_MAKEFILE)?;
        fixture.run_git(&["add", "--", "Makefile"])?;
        fixture.run_git(&[
            "-c",
            "user.name=Forge CLI tests",
            "-c",
            "user.email=forge-cli-tests@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "fixture baseline",
        ])?;
        Ok(fixture)
    }

    fn clean_rust_repository(label: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let fixture = Self::plain(label)?;
        fixture.run_git(&["init", "--quiet"])?;
        fs::create_dir(fixture.worktree.join("src"))?;
        fs::write(
            fixture.worktree.join("Cargo.toml"),
            b"[package]\nname = \"forge-evidence-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[workspace]\n",
        )?;
        fs::write(
            fixture.worktree.join("Cargo.lock"),
            b"# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n\n[[package]]\nname = \"forge-evidence-fixture\"\nversion = \"0.1.0\"\n",
        )?;
        fs::write(fixture.worktree.join(".gitignore"), b"/target/\n")?;
        fs::write(
            fixture.worktree.join("src/lib.rs"),
            b"pub fn answer() -> u8 {\n    42\n}\n",
        )?;
        fixture.run_git(&[
            "add",
            "--",
            ".gitignore",
            "Cargo.lock",
            "Cargo.toml",
            "src/lib.rs",
        ])?;
        fixture.run_git(&[
            "-c",
            "user.name=Forge CLI tests",
            "-c",
            "user.email=forge-cli-tests@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "fixture baseline",
        ])?;
        Ok(fixture)
    }

    fn run_forge(&self, arguments: &[&str]) -> Result<Output, Box<dyn std::error::Error>> {
        let mut command = ProcessCommand::new(env!("CARGO_BIN_EXE_forge"));
        command.current_dir(&self.worktree).args(arguments);
        self.configure_git_environment(&mut command);
        Ok(command.output()?)
    }

    #[cfg(unix)]
    fn run_forge_with_path_prefix(
        &self,
        arguments: &[&str],
        prefix: &Path,
    ) -> Result<Output, Box<dyn std::error::Error>> {
        let inherited_path = std::env::var_os("PATH").unwrap_or_default();
        let path = std::env::join_paths(
            std::iter::once(prefix.to_path_buf()).chain(std::env::split_paths(&inherited_path)),
        )?;
        let mut command = ProcessCommand::new(env!("CARGO_BIN_EXE_forge"));
        command
            .current_dir(&self.worktree)
            .args(arguments)
            .env("PATH", path);
        self.configure_git_environment(&mut command);
        Ok(command.output()?)
    }

    fn git_output(&self, arguments: &[&str]) -> io::Result<Output> {
        let mut command = ProcessCommand::new("git");
        command
            .current_dir(&self.worktree)
            .arg("--no-pager")
            .arg("--no-optional-locks")
            .arg("-c")
            .arg("core.fsmonitor=false")
            .arg("-c")
            .arg("core.autocrlf=false")
            .args(arguments);
        self.configure_git_environment(&mut command);
        command.output()
    }

    fn run_git(&self, arguments: &[&str]) -> io::Result<()> {
        let output = self.git_output(arguments)?;
        if output.status.success() {
            return Ok(());
        }
        Err(io::Error::other(format!(
            "git {arguments:?} failed with status {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim_end()
        )))
    }

    fn configure_git_environment(&self, command: &mut ProcessCommand) {
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
            "GIT_EXEC_PATH",
            "GIT_EXTERNAL_DIFF",
        ] {
            command.env_remove(name);
        }
        command
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", &self.global_git_config)
            .env("GIT_CEILING_DIRECTORIES", &self.root)
            .env("GIT_ATTR_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_PAGER", "cat")
            .env("XDG_CONFIG_HOME", &self.xdg_config_home)
            .env("LC_ALL", "C");
    }

    fn snapshot(&self) -> Result<GitSnapshot, Box<dyn std::error::Error>> {
        Ok(GitSnapshot {
            status: self.successful_git_stdout(&[
                "status",
                "--porcelain=v2",
                "-z",
                "--branch",
                "--untracked-files=all",
            ])?,
            tracked_paths: self.successful_git_stdout(&["ls-files", "--cached", "-z", "--"])?,
            untracked_paths: self.successful_git_stdout(&[
                "ls-files",
                "--others",
                "--exclude-standard",
                "-z",
                "--",
            ])?,
            index_diff: self.successful_git_stdout(&[
                "diff",
                "--cached",
                "--no-ext-diff",
                "--binary",
                "--",
            ])?,
            worktree_diff: self.successful_git_stdout(&[
                "diff",
                "--no-ext-diff",
                "--binary",
                "--",
            ])?,
        })
    }

    fn successful_git_stdout(&self, arguments: &[&str]) -> io::Result<Vec<u8>> {
        let output = self.git_output(arguments)?;
        if output.status.success() {
            return Ok(output.stdout);
        }
        Err(io::Error::other(format!(
            "git {arguments:?} failed with status {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim_end()
        )))
    }

    fn assert_no_forge_artifacts(&self) {
        assert!(!self.worktree.join("forge.toml").exists());
        assert!(!self.worktree.join(".forge").exists());
        assert!(!self.worktree.join("explain-must-not-run").exists());
    }

    fn private_forge_state_dir(&self) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let raw =
            self.successful_git_stdout(&["rev-parse", "--path-format=absolute", "--git-dir"])?;
        let path = String::from_utf8(raw)?;
        Ok(PathBuf::from(path.trim_end()).join("forge"))
    }

    #[cfg(unix)]
    fn git_state_layout(&self) -> Result<GitStateLayout, Box<dyn std::error::Error>> {
        let git_dir = String::from_utf8(self.successful_git_stdout(&[
            "rev-parse",
            "--path-format=absolute",
            "--git-dir",
        ])?)?;
        let common_dir = String::from_utf8(self.successful_git_stdout(&[
            "rev-parse",
            "--path-format=absolute",
            "--git-common-dir",
        ])?)?;
        Ok(GitStateLayout::new(
            PathBuf::from(git_dir.trim_end()),
            PathBuf::from(common_dir.trim_end()),
        ))
    }

    #[cfg(unix)]
    fn private_state_snapshot(&self) -> Result<PrivateStateSnapshot, Box<dyn std::error::Error>> {
        fn visit(
            root: &Path,
            current: &Path,
            entries: &mut Vec<(PathBuf, Vec<u8>)>,
        ) -> io::Result<()> {
            let mut children = current.read_dir()?.collect::<Result<Vec<_>, _>>()?;
            children.sort_by_key(std::fs::DirEntry::file_name);
            for child in children {
                let path = child.path();
                let relative = path
                    .strip_prefix(root)
                    .map_err(io::Error::other)?
                    .to_path_buf();
                let metadata = fs::symlink_metadata(&path)?;
                if metadata.is_dir() {
                    entries.push((relative, Vec::new()));
                    visit(root, &path, entries)?;
                } else if metadata.is_file() {
                    entries.push((relative, fs::read(&path)?));
                } else {
                    entries.push((relative, b"<non-regular>".to_vec()));
                }
            }
            Ok(())
        }

        let root = self.private_forge_state_dir()?;
        if !root.exists() {
            return Ok(Vec::new());
        }
        let mut entries = Vec::new();
        visit(&root, &root, &mut entries)?;
        Ok(entries)
    }

    #[cfg(unix)]
    fn persisted_receipts(&self) -> Result<Vec<(String, Value)>, Box<dyn std::error::Error>> {
        let directory = self.private_forge_state_dir()?.join("receipts/v2");
        if !directory.exists() {
            return Ok(Vec::new());
        }
        let mut paths = directory
            .read_dir()?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<Vec<_>, _>>()?;
        paths.sort();
        paths
            .into_iter()
            .map(|path| {
                let name = path
                    .file_name()
                    .and_then(std::ffi::OsStr::to_str)
                    .ok_or_else(|| io::Error::other("Receipt filename is not UTF-8"))?
                    .to_owned();
                let document = serde_json::from_slice(&fs::read(path)?)?;
                Ok((name, document))
            })
            .collect()
    }

    fn generated_manifest_path(&self) -> Result<PathBuf, Box<dyn std::error::Error>> {
        Ok(self.private_forge_state_dir()?.join("generated-v1.json"))
    }
}

impl Drop for TestWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[derive(Debug, PartialEq, Eq)]
struct GitSnapshot {
    status: Vec<u8>,
    tracked_paths: Vec<u8>,
    untracked_paths: Vec<u8>,
    index_diff: Vec<u8>,
    worktree_diff: Vec<u8>,
}

fn run(arguments: &[&str]) -> Result<Output, Box<dyn std::error::Error>> {
    Ok(ProcessCommand::new(env!("CARGO_BIN_EXE_forge"))
        .args(arguments)
        .output()?)
}

fn native_repository_path(components: &[&str]) -> String {
    components
        .iter()
        .collect::<PathBuf>()
        .to_string_lossy()
        .into_owned()
}

#[cfg(unix)]
fn executable_on_path(program: &str) -> io::Result<PathBuf> {
    let path = std::env::var_os("PATH")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "PATH is unavailable"))?;
    std::env::split_paths(&path)
        .map(|directory| directory.join(program))
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("`{program}` is unavailable on PATH"),
            )
        })
}

#[cfg(unix)]
fn shell_single_quote(path: &Path) -> io::Result<String> {
    let value = path.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "fixture path is not valid UTF-8",
        )
    })?;
    Ok(format!("'{}'", value.replace('\'', "'\\''")))
}

fn required_object<'a>(
    parent: &'a Value,
    key: &str,
) -> Result<&'a serde_json::Map<String, Value>, Box<dyn std::error::Error>> {
    parent
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| io::Error::other(format!("JSON object `{key}` is missing")).into())
}

fn required_array<'a>(
    parent: &'a Value,
    key: &str,
) -> Result<&'a Vec<Value>, Box<dyn std::error::Error>> {
    parent
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| io::Error::other(format!("JSON array `{key}` is missing")).into())
}

fn required_doctor_check<'a>(
    document: &'a Value,
    id: &str,
) -> Result<&'a Value, Box<dyn std::error::Error>> {
    required_array(&document["data"], "checks")?
        .iter()
        .find(|check| check["id"] == id)
        .ok_or_else(|| io::Error::other(format!("doctor check `{id}` is missing")).into())
}

fn assert_confidence(value: &Value, context: &str) -> Result<(), Box<dyn std::error::Error>> {
    let confidence = value
        .as_str()
        .ok_or_else(|| io::Error::other(format!("{context} confidence is not a string")))?;
    assert!(
        matches!(confidence, "low" | "medium" | "high" | "unknown"),
        "unexpected {context} confidence: {confidence}"
    );
    Ok(())
}

fn assert_provenance(value: &Value, context: &str) -> Result<(), Box<dyn std::error::Error>> {
    let provenance = value
        .as_array()
        .ok_or_else(|| io::Error::other(format!("{context} provenance is not an array")))?;
    assert!(!provenance.is_empty(), "{context} provenance is empty");
    for source in provenance {
        let source = source
            .as_object()
            .ok_or_else(|| io::Error::other(format!("{context} provenance is not structured")))?;
        assert!(
            source
                .get("rule_id")
                .and_then(Value::as_str)
                .is_some_and(|rule| !rule.is_empty()),
            "{context} provenance has no rule_id"
        );
        assert!(
            source
                .get("detail")
                .and_then(Value::as_str)
                .is_some_and(|detail| !detail.is_empty()),
            "{context} provenance has no detail"
        );
    }
    Ok(())
}

fn assert_derivation_evidence(data: &Value, key: &str) -> Result<(), Box<dyn std::error::Error>> {
    let evidence = data
        .get(key)
        .ok_or_else(|| io::Error::other(format!("model evidence `{key}` is missing")))?;
    assert_provenance(&evidence["provenance"], key)?;
    assert_confidence(&evidence["confidence"], key)
}

fn assert_complete_model_contract(document: &Value) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(document["schema"], "forge.model/v1");
    assert_eq!(document["ok"], true);
    assert_eq!(document["truncated"], false);
    assert!(document["artifacts"].as_array().is_some_and(Vec::is_empty));

    let data = document
        .get("data")
        .ok_or_else(|| io::Error::other("model envelope has no data"))?;
    assert!(
        data["repository"]
            .as_str()
            .is_some_and(|repository| !repository.is_empty())
    );
    assert!(
        data["work_state"]
            .as_str()
            .is_some_and(|state| !state.is_empty())
    );
    required_array(data, "units")?;

    for key in [
        "repository_evidence",
        "unit_inventory_evidence",
        "asset_inventory_evidence",
        "adapter_inventory_evidence",
        "policy_evidence",
    ] {
        assert_derivation_evidence(data, key)?;
    }

    let commands = required_object(data, "commands")?;
    let command_sets = required_object(data, "command_sets")?;
    assert_eq!(commands.len(), MODEL_INTENTS.len());
    assert_eq!(command_sets.len(), MODEL_INTENTS.len());
    for intent in MODEL_INTENTS {
        assert!(
            commands.contains_key(intent),
            "missing command intent {intent}"
        );
        let command_set = command_sets
            .get(intent)
            .ok_or_else(|| io::Error::other(format!("missing command set for {intent}")))?;
        assert_eq!(
            command_set["resolution"], "resolved",
            "static Make target {intent} did not resolve"
        );
        assert!(
            command_set["candidates"]
                .as_array()
                .is_some_and(|candidates| !candidates.is_empty()),
            "resolved intent {intent} has no candidate"
        );
        assert_provenance(&command_set["provenance"], &format!("command set {intent}"))?;
        assert_confidence(
            &command_set["resolution_confidence"],
            &format!("command set {intent} resolution"),
        )?;
        assert_confidence(
            &command_set["coverage_confidence"],
            &format!("command set {intent} coverage"),
        )?;
    }

    for (legacy_key, detail_key) in [
        ("units", "unit_details"),
        ("assets", "asset_details"),
        ("adapters", "adapter_details"),
        ("assumptions", "assumption_details"),
    ] {
        assert_eq!(
            required_array(data, legacy_key)?.len(),
            required_array(data, detail_key)?.len(),
            "{detail_key} must accompany every {legacy_key} entry"
        );
    }
    for detail in required_array(data, "asset_details")? {
        assert_provenance(&detail["provenance"], "asset detail")?;
        assert_confidence(&detail["confidence"], "asset detail")?;
    }
    for detail in required_array(data, "adapter_details")? {
        assert_provenance(&detail["provenance"], "adapter detail")?;
        assert_confidence(&detail["confidence"], "adapter detail")?;
    }
    for detail in required_array(data, "assumption_details")? {
        assert_provenance(&detail["provenance"], "assumption detail")?;
        assert_confidence(&detail["confidence"], "assumption detail")?;
    }
    Ok(())
}

fn structured_diagnostic_code(document: &Value) -> Result<String, Box<dyn std::error::Error>> {
    assert_eq!(document["schema"], "forge.diagnostic/v1");
    assert_eq!(document["ok"], false);
    let diagnostic = required_array(document, "diagnostics")?
        .first()
        .ok_or_else(|| io::Error::other("diagnostic envelope has no diagnostic"))?;
    let code = diagnostic["code"]
        .as_str()
        .ok_or_else(|| io::Error::other("diagnostic has no code"))?;
    for field in ["what", "where", "why", "next"] {
        assert!(
            diagnostic[field]
                .as_str()
                .is_some_and(|text| !text.is_empty()),
            "diagnostic field `{field}` is missing"
        );
    }
    Ok(code.to_owned())
}

fn assert_json_diagnostic_failure(
    output: &Output,
    expected_exit: i32,
    expected_code: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        output.status.code(),
        Some(expected_exit),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "JSON failure leaked output to stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Parsing the complete byte slice rejects a second JSON document or any non-whitespace
    // process output before or after the diagnostic envelope.
    let document: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(structured_diagnostic_code(&document)?, expected_code);
    assert_eq!(required_array(&document, "diagnostics")?.len(), 1);
    Ok(())
}

#[test]
fn version_human_output_is_stable_and_quiet() -> Result<(), Box<dyn std::error::Error>> {
    let output = run(&["version"])?;

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8(output.stdout)?, "forge 0.1.0-rc.1\n");
    assert!(output.stderr.is_empty());
    Ok(())
}

#[test]
fn version_json_is_one_clean_versioned_envelope() -> Result<(), Box<dyn std::error::Error>> {
    let output = run(&["version", "--json"])?;

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let document: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(document["schema"], "forge.version/v1");
    assert_eq!(document["ok"], true);
    assert_eq!(document["data"]["name"], "forge");
    assert_eq!(document["data"]["version"], "0.1.0-rc.1");
    Ok(())
}

#[test]
fn clap_meta_requests_preserve_the_single_json_document_contract()
-> Result<(), Box<dyn std::error::Error>> {
    for arguments in [
        &["--json", "--help"][..],
        &["--format", "json", "--help"][..],
        &["--format=json", "--help"][..],
        &["--json", "help"][..],
        &["--json"][..],
    ] {
        let output = run(arguments)?;
        assert_eq!(
            output.status.code(),
            Some(0),
            "arguments={arguments:?} stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty(), "arguments={arguments:?}");
        let document: Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(document["schema"], "forge.diagnostic/v1");
        assert_eq!(document["ok"], true);
        assert_eq!(document["data"]["diagnostic"]["code"], "FGE0009");
        assert_eq!(document["data"]["diagnostic"]["severity"], "info");
        assert!(
            document["data"]["diagnostic"]["why"]
                .as_str()
                .is_some_and(|help| help.contains("Usage:")),
            "arguments={arguments:?} document={document:#}"
        );
    }

    for arguments in [
        &["--json", "--version"][..],
        &["--format", "json", "--version"][..],
        &["--format=json", "--version"][..],
    ] {
        let output = run(arguments)?;
        assert_eq!(output.status.code(), Some(0), "arguments={arguments:?}");
        assert!(output.stderr.is_empty(), "arguments={arguments:?}");
        let document: Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(document["schema"], "forge.version/v1");
        assert_eq!(document["ok"], true);
    }
    Ok(())
}

#[test]
fn schema_list_json_uses_its_own_contract() -> Result<(), Box<dyn std::error::Error>> {
    let output = run(&["schema", "--json"])?;

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let document: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(document["schema"], "forge.schema-index/v1");
    assert!(
        document["data"]["schemas"]
            .as_array()
            .is_some_and(|schemas| schemas.len() >= 10)
    );
    Ok(())
}

#[test]
fn one_schema_is_emitted_as_a_valid_json_schema() -> Result<(), Box<dyn std::error::Error>> {
    let output = run(&["schema", "doctor"])?;

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let document: Value = serde_json::from_slice(&output.stdout)?;
    assert!(document.get("$schema").is_some());
    Ok(())
}

#[test]
fn json_usage_error_never_pollutes_stdout() -> Result<(), Box<dyn std::error::Error>> {
    let output = run(&["unknown-command", "--json"])?;

    assert_eq!(output.status.code(), Some(64));
    assert!(output.stderr.is_empty());
    let document: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(document["schema"], "forge.diagnostic/v1");
    assert_eq!(document["ok"], false);
    assert_eq!(document["diagnostics"][0]["code"], "FGE0001");
    Ok(())
}

#[test]
fn version_output_selection_failure_is_one_clean_structured_diagnostic()
-> Result<(), Box<dyn std::error::Error>> {
    // `version` has no product-domain failure path. This deliberately covers the shared output
    // selection boundary after Clap has selected the Version command.
    let output = run(&["version", "--json", "--format", "human"])?;

    assert_json_diagnostic_failure(&output, 64, "FGE0002")
}

#[test]
fn schema_unknown_kind_is_one_clean_structured_diagnostic() -> Result<(), Box<dyn std::error::Error>>
{
    let output = run(&["schema", "definitely-unknown", "--json"])?;

    assert_json_diagnostic_failure(&output, 64, "FGE0004")
}

#[test]
fn completions_json_is_one_clean_structured_diagnostic() -> Result<(), Box<dyn std::error::Error>> {
    let output = run(&["completions", "bash", "--json"])?;

    assert_json_diagnostic_failure(&output, 64, "FGE0005")
}

#[test]
fn evidence_export_outside_git_is_a_structured_failure_without_writes()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::plain("evidence-export-no-git")?;
    assert_eq!(fs::read_dir(&fixture.worktree)?.count(), 0);

    let output = fixture.run_forge(&["evidence", "export", "--json"])?;

    assert_json_diagnostic_failure(&output, 2, "FGE2001")?;
    assert_eq!(fs::read_dir(&fixture.worktree)?.count(), 0);
    fixture.assert_no_forge_artifacts();
    Ok(())
}

#[test]
fn init_defaults_to_a_deterministic_read_only_plan() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::zero_config_repository("init-dry-run")?;
    let before = fixture.snapshot()?;
    let private_state = fixture.private_forge_state_dir()?;
    assert!(!private_state.exists());

    let first = fixture.run_forge(&["init", "--json"])?;
    let second = fixture.run_forge(&["init", "--json"])?;

    assert_eq!(first.status.code(), Some(0));
    assert_eq!(second.status.code(), Some(0));
    assert!(first.stderr.is_empty());
    assert!(second.stderr.is_empty());
    assert_eq!(first.stdout, second.stdout);
    let document: Value = serde_json::from_slice(&first.stdout)?;
    assert_eq!(document["schema"], "forge.init-plan/v1");
    assert_eq!(document["ok"], true);
    assert!(required_array(&document, "diagnostics")?.is_empty());
    let edits = required_array(&document["data"], "edits")?;
    assert_eq!(edits.len(), 1);
    assert_eq!(edits[0]["kind"], "create");
    assert_eq!(edits[0]["path"]["display"], "AGENTS.md");
    assert_eq!(fixture.snapshot()?, before);
    assert!(!fixture.worktree.join("AGENTS.md").exists());
    assert!(!private_state.exists());
    fixture.assert_no_forge_artifacts();
    Ok(())
}

#[test]
fn explicit_github_ci_apply_is_create_only_active_and_idempotent()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::clean_runner_repository("init-github-ci")?;

    let applied = fixture.run_forge(&["init", "--with-ci", "github", "--apply", "--json"])?;

    assert_eq!(
        applied.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&applied.stdout),
        String::from_utf8_lossy(&applied.stderr)
    );
    assert!(applied.stderr.is_empty());
    let document: Value = serde_json::from_slice(&applied.stdout)?;
    let edits = required_array(&document["data"], "edits")?;
    let workflow_display = native_repository_path(&[".github", "workflows", "verify.yml"]);
    let workflow_edit = edits
        .iter()
        .find(|edit| edit["path"]["display"] == workflow_display)
        .ok_or("missing GitHub workflow create edit")?;
    assert_eq!(workflow_edit["kind"], "create");

    let workflow_path = fixture.worktree.join(".github/workflows/verify.yml");
    let workflow = fs::read_to_string(&workflow_path)?;
    assert!(workflow.contains("on:\n  workflow_dispatch:"));
    assert!(workflow.contains("permissions:\n  contents: read\n"));
    assert!(workflow.contains("runs-on: ubuntu-24.04"));
    assert!(
        workflow.contains("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1")
    );
    assert!(workflow.contains("persist-credentials: false"));
    for forbidden in [
        "pull_request:",
        "push:",
        "matrix:",
        "cache",
        "secrets:",
        "release",
        "forge evidence",
    ] {
        assert!(
            !workflow.contains(forbidden),
            "unexpected `{forbidden}` in {workflow}"
        );
    }

    let second = fixture.run_forge(&["init", "--with-ci", "github", "--json"])?;
    assert_eq!(second.status.code(), Some(0));
    let second_document: Value = serde_json::from_slice(&second.stdout)?;
    assert!(required_array(&second_document["data"], "edits")?.is_empty());
    assert_eq!(fs::read_to_string(&workflow_path)?, workflow);

    fs::write(
        &workflow_path,
        format!("# repository-owned comment\n{workflow}"),
    )?;
    let commented = fs::read(&workflow_path)?;
    let semantic = fixture.run_forge(&["init", "--with-ci", "github", "--json"])?;
    assert_eq!(semantic.status.code(), Some(0));
    let semantic_document: Value = serde_json::from_slice(&semantic.stdout)?;
    assert!(required_array(&semantic_document["data"], "edits")?.is_empty());
    assert_eq!(fs::read(&workflow_path)?, commented);
    Ok(())
}

#[cfg(unix)]
#[test]
fn init_apply_write_failure_does_not_create_private_state() -> Result<(), Box<dyn std::error::Error>>
{
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = TestWorkspace::clean_runner_repository("init-write-failure-no-state")?;
    let workflow_directory = fixture.worktree.join(".github/workflows");
    fs::create_dir_all(&workflow_directory)?;
    let original_permissions = fs::metadata(&workflow_directory)?.permissions();
    fs::set_permissions(&workflow_directory, fs::Permissions::from_mode(0o500))?;

    let output = fixture.run_forge(&["init", "--with-ci", "github", "--apply", "--json"]);
    fs::set_permissions(&workflow_directory, original_permissions)?;
    let output = output?;

    assert_json_diagnostic_failure(&output, 2, "FGE2212")?;
    assert!(
        !fixture.private_forge_state_dir()?.exists(),
        "a failed repository write must not create Git-private Forge state"
    );
    assert!(
        !fixture.worktree.join("AGENTS.md").exists(),
        "the lexically first blocked CI target must fail before later edits"
    );
    assert!(!workflow_directory.join("verify.yml").exists());
    Ok(())
}

#[test]
fn explicit_github_ci_rejects_non_equivalent_and_unknown_existing_targets_without_writes()
-> Result<(), Box<dyn std::error::Error>> {
    for (label, content, expected_why) in [
        (
            "different",
            "name: repository-ci\non: workflow_dispatch\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make test\n",
            "valid but not semantically equal",
        ),
        ("unknown", "jobs: [\n", "equivalence is unknown"),
    ] {
        let fixture = TestWorkspace::clean_runner_repository(&format!("init-github-ci-{label}"))?;
        let workflow_directory = fixture.worktree.join(".github/workflows");
        fs::create_dir_all(&workflow_directory)?;
        fs::write(workflow_directory.join("verify.yml"), content)?;
        fixture.run_git(&["add", "--", ".github/workflows/verify.yml"])?;
        fixture.run_git(&[
            "-c",
            "user.name=Forge CLI tests",
            "-c",
            "user.email=forge-cli-tests@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "existing CI",
        ])?;
        let before = fixture.snapshot()?;

        let output = fixture.run_forge(&["init", "--with-ci", "github", "--json"])?;

        assert_eq!(
            output.status.code(),
            Some(65),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        let diagnostic: Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(structured_diagnostic_code(&diagnostic)?, "FGE1230");
        assert!(
            diagnostic["diagnostics"][0]["why"]
                .as_str()
                .is_some_and(|why| why.contains(expected_why))
        );
        assert_eq!(fixture.snapshot()?, before);
        assert!(!fixture.worktree.join("AGENTS.md").exists());
        fixture.assert_no_forge_artifacts();
    }
    Ok(())
}

#[test]
fn init_reports_absent_project_commands_without_changing_the_plan_schema()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::plain("init-missing-project-command")?;
    fixture.run_git(&["init", "--quiet"])?;
    fs::write(
        fixture.worktree.join("Makefile"),
        b".PHONY: test\ntest:\n\t@printf test\n",
    )?;
    fixture.run_git(&["add", "--", "Makefile"])?;
    let before = fixture.snapshot()?;

    let output = fixture.run_forge(&["init", "--json"])?;

    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let document: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(document["schema"], "forge.init-plan/v1");
    assert!(document["data"].get("diagnostics").is_none());
    let diagnostic = required_array(&document, "diagnostics")?
        .iter()
        .find(|diagnostic| {
            diagnostic["code"] == "FGE2232" && diagnostic["where"] == "project command `verify`"
        })
        .ok_or("missing verify command diagnostic")?;
    assert_eq!(diagnostic["severity"], "warning");
    assert_eq!(diagnostic["what"], "project command `verify` is absent");
    assert!(
        diagnostic["why"]
            .as_str()
            .is_some_and(|why| why.contains("resolution provenance:"))
    );
    assert!(
        diagnostic["next"]
            .as_str()
            .is_some_and(|next| next.contains("[commands.verify]"))
    );
    assert_eq!(fixture.snapshot()?, before);
    fixture.assert_no_forge_artifacts();

    let human = fixture.run_forge(&["init"])?;
    assert_eq!(human.status.code(), Some(0));
    assert!(human.stderr.is_empty());
    let stdout = String::from_utf8(human.stdout)?;
    assert!(stdout.contains("warnings:"));
    assert!(stdout.contains("warning[FGE2232]: project command `verify` is absent"));
    assert_eq!(fixture.snapshot()?, before);
    Ok(())
}

#[test]
fn init_reports_ambiguous_project_commands_without_selecting_a_candidate()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::plain("init-ambiguous-project-command")?;
    fixture.run_git(&["init", "--quiet"])?;
    fs::write(
        fixture.worktree.join("Makefile"),
        b".PHONY: check test\ncheck:\n\t@printf check\ntest:\n\t@printf make\n",
    )?;
    fs::write(
        fixture.worktree.join("justfile"),
        b"test:\n    @printf just\n",
    )?;
    fixture.run_git(&["add", "--", "Makefile", "justfile"])?;
    let before = fixture.snapshot()?;

    let output = fixture.run_forge(&["init", "--json"])?;

    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let document: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(document["schema"], "forge.init-plan/v1");
    assert!(document["data"].get("diagnostics").is_none());
    let diagnostic = required_array(&document, "diagnostics")?
        .iter()
        .find(|diagnostic| {
            diagnostic["code"] == "FGE2233" && diagnostic["where"] == "project command `test`"
        })
        .ok_or("missing ambiguous test command diagnostic")?;
    assert_eq!(diagnostic["severity"], "warning");
    assert_eq!(diagnostic["what"], "project command `test` is ambiguous");
    assert!(
        diagnostic["why"]
            .as_str()
            .is_some_and(|why| why.contains("2 equally authoritative candidates"))
    );
    assert!(
        diagnostic["next"]
            .as_str()
            .is_some_and(|next| next.contains("[commands.test]"))
    );
    assert_eq!(fixture.snapshot()?, before);
    fixture.assert_no_forge_artifacts();
    Ok(())
}

#[test]
fn init_reports_unknown_project_commands_without_guessing_configuration()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::plain("init-unknown-project-command")?;
    fixture.run_git(&["init", "--quiet"])?;
    fs::create_dir(fixture.worktree.join("src"))?;
    fs::write(
        fixture.worktree.join("Cargo.toml"),
        b"[package]\nname = \"unknown-command-fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )?;
    fs::write(fixture.worktree.join("src/lib.rs"), b"pub fn value() {}\n")?;
    fs::write(
        fixture.worktree.join("Makefile"),
        b"test:\ninclude commands.mk\n",
    )?;
    fixture.run_git(&["add", "--", "Cargo.toml", "Makefile", "src/lib.rs"])?;
    let before = fixture.snapshot()?;

    let output = fixture.run_forge(&["init", "--json"])?;

    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let document: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(document["schema"], "forge.init-plan/v1");
    assert!(document["data"].get("diagnostics").is_none());
    let diagnostic = required_array(&document, "diagnostics")?
        .iter()
        .find(|diagnostic| {
            diagnostic["code"] == "FGE2234" && diagnostic["where"] == "project command `test`"
        })
        .ok_or("missing unknown test command diagnostic")?;
    assert_eq!(diagnostic["severity"], "warning");
    assert_eq!(
        diagnostic["what"],
        "project command `test` cannot be inferred safely"
    );
    assert!(
        diagnostic["why"]
            .as_str()
            .is_some_and(|why| why.contains("command resolution remains unknown"))
    );
    assert!(
        diagnostic["next"]
            .as_str()
            .is_some_and(|next| next.contains("[commands.test]") && next.contains("will not guess"))
    );
    assert_eq!(fixture.snapshot()?, before);
    fixture.assert_no_forge_artifacts();
    Ok(())
}

#[test]
fn adapter_config_booleans_override_automatic_init_selection()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::clean_runner_repository("init-adapter-overrides")?;
    fs::write(
        fixture.worktree.join("forge.toml"),
        b"schema = 1\n\n[adapters]\nagents = false\nclaude = false\n",
    )?;
    fixture.run_git(&["add", "--", "forge.toml"])?;
    fixture.run_git(&[
        "-c",
        "user.name=Forge CLI tests",
        "-c",
        "user.email=forge-cli-tests@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "disable automatic adapters",
    ])?;

    let disabled = fixture.run_forge(&["init", "--json"])?;
    assert_eq!(
        disabled.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&disabled.stdout),
        String::from_utf8_lossy(&disabled.stderr)
    );
    let disabled_document: Value = serde_json::from_slice(&disabled.stdout)?;
    assert!(required_array(&disabled_document["data"], "edits")?.is_empty());
    assert!(!fixture.worktree.join("AGENTS.md").exists());
    assert!(!fixture.worktree.join("CLAUDE.md").exists());

    fs::write(
        fixture.worktree.join("forge.toml"),
        b"schema = 1\n\n[adapters]\nagents = true\nclaude = true\n",
    )?;
    fixture.run_git(&["add", "--", "forge.toml"])?;
    fixture.run_git(&[
        "-c",
        "user.name=Forge CLI tests",
        "-c",
        "user.email=forge-cli-tests@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "enable automatic adapters",
    ])?;

    let enabled = fixture.run_forge(&["init", "--apply", "--json"])?;
    assert_eq!(
        enabled.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&enabled.stdout),
        String::from_utf8_lossy(&enabled.stderr)
    );
    let enabled_document: Value = serde_json::from_slice(&enabled.stdout)?;
    assert_eq!(required_array(&enabled_document["data"], "edits")?.len(), 2);
    assert!(fixture.worktree.join("AGENTS.md").is_file());
    assert!(fixture.worktree.join("CLAUDE.md").is_file());
    Ok(())
}

#[test]
fn init_apply_rejects_dirty_state_without_writing() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::zero_config_repository("init-dirty-rejected")?;
    let before = fixture.snapshot()?;

    let output = fixture.run_forge(&["init", "--apply"])?;

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8(output.stderr)?.contains("error[FGE2205]"));
    assert_eq!(fixture.snapshot()?, before);
    assert!(!fixture.worktree.join("AGENTS.md").exists());
    fixture.assert_no_forge_artifacts();
    Ok(())
}

#[test]
fn init_apply_is_brownfield_safe_and_second_plan_is_empty() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = TestWorkspace::clean_runner_repository("init-apply")?;
    let makefile_before = fs::read(fixture.worktree.join("Makefile"))?;
    assert!(!fixture.worktree.join("forge.toml").exists());

    let applied = fixture.run_forge(&["init", "--apply", "--json"])?;

    assert_eq!(applied.status.code(), Some(0));
    assert!(applied.stderr.is_empty());
    let applied_document: Value = serde_json::from_slice(&applied.stdout)?;
    assert_eq!(applied_document["schema"], "forge.init-plan/v1");
    assert_eq!(required_array(&applied_document["data"], "edits")?.len(), 1);
    let agents = fs::read_to_string(fixture.worktree.join("AGENTS.md"))?;
    assert!(agents.contains("<!-- forge:begin block=project-index schema=1"));
    assert!(agents.contains("## Project-native commands"));
    assert_eq!(
        fs::read(fixture.worktree.join("Makefile"))?,
        makefile_before
    );
    assert!(!fixture.worktree.join("explain-must-not-run").exists());
    assert!(
        !fixture.worktree.join("forge.toml").exists(),
        "zero-config init must not create a Forge configuration file"
    );
    let manifest_bytes = fs::read(fixture.generated_manifest_path()?)?;
    let manifest: Value = serde_json::from_slice(&manifest_bytes)?;
    assert_eq!(manifest["schema"], 1);
    assert_eq!(manifest["behavior_version"], "managed-markdown-v2");
    assert_eq!(manifest["adapters"][0]["path"]["display"], "AGENTS.md");
    assert!(
        !String::from_utf8_lossy(&manifest_bytes).contains(&fixture.worktree.display().to_string())
    );

    let second = fixture.run_forge(&["init", "--json"])?;
    assert_eq!(second.status.code(), Some(0));
    assert!(second.stderr.is_empty());
    let second_document: Value = serde_json::from_slice(&second.stdout)?;
    assert!(required_array(&second_document["data"], "edits")?.is_empty());

    let second_apply = fixture.run_forge(&["init", "--apply", "--allow-dirty", "--json"])?;
    assert_eq!(second_apply.status.code(), Some(0));
    let second_apply_document: Value = serde_json::from_slice(&second_apply.stdout)?;
    assert!(required_array(&second_apply_document["data"], "edits")?.is_empty());
    assert_eq!(
        fs::read_to_string(fixture.worktree.join("AGENTS.md"))?,
        agents
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn init_postcheck_rejects_changed_repository_layout_after_verified_apply()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = TestWorkspace::clean_rust_repository("init-postcheck-layout-changed")?;
    let real_git = executable_on_path("git")?;
    let alternate_worktree = fixture.root.join("support/alternate-worktree");
    fs::create_dir(&alternate_worktree)?;
    let mut init_alternate = ProcessCommand::new(&real_git);
    init_alternate
        .current_dir(&alternate_worktree)
        .args(["init", "--quiet"]);
    fixture.configure_git_environment(&mut init_alternate);
    let initialized = init_alternate.output()?;
    assert!(
        initialized.status.success(),
        "alternate git init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&initialized.stdout),
        String::from_utf8_lossy(&initialized.stderr)
    );

    let wrapper_directory = fixture.root.join("support/layout-bin");
    fs::create_dir(&wrapper_directory)?;
    let wrapper = wrapper_directory.join("git");
    let agents = fixture.worktree.join("AGENTS.md");
    let switched = fixture.root.join("support/layout-switched");
    let alternate_git_dir = alternate_worktree.join(".git");
    let script = format!(
        "#!/bin/sh\nset -eu\nif [ -f {agents} ]; then\n  if [ ! -f {switched} ]; then printf '%s\\n' switched > {switched}; fi\n  exec {real_git} --git-dir={alternate_git_dir} --work-tree={worktree} \"$@\"\nfi\nexec {real_git} \"$@\"\n",
        agents = shell_single_quote(&agents)?,
        switched = shell_single_quote(&switched)?,
        real_git = shell_single_quote(&real_git)?,
        alternate_git_dir = shell_single_quote(&alternate_git_dir)?,
        worktree = shell_single_quote(&fixture.worktree)?,
    );
    fs::write(&wrapper, script)?;
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700))?;

    let output =
        fixture.run_forge_with_path_prefix(&["init", "--apply", "--json"], &wrapper_directory)?;

    assert_json_diagnostic_failure(&output, 70, "FGE0210")?;
    let document: Value = serde_json::from_slice(&output.stdout)?;
    let diagnostic = &required_array(&document, "diagnostics")?[0];
    assert_eq!(diagnostic["where"], "init post-check");
    assert!(
        diagnostic["why"].as_str().is_some_and(|why| {
            why.contains("apply report: written=[")
                && why.contains("AGENTS.md(kind=create")
                && why.contains("verified=true")
        }),
        "post-apply write progress was missing: {diagnostic:#}"
    );
    assert!(
        diagnostic["next"]
            .as_str()
            .is_some_and(|next| next.contains("treat the reported write progress as authoritative"))
    );
    assert!(
        switched.is_file(),
        "the post-apply Git layout was never selected"
    );
    assert!(
        agents.is_file(),
        "the verified apply was unexpectedly rolled back"
    );
    assert!(
        !fixture.generated_manifest_path()?.exists(),
        "repository-layout failure must precede adapter-manifest persistence"
    );
    assert!(
        !fixture.private_forge_state_dir()?.exists(),
        "post-check failure must not leave a newly created private state directory"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn init_postcheck_rejects_nonconvergent_output_after_verified_apply()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = TestWorkspace::clean_rust_repository("init-postcheck-nonconvergent")?;
    let wrapper_directory = fixture.root.join("support/nonconvergent-bin");
    fs::create_dir(&wrapper_directory)?;
    let wrapper = wrapper_directory.join("git");
    let agents = fixture.worktree.join("AGENTS.md");
    let changed = fixture.root.join("support/agents-changed-after-apply");
    let real_git = executable_on_path("git")?;
    let injected = b"# Concurrent edit after Forge apply\n";
    let script = format!(
        "#!/bin/sh\nset -eu\nif [ -f {agents} ] && [ ! -f {changed} ]; then\n  printf '%s\\n' changed > {changed}\n  printf '%s\\n' '# Concurrent edit after Forge apply' > {agents}\nfi\nexec {real_git} \"$@\"\n",
        agents = shell_single_quote(&agents)?,
        changed = shell_single_quote(&changed)?,
        real_git = shell_single_quote(&real_git)?,
    );
    fs::write(&wrapper, script)?;
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700))?;

    let output =
        fixture.run_forge_with_path_prefix(&["init", "--apply", "--json"], &wrapper_directory)?;

    assert_json_diagnostic_failure(&output, 70, "FGE0211")?;
    let document: Value = serde_json::from_slice(&output.stdout)?;
    let diagnostic = &required_array(&document, "diagnostics")?[0];
    assert_eq!(diagnostic["where"], "init post-check");
    assert!(
        diagnostic["why"].as_str().is_some_and(|why| {
            why.contains("a fresh detection still planned edits for [AGENTS.md]")
                && why.contains("apply report: written=[")
                && why.contains("AGENTS.md(kind=create")
                && why.contains("verified=true")
        }),
        "post-check convergence or write progress was missing: {diagnostic:#}"
    );
    assert!(
        diagnostic["next"]
            .as_str()
            .is_some_and(|next| next.contains("treat the reported write progress as authoritative"))
    );
    assert!(changed.is_file(), "the post-apply edit was never injected");
    assert_eq!(fs::read(&agents)?, injected);
    assert!(
        !fixture.generated_manifest_path()?.exists(),
        "convergence failure must precede adapter-manifest persistence"
    );
    assert!(
        !fixture.private_forge_state_dir()?.exists(),
        "convergence failure must not leave a newly created private state directory"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn portable_script_command_is_identical_in_model_receipt_and_agents()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::clean_rust_repository("portable-script-command")?;
    fs::create_dir(fixture.worktree.join("scripts"))?;
    fs::write(
        fixture.worktree.join("scripts/test.sh"),
        b"#!/usr/bin/env bash\nexit 0\n",
    )?;
    fixture.run_git(&["add", "--", "scripts/test.sh"])?;
    fixture.run_git(&[
        "-c",
        "user.name=Forge CLI tests",
        "-c",
        "user.email=forge-cli-tests@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "add project test entrypoint",
    ])?;

    let explained = fixture.run_forge(&["explain", "--json"])?;
    assert_eq!(explained.status.code(), Some(0));
    let model: Value = serde_json::from_slice(&explained.stdout)?;
    let candidate = &model["data"]["command_sets"]["test"]["candidates"][0]["command"];
    assert_eq!(candidate["program"], "bash");
    assert_eq!(candidate["args"], serde_json::json!(["scripts/test.sh"]));

    let observed = fixture.run_forge(&["evidence", "run", "test", "--json"])?;
    assert_eq!(
        observed.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&observed.stdout),
        String::from_utf8_lossy(&observed.stderr)
    );
    let receipt: Value = serde_json::from_slice(&observed.stdout)?;
    let receipt_command = &receipt["data"]["observations"][0]["command"]["command"];
    assert_eq!(receipt_command, candidate);

    let initialized = fixture.run_forge(&["init", "--apply", "--json"])?;
    assert_eq!(
        initialized.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&initialized.stdout),
        String::from_utf8_lossy(&initialized.stderr)
    );
    let agents = fs::read_to_string(fixture.worktree.join("AGENTS.md"))?;
    assert!(agents.contains("argv `bash` `scripts/test.sh`; cwd `.`"));
    assert!(!agents.contains("/usr/bin/env"));
    Ok(())
}

#[test]
fn init_explicit_runners_apply_converge_and_never_depend_on_forge()
-> Result<(), Box<dyn std::error::Error>> {
    for (choice, path, block_id) in GENERATED_RUNNER_CASES {
        let fixture = TestWorkspace::clean_rust_repository(&format!("init-runner-{choice}"))?;
        let preview = fixture.run_forge(&["init", "--with-runner", choice, "--json"])?;
        assert_eq!(
            preview.status.code(),
            Some(0),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&preview.stdout),
            String::from_utf8_lossy(&preview.stderr)
        );
        let preview_document: Value = serde_json::from_slice(&preview.stdout)?;
        assert_eq!(required_array(&preview_document["data"], "edits")?.len(), 2);
        assert!(
            !required_array(&preview_document, "diagnostics")?
                .iter()
                .any(|diagnostic| {
                    diagnostic["code"] == "FGE2232"
                        && diagnostic["where"] == "project command `verify`"
                })
        );
        assert!(!fixture.worktree.join(path).exists());

        let applied = fixture.run_forge(&["init", "--apply", "--with-runner", choice, "--json"])?;
        assert_eq!(
            applied.status.code(),
            Some(0),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&applied.stdout),
            String::from_utf8_lossy(&applied.stderr)
        );
        let runner = fs::read_to_string(fixture.worktree.join(path))?;
        assert!(runner.contains(&format!("# forge:begin block={block_id}")));
        assert!(runner.contains("verify"));
        assert!(!runner.contains("forge evidence"));

        let second = fixture.run_forge(&["init", "--with-runner", choice, "--json"])?;
        assert_eq!(
            second.status.code(),
            Some(0),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&second.stdout),
            String::from_utf8_lossy(&second.stderr)
        );
        let second_document: Value = serde_json::from_slice(&second.stdout)?;
        assert!(required_array(&second_document["data"], "edits")?.is_empty());
    }
    Ok(())
}

#[cfg(windows)]
#[test]
fn init_shell_dependent_runners_fail_with_one_explicit_platform_diagnostic()
-> Result<(), Box<dyn std::error::Error>> {
    for (choice, path) in [("make", "Makefile"), ("just", "justfile")] {
        let fixture =
            TestWorkspace::clean_rust_repository(&format!("init-runner-{choice}-unsupported"))?;
        let output = fixture.run_forge(&["init", "--with-runner", choice, "--json"])?;

        assert_json_diagnostic_failure(&output, 2, "FGE2229")?;
        let document: Value = serde_json::from_slice(&output.stdout)?;
        let diagnostic = &required_array(&document, "diagnostics")?[0];
        assert_eq!(
            diagnostic["what"],
            "the explicit runner is not supported on this platform"
        );
        assert_eq!(diagnostic["where"], path);
        assert_eq!(
            diagnostic["why"],
            format!("the explicit `{choice}` runner recipe is not portable on this platform")
        );
        assert_eq!(
            diagnostic["next"],
            "select --with-runner task on Windows, or keep using the reported project-native commands"
        );
        assert!(!fixture.worktree.join(path).exists());
        assert!(!fixture.worktree.join("AGENTS.md").exists());
    }
    Ok(())
}

#[test]
fn init_with_runner_preserves_an_existing_human_runner_byte_for_byte()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::clean_runner_repository("init-existing-runner")?;
    let before = fs::read(fixture.worktree.join("Makefile"))?;

    let output = fixture.run_forge(&["init", "--apply", "--with-runner", "make", "--json"])?;

    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(fixture.worktree.join("Makefile"))?, before);
    assert!(fixture.worktree.join("AGENTS.md").is_file());
    Ok(())
}

#[test]
fn init_allow_dirty_preserves_existing_unmanaged_agents_text()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::zero_config_repository("init-brownfield-dirty")?;
    let existing = b"# Human-owned guidance\n\nKeep this paragraph byte-for-byte.\n";
    fs::write(fixture.worktree.join("AGENTS.md"), existing)?;

    let output = fixture.run_forge(&["init", "--apply", "--allow-dirty", "--json"])?;

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let observed = fs::read(fixture.worktree.join("AGENTS.md"))?;
    assert!(observed.starts_with(existing));
    assert!(String::from_utf8_lossy(&observed).contains("forge:begin block=project-index"));
    assert!(!fixture.worktree.join("explain-must-not-run").exists());
    Ok(())
}

#[test]
fn init_empty_repository_is_a_structured_environment_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::plain("init-empty")?;
    fixture.run_git(&["init", "--quiet"])?;
    let before = fixture.snapshot()?;

    let output = fixture.run_forge(&["init", "--json"])?;

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let document: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(document["schema"], "forge.diagnostic/v1");
    assert_eq!(structured_diagnostic_code(&document)?, "FGE2209");
    assert_eq!(fixture.snapshot()?, before);
    fixture.assert_no_forge_artifacts();
    Ok(())
}

#[test]
fn adapters_check_reports_initial_drift_without_creating_state()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::clean_runner_repository("adapters-initial")?;
    let before = fixture.snapshot()?;
    let private_state = fixture.private_forge_state_dir()?;
    assert!(!private_state.exists());

    let checked = fixture.run_forge(&["adapters", "check", "--json"])?;
    assert_eq!(checked.status.code(), Some(1));
    assert!(checked.stderr.is_empty());
    let document: Value = serde_json::from_slice(&checked.stdout)?;
    assert_eq!(document["schema"], "forge.adapters/v1");
    assert_eq!(document["data"]["changed"], true);
    assert_eq!(document["data"]["applied"], false);
    assert_eq!(document["data"]["adapters"][0]["drift"], "asset-changed");
    assert_eq!(fixture.snapshot()?, before);
    assert!(!private_state.exists());

    let preview = fixture.run_forge(&["adapters", "sync", "--json"])?;
    assert_eq!(preview.status.code(), Some(0));
    assert!(preview.stderr.is_empty());
    let preview_document: Value = serde_json::from_slice(&preview.stdout)?;
    assert_eq!(preview_document["data"]["changed"], true);
    assert_eq!(preview_document["data"]["applied"], false);
    assert_eq!(fixture.snapshot()?, before);
    assert!(!private_state.exists());
    Ok(())
}

#[test]
fn adapters_check_is_read_only_after_init_and_detects_missing_generated_target()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::clean_runner_repository("adapters-check")?;
    let initialized = fixture.run_forge(&["init", "--apply", "--json"])?;
    assert_eq!(initialized.status.code(), Some(0));
    let manifest_path = fixture.generated_manifest_path()?;
    let manifest_before = fs::read(&manifest_path)?;
    let before = fixture.snapshot()?;

    let checked = fixture.run_forge(&["adapters", "check", "--json"])?;
    assert_eq!(checked.status.code(), Some(0));
    let document: Value = serde_json::from_slice(&checked.stdout)?;
    assert_eq!(document["data"]["changed"], false);
    assert_eq!(document["data"]["adapters"][0]["drift"], "no-drift");
    assert_eq!(fixture.snapshot()?, before);
    assert_eq!(fs::read(&manifest_path)?, manifest_before);

    fs::remove_file(&manifest_path)?;
    let stale_before = fixture.snapshot()?;
    let stale = fixture.run_forge(&["adapters", "check", "--json"])?;
    assert_eq!(stale.status.code(), Some(1));
    let stale_document: Value = serde_json::from_slice(&stale.stdout)?;
    assert_eq!(
        stale_document["data"]["adapters"][0]["drift"],
        "manifest-stale"
    );
    assert_eq!(fixture.snapshot()?, stale_before);
    assert!(!manifest_path.exists());

    // A private manifest is deliberately constrained more tightly than an ordinary file on
    // Windows and Unix. Use a fresh Forge-created manifest for the missing-target case instead of
    // recreating protected state with the test process and accidentally testing host ACL defaults.
    let missing_fixture = TestWorkspace::clean_runner_repository("adapters-check-missing-target")?;
    let initialized = missing_fixture.run_forge(&["init", "--apply", "--json"])?;
    assert_eq!(initialized.status.code(), Some(0));
    let missing_manifest_path = missing_fixture.generated_manifest_path()?;
    let missing_manifest_before = fs::read(&missing_manifest_path)?;
    fs::remove_file(missing_fixture.worktree.join("AGENTS.md"))?;
    let missing_before = missing_fixture.snapshot()?;
    let missing = missing_fixture.run_forge(&["adapters", "check", "--json"])?;
    assert_eq!(
        missing.status.code(),
        Some(1),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&missing.stdout),
        String::from_utf8_lossy(&missing.stderr)
    );
    let missing_document: Value = serde_json::from_slice(&missing.stdout)?;
    assert_eq!(
        missing_document["data"]["adapters"][0]["drift"],
        "generated-missing"
    );
    assert_eq!(missing_fixture.snapshot()?, missing_before);
    assert_eq!(fs::read(&missing_manifest_path)?, missing_manifest_before);
    Ok(())
}

#[test]
fn disabling_adopted_adapters_reports_stale_state_without_removing_content()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::clean_runner_repository("adapters-disabled-adopted")?;
    let initialized = fixture.run_forge(&["init", "--apply", "--adapter", "claude"])?;
    assert_eq!(initialized.status.code(), Some(0));
    let agents_path = fixture.worktree.join("AGENTS.md");
    let claude_path = fixture.worktree.join("CLAUDE.md");
    let mut agents = fs::read(&agents_path)?;
    agents.extend_from_slice(b"\n# Human-owned AGENTS note\nKeep this byte-for-byte.\n");
    fs::write(&agents_path, &agents)?;
    let mut claude = b"# Human-owned CLAUDE note\n\n".to_vec();
    claude.extend_from_slice(&fs::read(&claude_path)?);
    fs::write(&claude_path, &claude)?;
    fs::write(
        fixture.worktree.join("forge.toml"),
        b"schema = 1\n\n[adapters]\nagents = false\nclaude = false\n",
    )?;
    fixture.run_git(&["add", "--", "AGENTS.md", "CLAUDE.md", "forge.toml"])?;
    fixture.run_git(&[
        "-c",
        "user.name=Forge CLI tests",
        "-c",
        "user.email=forge-cli-tests@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "disable adopted adapters",
    ])?;
    let manifest_path = fixture.generated_manifest_path()?;
    let manifest_before = fs::read(&manifest_path)?;

    let checked = fixture.run_forge(&["adapters", "check", "--json"])?;
    assert_eq!(checked.status.code(), Some(1));
    let checked_document: Value = serde_json::from_slice(&checked.stdout)?;
    let statuses = required_array(&checked_document["data"], "adapters")?;
    assert_eq!(statuses.len(), 2);
    assert!(
        statuses
            .iter()
            .all(|status| status["drift"] == "manifest-stale")
    );

    let rejected = fixture.run_forge(&["adapters", "sync", "--apply", "--json"])?;
    assert_eq!(rejected.status.code(), Some(65));
    let rejected_document: Value = serde_json::from_slice(&rejected.stdout)?;
    assert_eq!(structured_diagnostic_code(&rejected_document)?, "FGE1213");
    assert_eq!(fs::read(&agents_path)?, agents);
    assert_eq!(fs::read(&claude_path)?, claude);
    assert_eq!(fs::read(&manifest_path)?, manifest_before);
    Ok(())
}

#[test]
fn adapters_user_edit_requires_named_force_and_converges_after_apply()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::clean_runner_repository("adapters-user-edit")?;
    let initialized = fixture.run_forge(&["init", "--apply"])?;
    assert_eq!(initialized.status.code(), Some(0));
    let agents_path = fixture.worktree.join("AGENTS.md");
    let edited = fs::read_to_string(&agents_path)?
        .replace("## Project-native commands", "## Human-edited commands");
    fs::write(&agents_path, edited)?;

    let checked = fixture.run_forge(&["adapters", "check", "--json"])?;
    assert_eq!(checked.status.code(), Some(1));
    let checked_document: Value = serde_json::from_slice(&checked.stdout)?;
    assert_eq!(
        checked_document["data"]["adapters"][0]["drift"],
        "user-edited"
    );
    let rejected = fixture.run_forge(&["adapters", "sync", "--apply", "--json"])?;
    assert_eq!(rejected.status.code(), Some(1));

    fixture.run_git(&["add", "--", "AGENTS.md"])?;
    fixture.run_git(&[
        "-c",
        "user.name=Forge CLI tests",
        "-c",
        "user.email=forge-cli-tests@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "record edited generated block",
    ])?;
    let forced = fixture.run_forge(&[
        "adapters",
        "sync",
        "--apply",
        "--force-block",
        "project-index",
        "--json",
    ])?;
    assert_eq!(forced.status.code(), Some(0));
    let final_check = fixture.run_forge(&["adapters", "check", "--json"])?;
    assert_eq!(final_check.status.code(), Some(0));
    let final_document: Value = serde_json::from_slice(&final_check.stdout)?;
    assert_eq!(final_document["data"]["changed"], false);
    assert_eq!(final_document["data"]["adapters"][0]["drift"], "no-drift");
    Ok(())
}

#[test]
fn adapters_classifies_project_fact_changes_as_asset_drift_even_with_an_old_manifest()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::clean_runner_repository("adapters-asset-drift")?;
    assert_eq!(
        fixture.run_forge(&["init", "--apply"])?.status.code(),
        Some(0)
    );
    let changed_makefile = STATIC_MAKEFILE.replace("test", "spec");
    fs::write(fixture.worktree.join("Makefile"), changed_makefile)?;
    let before = fixture.snapshot()?;

    let checked = fixture.run_forge(&["adapters", "check", "--json"])?;
    assert_eq!(checked.status.code(), Some(1));
    let document: Value = serde_json::from_slice(&checked.stdout)?;
    assert_eq!(document["data"]["adapters"][0]["drift"], "asset-changed");
    assert_eq!(fixture.snapshot()?, before);

    let forced_preview = fixture.run_forge(&[
        "adapters",
        "sync",
        "--force-block",
        "project-index",
        "--json",
    ])?;
    assert_eq!(forced_preview.status.code(), Some(0));
    let forced_document: Value = serde_json::from_slice(&forced_preview.stdout)?;
    assert_eq!(
        forced_document["data"]["adapters"][0]["drift"],
        "asset-changed"
    );
    assert_eq!(fixture.snapshot()?, before);
    Ok(())
}

#[test]
fn adapters_distinguishes_a_missing_managed_block_from_a_missing_file()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::clean_runner_repository("adapters-block-missing")?;
    assert_eq!(
        fixture.run_forge(&["init", "--apply"])?.status.code(),
        Some(0)
    );
    let agents_path = fixture.worktree.join("AGENTS.md");
    fs::write(&agents_path, b"# Human-owned guidance remains\n")?;
    let before = fixture.snapshot()?;

    let checked = fixture.run_forge(&["adapters", "check", "--json"])?;
    assert_eq!(checked.status.code(), Some(1));
    let document: Value = serde_json::from_slice(&checked.stdout)?;
    assert_eq!(
        document["data"]["adapters"][0]["drift"],
        "generated-missing"
    );
    assert_eq!(fixture.snapshot()?, before);
    assert_eq!(fs::read(&agents_path)?, b"# Human-owned guidance remains\n");
    Ok(())
}

#[test]
fn adapters_reports_every_user_edited_target_before_requesting_force()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::clean_runner_repository("adapters-all-user-edits")?;
    assert_eq!(
        fixture
            .run_forge(&["init", "--apply", "--adapter", "claude"])?
            .status
            .code(),
        Some(0)
    );
    let agents_path = fixture.worktree.join("AGENTS.md");
    let agents = fs::read_to_string(&agents_path)?
        .replace("## Project-native commands", "## Human-edited commands");
    fs::write(&agents_path, agents)?;
    let claude_path = fixture.worktree.join("CLAUDE.md");
    let claude = fs::read_to_string(&claude_path)?.replace("@AGENTS.md", "@AGENTS-edited.md");
    fs::write(&claude_path, claude)?;

    let checked = fixture.run_forge(&["adapters", "check", "--json"])?;
    assert_eq!(checked.status.code(), Some(1));
    let document: Value = serde_json::from_slice(&checked.stdout)?;
    let statuses = required_array(&document["data"], "adapters")?;
    assert_eq!(statuses.len(), 2);
    assert!(
        statuses
            .iter()
            .all(|status| status["drift"] == "user-edited")
    );
    assert_eq!(statuses[0]["path"]["display"], "AGENTS.md");
    assert_eq!(statuses[1]["path"]["display"], "CLAUDE.md");
    Ok(())
}

#[test]
fn adapters_preserves_user_bytes_outside_a_satisfied_managed_block()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::clean_runner_repository("adapters-outside-bytes")?;
    assert_eq!(
        fixture.run_forge(&["init", "--apply"])?.status.code(),
        Some(0)
    );
    let agents_path = fixture.worktree.join("AGENTS.md");
    let mut agents = fs::read(&agents_path)?;
    agents.extend_from_slice(b"\n# Human-owned local note\nKeep this byte-for-byte.\n");
    fs::write(&agents_path, &agents)?;
    fixture.run_git(&["add", "--", "AGENTS.md"])?;
    fixture.run_git(&[
        "-c",
        "user.name=Forge CLI tests",
        "-c",
        "user.email=forge-cli-tests@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "add human-owned adapter context",
    ])?;

    let checked = fixture.run_forge(&["adapters", "check", "--json"])?;
    assert_eq!(checked.status.code(), Some(0));
    let document: Value = serde_json::from_slice(&checked.stdout)?;
    assert_eq!(document["data"]["adapters"][0]["drift"], "no-drift");

    let synchronized = fixture.run_forge(&["adapters", "sync", "--apply", "--json"])?;
    assert_eq!(synchronized.status.code(), Some(0));
    assert_eq!(fs::read(&agents_path)?, agents);
    Ok(())
}

#[test]
fn adapters_rejects_an_unexplained_manifest_source_digest() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = TestWorkspace::clean_runner_repository("adapters-source-stale")?;
    assert_eq!(
        fixture.run_forge(&["init", "--apply"])?.status.code(),
        Some(0)
    );
    let manifest_path = fixture.generated_manifest_path()?;
    let mut manifest: Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    manifest["source_digest"] = Value::from(format!("blake3:{}", "f".repeat(64)));
    fs::write(&manifest_path, serde_json::to_vec(&manifest)?)?;

    let checked = fixture.run_forge(&["adapters", "check", "--json"])?;
    assert_eq!(checked.status.code(), Some(1));
    let document: Value = serde_json::from_slice(&checked.stdout)?;
    assert_eq!(document["data"]["adapters"][0]["drift"], "manifest-stale");
    Ok(())
}

#[test]
fn adapters_future_and_malformed_manifests_are_data_errors()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::clean_runner_repository("adapters-state-errors")?;
    let initialized = fixture.run_forge(&["init", "--apply"])?;
    assert_eq!(initialized.status.code(), Some(0));
    let manifest_path = fixture.generated_manifest_path()?;
    let mut manifest: Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    manifest["schema"] = Value::from(2);
    fs::write(&manifest_path, serde_json::to_vec(&manifest)?)?;
    let future_bytes = fs::read(&manifest_path)?;

    let future = fixture.run_forge(&["adapters", "check", "--json"])?;
    assert_eq!(future.status.code(), Some(65));
    let future_document: Value = serde_json::from_slice(&future.stdout)?;
    assert_eq!(structured_diagnostic_code(&future_document)?, "FGE1211");
    assert_eq!(fs::read(&manifest_path)?, future_bytes);

    let future_doctor = fixture.run_forge(&["doctor", "--json"])?;
    assert_eq!(future_doctor.status.code(), Some(65));
    assert!(future_doctor.stderr.is_empty());
    let future_doctor: Value = serde_json::from_slice(&future_doctor.stdout)?;
    assert_eq!(future_doctor["schema"], "forge.doctor/v1");
    assert_eq!(future_doctor["ok"], true);
    assert_eq!(
        required_doctor_check(&future_doctor, "state.layout")?["status"],
        "fail"
    );
    assert_eq!(
        required_doctor_check(&future_doctor, "adapters.drift")?["status"],
        "fail"
    );
    assert_eq!(fs::read(&manifest_path)?, future_bytes);

    fs::write(&manifest_path, b"{ private-state")?;
    let malformed_bytes = fs::read(&manifest_path)?;
    let malformed = fixture.run_forge(&["adapters", "check", "--json"])?;
    assert_eq!(malformed.status.code(), Some(65));
    let malformed_document: Value = serde_json::from_slice(&malformed.stdout)?;
    assert_eq!(structured_diagnostic_code(&malformed_document)?, "FGE1211");
    let malformed_doctor = fixture.run_forge(&["doctor", "--json"])?;
    assert_eq!(malformed_doctor.status.code(), Some(65));
    assert!(malformed_doctor.stderr.is_empty());
    let malformed_doctor: Value = serde_json::from_slice(&malformed_doctor.stdout)?;
    assert_eq!(malformed_doctor["schema"], "forge.doctor/v1");
    assert_eq!(malformed_doctor["ok"], true);
    assert_eq!(
        required_doctor_check(&malformed_doctor, "state.layout")?["status"],
        "fail"
    );
    assert_eq!(
        required_doctor_check(&malformed_doctor, "adapters.drift")?["status"],
        "fail"
    );
    assert_eq!(fs::read(&manifest_path)?, malformed_bytes);
    Ok(())
}

#[cfg(unix)]
#[test]
fn state_writing_commands_report_lock_contention_as_temporary_without_writing()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::clean_runner_repository("state-lock-exit-matrix")?;
    let store = AtomicStateStore::new(fixture.git_state_layout()?)?;
    let _lock = store.try_lock()?;
    let worktree_before = fixture.snapshot()?;
    let state_before = fixture.private_state_snapshot()?;

    for (arguments, diagnostic_code) in [
        (&["init", "--apply", "--json"][..], "FGE2217"),
        (&["adapters", "sync", "--apply", "--json"][..], "FGE2217"),
        (&["evidence", "export", "--json"][..], "FGE3308"),
    ] {
        let output = fixture.run_forge(arguments)?;
        assert_eq!(
            output.status.code(),
            Some(75),
            "arguments={arguments:?} stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        let document: Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(structured_diagnostic_code(&document)?, diagnostic_code);
        assert_eq!(fixture.snapshot()?, worktree_before);
        assert_eq!(fixture.private_state_snapshot()?, state_before);
    }
    Ok(())
}

#[test]
fn no_arguments_prints_help_successfully() -> Result<(), Box<dyn std::error::Error>> {
    let output = run(&[])?;

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("Usage: forge"));
    assert!(stdout.contains("Commands:"));
    Ok(())
}

#[test]
fn explain_json_is_complete_deterministic_and_read_only() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = TestWorkspace::zero_config_repository("explain-json")?;
    fixture.assert_no_forge_artifacts();
    let before = fixture.snapshot()?;

    let first = fixture.run_forge(&["explain", "--json"])?;
    let second = fixture.run_forge(&["explain", "--json"])?;

    assert_eq!(first.status.code(), Some(0));
    assert_eq!(second.status.code(), Some(0));
    assert!(first.stderr.is_empty());
    assert!(second.stderr.is_empty());
    assert_eq!(first.stdout, second.stdout);
    let document: Value = serde_json::from_slice(&first.stdout)?;
    assert_complete_model_contract(&document)?;

    assert_eq!(fixture.snapshot()?, before);
    fixture.assert_no_forge_artifacts();
    Ok(())
}

#[test]
fn explain_human_output_summarizes_the_detected_model() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::zero_config_repository("explain-human")?;
    let before = fixture.snapshot()?;

    let output = fixture.run_forge(&["explain"])?;

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout)?;
    for summary in ["repository:", "work state:", "units:", "commands:"] {
        assert!(
            stdout.contains(summary),
            "missing human summary `{summary}`"
        );
    }
    assert_eq!(fixture.snapshot()?, before);
    fixture.assert_no_forge_artifacts();
    Ok(())
}

#[test]
fn explain_outside_git_is_a_structured_environment_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::plain("explain-no-git")?;

    let output = fixture.run_forge(&["explain", "--json"])?;

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let document: Value = serde_json::from_slice(&output.stdout)?;
    let code = structured_diagnostic_code(&document)?;
    assert!(
        code.starts_with("FGE1") || code.starts_with("FGE2"),
        "non-Git diagnostic code is outside detection/environment ranges: {code}"
    );
    fixture.assert_no_forge_artifacts();
    Ok(())
}

#[test]
fn explain_with_missing_explicit_config_fails_closed_without_writes()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::zero_config_repository("explain-missing-config")?;
    let before = fixture.snapshot()?;

    let output = fixture.run_forge(&["--config", "missing/forge.toml", "explain", "--json"])?;

    assert!(
        matches!(output.status.code(), Some(64 | 65)),
        "missing explicit config must be a usage or data error, got {:?}",
        output.status.code()
    );
    assert!(output.stderr.is_empty());
    let document: Value = serde_json::from_slice(&output.stdout)?;
    let code = structured_diagnostic_code(&document)?;
    assert!(
        code.starts_with("FGE0") || code.starts_with("FGE1"),
        "missing config diagnostic code is outside usage/detection ranges: {code}"
    );
    assert_eq!(fixture.snapshot()?, before);
    fixture.assert_no_forge_artifacts();
    Ok(())
}

#[test]
fn doctor_json_is_complete_deterministic_and_read_only() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::zero_config_repository("doctor-read-only")?;
    let before = fixture.snapshot()?;
    let private_state = fixture.private_forge_state_dir()?;
    assert!(!private_state.exists());

    let first = fixture.run_forge(&["doctor", "--json"])?;
    let second = fixture.run_forge(&["doctor", "--json"])?;

    // CI protection and ownership are deliberately unknown from a local clone.
    assert_eq!(first.status.code(), Some(1));
    assert_eq!(second.status.code(), Some(1));
    assert!(first.stderr.is_empty());
    assert!(second.stderr.is_empty());
    assert_eq!(first.stdout, second.stdout);
    let document: Value = serde_json::from_slice(&first.stdout)?;
    assert_eq!(document["schema"], "forge.doctor/v1");
    assert_eq!(document["ok"], true);
    assert_eq!(document["data"]["overall"], "unknown");
    let ids = required_array(&document["data"], "checks")?
        .iter()
        .map(|check| check["id"].as_str().unwrap_or_default())
        .collect::<Vec<_>>();
    assert_eq!(
        ids,
        [
            "git.repository",
            "git.operation",
            "state.layout",
            "config.schema",
            "project.units",
            "project.commands",
            "toolchain.required",
            "adapters.drift",
            "ci.visible",
            "ownership.visible",
            "path.safety",
            "process.capability",
        ]
    );
    for check in required_array(&document["data"], "checks")? {
        assert!(
            check["detail"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        );
        assert!(
            check["next"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        );
    }
    let toolchain = required_array(&document["data"], "checks")?
        .iter()
        .find(|check| check["id"] == "toolchain.required")
        .ok_or_else(|| io::Error::other("toolchain doctor check is missing"))?;
    assert_eq!(toolchain["status"], "unknown");
    let process = required_array(&document["data"], "checks")?
        .iter()
        .find(|check| check["id"] == "process.capability")
        .ok_or_else(|| io::Error::other("process capability doctor check is missing"))?;
    assert_eq!(process["status"], "pass");
    let state = required_array(&document["data"], "checks")?
        .iter()
        .find(|check| check["id"] == "state.layout")
        .ok_or_else(|| io::Error::other("state layout doctor check is missing"))?;
    assert_eq!(state["status"], "unknown");
    assert!(required_object(&document["data"], "tool_versions")?.is_empty());
    assert_eq!(fixture.snapshot()?, before);
    assert!(!private_state.exists());
    fixture.assert_no_forge_artifacts();
    Ok(())
}

#[test]
fn doctor_separates_visible_repository_evidence_from_unobservable_host_enforcement()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::clean_runner_repository("doctor-visible-evidence")?;
    let workflows = fixture.worktree.join(".github/workflows");
    fs::create_dir_all(&workflows)?;
    let workflow = workflows.join("verify.yml");
    let codeowners = fixture.worktree.join(".github/CODEOWNERS");
    fs::write(&workflow, b"on: push\njobs: [\n")?;
    fs::write(&codeowners, b"docs/**\n")?;
    fixture.run_git(&[
        "add",
        "--",
        ".github/workflows/verify.yml",
        ".github/CODEOWNERS",
    ])?;

    let invalid_before = fixture.snapshot()?;
    let invalid = fixture.run_forge(&["doctor", "--json"])?;
    assert_eq!(fixture.snapshot()?, invalid_before);
    let invalid: Value = serde_json::from_slice(&invalid.stdout)?;
    let invalid_checks = required_array(&invalid["data"], "checks")?;
    for id in ["ci.visible", "ownership.visible"] {
        let check = invalid_checks
            .iter()
            .find(|check| check["id"] == id)
            .ok_or_else(|| io::Error::other(format!("doctor check `{id}` is missing")))?;
        assert_eq!(check["status"], "fail", "unexpected check: {check:#}");
    }

    fs::write(
        &workflow,
        b"name: verify\non: push\njobs:\n  verify:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo 'make --file Makefile verify'\n",
    )?;
    fs::write(&codeowners, b"# * @commented-owner-is-not-a-rule\n")?;

    let decoy_before = fixture.snapshot()?;
    let decoy = fixture.run_forge(&["doctor", "--json"])?;
    assert_eq!(fixture.snapshot()?, decoy_before);
    let decoy: Value = serde_json::from_slice(&decoy.stdout)?;
    let decoy_checks = required_array(&decoy["data"], "checks")?;
    for id in ["ci.visible", "ownership.visible"] {
        let check = decoy_checks
            .iter()
            .find(|check| check["id"] == id)
            .ok_or_else(|| io::Error::other(format!("doctor check `{id}` is missing")))?;
        assert_eq!(check["status"], "unknown", "unexpected check: {check:#}");
    }

    fs::write(
        &workflow,
        b"name: verify\non: push\njobs:\n  verify:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make --file Makefile verify\n",
    )?;
    fs::write(&codeowners, b"* @forge-maintainers\n")?;
    let proven_before = fixture.snapshot()?;

    let proven = fixture.run_forge(&["doctor", "--json"])?;

    assert_eq!(fixture.snapshot()?, proven_before);
    let proven: Value = serde_json::from_slice(&proven.stdout)?;
    let proven_checks = required_array(&proven["data"], "checks")?;
    let ci = proven_checks
        .iter()
        .find(|check| check["id"] == "ci.visible")
        .ok_or_else(|| io::Error::other("ci.visible doctor check is missing"))?;
    assert_eq!(ci["status"], "unknown", "unexpected check: {ci:#}");
    assert!(
        ci["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("server-side"))
    );
    let ownership = proven_checks
        .iter()
        .find(|check| check["id"] == "ownership.visible")
        .ok_or_else(|| io::Error::other("ownership.visible doctor check is missing"))?;
    assert_eq!(
        ownership["status"], "pass",
        "unexpected check: {ownership:#}"
    );
    assert!(
        ownership["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("hosting enforcement remains unobservable"))
    );
    Ok(())
}

#[test]
fn doctor_reports_only_actually_probed_rust_command_dependencies()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::plain("doctor-rust-toolchain")?;
    fixture.run_git(&["init", "--quiet"])?;
    fs::create_dir(fixture.worktree.join("src"))?;
    fs::write(
        fixture.worktree.join("Cargo.toml"),
        b"[package]\nname = \"doctor-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[workspace]\n",
    )?;
    fs::write(
        fixture.worktree.join("Cargo.lock"),
        b"# This file is automatically @generated by Cargo.\nversion = 4\n\n[[package]]\nname = \"doctor-fixture\"\nversion = \"0.1.0\"\n",
    )?;
    fs::write(
        fixture.worktree.join("src/lib.rs"),
        b"pub fn fixture() {}\n",
    )?;
    fixture.run_git(&["add", "--", "Cargo.toml", "Cargo.lock", "src/lib.rs"])?;
    let before = fixture.snapshot()?;

    let output = fixture.run_forge(&["doctor", "--json"])?;

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let document: Value = serde_json::from_slice(&output.stdout)?;
    let toolchain = required_array(&document["data"], "checks")?
        .iter()
        .find(|check| check["id"] == "toolchain.required")
        .ok_or_else(|| io::Error::other("toolchain doctor check is missing"))?;
    assert_eq!(
        toolchain["status"], "pass",
        "unexpected doctor output: {document:#}"
    );
    let versions = required_object(&document["data"], "tool_versions")?;
    for tool in ["cargo", "rustc", "rustfmt"] {
        assert!(
            versions
                .get(tool)
                .and_then(Value::as_str)
                .is_some_and(|version| !version.is_empty()),
            "missing validated {tool} version: {versions:?}"
        );
    }
    assert_eq!(versions.len(), 3);
    assert_eq!(fixture.snapshot()?, before);
    fixture.assert_no_forge_artifacts();
    Ok(())
}

#[test]
fn next_on_unborn_changes_is_deterministic_read_only_and_never_executes_commands()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::zero_config_repository("next-changed")?;
    let before = fixture.snapshot()?;
    let private_state = fixture.private_forge_state_dir()?;
    assert!(!private_state.exists());

    let first = fixture.run_forge(&["next", "--json"])?;
    let second = fixture.run_forge(&["next", "--json"])?;

    assert_eq!(first.status.code(), Some(1));
    assert_eq!(second.status.code(), Some(1));
    assert!(first.stderr.is_empty());
    assert!(second.stderr.is_empty());
    assert_eq!(first.stdout, second.stdout);
    let document: Value = serde_json::from_slice(&first.stdout)?;
    assert_eq!(document["schema"], "forge.next/v1");
    assert_eq!(document["ok"], true);
    assert_eq!(document["data"]["state"], "changed-unverified");
    assert_eq!(document["data"]["required_action"], "run-intent");
    assert_eq!(document["data"]["intent"], "check");
    assert!(
        document["data"]["project_commands"]
            .as_array()
            .is_some_and(|commands| commands.iter().any(|command| {
                command["program"] == "make"
                    && command["args"]
                        .as_array()
                        .is_some_and(|args| args.iter().any(|arg| arg == "check"))
            }))
    );
    assert_eq!(
        document["data"]["receipt_command"],
        "forge evidence run check"
    );
    assert!(
        document["data"]["context_paths"]
            .as_array()
            .is_some_and(|paths| paths
                .iter()
                .any(|path| path["path"]["display"] == "Makefile"))
    );
    assert_eq!(document["data"]["risk"]["level"], "unknown");
    assert!(
        document["data"]["provenance"]
            .as_array()
            .is_some_and(|sources| !sources.is_empty())
    );
    assert_eq!(fixture.snapshot()?, before);
    assert!(!private_state.exists());
    assert!(!fixture.worktree.join("explain-must-not-run").exists());
    Ok(())
}

#[test]
fn next_reports_exact_codeowner_and_document_context_with_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::plain("next-exact-context")?;
    fixture.run_git(&["init", "--quiet"])?;
    fs::create_dir_all(fixture.worktree.join("src"))?;
    fs::create_dir_all(fixture.worktree.join("docs/adr"))?;
    fs::create_dir_all(fixture.worktree.join(".github"))?;
    fs::write(
        fixture.worktree.join("forge.toml"),
        b"schema = 1\n\n[commands.check]\nprogram = \"git\"\nargs = [\"--version\"]\ninputs = [\"**\"]\nmutability = \"read-only\"\nnetwork = \"offline-requested\"\nsuccess = \"exit-zero\"\ncoverage = [\"compile\"]\nenforcement = \"required\"\n",
    )?;
    fs::write(
        fixture.worktree.join(".github/CODEOWNERS"),
        b"src/** @forge/source\n",
    )?;
    fs::write(
        fixture.worktree.join("docs/adr/0001-context.md"),
        b"# Context contract\n\nChanges to `src/widget.rs` require this decision as context.\n",
    )?;
    fs::write(
        fixture.worktree.join("src/widget.rs"),
        b"pub fn value() -> u8 { 1 }\n",
    )?;
    fixture.run_git(&[
        "add",
        "--",
        ".github/CODEOWNERS",
        "docs/adr/0001-context.md",
        "forge.toml",
        "src/widget.rs",
    ])?;
    fixture.run_git(&[
        "-c",
        "user.name=Forge CLI tests",
        "-c",
        "user.email=forge-cli-tests@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "fixture baseline",
    ])?;
    fs::write(
        fixture.worktree.join("src/widget.rs"),
        b"pub fn value() -> u8 { 2 }\n",
    )?;
    let before = fixture.snapshot()?;
    let private_state = fixture.private_forge_state_dir()?;

    let output = fixture.run_forge(&["next", "--json"])?;

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let document: Value = serde_json::from_slice(&output.stdout)?;
    let context = required_array(&document["data"], "context_paths")?;
    for (path, rule, confidence) in [
        (
            native_repository_path(&["src", "widget.rs"]),
            "context.exact-change.v1",
            "high",
        ),
        (
            native_repository_path(&[".github", "CODEOWNERS"]),
            "context.codeowners-match.v1",
            "medium",
        ),
        (
            native_repository_path(&["docs", "adr", "0001-context.md"]),
            "context.exact-document-match.v1",
            "medium",
        ),
    ] {
        let item = context
            .iter()
            .find(|item| item["path"]["display"] == path.as_str())
            .ok_or_else(|| io::Error::other(format!("missing context path `{path}`")))?;
        assert_eq!(item["confidence"], confidence, "unexpected item: {item:#}");
        assert!(
            item["provenance"]
                .as_array()
                .is_some_and(|sources| sources.iter().any(|source| source == rule)),
            "missing provenance `{rule}`: {item:#}"
        );
    }
    assert_eq!(fixture.snapshot()?, before);
    assert!(!private_state.exists());
    Ok(())
}

#[test]
fn next_uses_the_builtin_policy_when_head_has_no_config() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = TestWorkspace::clean_runner_repository("next-head-config-absent")?;
    let before = fixture.snapshot()?;

    let output = fixture.run_forge(&["next", "--json"])?;

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let document: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(document["schema"], "forge.next/v1");
    assert_eq!(document["data"]["state"], "idle");
    assert_eq!(document["data"]["required_action"], "none");
    assert_eq!(document["data"]["risk"]["level"], "unknown");
    assert!(
        document["data"]["uncertain_assumptions"]
            .as_array()
            .is_some_and(|assumptions| assumptions.iter().all(|assumption| {
                assumption["provenance"].as_array().is_none_or(|sources| {
                    sources
                        .iter()
                        .all(|source| source != "navigation.approved-base-unknown.v1")
                })
            }))
    );
    assert_eq!(fixture.snapshot()?, before);
    assert!(!fixture.worktree.join("explain-must-not-run").exists());
    Ok(())
}

#[test]
fn next_reports_an_empty_unborn_repository_as_idle() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::plain("next-idle")?;
    fixture.run_git(&["init", "--quiet"])?;
    let before = fixture.snapshot()?;

    let output = fixture.run_forge(&["next", "--json"])?;

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let document: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(document["data"]["state"], "idle");
    assert_eq!(document["data"]["required_action"], "none");
    assert!(
        document["data"]["project_commands"]
            .as_array()
            .is_some_and(Vec::is_empty)
    );
    assert_eq!(fixture.snapshot()?, before);
    fixture.assert_no_forge_artifacts();
    Ok(())
}

#[test]
fn next_stops_at_external_authority_for_a_critical_policy_change()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::plain("next-protected")?;
    fixture.run_git(&["init", "--quiet"])?;
    fs::write(fixture.worktree.join("AGENTS.md"), b"repository policy\n")?;
    let before = fixture.snapshot()?;

    let output = fixture.run_forge(&["next", "--json"])?;

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let document: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(document["data"]["state"], "blocked");
    assert_eq!(document["data"]["required_action"], "stop-and-escalate");
    assert_eq!(document["data"]["risk"]["level"], "critical");
    assert!(
        document["data"]["risk"]["matched"]
            .as_array()
            .is_some_and(|matches| matches.iter().any(|rule| rule == "risk/ci-policy"))
    );
    assert!(
        document["data"]["blockers"]
            .as_array()
            .is_some_and(|blockers| !blockers.is_empty())
    );
    assert_eq!(fixture.snapshot()?, before);
    fixture.assert_no_forge_artifacts();
    Ok(())
}

#[cfg(unix)]
#[test]
fn next_advances_from_check_to_test_and_then_local_verified_without_writing()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::clean_rust_repository("next-receipt-progression")?;
    let warm_check = fixture.run_forge(&["evidence", "run", "check", "--json"])?;
    assert_eq!(
        warm_check.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&warm_check.stdout),
        String::from_utf8_lossy(&warm_check.stderr)
    );
    let state_after_warm_check = fixture.private_state_snapshot()?;
    let worktree_after_warm_check = fixture.snapshot()?;

    let warm = fixture.run_forge(&["-v", "next", "--json"])?;
    assert_eq!(
        warm.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&warm.stdout),
        String::from_utf8_lossy(&warm.stderr)
    );
    assert_eq!(warm.stderr, b"inventory-cache: hit\n");
    let warm_document: Value = serde_json::from_slice(&warm.stdout)?;
    assert_eq!(warm_document["data"]["state"], "idle");
    assert_eq!(fixture.private_state_snapshot()?, state_after_warm_check);
    assert_eq!(fixture.snapshot()?, worktree_after_warm_check);

    fs::write(
        fixture.worktree.join("src/main.rs"),
        b"fn main() {\n    println!(\"{}\", forge_evidence_fixture::answer());\n}\n",
    )?;

    let check = fixture.run_forge(&["evidence", "run", "check", "--json"])?;
    assert_eq!(
        check.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
    let state_after_check = fixture.private_state_snapshot()?;
    let worktree_after_check = fixture.snapshot()?;

    let partial = fixture.run_forge(&["next", "--json"])?;
    assert_eq!(
        partial.status.code(),
        Some(1),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&partial.stdout),
        String::from_utf8_lossy(&partial.stderr)
    );
    assert!(partial.stderr.is_empty());
    let partial_document: Value = serde_json::from_slice(&partial.stdout)?;
    assert_eq!(partial_document["data"]["state"], "partially-verified");
    assert_eq!(partial_document["data"]["required_action"], "run-intent");
    assert_eq!(partial_document["data"]["intent"], "test");
    assert_eq!(
        partial_document["data"]["receipt_command"],
        "forge evidence run test"
    );
    assert!(
        partial_document["data"]["project_commands"]
            .as_array()
            .is_some_and(|commands| !commands.is_empty())
    );
    assert_eq!(fixture.private_state_snapshot()?, state_after_check);
    assert_eq!(fixture.snapshot()?, worktree_after_check);

    let test = fixture.run_forge(&["evidence", "run", "test", "--json"])?;
    assert_eq!(
        test.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&test.stdout),
        String::from_utf8_lossy(&test.stderr)
    );
    let state_after_test = fixture.private_state_snapshot()?;
    let worktree_after_test = fixture.snapshot()?;

    let verified = fixture.run_forge(&["next", "--json"])?;
    assert_eq!(
        verified.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&verified.stdout),
        String::from_utf8_lossy(&verified.stderr)
    );
    assert!(verified.stderr.is_empty());
    let verified_document: Value = serde_json::from_slice(&verified.stdout)?;
    assert_eq!(verified_document["data"]["state"], "local-verified");
    assert_eq!(verified_document["data"]["required_action"], "none");
    assert!(verified_document["data"]["intent"].is_null());
    assert!(verified_document["data"]["receipt_command"].is_null());
    assert_eq!(fixture.private_state_snapshot()?, state_after_test);
    assert_eq!(fixture.snapshot()?, worktree_after_test);
    Ok(())
}

#[cfg(unix)]
fn install_clippy_version_mutator(
    fixture: &TestWorkspace,
    tracked: &Path,
) -> Result<(PathBuf, PathBuf), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt as _;

    let wrapper_directory = fixture.root.join("support/scope-drift-bin");
    fs::create_dir(&wrapper_directory)?;
    let wrapper = wrapper_directory.join("cargo");
    let trigger = fixture.root.join("support/trigger-scope-drift");
    fs::write(&trigger, b"armed\n")?;
    let real_cargo = executable_on_path("cargo")?;
    let script = format!(
        "#!/bin/sh\nset -eu\nif [ \"${{1-}}\" = \"clippy\" ] && [ \"${{2-}}\" = \"--version\" ] && [ -f {trigger} ]; then\n  printf '%s\\n' 'pub fn answer() -> u8 {{' '    44' '}}' > {tracked}\n  /bin/rm -f {trigger}\nfi\nexec {real_cargo} \"$@\"\n",
        trigger = shell_single_quote(&trigger)?,
        tracked = shell_single_quote(tracked)?,
        real_cargo = shell_single_quote(&real_cargo)?,
    );
    fs::write(&wrapper, script)?;
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700))?;
    Ok((wrapper_directory, trigger))
}

#[cfg(unix)]
#[test]
fn next_does_not_evaluate_receipts_for_a_clean_idle_repository()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::clean_rust_repository("next-clean-receipt-not-applicable")?;
    let tracked = fixture.worktree.join("src/lib.rs");
    let seed = fixture.run_forge(&["evidence", "run", "check", "--json"])?;
    assert_eq!(
        seed.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&seed.stdout),
        String::from_utf8_lossy(&seed.stderr)
    );
    let cache_hit = fixture.run_forge(&["-v", "explain", "--json"])?;
    assert_eq!(cache_hit.status.code(), Some(0));
    assert_eq!(cache_hit.stderr, b"inventory-cache: hit\n");
    let state_before = fixture.private_state_snapshot()?;
    let worktree_before = fixture.snapshot()?;
    let (wrapper_directory, trigger) = install_clippy_version_mutator(&fixture, &tracked)?;

    // Default Clippy is advisory, so doctor does not run this probe. If clean navigation reaches
    // Receipt applicability, the retained check Receipt does run it and mutates the worktree.
    let output = fixture.run_forge_with_path_prefix(&["next", "--json"], &wrapper_directory)?;

    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let document: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(document["data"]["state"], "idle");
    assert_eq!(document["data"]["required_action"], "none");
    assert!(
        trigger.exists(),
        "clean idle navigation unexpectedly ran a Receipt-only probe"
    );
    assert_eq!(fs::read(&tracked)?, b"pub fn answer() -> u8 {\n    42\n}\n");
    assert_eq!(fixture.private_state_snapshot()?, state_before);
    assert_eq!(fixture.snapshot()?, worktree_before);
    Ok(())
}

#[cfg(unix)]
#[test]
fn next_confirms_after_receipt_evaluation_and_rejects_repository_drift()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::clean_rust_repository("next-receipt-scope-drift")?;
    let tracked = fixture.worktree.join("src/lib.rs");
    let seed = fixture.run_forge(&["evidence", "run", "check", "--json"])?;
    assert_eq!(
        seed.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&seed.stdout),
        String::from_utf8_lossy(&seed.stderr)
    );
    fs::write(&tracked, b"pub fn answer() -> u8 {\n    43\n}\n")?;
    let state_before = fixture.private_state_snapshot()?;
    let status_arguments = [
        "status",
        "--porcelain=v2",
        "-z",
        "--branch",
        "--untracked-files=all",
    ];
    let status_before = fixture.successful_git_stdout(&status_arguments)?;
    let (wrapper_directory, trigger) = install_clippy_version_mutator(&fixture, &tracked)?;

    // The existing tracked change makes Receipt applicability relevant. Default Clippy is
    // advisory, so doctor does not run this probe: Receipt evaluation changes the same dirty path
    // after its content was digested. Porcelain status remains identical, requiring the final
    // content confirmation to fail closed rather than accepting the raced Receipt evaluation.
    let output = fixture.run_forge_with_path_prefix(&["next", "--json"], &wrapper_directory)?;

    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let document: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(structured_diagnostic_code(&document)?, "FGE3313");
    assert!(!trigger.exists(), "the Receipt-only probe did not run");
    assert_eq!(fs::read(&tracked)?, b"pub fn answer() -> u8 {\n    44\n}\n");
    assert_eq!(
        fixture.successful_git_stdout(&status_arguments)?,
        status_before,
        "the fixture must exercise same-status dirty-content revalidation"
    );
    assert_eq!(fixture.private_state_snapshot()?, state_before);
    Ok(())
}

#[cfg(unix)]
#[test]
fn doctor_reports_unsafe_private_state_without_following_or_writing_it()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;

    let fixture = TestWorkspace::clean_runner_repository("doctor-unsafe-state")?;
    let before = fixture.snapshot()?;
    let state = fixture.private_forge_state_dir()?;
    let outside = fixture.root.join("outside-state");
    fs::create_dir(&outside)?;
    symlink(&outside, &state)?;

    let output = fixture.run_forge(&["doctor", "--json"])?;

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let document: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(document["schema"], "forge.doctor/v1");
    assert_eq!(document["data"]["overall"], "fail");
    let checks = required_array(&document["data"], "checks")?;
    let state_check = checks
        .iter()
        .find(|check| check["id"] == "state.layout")
        .ok_or_else(|| io::Error::other("state.layout check is missing"))?;
    assert_eq!(state_check["status"], "fail");
    assert_eq!(fixture.snapshot()?, before);
    assert!(outside.read_dir()?.next().is_none());
    assert!(!fixture.worktree.join("explain-must-not-run").exists());
    Ok(())
}

#[cfg(unix)]
#[test]
fn doctor_rejects_unsafe_default_adapter_targets_before_adoption()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;

    for target_kind in ["directory", "symlink"] {
        let fixture = TestWorkspace::clean_runner_repository(&format!(
            "doctor-unsafe-default-target-{target_kind}"
        ))?;
        let agents = fixture.worktree.join("AGENTS.md");
        if target_kind == "directory" {
            fs::create_dir(&agents)?;
        } else {
            let outside = fixture.root.join("outside-agents.md");
            fs::write(
                &outside,
                b"must not be read through the repository target\n",
            )?;
            symlink(&outside, &agents)?;
        }
        let before = fixture.snapshot()?;
        let private_state = fixture.private_forge_state_dir()?;

        let output = fixture.run_forge(&["doctor", "--json"])?;

        assert_eq!(output.status.code(), Some(1), "target kind {target_kind}");
        assert!(output.stderr.is_empty());
        let document: Value = serde_json::from_slice(&output.stdout)?;
        let path_safety = required_array(&document["data"], "checks")?
            .iter()
            .find(|check| check["id"] == "path.safety")
            .ok_or_else(|| io::Error::other("path.safety doctor check is missing"))?;
        assert_eq!(path_safety["status"], "fail", "target kind {target_kind}");
        assert_eq!(fixture.snapshot()?, before);
        assert!(!private_state.exists());
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn evidence_run_json_is_the_exact_persisted_receipt_and_contains_no_child_output()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::clean_runner_repository("evidence-run-pass")?;
    fs::write(
        fixture.worktree.join("Makefile"),
        b".PHONY: check\ncheck:\n\t@printf 'child-stdout-must-not-leak\\n'\n\t@printf 'child-stderr-must-not-leak\\n' >&2\n",
    )?;
    let before = fixture.snapshot()?;

    let output = fixture.run_forge(&["evidence", "run", "check", "--json"])?;

    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert!(
        !output
            .stdout
            .windows(b"child-stdout-must-not-leak".len())
            .any(|window| window == b"child-stdout-must-not-leak")
    );
    assert!(
        !output
            .stdout
            .windows(b"child-stderr-must-not-leak".len())
            .any(|window| window == b"child-stderr-must-not-leak")
    );
    let document: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(document["schema"], "forge.receipt/v2");
    assert_eq!(document["ok"], true);
    assert_eq!(document["data"]["intent"], "check");
    assert_eq!(document["data"]["outcome"], "pass");
    let observations = required_array(&document["data"], "observations")?;
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0]["raw_exit_code"], 0);
    assert!(observations[0]["stdout_total_bytes"].as_u64().is_some());
    assert_eq!(observations[0]["diagnostic_summary"]["state"], "observed");
    assert_eq!(
        observations[0]["diagnostic_summary"]["stdout_total_bytes"],
        observations[0]["stdout_total_bytes"]
    );
    assert!(
        observations[0]["diagnostic_summary"]["stderr_total_bytes"]
            .as_u64()
            .is_some()
    );
    assert!(observations[0]["stdout_digest"].as_str().is_some());
    assert!(observations[0]["stderr_digest"].as_str().is_some());
    assert!(observations[0]["json_error_status"].is_null());
    assert!(
        observations[0]["log_refs"]
            .as_array()
            .is_some_and(Vec::is_empty)
    );
    assert_eq!(
        document["data"]["dependencies"]["base_task"]["state"],
        "known"
    );
    assert!(document["data"]["dependencies"]["base_task"]["value"].is_string());

    let receipt_id = document["data"]["id"]
        .as_str()
        .ok_or_else(|| io::Error::other("Receipt ID is missing"))?;
    let object_name = receipt_id
        .strip_prefix("receipt:blake3:")
        .ok_or_else(|| io::Error::other("Receipt ID has the wrong prefix"))?;
    let persisted = fixture
        .private_forge_state_dir()?
        .join("receipts/v2")
        .join(format!("{object_name}.json"));
    assert_eq!(fs::read(persisted)?, output.stdout);
    assert_eq!(fixture.snapshot()?, before);
    Ok(())
}

#[test]
fn missing_executable_persists_a_typed_infrastructure_receipt()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::clean_runner_repository("evidence-missing-executable")?;
    fs::write(
        fixture.worktree.join("forge.toml"),
        b"schema = 1\n\n[commands.check]\nprogram = \"forge-command-that-does-not-exist\"\nmutability = \"read-only\"\nnetwork = \"inherit\"\nsuccess = \"exit-zero\"\ncoverage = [\"compile\"]\nenforcement = \"required\"\n",
    )?;
    fixture.run_git(&["add", "--", "forge.toml"])?;
    fixture.run_git(&[
        "-c",
        "user.name=Forge CLI tests",
        "-c",
        "user.email=forge-cli-tests@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "missing executable fixture",
    ])?;
    let before = fixture.snapshot()?;

    let output = fixture.run_forge(&["evidence", "run", "check", "--json"])?;

    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let document: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(document["schema"], "forge.receipt/v2");
    assert_eq!(document["data"]["outcome"], "infrastructure-failure");
    assert_eq!(document["data"]["coverage"], serde_json::json!([]));
    let observation = &document["data"]["observations"][0];
    assert_eq!(observation["process_error_kind"], "executable-unavailable");
    assert_eq!(observation["outcome"], "infrastructure-failure");
    assert_eq!(observation["diagnostic_summary"]["state"], "unavailable");
    assert!(
        observation["diagnostic_summary"]
            .get("stdout_total_bytes")
            .is_none()
    );
    assert!(
        observation["diagnostic_summary"]
            .get("stderr_total_bytes")
            .is_none()
    );
    assert!(observation["raw_exit_code"].is_null());
    assert!(observation.get("stdout_total_bytes").is_none());
    assert!(observation.get("stdout_truncated").is_none());
    assert!(observation.get("stderr_truncated").is_none());
    assert_eq!(observation["output_truncated"], true);
    assert_ne!(observation["stdout_digest"], observation["stderr_digest"]);
    let receipt_id = document["data"]["id"]
        .as_str()
        .ok_or_else(|| io::Error::other("Receipt ID is not a string"))?;
    let object_name = receipt_id
        .strip_prefix("receipt:blake3:")
        .ok_or_else(|| io::Error::other("Receipt ID has the wrong prefix"))?;
    let persisted = fixture
        .private_forge_state_dir()?
        .join("receipts/v2")
        .join(format!("{object_name}.json"));
    assert_eq!(fs::read(persisted)?, output.stdout);
    assert_eq!(fixture.snapshot()?, before);
    Ok(())
}

#[cfg(unix)]
#[test]
fn post_run_scope_failure_persists_an_unknown_scope_observation_before_failing()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = TestWorkspace::clean_runner_repository("evidence-post-scope-unavailable")?;
    let script = fixture.worktree.join("break-after-scope.sh");
    fs::write(
        &script,
        b"#!/bin/sh\nset -eu\nrm -- victim.txt\nmkfifo victim.txt\n",
    )?;
    let mut permissions = fs::metadata(&script)?.permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&script, permissions)?;
    fs::write(
        fixture.worktree.join("victim.txt"),
        b"stable before scope\n",
    )?;
    fs::write(
        fixture.worktree.join("forge.toml"),
        b"schema = 1\n\n[commands.check]\nprogram = \"./break-after-scope.sh\"\ninputs = [\"**\"]\nmutability = \"working-tree-write\"\nnetwork = \"offline-requested\"\nsuccess = \"exit-zero\"\ncoverage = [\"compile\"]\nenforcement = \"required\"\n",
    )?;
    fixture.run_git(&[
        "add",
        "--",
        "break-after-scope.sh",
        "forge.toml",
        "victim.txt",
    ])?;
    fixture.run_git(&[
        "-c",
        "user.name=Forge CLI tests",
        "-c",
        "user.email=forge-cli-tests@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "post-run scope failure fixture",
    ])?;

    let output = fixture.run_forge(&["evidence", "run", "check", "--json"])?;

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let diagnostic: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(structured_diagnostic_code(&diagnostic)?, "FGE3209");
    let why = diagnostic["diagnostics"][0]["why"]
        .as_str()
        .ok_or_else(|| io::Error::other("post-run diagnostic has no why"))?;
    assert!(why.contains("observation-only (non-proving)"));

    let receipts = fixture.persisted_receipts()?;
    assert_eq!(receipts.len(), 1);
    let (filename, receipt) = &receipts[0];
    let receipt_id = receipt["data"]["id"]
        .as_str()
        .ok_or_else(|| io::Error::other("persisted Receipt has no ID"))?;
    let object_name = receipt_id
        .strip_prefix("receipt:blake3:")
        .ok_or_else(|| io::Error::other("persisted Receipt ID has the wrong prefix"))?;
    assert_eq!(filename, &format!("{object_name}.json"));
    assert!(why.contains(receipt_id));
    assert!(why.contains(&format!("receipts/v2/{filename}")));
    assert_eq!(receipt["data"]["outcome"], "pass");
    assert_eq!(receipt["data"]["observations"][0]["raw_exit_code"], 0);
    assert_eq!(
        receipt["data"]["dependencies"]["scope_before"]["state"],
        "known"
    );
    assert_eq!(
        receipt["data"]["dependencies"]["scope_after"]["state"],
        "unknown"
    );

    fs::remove_file(fixture.worktree.join("victim.txt"))?;
    fs::write(
        fixture.worktree.join("victim.txt"),
        b"stable before scope\n",
    )?;
    let show = fixture.run_forge(&["evidence", "show", "--json"])?;
    assert_eq!(
        show.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&show.stdout),
        String::from_utf8_lossy(&show.stderr)
    );
    let evidence: Value = serde_json::from_slice(&show.stdout)?;
    assert!(
        evidence["data"]["valid_receipts"]
            .as_array()
            .is_some_and(Vec::is_empty)
    );
    assert_eq!(
        evidence["data"]["stale_receipts"].as_array().map(Vec::len),
        Some(1)
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn post_run_head_drift_persists_both_known_scopes_before_returning_env_unmet()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::clean_runner_repository("evidence-post-head-drift")?;
    fs::write(
        fixture.worktree.join("forge.toml"),
        b"schema = 1\n\n[commands.check]\nprogram = \"git\"\nargs = [\"-c\", \"user.name=Forge CLI tests\", \"-c\", \"user.email=forge-cli-tests@example.invalid\", \"commit\", \"--quiet\", \"--allow-empty\", \"-m\", \"move HEAD during evidence run\"]\ninputs = [\"**\"]\nmutability = \"working-tree-write\"\nnetwork = \"offline-requested\"\nsuccess = \"exit-zero\"\ncoverage = [\"compile\"]\nenforcement = \"required\"\n",
    )?;
    fixture.run_git(&["add", "--", "forge.toml"])?;
    fixture.run_git(&[
        "-c",
        "user.name=Forge CLI tests",
        "-c",
        "user.email=forge-cli-tests@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "HEAD drift fixture",
    ])?;
    let head_before = fixture.successful_git_stdout(&["rev-parse", "HEAD"])?;

    let output = fixture.run_forge(&["evidence", "run", "check", "--json"])?;

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let diagnostic: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(structured_diagnostic_code(&diagnostic)?, "FGE3215");
    let why = diagnostic["diagnostics"][0]["why"]
        .as_str()
        .ok_or_else(|| io::Error::other("HEAD drift diagnostic has no why"))?;
    assert!(why.contains("observation-only (non-proving)"));

    let receipts = fixture.persisted_receipts()?;
    assert_eq!(receipts.len(), 1);
    let (filename, receipt) = &receipts[0];
    let receipt_id = receipt["data"]["id"]
        .as_str()
        .ok_or_else(|| io::Error::other("persisted Receipt has no ID"))?;
    assert!(why.contains(receipt_id));
    assert!(why.contains(&format!("receipts/v2/{filename}")));
    assert_eq!(receipt["data"]["outcome"], "pass");
    assert_eq!(receipt["data"]["observations"][0]["raw_exit_code"], 0);
    let before = &receipt["data"]["dependencies"]["scope_before"];
    let after = &receipt["data"]["dependencies"]["scope_after"];
    assert_eq!(before["state"], "known");
    assert_eq!(after["state"], "known");
    assert_ne!(before["value"], after["value"]);
    assert_ne!(
        fixture.successful_git_stdout(&["rev-parse", "HEAD"])?,
        head_before
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn configured_offline_request_reaches_the_project_process_as_best_effort_guards()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = TestWorkspace::clean_runner_repository("evidence-configured-offline")?;
    let script = fixture.worktree.join("verify-offline-env.sh");
    fs::write(
        &script,
        br#"#!/bin/sh
[ "${CARGO_NET_OFFLINE-}" = true ] &&
[ "${RUSTUP_AUTO_INSTALL-}" = 0 ] &&
[ "${GOPROXY-}" = off ] &&
[ "${GOSUMDB-}" = off ] &&
[ "${GOTOOLCHAIN-}" = local ]
"#,
    )?;
    let mut permissions = fs::metadata(&script)?.permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&script, permissions)?;
    fs::write(
        fixture.worktree.join("forge.toml"),
        b"schema = 1\n\n[commands.check]\nprogram = \"./verify-offline-env.sh\"\nmutability = \"read-only\"\nnetwork = \"offline-requested\"\nsuccess = \"exit-zero\"\ncoverage = [\"compile\"]\n",
    )?;
    fixture.run_git(&["add", "--", "forge.toml", "verify-offline-env.sh"])?;
    fixture.run_git(&[
        "-c",
        "user.name=Forge CLI tests",
        "-c",
        "user.email=forge-cli-tests@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "offline command fixture",
    ])?;
    let before = fixture.snapshot()?;

    let output = fixture.run_forge(&["evidence", "run", "check", "--json"])?;

    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let document: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(document["data"]["outcome"], "pass");
    assert_eq!(
        document["data"]["observations"][0]["command"]["command"]["network"],
        "offline-requested"
    );
    assert_eq!(fixture.snapshot()?, before);
    Ok(())
}

#[test]
fn evidence_run_rejects_an_unresolved_intent_without_creating_state()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::plain("evidence-run-unresolved")?;
    fixture.run_git(&["init", "--quiet"])?;
    let private_state = fixture.private_forge_state_dir()?;
    assert!(!private_state.exists());

    let output = fixture.run_forge(&["evidence", "run", "check", "--json"])?;

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let document: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(structured_diagnostic_code(&document)?, "FGE3205");
    assert!(!private_state.exists());
    Ok(())
}

#[cfg(unix)]
#[test]
fn evidence_run_checks_the_state_lock_before_a_project_command_can_start()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::clean_runner_repository("evidence-lock-preflight")?;
    let first_started = fixture.worktree.join("first-started");
    let release_first = fixture.worktree.join("release-first");
    let second_started = fixture.worktree.join("second-started");
    fs::write(
        fixture.worktree.join("Makefile"),
        b".PHONY: check test\ncheck:\n\t@printf started > first-started\n\t@count=0; while [ ! -f release-first ] && [ $$count -lt 200 ]; do sleep 0.02; count=$$((count + 1)); done\ntest:\n\t@printf started > second-started\n",
    )?;

    let mut first_command = ProcessCommand::new(env!("CARGO_BIN_EXE_forge"));
    first_command
        .current_dir(&fixture.worktree)
        .args(["evidence", "run", "check", "--json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    fixture.configure_git_environment(&mut first_command);
    let mut first = first_command.spawn()?;

    let start_deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if first_started.exists() {
            break;
        }
        if let Some(status) = first.try_wait()? {
            let output = first.wait_with_output()?;
            return Err(io::Error::other(format!(
                "first evidence command exited with {status} before its project command started: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ))
            .into());
        }
        if Instant::now() >= start_deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    if !first_started.exists() {
        fs::write(&release_first, b"release\n")?;
        let output = first.wait_with_output()?;
        return Err(io::Error::other(format!(
            "first evidence command did not start within 30 seconds: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ))
        .into());
    }

    let second = fixture.run_forge(&["evidence", "run", "test", "--json"])?;
    fs::write(&release_first, b"release\n")?;
    let first = first.wait_with_output()?;

    assert_eq!(
        first.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );
    assert_eq!(
        second.status.code(),
        Some(75),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr)
    );
    let diagnostic: Value = serde_json::from_slice(&second.stdout)?;
    assert_eq!(structured_diagnostic_code(&diagnostic)?, "FGE3214");
    assert!(!second_started.exists());
    Ok(())
}

#[cfg(unix)]
#[test]
fn evidence_run_rejects_unsafe_state_before_a_project_command_can_start()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = TestWorkspace::clean_runner_repository("evidence-unsafe-state-preflight")?;
    let state = fixture.private_forge_state_dir()?;
    fs::create_dir(&state)?;
    fs::set_permissions(&state, fs::Permissions::from_mode(0o755))?;

    let output = fixture.run_forge(&["evidence", "run", "check", "--json"])?;

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let diagnostic: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(structured_diagnostic_code(&diagnostic)?, "FGE3214");
    assert!(!fixture.worktree.join("explain-must-not-run").exists());
    Ok(())
}

#[cfg(unix)]
#[test]
fn evidence_run_human_previews_the_real_command_before_returning_the_receipt_summary()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::clean_runner_repository("evidence-run-human")?;
    fs::write(
        fixture.worktree.join("Makefile"),
        b".PHONY: check\ncheck:\n\t@printf 'hidden-child-output\\n'\n",
    )?;

    let output = fixture.run_forge(&["evidence", "run", "check"])?;

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout)?;
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stdout.contains("intent: check"));
    assert!(stdout.contains("outcome: pass"));
    assert!(stdout.contains("receipt applicability: observation-only (non-proving)"));
    assert!(stdout.contains("toolchain dependency is unknown"));
    assert!(stderr.contains("command 1/1:"));
    assert!(stderr.contains("program: \"make\""));
    assert!(stderr.contains("args: [\"--file\", \"Makefile\", \"check\"]"));
    assert!(!stdout.contains("hidden-child-output"));
    assert!(!stderr.contains("hidden-child-output"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn quiet_suppresses_the_nonessential_evidence_command_preview()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::clean_runner_repository("evidence-run-quiet")?;

    let output = fixture.run_forge(&["--quiet", "evidence", "run", "check"])?;

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("intent: check"));
    assert!(stdout.contains("outcome: pass"));
    Ok(())
}

#[test]
fn evidence_show_and_verify_leave_absent_private_state_absent()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::clean_runner_repository("evidence-read-only-absent")?;
    let private_state = fixture.private_forge_state_dir()?;
    assert!(!private_state.exists());

    let show = fixture.run_forge(&["evidence", "show", "--json"])?;
    assert_eq!(
        show.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&show.stdout),
        String::from_utf8_lossy(&show.stderr)
    );
    assert!(show.stderr.is_empty());
    let show_document: Value = serde_json::from_slice(&show.stdout)?;
    assert_eq!(show_document["schema"], "forge.evidence/v2");
    assert_eq!(show_document["data"]["local_state"], "unknown");
    assert!(required_array(&show_document["data"], "valid_receipts")?.is_empty());
    assert!(required_array(&show_document["data"], "stale_receipts")?.is_empty());
    assert!(!private_state.exists());

    let verify = fixture.run_forge(&["evidence", "verify", "--json"])?;
    assert_eq!(verify.status.code(), Some(2));
    assert!(verify.stderr.is_empty());
    let verify_document: Value = serde_json::from_slice(&verify.stdout)?;
    assert_eq!(verify_document["schema"], "forge.evidence/v2");
    assert_eq!(verify_document["data"]["local_state"], "unknown");
    assert!(!private_state.exists());
    Ok(())
}

#[test]
fn rust_evidence_declares_provider_gaps_without_changing_local_sufficiency()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::clean_rust_repository("evidence-rust-coverage-gaps")?;

    let before = fixture.run_forge(&["evidence", "show", "--json"])?;
    assert_eq!(
        before.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&before.stdout),
        String::from_utf8_lossy(&before.stderr)
    );
    let before_document: Value = serde_json::from_slice(&before.stdout)?;
    let before_state = before_document["data"]["local_state"].clone();
    let before_gaps = required_array(
        &before_document["data"]["coverage_and_gaps"],
        "not_verified",
    )?;
    for expected in [
        "format",
        "compile",
        "custom:rust-format",
        "custom:rust-compile",
        "custom:rust-examples-compile",
        "custom:rust-benches-compile",
        "custom:rust-cross-target",
        "custom:rust-performance",
    ] {
        assert!(
            before_gaps
                .iter()
                .any(|value| value.as_str() == Some(expected)),
            "missing Rust coverage expectation {expected}: {before_document:#}"
        );
    }

    let run = fixture.run_forge(&["evidence", "run", "format-check", "--json"])?;
    assert_eq!(
        run.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    let after = fixture.run_forge(&["evidence", "show", "--json"])?;
    assert_eq!(
        after.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&after.stdout),
        String::from_utf8_lossy(&after.stderr)
    );
    let after_document: Value = serde_json::from_slice(&after.stdout)?;
    assert_eq!(after_document["data"]["local_state"], before_state);
    let verified = required_array(&after_document["data"]["coverage_and_gaps"], "verified")?;
    for expected in ["format", "custom:rust-format"] {
        assert!(
            verified
                .iter()
                .any(|value| value.as_str() == Some(expected)),
            "missing verified Rust coverage {expected}: {after_document:#}"
        );
    }
    let after_gaps = required_array(&after_document["data"]["coverage_and_gaps"], "not_verified")?;
    assert!(
        !after_gaps
            .iter()
            .any(|value| value.as_str() == Some("custom:rust-format"))
    );
    for expected in [
        "custom:rust-compile",
        "custom:rust-cross-target",
        "custom:rust-performance",
    ] {
        assert!(
            after_gaps
                .iter()
                .any(|value| value.as_str() == Some(expected)),
            "missing residual Rust coverage gap {expected}: {after_document:#}"
        );
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn evidence_export_json_is_the_exact_privately_persisted_bundle()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::clean_runner_repository("evidence-export-exact")?;

    let output = fixture.run_forge(&["evidence", "export", "--json"])?;

    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let document: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(document["schema"], "forge.evidence/v2");
    assert_eq!(document["ok"], true);
    assert!(required_array(&document["data"], "external_attestations")?.is_empty());
    let evidence_id = document["data"]["id"]
        .as_str()
        .ok_or_else(|| io::Error::other("Evidence ID is missing"))?;
    let object_name = evidence_id
        .strip_prefix("evidence:blake3:")
        .ok_or_else(|| io::Error::other("Evidence ID has the wrong prefix"))?;
    let persisted = fixture
        .private_forge_state_dir()?
        .join("evidence/v2")
        .join(format!("{object_name}.json"));
    let inventory_cache = fixture.private_forge_state_dir()?.join("cache/inventory");
    assert_eq!(
        inventory_cache
            .read_dir()?
            .collect::<Result<Vec<_>, _>>()?
            .len(),
        1,
        "a successful Evidence export is an authorized state write and should publish its retained cache candidate"
    );
    assert_eq!(fs::read(persisted)?, output.stdout);
    Ok(())
}

#[cfg(unix)]
#[test]
fn current_rust_receipt_becomes_scope_stale_and_verify_is_insufficient()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::clean_rust_repository("evidence-scope-stale")?;

    let run = fixture.run_forge(&["evidence", "run", "check", "--json"])?;
    assert_eq!(
        run.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    let current = fixture.run_forge(&["evidence", "show", "--json"])?;
    assert_eq!(current.status.code(), Some(0));
    let current_document: Value = serde_json::from_slice(&current.stdout)?;
    assert_eq!(
        required_array(&current_document["data"], "valid_receipts")?.len(),
        1
    );

    fs::write(
        fixture.worktree.join("src/lib.rs"),
        b"pub fn answer() -> u8 {\n    43\n}\n",
    )?;
    let state_before = fixture.private_state_snapshot()?;
    let worktree_before = fixture.snapshot()?;

    let show = fixture.run_forge(&["evidence", "show", "--json"])?;
    assert_eq!(
        show.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&show.stdout),
        String::from_utf8_lossy(&show.stderr)
    );
    let show_document: Value = serde_json::from_slice(&show.stdout)?;
    assert!(required_array(&show_document["data"], "valid_receipts")?.is_empty());
    let stale = required_array(&show_document["data"], "stale_receipts")?;
    assert_eq!(stale.len(), 1);
    assert_eq!(stale[0]["schema"], "forge.receipt/v2");
    assert!(
        required_array(&stale[0]["validity"], "reasons")?
            .iter()
            .any(|reason| {
                reason["code"] == "dependency-changed" && reason["dependency"] == "scope"
            })
    );

    let verify = fixture.run_forge(&["evidence", "verify", "--json"])?;
    assert_eq!(
        verify.status.code(),
        Some(1),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );
    let verify_document: Value = serde_json::from_slice(&verify.stdout)?;
    assert_eq!(verify_document["data"]["local_state"], "insufficient");
    assert_eq!(fixture.private_state_snapshot()?, state_before);
    assert_eq!(fixture.snapshot()?, worktree_before);
    Ok(())
}

#[cfg(unix)]
#[test]
fn newest_current_failure_controls_coverage_over_an_older_current_pass()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = TestWorkspace::clean_rust_repository("evidence-newest-failure")?;
    let wrapper_directory = fixture.root.join("support/outcome-bin");
    fs::create_dir(&wrapper_directory)?;
    let wrapper = wrapper_directory.join("cargo");
    let trigger = fixture.root.join("support/fail-cargo-check");
    let real_cargo = executable_on_path("cargo")?;
    let script = format!(
        "#!/bin/sh\nset -eu\nif [ \"${{1-}}\" = \"check\" ] && [ -f {} ]; then\n  exit 17\nfi\nexec {} \"$@\"\n",
        shell_single_quote(&trigger)?,
        shell_single_quote(&real_cargo)?,
    );
    fs::write(&wrapper, script)?;
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700))?;
    fs::write(
        fixture.worktree.join("src/main.rs"),
        b"fn main() {\n    println!(\"{}\", forge_evidence_fixture::answer());\n}\n",
    )?;

    let passing = fixture
        .run_forge_with_path_prefix(&["evidence", "run", "check", "--json"], &wrapper_directory)?;
    assert_eq!(
        passing.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&passing.stdout),
        String::from_utf8_lossy(&passing.stderr)
    );

    std::thread::sleep(Duration::from_millis(1_100));
    fs::write(&trigger, b"armed\n")?;
    let failing = fixture
        .run_forge_with_path_prefix(&["evidence", "run", "check", "--json"], &wrapper_directory)?;
    assert_eq!(
        failing.status.code(),
        Some(1),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&failing.stdout),
        String::from_utf8_lossy(&failing.stderr)
    );

    let show =
        fixture.run_forge_with_path_prefix(&["evidence", "show", "--json"], &wrapper_directory)?;
    assert_eq!(
        show.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&show.stdout),
        String::from_utf8_lossy(&show.stderr)
    );
    let document: Value = serde_json::from_slice(&show.stdout)?;
    assert_eq!(
        document["data"]["local_state"], "failing",
        "unexpected Evidence document: {document:#}"
    );
    assert_eq!(
        required_array(&document["data"], "valid_receipts")?.len(),
        1,
        "the older pass remains historical display data"
    );
    assert!(
        required_array(&document["data"]["coverage_and_gaps"], "verified")?.is_empty(),
        "an older pass must not contribute decision coverage"
    );
    assert!(
        !required_array(&document["data"]["coverage_and_gaps"], "not_verified")?.is_empty(),
        "the newest failure must retain its unsatisfied coverage"
    );

    let state_before_next = fixture.private_state_snapshot()?;
    let worktree_before_next = fixture.snapshot()?;
    let next = fixture.run_forge_with_path_prefix(&["next", "--json"], &wrapper_directory)?;
    assert_eq!(
        next.status.code(),
        Some(1),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&next.stdout),
        String::from_utf8_lossy(&next.stderr)
    );
    assert!(next.stderr.is_empty());
    let next_document: Value = serde_json::from_slice(&next.stdout)?;
    assert_eq!(next_document["data"]["state"], "checks-failing");
    assert_eq!(next_document["data"]["required_action"], "fix-failures");
    assert_eq!(next_document["data"]["intent"], "check");
    assert!(next_document["data"]["receipt_command"].is_null());
    assert!(
        next_document["data"]["project_commands"]
            .as_array()
            .is_some_and(|commands| !commands.is_empty())
    );
    assert_eq!(fixture.private_state_snapshot()?, state_before_next);
    assert_eq!(fixture.snapshot()?, worktree_before_next);
    Ok(())
}

#[cfg(unix)]
#[test]
fn changed_project_command_and_policy_are_explicit_stale_reasons()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::clean_rust_repository("evidence-command-policy-stale")?;
    let run = fixture.run_forge(&["evidence", "run", "check", "--json"])?;
    assert_eq!(
        run.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    fs::write(
        fixture.worktree.join("forge.toml"),
        b"schema = 1\n\n[commands.check]\nprogram = \"cargo\"\nargs = [\"check\"]\ninputs = [\"**\"]\nmutability = \"external-side-effect\"\nnetwork = \"inherit\"\nsuccess = \"exit-zero\"\ncoverage = [\"compile\"]\nenforcement = \"required\"\n\n[[risk]]\nid = \"risk/fixture-source\"\nlevel = \"high\"\npaths = [\"src/**\"]\nexternal = []\n",
    )?;
    let state_before = fixture.private_state_snapshot()?;

    let show = fixture.run_forge(&["evidence", "show", "--json"])?;

    assert_eq!(
        show.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&show.stdout),
        String::from_utf8_lossy(&show.stderr)
    );
    let document: Value = serde_json::from_slice(&show.stdout)?;
    let stale = required_array(&document["data"], "stale_receipts")?;
    assert_eq!(stale.len(), 1);
    let reasons = required_array(&stale[0]["validity"], "reasons")?;
    for dependency in ["scope", "command", "toolchain", "environment", "policy"] {
        assert!(
            reasons.iter().any(|reason| {
                reason["code"] == "dependency-changed" && reason["dependency"] == dependency
            }),
            "missing `{dependency}` stale reason: {reasons:#?}"
        );
    }
    assert_eq!(fixture.private_state_snapshot()?, state_before);
    Ok(())
}

#[cfg(unix)]
#[test]
fn evidence_show_fails_closed_when_confirmation_detection_drifts()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = TestWorkspace::clean_rust_repository("evidence-detection-drift")?;
    let run = fixture.run_forge(&["evidence", "run", "check", "--json"])?;
    assert_eq!(
        run.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    let state_before = fixture.private_state_snapshot()?;

    let wrapper_directory = fixture.root.join("support/drift-bin");
    fs::create_dir(&wrapper_directory)?;
    let wrapper = wrapper_directory.join("cargo");
    let trigger = fixture.root.join("support/trigger-detection-drift");
    fs::write(&trigger, b"armed\n")?;
    let config = fixture.worktree.join("forge.toml");
    let real_cargo = executable_on_path("cargo")?;
    let script = format!(
        "#!/bin/sh\nset -eu\nif [ \"${{1-}}\" = \"--version\" ] && [ -f {} ]; then\n  printf '%s\\n' 'schema = 1' > {}\nfi\nexec {} \"$@\"\n",
        shell_single_quote(&trigger)?,
        shell_single_quote(&config)?,
        shell_single_quote(&real_cargo)?,
    );
    fs::write(&wrapper, script)?;
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700))?;

    let output =
        fixture.run_forge_with_path_prefix(&["evidence", "show", "--json"], &wrapper_directory)?;

    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let document: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(structured_diagnostic_code(&document)?, "FGE3312");
    assert_eq!(fs::read_to_string(config)?, "schema = 1\n");
    assert_eq!(fixture.private_state_snapshot()?, state_before);
    Ok(())
}

#[cfg(unix)]
#[test]
fn evidence_show_fails_closed_on_corrupt_private_state_without_repairing_it()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = TestWorkspace::clean_runner_repository("evidence-corrupt-state")?;
    let seed = fixture.run_forge(&["evidence", "run", "check", "--json"])?;
    assert_eq!(
        seed.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&seed.stdout),
        String::from_utf8_lossy(&seed.stderr)
    );
    let state = fixture.private_forge_state_dir()?;
    let receipts = state.join("receipts/v2");
    fs::create_dir_all(&receipts)?;
    for directory in [&state, &state.join("receipts"), &receipts] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    }
    let corrupt = receipts.join(format!("{}.json", "a".repeat(64)));
    fs::write(&corrupt, b"{}\n")?;
    fs::set_permissions(&corrupt, fs::Permissions::from_mode(0o600))?;
    let before = fixture.private_state_snapshot()?;

    let output = fixture.run_forge(&["evidence", "show", "--json"])?;

    assert_eq!(output.status.code(), Some(65));
    assert!(output.stderr.is_empty());
    let document: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(structured_diagnostic_code(&document)?, "FGE3308");
    assert_eq!(fixture.private_state_snapshot()?, before);

    let doctor = fixture.run_forge(&["doctor", "--json"])?;
    assert_eq!(doctor.status.code(), Some(65));
    assert!(doctor.stderr.is_empty());
    let doctor_document: Value = serde_json::from_slice(&doctor.stdout)?;
    assert_eq!(doctor_document["schema"], "forge.doctor/v1");
    assert_eq!(doctor_document["ok"], true);
    assert_eq!(
        required_doctor_check(&doctor_document, "state.layout")?["status"],
        "fail"
    );
    assert_eq!(fixture.private_state_snapshot()?, before);

    let run = fixture.run_forge(&["evidence", "run", "check", "--json"])?;
    assert_eq!(run.status.code(), Some(65));
    assert!(run.stderr.is_empty());
    let run_document: Value = serde_json::from_slice(&run.stdout)?;
    assert_eq!(structured_diagnostic_code(&run_document)?, "FGE3214");
    assert_eq!(fixture.private_state_snapshot()?, before);

    let next = fixture.run_forge(&["next", "--json"])?;
    assert_eq!(next.status.code(), Some(65));
    assert!(next.stderr.is_empty());
    let next_document: Value = serde_json::from_slice(&next.stdout)?;
    assert_eq!(next_document["data"]["state"], "unknown");
    assert_eq!(next_document["data"]["required_action"], "run-doctor");
    assert_eq!(
        next_document["data"]["provenance"],
        serde_json::json!(["navigation.receipts-corrupt.v1"])
    );
    assert_eq!(
        next_document["data"]["reason"],
        "retained private Evidence state is corrupt and cannot be used for navigation"
    );
    assert!(!String::from_utf8_lossy(&next.stdout).contains("/.git/forge"));
    assert_eq!(fixture.private_state_snapshot()?, before);
    Ok(())
}

#[cfg(unix)]
#[test]
fn navigation_degrades_future_receipt_schema_and_layout_without_repairing_state()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt as _;

    #[derive(Debug, Clone, Copy)]
    enum FutureState {
        Schema,
        Layout,
    }

    for case in [FutureState::Schema, FutureState::Layout] {
        let fixture = TestWorkspace::clean_runner_repository(&format!("evidence-future-{case:?}"))?;
        let state = fixture.private_forge_state_dir()?;
        let receipts = state.join("receipts");
        let version = receipts.join(match case {
            FutureState::Schema => "v2",
            FutureState::Layout => "v3",
        });
        fs::create_dir_all(&version)?;
        for directory in [&state, &receipts, &version] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        }
        if matches!(case, FutureState::Schema) {
            let future = version.join(format!("{}.json", "b".repeat(64)));
            fs::write(
                &future,
                br#"{"schema":"forge.receipt/v3","tool_version":"future","ok":true,"data":{},"diagnostics":[],"truncated":false,"artifacts":[]}
"#,
            )?;
            fs::set_permissions(&future, fs::Permissions::from_mode(0o600))?;
        }
        let before = fixture.private_state_snapshot()?;

        let show = fixture.run_forge(&["evidence", "show", "--json"])?;
        assert_eq!(show.status.code(), Some(65), "future fixture {case:?}");
        let show_document: Value = serde_json::from_slice(&show.stdout)?;
        assert_eq!(structured_diagnostic_code(&show_document)?, "FGE3308");

        let doctor = fixture.run_forge(&["doctor", "--json"])?;
        assert_eq!(doctor.status.code(), Some(65), "future fixture {case:?}");
        assert!(doctor.stderr.is_empty());
        let doctor_document: Value = serde_json::from_slice(&doctor.stdout)?;
        assert_eq!(doctor_document["schema"], "forge.doctor/v1");
        assert_eq!(doctor_document["ok"], true);
        assert_eq!(
            required_doctor_check(&doctor_document, "state.layout")?["status"],
            "fail"
        );

        let next = fixture.run_forge(&["next", "--json"])?;
        assert_eq!(next.status.code(), Some(65), "future fixture {case:?}");
        assert!(next.stderr.is_empty());
        let next_document: Value = serde_json::from_slice(&next.stdout)?;
        assert_eq!(next_document["data"]["state"], "unknown");
        assert_eq!(next_document["data"]["required_action"], "run-doctor");
        assert_eq!(
            next_document["data"]["provenance"],
            serde_json::json!(["navigation.receipts-future.v1"])
        );
        assert_eq!(fixture.private_state_snapshot()?, before);
    }
    Ok(())
}
