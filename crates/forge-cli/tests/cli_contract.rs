//! End-to-end stdout, stderr, and exit-code contracts for the bootstrap commands.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

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

static NEXT_FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

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

    fn run_forge(&self, arguments: &[&str]) -> Result<Output, Box<dyn std::error::Error>> {
        let mut command = ProcessCommand::new(env!("CARGO_BIN_EXE_forge"));
        command.current_dir(&self.worktree).args(arguments);
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

#[test]
fn version_human_output_is_stable_and_quiet() -> Result<(), Box<dyn std::error::Error>> {
    let output = run(&["version"])?;

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8(output.stdout)?, "forge 0.0.0\n");
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
    assert_eq!(document["data"]["version"], "0.0.0");
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
fn init_defaults_to_a_deterministic_read_only_plan() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = TestWorkspace::zero_config_repository("init-dry-run")?;
    let before = fixture.snapshot()?;

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
    let edits = required_array(&document["data"], "edits")?;
    assert_eq!(edits.len(), 1);
    assert_eq!(edits[0]["kind"], "create");
    assert_eq!(edits[0]["path"]["display"], "AGENTS.md");
    assert_eq!(fixture.snapshot()?, before);
    assert!(!fixture.worktree.join("AGENTS.md").exists());
    fixture.assert_no_forge_artifacts();
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
