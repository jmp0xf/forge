//! Reviewable byte-for-byte contracts for representative human-readable CLI output.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContentAddressNormalization {
    None,
    EvidenceObject,
    ReceiptObject,
}

#[derive(Debug)]
struct GoldenWorkspace {
    root: PathBuf,
    worktree: PathBuf,
    global_git_config: PathBuf,
    xdg_config_home: PathBuf,
}

impl GoldenWorkspace {
    fn clean_repository(label: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let fixture_parent =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/human-golden-fixtures");
        fs::create_dir_all(&fixture_parent)?;
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let fixture_id = NEXT_FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
        let root = fixture_parent.join(format!(
            "{label}-{}-{nonce}-{fixture_id}",
            std::process::id()
        ));
        let worktree = root.join("worktree");
        let support = root.join("support");
        let xdg_config_home = support.join("xdg");
        fs::create_dir_all(&worktree)?;
        fs::create_dir_all(&xdg_config_home)?;
        let global_git_config = support.join("global.gitconfig");
        fs::write(&global_git_config, b"")?;

        let fixture = Self {
            root,
            worktree,
            global_git_config,
            xdg_config_home,
        };
        fixture.run_git(&["init", "--quiet"])?;
        fs::write(
            fixture.worktree.join("README.md"),
            b"# Human output golden fixture\n",
        )?;
        fs::write(
            fixture.worktree.join("forge.toml"),
            b"schema = 1\n\n[commands.check]\nprogram = \"golden-check\"\nargs = []\ninputs = [\"**\"]\nmutability = \"read-only\"\nnetwork = \"offline-requested\"\nsuccess = \"exit-zero\"\ncoverage = [\"compile\"]\nenforcement = \"required\"\n",
        )?;
        fixture.run_git(&["add", "--", "README.md", "forge.toml"])?;
        fixture.run_git(&[
            "-c",
            "user.name=Forge golden tests",
            "-c",
            "user.email=forge-golden-tests@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "fixture baseline",
        ])?;
        Ok(fixture)
    }

    fn use_git_version_check(&self) -> Result<(), Box<dyn std::error::Error>> {
        fs::write(
            self.worktree.join("forge.toml"),
            b"schema = 1\n\n[commands.check]\nprogram = \"git\"\nargs = [\"--version\"]\ninputs = [\"**\"]\nmutability = \"read-only\"\nnetwork = \"offline-requested\"\nsuccess = \"exit-zero\"\ncoverage = [\"compile\"]\nenforcement = \"required\"\n",
        )?;
        self.run_git(&["add", "--", "forge.toml"])?;
        self.run_git(&[
            "-c",
            "user.name=Forge golden tests",
            "-c",
            "user.email=forge-golden-tests@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "use available golden command",
        ])?;
        Ok(())
    }

    fn run_forge(&self, arguments: &[&str]) -> Result<Output, Box<dyn std::error::Error>> {
        let mut command = ProcessCommand::new(env!("CARGO_BIN_EXE_forge"));
        command
            .current_dir(&self.worktree)
            .arg("--no-cache")
            .args(arguments);
        self.configure_git_environment(&mut command);
        Ok(command.output()?)
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

    fn git_stdout(&self, arguments: &[&str]) -> io::Result<Vec<u8>> {
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
            .env("LC_ALL", "C")
            .env("GIT_AUTHOR_DATE", "2000-01-01T00:00:00Z")
            .env("GIT_COMMITTER_DATE", "2000-01-01T00:00:00Z");
    }

    fn normalized_stdout(
        &self,
        output: Output,
        expected_exit: i32,
        content_address: ContentAddressNormalization,
    ) -> Result<String, Box<dyn std::error::Error>> {
        assert_eq!(
            output.status.code(),
            Some(expected_exit),
            "unexpected exit; stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.stderr.is_empty(),
            "human result unexpectedly wrote stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut stdout = String::from_utf8(output.stdout)?;

        // Detection reports Git's native absolute repository spelling. On Windows that spelling
        // intentionally differs from `std::fs::canonicalize`'s verbatim (`\\?\`) path, so derive
        // the exact display through the same Git contract instead of guessing separator aliases.
        let repository_root = String::from_utf8(self.git_stdout(&[
            "rev-parse",
            "--path-format=absolute",
            "--show-toplevel",
        ])?)?;
        let repository_root = repository_root.trim_end();
        if stdout.lines().any(|line| line.starts_with("root: ")) {
            assert!(
                stdout.contains(&format!("root: {repository_root}")),
                "human output did not use Git's exact repository-root spelling"
            );
            stdout = stdout.replace(repository_root, "<REPOSITORY_ROOT>");
        }

        let process_capability = if cfg!(windows) {
            "Windows Job Object isolation"
        } else {
            "Unix process-group isolation"
        };
        let process_capability_line = format!(
            "[pass] process.capability: the compiled runtime provides {process_capability} for timeout and cancellation"
        );
        if stdout.contains(&process_capability_line) {
            stdout = stdout.replace(
                &process_capability_line,
                "[pass] process.capability: the compiled runtime provides <PROCESS_TREE_CAPABILITY> for timeout and cancellation",
            );
        }

        // Repository identity is intentionally derived from the native absolute Git common-dir
        // path, which is unique for every fixture instance.
        replace_prefixed_line(
            &mut stdout,
            "repository: local:blake3:",
            "repository: <REPOSITORY_ID>",
        );

        match content_address {
            ContentAddressNormalization::None => {}
            ContentAddressNormalization::EvidenceObject => {
                // Evidence binds its content address to the current clock even though the human
                // summary omits the timestamp. Normalize only that content-addressed field.
                assert!(
                    replace_prefixed_line(
                        &mut stdout,
                        "- evidence object: ",
                        "- evidence object: <EVIDENCE_OBJECT>",
                    ),
                    "evidence human output omitted its content-addressed object field"
                );
            }
            ContentAddressNormalization::ReceiptObject => {
                // A Receipt includes observation timestamps and command output identities.
                assert!(
                    replace_prefixed_line(
                        &mut stdout,
                        "receipt object: ",
                        "receipt object: <RECEIPT_OBJECT>",
                    ),
                    "Evidence run output omitted its content-addressed Receipt field"
                );
            }
        }
        Ok(stdout)
    }
}

impl Drop for GoldenWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn replace_prefixed_line(value: &mut String, prefix: &str, replacement: &str) -> bool {
    let start = if value.starts_with(prefix) {
        Some(0)
    } else {
        value.match_indices(prefix).find_map(|(index, _)| {
            value
                .as_bytes()
                .get(index.wrapping_sub(1))
                .eq(&Some(&b'\n'))
                .then_some(index)
        })
    };
    let Some(start) = start else {
        return false;
    };
    let end = value[start..]
        .find('\n')
        .map_or(value.len(), |offset| start + offset);
    value.replace_range(start..end, replacement);
    true
}

fn run_without_repository(arguments: &[&str]) -> Result<Output, Box<dyn std::error::Error>> {
    Ok(ProcessCommand::new(env!("CARGO_BIN_EXE_forge"))
        .args(arguments)
        .output()?)
}

fn assert_golden(name: &str, actual: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden/human")
        .join(name);
    let expected = fs::read_to_string(&path)?;
    assert!(
        actual == expected,
        "human output differs from {}\n\n--- expected ---\n{}--- actual ---\n{}--- end ---",
        path.display(),
        expected,
        actual,
    );
    Ok(())
}

fn assert_static_command(name: &str, arguments: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let output = run_without_repository(arguments)?;
    assert_eq!(output.status.code(), Some(0));
    assert!(
        output.stderr.is_empty(),
        "human result unexpectedly wrote stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_golden(name, &String::from_utf8(output.stdout)?)
}

fn assert_failure_golden(
    name: &str,
    arguments: &[&str],
    expected_exit: i32,
) -> Result<(), Box<dyn std::error::Error>> {
    let output = run_without_repository(arguments)?;
    assert_eq!(
        output.status.code(),
        Some(expected_exit),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "human failure unexpectedly wrote stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_golden(name, &String::from_utf8(output.stderr)?)
}

#[test]
fn version_human_output_matches_golden() -> Result<(), Box<dyn std::error::Error>> {
    assert_static_command("version.txt", &["version"])
}

#[test]
fn schema_list_human_output_matches_golden() -> Result<(), Box<dyn std::error::Error>> {
    assert_static_command("schema-list.txt", &["schema"])
}

#[test]
fn completions_bash_output_matches_golden_byte_for_byte() -> Result<(), Box<dyn std::error::Error>>
{
    assert_static_command("completions-bash.txt", &["completions", "bash"])
}

#[test]
fn unknown_schema_human_diagnostic_matches_golden() -> Result<(), Box<dyn std::error::Error>> {
    assert_failure_golden(
        "schema-unknown-error.txt",
        &["schema", "not-a-schema", "--color", "never"],
        64,
    )
}

#[test]
fn explain_human_output_matches_golden() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = GoldenWorkspace::clean_repository("explain")?;
    let output = fixture.run_forge(&["explain"])?;
    let stdout = fixture.normalized_stdout(output, 0, ContentAddressNormalization::None)?;
    assert_golden("explain.txt", &stdout)
}

#[test]
fn init_human_output_matches_golden() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = GoldenWorkspace::clean_repository("init")?;
    let output = fixture.run_forge(&["init"])?;
    let stdout = fixture.normalized_stdout(output, 0, ContentAddressNormalization::None)?;
    assert_golden("init.txt", &stdout)
}

#[test]
fn doctor_human_output_matches_golden() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = GoldenWorkspace::clean_repository("doctor")?;
    fixture.use_git_version_check()?;
    let output = fixture.run_forge(&["doctor"])?;
    let stdout = fixture.normalized_stdout(output, 1, ContentAddressNormalization::None)?;
    assert_golden("doctor.txt", &stdout)
}

#[test]
fn next_human_output_matches_golden() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = GoldenWorkspace::clean_repository("next")?;
    fixture.use_git_version_check()?;
    let output = fixture.run_forge(&["next"])?;
    let stdout = fixture.normalized_stdout(output, 0, ContentAddressNormalization::None)?;
    assert_golden("next.txt", &stdout)
}

#[test]
fn adapters_check_human_output_matches_golden() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = GoldenWorkspace::clean_repository("adapters")?;
    let output = fixture.run_forge(&["adapters", "check"])?;
    let stdout = fixture.normalized_stdout(output, 1, ContentAddressNormalization::None)?;
    assert_golden("adapters-check.txt", &stdout)
}

#[test]
fn adapters_sync_dry_run_human_output_matches_golden() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = GoldenWorkspace::clean_repository("adapters-sync")?;
    let output = fixture.run_forge(&["adapters", "sync", "--dry-run"])?;
    let stdout = fixture.normalized_stdout(output, 0, ContentAddressNormalization::None)?;
    assert_golden("adapters-sync-dry-run.txt", &stdout)
}

#[test]
fn evidence_run_quiet_human_output_matches_golden() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = GoldenWorkspace::clean_repository("evidence-run")?;
    fixture.use_git_version_check()?;
    let output = fixture.run_forge(&["--quiet", "evidence", "run", "check"])?;
    let stdout =
        fixture.normalized_stdout(output, 0, ContentAddressNormalization::ReceiptObject)?;
    assert_golden("evidence-run.txt", &stdout)
}

#[test]
fn evidence_show_human_output_matches_golden() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = GoldenWorkspace::clean_repository("evidence")?;
    let output = fixture.run_forge(&["evidence", "show"])?;
    let stdout =
        fixture.normalized_stdout(output, 0, ContentAddressNormalization::EvidenceObject)?;
    assert_golden("evidence-show.txt", &stdout)
}

#[test]
fn evidence_verify_human_output_matches_golden() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = GoldenWorkspace::clean_repository("evidence-verify")?;
    let output = fixture.run_forge(&["evidence", "verify"])?;
    let stdout =
        fixture.normalized_stdout(output, 2, ContentAddressNormalization::EvidenceObject)?;
    assert_golden("evidence-verify.txt", &stdout)
}

#[test]
fn evidence_export_human_output_matches_golden() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = GoldenWorkspace::clean_repository("evidence-export")?;
    let output = fixture.run_forge(&["evidence", "export"])?;
    let stdout =
        fixture.normalized_stdout(output, 0, ContentAddressNormalization::EvidenceObject)?;
    assert_golden("evidence-export.txt", &stdout)
}
