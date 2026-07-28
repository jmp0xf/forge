//! Named end-to-end checks for special conditions in the public v0 fixture matrix.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::Value;

const REQUIRED_FIXTURES: &[&str] = &[
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

const COMMANDLESS_UNINSTALL_SCENARIOS: &[&str] = &[
    "empty-repo",
    "huge-output",
    "malicious-runner",
    "timeout-tree",
];

const INIT_MANAGED_PROJECT_FILES: &[&str] = &["AGENTS.md", "CLAUDE.md", "forge.toml"];

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Eq, PartialEq)]
enum WorktreeEntry {
    Directory,
    File(Vec<u8>),
    Symlink(PathBuf),
    Other,
}

type WorktreeSnapshot = Vec<(PathBuf, WorktreeEntry)>;

#[test]
fn public_manifest_contains_the_exact_v0_matrix_without_forge_owned_project_commands()
-> Result<(), Box<dyn std::error::Error>> {
    let manifest: Value = serde_json::from_slice(&fs::read(
        repository_root().join("fixtures/generated/manifest-v1.json"),
    )?)?;
    let fixtures = manifest["fixtures"]
        .as_array()
        .ok_or("fixture manifest omitted fixtures")?;
    let mut observed = BTreeSet::new();
    for fixture in fixtures {
        let id = fixture["id"].as_str().ok_or("fixture omitted id")?;
        assert!(observed.insert(id), "duplicate fixture `{id}`");
        for command in fixture["commands"]
            .as_array()
            .ok_or("fixture omitted commands")?
        {
            assert_ne!(
                command["program"].as_str(),
                Some("forge"),
                "fixture `{id}` made Forge a project-native dependency"
            );
        }
    }
    assert_eq!(
        observed,
        REQUIRED_FIXTURES.iter().copied().collect::<BTreeSet<_>>()
    );
    Ok(())
}

#[test]
fn rust_package_with_a_path_dependency_uses_metadata_without_writing_a_lockfile()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = FixtureWorkspace::from_generated("rust-no-lock")?;
    let lockfile = fixture.worktree.join("Cargo.lock");
    assert!(
        !lockfile.exists(),
        "fixture unexpectedly started with Cargo.lock"
    );
    fixture.initialize_git()?;
    let before = fixture.snapshot_worktree()?;

    let output = fixture.run_forge(&["explain", "--json"])?;

    assert_eq!(output.status.code(), Some(0), "{}", display_output(&output));
    assert_eq!(
        fixture.snapshot_worktree()?,
        before,
        "read-only Rust detection changed the worktree"
    );
    assert!(
        !lockfile.exists(),
        "cargo metadata created a lockfile during read-only detection"
    );

    let document: Value = serde_json::from_slice(&output.stdout)?;
    let units = required_array(&document["data"], "units")?;
    let mut display_names = BTreeSet::new();
    for unit in units {
        let display_name = unit["display_name"]
            .as_str()
            .ok_or("Rust unit omitted display_name")?;
        assert!(display_names.insert(display_name));
        assert_eq!(unit["language"], "rust");
    }
    assert_eq!(
        display_names,
        ["fixture-rust-no-lock", "fixture-rust-no-lock-support",]
            .into_iter()
            .collect()
    );

    let unit_details = required_array(&document["data"], "unit_details")?;
    assert_eq!(unit_details.len(), 2);
    for unit_detail in unit_details {
        let derivation = &unit_detail["derivation_evidence"];
        assert_eq!(derivation["confidence"], "high");
        assert!(
            required_array(derivation, "provenance")?
                .iter()
                .any(|source| source["rule_id"] == "rust.cargo-metadata-v1"),
            "a Rust unit came from static fallback instead of validated cargo metadata"
        );
    }
    Ok(())
}

#[test]
fn brownfield_runners_and_adapter_text_are_preserved_byte_for_byte()
-> Result<(), Box<dyn std::error::Error>> {
    for (fixture_id, runner_path) in [
        ("brownfield-make", "Makefile"),
        ("brownfield-just", "justfile"),
        ("brownfield-task", "Taskfile.yml"),
    ] {
        let fixture = FixtureWorkspace::from_generated(fixture_id)?;
        let runner_before = fs::read(fixture.worktree.join(runner_path))?;
        fixture.initialize_git()?;

        let output = fixture.run_forge(&["init", "--apply", "--json"])?;

        assert_eq!(output.status.code(), Some(0), "{}", display_output(&output));
        assert_eq!(fs::read(fixture.worktree.join(runner_path))?, runner_before);
        assert!(fixture.worktree.join("AGENTS.md").is_file());
    }

    let fixture = FixtureWorkspace::from_generated("brownfield-adapters")?;
    let agents_before = fs::read(fixture.worktree.join("AGENTS.md"))?;
    let claude_before = fs::read(fixture.worktree.join("CLAUDE.md"))?;
    fixture.initialize_git()?;

    let output = fixture.run_forge(&["init", "--apply", "--adapter", "claude", "--json"])?;

    assert_eq!(output.status.code(), Some(0), "{}", display_output(&output));
    let agents_after = fs::read(fixture.worktree.join("AGENTS.md"))?;
    let claude_after = fs::read(fixture.worktree.join("CLAUDE.md"))?;
    assert!(agents_after.starts_with(&agents_before));
    assert!(claude_after.starts_with(&claude_before));
    assert!(String::from_utf8_lossy(&agents_after).contains("forge:begin block=project-index"));
    assert!(String::from_utf8_lossy(&claude_after).contains("forge:begin block=claude-pointer"));
    Ok(())
}

#[test]
fn dirty_worktree_can_be_previewed_but_apply_requires_explicit_permission()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = FixtureWorkspace::from_generated("dirty-worktree")?;
    fixture.initialize_git()?;
    let dirty_path = fixture.worktree.join("human-work-in-progress.txt");
    let dirty_bytes = b"do not overwrite this uncommitted work\n";
    fs::write(&dirty_path, dirty_bytes)?;
    let before = fixture.snapshot_worktree()?;

    let preview = fixture.run_forge(&["init", "--json"])?;
    assert_eq!(
        preview.status.code(),
        Some(0),
        "{}",
        display_output(&preview)
    );
    assert_eq!(fixture.snapshot_worktree()?, before);

    let rejected = fixture.run_forge(&["init", "--apply", "--json"])?;
    assert_eq!(
        rejected.status.code(),
        Some(2),
        "{}",
        display_output(&rejected)
    );
    assert_eq!(fixture.snapshot_worktree()?, before);

    let applied = fixture.run_forge(&["init", "--apply", "--allow-dirty", "--json"])?;
    assert_eq!(
        applied.status.code(),
        Some(0),
        "{}",
        display_output(&applied)
    );
    assert_eq!(fs::read(dirty_path)?, dirty_bytes);
    assert!(fixture.worktree.join("AGENTS.md").is_file());
    Ok(())
}

#[test]
fn non_git_and_empty_repository_fixtures_fail_before_writing_adapters()
-> Result<(), Box<dyn std::error::Error>> {
    let non_git = FixtureWorkspace::from_generated("non-git")?;
    let before = non_git.snapshot_worktree()?;
    let output = non_git.run_forge(&["init", "--apply", "--json"])?;
    assert_eq!(output.status.code(), Some(2), "{}", display_output(&output));
    assert_eq!(non_git.snapshot_worktree()?, before);
    assert!(!non_git.worktree.join("AGENTS.md").exists());

    let empty = FixtureWorkspace::from_generated("empty-repo")?;
    empty.initialize_git()?;
    let before = empty.snapshot_worktree()?;
    let output = empty.run_forge(&["init", "--apply", "--json"])?;
    assert_eq!(output.status.code(), Some(2), "{}", display_output(&output));
    assert_eq!(empty.snapshot_worktree()?, before);
    assert!(!empty.worktree.join("AGENTS.md").exists());
    Ok(())
}

#[test]
fn linked_worktrees_keep_private_state_and_receipts_isolated()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = FixtureWorkspace::from_generated("linked-worktrees")?;
    fixture.initialize_git()?;
    let linked = fixture.root.join("linked-worktree");
    let linked_text = linked
        .to_str()
        .ok_or("temporary linked-worktree path is not UTF-8")?;
    fixture.run_git(&[
        "worktree",
        "add",
        "--quiet",
        "--detach",
        linked_text,
        "HEAD",
    ])?;

    let main_git_dir = fixture.git_dir(&fixture.worktree)?;
    let linked_git_dir = fixture.git_dir(&linked)?;
    assert_ne!(main_git_dir, linked_git_dir);
    assert!(!main_git_dir.join("forge").exists());
    assert!(!linked_git_dir.join("forge").exists());

    let main_run =
        fixture.run_forge_in(&fixture.worktree, &["evidence", "run", "test", "--json"])?;
    assert_eq!(
        main_run.status.code(),
        Some(0),
        "{}",
        display_output(&main_run)
    );
    assert!(main_git_dir.join("forge/receipts/v2").is_dir());
    let shared_inventory_cache = main_git_dir.join("forge/cache/inventory");
    let cache_entries = receipt_files(&shared_inventory_cache)?;
    assert_eq!(cache_entries.len(), 1);

    let linked_show = fixture.run_forge_in(&linked, &["evidence", "show", "--json"])?;
    assert_eq!(
        linked_show.status.code(),
        Some(0),
        "{}",
        display_output(&linked_show)
    );
    let linked_document: Value = serde_json::from_slice(&linked_show.stdout)?;
    assert!(required_array(&linked_document["data"], "valid_receipts")?.is_empty());
    assert!(required_array(&linked_document["data"], "stale_receipts")?.is_empty());
    assert!(
        !linked_git_dir.join("forge").exists(),
        "a read-only Evidence view created linked-worktree state"
    );
    assert_eq!(
        receipt_files(&shared_inventory_cache)?,
        cache_entries,
        "the linked worktree should reuse the same immutable inventory cache entry"
    );

    let linked_explain = fixture.run_forge_in(&linked, &["-v", "explain", "--json"])?;
    assert_eq!(
        linked_explain.status.code(),
        Some(0),
        "{}",
        display_output(&linked_explain)
    );
    assert_eq!(
        linked_explain.stderr, b"inventory-cache: hit\n",
        "the linked worktree must report an actual immutable cache hit"
    );
    let _: Value = serde_json::from_slice(&linked_explain.stdout)?;

    let linked_run = fixture.run_forge_in(&linked, &["evidence", "run", "test", "--json"])?;
    assert_eq!(
        linked_run.status.code(),
        Some(0),
        "{}",
        display_output(&linked_run)
    );
    assert!(linked_git_dir.join("forge/receipts/v2").is_dir());
    assert!(!receipt_files(&main_git_dir.join("forge/receipts/v2"))?.is_empty());
    assert!(!receipt_files(&linked_git_dir.join("forge/receipts/v2"))?.is_empty());
    Ok(())
}

#[test]
fn read_only_cache_misses_do_not_publish_and_no_cache_bypasses_existing_entries()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = FixtureWorkspace::from_generated("brownfield-make")?;
    fixture.initialize_git()?;
    let git_dir = fixture.git_dir(&fixture.worktree)?;
    let private_root = git_dir.join("forge");
    assert!(!private_root.exists());

    let uncached = fixture.run_forge(&["-v", "--no-cache", "explain", "--json"])?;
    assert_eq!(
        uncached.status.code(),
        Some(0),
        "{}",
        display_output(&uncached)
    );
    assert!(
        !private_root.exists(),
        "--no-cache must not create Git-private cache state"
    );
    assert_eq!(uncached.stderr, b"inventory-cache: disabled\n");

    let quiet_uncached = fixture.run_forge(&["-q", "-v", "--no-cache", "explain", "--json"])?;
    assert_eq!(
        quiet_uncached.status.code(),
        Some(0),
        "{}",
        display_output(&quiet_uncached)
    );
    assert!(
        quiet_uncached.stderr.is_empty(),
        "--quiet must suppress verbose cache diagnostics"
    );

    let cache_miss = fixture.run_forge(&["-v", "explain", "--json"])?;
    assert_eq!(
        cache_miss.status.code(),
        Some(0),
        "{}",
        display_output(&cache_miss)
    );
    assert_eq!(cache_miss.stderr, b"inventory-cache: miss\n");
    assert!(
        !private_root.exists(),
        "read-only explain must report a miss without publishing it"
    );

    let shown = fixture.run_forge(&["evidence", "show", "--json"])?;
    assert_eq!(shown.status.code(), Some(0), "{}", display_output(&shown));
    assert!(
        !private_root.exists(),
        "evidence show must not publish a detection-cache miss"
    );

    let verified = fixture.run_forge(&["evidence", "verify", "--json"])?;
    assert_eq!(
        verified.status.code(),
        Some(2),
        "{}",
        display_output(&verified)
    );
    assert!(
        !private_root.exists(),
        "evidence verify must not publish a detection-cache miss"
    );

    let uncached_run = fixture.run_forge(&["--no-cache", "evidence", "run", "test", "--json"])?;
    assert_eq!(
        uncached_run.status.code(),
        Some(0),
        "{}",
        display_output(&uncached_run)
    );
    let inventory_cache = private_root.join("cache/inventory");
    assert!(
        !inventory_cache.exists(),
        "--no-cache evidence run must persist its Receipt without publishing inventory cache"
    );

    let primed = fixture.run_forge(&["evidence", "run", "test", "--json"])?;
    assert_eq!(primed.status.code(), Some(0), "{}", display_output(&primed));
    let before = receipt_files(&inventory_cache)?
        .into_iter()
        .map(|path| Ok((path.clone(), fs::read(path)?)))
        .collect::<Result<Vec<_>, io::Error>>()?;
    assert_eq!(before.len(), 1);

    let cache_hit = fixture.run_forge(&["-v", "explain", "--json"])?;
    assert_eq!(
        cache_hit.status.code(),
        Some(0),
        "{}",
        display_output(&cache_hit)
    );
    assert_eq!(cache_hit.stderr, b"inventory-cache: hit\n");

    let bypassed = fixture.run_forge(&["-v", "--no-cache", "explain", "--json"])?;
    assert_eq!(
        bypassed.status.code(),
        Some(0),
        "{}",
        display_output(&bypassed)
    );
    let after = receipt_files(&inventory_cache)?
        .into_iter()
        .map(|path| Ok((path.clone(), fs::read(path)?)))
        .collect::<Result<Vec<_>, io::Error>>()?;
    assert_eq!(
        after, before,
        "--no-cache must not rewrite or delete entries"
    );
    assert_eq!(bypassed.stderr, b"inventory-cache: disabled\n");
    Ok(())
}

#[test]
fn submodule_gitlink_is_a_non_recursive_boundary() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = FixtureWorkspace::from_generated("submodule")?;
    fixture.initialize_git()?;

    let dependency = fixture.root.join("dependency-repository");
    fs::create_dir_all(&dependency)?;
    fs::write(
        dependency.join("dependency.txt"),
        fs::read(fixture.worktree.join("dependency-seed.txt"))?,
    )?;
    fixture.run_git_in(&dependency, &["init", "--quiet"])?;
    fixture.run_git_in(&dependency, &["add", "--all", "--"])?;
    fixture.commit_in(&dependency, "dependency baseline")?;

    let dependency_text = dependency
        .to_str()
        .ok_or("temporary submodule source path is not UTF-8")?;
    fixture.run_git(&[
        "-c",
        "protocol.file.allow=always",
        "submodule",
        "add",
        "--quiet",
        dependency_text,
        "vendor/dependency",
    ])?;
    fixture.commit_in(&fixture.worktree, "add local submodule")?;

    let output = fixture.run_forge(&["init", "--apply", "--json"])?;
    assert_eq!(output.status.code(), Some(0), "{}", display_output(&output));
    assert!(fixture.worktree.join("AGENTS.md").is_file());
    assert!(
        !fixture
            .worktree
            .join("vendor/dependency/AGENTS.md")
            .exists()
    );

    let stage = fixture.git_stdout_in(
        &fixture.worktree,
        &["ls-files", "--stage", "--", "vendor/dependency"],
    )?;
    assert!(
        stage.starts_with(b"160000 "),
        "submodule stopped being a Gitlink: {}",
        String::from_utf8_lossy(&stage)
    );
    let submodule_git_dir = fixture.git_dir(&fixture.worktree.join("vendor/dependency"))?;
    assert!(!submodule_git_dir.join("forge").exists());
    Ok(())
}

// Darwin filesystems reject malformed UTF-8 names before Git or Forge can observe them. Linux and
// other byte-preserving Unix hosts exercise the native-path contract here; Windows needs a
// separate wide-path fixture.
#[cfg(all(unix, not(any(target_os = "macos", target_os = "ios"))))]
#[test]
fn unix_non_utf8_git_path_survives_detection_and_init_without_loss()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::ffi::OsStringExt as _;

    let fixture = FixtureWorkspace::from_generated("non-utf8-path")?;
    let raw_name = OsString::from_vec(b"raw-\xff-name.txt".to_vec());
    let raw_path = fixture.worktree.join(&raw_name);
    let raw_contents = b"native path bytes must survive\n";
    fs::write(&raw_path, raw_contents).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("create non-UTF-8 fixture path: {error}"),
        )
    })?;
    fixture
        .initialize_git()
        .map_err(|error| io::Error::other(format!("commit non-UTF-8 fixture path: {error}")))?;

    let output = fixture.run_forge(&["init", "--apply", "--json"])?;
    assert_eq!(output.status.code(), Some(0), "{}", display_output(&output));
    assert_eq!(
        fs::read(&raw_path).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("read non-UTF-8 fixture path after init: {error}"),
            )
        })?,
        raw_contents
    );

    let tracked =
        fixture.git_stdout_in(&fixture.worktree, &["ls-files", "--cached", "-z", "--"])?;
    assert!(
        tracked
            .split(|byte| *byte == 0)
            .any(|path| path == raw_name.as_encoded_bytes()),
        "Git's exact native path bytes disappeared after init"
    );
    Ok(())
}

#[cfg(windows)]
mod windows_wide_path_fixture {
    use std::ffi::OsString;
    use std::fs;
    use std::io;
    use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
    use std::path::{Component, Path, PathBuf, Prefix};
    use std::process::{Command, Output};

    use serde_json::Value;

    use super::{FixtureWorkspace, display_output, required_array};

    const CLASSIC_MAX_PATH_UNITS: usize = 260;
    const MIN_TEST_PATH_UNITS: usize = CLASSIC_MAX_PATH_UNITS + 64;
    const MAX_TEST_PATH_UNITS: usize = 1_024;
    const UNC_ROOT_ENV: &str = "FORGE_WINDOWS_UNC_TEST_ROOT";
    const WIDE_TRACKED_NAME: &str = "tracked path-路径-🧪.txt";

    #[test]
    fn windows_long_utf16_path_survives_detection_init_and_write()
    -> Result<(), Box<dyn std::error::Error>> {
        let parent = std::env::temp_dir().join("forge-fixture-matrix-tests");
        fs::create_dir_all(&parent)?;
        let fixture = long_fixture_at("non-utf8-path", &parent)?;
        exercise_wide_fixture(fixture)
    }

    #[test]
    #[ignore = "requires an externally provisioned writable UNC share in FORGE_WINDOWS_UNC_TEST_ROOT"]
    fn windows_unc_long_path_survives_detection_init_state_and_write()
    -> Result<(), Box<dyn std::error::Error>> {
        let raw_parent = std::env::var_os(UNC_ROOT_ENV).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("{UNC_ROOT_ENV} is required"),
            )
        })?;
        let parent = fs::canonicalize(PathBuf::from(raw_parent))?;
        if !is_qualifying_unc(&parent) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{UNC_ROOT_ENV} did not resolve to a non-administrative UNC share"),
            )
            .into());
        }

        let fixture = long_fixture_at("non-utf8-path", &parent)?;
        if !is_qualifying_unc(&fs::canonicalize(&fixture.worktree)?) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "long fixture escaped the configured UNC share",
            )
            .into());
        }
        exercise_wide_fixture(fixture)
    }

    #[test]
    fn windows_unc_qualification_rejects_local_and_administrative_roots() {
        assert!(!is_qualifying_unc(Path::new(r"C:\forge-tests")));
        assert!(!is_qualifying_unc(Path::new(r"\\server\C$\forge-tests")));
        assert!(is_qualifying_unc(Path::new(r"\\server\forge-tests\root")));
        assert!(is_qualifying_unc(Path::new(
            r"\\?\UNC\server\forge-tests\root"
        )));
    }

    fn exercise_wide_fixture(fixture: FixtureWorkspace) -> Result<(), Box<dyn std::error::Error>> {
        let canonical_worktree = fs::canonicalize(&fixture.worktree)?;
        let measured_path = canonical_worktree.join("Cargo.toml");
        let measured_units = wide_units(&measured_path);
        assert!(
            (MIN_TEST_PATH_UNITS..MAX_TEST_PATH_UNITS).contains(&measured_units),
            "fixture path has {measured_units} UTF-16 units; expected {MIN_TEST_PATH_UNITS}..{MAX_TEST_PATH_UNITS}"
        );

        let tracked_units = WIDE_TRACKED_NAME.encode_utf16().collect::<Vec<_>>();
        let tracked_name = OsString::from_wide(&tracked_units);
        assert_eq!(
            tracked_name.encode_wide().collect::<Vec<_>>(),
            tracked_units
        );
        let tracked_path = fixture.worktree.join(&tracked_name);
        let tracked_contents = b"Windows native path content must survive\n";
        fs::write(&tracked_path, tracked_contents)?;

        let human_agents = b"# Human guidance\r\n\r\nKeep this byte-for-byte.\r\n";
        fs::write(fixture.worktree.join("AGENTS.md"), human_agents)?;
        fixture.initialize_git()?;

        let tracked =
            fixture.git_stdout_in(&fixture.worktree, &["ls-files", "--cached", "-z", "--"])?;
        assert!(
            tracked
                .split(|byte| *byte == 0)
                .any(|path| path == WIDE_TRACKED_NAME.as_bytes()),
            "Git did not preserve the UTF-8 index spelling of the native wide path"
        );

        let before_preview = fixture.snapshot_worktree()?;
        let preview =
            run_forge_with_explicit_dir(&fixture, &["init", "--adapter", "claude", "--json"])?;
        assert_eq!(
            preview.status.code(),
            Some(0),
            "{}",
            display_output(&preview)
        );
        assert_eq!(fixture.snapshot_worktree()?, before_preview);

        let applied = run_forge_with_explicit_dir(
            &fixture,
            &["init", "--apply", "--adapter", "claude", "--json"],
        )?;
        assert_eq!(
            applied.status.code(),
            Some(0),
            "{}",
            display_output(&applied)
        );
        let agents_after = fs::read(fixture.worktree.join("AGENTS.md"))?;
        assert!(agents_after.starts_with(human_agents));
        assert!(String::from_utf8_lossy(&agents_after).contains("forge:begin block=project-index"));
        let claude_after = fs::read(fixture.worktree.join("CLAUDE.md"))?;
        assert!(
            String::from_utf8_lossy(&claude_after).contains("forge:begin block=claude-pointer")
        );
        assert_eq!(fs::read(&tracked_path)?, tracked_contents);
        assert!(!fixture.worktree.join(".forge").exists());
        assert!(fixture.git_dir(&fixture.worktree)?.join("forge").is_dir());

        let converged =
            run_forge_with_explicit_dir(&fixture, &["init", "--adapter", "claude", "--json"])?;
        assert_eq!(
            converged.status.code(),
            Some(0),
            "{}",
            display_output(&converged)
        );
        let converged_document: Value = serde_json::from_slice(&converged.stdout)?;
        assert!(required_array(&converged_document["data"], "edits")?.is_empty());

        let after_first_apply = fixture.snapshot_worktree()?;
        let second_apply = run_forge_with_explicit_dir(
            &fixture,
            &[
                "init",
                "--apply",
                "--allow-dirty",
                "--adapter",
                "claude",
                "--json",
            ],
        )?;
        assert_eq!(
            second_apply.status.code(),
            Some(0),
            "{}",
            display_output(&second_apply)
        );
        let second_document: Value = serde_json::from_slice(&second_apply.stdout)?;
        assert!(required_array(&second_document["data"], "edits")?.is_empty());
        assert_eq!(fixture.snapshot_worktree()?, after_first_apply);
        Ok(())
    }

    fn long_fixture_at(
        id: &str,
        existing_parent: &Path,
    ) -> Result<FixtureWorkspace, Box<dyn std::error::Error>> {
        let parent = fs::canonicalize(existing_parent)?;
        if !parent.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Windows fixture parent did not canonicalize to an absolute path",
            )
            .into());
        }
        FixtureWorkspace::from_generated_with_layout(id, &parent, &long_worktree_relative())
    }

    fn long_worktree_relative() -> PathBuf {
        let mut relative = PathBuf::from("windows-wide");
        for index in 0..4 {
            relative.push(wide_component(index));
        }
        relative.push("worktree");
        relative
    }

    fn wide_component(index: usize) -> OsString {
        let mut units = format!("forge-wide-{index:02}-")
            .encode_utf16()
            .collect::<Vec<_>>();
        units.extend(std::iter::repeat_n(u16::from(b'w'), 64));
        units.extend("路径-🧪".encode_utf16());
        assert!(units.len() < 240);
        OsString::from_wide(&units)
    }

    fn wide_units(path: &Path) -> usize {
        path.as_os_str().encode_wide().count()
    }

    fn is_qualifying_unc(path: &Path) -> bool {
        match path.components().next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::UNC(_, share) | Prefix::VerbatimUNC(_, share) => {
                    !share.to_string_lossy().ends_with('$')
                }
                _ => false,
            },
            _ => false,
        }
    }

    fn run_forge_with_explicit_dir(
        fixture: &FixtureWorkspace,
        arguments: &[&str],
    ) -> Result<Output, Box<dyn std::error::Error>> {
        let mut command = Command::new(env!("CARGO_BIN_EXE_forge"));
        command
            .current_dir(&fixture.root)
            .arg("--dir")
            .arg(&fixture.worktree)
            .args(arguments);
        fixture.configure_environment(&mut command);
        Ok(command.output()?)
    }
}

#[cfg(unix)]
#[test]
fn symlink_adapter_target_cannot_escape_the_repository() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;

    let fixture = FixtureWorkspace::from_generated("symlink-escape")?;
    let outside = fixture.root.join("outside-guidance.md");
    let outside_before = b"outside repository boundary\n";
    fs::write(&outside, outside_before)?;
    symlink(&outside, fixture.worktree.join("AGENTS.md"))?;
    fixture.initialize_git()?;

    let output = fixture.run_forge(&["init", "--apply", "--json"])?;
    assert!(
        matches!(output.status.code(), Some(2 | 65)),
        "{}",
        display_output(&output)
    );
    assert_eq!(fs::read(&outside)?, outside_before);
    assert!(
        fs::symlink_metadata(fixture.worktree.join("AGENTS.md"))?
            .file_type()
            .is_symlink()
    );
    assert!(!fixture.worktree.join(".forge").exists());
    Ok(())
}

#[test]
fn malicious_runner_is_never_expanded_by_read_only_detection()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = FixtureWorkspace::from_generated("malicious-runner")?;
    fixture.initialize_git()?;
    let sentinels = [
        "FORGE-MUST-NOT-EXECUTE",
        "FORGE-MUST-NOT-BUILD",
        "FORGE-MUST-NOT-OBEY-MANIFEST",
        "FORGE-MUST-NOT-OBEY-README",
    ];
    let before = fixture.snapshot_worktree()?;

    for arguments in [
        &["explain", "--json"][..],
        &["doctor", "--json"][..],
        &["next", "--json"][..],
    ] {
        let output = fixture.run_forge(arguments)?;
        assert!(
            matches!(output.status.code(), Some(0..=2)),
            "{}",
            display_output(&output)
        );
        let _: Value = serde_json::from_slice(&output.stdout)?;
        for sentinel in sentinels {
            assert!(
                !fixture.worktree.join(sentinel).exists(),
                "read-only discovery executed untrusted repository content: {sentinel}"
            );
        }
        assert_eq!(fixture.snapshot_worktree()?, before);
    }
    Ok(())
}

#[test]
fn missing_tool_is_reported_without_becoming_a_shell_command()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = FixtureWorkspace::from_generated("missing-tools")?;
    fixture.initialize_git()?;
    fs::write(
        fixture.worktree.join("unverified-change.txt"),
        b"a changed scope must not be routed to an unavailable command\n",
    )?;
    let before = fixture.snapshot_worktree()?;

    let doctor = fixture.run_forge(&["doctor", "--json"])?;
    assert!(
        matches!(doctor.status.code(), Some(1 | 2)),
        "{}",
        display_output(&doctor)
    );
    let document: Value = serde_json::from_slice(&doctor.stdout)?;
    let toolchain = document["data"]["checks"]
        .as_array()
        .and_then(|checks| {
            checks
                .iter()
                .find(|check| check["id"] == "toolchain.required")
        })
        .ok_or("doctor omitted toolchain.required")?;
    assert!(matches!(
        toolchain["status"].as_str(),
        Some("fail" | "unknown")
    ));

    #[cfg(unix)]
    {
        let next = fixture.run_forge(&["next", "--json"])?;
        assert_eq!(next.status.code(), Some(2), "{}", display_output(&next));
        let document: Value = serde_json::from_slice(&next.stdout)?;
        assert_eq!(document["data"]["state"], "blocked");
        assert_eq!(document["data"]["required_action"], "resolve-blocker");
        assert!(document["data"]["intent"].is_null());
        assert!(
            document["data"]["project_commands"]
                .as_array()
                .is_some_and(Vec::is_empty)
        );
        assert!(document["data"]["receipt_command"].is_null());
        assert!(
            document["data"]["blockers"]
                .as_array()
                .is_some_and(|blockers| blockers.iter().any(|blocker| blocker
                    .as_str()
                    .is_some_and(|blocker| blocker.starts_with("environment/toolchain:"))))
        );
    }

    let evidence = fixture.run_forge(&["evidence", "run", "check", "--json"])?;
    assert_eq!(
        evidence.status.code(),
        Some(2),
        "{}",
        display_output(&evidence)
    );
    let _: Value = serde_json::from_slice(&evidence.stdout)?;
    assert_eq!(fixture.snapshot_worktree()?, before);
    Ok(())
}

#[cfg(unix)]
#[test]
fn timeout_fixture_records_a_typed_timeout_without_leaking_child_output()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = FixtureWorkspace::from_generated("timeout-tree")?;
    fixture.initialize_git()?;
    let fake_bin = fixture.install_fake_tool("forge-fixture-sleep", "sleep")?;

    let output = fixture.run_forge_with_path(&["evidence", "run", "check", "--json"], &fake_bin)?;

    assert_eq!(
        output.status.code(),
        Some(124),
        "{}",
        display_output(&output)
    );
    assert!(output.stderr.is_empty());
    let receipt: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(receipt["data"]["outcome"], "timed-out");
    assert_eq!(receipt["data"]["observations"][0]["timed_out"], true);
    assert_eq!(receipt["data"]["observations"][0]["interrupted"], false);
    assert_eq!(
        receipt["data"]["observations"][0]["command"]["command"]["program"],
        "forge-fixture-sleep"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn huge_output_fixture_drains_complete_stream_but_bounds_the_receipt()
-> Result<(), Box<dyn std::error::Error>> {
    const PAYLOAD_BYTES: usize = 700_000;

    let fixture = FixtureWorkspace::from_generated("huge-output")?;
    fs::write(
        fixture.worktree.join("payload.bin"),
        vec![b'x'; PAYLOAD_BYTES],
    )?;
    fixture.initialize_git()?;
    let fake_bin = fixture.install_fake_tool("forge-fixture-cat", "cat")?;

    let output = fixture.run_forge_with_path(&["evidence", "run", "check", "--json"], &fake_bin)?;

    assert_eq!(output.status.code(), Some(0), "{}", display_output(&output));
    assert!(output.stderr.is_empty());
    assert!(
        output.stdout.len() < 128 * 1024,
        "bounded Receipt unexpectedly retained child output"
    );
    assert!(
        !output
            .stdout
            .windows(1024)
            .any(|window| window.iter().all(|byte| *byte == b'x'))
    );
    let receipt: Value = serde_json::from_slice(&output.stdout)?;
    let observation = &receipt["data"]["observations"][0];
    assert_eq!(observation["stdout_total_bytes"], PAYLOAD_BYTES as u64);
    assert_eq!(observation["stdout_truncated"], true);
    assert_eq!(observation["stderr_truncated"], false);
    assert_eq!(observation["output_truncated"], true);
    Ok(())
}

#[test]
fn managed_block_conflict_aborts_the_whole_apply_without_writes()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = FixtureWorkspace::from_generated("managed-block-conflict")?;
    fixture.initialize_git()?;
    let before = fixture.snapshot_worktree()?;

    let output = fixture.run_forge(&["init", "--apply", "--json"])?;

    assert_eq!(
        output.status.code(),
        Some(65),
        "{}",
        display_output(&output)
    );
    let document: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(document["ok"], false);
    assert_eq!(fixture.snapshot_worktree()?, before);
    assert!(!fixture.worktree.join(".git/forge").exists());
    Ok(())
}

#[test]
fn crlf_fixture_survives_init_uninstall_and_native_verification()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = FixtureWorkspace::from_generated("crlf")?;
    let crlf = b"first\r\nsecond\r\n";
    fs::write(fixture.worktree.join("seed.txt"), crlf)?;
    fixture.initialize_git()?;

    let applied = fixture.run_forge(&["init", "--apply", "--json"])?;
    assert_eq!(
        applied.status.code(),
        Some(0),
        "{}",
        display_output(&applied)
    );
    assert_eq!(fs::read(fixture.worktree.join("seed.txt"))?, crlf);
    assert!(fixture.worktree.join("AGENTS.md").is_file());

    fs::remove_file(fixture.worktree.join("AGENTS.md"))?;
    let private_state = fixture.worktree.join(".git/forge");
    if private_state.exists() {
        fs::remove_dir_all(private_state)?;
    }
    let native = fixture.run_native("cargo", &["test", "--offline"], &fixture.worktree)?;
    assert!(native.status.success(), "{}", display_output(&native));
    assert_eq!(fs::read(fixture.worktree.join("seed.txt"))?, crlf);
    assert!(!fixture.worktree.join("AGENTS.md").exists());
    assert!(!fixture.worktree.join(".git/forge").exists());
    Ok(())
}

#[test]
fn every_available_native_command_survives_fixture_install_and_uninstall()
-> Result<(), Box<dyn std::error::Error>> {
    let manifest: Value = serde_json::from_slice(&fs::read(
        repository_root().join("fixtures/generated/manifest-v1.json"),
    )?)?;
    let fixtures = required_array(&manifest, "fixtures")?;
    let mut fixture_proofs = BTreeMap::new();

    for fixture_definition in fixtures {
        let id = fixture_definition["id"]
            .as_str()
            .ok_or("fixture manifest entry omitted id")?;
        let fixture = FixtureWorkspace::from_generated(id)?;
        // `.git` is intentionally outside the worktree baseline; fixture support and tool caches
        // live under `fixture.root`, beside rather than inside this copied project.
        let baseline = fixture.snapshot_worktree()?;
        let original_managed_files = INIT_MANAGED_PROJECT_FILES
            .iter()
            .map(|relative| Ok((*relative, read_optional(fixture.worktree.join(relative))?)))
            .collect::<Result<Vec<_>, io::Error>>()?;

        if id != "non-git" {
            fixture.initialize_git()?;
        }
        let applied = fixture.run_forge(&["init", "--apply", "--json"])?;
        let expected_init_exit = match id {
            "empty-repo" | "non-git" => 2,
            "managed-block-conflict" => 65,
            _ => 0,
        };
        assert_eq!(
            applied.status.code(),
            Some(expected_init_exit),
            "fixture `{id}` expected init exit {expected_init_exit}: {}",
            summarize_init_output(&applied)
        );

        for (relative, original) in original_managed_files {
            restore_optional(fixture.worktree.join(relative), original.as_deref())?;
        }
        if id != "non-git" {
            let state = fixture.git_dir(&fixture.worktree)?.join("forge");
            if state.exists() {
                fs::remove_dir_all(&state)?;
            }
            assert!(
                !state.exists(),
                "fixture `{id}` retained private Forge state"
            );
        }

        assert_eq!(
            fixture.snapshot_worktree()?,
            baseline,
            "fixture `{id}` uninstall did not restore the complete pre-test worktree baseline"
        );

        let commands = required_array(fixture_definition, "commands")?;
        if commands.is_empty() {
            assert!(
                COMMANDLESS_UNINSTALL_SCENARIOS.contains(&id),
                "fixture `{id}` has no native command without an explicit scenario-only classification"
            );
        }
        let mut proven_commands = 0_usize;
        let mut unavailable_commands = 0_usize;
        let mut missing_host_tools = BTreeSet::new();
        for (command_index, command) in commands.iter().enumerate() {
            let program = command["program"]
                .as_str()
                .ok_or("fixture command omitted program")?;
            if !tool_is_available(program)? {
                missing_host_tools.insert(program.to_owned());
                unavailable_commands += 1;
                continue;
            }
            let arguments = required_array(command, "args")?
                .iter()
                .map(|argument| argument.as_str().ok_or("fixture argument is not a string"))
                .collect::<Result<Vec<_>, _>>()?;
            let cwd = command["cwd"]
                .as_str()
                .ok_or("fixture command omitted cwd")?;
            let output = fixture.run_declared_native_without_forge(
                program,
                &arguments,
                &fixture.worktree.join(cwd),
                command_index,
            )?;
            assert!(
                output.status.success(),
                "fixture `{id}` native command {command_index}: {}",
                display_output(&output)
            );
            proven_commands += 1;
        }

        assert_eq!(
            proven_commands + unavailable_commands,
            commands.len(),
            "fixture `{id}` did not account for every declared native command"
        );
        let native_proof = if commands.is_empty() {
            "scenario-only".to_owned()
        } else if missing_host_tools.is_empty() {
            assert_eq!(proven_commands, commands.len());
            format!("Proven(native_commands={proven_commands})")
        } else {
            format!(
                "missing-host-tool(programs={missing_host_tools:?}, native_commands_proven={proven_commands})"
            )
        };
        let proof = if expected_init_exit == 0 {
            native_proof
        } else {
            format!("expected-refusal(init_exit={expected_init_exit}); native={native_proof}")
        };
        assert!(
            fixture_proofs.insert(id.to_owned(), proof).is_none(),
            "fixture `{id}` produced more than one uninstall proof"
        );
    }

    assert_eq!(
        fixture_proofs.len(),
        fixtures.len(),
        "not every fixture produced an uninstall proof: {fixture_proofs:#?}"
    );
    assert_eq!(
        fixture_proofs
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        REQUIRED_FIXTURES.iter().copied().collect::<BTreeSet<_>>(),
        "the uninstall proof ledger did not cover the public fixture matrix"
    );
    Ok(())
}

#[test]
#[ignore = "opt-in v0 latency benchmark over a committed 100000-file repository"]
fn large_repository_v0_latency_benchmark() -> Result<(), Box<dyn std::error::Error>> {
    const FILE_COUNT: usize = 100_000;
    const WARM_SAMPLES: usize = 20;

    require_release_benchmark()?;
    let fixture = FixtureWorkspace::from_generated("large-repository")?;
    fixture.initialize_git()?;
    // Keep the project command's normal Cargo build products out of the tracked-worktree
    // performance state. Otherwise the cache primer changes the Git snapshot and the supposedly
    // warm samples measure a dirty 100000-file rescan instead of the published inventory cache.
    fs::write(fixture.worktree.join(".gitignore"), b"/target/\n")?;
    let inventory = fixture.worktree.join("inventory");
    fs::create_dir(&inventory)?;
    for shard in 0..100_usize {
        let directory = inventory.join(format!("{shard:03}"));
        fs::create_dir(&directory)?;
        for item in 0..1_000_usize {
            fs::write(directory.join(format!("{item:04}.txt")), b"fixture\n")?;
        }
    }
    assert_eq!(count_regular_files(&inventory)?, FILE_COUNT);
    fixture.run_git(&["add", "--all", "--"])?;
    fixture.commit_in(
        &fixture.worktree,
        "materialize 100000-file performance fixture",
    )?;

    let started = Instant::now();
    let output = fixture.run_forge(&["explain", "--json"])?;
    let first_inventory = started.elapsed();

    assert_eq!(output.status.code(), Some(0), "{}", display_output(&output));
    let _: Value = serde_json::from_slice(&output.stdout)?;
    let private_root = fixture.git_dir(&fixture.worktree)?.join("forge");
    assert!(
        !private_root.exists(),
        "the cold read-only inventory measurement must not publish a cache"
    );
    let cold_inventory_peak_rss = benchmark_peak_rss_bytes(&fixture, &["explain", "--json"], 0)?;

    let primed = fixture.run_forge(&["evidence", "run", "check", "--json"])?;
    assert_eq!(primed.status.code(), Some(0), "{}", display_output(&primed));
    let _: Value = serde_json::from_slice(&primed.stdout)?;
    assert_eq!(
        receipt_files(&private_root.join("cache/inventory"))?.len(),
        1,
        "an authorized Evidence write must publish exactly one reusable inventory entry"
    );
    let cache_hit = fixture.run_forge(&["-v", "explain", "--json"])?;
    assert_eq!(
        cache_hit.status.code(),
        Some(0),
        "{}",
        display_output(&cache_hit)
    );
    assert_eq!(
        cache_hit.stderr, b"inventory-cache: hit\n",
        "warm measurements require a proven inventory-cache hit"
    );
    let _: Value = serde_json::from_slice(&cache_hit.stdout)?;

    let version = benchmark_json_command(&fixture, &["version", "--json"], 0, WARM_SAMPLES)?;
    let next = benchmark_json_command(&fixture, &["next", "--json"], 0, WARM_SAMPLES)?;
    let adapters =
        benchmark_json_command(&fixture, &["adapters", "check", "--json"], 1, WARM_SAMPLES)?;
    let doctor = benchmark_json_command(&fixture, &["doctor", "--json"], 1, WARM_SAMPLES)?;
    let git_status = benchmark_git_command(
        &fixture,
        &[
            "status",
            "--porcelain=v2",
            "-z",
            "--branch",
            "--untracked-files=all",
        ],
        WARM_SAMPLES,
    )?;
    let git_diff_files = benchmark_git_command(&fixture, &["diff-files", "--quiet"], WARM_SAMPLES)?;
    let git_diff_index = benchmark_git_command(
        &fixture,
        &["diff-index", "--cached", "--quiet", "HEAD", "--"],
        WARM_SAMPLES,
    )?;
    let git_untracked = benchmark_git_command(
        &fixture,
        &["ls-files", "--others", "--exclude-standard", "-z", "--"],
        WARM_SAMPLES,
    )?;
    let git_index_entries = benchmark_git_command(
        &fixture,
        &["ls-files", "--stage", "-v", "-z", "--"],
        WARM_SAMPLES,
    )?;
    let git_index = fixture.git_dir(&fixture.worktree)?.join("index");
    let git_index_argument = git_index
        .to_str()
        .ok_or("performance fixture Git index path is not UTF-8")?;
    let git_hash_index = benchmark_git_command(
        &fixture,
        &["hash-object", "--no-filters", git_index_argument],
        WARM_SAMPLES,
    )?;

    let peak_rss = cold_inventory_peak_rss.map_or_else(
        || String::from("unavailable on this platform"),
        |bytes| {
            format!(
                "{:.2} MiB ({bytes} bytes; target < 150 MiB)",
                bytes as f64 / (1024.0 * 1024.0)
            )
        },
    );
    eprintln!(
        "v0 release benchmark ({FILE_COUNT} committed files, {WARM_SAMPLES} warm samples):\n  first inventory: {} ms (target < 5000 ms)\n  cold inventory forge peak RSS: {peak_rss}\n  version p95: {} ms (target < 50 ms)\n  next p95: {} ms (target < 200 ms)\n  adapters check p95: {} ms (target < 300 ms)\n  doctor p95: {} ms (target < 3000 ms)\n  git status p50/p95: {}/{} ms (stdout {} bytes, stderr {} bytes)\n  git diff-files p50/p95: {}/{} ms (stdout {} bytes, stderr {} bytes)\n  git diff-index --cached p50/p95: {}/{} ms (stdout {} bytes, stderr {} bytes)\n  git ls-files --others p50/p95: {}/{} ms (stdout {} bytes, stderr {} bytes)\n  git ls-files --stage -v p50/p95: {}/{} ms (stdout {} bytes, stderr {} bytes)\n  git hash-object index p50/p95: {}/{} ms (stdout {} bytes, stderr {} bytes)",
        first_inventory.as_millis(),
        percentile_95(&version).as_millis(),
        percentile_95(&next).as_millis(),
        percentile_95(&adapters).as_millis(),
        percentile_95(&doctor).as_millis(),
        git_status.p50.as_millis(),
        git_status.p95.as_millis(),
        git_status.stdout_bytes,
        git_status.stderr_bytes,
        git_diff_files.p50.as_millis(),
        git_diff_files.p95.as_millis(),
        git_diff_files.stdout_bytes,
        git_diff_files.stderr_bytes,
        git_diff_index.p50.as_millis(),
        git_diff_index.p95.as_millis(),
        git_diff_index.stdout_bytes,
        git_diff_index.stderr_bytes,
        git_untracked.p50.as_millis(),
        git_untracked.p95.as_millis(),
        git_untracked.stdout_bytes,
        git_untracked.stderr_bytes,
        git_index_entries.p50.as_millis(),
        git_index_entries.p95.as_millis(),
        git_index_entries.stdout_bytes,
        git_index_entries.stderr_bytes,
        git_hash_index.p50.as_millis(),
        git_hash_index.p95.as_millis(),
        git_hash_index.stdout_bytes,
        git_hash_index.stderr_bytes,
    );
    if std::env::var_os("FORGE_RETAIN_LARGE_REPOSITORY_FIXTURE") == Some(OsString::from("1")) {
        let retained_root = fixture.retain();
        eprintln!(
            "retained large-repository fixture: {}",
            retained_root.display()
        );
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GitBenchmarkResult {
    p50: Duration,
    p95: Duration,
    stdout_bytes: usize,
    stderr_bytes: usize,
}

fn benchmark_git_command(
    fixture: &FixtureWorkspace,
    arguments: &[&str],
    samples: usize,
) -> Result<GitBenchmarkResult, Box<dyn std::error::Error>> {
    if samples == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "samples must be positive").into());
    }

    let warmup = fixture.git_output_in(&fixture.worktree, arguments)?;
    if !warmup.status.success() {
        return Err(io::Error::other(format!(
            "git {arguments:?} warmup failed: {}",
            display_output(&warmup)
        ))
        .into());
    }
    let expected_stdout = warmup.stdout;
    let expected_stderr = warmup.stderr;
    let mut durations = Vec::with_capacity(samples);
    for _ in 0..samples {
        let started = Instant::now();
        let output = fixture.git_output_in(&fixture.worktree, arguments)?;
        durations.push(started.elapsed());
        assert!(
            output.status.success(),
            "git {arguments:?}: {}",
            display_output(&output)
        );
        assert_eq!(
            output.stdout, expected_stdout,
            "git {arguments:?} stdout changed between warm samples"
        );
        assert_eq!(
            output.stderr, expected_stderr,
            "git {arguments:?} stderr changed between warm samples"
        );
    }
    Ok(GitBenchmarkResult {
        p50: percentile(&durations, 50),
        p95: percentile_95(&durations),
        stdout_bytes: expected_stdout.len(),
        stderr_bytes: expected_stderr.len(),
    })
}

#[cfg(debug_assertions)]
fn require_release_benchmark() -> Result<(), io::Error> {
    Err(io::Error::other(
        "the v0 performance benchmark must be built with cargo test --release",
    ))
}

#[cfg(not(debug_assertions))]
fn require_release_benchmark() -> Result<(), io::Error> {
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn benchmark_peak_rss_bytes(
    fixture: &FixtureWorkspace,
    arguments: &[&str],
    expected_exit: i32,
) -> Result<Option<u64>, Box<dyn std::error::Error>> {
    let mut command = Command::new("/usr/bin/time");
    command.current_dir(&fixture.worktree);
    #[cfg(target_os = "macos")]
    command.arg("-l");
    #[cfg(target_os = "linux")]
    command.arg("-v");
    command.arg(env!("CARGO_BIN_EXE_forge")).args(arguments);
    fixture.configure_environment(&mut command);

    let output = command.output()?;
    assert_eq!(
        output.status.code(),
        Some(expected_exit),
        "peak-RSS sample for {}: {}",
        arguments.join(" "),
        display_output(&output)
    );
    let _: Value = serde_json::from_slice(&output.stdout)?;

    let stderr = String::from_utf8(output.stderr)?;
    #[cfg(target_os = "macos")]
    let bytes = parse_macos_peak_rss_bytes(&stderr);
    #[cfg(target_os = "linux")]
    let bytes = parse_linux_peak_rss_bytes(&stderr);
    bytes.map(Some).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "/usr/bin/time did not report a parseable maximum resident set size",
        )
        .into()
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn benchmark_peak_rss_bytes(
    _fixture: &FixtureWorkspace,
    _arguments: &[&str],
    _expected_exit: i32,
) -> Result<Option<u64>, Box<dyn std::error::Error>> {
    Ok(None)
}

#[cfg(target_os = "macos")]
fn parse_macos_peak_rss_bytes(stderr: &str) -> Option<u64> {
    stderr.lines().find_map(|line| {
        line.trim()
            .strip_suffix("maximum resident set size")?
            .trim()
            .parse()
            .ok()
    })
}

#[cfg(target_os = "linux")]
fn parse_linux_peak_rss_bytes(stderr: &str) -> Option<u64> {
    stderr.lines().find_map(|line| {
        line.trim()
            .strip_prefix("Maximum resident set size (kbytes):")?
            .trim()
            .parse::<u64>()
            .ok()
            .and_then(|kibibytes| kibibytes.checked_mul(1024))
    })
}

#[cfg(target_os = "macos")]
#[test]
fn macos_time_peak_rss_parser_preserves_the_byte_unit() {
    let output = "       43122688  maximum resident set size\n";
    assert_eq!(parse_macos_peak_rss_bytes(output), Some(43_122_688));
}

#[cfg(target_os = "linux")]
#[test]
fn linux_time_peak_rss_parser_converts_kibibytes_to_bytes() {
    let output = "Maximum resident set size (kbytes): 42112\n";
    assert_eq!(parse_linux_peak_rss_bytes(output), Some(43_122_688));
}

fn benchmark_json_command(
    fixture: &FixtureWorkspace,
    arguments: &[&str],
    expected_exit: i32,
    samples: usize,
) -> Result<Vec<Duration>, Box<dyn std::error::Error>> {
    if samples == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "samples must be positive").into());
    }
    let mut durations = Vec::with_capacity(samples);
    for _ in 0..samples {
        let started = Instant::now();
        let output = fixture.run_forge(arguments)?;
        durations.push(started.elapsed());
        assert_eq!(
            output.status.code(),
            Some(expected_exit),
            "{}: {}",
            arguments.join(" "),
            display_output(&output)
        );
        let _: Value = serde_json::from_slice(&output.stdout)?;
    }
    Ok(durations)
}

fn percentile_95(samples: &[Duration]) -> Duration {
    percentile(samples, 95)
}

fn percentile(samples: &[Duration], percentage: usize) -> Duration {
    assert!((1..=100).contains(&percentage));
    let mut ordered = samples.to_vec();
    ordered.sort_unstable();
    let rank = ordered.len().saturating_mul(percentage).div_ceil(100);
    ordered[rank.saturating_sub(1)]
}

#[derive(Debug)]
struct FixtureWorkspace {
    root: PathBuf,
    worktree: PathBuf,
    global_git_config: PathBuf,
    xdg_config_home: PathBuf,
    remove_on_drop: bool,
}

impl FixtureWorkspace {
    fn from_generated(id: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let parent = std::env::temp_dir().join("forge-fixture-matrix-tests");
        Self::from_generated_with_layout(id, &parent, Path::new("worktree"))
    }

    fn from_generated_with_layout(
        id: &str,
        parent: &Path,
        worktree_relative: &Path,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        if worktree_relative.as_os_str().is_empty()
            || worktree_relative
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "fixture worktree layout must contain only normal relative components",
            )
            .into());
        }
        fs::create_dir_all(parent)?;
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = parent.join(format!("{id}-{}-{nonce}-{sequence}", std::process::id()));
        let worktree = root.join(worktree_relative);
        let support = root.join("support");
        let xdg_config_home = support.join("xdg");
        fs::create_dir_all(&worktree)?;
        fs::create_dir_all(&xdg_config_home)?;
        let global_git_config = support.join("global.gitconfig");
        fs::write(&global_git_config, b"")?;
        copy_tree(
            &repository_root().join("fixtures/generated").join(id),
            &worktree,
        )?;
        Ok(Self {
            root,
            worktree,
            global_git_config,
            xdg_config_home,
            remove_on_drop: true,
        })
    }

    fn retain(mut self) -> PathBuf {
        self.remove_on_drop = false;
        self.root.clone()
    }

    fn initialize_git(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.run_git(&["init", "--quiet"])?;
        self.run_git(&["add", "--all", "--"])?;
        self.run_git(&[
            "-c",
            "user.name=Forge fixture tests",
            "-c",
            "user.email=forge-fixtures@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "fixture baseline",
        ])?;
        Ok(())
    }

    fn run_git(&self, arguments: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
        self.run_git_in(&self.worktree, arguments)
    }

    fn run_git_in(&self, cwd: &Path, arguments: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
        let output = self.git_output_in(cwd, arguments)?;
        if output.status.success() {
            return Ok(());
        }
        Err(io::Error::other(format!(
            "git {arguments:?} failed in {}: {}",
            cwd.display(),
            display_output(&output)
        ))
        .into())
    }

    fn git_output_in(
        &self,
        cwd: &Path,
        arguments: &[&str],
    ) -> Result<Output, Box<dyn std::error::Error>> {
        let mut command = Command::new("git");
        command
            .current_dir(cwd)
            .arg("--no-pager")
            .arg("--no-optional-locks");
        #[cfg(windows)]
        command.arg("-c").arg("core.longpaths=true");
        command
            .arg("-c")
            .arg("core.fsmonitor=false")
            .arg("-c")
            .arg("core.autocrlf=false")
            .args(arguments);
        self.configure_environment(&mut command);
        Ok(command.output()?)
    }

    fn git_stdout_in(
        &self,
        cwd: &Path,
        arguments: &[&str],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let output = self.git_output_in(cwd, arguments)?;
        if output.status.success() {
            return Ok(output.stdout);
        }
        Err(io::Error::other(format!(
            "git {arguments:?} failed in {}: {}",
            cwd.display(),
            display_output(&output)
        ))
        .into())
    }

    fn commit_in(&self, cwd: &Path, message: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.run_git_in(
            cwd,
            &[
                "-c",
                "user.name=Forge fixture tests",
                "-c",
                "user.email=forge-fixtures@example.invalid",
                "commit",
                "--quiet",
                "-m",
                message,
            ],
        )
    }

    fn git_dir(&self, cwd: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let raw = self.git_stdout_in(cwd, &["rev-parse", "--path-format=absolute", "--git-dir"])?;
        let path = String::from_utf8(raw)?;
        Ok(PathBuf::from(path.trim_end()))
    }

    fn run_forge(&self, arguments: &[&str]) -> Result<Output, Box<dyn std::error::Error>> {
        self.run_forge_in(&self.worktree, arguments)
    }

    fn run_forge_in(
        &self,
        cwd: &Path,
        arguments: &[&str],
    ) -> Result<Output, Box<dyn std::error::Error>> {
        let mut command = Command::new(env!("CARGO_BIN_EXE_forge"));
        command.current_dir(cwd).args(arguments);
        self.configure_environment(&mut command);
        Ok(command.output()?)
    }

    #[cfg(unix)]
    fn install_fake_tool(
        &self,
        fake_name: &str,
        source_name: &str,
    ) -> Result<PathBuf, Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let source = find_path_executable(source_name)
            .ok_or_else(|| format!("required host executable `{source_name}` was not found"))?;
        let fake_bin = self.root.join("support/fake-bin");
        fs::create_dir_all(&fake_bin)?;
        // Keep the host binary at its original inode. In particular, copying an Apple platform
        // binary may omit signing metadata and make the kernel terminate an otherwise valid fake.
        symlink(source, fake_bin.join(fake_name))?;
        Ok(fake_bin)
    }

    #[cfg(unix)]
    fn run_forge_with_path(
        &self,
        arguments: &[&str],
        first_path: &Path,
    ) -> Result<Output, Box<dyn std::error::Error>> {
        let mut command = Command::new(env!("CARGO_BIN_EXE_forge"));
        command
            .current_dir(&self.worktree)
            .args(arguments)
            .env("PATH", prepend_to_path(first_path)?);
        self.configure_environment(&mut command);
        Ok(command.output()?)
    }

    fn run_native(
        &self,
        program: &str,
        arguments: &[&str],
        cwd: &Path,
    ) -> Result<Output, Box<dyn std::error::Error>> {
        let mut command = Command::new(program);
        command
            .current_dir(cwd)
            .args(arguments)
            .env("RUSTUP_AUTO_INSTALL", "0")
            .env("CARGO_NET_OFFLINE", "true")
            .env("CARGO_TARGET_DIR", self.root.join("native-target"));
        Ok(command.output()?)
    }

    fn run_declared_native_without_forge(
        &self,
        program: &str,
        arguments: &[&str],
        cwd: &Path,
        command_index: usize,
    ) -> Result<Output, Box<dyn std::error::Error>> {
        let mut command = Command::new(program);
        command
            .current_dir(cwd)
            .args(arguments)
            .env("PATH", forge_free_path()?)
            .env("RUSTUP_AUTO_INSTALL", "0")
            .env("CARGO_NET_OFFLINE", "true");
        if program == "cargo" {
            command.env(
                "CARGO_TARGET_DIR",
                self.root
                    .join("uninstall-native-targets")
                    .join(command_index.to_string()),
            );
        } else if program == "go" {
            command
                .env_remove("GOWORK")
                .env("GOPROXY", "off")
                .env("GOSUMDB", "off")
                .env("GOCACHE", self.root.join("uninstall-go-cache"))
                .env("GOMODCACHE", self.root.join("uninstall-go-module-cache"))
                .env("GOPATH", self.root.join("uninstall-go-path"));
        }
        Ok(command.output()?)
    }

    fn configure_environment(&self, command: &mut Command) {
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
            .env("RUSTUP_AUTO_INSTALL", "0");
    }

    fn snapshot_worktree(&self) -> Result<WorktreeSnapshot, Box<dyn std::error::Error>> {
        let mut snapshot = Vec::new();
        snapshot_tree(&self.worktree, &self.worktree, &mut snapshot)?;
        snapshot.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(snapshot)
    }
}

impl Drop for FixtureWorkspace {
    fn drop(&mut self) {
        if self.remove_on_drop {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn copy_tree(source: &Path, destination: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(destination)?;
    let mut entries = fs::read_dir(source)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            copy_tree(&source_path, &destination_path)?;
        } else if file_type.is_file() {
            fs::copy(source_path, destination_path)?;
        } else {
            return Err(format!(
                "fixture contains a non-regular entry: {}",
                source_path.display()
            )
            .into());
        }
    }
    Ok(())
}

fn snapshot_tree(
    root: &Path,
    current: &Path,
    output: &mut WorktreeSnapshot,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut entries = fs::read_dir(current)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        if current == root && entry.file_name() == ".git" {
            continue;
        }
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            output.push((
                path.strip_prefix(root)?.to_path_buf(),
                WorktreeEntry::Directory,
            ));
            snapshot_tree(root, &path, output)?;
        } else if file_type.is_file() {
            output.push((
                path.strip_prefix(root)?.to_path_buf(),
                WorktreeEntry::File(fs::read(path)?),
            ));
        } else if file_type.is_symlink() {
            output.push((
                path.strip_prefix(root)?.to_path_buf(),
                WorktreeEntry::Symlink(fs::read_link(path)?),
            ));
        } else {
            output.push((path.strip_prefix(root)?.to_path_buf(), WorktreeEntry::Other));
        }
    }
    Ok(())
}

fn required_array<'a>(
    value: &'a Value,
    field: &str,
) -> Result<&'a Vec<Value>, Box<dyn std::error::Error>> {
    value[field]
        .as_array()
        .ok_or_else(|| format!("field `{field}` is not an array").into())
}

fn read_optional(path: impl AsRef<Path>) -> io::Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn restore_optional(path: impl AsRef<Path>, original: Option<&[u8]>) -> io::Result<()> {
    let path = path.as_ref();
    match original {
        Some(bytes) => fs::write(path, bytes),
        None => match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        },
    }
}

fn forge_free_path() -> Result<OsString, Box<dyn std::error::Error>> {
    let forge_parent = Path::new(env!("CARGO_BIN_EXE_forge"))
        .parent()
        .ok_or("Forge test binary has no parent directory")?;
    let path = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .filter(|entry| entry != forge_parent)
        .collect::<Vec<_>>();
    Ok(std::env::join_paths(path)?)
}

fn tool_is_available(program: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let version_argument = if program == "go" {
        "version"
    } else {
        "--version"
    };
    match Command::new(program)
        .arg(version_argument)
        .env("PATH", forge_free_path()?)
        .output()
    {
        Ok(output) if output.status.success() => Ok(true),
        Ok(output) => Err(io::Error::other(format!(
            "`{program} {version_argument}` failed: {}",
            display_output(&output)
        ))
        .into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn receipt_files(directory: &Path) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut receipts = fs::read_dir(directory)?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter_map(|entry| match entry.file_type() {
            Ok(file_type) if file_type.is_file() => Some(Ok(entry.path())),
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
        .collect::<Result<Vec<_>, io::Error>>()?;
    receipts.sort();
    Ok(receipts)
}

fn count_regular_files(root: &Path) -> Result<usize, Box<dyn std::error::Error>> {
    let mut count = 0_usize;
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file() {
                count += 1;
            } else {
                return Err(format!(
                    "large fixture contains a non-regular entry: {}",
                    entry.path().display()
                )
                .into());
            }
        }
    }
    Ok(count)
}

#[cfg(unix)]
fn find_path_executable(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
}

#[cfg(unix)]
fn prepend_to_path(first: &Path) -> Result<OsString, std::env::JoinPathsError> {
    std::env::join_paths(
        std::iter::once(first.to_path_buf()).chain(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_default(),
        )),
    )
}

fn display_output(output: &Output) -> String {
    format!(
        "status={:?}; stdout={}; stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn summarize_init_output(output: &Output) -> String {
    let Ok(document) = serde_json::from_slice::<Value>(&output.stdout) else {
        return display_output(output);
    };
    if document["ok"] == false {
        let diagnostic = &document["data"]["diagnostic"];
        return format!(
            "status={:?}, code={}, why={}",
            output.status.code(),
            diagnostic["code"],
            diagnostic["why"]
        );
    }
    let edits = document["data"]["edits"]
        .as_array()
        .map(|edits| {
            edits
                .iter()
                .map(|edit| format!("{}:{}", edit["kind"], edit["path"]["display"]))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let assumptions = document["data"]["assumptions"]
        .as_array()
        .map(|assumptions| {
            assumptions
                .iter()
                .map(|assumption| assumption["statement"].to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    format!(
        "status={:?}, edits=[{}], assumptions=[{}]",
        output.status.code(),
        edits.join(", "),
        assumptions.join(", ")
    )
}
