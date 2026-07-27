//! Repository-level dogfood invariant: the checked-in adapter projection is a fixed point.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

#[test]
fn forge_init_dry_run_is_a_zero_diff_on_its_own_repository()
-> Result<(), Box<dyn std::error::Error>> {
    let root = repository_root();
    let mut command = Command::new(env!("CARGO_BIN_EXE_forge"));
    command
        .current_dir(&root)
        .args(["init", "--dry-run", "--json"]);
    for name in [
        "GIT_CONFIG",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_PARAMETERS",
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
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_PAGER", "cat")
        .env("LC_ALL", "C");

    let output = command.output()?;
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let envelope: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(envelope["schema"], "forge.init-plan/v1");
    assert_eq!(
        envelope["data"]["edits"],
        Value::Array(Vec::new()),
        "run `cargo run -p forge-cli -- init --apply --allow-dirty` after reviewing the dogfood diff"
    );
    Ok(())
}
