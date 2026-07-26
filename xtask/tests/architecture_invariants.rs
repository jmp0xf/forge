//! Cheap architecture guards for stable, mechanically checkable invariants.

use std::fs;
use std::path::{Path, PathBuf};

fn repository_root() -> Result<PathBuf, Box<dyn std::error::Error>> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "xtask manifest directory has no parent".into())
}

#[test]
fn only_the_runtime_process_module_constructs_product_subprocesses()
-> Result<(), Box<dyn std::error::Error>> {
    let root = repository_root()?;
    let source_root = root.join("crates");
    let mut violations = Vec::new();
    for path in rust_source_files(&source_root)? {
        if path.ends_with("forge-runtime/src/process.rs")
            || path
                .components()
                .any(|component| component.as_os_str() == "tests")
        {
            continue;
        }
        let source = fs::read_to_string(&path)?;
        if source.contains("std::process::Command")
            || source.contains("use std::process::Command")
            || source.contains("Command::new(")
        {
            violations.push(path);
        }
    }
    assert!(
        violations.is_empty(),
        "external commands bypass forge-runtime::process: {violations:?}"
    );
    Ok(())
}

#[test]
fn committed_tree_has_no_tool_private_worktree_directory() -> Result<(), Box<dyn std::error::Error>>
{
    let root = repository_root()?;
    let mut violations = Vec::new();
    visit_directories(&root, &mut |path| {
        let relative = path.strip_prefix(&root).unwrap_or(path);
        if matches!(
            relative.to_str(),
            Some(".forge" | ".ai" | ".agent" | "docs/ai")
        ) {
            violations.push(relative.to_path_buf());
        }
    })?;
    assert!(
        violations.is_empty(),
        "private Forge directories must not be committed: {violations:?}"
    );
    Ok(())
}

#[test]
fn primary_verification_workflow_does_not_depend_on_forge() -> Result<(), Box<dyn std::error::Error>>
{
    let root = repository_root()?;
    let workflow = fs::read_to_string(root.join(".github/workflows/verify.yml"))?;

    assert!(!workflow.contains("cargo run -p forge-cli"));
    assert!(
        !workflow
            .lines()
            .any(|line| line.trim_start().starts_with("- run: forge "))
    );
    Ok(())
}

fn rust_source_files(root: &Path) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut files = Vec::new();
    visit_files(root, &mut |path| {
        if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path.to_path_buf());
        }
    })?;
    files.sort();
    Ok(files)
}

fn visit_files(
    root: &Path,
    visitor: &mut dyn FnMut(&Path),
) -> Result<(), Box<dyn std::error::Error>> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_dir() {
            visit_files(&path, visitor)?;
        } else if file_type.is_file() {
            visitor(&path);
        }
    }
    Ok(())
}

fn visit_directories(
    root: &Path,
    visitor: &mut dyn FnMut(&Path),
) -> Result<(), Box<dyn std::error::Error>> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let path = entry.path();
        let name = entry.file_name();
        if name == ".git" || name == "target" {
            continue;
        }
        visitor(&path);
        visit_directories(&path, visitor)?;
    }
    Ok(())
}
