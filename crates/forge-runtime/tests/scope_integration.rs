use std::fs;
use std::path::Path;
use std::process::Command;

use forge_core::evidence::DependencyValue;
use forge_core::ports::GitPort as _;
use forge_core::scope::scope_dependency_digest;
use forge_runtime::git::GitCli;
use forge_runtime::hash::Blake3Hasher;
use forge_runtime::scope::{
    ScopeAcquisitionError, acquire_repository_scope, prepare_repository_scope_candidate,
};

fn git(root: &Path, args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new("git")
        .current_dir(root)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "GIT_CONFIG_GLOBAL",
            root.join(".forge-test-empty-gitconfig"),
        )
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("git {args:?} failed with {status}").into())
    }
}

fn repository() -> Result<tempfile::TempDir, Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    git(root.path(), &["init", "--quiet"])?;
    git(root.path(), &["config", "user.name", "Forge Tests"])?;
    git(
        root.path(),
        &["config", "user.email", "forge@example.invalid"],
    )?;
    fs::write(root.path().join("tracked.txt"), b"initial\n")?;
    git(root.path(), &["add", "tracked.txt"])?;
    git(root.path(), &["commit", "--quiet", "-m", "initial"])?;
    Ok(root)
}

fn digest(scope: &forge_core::scope::PreparedScope) -> forge_core::Digest {
    let DependencyValue::Known(digest) =
        scope_dependency_digest(&Blake3Hasher, &DependencyValue::Known(scope.clone()))
    else {
        unreachable!("a prepared scope is known")
    };
    digest
}

#[test]
fn clean_staged_dirty_and_untracked_content_produce_distinct_scopes()
-> Result<(), Box<dyn std::error::Error>> {
    let repository = repository()?;
    let git_cli = GitCli::new();
    let root = git_cli.repository_root(repository.path())?;

    let clean = digest(&acquire_repository_scope(&git_cli, &root)?);
    fs::write(root.join("tracked.txt"), b"staged\n")?;
    git(&root, &["add", "tracked.txt"])?;
    let staged = digest(&acquire_repository_scope(&git_cli, &root)?);
    fs::write(root.join("tracked.txt"), b"dirty\n")?;
    let dirty = digest(&acquire_repository_scope(&git_cli, &root)?);
    fs::write(root.join("untracked.txt"), b"untracked\n")?;
    let untracked = digest(&acquire_repository_scope(&git_cli, &root)?);

    assert_ne!(clean, staged);
    assert_ne!(staged, dirty);
    assert_ne!(dirty, untracked);
    Ok(())
}

#[test]
fn retained_scope_candidate_matches_fresh_acquisition() -> Result<(), Box<dyn std::error::Error>> {
    let repository = repository()?;
    let git_cli = GitCli::new();
    let root = git_cli.repository_root(repository.path())?;
    let status = git_cli.status(&root)?;
    let index = git_cli.index_entries(&root)?;

    let candidate = prepare_repository_scope_candidate(&root, &status, &index)?;
    let prepared_digest = digest(candidate.prepared_scope());
    let confirmed = candidate.confirm(&git_cli)?;

    assert_eq!(prepared_digest, digest(&confirmed));
    assert_eq!(
        digest(&confirmed),
        digest(&acquire_repository_scope(&git_cli, &root)?)
    );
    Ok(())
}

#[test]
fn retained_scope_candidate_rejects_later_repository_or_dirty_content_changes()
-> Result<(), Box<dyn std::error::Error>> {
    let repository = repository()?;
    let git_cli = GitCli::new();
    let root = git_cli.repository_root(repository.path())?;
    let clean_status = git_cli.status(&root)?;
    let clean_index = git_cli.index_entries(&root)?;
    let clean_candidate = prepare_repository_scope_candidate(&root, &clean_status, &clean_index)?;
    fs::write(root.join("tracked.txt"), b"first dirty value\n")?;
    assert!(matches!(
        clean_candidate.confirm(&git_cli),
        Err(ScopeAcquisitionError::RepositoryChanged)
    ));

    let dirty_status = git_cli.status(&root)?;
    let dirty_index = git_cli.index_entries(&root)?;
    let dirty_candidate = prepare_repository_scope_candidate(&root, &dirty_status, &dirty_index)?;
    fs::write(root.join("tracked.txt"), b"second dirty value\n")?;
    assert!(matches!(
        dirty_candidate.confirm(&git_cli),
        Err(ScopeAcquisitionError::WorktreePathChanged { .. })
    ));
    Ok(())
}

#[test]
fn assume_unchanged_never_masquerades_as_a_clean_reusable_scope()
-> Result<(), Box<dyn std::error::Error>> {
    let repository = repository()?;
    let git_cli = GitCli::new();
    let root = git_cli.repository_root(repository.path())?;
    git(
        &root,
        &["update-index", "--assume-unchanged", "tracked.txt"],
    )?;
    fs::write(root.join("tracked.txt"), b"hidden change\n")?;

    let error = acquire_repository_scope(&git_cli, &root)
        .err()
        .ok_or("assume-unchanged index entry unexpectedly produced a scope")?;
    assert!(matches!(
        error,
        ScopeAcquisitionError::OpaqueIndexState { .. }
    ));
    Ok(())
}

#[test]
fn skip_worktree_never_masquerades_as_a_clean_reusable_scope()
-> Result<(), Box<dyn std::error::Error>> {
    let repository = repository()?;
    let git_cli = GitCli::new();
    let root = git_cli.repository_root(repository.path())?;
    git(&root, &["update-index", "--skip-worktree", "tracked.txt"])?;
    fs::write(root.join("tracked.txt"), b"hidden change\n")?;

    let error = acquire_repository_scope(&git_cli, &root)
        .err()
        .ok_or("skip-worktree index entry unexpectedly produced a scope")?;
    assert!(matches!(
        error,
        ScopeAcquisitionError::OpaqueIndexState { .. }
    ));
    Ok(())
}
