# Repository workflow

Human and automated contributors use the same engineering workflow.

## Authoritative sources

- Accepted implementation design: `docs/design-proposal.md`
- Architecture decisions and supersession history: `docs/adr/`
- Contribution rules: `CONTRIBUTING.md`
- Current code and tests: `crates/`, `xtask/`, `tests/`, and `fixtures/`

## Project commands

- Format check: `cargo fmt --all -- --check`
- Lint: `cargo clippy --workspace --all-targets -- -D warnings`
- Tests: `cargo test --workspace`
- Bootstrap CLI: `cargo run -p forge-cli -- version`

## Completion

A change is locally verified only when the relevant Cargo commands pass for the current worktree. Report the exact
commands and exit codes. Merge readiness still depends on independent CI and required review.

## Stop and escalate

Stop before weakening tests or assertions; changing CI, release, signing, ownership, or authority boundaries;
changing a versioned machine contract without a migration; or contradicting an accepted ADR without a superseding ADR.

<!-- forge:begin block=project-index schema=1 hash=blake3:613a02ac08e44b069a2ce64a4e9d059ef2fb515301e4483552e3d5c3a40119ef -->
## Authoritative paths
- `.github/workflows/verify.yml`
- `CONTRIBUTING.md`
- `Cargo.toml`
- `README.md`
- `SECURITY.md`
- `crates/forge-cli/Cargo.toml`
- `crates/forge-core/Cargo.toml`
- `crates/forge-detect/Cargo.toml`
- `crates/forge-render/Cargo.toml`
- `crates/forge-runtime/Cargo.toml`
- `crates/forge-schema/Cargo.toml`
- `docs/adr/0000-template.md`
- `docs/adr/0001-name-the-cli-forge-and-centralize-product-identity.md`
- `docs/adr/0002-use-rust-2024-with-msrv-1-85.md`
- `docs/adr/0003-project-native-commands-are-the-stable-interface.md`
- `docs/adr/0004-use-a-six-crate-layered-workspace.md`
- `docs/adr/0005-store-runtime-state-in-git-private-directories.md`
- `docs/adr/0006-use-managed-blocks-for-generated-host-adapters.md`
- `docs/adr/0007-shell-out-to-git-porcelain-v2.md`
- `docs/adr/0008-use-synchronous-execution-without-tokio.md`
- `docs/adr/0009-version-all-machine-readable-contracts.md`
- `docs/adr/0010-separate-local-evidence-from-external-approval.md`
- `docs/adr/0011-bound-self-hosting-with-an-external-authority-set.md`
- `docs/adr/0012-support-rust-and-go-first.md`
- `docs/adr/0013-defer-ast-semantic-indexing-and-model-integration.md`
- `docs/adr/0014-default-to-zero-config-and-minimal-init.md`
- `docs/adr/0015-isolate-worktree-state-and-share-only-content-addressed-cache.md`
- `docs/adr/0016-use-dependency-based-evidence-invalidation.md`
- `docs/adr/0017-do-not-generate-runner-ci-or-organization-docs-by-default.md`
- `docs/adr/0018-derive-local-repository-identity-from-git-common-dir.md`
- `docs/adr/README.md`
- `docs/design-proposal.md`
- `fuzz/Cargo.toml`
- `xtask/Cargo.toml`

## Project-native commands
- format-check step 1/2 (required): env `RUSTUP_AUTO_INSTALL=0`; argv `cargo` `fmt` `--all` `--` `--check`; cwd `.`.
- format-check step 2/2 (required): env `RUSTUP_AUTO_INSTALL=0`; argv `cargo` `fmt` `--all` `--` `--check`; cwd `fuzz`.
- format step 1/2 (required): env `RUSTUP_AUTO_INSTALL=0`; argv `cargo` `fmt` `--all`; cwd `.`.
- format step 2/2 (required): env `RUSTUP_AUTO_INSTALL=0`; argv `cargo` `fmt` `--all`; cwd `fuzz`.
- check step 1/4 (required): env `RUSTUP_AUTO_INSTALL=0`; argv `cargo` `fmt` `--all` `--` `--check`; cwd `.`.
- check step 2/4 (required): env `RUSTUP_AUTO_INSTALL=0`; argv `cargo` `check` `--workspace` `--all-targets`; cwd `.`; explicit authorization required.
- check step 3/4 (required): env `RUSTUP_AUTO_INSTALL=0`; argv `cargo` `fmt` `--all` `--` `--check`; cwd `fuzz`.
- check step 4/4 (required): env `RUSTUP_AUTO_INSTALL=0`; argv `cargo` `check` `--all-targets`; cwd `fuzz`; explicit authorization required.
- test step 1/6 (required): env `RUSTUP_AUTO_INSTALL=0`; argv `cargo` `fmt` `--all` `--` `--check`; cwd `.`.
- test step 2/6 (required): env `RUSTUP_AUTO_INSTALL=0`; argv `cargo` `check` `--workspace` `--all-targets`; cwd `.`; explicit authorization required.
- test step 3/6 (required): env `RUSTUP_AUTO_INSTALL=0`; argv `cargo` `test` `--workspace` `--no-fail-fast`; cwd `.`; explicit authorization required.
- test step 4/6 (required): env `RUSTUP_AUTO_INSTALL=0`; argv `cargo` `fmt` `--all` `--` `--check`; cwd `fuzz`.
- test step 5/6 (required): env `RUSTUP_AUTO_INSTALL=0`; argv `cargo` `check` `--all-targets`; cwd `fuzz`; explicit authorization required.
- test step 6/6 (required): env `RUSTUP_AUTO_INSTALL=0`; argv `cargo` `test` `--no-fail-fast`; cwd `fuzz`; explicit authorization required.

## Completion evidence
- Applicable required commands above must pass; advisory commands are informative only.
- Local command success does not prove CI, review, release, signing, or authorization.

## Stop boundaries
- Stop rather than guessing when an applicable intent is absent, ambiguous, or unknown.
- Stop before changing CI, release, signing, ownership, migrations, or destructive/external state unless explicitly authorized.
<!-- forge:end block=project-index -->
