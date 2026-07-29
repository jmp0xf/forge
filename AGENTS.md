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

<!-- forge:begin block=project-index schema=1 hash=blake3:e1acb2f9afc6fdca74da84ad334e3ff68eefe00c3a9904c724f369799f8bb35a -->
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
- `docs/adr/`
- `docs/design-proposal.md`
- `fixtures/definitions/projects/`
- `fixtures/generated/`
- `forge.toml`
- `fuzz/Cargo.toml`
- `xtask/Cargo.toml`

## Project-native commands
- format-check step 1/2 (required): env `RUSTUP_AUTO_INSTALL=0`; argv `cargo` `fmt` `--all` `--` `--check`; cwd `.`.
- format-check step 2/2 (required): env `RUSTUP_AUTO_INSTALL=0`; argv `cargo` `fmt` `--all` `--` `--check`; cwd `fuzz`.
- format step 1/2 (required): env `RUSTUP_AUTO_INSTALL=0`; argv `cargo` `fmt` `--all`; cwd `.`.
- format step 2/2 (required): env `RUSTUP_AUTO_INSTALL=0`; argv `cargo` `fmt` `--all`; cwd `fuzz`.
- check step 1/6 (required): env `RUSTUP_AUTO_INSTALL=0`; argv `cargo` `fmt` `--all` `--` `--check`; cwd `.`.
- check step 2/6 (required): env `RUSTUP_AUTO_INSTALL=0`; argv `cargo` `check` `--workspace` `--all-targets`; cwd `.`; explicit authorization required.
- check step 3/6 (required): env `RUSTUP_AUTO_INSTALL=0`; argv `cargo` `clippy` `--workspace` `--all-targets`; cwd `.`; explicit authorization required.
- check step 4/6 (required): env `RUSTUP_AUTO_INSTALL=0`; argv `cargo` `fmt` `--all` `--` `--check`; cwd `fuzz`.
- check step 5/6 (required): env `RUSTUP_AUTO_INSTALL=0`; argv `cargo` `check` `--all-targets`; cwd `fuzz`; explicit authorization required.
- check step 6/6 (advisory): env `RUSTUP_AUTO_INSTALL=0`; argv `cargo` `clippy` `--all-targets`; cwd `fuzz`; explicit authorization required.
- fix step 1/2 (required): env `RUSTUP_AUTO_INSTALL=0`; argv `cargo` `fmt` `--all`; cwd `.`.
- fix step 2/2 (required): env `RUSTUP_AUTO_INSTALL=0`; argv `cargo` `fmt` `--all`; cwd `fuzz`.
- test step 1/8 (required): env `RUSTUP_AUTO_INSTALL=0`; argv `cargo` `fmt` `--all` `--` `--check`; cwd `.`.
- test step 2/8 (required): env `RUSTUP_AUTO_INSTALL=0`; argv `cargo` `check` `--workspace` `--all-targets`; cwd `.`; explicit authorization required.
- test step 3/8 (required): env `RUSTUP_AUTO_INSTALL=0`; argv `cargo` `clippy` `--workspace` `--all-targets`; cwd `.`; explicit authorization required.
- test step 4/8 (required): env `RUSTUP_AUTO_INSTALL=0`; argv `cargo` `test` `--workspace` `--no-fail-fast`; cwd `.`; explicit authorization required.
- test step 5/8 (required): env `RUSTUP_AUTO_INSTALL=0`; argv `cargo` `fmt` `--all` `--` `--check`; cwd `fuzz`.
- test step 6/8 (required): env `RUSTUP_AUTO_INSTALL=0`; argv `cargo` `check` `--all-targets`; cwd `fuzz`; explicit authorization required.
- test step 7/8 (advisory): env `RUSTUP_AUTO_INSTALL=0`; argv `cargo` `clippy` `--all-targets`; cwd `fuzz`; explicit authorization required.
- test step 8/8 (required): env `RUSTUP_AUTO_INSTALL=0`; argv `cargo` `test` `--no-fail-fast`; cwd `fuzz`; explicit authorization required.
- verify (required): argv `cargo` `run` `--locked` `-p` `xtask` `--` `verify`; cwd `.`; explicit authorization required.

## Optional local Receipts
- `forge evidence run format-check` executes the same resolved `format-check` command set and records a scope-bound local Receipt.
- `forge evidence run check` executes the same resolved `check` command set and records a scope-bound local Receipt.
- `forge evidence run test` executes the same resolved `test` command set and records a scope-bound local Receipt.
- `forge evidence run verify` executes the same resolved `verify` command set and records a scope-bound local Receipt.
- A local Receipt is optional evidence, never CI, review, release, or approval authority.

## Completion evidence
- Applicable required commands above must pass; advisory commands are informative only.
- Local command success does not prove CI, review, release, signing, or authorization.

## Stop boundaries
- Stop rather than guessing when an applicable intent is absent, ambiguous, or unknown.
- Stop before changing CI, release, signing, ownership, migrations, or destructive/external state unless explicitly authorized.
<!-- forge:end block=project-index -->
