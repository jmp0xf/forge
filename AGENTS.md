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
