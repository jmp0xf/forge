# Contributing to Forge

## Source of truth

The accepted architecture is [`docs/design-proposal.md`](docs/design-proposal.md). Decisions that should remain
stable across refactors are recorded in [`docs/adr/`](docs/adr/). A pull request that changes an accepted decision
must add a new ADR with `Status: Accepted` and mark the old ADR as superseded; editing history in place is not enough.

## Development checks

The workspace uses Rust 2024 with MSRV 1.85. To build and install the current checkout for local dogfooding:

```bash
cargo install --locked --path crates/forge-cli
forge version
```

Installation does not replace verification. Run the complete local gates from the repository root and preserve their
exact exit codes:

```bash
RUSTUP_AUTO_INSTALL=0 cargo fmt --all -- --check
RUSTUP_AUTO_INSTALL=0 cargo check --workspace --all-targets
RUSTUP_AUTO_INSTALL=0 cargo clippy --workspace --all-targets -- -D warnings
RUSTUP_AUTO_INSTALL=0 cargo test --workspace --no-fail-fast

(cd fuzz && RUSTUP_AUTO_INSTALL=0 cargo fmt --all -- --check)
(cd fuzz && RUSTUP_AUTO_INSTALL=0 cargo check --all-targets)
(cd fuzz && RUSTUP_AUTO_INSTALL=0 cargo test --no-fail-fast)

RUSTUP_AUTO_INSTALL=0 cargo run -p xtask -- check-schemas
```

The repository intentionally dogfoods its Cargo commands directly; it does not need a generated Makefile, justfile, or
Taskfile to build itself. `forge init --with-runner make|just|task` is an explicit product feature for repositories that
choose a common `verify` entry point, not a reason to introduce a redundant runner here by default.

Focused checks are useful while iterating, but do not replace the complete gates:

```bash
cargo test -p forge-cli --test json_schema_contract
cargo test -p forge-cli --test human_golden
cargo test -p forge-cli --test fixture_matrix
cargo test -p forge-cli --test dogfood_fixed_point
cargo test -p xtask --test fixture_projects
cargo test -p xtask --test compatibility_harness
```

The 100,000-file benchmark is intentionally opt-in and reports measurements rather than turning startup targets into
portable correctness assertions:

```bash
cargo test --release -p forge-cli --test fixture_matrix large_repository_v0_latency_benchmark \
  -- --ignored --exact --nocapture
```

The benchmark refuses a debug build. On macOS and Linux it also wraps a separate cold-inventory
`forge` invocation with `/usr/bin/time` and reports that process's peak RSS; this excludes the Cargo
test driver and fixture-materialization memory. It reports warm p50/p95 for the Git plumbing used to
interpret the large repository so a slow Forge result can be separated from host Git cost.

For changes to critical parsers, paths, evidence state, validity, risk, or anti-weakening rules, also run the applicable
fuzz targets from [`fuzz/README.md`](fuzz/README.md) and the checked-in bounded mutation surface:

```bash
cargo mutants
```

Record tool versions, campaign bounds, and survivors or crashes. The presence of corpora or configuration is not a
claim that a campaign ran for the current candidate.

## Generated contracts and fixtures

Checked-in schemas and fixture repositories are reviewable interfaces:

```bash
cargo run -p xtask -- check-schemas
cargo run -p xtask -- generate-fixtures
```

`schema-export` and `generate-fixtures` are writes. Run them only when intentionally updating their source contracts,
then review the complete diff. Fixture definitions live under `fixtures/definitions/`; generated material belongs only
under `fixtures/generated/`. The public N-1 self-check requires two explicit binaries:

```bash
cargo run -p xtask -- diff-plans \
  --baseline /path/to/known-good-forge \
  --candidate /path/to/candidate-forge
```

That comparison is candidate-controlled public evidence. It is not the external held-out authority or a release
approval.

## Release-candidate assets

The repository can locally assemble and verify the frozen `0.1.0-rc.1` GitHub Release asset set without mutating any
external hosting or release system. Start from a clean Git checkout and create a dedicated real output directory
outside the checkout; an output inside the repository (including `.git/`) is rejected, and the release commands
intentionally do not create the directory:

```bash
git status --porcelain=v2 --untracked-files=all --ignore-submodules=none
mkdir -p /absolute/path/to/dist
RUSTUP_AUTO_INSTALL=0 cargo build --locked --offline -p xtask
target/debug/xtask release-build --target <TRIPLE> --output-dir /absolute/path/to/dist
target/debug/xtask release-finalize --output-dir /absolute/path/to/dist
target/debug/xtask release-check --output-dir /absolute/path/to/dist
```

All five targets must be staged before finalization. The exact matrix, external SLSA/Sigstore gate, unassigned
ownership and license/notice requirements, Windows/PowerShell commands, fixed twelve-subject upload rule, and N−1
rollback procedure are documented in [`docs/release.md`](docs/release.md). These local commands never tag, sign,
attest, upload, publish, or authorize a release.

## Change discipline

- Keep crate dependencies in the direction defined by ADR-0004.
- Keep core domain logic free of filesystem, process, Git, clock, and network side effects.
- Execute external commands as `program + argv`; do not build shell command strings in core paths.
- Never add committed `.forge/`, `.ai/`, `.agent/`, or similar private working-tree directories.
- Do not describe local receipts as merge, release, or production authorization.
- Do not add Tokio, an embedded Git implementation, AST indexing, embeddings, an LLM SDK, or a database without a
  superseding ADR backed by measured need.
- Machine-readable output, exit codes, managed-block markers, and agent-visible diagnostics are interfaces. Review
  changes to them as compatibility changes.
- Preserve Receipt/Evidence v1 as historical, non-proving input while v2 is current. Do not change a versioned
  machine contract without the required migration and compatibility behavior.
- Keep read-only operations read-only: `evidence show`, `evidence verify`, previews, and failed applies must not
  publish cache or create private state as a side effect.

## Pull request evidence

Include the commands run, their exact exit status, the tested platform and tool versions, and known gaps in the pull
request description. Where the resolved command metadata is sufficient, Forge can additionally record local
observations:

```bash
forge evidence run test
forge evidence verify
forge evidence export
```

A Receipt or Evidence bundle is a local observation tied to its recorded dependencies. It is not a CI result, review,
merge approval, release authorization, deployment attestation, or substitute for an independently controlled authority
set.
