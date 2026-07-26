# Forge

Forge is a repository-native, executor-neutral engineering runtime layer for humans and coding agents.
It discovers the repository's own build and verification interface, produces minimal host adapters,
computes the next verifiable action, and records scope-bound local evidence. It does **not** own project
build logic, call an LLM, run an agent loop, or replace independent CI and approval.

This repository contains:

- the accepted implementation design in [`docs/design-proposal.md`](docs/design-proposal.md);
- the initial architecture decision records in [`docs/adr/`](docs/adr/);
- a Rust workspace that fixes crate boundaries before implementation;
- thin `AGENTS.md` and `CLAUDE.md` entry points;
- a CI skeleton whose main verification path uses Cargo directly and does not depend on a built Forge binary.

## Status

M0 and M1 are implemented. The executable protocol surface is backed by typed identifiers, structured diagnostics,
stable exit codes, checked-in JSON Schemas, and shell completions. Runtime boundaries now include typed Git porcelain
and Git-authoritative inventory, native repository paths, isolated private state, atomic repository-confined writes,
BLAKE3 hashing, and synchronous bounded subprocess execution with timeout, cancellation, and process-tree cleanup.

M2 project-model and generic detection work is next. `init`, `doctor`, `next`, adapters, explain, and evidence still
fail explicitly rather than pretending placeholder behavior is complete.

## Bootstrap commands

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p forge-cli -- version
cargo run -p forge-cli -- version --json
cargo run -p forge-cli -- schema
cargo run -p xtask -- check-schemas
```

Rust 2024 Edition is required. The declared MSRV is Rust 1.85; CI should test both 1.85 and current stable.

## Repository shape

```text
crates/forge-schema   versioned machine contracts
crates/forge-core     pure domain model, policies, state machines, and ports
crates/forge-runtime  Git/filesystem/process/state implementations
crates/forge-detect   repository, runner, Rust, and Go discovery
crates/forge-render   managed blocks, change plans, and host adapter rendering
crates/forge-cli      binary composition, I/O discipline, and exit-code mapping
xtask                 schema export, fixture generation, and compatibility checks
```

The stable interface of projects analyzed by Forge remains their own commands (`cargo`, `go`, `make`, `just`,
`task`, or existing scripts). Removing Forge must not break a project's build, tests, verification, or release.

## Current implementation boundary

M1 is complete. Continue with M2 in the design proposal: repository facts, strict optional configuration, static
runner discovery, deterministic command resolution, the complete `ProjectModel`, and read-only `forge explain`.
Higher-level write, navigation, and evidence commands remain explicit failures until their prerequisite milestones
are real.

Do not add a feature that changes an accepted decision without an ADR that supersedes the relevant record.
