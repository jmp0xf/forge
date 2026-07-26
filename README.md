# Forge

Forge is a repository-native, executor-neutral engineering runtime layer for humans and coding agents.
It discovers the repository's own build and verification interface, produces minimal host adapters,
computes the next verifiable action, and is designed to record scope-bound local evidence. It does **not** own project
build logic, call an LLM, run an agent loop, or replace independent CI and approval.

This repository contains:

- the accepted implementation design in [`docs/design-proposal.md`](docs/design-proposal.md);
- the initial architecture decision records in [`docs/adr/`](docs/adr/);
- a Rust workspace that fixes crate boundaries before implementation;
- thin `AGENTS.md` and `CLAUDE.md` entry points;
- a CI skeleton whose main verification path uses Cargo directly and does not depend on a built Forge binary.

## Status

M0 through M5 are implemented. Forge now provides typed contracts and diagnostics, hardened Git/filesystem/process
boundaries, Rust and Go project-model detection, deterministic command resolution, minimal managed-block `init`, host
adapter drift/sync, `doctor`, and the read-only `next` reducer with effective-policy, risk, and bounded context output.

M6 Receipt/Evidence foundations are in progress. The accepted design does not yet define a trustworthy comparison
base for committed repositories and the published Receipt v1 shape cannot represent every invalidation dimension
required by the accepted ADRs. Until those contracts are resolved, committed-repository navigation remains explicitly
`unknown` and evidence commands fail closed instead of claiming that local observations are sufficient. Explicit
runner/CI generation also remains disabled because its generated-file contracts are not frozen.

See the [v0 implementation status](docs/v0-implementation-status.md) for the exact implemented boundary and the
decisions required before the public Evidence surface can be enabled.

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

The implemented command surface is `init`, `doctor`, `next`, `adapters`, `explain`, `schema`, `version`, and
`completions`. `init --with-runner`, `init --with-ci`, and every `evidence` subcommand report explicit unsupported
boundaries rather than generating or validating contracts that the accepted design has not fixed. `improve` and
`evolve` are intentionally not v0 commands; controlled improvement candidates and bounded self-hosting remain later
version work.

Do not add a feature that changes an accepted decision without an ADR that supersedes the relevant record.
