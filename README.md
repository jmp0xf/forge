# Forge

Forge is a repository-native, executor-neutral engineering runtime layer for humans and coding agents.
It discovers the repository's own build and verification interface, produces minimal host adapters,
computes the next verifiable action, and records scope-bound local evidence. It does **not** own project
build logic, call an LLM, run an agent loop, or replace independent CI and approval.

This repository is the pre-implementation bootstrap for Forge. It contains:

- the accepted implementation design in [`docs/design-proposal.md`](docs/design-proposal.md);
- the initial architecture decision records in [`docs/adr/`](docs/adr/);
- a dependency-free Rust workspace skeleton that fixes crate boundaries before implementation;
- thin `AGENTS.md` and `CLAUDE.md` entry points;
- a CI skeleton whose main verification path uses Cargo directly and does not depend on a built Forge binary.

## Status

The design is ready for implementation. The Rust sources are deliberately small: they establish package names,
dependency direction, public boundary types, and a minimal `forge version` / `forge schema` bootstrap without
pretending that `init`, `doctor`, `next`, adapters, or evidence already work.

## Bootstrap commands

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p forge-cli -- version
cargo run -p forge-cli -- schema
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

## First implementation milestone

Start with M0 and M1 in the design proposal:

1. add the selected serialization, CLI, diagnostic, hashing, file-locking, and test dependencies after a joint
   compatibility spike;
2. freeze the first JSON Schemas and exit-code mapping;
3. implement Git porcelain-v2 parsing, native path handling, atomic state, and the synchronous process runner;
4. add the invariant and fixture tests before implementing higher-level commands.

Do not add a feature that changes an accepted decision without an ADR that supersedes the relevant record.
