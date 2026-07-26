# Contributing to Forge

## Source of truth

The accepted architecture is [`docs/design-proposal.md`](docs/design-proposal.md). Decisions that should remain
stable across refactors are recorded in [`docs/adr/`](docs/adr/). A pull request that changes an accepted decision
must add a new ADR with `Status: Accepted` and mark the old ADR as superseded; editing history in place is not enough.

## Development checks

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The repository intentionally has no Makefile or justfile at bootstrap. Cargo commands are already a clear,
portable project interface for this single-language repository. Introducing a runner requires measured need and an ADR.

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

## Pull request evidence

Until Forge can generate its own receipts, include the commands run, their exit status, the tested platform, and
known gaps in the pull request description. Green local checks do not replace required CI or review.
