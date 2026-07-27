# Forge v0 implementation status

This is a maintenance handoff, not an architecture decision. The accepted contract remains
`docs/design-proposal.md` together with `docs/adr/`. Update this note when a listed boundary is
resolved or superseded.

## Implemented boundary

M0 through M6 have local implementations. The in-repository parts of M7 are present, but M7 release
acceptance is not complete.

| Area | Current local implementation |
|---|---|
| Protocol and layering | Six-crate workspace, typed IDs/contracts/diagnostics, stable exit codes, dependency-direction and architecture checks |
| Runtime | Bounded Git, native-path, filesystem, synchronous process, state, lock, timeout, cancellation, output-digest, and private-permission paths |
| Detection | Strict `forge.toml`, repository/runner/Rust/Go/mixed discovery, deterministic command resolution, risk and policy provenance |
| Integration | Default-dry-run `init`, managed `AGENTS.md`/host adapters, adapter drift/sync, and explicit make/just/task runner generation |
| Navigation | `doctor`, deterministic read-only `next`, `explain`, schema/version/completion output |
| Local evidence | Receipt/Evidence v2 run/show/verify/export, dependency invalidation, immutable state, bounded retention, and v1 historical readers |
| In-repository hardening | 28 public fixtures, schema/golden/compatibility tests, dogfood fixed point, fuzz corpora, bounded mutation config, and opt-in large-repository benchmark |

Default `init` still does not generate a runner, CI, configuration, ADR, runbook, or ownership file.
Runner generation occurs only after an explicit choice and creates a project-native managed `verify`
target from already resolved required commands. `init --with-ci github` remains deliberately
unavailable and returns an explicit environment-unmet diagnostic.

`improve`, `evolve`, model integration, external-attestation import, and release orchestration remain
outside the v0 command surface.

## Receipt and Evidence v2

ADRs 0019-0022 resolve the earlier M6 decisions:

- `forge.worktree-comparison/v1` uses the invocation's immutable `HEAD` as the local worktree
  baseline, never guesses an upstream, default branch, PR target, or merge authority;
- unborn repositories use not-applicable base/task state; merge, rebase, unmerged, and unstable
  repository states fail closed for evidence execution;
- Receipt/Evidence writers use `forge.receipt/v2` and `forge.evidence/v2`; v1 remains readable only
  as historical, non-proving input for the documented compatibility period;
- Receipt validity covers repository, before/after scope, ordered command set, toolchain,
  allowlisted environment, effective policy, base/task, and versioned Forge behavior;
- missing command semantics, unknown dependencies, a non-passing outcome, an unconfirmed mutating
  command, or a changed scope remains typed non-proving/stale state rather than a pass;
- Evidence partitions `verified`, `advisory`, `not_verified`, and `external_required`, and v0 always
  emits an empty external-attestation set.
- One `forge.operation-control/v1` deadline and cancellation source spans the complete command;
  child stages only receive remaining time and cannot reset the user-supplied total budget.
- Detected Rust projects add both generic and `custom:rust-*` coverage expectations. Missing
  expectations are projected as gaps after Receipt evaluation, while policy-driven local
  sufficiency remains unchanged; `cargo check --all-targets` does not claim that
  feature-gated examples or benches were compiled.

`evidence run` validates the selected command chain, executes it as `program + argv`, records bounded
observations, and persists an immutable worktree-local Receipt. `show` and `verify` reopen existing
state read-only and recompute current applicability from a stable detection/scope pair; neither
creates Forge directories, locks, cache entries, or access-time metadata. `export` performs the same
recomputation and explicitly persists the canonical Evidence object it emits.

Receipt, Evidence, and optional log objects use content-derived names, atomic no-clobber writes,
worktree isolation, reference-aware retention, bounded scans, and fail-closed malformed/future-state
handling. Default Receipt/Evidence does not retain complete stdout/stderr, environment values,
secrets, source files, or private reasoning.

These are local observations only. They do not mean that a change passed CI, review, merge policy,
deployment validation, signing, or release approval.

## Inventory cache

Clean, stable, eligible repositories can reuse a content-addressed inventory entry under
`<git-common-dir>/forge/cache/`. The key binds repository identity, HEAD, effective policy,
inventory options, platform, Forge behavior, and a worktree-independent semantic Git-index
projection of mode, blob identity, and native path. Raw index bytes bracket status/index reads only
to reject concurrent changes; they do not enter the shared key because checkout-local stat data
differs across linked worktrees. A cache payload retains only sorted regular-file paths, never live
worktree byte sizes. Before reuse, Forge requires clean status, matches every cached path against
the current bounded stage-zero index projection, and rechecks the raw index snapshot. Malformed,
unsafe, dirty, untracked, unmerged, split-index, locked-index, symlink/reparse, Gitlink,
assume-unchanged, skip-worktree, or any exposed index state outside the explicitly accepted
ordinary stage-zero subset falls back to authoritative inventory.

A miss is retained in memory and is published only after an authorized Forge state write succeeds.
Read-only commands, dry-runs, and failed applies do not publish a miss. `--no-cache` bypasses reads
and publication without rewriting existing entries. Linked worktrees keep Receipt/Evidence state
separate while sharing only eligible immutable inventory cache entries through the Git common
directory.

## Verification assets

The repository contains, without claiming that every campaign passed for the current candidate:

- a versioned definition manifest and deterministic generator for all 28 fixtures required by the
  accepted design;
- E2E construction for dirty indexes, linked worktrees, non-UTF-8 paths, symlinks, submodules,
  timeouts/process trees, bounded huge output, malicious manifests, CRLF, uninstallability, and
  cache side effects;
- checked-in JSON Schemas, schema-drift checks, and representative CLI-instance validation;
- byte-level human-output goldens and representative stable failure diagnostics;
- `xtask diff-plans`, which compares two explicit binaries over public fixture plans, diagnostics,
  exits, supported schema sets, and shared schema documents;
- a dogfood test requiring this repository's default `init --dry-run --json` plan to be a zero diff;
- four fuzz targets/corpora for porcelain v2, managed blocks, strict config, and native paths;
- a checked-in bounded `cargo-mutants` surface for evidence, navigation, risk, validity, and policy
  anti-weakening decisions; and
- an ignored 100,000-file benchmark that reports first-inventory and warm-command p95 values without
  converting performance goals into platform-independent assertions.

The public fixture and N-1 harness are candidate-controlled self-checks. Specialized platform state
is constructed by integration tests and the harness currently uses reviewed Unix process-group
containment; it fails closed on Windows rather than pretending equivalent Job Object coverage.

## Work still required before v0 release

The following boundaries are intentionally not inferred from local implementation or test assets:

1. **Current-candidate verification.** Every handoff must run the root and fuzz Cargo commands from
   `AGENTS.md`, schema checks, applicable fixtures, and targeted hardening campaigns, then report
   exact commands, exit codes, platform, tool versions, and remaining gaps. This document is not a
   substitute for that run ledger.
2. **Filesystem threat model and security review.** The path-based final replacement does not pin
   ancestor handles against a concurrent untrusted rename. `SECURITY.md` remains authoritative for
   this TOCTOU limitation. A private reporting channel and independent security review are still
   required before public release.
3. **Cross-platform evidence.** Linux x86_64/aarch64, macOS x86_64/aarch64, and Windows x86_64
   build/E2E/process/path matrices have not been proven by this local worktree. Windows Job Object,
   UNC/wide-path, case, ACL, and native replacement behavior require their actual platform tests.
4. **Independent CI and review.** A checked-in workflow is candidate-controlled configuration, not
   proof that required CI ran or that maintainers reviewed and approved the result.
5. **Distribution and release.** Version selection, packaging, SBOM, checksums, signing, publishing,
   provenance, rollback, and release ownership remain unimplemented or externally unauthorized.
6. **No self-authorization claim.** v0 remains ordinary dogfooding: candidate-controlled tests and
   the public N-1 harness are reviewable self-checks, not final authority. Held-out tests and the
   physically separate Authority Set are v0.3 requirements rather than v0 release blockers; they
   must exist before Forge can claim trusted self-hosting. Independent CI, review, release,
   signing, and promotion authority still cannot be inferred from this candidate's local results.

Do not weaken tests, alter release/signing/ownership/authority boundaries, or change a versioned
machine contract without the required authorization, migration, and ADR process.
