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
| Runtime | Bounded Git, native-path, filesystem, synchronous process, state, lock, timeout, cancellation, output-digest, private-permission, handle-confined repository writes, and fail-closed Windows directory-swap handling |
| Detection | Strict `forge.toml`, repository/runner/Rust/Go/mixed discovery, deterministic command resolution, risk and policy provenance |
| Integration | Default-dry-run `init`, managed `AGENTS.md`/host adapters, adapter drift/sync, explicit make/just/task runners, and create-only GitHub CI generation |
| Navigation | `doctor`, deterministic read-only `next`, `explain`, schema/version/completion output |
| Local evidence | Receipt/Evidence v2 run/show/verify/export, content-free dual-stream diagnostic summaries, dependency invalidation, immutable state, bounded retention, and v1 historical readers |
| In-repository hardening | Direct project-native CI gates, 28 public fixtures, schema/golden/compatibility tests, dogfood fixed point, fuzz corpora, bounded mutation config, and opt-in large-repository benchmark |
| Local release candidates | Create-only `0.1.0-rc.1` five-target assembler, exact-commit isolated source binding, executable checks, CycloneDX SBOMs, release manifest, SHA-256 checksums, and explicit external authority/rollback gates |

Default `init` still does not generate a runner, CI, configuration, ADR, runbook, or ownership file.
Runner generation occurs only after an explicit choice and creates a project-native managed `verify`
target from already resolved required commands. `init --with-ci github` explicitly creates only a
missing `.github/workflows/verify.yml`; equivalent complete YAML is a no-op, while non-equivalent or
unknown existing content fails without writes and is never overwritten.

`improve`, `evolve`, model integration, external-attestation import, and external release
orchestration remain outside the v0 command surface. Repository-only `xtask` commands assemble and
check local review candidates; they do not tag, sign, attest, upload, publish, or authorize a
release.

ADR-0034 supersedes ADR-0033 because its non-NULL `RootDirectory` choice does not match Microsoft's
documented same-directory simple-leaf form, and native Windows runs did not establish the expected
progress guarantee. Same-directory Windows rename again uses a NULL root and simple leaf. The common
contract is the safety invariant, not identical platform progress: Forge content must not enter a
replacement tree; failures before a successful native rename are `NotCommitted`; failures in a
post-commit hook, identity revalidation, or post-commit read are `CommittedUnverified`. This does
not change a versioned machine contract or qualify every Windows filesystem.

## Receipt and Evidence v2

ADRs 0019-0026 and 0032 resolve and extend the earlier M6 decisions:

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
- Current Receipt v2 writers record an O(1), content-free `diagnostic_summary` for every command
  observation. Normal completion, timeout, interruption, and pre-spawn control observations use
  `observed` with complete stdout/stderr byte counts; typed process-boundary failures use
  `unavailable` without counts. Early-v2 missing summaries and future states remain readable but
  non-proving. Receipt schema and identity remain v2, while `forge.evidence-behavior/v7` makes v6
  receipts stale instead of rewriting them.
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
differs across linked worktrees. A cache entry is a fixed-shape eligibility attestation over the
schema, key, platform, rules, semantic-index projection, entry count, and payload digest; it retains
neither paths nor live worktree byte sizes. Before reuse, Forge requires clean status, validates the
attestation, rebuilds the complete inventory and file set solely from the current bounded typed
stage-zero index entries, and rechecks the raw index snapshot. Malformed,
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
  cache side effects, plus an explicit strict exitability qualification that fails closed unless
  every declared project-native tool is available and every native command passes after uninstall;
- checked-in JSON Schemas, schema-drift checks, and representative CLI-instance validation;
- byte-level human-output goldens and representative stable failure diagnostics;
- `xtask diff-plans`, which compares two explicit binaries over public fixture plans, diagnostics,
  exits, supported schema sets, and shared schema documents;
- a dogfood test requiring this repository's default `init --dry-run --json` plan to be a zero diff;
- release-source revalidation tests that advance the original repository `HEAD` and mutate the
  detached source tree or `Cargo.lock` after preparation, requiring each later release boundary to
  fail closed;
- four fuzz targets/corpora for porcelain v2, managed blocks, strict config, and native paths;
- a checked-in bounded `cargo-mutants` surface for evidence, navigation, risk, validity, and policy
  anti-weakening decisions;
- an ignored 100,000-file benchmark that reports one first-inventory observation, repeated
  uncached-inventory p50/p95, warm-command p95, and Git-plumbing p50/p95 without converting
  performance goals into platform-independent assertions;
- a `Project contract / generated drift` CI job that directly runs the required root and fuzz
  project-native commands, then checks schemas, generated fixtures, tracked/untracked drift, and
  the bootstrap CLI. MSRV, native targets, strict fixtures, fuzz campaigns, and opt-in mutation
  remain separate qualification jobs.

The public fixture and N-1 harness are candidate-controlled self-checks. Specialized platform state
is constructed by integration tests and the harness currently uses reviewed Unix process-group
containment; it fails closed on Windows rather than pretending equivalent Job Object coverage.

## Current-candidate verification

### Local verification

Against code commit `e9b8f52` plus this documentation-only status update on macOS 26.5.2 arm64 with
Rust/Cargo 1.96.0 and Git 2.51.0, the following commands exited zero:

- from the repository root, `env RUSTUP_AUTO_INSTALL=0 cargo fmt --all -- --check`,
  `env RUSTUP_AUTO_INSTALL=0 cargo check --workspace --all-targets`,
  `env RUSTUP_AUTO_INSTALL=0 cargo clippy --workspace --all-targets`,
  `env RUSTUP_AUTO_INSTALL=0 cargo clippy --workspace --all-targets -- -D warnings`, and
  `env RUSTUP_AUTO_INSTALL=0 cargo test --workspace --no-fail-fast`;
- from `fuzz/`, `env RUSTUP_AUTO_INSTALL=0 cargo fmt --all -- --check`,
  `env RUSTUP_AUTO_INSTALL=0 cargo check --all-targets`, the advisory
  `env RUSTUP_AUTO_INSTALL=0 cargo clippy --all-targets`, the additional strict
  `env RUSTUP_AUTO_INSTALL=0 cargo clippy --all-targets -- -D warnings`, and
  `env RUSTUP_AUTO_INSTALL=0 cargo test --no-fail-fast`;
- from the repository root, `env RUSTUP_AUTO_INSTALL=0 cargo run -p xtask -- check-schemas` and
  `env RUSTUP_AUTO_INSTALL=0 cargo run -p xtask -- generate-fixtures`, with the latter reporting 0
  written and 105 unchanged; and
- from the repository root, `env RUSTUP_AUTO_INSTALL=0 cargo run -p forge-cli -- version`,
  `env RUSTUP_AUTO_INSTALL=0 cargo run -p forge-cli -- init --dry-run --json` with zero edits, and
  `env RUSTUP_AUTO_INSTALL=0 cargo run -p forge-cli -- adapters check --json` with no drift.

Dogfood first detected that the private adapter manifest still bound the previous renderer behavior;
an authorized explicit sync/apply updated only private Git state, left `AGENTS.md` and `CLAUDE.md`
byte-identical, and made the next check report no drift. The current
`env RUSTUP_AUTO_INSTALL=0 cargo run -p forge-cli -- doctor --json` run safely parsed one local
workflow and confirmed all seven required project-native verification commands. It exited 1 with
`overall=unknown`, as specified, because read-only doctor does not prove state-write/lock
capability, server-side required checks or branch protection, and no conventional CODEOWNERS file
is visible. A later
`env RUSTUP_AUTO_INSTALL=0 cargo run -p forge-cli -- adapters sync --apply --json` attempt while this
status file was dirty exited 2 before writing, as required; it did not treat the earlier
authorization as permission to bypass the clean worktree gate.

### GitHub Actions

Failed runs `30374770619` and `30377585092` are retained as regression evidence, not waived. The
first drove the native-path assertion and Windows rename corrections in `9a4ef99` and `f2c6c7d`;
the second showed that the fixture harness still invoked Git with `-C` for its deliberately long
worktree before long-path-aware access, and that Windows could reject the intermediate-directory
swap before the test's assumed topology existed. Commits `d733c5e` and `fa57004` addressed those two
observations.

Run `30379720907` then confirmed all 117 Windows runtime tests, including the corrected directory
swap case, but its only fixture failure showed that explicit `--git-dir`/`--work-tree` still did not
make `git init` accept the long target before configuration. Commit `e9b8f52` now creates the
ordinary non-bare fixture repository at a short path, moves the whole repository with the native
filesystem, and requires all subsequent Git and Forge operations to resolve, read, write, and
converge at the final path without help from ambient/global `core.longpaths` configuration.

Run `30382132956` did not execute this candidate: GitHub rejected all nine non-optional jobs before
creating their first step because recent account payments failed or the Actions spending limit must
be increased. It is external infrastructure evidence only, not a test failure or a qualification
pass. A later failed-jobs rerun was accepted by GitHub but again completed all nine jobs with no
steps or logs, confirming that the external boundary still applied. After the account owner repairs
it, the same commit needs a fresh complete run. The bounded mutation job remains an explicit
`workflow_dispatch` campaign and is intentionally skipped on ordinary pull-request runs.

## Historical local calibration and hardening evidence

On 2026-07-28, the ignored release benchmark completed against commit `655b42b` on
macOS 26.5.2 arm64 with Rust/Cargo 1.96.0 and Git 2.51.0. It used the generated
100,000-committed-file fixture. This is one local observation, not a portable performance
qualification:

| Measurement | Observed | Design target | Result |
|---|---:|---:|---|
| First uncached inventory | 3,052 ms | single observation | not classified |
| Uncached inventory p50/p95 (20 samples) | 2,389 / 2,469 ms | p95 < 5,000 ms | met locally |
| Cold Forge peak RSS | unavailable | < 150 MiB | not measured |
| `version` p95 | 4 ms | < 50 ms | met locally |
| warm `next` p95 | 1,043 ms | < 200 ms | not met |
| warm `adapters check` p95 | 561 ms | < 300 ms | not met |
| warm `doctor` p95 | 651 ms | < 3,000 ms | met locally |

The same fixture measured bare `git status` at 278 ms p95. That host-level baseline does not weaken
or redefine Forge's targets; this machine still cannot qualify the 200 ms `next` target, and the
remaining Forge overhead requires measurement and reduction on a calibrated runner and
representative real repositories. Benchmark process success must not be described as every
performance target passing. When the host blocks `/usr/bin/time` from collecting resource usage,
the benchmark reports RSS as unavailable rather than claiming a result, while retaining the
independent latency samples.

A historical bounded full `cargo-mutants 27.0.0` campaign against commit `7e9b559` tested 300 mutants in 88
minutes: 276 were caught, 24 were unviable, none were missed, and none timed out. The baseline build
and test suite passed, so no viable mutant survived that bounded surface. The full
rerun included and caught the previously surviving deletion of the `risk/docs-only` arm in
`add_content_uncertainty`, confirming the regression test added by `e51837c` within the complete
campaign.

A later targeted `cargo-mutants 27.0.0` campaign against the navigation-receipt validation predicate
first exposed one viable `||`-to-`&&` survivor. Commit `a9937d1` added an exhaustive truth-table
regression and included the predicate in the checked-in bounded mutation surface. The targeted
rerun passed its baseline, tested six mutants, caught five, classified one as unviable, and missed
none.

## Work still required before v0 release

The following boundaries are intentionally not inferred from local implementation or test assets:

1. **Current-candidate verification.** Every handoff must run the root and fuzz Cargo commands from
   `AGENTS.md`, schema checks, applicable fixtures, and targeted hardening campaigns, then report
   exact commands, exit codes, platform, tool versions, and remaining gaps. The current local and
   GitHub Actions ledgers are recorded above; this document is not a substitute for rerunning them
   on a later candidate. The strict CI job provisions fixed `just`, `task`, and Go versions and
   fails closed if any declared fixture-native command is unavailable or fails. Every release
   candidate still needs that gate on its controlled, fully provisioned runner.
2. **Filesystem threat model and security review.** Repository writes and release-asset reads/writes
   pin root directory handles and revalidate the visible root identity. Earlier native runs provide
   Linux, macOS, and partial GitHub-hosted Windows 2025 evidence, but the current `e9b8f52` Windows
   long-path scenario still requires the billing-blocked rerun. NTFS/ReFS qualification, SMB/UNC,
   other Windows versions, and independent security review remain open. `SECURITY.md` still lacks a
   usable private reporting channel.
3. **Declared MSRV verification.** The workspace declares Rust 1.85. Current-candidate locked root
   workspace check/test, schema/fixture drift checks, and fuzz workspace check/test run in the
   dedicated CI job. A passing job proves those commands for only that commit; it does not prove
   server-side required-check configuration or future-candidate compatibility.
4. **Performance qualification.** The local calibration above did not meet the warm `next` or
   `adapters check` goals. Keep those targets unchanged, separate host Git cost from Forge overhead,
   and obtain repeatable results on calibrated release runners and representative real repositories.
5. **Cross-platform evidence.** The five native CI jobs run locked root workspace check, strict
   Clippy, full tests, release-candidate assembly, and candidate execution on x86_64/aarch64 Linux
   musl, x86_64/aarch64 macOS, and x86_64 Windows MSVC. A passing matrix is native evidence for that
   exact GitHub-hosted environment, not universal filesystem, runner, TTY, UNC-share, or downstream
   distribution compatibility. The strict compatibility harness remains Unix-only by design and
   external writable UNC qualification remains opt-in.
6. **Independent CI and review.** A successful GitHub Actions run proves that the checked-in jobs
   executed for one commit. It does not prove that those checks are required by branch protection,
   that the workflow cannot be weakened by the candidate under review, or that maintainers reviewed
   and approved the result.
7. **Distribution and release.** Version selection and the local raw-binary/SBOM/manifest/checksum
   assembly plus rollback procedure are implemented as candidate-controlled checks. Native CI is
   evidence only for its exact commit and runner: independent musl static-link confirmation, macOS
   minimum-version behavior, Windows runtime dependencies, release asset name/case handling,
   distributable license/notice text, external provenance and signing, immutable GitHub publication,
   release/security/rollback ownership, OIDC identities, approvals, and withdrawal authority remain
   unproven, unassigned, or externally unauthorized.
   The local isolated clone is time-bounded but its copied Git object database is not byte-bounded;
   use a capacity-controlled builder and treat an interrupted clone as disposable temporary state.
   This implementation task did not authorize a tag, signature, attestation, upload, publication,
   or release.
8. **No self-authorization claim.** v0 remains ordinary dogfooding: candidate-controlled tests and
   the public N-1 harness are reviewable self-checks, not final authority. Held-out tests and the
   physically separate Authority Set are v0.3 requirements rather than v0 release blockers; they
   must exist before Forge can claim trusted self-hosting. Independent CI, review, release,
   signing, and promotion authority still cannot be inferred from this candidate's local results.

Do not weaken tests, alter release/signing/ownership/authority boundaries, or change a versioned
machine contract without the required authorization, migration, and ADR process.
