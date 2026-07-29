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
| Runtime | Bounded Git, native-path, filesystem and synchronous process boundaries; timeout/cancellation and native process-tree termination; handle-confined repository writes; owner-private, capability-confined immutable state scan/GC/recovery; and fail-closed Windows directory-swap handling |
| Detection | Strict `forge.toml`, repository/runner/Rust/Go/mixed discovery, deterministic command resolution, risk and policy provenance |
| Integration | Default-dry-run `init`, managed `AGENTS.md`/host adapters, adapter drift/sync, explicit make/just/task runners, and create-only GitHub CI generation |
| Navigation | `doctor`, deterministic read-only `next`, `explain`, schema/version/completion output |
| Local evidence | Receipt/Evidence v2 run/show/verify/export, content-free dual-stream diagnostic summaries, dependency invalidation with typed-unknown fact preservation, immutable state, bounded retention, and v1 historical readers |
| In-repository hardening | Direct project-native CI gates plus a bounded unified verifier, an exact 20-invariant executable-test/CI/external-required marker ledger, 28 public fixtures, schema/golden/compatibility tests, dogfood fixed point, fuzz corpora, bounded mutation config, and opt-in large-repository benchmark |
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

ADRs 0035 and 0036 extend capability confinement to immutable Receipt/Evidence/log state. GC scans,
reopens, quarantines, recovers, and deletes through pinned worktree/class-directory handles. Current
same-directory quarantine files are recoverable under the worktree lock; legacy v1 quarantine files
and the unreleased directory-shaped residue fail closed and preserve all bytes instead of guessing a
migration. ADR-0038 fixes the v0 production boundary: arbitrary project stdout/stderr content is not
persisted, current `log_refs` are empty, and the existing log-store primitive is reserved for a future
typed producer that has already enforced its content policy.

ADR-0039 separates a current Receipt's validity projection from the stronger proving predicate.
An explicit typed unknown dependency now affects only its actual validity axis; known dependency and
mutability facts remain visible, while the Receipt still cannot satisfy Evidence or bind as valid.
Unknown command semantics and future/opaque contract content remain wholly non-proving. A current
typed infrastructure failure may affect local state, but a semantically non-supporting Receipt that
otherwise looks passing falls back to the opaque non-proving representation rather than becoming a
valid or passing newest Receipt.

## Receipt and Evidence v2

ADRs 0019-0026, 0032, and 0039 resolve and extend the earlier M6 decisions:

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
- Receipt validity projection uses `forge.receipt-validity/v2`: explicit typed unknown dependencies
  remain accurately projectable but never proving. Receipt/Evidence schemas and identities remain
  unchanged; `forge.evidence-behavior/v8` makes v7 receipts stale rather than silently applying the
  new reader behavior to them.
- Detected Rust projects add both generic and `custom:rust-*` coverage expectations. Missing
  expectations are projected as gaps after Receipt evaluation, while policy-driven local
  sufficiency remains unchanged; `cargo check --all-targets` does not claim that
  feature-gated examples or benches were compiled.

`evidence run` validates the selected command chain, executes it as `program + argv`, records bounded
observations, and persists an immutable worktree-local Receipt. `show` and `verify` reopen existing
state read-only and recompute current applicability from a stable detection/scope pair; neither
creates Forge directories, locks, or cache entries, though the host filesystem may still update
host-managed access times. `export` performs the same recomputation and explicitly
persists only the canonical Evidence object it emits.

This repository's resolved `verify` command is `cargo run --locked -p xtask -- verify`. The v0
toolchain classifier deliberately does not infer nested toolchains through `cargo run`, so that
command records an explicit unknown toolchain dependency and remains observation-only. ADR-0039
makes the resulting reason precise; it does not promote that unknown dependency to proving.

Receipt, Evidence, and optional log objects use content-derived names, atomic no-clobber writes,
worktree isolation, reference-aware retention, bounded streaming scans, owner-private permissions,
and fail-closed malformed/future-state handling. Each Receipt is limited to 4 MiB and each Evidence
object to 8 MiB. One snapshot is limited to 4,096 Receipts, 4,096 Evidence objects, 4,096 logs,
131,072 references, and 512 MiB of scanned bytes; recovery verification has its own 512 MiB budget
and reopens/streams objects in sequence instead of retaining every object or descriptor. Retained
state is capped at 256 MiB. v0 Receipt/Evidence/log production writers retain no stdout/stderr
content, environment values, secrets, source files, or private reasoning. Observed-output digests
and byte counts still reveal equality and size and therefore are content-free, not zero-information
or a claim of redaction.

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
- a direct locked root/fuzz contract job, read-only schema/fixture drift job, and supplemental
  `unified-verify` matrix that runs the same bounded `xtask verify` entry point on Ubuntu and
  Windows. MSRV, five native targets, strict fixtures, fuzz campaigns, and opt-in mutation remain
  separate qualification jobs. The direct root/fuzz project-contract gate does not use an installed
  Forge binary as its orchestrator; supplemental qualification jobs may build and execute Forge.

The public fixture and N-1 harness are candidate-controlled self-checks. The two-binary N-1 harness
remains Unix-only; portable runtime tests separately exercise the platform process-tree backend,
including Windows Job Object behavior when run on Windows. Cross-compilation is not runtime proof.

## Current-candidate verification

### Local verification

On 2026-07-30, the complete executable gate ran against the exact code/CI tree subsequently
committed as `f7c1adf`; the only concurrent uncommitted change was this status-only handoff. On
macOS 26.5.2 arm64 with Rust/Cargo 1.96.0 and Git 2.51.0, the project-owned normal local gate
`env RUSTUP_AUTO_INSTALL=0 cargo run --locked -p xtask -- verify` exited 0. It checked 13 checked-in
schemas and 28 deterministic fixtures/105 generated files without writing, then passed all eight
required child steps and the final advisory fuzz Clippy step:

| Child step | Result | Observed duration |
|---|---|---:|
| root format check | passed | 603 ms |
| root workspace check | passed | 86,346 ms |
| root strict Clippy | passed | 12,322 ms |
| root workspace tests | passed | 308,176 ms |
| fuzz format check | passed | 674 ms |
| fuzz workspace check | passed | 769 ms |
| fuzz workspace tests | passed | 42 ms |
| bootstrap `forge version` | passed | 52,477 ms |
| fuzz Clippy (advisory) | passed | 226 ms |

Before the unified gate, the same code tree separately passed all 163 `forge-cli` binary unit tests,
the typed-unknown run/show/verify round-trip, the v8 behavior fixed vector, strict `forge-cli`
Clippy, and `git diff --check`. The workspace gate then reran the complete root test and strict lint
surfaces, including the architecture-invariant ledger and state tests. These checks do not qualify a
different OS, target, filesystem, CI control plane, or release authority. Rust 1.85.0 and stable
fixture checks previously passed at `fc7fc49`, but that older result does not qualify `f7c1adf`.

### GitHub Actions

Pull-request run [`30469270759`](https://github.com/jmp0xf/forge/actions/runs/30469270759) targeted
`fc7fc49` after the CI update. For each of its 16 job records, the API returned `steps = null` and
`logs_url = null`; GitHub marked all 15 non-optional jobs failed and skipped the opt-in mutation job.
Therefore no checkout, build, test, Linux/Windows unified verifier, MSRV, native target, strict
fixture, or fuzz command executed. This is an external pre-run failure, not a code-test failure and
not qualification evidence. The connector does not expose the run-level UI annotation; the
zero-step signature matches earlier run `30382132956`, whose UI explicitly reported account
payment/spending-limit rejection, but that cause remains an inference for the current run until the
repository owner confirms it or a fresh run creates real steps and logs.

Historical runs `30374770619`, `30377585092`, and `30379720907` remain useful regression evidence:
they drove the Windows rename/topology and long-path fixture corrections and last confirmed all 117
then-current Windows runtime tests. They predate the immutable-state confinement and unified verifier
changes and cannot qualify `fc7fc49` or a later candidate.

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

1. **Current-candidate verification.** Every handoff must rerun the project-owned normal local gate
   and applicable targeted campaigns, then report exact commands, exits, platform/tool versions,
   and gaps. The current macOS ledger is above; it is not evidence for a later commit. The strict CI
   job additionally provisions fixed `just`, `task`, and Go versions and fails closed if any
   fixture-native command is unavailable. No current external job reached that gate.
2. **Filesystem threat model and security review.** Repository/release writes and immutable state
   mutation now use separate handle-confined capabilities with fail-closed identity, ACL, scan,
   recovery, and budget checks. They are not a malicious-same-principal sandbox or a multi-file
   transaction. The current candidate still needs real Windows NTFS runtime evidence; ReFS,
   SMB/UNC, other Windows versions, and independent security review remain open. `SECURITY.md`
   still lacks a usable private reporting channel.
3. **Declared MSRV verification.** The workspace declares Rust 1.85. The current candidate passed
   the read-only fixture check under local Rust 1.85.0, but its locked root check/test,
   schema/fixture drift set, and fuzz check/test did not execute in CI. A future passing job proves
   those commands for only that exact commit, not required-check configuration or future
   compatibility.
4. **Performance qualification.** The local calibration above did not meet the warm `next` or
   `adapters check` goals. Keep those targets unchanged, separate host Git cost from Forge overhead,
   and obtain repeatable results on calibrated release runners and representative real repositories.
5. **Cross-platform evidence.** Two unified-verifier jobs are configured to exercise Linux and
   Windows orchestration; five native jobs cover locked root check, strict Clippy, tests,
   release-candidate assembly, and execution on x86_64/aarch64 Linux musl, x86_64/aarch64 macOS,
   and x86_64 Windows MSVC. None ran for the current candidate. The local aarch64-musl attempt could
   not link because
   `aarch64-linux-musl-gcc` is unavailable, so it is not a pass. A future green matrix remains
   evidence only for its exact runner/filesystem, not universal TTY, UNC, downstream, or platform
   compatibility; the two-binary compatibility harness remains Unix-only and writable UNC
   qualification remains opt-in.
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
