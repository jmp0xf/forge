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
| Local evidence | Receipt/Evidence v2 run/show/verify/export, content-free dual-stream diagnostic summaries, dependency invalidation with typed-unknown fact preservation and fail-closed handling of unbound Cargo/Go configuration, immutable state, bounded retention, and v1 historical readers |
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

ADR-0040 closes an external configuration invalidation gap without reading private configuration
content. Cargo commands remain environment-known only when their cwd-to-root and Cargo-home
configuration discovery chain is provably empty and argv has no explicit `--config`. Forge-native
Go commands remain environment-known only for the isolated single-module defaults; explicit Go and
go.work commands are typed environment-unknown in v0. These commands still execute and preserve
their other facts, but an unknown environment cannot satisfy Evidence.

Windows Git execution has a narrower explicit path boundary than Forge's internal native-path
representation. Every Git launch validates its canonical working directory. Its effective ordinary
drive-letter or UNC spelling must contain fewer than 260 UTF-16 code units; verbatim disk and UNC
forms are measured as their ordinary projection, while generic-verbatim and device namespaces fail
closed. Invoking Forge at a qualifying short repository root still permits tracked Unicode
descendants beyond that limit. This does not claim arbitrary long-root support, and writable UNC
qualification remains opt-in and unrun.

Windows release-candidate assembly discovers Visual Studio from a canonical installation identity,
then gives external MSVC tools only a revalidated ordinary drive spelling below the legacy path
limit. The installation root must re-canonicalize to the same identity through an ordinary drive
spelling below 260 UTF-16 units. The selected tool and Visual-Studio-root-derived `PATH`, `LIB`, and
`INCLUDE` entries must be ordinary drive-absolute, traversal-free, NUL-free, and below that limit;
the exact inherited suffix and derived non-Visual-Studio SDK entries remain compatible. UNC,
device, generic-verbatim, or overlong installation roots, and unsafe Visual-Studio-owned
descendants, fail closed. A standard hosted runner can exercise this boundary but cannot qualify
every supported or future Visual Studio layout.

Dropping a file-backed `StateLock` attempts `fs2::FileExt::unlock` before its descriptor is closed;
because `Drop` cannot report failure, descriptor close remains the fallback. The Unix regression
keeps a duplicated descriptor for the same open-file description alive and requires immediate
reacquisition after guard destruction, exercising the lifetime mechanism also inherited across
`fork` without claiming a forked-child integration test.

## Receipt and Evidence v2

ADRs 0019-0026, 0032, 0039, and 0040 resolve and extend the earlier M6 decisions:

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
- Project-command environment acquisition uses
  `forge.project-command-environment-acquisition/v1`. Standard Cargo configuration or incomplete
  Go isolation becomes typed environment unknown without reading configuration content. Schemas,
  identities, canonical JSON, toolchain probes, and validity v2 remain unchanged;
  `forge.evidence-behavior/v9` makes v8 receipts stale instead of applying the stronger acquisition
  rule retroactively.
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

The executable and workflow qualification below is bound to commit
`5c92a012d3da83016a9214f7e184c5023b07e926`. Before the external run, the focused macOS 26.5.2
arm64 recheck used Rust/Cargo 1.96.0 and Git 2.51.0 and produced these exit-0 observations:

- `cargo test --locked -p xtask --no-fail-fast` passed 82 unit tests and every xtask integration
  suite, including release-candidate environment construction;
- strict host, `x86_64-pc-windows-gnu`, and `x86_64-pc-windows-msvc` xtask Clippy checks passed;
- `cargo +1.85.0 check --locked -p xtask --all-targets` passed the declared MSRV surface;
- the runtime state suite passed with the explicit-unlock regression, and formatting plus
  `git diff --check` passed.

These checks targeted the Windows fixes without treating cross-compilation as runtime proof. The
documentation-only readiness follow-up does not change executable, workflow, fixture,
configuration, or versioned machine-contract behavior. Its final full local gate is recorded in the
PR handoff because a document cannot bind evidence to its own not-yet-created commit.

### GitHub Actions

Pull-request run [`30520650330`](https://github.com/jmp0xf/forge/actions/runs/30520650330),
attempt 1, reported head SHA `5c92a012d3da83016a9214f7e184c5023b07e926` and succeeded from
2026-07-30 06:46:24Z through 07:08:09Z. The debug log records that GitHub checked out the synthetic
PR merge ref at `cd9dff3caeede4b6cb4eb2235effc8974895f8d3`. All 15 non-mutation jobs
configured for pull requests succeeded. The opt-in performance step and bounded mutation job were
skipped because the pull-request event did not request those campaigns.

| Qualification surface | Job IDs | Result |
|---|---|---|
| Unified project verifier, Ubuntu and Windows | `90800017536`, `90800017581` | passed |
| Direct root and fuzz contract | `90800017591` | passed |
| Rust 1.85 MSRV | `90800017559` | passed |
| Five native targets | `90800017614`, `90800017633`, `90800017624`, `90800017626`, `90800017729` | passed |
| Strict fixture exitability | `90800017596` | passed |
| Critical fuzz campaigns | `90800017595` | passed |
| Schema and generated drift | `90800017599` | passed |
| Host adapters | `90800017562` | passed |
| Repository dogfood fixed point | `90800017619` | passed |
| Candidate authority boundary | `90800017555` | passed |

The Windows unified job passed 13 schemas, 28 fixtures, all eight required verifier steps, and the
advisory fuzz lint. Its fuzz workspace check passed, closing the earlier hosted MSVC `<cassert>`
failure. The native Windows job passed locked check, strict Clippy, all workspace tests,
release-candidate assembly, and execution of the resulting `forge 0.1.0-rc.1` binary. This is
candidate-controlled evidence for that run, merge ref, runner image, and observed toolchain; it is
not proof of required-check configuration, independent review, signing, promotion, or release
authority.

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

1. **Current-candidate verification.** The focused local checks and exact code/CI run are recorded
   above. Run `30520650330` executed all 15 non-mutation jobs configured for pull requests
   successfully for head commit `5c92a01` through its then-current PR merge ref; the opt-in
   performance step and mutation job were skipped because the pull-request event requested neither
   campaign. The strict fixture job provisioned pinned Go, `just`, and `task` versions and passed
   every declared project-native command after fixture installation and uninstall. This evidence
   is commit-, merge-ref-, and runner-bound. The final status-only follow-up does not change the
   qualified executable/CI tree, but its own full local gate and CI run belong in the PR handoff.
   Any later executable, workflow, fixture, schema, configuration, or machine-contract change
   requires fresh qualification.
2. **Filesystem threat model and security review.** Repository/release writes and immutable state
   mutation use separate handle-confined capabilities with fail-closed identity, ACL, scan,
   recovery, and resource-bound checks. They are not a malicious-same-principal sandbox or a
   multi-file transaction. The passing `windows-2025` jobs provide one hosted native Windows run,
   but the workflow does not separately assert NTFS, ReFS, SMB, or UNC semantics. Hermetic tests
   cover a qualifying short Git-launchable working directory with a tracked Unicode descendant
   beyond the classic `MAX_PATH` limit, plus typed no-write rejection of an overlong Git working
   directory before Git is spawned. They do not provide arbitrary long-root support; device and
   generic-verbatim repository roots are deliberately rejected rather than treated as supported.
   The opt-in writable UNC test did not run; ReFS, SMB/UNC, nonstandard or overlong Visual Studio
   installations, other Windows versions/configurations, and independent security review remain
   unqualified. `SECURITY.md` still lacks a usable private reporting channel.
3. **Declared MSRV verification.** The workspace declares Rust 1.85. The current candidate passed
   the locked root workspace check and tests, schema and fixture drift checks, and fuzz workspace
   check and tests under Rust 1.85.0 in job `90800017559`. That job qualifies only those commands
   on its Ubuntu runner; the five native-target jobs use stable Rust, so Rust 1.85 support across
   every native target, downstream feature combination, or future dependency resolution is not
   inferred.
4. **Performance qualification.** The local calibration above did not meet the warm `next` or
   `adapters check` goals. Keep those targets unchanged, separate host Git cost from Forge overhead,
   and obtain repeatable results on calibrated release runners and representative real repositories.
5. **Cross-platform evidence.** Run `30520650330` passed both unified-verifier jobs on
   `ubuntu-24.04` and `windows-2025` and all five native jobs on x86_64/aarch64 Linux musl,
   x86_64/aarch64 macOS, and x86_64 Windows MSVC. The Windows unified job ran the complete
   project-owned verifier, including the root and fuzz workspaces under the materialized MSVC
   environment; the native Windows job passed locked check, strict Clippy, tests,
   release-candidate assembly, and execution. Each result qualifies only the reported head and PR
   merge ref on that hosted runner and its observed filesystem/toolchain layout. It does not
   establish universal TTY, writable UNC, ReFS, SMB, downstream, or other platform compatibility;
   the two-binary compatibility harness remains Unix-only and writable UNC qualification remains
   opt-in and unrun.
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
9. **External tool configuration closure.** v0 fails closed instead of reading potentially private
   Cargo configuration or claiming that indirect wrapper/linker dependencies are bound. Cargo
   repositories with standard config files, explicit Go commands, and Go workspaces therefore need
   a future privacy-safe parser, indirect-tool binding, and before/after stability qualification
   before their Receipts can become proving. This limitation reduces evidence reuse; it does not
   weaken command execution or promote unknown facts.

Do not weaken tests, alter release/signing/ownership/authority boundaries, or change a versioned
machine contract without the required authorization, migration, and ADR process.
