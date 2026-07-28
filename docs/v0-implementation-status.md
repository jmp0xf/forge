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
| Integration | Default-dry-run `init`, managed `AGENTS.md`/host adapters, adapter drift/sync, explicit make/just/task runners, and create-only GitHub CI generation |
| Navigation | `doctor`, deterministic read-only `next`, `explain`, schema/version/completion output |
| Local evidence | Receipt/Evidence v2 run/show/verify/export, dependency invalidation, immutable state, bounded retention, and v1 historical readers |
| In-repository hardening | 28 public fixtures, schema/golden/compatibility tests, dogfood fixed point, fuzz corpora, bounded mutation config, and opt-in large-repository benchmark |
| Local release candidates | Create-only `0.1.0-rc.1` five-target assembler, exact-commit isolated source binding, executable checks, CycloneDX SBOMs, release manifest, SHA-256 checksums, and explicit external authority/rollback gates |

Default `init` still does not generate a runner, CI, configuration, ADR, runbook, or ownership file.
Runner generation occurs only after an explicit choice and creates a project-native managed `verify`
target from already resolved required commands. `init --with-ci github` explicitly creates only a
missing `.github/workflows/verify.yml`; equivalent complete YAML is a no-op, while non-equivalent or
unknown existing content fails without writes and is never overwritten.

`improve`, `evolve`, model integration, external-attestation import, and external release orchestration remain outside
the v0 command surface. Repository-only `xtask` commands assemble and check local review candidates; they do not tag,
sign, attest, upload, publish, or authorize a release.

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
  anti-weakening decisions; and
- an ignored 100,000-file benchmark that reports one first-inventory observation, repeated
  uncached-inventory p50/p95, warm-command p95, and Git-plumbing p50/p95 without converting
  performance goals into platform-independent assertions.

The public fixture and N-1 harness are candidate-controlled self-checks. Specialized platform state
is constructed by integration tests and the harness currently uses reviewed Unix process-group
containment; it fails closed on Windows rather than pretending equivalent Job Object coverage.

## Current-candidate local verification

Against current code commit `655b42b` on macOS 26.5.2 arm64:

- the stable root format, check, `clippy -D warnings`, and isolated full test suite, plus the fuzz
  workspace format, check, `clippy -D warnings`, and full test suite, exited zero; schema drift
  checking, fixture regeneration (0 written, 105 unchanged), `forge version`, and the repository's
  zero-diff `init --dry-run --json` dogfood also exited zero;
- locked Rust 1.85 root workspace check/test and fuzz workspace check/test exited zero;
- the strict release fixture gate accounted for all 28 fixtures, ran all 27 declared native
  commands after install and uninstall, recorded four scenario-only fixtures as not applicable,
  and exited zero; and
- against the earlier code commit `7e9b559`, all four checked-in fuzz targets completed
  60-second `cargo-fuzz 0.13.2` campaigns with checked-in seeds, exited zero, and produced no crash
  artifacts. Cross-target checks with `-D warnings` also passed for `x86_64-apple-darwin`,
  `x86_64-unknown-linux-gnu`, and `x86_64-pc-windows-gnu`. The
  `aarch64-unknown-linux-musl` check stopped in the `blake3` C build because
  `aarch64-linux-musl-gcc` was unavailable; this is a builder-toolchain gap, not a successful
  target qualification.

One earlier root full-suite run executed concurrently with the complete MSRV suite and observed one
scheduling-sensitive total-command-timeout test failure. The exact test then passed three
consecutive isolated runs, and the isolated full root suite passed. This is retained as harness
concurrency evidence rather than treated as a waived failure.

## Current local calibration

On 2026-07-28, the ignored release benchmark completed against current code commit `655b42b` on
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

A bounded full `cargo-mutants 27.0.0` campaign against commit `7e9b559` tested 300 mutants in 88
minutes: 276 were caught, 24 were unviable, none were missed, and none timed out. The baseline build
and test suite passed, so no viable mutant survived this bounded current-candidate surface. The full
rerun included and caught the previously surviving deletion of the `risk/docs-only` arm in
`add_content_uncertainty`, confirming the regression test added by `e51837c` within the complete
campaign.

## Work still required before v0 release

The following boundaries are intentionally not inferred from local implementation or test assets:

1. **Current-candidate verification.** Every handoff must run the root and fuzz Cargo commands from
   `AGENTS.md`, schema checks, applicable fixtures, and targeted hardening campaigns, then report
   exact commands, exit codes, platform, tool versions, and remaining gaps. This document is not a
   substitute for that run ledger. Against commit `f6e5e97`, the strict exitability preflight first
   accounted for all 28 fixtures and 27 declared native commands, then exited 101 before fixture
   mutation because the ambient host lacked `just` and `task`; this confirmed that missing tools
   cannot be mistaken for a pass. The gate was then rerun with no global installation and a
   temporary `PATH` containing the official
   [`just 1.50.0`](https://github.com/casey/just/releases/tag/1.50.0) and
   [`task 3.51.1`](https://github.com/go-task/task/releases/tag/v3.51.1) macOS arm64 release binaries.
   Their archives matched the publishers' SHA-256 values
   `891262207663bff1aa422dbe799a76deae4064eaa445f14eb28aef7a388222cd` and
   `a0330f0df20dd1187e323f284a7f365c0ea1f2f271c1e154811e9fc4724bed13` respectively. The strict
   ledger then recorded all 27 declared commands as passed, four explicitly named scenario-only
   fixtures as not applicable, and exited zero. The same complete gate passed again against
   current code commit `655b42b`. This is one local qualification; every release
   candidate still needs the strict gate on its controlled, fully provisioned runner.
2. **Filesystem threat model and security review.** Repository writes and release-asset reads/writes
   now pin root directory handles and revalidate the visible root identity. Native adversarial tests
   and independent security review remain required; `SECURITY.md` still lacks a usable private
   reporting channel.
3. **Declared MSRV verification.** The workspace declares Rust 1.85. Current-candidate locked root
   workspace check/test and fuzz workspace check/test passed locally with the exact Rust 1.85
   toolchain. This is one macOS-host observation; independent CI enforcement, generated-asset
   behavior under the MSRV, and the native release target matrix remain release work.
4. **Performance qualification.** The local calibration above did not meet the warm `next` or
   `adapters check` goals. Keep those targets unchanged, separate host Git cost from Forge overhead,
   and obtain repeatable results on calibrated release runners and representative real repositories.
5. **Cross-platform evidence.** Host-side cross-target checks passed for
   `x86_64-apple-darwin`, `x86_64-unknown-linux-gnu`, and `x86_64-pc-windows-gnu`;
   `aarch64-unknown-linux-musl` remains blocked by the unavailable
   `aarch64-linux-musl-gcc` builder toolchain. These compile-only observations do not prove native
   Linux, macOS, or Windows E2E/process/path behavior. Windows Job Object, UNC/wide-path, case, ACL,
   native replacement behavior, and all five release-target native runs still require actual
   platform evidence.
6. **Independent CI and review.** A checked-in workflow is candidate-controlled configuration, not
   proof that required CI ran or that maintainers reviewed and approved the result.
7. **Distribution and release.** Version selection and the local raw-binary/SBOM/manifest/checksum
   assembly plus rollback procedure are implemented as candidate-controlled checks. Native builds,
   distributable license/notice text, external provenance and signing, immutable GitHub publication,
   release/security/rollback ownership, OIDC identities, approvals, and withdrawal authority remain
   unproven, unassigned, or externally unauthorized.
   The local isolated clone is time-bounded but its copied Git object database is not byte-bounded;
   use a capacity-controlled builder and treat an interrupted clone as disposable temporary state.
8. **No self-authorization claim.** v0 remains ordinary dogfooding: candidate-controlled tests and
   the public N-1 harness are reviewable self-checks, not final authority. Held-out tests and the
   physically separate Authority Set are v0.3 requirements rather than v0 release blockers; they
   must exist before Forge can claim trusted self-hosting. Independent CI, review, release,
   signing, and promotion authority still cannot be inferred from this candidate's local results.

Do not weaken tests, alter release/signing/ownership/authority boundaries, or change a versioned
machine contract without the required authorization, migration, and ADR process.
