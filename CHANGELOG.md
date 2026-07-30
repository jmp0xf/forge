# Changelog

All notable changes will be documented here.

## [Unreleased]

### Added

- Pre-implementation repository skeleton.
- Accepted design proposal and initial ADR set.
- M0 typed identifiers, lossless wire paths, structured diagnostics, stable exit codes, and versioned JSON envelopes.
- The complete v0 clap command surface, including working `version`, `schema`, and `completions` commands.
- Checked-in JSON Schemas plus deterministic `schema-export` and drift-checking `check-schemas` xtasks.
- M1 typed Git porcelain-v2 and `ls-files -z` access with SHA-1/SHA-256, unborn, linked-worktree, native-path, and
  fuzz fixtures.
- Git-authoritative, ignore-aware bounded inventory that never hides tracked files because of later ignore rules.
- Repository-confined atomic files, per-worktree private state and locks, and content-addressed shared-cache layout.
- Synchronous argv-only process execution with bounded output, anonymous private spooling, timeout and Ctrl-C
  cancellation, and process-tree cleanup.
- M2 deterministic project-model detection: strict optional `forge.toml`, standard runners and scripts, immutable
  HEAD policy comparison, risk provenance, and a content-addressed inventory cache with live index confirmation.
- M3 Rust, Go, mixed-workspace, dependency-edge, toolchain, offline-probe, and command-resolution providers.
- M4 dry-run-first `init`, transactional managed-block application, private adoption manifests, explicit
  make/just/task runner generation, create-only GitHub Actions generation, adapter drift inspection, and adapter
  synchronization.
- M5 `explain`, fixed-registry `doctor`, and deterministic `next`, including environment blockers, exact changed
  paths, manifests, named tests, dependency edges, CODEOWNERS matches, and bounded exact document matches.
- M6 Receipt and Evidence v2 execution, validation, immutable storage, bounded logs and retention, read-only
  inspection, export, dependency invalidation, and historical non-proving v1 readers.
- M7 fixture generation, JSON instance validation, byte-level human-output goldens, a public two-binary compatibility
  harness serving as the N-1 skeleton, `init --dry-run --json` dogfood fixed-point checks, four fuzz targets, mutation
  configuration, and an opt-in 100,000-file benchmark, without claiming a released-predecessor comparison.
- Machine-readable doctor skip reasons and provenance/confidence metadata for every selected `next` context path.
- A create-only local `0.1.0-rc.2` release assembler for the five supported targets, with exact-commit isolated source
  binding, executable-format checks, deterministic target-bound CycloneDX 1.6 SBOMs with license expressions, a
  source-bound checked-in third-party license corpus, a v2 artifact manifest, SHA-256 checksums, and an explicit
  external SLSA/Sigstore/ownership/rollback gate.

### Changed

- Receipt applicability now binds the immutable HEAD comparison base, before/after scope, ordered command specs,
  toolchains, allowlisted environment, effective policy, and Forge behavior version.
- `--timeout` now applies one fixed wall-clock budget to the complete command; later Git, detection, scope, state,
  and child-process stages can only consume the remaining time.
- Rust Evidence now lists provider-qualified coverage and missing build, examples/benches compile, cross-target, and
  performance dimensions without allowing Go coverage in a mixed repository to stand in for Rust.
- `help`, `version`, and commandless JSON requests now preserve the single-envelope JSON contract.
- Read-only doctor checks distinguish proven failure, bounded uncertainty, user-requested skips, platform limits,
  and facts that require hosting or other external authority.
- Windows generated-runner support is explicit: Task is supported and Make/Just fail with a typed recovery
  diagnostic instead of producing platform-incompatible output.
- ADR-0041 supersedes the unpublished rc.1 contract: the fixed release set is now 13 files, manifest v2 records 11
  artifacts and 13 provenance subjects, and final authority is split across isolated build, finalize, and protected
  attestation domains in the external Authority repository.

### Removed

- The unpublished `0.1.0-rc.1` candidate path; no rc.1 tag, Release, signature, or public asset is created.

### Security

- Generic Windows execution rejects `.bat` and `.cmd` programs because Rust would otherwise invoke `cmd.exe`
  implicitly.
- Git and subprocess execution disable interactive prompts, pagers, trace controls, and optional Git locks at the
  runtime boundary.
- Repository traversal and writes reject symlink escapes; runtime state uses private permissions on Unix.
- Required Rust and Go probes request offline/local toolchain behavior, and executable availability checks do not
  run repository-owned code.
- Managed adapter planning rechecks target type, complete preimages, repository identity, work state, and the full
  deterministic plan immediately before authorized writes.
