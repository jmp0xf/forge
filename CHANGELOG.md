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

### Changed

### Removed

### Security

- Generic Windows execution rejects `.bat` and `.cmd` programs because Rust would otherwise invoke `cmd.exe`
  implicitly.
- Git and subprocess execution disable interactive prompts, pagers, trace controls, and optional Git locks at the
  runtime boundary.
- Repository traversal and writes reject symlink escapes; runtime state uses private permissions on Unix.
