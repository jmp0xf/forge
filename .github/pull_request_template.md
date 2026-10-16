## Change summary

<!-- Describe what this PR changes and why. Reference relevant issues, ADRs, or design decisions. -->

## Verification evidence

<!-- Document the commands run, their exact exit status, platform/tool versions, and any known gaps.
     Include local command results or link to CI runs. For changes affecting core behavior, include:
     - cargo test output with counts
     - cargo clippy results
     - fixture matrix results if applicable
     - Generated contract checks if schemas/fixtures changed
     
     Local receipts are observations, not CI/review/approval authority. -->

```bash
# Example verification commands and their results
RUSTUP_AUTO_INSTALL=0 cargo test --locked --workspace --no-fail-fast
# exit: 0, passed: X, failed: 0

RUSTUP_AUTO_INSTALL=0 cargo clippy --locked --workspace --all-targets -- -D warnings
# exit: 0, no warnings
```

## Safety boundary

<!-- Identify which boundaries this change approaches or crosses:
     - Does it modify tests, fixtures, CI, or baselines? (requires owner review per CODEOWNERS)
     - Does it change versioned machine contracts (schemas, exit codes, CLI surface)?
     - Does it alter evidence validity, risk classification, or authority boundaries?
     - Does it touch release, signing, or qualification paths?
     - Does it weaken assertions, skip tests, or relax policy?
     
     Changes to protected paths require independent approval. -->

## Risk level

<!-- Classify this change using repository risk tiers:
     - **low**: docs-only (not affecting commands/policy/safety)
     - **medium**: source changes, dependency updates, toolchain changes
     - **high**: public API changes, unsafe/cgo, test weakening, dependency graph changes
     - **critical**: CI/policy/CODEOWNERS changes, migrations, permission/auth changes, release/signing
     
     Risk determines required evidence and approval. See AGENTS.md for AI operating levels. -->

**Risk level:** <!-- low | medium | high | critical -->

## Remaining uncertainty

<!-- List known gaps, unverified assumptions, or areas requiring follow-up:
     - Platform coverage (tested only on Linux, not macOS/Windows)
     - Edge cases not covered by current fixtures
     - Behavioral changes without explicit N-1 compatibility check
     - Performance impact not measured
     - Missing test coverage for error paths
     
     Unknown should be explicit, not assumed covered. -->

## Rollback plan

<!-- Describe how to safely revert this change if problems are discovered:
     - Can it be reverted with `git revert` cleanly?
     - Does it require a migration or data cleanup?
     - Does it change persisted state, schemas, or external contracts?
     - Would rollback break newer changes that depend on it?
     
     If rollback is not clean, explain the necessary recovery steps. -->
