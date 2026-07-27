# Fixture repositories

Fixtures are public regression material, not the external held-out authority set used by trusted self-hosting. The
required v0 matrix is specified in `docs/design-proposal.md` and is fully represented here.

The checked-in boundary is explicit:

- `definitions/manifest-v1.json` is the versioned source manifest. It declares every fixture, every materialized file,
  and project-native commands as `program + args + cwd`; the generator never executes those commands.
- `definitions/projects/` contains the reviewable source bytes. Undeclared files and symlinks fail generation.
- `generated/` is the only materialization destination. Its `manifest-v1.json` binds the exact source-manifest bytes and
  every generated file with BLAKE3 identities. Files not owned by the current manifest are left unchanged.

All 28 fixture IDs required by the accepted design are present. Language fixtures declare independently runnable native
commands. Scenarios whose defining condition cannot be represented by portable checked-in bytes (for example a dirty
index, linked worktrees, a non-UTF-8 path, a symlink, a process tree, or 100,000 files) provide only deterministic seed
bytes here; their tests construct the special state inside a temporary directory.

Regenerate with:

```text
cargo run -p xtask -- generate-fixtures
```

Generation performs no network access or tool installation. All paths are validated before the first write, symlinks
are rejected, project files are written in lexical order, and the generated root manifest is written last as a
completion record. Running the command again with unchanged definitions performs zero writes.

Verify fixture generation and behavior with:

```text
cargo run -p xtask -- generate-fixtures
cargo test -p xtask --test fixture_projects
cargo test -p forge-cli --test fixture_matrix
```

`fixture_projects` runs each declared project-native command when that command's tool is available, with isolated Cargo
and Go state; unavailable optional tools are skipped, not treated as proof. `fixture_matrix` constructs non-portable Git
and process states in temporary repositories and checks the v0 safety, idempotency, isolation, bounded-output, cache,
uninstallability, and malicious-input scenarios. Neither test installs tools or uses a network to fill missing
dependencies.

The large-repository performance case is ignored by default because it commits 100,000 files. Run it explicitly when
collecting performance evidence:

```text
cargo test --release -p forge-cli --test fixture_matrix large_repository_v0_latency_benchmark \
  -- --ignored --exact --nocapture
```

It refuses a debug build and reports first inventory, cold-inventory `forge` peak RSS on macOS/Linux, and warm
`version`, `next`, `adapters check`, and `doctor` p95 samples. It also reports warm p50/p95 and stable output sizes for
Git status, worktree/index dirtiness checks, untracked enumeration, and index hashing. The RSS sample directly wraps
the release `forge` process, excluding the Cargo test driver and fixture materialization. The design's figures are
startup goals, not portable correctness assertions, so review the measurements and record the host rather than
treating test completion as a performance pass.

For follow-up profiling against the exact materialized repository, set
`FORGE_RETAIN_LARGE_REPOSITORY_FIXTURE=1`; the benchmark prints the retained temporary root. Remove it manually after
the investigation so the opt-in diagnostic does not silently delete evidence another process is still inspecting.

Compare an explicit known-good binary with a candidate over these public fixtures and their public schemas with:

```text
cargo run -p xtask -- diff-plans --baseline /path/to/forge-n-minus-1 --candidate /path/to/forge-candidate
```

The harness rebuilds each side in an isolated temporary repository at the same absolute path, runs the default JSON
`init` dry-run, and compares exit status, schema, diagnostics, plan, and all remaining envelope fields except the root
`tool_version` string value. It also compares supported Schema sets and every Schema document shared by both binaries.
Exit `1` is a reviewable behavior difference; exit `2` is an unmet execution environment; exit `64` is invalid harness
usage; and exit `70` is a harness or checked-in fixture invariant failure. This is a candidate-repository public
self-check, not the physically separate authority required for release approval. The v0 skeleton uses Unix process
groups to terminate subject descendants and currently fails closed with exit `2` on Windows rather than running without
reviewed Job Object containment. Specialized fixture states that cannot be encoded as checked-in bytes remain covered by
their dedicated matrix tests; this harness compares their deterministic seed repositories.

Passing these public checks does not prove independent CI, cross-platform coverage, release/signing readiness, or the
physically separate held-out authority required by the accepted design.
