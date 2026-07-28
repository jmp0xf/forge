# Forge v0 release-candidate runbook

This runbook assembles reviewable local assets for `0.1.0-rc.1`. It does not grant release authority and does not
perform a tag, upload, signature, attestation, or GitHub Release mutation. The frozen contract and its trust boundary
are in [ADR-0029](adr/0029-publish-reviewable-v0-release-candidates.md).

## Fixed matrix

Build exactly one `forge` binary for each target:

- `x86_64-unknown-linux-musl`
- `aarch64-unknown-linux-musl`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`
- `x86_64-pc-windows-msvc`

The Linux artifacts must be static 64-bit ELF files without a `PT_INTERP` loader. The local structural check establishes
only that an ELF is static-compatible; the protected builder, external provenance, and native E2E must establish that
the named musl target really produced it. The macOS artifacts must be thin 64-bit `MH_EXECUTE` Mach-O files with a
nonempty file-backed executable segment and a file-backed `LC_MAIN`. The Windows artifact must be an executable,
non-DLL x86-64 PE32+ image whose entry point is file-backed by an executable section. Confirm the `LC_MAIN` assumption
with a real Rust output on each native macOS runner. These structural checks do not replace native-platform E2E.

## Build and stage

Every release command requires a clean, ordinary Git checkout. Forge binds the source worktree to its canonical path
and repeatedly compares `HEAD`, complete porcelain v2 status, the raw and semantic index, and `Cargo.lock`. Index
locks, split indexes, non-stage-zero entries, Gitlinks, symlinks, assume-unchanged, skip-worktree, sparse or unmerged
state, and tracked or untracked changes fail closed.

The command then clones the accepted commit into a private checkout with system/global Git configuration, hooks,
external object alternates, recursive submodules, and LFS smudging disabled. It verifies the object database, compares
the isolated index and lockfile with the accepted worktree, and hashes every checked-out regular file with
`git hash-object --no-filters` against its index blob. A `.gitattributes` conversion that changes a blob's bytes is
rejected rather than becoming a platform-dependent build input. The Git control marker is removed before Cargo runs,
so Cargo sees only the detached source tree; committed LFS pointer bytes remain pointers and are not hydrated.

Forge snapshots every isolated directory and regular file, including file bytes and platform permission/attribute
bits, before and after Cargo metadata and release work. Cargo metadata must resolve the exact isolated workspace root,
and every local package manifest and target source must be a real file inside that snapshot. Cargo configuration in an
ancestor outside the isolated source or in `CARGO_HOME`/the user Cargo home is rejected before and after each Cargo
invocation. A different worktree, external local path package, source change, or incomplete observation fails closed.
Git and Cargo run with closed stdin, bounded stdout/stderr, timeouts, and the shared cross-platform process-tree
boundary. Review the checkout, create a dedicated output directory outside it, and build the repository-only tool once:

```text
git status --porcelain=v2 --untracked-files=all --ignore-submodules=none
mkdir -p /absolute/path/to/forge-0.1.0-rc.1-dist
RUSTUP_AUTO_INSTALL=0 cargo build --locked --offline -p xtask
```

On Windows PowerShell, use the native path and environment syntax:

```text
git status --porcelain=v2 --untracked-files=all --ignore-submodules=none
New-Item -ItemType Directory -Force C:\forge-0.1.0-rc.1-dist
$env:RUSTUP_AUTO_INSTALL = "0"
cargo build --locked --offline -p xtask
```

On a runner with the exact target and linker already installed, build and stage one target. Keep each invocation on one
line so the same argument contract works in POSIX shells and PowerShell:

```text
target/debug/xtask release-build --target x86_64-unknown-linux-musl --output-dir /absolute/path/to/forge-0.1.0-rc.1-dist
```

```text
.\target\debug\xtask.exe release-build --target x86_64-pc-windows-msvc --output-dir C:\forge-0.1.0-rc.1-dist
```

Repeat on appropriate trusted runners for all five targets, transferring only the fixed named binary/SBOM pairs between
jobs. `release-build` has no arbitrary external-binary staging mode. It runs the locked, offline release build in a new
temporary Cargo target directory for that invocation; it does not reuse `target/forge-release-build` or another prior
build cache.

The nested Cargo process is offline and receives only the minimal toolchain environment plus explicit compiler,
wrapper, linker, SDK, and target controls needed by common Unix, macOS, and MSVC setups. Secret-like environment names
and registry tokens are not forwarded. External Cargo configuration is rejected, but the selected Cargo executable,
toolchain, wrappers, linkers, SDK, dependency cache, build scripts, and allowed environment values remain builder
inputs. These controls do not make the local build reproducible or authoritative. The protected builder must freeze
and attest them separately.

The output directory must already exist, resolve outside the source repository and its actual worktree-specific and
shared Git directories, and be a real directory rather than a symlink. An output below any of those boundaries is
rejected before any candidate write. Forge pins the
accepted directory through `RepositoryWriter`; candidate file reads and create-only writes remain relative to that
handle. It likewise pins the fresh temporary Cargo target root before the build and reads the resulting binary through
that handle without following symlinks. The candidate namespace is the fixed twelve names defined below. Other
directory entries are never manifest, checksum, or provenance inputs, but a dedicated empty directory is still
recommended. Never upload with a directory glob.

Staging refuses unknown targets, mismatched executable structures, a directory that was already finalized, and a
same-name asset with different bytes. Repeating the same target with exactly the same binary and derived SBOM is an
idempotent no-op. Each binary/SBOM pair and manifest/checksum pair is fully preflighted before either missing sibling is
created, so a known collision does not leave a new partial pair. It never overwrites a different file. Each target-bound
CycloneDX 1.6 SBOM selects exactly the workspace-member `forge-cli` release graph, includes build dependencies but
excludes dev-only dependencies, and binds:

- the exact Git source commit;
- the `Cargo.lock` SHA-256;
- the binary SHA-256 and byte length;
- the exact target triple.

A selected local package with no registry source must be an exact workspace member; external path dependencies are
rejected because their source bytes are not covered by this Git snapshot and lockfile claim.

The SBOM deliberately has no timestamp or host path.

The pair is not a multi-file transaction. If another process wins a create after preflight, Forge rereads that one
name: identical bytes are accepted and different bytes fail without replacement. A concurrent failure can therefore
leave a sibling that this invocation already created successfully; inspect the error and rerun only after verifying the
fixed names and bytes.

### Failure residue and local limits

A failure before the first candidate write does not create an asset. Binary/SBOM and manifest/checksum pairs are
preflighted before their first write, but the complete command is not a transaction: a concurrent create or a final
source/root revalidation failure can return nonzero after one or more create-only files were safely written. A nonzero
command therefore never accepts the directory as a candidate. Do not overwrite or guess which files are valid; inspect
the reported fixed names, move the directory aside or choose a new empty output directory, rerun the required build or
finalize step, and require `release-check` to pass before external review.

The isolated source tree is bounded to 200,000 entries, 256 MiB per file, and 4 GiB total visible file bytes. Those
bounds apply after Git has cloned its object database. The local clone and full `git fsck` are time-bounded but the
copied history/object database is not byte-bounded, so release builders must provide disposable temporary storage with
an independent capacity limit. Forge is not an OS sandbox: another process running as the same principal can race
between checks, and ACLs, extended attributes, ownership, host toolchain behavior, and network behavior inside invoked
build tools are not part of the local source snapshot. Treat the temporary checkout and target directory as
disposable after interruption or failure.

## Finalize and check

After all five binary/SBOM pairs are in one directory:

```text
target/debug/xtask release-finalize --output-dir /absolute/path/to/forge-0.1.0-rc.1-dist
target/debug/xtask release-check --output-dir /absolute/path/to/forge-0.1.0-rc.1-dist
```

On Windows:

```text
.\target\debug\xtask.exe release-finalize --output-dir C:\forge-0.1.0-rc.1-dist
.\target\debug\xtask.exe release-check --output-dir C:\forge-0.1.0-rc.1-dist
```

Finalization requires all ten fixed staged files and writes, without replacing different bytes:

- `release-manifest.json`, a `forge.release-manifest/v1` document with target, type, byte length, and SHA-256 for each
  binary and SBOM;
- `SHA256SUMS`, covering those ten files and `release-manifest.json` in lexical order.

The v1 compatibility reader ignores future optional object fields and maps future enum values to a non-authorizing
`unknown` state. That makes same-major documents readable; it does not make them current candidates.
`release-finalize` and `release-check` independently rebuild the canonical manifest and require exact bytes.

`release-check` revalidates the fixed twelve-file candidate namespace, executable structures, source-bound locked
dependency graphs, byte-for-byte SBOMs, manifest, and all SHA-256 values. A successful result means only that the
candidate-controlled local assets are internally consistent. It does not claim that unrelated directory entries are
release assets.

The exact external-provenance subject set is:

- five fixed target binary names;
- the five matching `.cdx.json` names;
- `release-manifest.json`;
- `SHA256SUMS`.

The external builder must independently bind the exact name, byte length, and SHA-256 of all twelve finalized files.
The manifest's `provenance.subjects` array freezes those names but does not self-assert their external digests. Upload
those twelve explicit paths; do not use `*`, recursive directory upload, or filesystem enumeration as authority.

## External release gate

Before any public release, the externally controlled Authority Set must provide and preserve evidence for all of the
following:

1. Required Cargo gates and native/basic E2E passed on each platform tier, including Windows path/process behavior,
   exact on-disk asset-name spelling on case-insensitive filesystems, the declared macOS baseline, and both static musl
   architectures. Handle-relative reads on Windows do not by themselves prove the original directory-entry casing.
2. An independently protected builder generated SLSA provenance v1 whose subjects are exactly all twelve finalized
   local assets, including `release-manifest.json` and `SHA256SUMS`.
3. The provenance/signature used Sigstore keyless OIDC and matched a frozen issuer, subject, protected GitHub
   Environment, approval rule, and transparency-log policy outside the candidate write set.
4. Named release approver, security approver, rollback owner, security contact, and withdrawal permissions were filled
   in and exercised. They are intentionally unassigned in the local manifest today.
5. The protected builder froze and recorded the compiler, wrappers, linker, dependency cache and relevant environment;
   local source/lock/binary binding alone does not prove those inputs.
6. Owner/legal confirmed distributable license and notice text. This repository currently declares
   `MIT OR Apache-2.0` without a checked-in license text; if compliance requires another asset, create a new ADR and
   candidate rather than changing this twelve-file RC in place.
7. The exact reviewed assets were attached to a new immutable GitHub Release; no file from an existing version was
   replaced.

Do not treat `release-check`, local Receipts, candidate CI, a draft GitHub Release, or a candidate-generated hash as any
of those external facts.

## Install a reviewed asset

Verify the downloaded file against independently verified `SHA256SUMS` and provenance. On Unix, give the raw binary an
executable bit and move it to a directory already selected by the user:

```text
chmod +x forge-0.1.0-rc.1-<TRIPLE>
./forge-0.1.0-rc.1-<TRIPLE> version
```

The Windows asset already ends in `.exe`. Installation does not run `forge init`, install project dependencies, or
modify a repository.

## Retention and rollback

Retain the current published release and its immediate predecessor, including their original assets, provenance, and
signatures. Never rebuild or resign an old version in place.

For an incident, stop distribution or mark the affected GitHub Release withdrawn, restore documentation to the
independently verified N−1 assets, and publish a new reviewed candidate for the fix. `0.1.0-rc.1` has no published N−1;
its only honest rollback is withdrawal and halted distribution until a new candidate clears the external gate.
