# Forge v0 release-candidate runbook

This runbook assembles reviewable local assets for `0.1.0-rc.2`. It does not grant release authority and does not
perform a tag, upload, signature, attestation, or GitHub Release mutation. `0.1.0-rc.1` was never tagged or published
and is not a distributable predecessor. The current contract and its trust boundary are in
[ADR-0041](adr/0041-publish-license-complete-rc2-through-external-authority.md), which supersedes ADR-0029.
The optional private build-input diagnostic and its non-authority boundary are fixed by
[ADR-0043](adr/0043-record-private-release-build-input-diagnostics.md).

The Forge candidate repository must not contain a release or signing workflow. The physically separate Authority Set
is the independent public
[`jmp0xf/forge-release-authority`](https://github.com/jmp0xf/forge-release-authority) repository. Its policy,
independent verifier, protected workflow, signing identity, approval, tag, upload, publication, and withdrawal
permissions must remain outside the candidate write set.

## Fixed matrix

Build exactly one `forge` binary for each target:

- `x86_64-unknown-linux-musl`
- `aarch64-unknown-linux-musl`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`
- `x86_64-pc-windows-msvc`

The exact staged asset names are:

| Target | Binary | SBOM |
|---|---|---|
| `x86_64-unknown-linux-musl` | `forge-0.1.0-rc.2-x86_64-unknown-linux-musl` | `forge-0.1.0-rc.2-x86_64-unknown-linux-musl.cdx.json` |
| `aarch64-unknown-linux-musl` | `forge-0.1.0-rc.2-aarch64-unknown-linux-musl` | `forge-0.1.0-rc.2-aarch64-unknown-linux-musl.cdx.json` |
| `x86_64-apple-darwin` | `forge-0.1.0-rc.2-x86_64-apple-darwin` | `forge-0.1.0-rc.2-x86_64-apple-darwin.cdx.json` |
| `aarch64-apple-darwin` | `forge-0.1.0-rc.2-aarch64-apple-darwin` | `forge-0.1.0-rc.2-aarch64-apple-darwin.cdx.json` |
| `x86_64-pc-windows-msvc` | `forge-0.1.0-rc.2-x86_64-pc-windows-msvc.exe` | `forge-0.1.0-rc.2-x86_64-pc-windows-msvc.exe.cdx.json` |

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
mkdir -p /absolute/path/to/forge-0.1.0-rc.2-dist
RUSTUP_AUTO_INSTALL=0 cargo fetch --locked
RUSTUP_AUTO_INSTALL=0 cargo build --locked --offline -p xtask
```

On Windows PowerShell, use the native path and environment syntax:

```text
git status --porcelain=v2 --untracked-files=all --ignore-submodules=none
New-Item -ItemType Directory -Force C:\forge-0.1.0-rc.2-dist
$env:RUSTUP_AUTO_INSTALL = "0"
cargo fetch --locked
cargo build --locked --offline -p xtask
```

The explicit online fetch must complete before entering the offline candidate path. It populates the locked `.crate`
archives for every target; having only unpacked source directories is insufficient because Forge independently hashes
the fetched archive bytes against `Cargo.lock`.

On a runner with the exact target and linker already installed, build and stage one target. Keep each invocation on one
line so the same argument contract works in POSIX shells and PowerShell:

```text
target/debug/xtask release-build --target x86_64-unknown-linux-musl --output-dir /absolute/path/to/forge-0.1.0-rc.2-dist
```

```text
.\target\debug\xtask.exe release-build --target x86_64-pc-windows-msvc --output-dir C:\forge-0.1.0-rc.2-dist
```

When diagnosing the exact pre-Cargo boundary, opt in to a separate private handoff directory:

```text
New-Item -ItemType Directory C:\forge-private-build-input
.\target\debug\xtask.exe release-build --target x86_64-pc-windows-msvc --output-dir C:\forge-0.1.0-rc.2-dist --build-input-observation-dir C:\forge-private-build-input
```

The observation directory must already exist, be disjoint from the release output, and neither contain nor sit inside
the source repository or its Git private directories. Forge creates exactly the target-bound fixed name
`release-build-input-observation-<TRIPLE>.json` with owner-private, create-only semantics before Cargo starts. A
pre-existing fixed name fails without replacement. Use a fresh dedicated directory even though unrelated entries are
not release assets.

The raw v1 document records the source commit, target, exact native Cargo program/ordered arguments/working directory,
and, on a native Windows MSVC build, the prepared `PATH`, `LIB`, and `INCLUDE` from the same invocation. Those values
can disclose local toolchain and SDK paths. The document is candidate-controlled diagnostic input only: it is not one
of the thirteen release files, a Receipt, Evidence, provenance, signature, approval, or publication authority. Never
print or upload it, and never place it under the release output.

For ordinary candidate handoff, transfer only the fixed binary/SBOM pair; an Authority-owned path may separately carry
only an allowlisted path-free summary. After a non-echoing local check, remove the raw file namespace in a
`finally`/equivalent cleanup path. A Cargo failure after observation can leave the file for private diagnosis;
interruption on a disposable hosted runner is contained by VM destruction, while a persistent self-hosted runner
requires a trusted post-job cleanup.

An Authority-owned sanitizer may read the raw file on the same runner, emit an allowlisted path-free summary, and remove
the raw file for canary diagnosis and policy development. Sanitization reduces disclosure; it does not make a
candidate-controlled report independent. Formal qualification must use a fresh run whose Authority-owned observation,
enforcement, and builder record independently bind the real inputs. Candidate CI, raw observation, or its sanitized
summary cannot by itself replace any independent Authority gate below.

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
that handle without following symlinks. The staging namespace is the ten fixed binary/SBOM names; the finalized
namespace is the thirteen names defined below. Unknown directory entries fail closed. Use a dedicated empty directory,
and never upload with a directory glob.

Staging refuses unknown targets, mismatched executable structures, a directory that was already finalized, and a
same-name asset with different bytes. Repeating the same target with exactly the same binary and derived SBOM is an
idempotent no-op. Each binary/SBOM pair and the notice/manifest/checksum finalization set are fully preflighted before
the first missing file in that set is created, so a known collision does not leave a new partial set. It never
overwrites a different file. Each target-bound
CycloneDX 1.6 SBOM selects exactly the workspace-member `forge-cli` release graph, includes build dependencies but
excludes dev-only dependencies, and binds:

- the exact Git source commit;
- the `Cargo.lock` SHA-256;
- the binary SHA-256 and byte length;
- the exact target triple; and
- a machine-readable license expression for every component.

A selected local package with no registry source must be an exact workspace member; external path dependencies are
rejected because their source bytes are not covered by this Git snapshot and lockfile claim.

The scoped Cargo tree supplies the reviewed nodes and edges; before staging, every native build must independently
report the same package-ID set through Cargo `compiler-artifact` messages. A mismatch fails rather than claiming that
the Cargo tree alone proves the built package set.

The SBOM deliberately has no timestamp or host path. Its license fields are an audit index, not a substitute for the
complete license and notice text distributed with the binary.

The pair is not a multi-file transaction. If another process wins a create after preflight, Forge rereads that one
name: identical bytes are accepted and different bytes fail without replacement. A concurrent failure can therefore
leave a sibling that this invocation already created successfully; inspect the error and rerun only after verifying the
fixed names and bytes.

## License closure

The source tree contains `LICENSE-MIT`, `LICENSE-APACHE`, and a checked-in `THIRD-PARTY-LICENSES.txt`. The third-party
file binds the exact union of the five target-specific `forge-cli` release graphs, preserving normal and build edges and
excluding pure dev-only edges. It includes a package/version/source/Cargo.lock-checksum/license-expression ledger,
the selected complete license and notice text, and the mapping from every package to those texts.

The read-only drift gate is:

```text
cargo fetch --locked
cargo run --locked -p xtask -- release-license-check
```

After an intentional dependency change, generate a review candidate with:

```text
cargo fetch --locked
cargo run --locked -p xtask -- release-license-generate
```

Generation is a maintainer write. Review the complete diff, package mapping, expressions, copyright statements,
license texts, and notices before accepting it. A changed release graph, lock checksum, expression, selected text, or
notice must fail `release-license-check` until the checked-in corpus is regenerated and reviewed. `release-finalize`
copies the accepted `THIRD-PARTY-LICENSES.txt` bytes from the already bound isolated source; it never scans the network,
Cargo cache, user registry directory, or build host for license material.

## Failure residue and local limits

A failure before the first candidate write does not create an asset. Binary/SBOM pairs and the
notice/manifest/checksum set are
preflighted before their first write, but the complete command is not a transaction: a concurrent create or a final
source/root revalidation failure can return nonzero after one or more create-only files were safely written. A nonzero
command therefore never accepts the directory as a candidate. Do not overwrite or guess which files are valid; inspect
the reported fixed names, move the directory aside or choose a new empty output directory, rerun the required build or
finalize step, and require `release-check` to pass before external review.

`release-license-generate` likewise is not a two-file transaction. It atomically replaces the baseline and notice
files one at a time, then rechecks that the reviewed policy did not change. A second write failure or a late policy
change can therefore leave a mixed pair. On any nonzero exit, inspect both diffs, restore a stable policy, rerun the
generator, and require `release-license-check` to pass before accepting either file.

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
target/debug/xtask release-finalize --output-dir /absolute/path/to/forge-0.1.0-rc.2-dist
target/debug/xtask release-check --output-dir /absolute/path/to/forge-0.1.0-rc.2-dist
```

On Windows:

```text
.\target\debug\xtask.exe release-finalize --output-dir C:\forge-0.1.0-rc.2-dist
.\target\debug\xtask.exe release-check --output-dir C:\forge-0.1.0-rc.2-dist
```

Finalization requires all ten fixed staged files and writes, without replacing different bytes:

- `THIRD-PARTY-LICENSES.txt`, copied byte-for-byte from the source-bound checked-in file;
- `release-manifest.json`, a `forge.release-manifest/v2` document whose 11 artifacts record target, kind, byte length,
  and SHA-256 for each binary, SBOM, and the license/notice file;
- `SHA256SUMS`, covering those 11 artifacts and `release-manifest.json` in lexical order, for exactly 12 lines.

The historical v1 schema and reader remain unchanged for the unpublished rc.1 candidate. v1 compatibility reading
does not make a document acceptable as an rc.2 candidate; current acceptance requires the strict v2 contract.
`release-finalize` and `release-check` independently rebuild the canonical manifest and require exact bytes.

`release-check` revalidates the fixed thirteen-file candidate namespace, executable structures, source-bound locked
dependency graphs, byte-for-byte SBOMs, manifest, and all SHA-256 values. A successful result means only that the
candidate-controlled local assets are internally consistent; unrelated directory entries are rejected. It does not
grant any external authority.

The exact external-provenance subject set is:

- five fixed target binary names;
- the five matching `.cdx.json` names;
- `THIRD-PARTY-LICENSES.txt`;
- `release-manifest.json`;
- `SHA256SUMS`.

The external Authority verifier must independently bind the exact name, byte length, and SHA-256 of all thirteen
finalized files. The manifest's `provenance.subjects` array freezes those names but does not self-assert their external
digests. Upload those thirteen explicit paths; do not use `*`, recursive directory upload, or filesystem enumeration
as authority.

## External release gate

The Authority workflow isolates three permission domains:

1. Five native build jobs may checkout and execute the exact Forge candidate. They receive no OIDC token, protected
   environment, secret, or release permission.
2. The finalize job may execute the candidate `release-finalize` and `release-check` commands. It likewise receives no
   OIDC token, protected environment, or GitHub Release write permission.
3. The protected attest job may receive OIDC and attestation-write permission, but it checks out and executes only the
   Authority repository and its independent verifier. It must not checkout Forge, run Cargo/xtask, or execute any
   candidate binary.

The protected identity is the immutable Authority repository identity recorded in ADR-0041, with issuer
`https://token.actions.githubusercontent.com` and environment `forge-release`. Before any public release, that
Authority Set must provide and preserve evidence for all of the following:

1. Required Cargo gates and native/basic E2E passed on each platform tier, including Windows path/process behavior,
   exact on-disk asset-name spelling on case-insensitive filesystems, the declared macOS baseline, and both static musl
   architectures. Handle-relative reads on Windows do not by themselves prove the original directory-entry casing.
2. The independent Authority verifier accepted exactly all thirteen finalized files, manifest v2, the 12 checksum
   entries, SBOM contents and licenses, executable structures, builder records, and SLSA predicate without importing a
   Forge crate or delegating final judgment to `release-check`.
3. SLSA provenance v1 and Sigstore keyless attestation covered exactly those thirteen subjects and matched the frozen
   issuer, immutable subject, protected GitHub Environment, approval rule, and transparency-log policy outside the
   candidate write set.
4. The named release approver, security approver, rollback owner, private-vulnerability triage owner, and withdrawal
   permissions were confirmed on the protected platform boundary. The current single owner assignment is
   accountability, not evidence of independent second-person review.
5. The protected builder froze and recorded the compiler, wrappers, linker, dependency cache and relevant environment;
   local source/lock/binary binding alone does not prove those inputs.
6. Owner/legal explicitly confirmed the right to distribute original contributions under the project license, reviewed
   the exact dependency/license ledger and notices, and confirmed that the thirteen-file distribution needs no other
   license artifact. Candidate text, chat, or a PR description is not that confirmation. If compliance requires a
   changed asset set, create a new ADR and candidate rather than changing rc.2 in place.
7. The exact reviewed assets were attached to a new immutable GitHub Release; no file from an existing version was
   replaced.

Do not treat `release-check`, local Receipts, candidate CI, a draft GitHub Release, or a candidate-generated hash as any
of those external facts.

After protected qualification and attestation, the authorized operator must download and independently reverify the
thirteen explicit files, then create the `v0.1.0-rc.2` tag and a draft prerelease without reusing an existing name,
upload each file by exact path, reread the remote assets, and only then publish the prerelease. v0 does not store a
long-lived personal access token in Actions. Tag, Release, and asset creation are create-only; never delete and rebuild
the same version or replace an existing asset.

## Install a reviewed asset

Verify the downloaded file against independently verified `SHA256SUMS` and provenance. On Unix, give the raw binary an
executable bit and move it to a directory already selected by the user:

```text
chmod +x forge-0.1.0-rc.2-<TRIPLE>
./forge-0.1.0-rc.2-<TRIPLE> version
```

The Windows asset already ends in `.exe`. Installation does not run `forge init`, install project dependencies, or
modify a repository.

## Retention and rollback

After Forge has a real predecessor, retain the current published release and its immediate predecessor, including
their original assets, provenance, and signatures. Never rebuild or resign an old version in place.

`0.1.0-rc.1` was never published, so rc.2 has no real N-1. For an rc.2 incident, stop distribution or mark the affected
GitHub Release withdrawn and halt installation guidance until a new reviewed candidate clears the complete external
gate. Do not redirect users to rc.1. For later releases with a real independently verified predecessor, rollback may
restore documentation to that preserved N-1 while a corrected candidate is qualified.
