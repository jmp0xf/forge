# Forge v0 implementation status

This is a maintenance handoff, not an architecture decision. The accepted contract remains
`docs/design-proposal.md` together with `docs/adr/`. Update this note when a listed boundary is
resolved or superseded.

## Implemented boundary

M0 through M5 are implemented: typed public contracts and diagnostics, hardened Git/filesystem/
process ports, Rust and Go project discovery, deterministic command resolution, minimal managed
host adapters, `init`, `doctor`, and the read-only `next` reducer.

M6 currently has the following internal foundations:

- worktree-isolated, bounded, atomic/no-clobber state primitives;
- complete stdout/stderr stream digests independent of retained output;
- dependency validity across repository, scope, command, toolchain, environment, policy,
  base/task, and Forge behavior, with dependency and applicability reasons kept separate;
- canonical command and toolchain dependency fingerprints that fail closed on unknown facts,
  unsafe environment names, and invalid provenance;
- a prepared-input scope digest over HEAD and sorted path/mode/content identities.

The prepared scope layer intentionally performs no Git or filesystem acquisition. It cannot choose
an input set, read dirty or untracked content, or turn a partial snapshot into a reusable digest.
Dirty Gitlinks are rejected because v0 does not recursively bind their nested content.

## Public Evidence boundary

`forge evidence run/show/verify/export` remains an explicit unsupported boundary. The CLI must not
write a new Receipt or treat an existing Receipt as current, valid, or evidence-eligible until all
dependencies required by ADR-0016 can be represented and built authoritatively. A future N-1 reader
may parse and display v1 only as a historical observation. In particular, a local passing
observation is not CI, approval, deployment proof, or merge authority.

Four decisions are required before opening that command surface:

1. **Comparison context.** Define how an explicit or configured base resolves to an immutable
   commit; define merge-base, unborn, detached, missing-upstream, shallow, and error behavior;
   define when task acceptance is not applicable; and identify the approved policy base used for
   same-change anti-weakening. Observed upstream state is not sufficient authority to select a base.
2. **Receipt/Evidence v2 and migration.** The checked-in Receipt v1 cannot express repository
   identity, base/task, Forge behavior, or Known/Unknown/NotApplicable dependency states. ADR-0009
   therefore requires a versioned migration and N-1 reader behavior rather than changing v1 field
   meaning in place. The same decision must freeze the complete Forge behavior digest composition,
   including scope, process-output, success-normalization, validity, coverage, environment, and
   policy protocol versions. Receipt/Evidence IDs and timestamp format belong in this contract.
3. **`forge.toml` command/evidence v2.** Define `inputs` matching and empty/symlink semantics;
   define and carry mutability, network, success predicate, coverage, and enforcement for configured
   commands; and separate local required intents from external requirements. The current v1 parser
   retains only `inputs`, but command resolution cannot yet carry even that scope authoritatively.
4. **State object lifecycle.** Define immutable Receipt/Evidence/log names, collision handling,
   references, retention roots, count/age/byte ordering, cross-worktree GC, malformed/future schema
   behavior, crash recovery, and deletion order. Until then, state may be append/no-clobber but not
   garbage-collected optimistically.

## Safe follow-on work before those decisions

- Add typed read-only Git acquisition for `ls-files -s -z`, explicit caller-supplied merge-base,
  binary diff, and name-status. The port must not choose a default comparison base.
- Observe the actual allowlisted execution environment and return a privacy-safe Known/Unknown
  dependency value; hashing only `CommandSpec.env` is not a complete environment fingerprint.
- Probe Cargo, rustc, target, and Go toolchain facts without installing or changing tools. Missing
  required facts stay Unknown.
- Normalize `ProcessObservation` into an internal command observation and aggregate only current,
  eligible, passing local coverage. External requirements and unknown dimensions remain separate.

## M7 boundary

Checked-in schemas, parser fuzz seeds, and substantial path/process/state hardening exist. The
fixture builder is still disabled because fixture source versus platform materialization, manifest
schema, no-clobber behavior, fake-tool protocol, runnable-command matrix, and N-1 fixture-set identity
are not frozen. CI, release, SBOM, checksum, signing, ownership, and authority boundaries must not be
changed as an implementation shortcut; they require their normal maintainership and external
authority decisions.
