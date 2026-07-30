# Security policy

Forge executes repository-local project commands and therefore treats repository content, manifests, task runners,
file names, symlinks, configuration, and subprocess output as untrusted input.

Security-sensitive reports should not be opened as public issues. Configure a private reporting channel before the
first public release and replace this paragraph with the project-specific contact process.

Forge does not claim to sandbox repository code, isolate the network, resist a malicious process running as the same
principal, or grant external authorization. The design explicitly distinguishes bounded local observation from
independent review, CI, branch protection, signing, and release authority.

## Current filesystem boundaries

### Working-tree writes

Repository writes reject lexical escapes, existing symlinks/reparse points, non-regular targets, and paths outside the
repository. On Unix and Windows, `RepositoryWriter` also pins the repository root and each target ancestor with
directory handles; temporary creation and final create/replace are relative to the same pinned parent. A concurrent
root or ancestor replacement therefore cannot redirect the target bytes into the replacement tree. Forge reopens and
compares the visible root and parent identities after commit and reports a failure when either changed. The complete
file may already exist in the safely pinned directory that was moved away; this is a diagnosed partial side effect,
not a rollback guarantee. Windows may instead reject the directory move or rename before commit; Forge then reports
`NotCommitted` and must not write into the replacement tree. Platforms without equivalent directory-handle
primitives fail closed for repository writes.

This boundary covers file creation and replacement routed through `RepositoryWriter`. A multi-file apply is not one
OS transaction: failures report committed and uncommitted paths so Git can be used for recovery.

### Immutable Evidence state

Receipt, Evidence, and log state uses the worktree-local `<git-dir>/forge` root. The typed Evidence entry points pin
that root and every existing or newly created target ancestor among the five supported class directories
(`receipts/v1`, `receipts/v2`, `evidence/v1`, `evidence/v2`, and `logs/v1`). Enumeration, object reopen, and immutable
create are handle-relative; GC quarantine, recovery, and deletion additionally reuse the scanned class-directory
capability. A visible root, ancestor, class-directory, or object identity change fails closed instead of redirecting a
mutation into a replacement tree.

The typed state boundary also enforces private access:

- Unix Evidence directories require owner `rwx` and no group/other permission bits; files grant no group/other bits.
  macOS additionally clears inherited extended ACLs on creation and rejects any extended ACL when reading.
- Windows objects must be owned by the current user and have a protected DACL containing exactly one full-control
  access rule for that user. ACLs are created explicitly and read back before Evidence bytes are accepted.
- Other platforms fail closed until equivalent owner-only creation and verification are implemented.

Before its first recovery or deletion mutation, GC validates the complete bounded hierarchy and every current
same-directory quarantine candidate across all five classes. A current v2 Receipt/Evidence or v1 log quarantine file
is recovered conservatively under the matching worktree lock. A quarantine file in a legacy read-only v1
Receipt/Evidence class, or the older directory-shaped quarantine layout, is unsupported: Forge preserves every byte
and requires manual recovery rather than guessing a migration. Conflicting original and quarantine objects are both
retained and reported.

Corrupt state cannot request an unbounded scan. One snapshot accepts at most 4,096 Receipts across v1/v2, 4,096
Evidence objects across v1/v2, 4,096 logs, 131,072 references, and 512 MiB of scanned object bytes. Receipt and
Evidence documents are capped at 4 MiB and 8 MiB respectively; logs have an explicit caller-supplied object limit.
The retained closure is capped at 256 MiB. Recovery verification has its own 512 MiB budget, and objects are reopened
and streamed sequentially so the scan does not require all contents or file descriptors to remain resident.

Forge v0 production commands do not persist arbitrary project stdout/stderr content in this state. An observed
process keeps complete per-stream digests, byte counts, truncation facts, and a content-free diagnostic summary; a
process-boundary failure keeps typed unavailable markers and no byte counts. These facts still reveal output size and
equality and may confirm low-entropy guesses, so “content-free” does not mean zero-information or redacted. Current
`log_refs` are empty. See
[ADR-0038](docs/adr/0038-do-not-persist-arbitrary-project-command-output-in-v0.md).

These boundaries do not turn repository reads, Git, subprocesses, GC, or the repository into a sandbox or protect
against a malicious same-principal process replacing an object after the final check. The per-worktree lock only
coordinates conforming Forge processes, GC is not a multi-object transaction, Windows NTFS evidence does not prove
ReFS or SMB/UNC behavior, and read-only filesystem access may still update host-managed access times. Independent
review and CI remain necessary.
