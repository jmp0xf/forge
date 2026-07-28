# Security policy

Forge executes repository-local project commands and therefore treats repository content, manifests, task runners,
file names, symlinks, configuration, and subprocess output as untrusted input.

Security-sensitive reports should not be opened as public issues. Configure a private reporting channel before the
first public release and replace this paragraph with the project-specific contact process.

The bootstrap repository does not yet make security claims about sandboxing, network isolation, tamper resistance,
or authorization. The design explicitly distinguishes best-effort local observation from external approval.

## Current filesystem boundary

Repository writes reject lexical escapes, existing symlinks/reparse points, non-regular targets, and paths outside the
repository. On Unix and Windows, `RepositoryWriter` also pins the repository root and each target ancestor with
directory handles; temporary creation and final create/replace are relative to the same pinned parent. A concurrent
root or ancestor replacement therefore cannot redirect the target bytes into the replacement tree. Forge reopens and
compares the visible root and parent identities after commit and reports a failure when either changed. The complete
file may already exist in the safely pinned directory that was moved away; this is a diagnosed partial side effect,
not a rollback guarantee. Platforms without equivalent directory-handle primitives fail closed for repository writes.

This boundary covers file creation and replacement routed through `RepositoryWriter`; it does not turn repository
reads, Git, subprocesses, Evidence garbage collection, or a multi-file apply into a sandbox or transaction. Their
existing bounded validation, identity/quarantine, stable-scope, and recovery rules remain separate. A process running
as the same principal may still change files after Forge returns, so independent review and CI remain necessary.
