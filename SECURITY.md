# Security policy

Forge executes repository-local project commands and therefore treats repository content, manifests, task runners,
file names, symlinks, configuration, and subprocess output as untrusted input.

Security-sensitive reports should not be opened as public issues. Configure a private reporting channel before the
first public release and replace this paragraph with the project-specific contact process.

The bootstrap repository does not yet make security claims about sandboxing, network isolation, tamper resistance,
or authorization. The design explicitly distinguishes best-effort local observation from external approval.

## Current filesystem boundary

Repository writes reject lexical escapes, existing symlinks, non-regular targets, and paths that canonicalize outside
the repository. They validate again immediately before the atomic rename. The current path-based rename does not pin
ancestor directory handles across that final interval, so it is not a security boundary against another process that
can concurrently replace repository directories. Do not run write operations in a repository whose directories are
writable by an untrusted local principal. Handle-relative Unix and Windows replacement is tracked as v0 hardening;
until then, the implementation makes no claim of closing that TOCTOU class.
