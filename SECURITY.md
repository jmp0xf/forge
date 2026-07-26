# Security policy

Forge executes repository-local project commands and therefore treats repository content, manifests, task runners,
file names, symlinks, configuration, and subprocess output as untrusted input.

Security-sensitive reports should not be opened as public issues. Configure a private reporting channel before the
first public release and replace this paragraph with the project-specific contact process.

The bootstrap repository does not yet make security claims about sandboxing, network isolation, tamper resistance,
or authorization. The design explicitly distinguishes best-effort local observation from external approval.
