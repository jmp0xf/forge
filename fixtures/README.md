# Fixture repositories

Fixture repositories are added incrementally with the implementation milestones. The required matrix is specified in
`docs/design-proposal.md`; it includes Rust packages/workspaces, Go modules/workspaces, mixed repositories, brownfield
runners and adapters, dirty worktrees, linked worktrees, submodules, non-UTF-8 paths, CRLF, symlink escape attempts,
missing tools, process timeouts, and bounded-output cases.

Fixtures are public regression material, not the external held-out authority set used by trusted self-hosting.
