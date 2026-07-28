# Cross-crate tests

The repository's implemented cross-crate verification surface includes:

- invariant tests for dependency direction, uninstallability, read-only commands, idempotence, determinism, output
  contracts, and authority separation;
- end-to-end tests over generated fixture repositories;
- tests for the explicit N-1 schema and init-plan compatibility harness;
- fuzz targets for Git porcelain, managed blocks, configuration, and native path handling.
