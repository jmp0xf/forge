# Cross-crate tests

The implementation will add:

- invariant tests for dependency direction, uninstallability, read-only commands, idempotence, determinism, output
  contracts, and authority separation;
- end-to-end tests over generated fixture repositories;
- N-1 compatibility tests for schemas and init plans;
- fuzz targets for Git porcelain, managed blocks, configuration, and native path handling.
