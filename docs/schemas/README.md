# Machine-readable Schemas

These versioned JSON Schemas are generated from `forge-schema` and checked in because Forge output is a behavior
interface consumed by humans, agents, scripts, and CI. Each root document fixes its `$id` and root `schema` field to
the same `forge.<domain>/v<n>` identifier. Most contracts use Forge's standard envelope; the standalone release
manifest intentionally does not.

Regenerate and verify them with:

```bash
cargo run -p xtask -- schema-export
cargo run -p xtask -- check-schemas
```

Do not edit generated files by hand. A reviewed wire-contract change belongs in `forge-schema`, with a major Schema
version change when a field is removed, renamed, retyped, or changes meaning.
