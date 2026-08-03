# Machine-readable Schemas

These versioned JSON Schemas are generated from `forge-schema` and checked in because Forge output is a behavior
interface consumed by humans, agents, scripts, and CI. Each root document fixes its `$id` and root `schema` field to
the same `forge.<domain>/v<n>` identifier. Most contracts use Forge's standard envelope. Release manifests, the
private diagnostic build-input observation, the release-build plan, and the apply descriptor are standalone contracts
with their own fixed root fields.

Base64 in the build-input observation is lossless encoding, not redaction or encryption. A raw document can contain
the Cargo program, arguments, working directory, and Windows `PATH`/`LIB`/`INCLUDE`; never upload, commit, cache, sign,
or treat it as Evidence, a release asset, or provenance. Schema validity establishes only the representable wire shape,
not independent truth or all decoded semantic checks. The fixed thirteen-asset release set is unchanged. An
Authority-owned sanitizer may produce safe canary input; formal qualification must independently observe and enforce
the real builder inputs.

The release-build plan is a candidate-controlled semantic request, not executable argv or release evidence. The apply
descriptor is a minimal candidate-visible, path-free SBOM projection that the Authority must generate and independently
validate from the Cargo execution it owns. Neither contract carries Authority-private probes, profiles, policy, run
identity, nonce, success state, or approval. Schema validity is not current qualification acceptance: current consumers
must separately enforce bounded canonical bytes, fixed values, graph closure, and all digest bindings. Adding these
schemas does not activate qualification, signing, tagging, or publication.

Regenerate and verify them with:

```bash
cargo run -p xtask -- schema-export
cargo run -p xtask -- check-schemas
```

Do not edit generated files by hand. A reviewed wire-contract change belongs in `forge-schema`, with a major Schema
version change when a field is removed, renamed, retyped, or changes meaning.
