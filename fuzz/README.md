# Fuzzing

This is a separate Cargo workspace so fuzz-only dependencies do not enter Forge's product workspace
or root `Cargo.lock`.

Install `cargo-fuzz` and a compatible nightly toolchain, then run from the repository root:

```console
cargo +nightly fuzz run parse_status_porcelain_v2
cargo +nightly fuzz run merge_managed_block
cargo +nightly fuzz run parse_forge_config
cargo +nightly fuzz run roundtrip_native_path
```

The four targets cover the v0 design's critical parser and path boundaries: Git porcelain-v2,
managed-block merging, strict `forge.toml`, and lossless native-path encoding. The porcelain corpus
files are opaque bytes, not UTF-8 text: checked-in seeds deliberately contain NUL delimiters and
embedded newlines. Read or copy them with byte-preserving tools; do not normalize line endings. The
ordinary `forge-core` integration test reads the same porcelain files as bytes and replays both
formats, so a regression seed remains useful even where `cargo-fuzz` is unavailable.

LibFuzzer may add hash-named files below the selected target's `corpus/` directory. Minimize and
review useful regressions before committing them; `artifacts/`, `coverage/`, and the fuzz build
directory are ignored.
