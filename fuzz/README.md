# Fuzzing

This is a separate Cargo workspace so fuzz-only dependencies do not enter Forge's product workspace
or root `Cargo.lock`.

Install `cargo-fuzz` and a compatible nightly toolchain, then run from the repository root:

```console
cargo +nightly fuzz run parse_status_porcelain_v2
```

The target sends every input to the porcelain-v2 parser once as SHA-1 and once as SHA-256. Corpus
files are opaque bytes, not UTF-8 text: checked-in seeds deliberately contain NUL delimiters and
embedded newlines. Read or copy them with byte-preserving tools; do not normalize line endings. The
ordinary `forge-core` integration test reads the same files as bytes and replays both formats, so a
regression seed remains useful even where `cargo-fuzz` is unavailable.

LibFuzzer may add hash-named files to `corpus/parse_status_porcelain_v2/`. Minimize and review useful
regressions before committing them; `artifacts/`, `coverage/`, and the fuzz build directory are
ignored.
