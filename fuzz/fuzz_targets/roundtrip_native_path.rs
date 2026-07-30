#![no_main]

use std::ffi::OsString;
use std::path::PathBuf;

use forge_core::RepoRelativePath;
use forge_schema::WirePath;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let original = native_path(input);
    let wire = WirePath::from_path(&original);
    if let Ok(decoded) = wire.to_path_buf() {
        assert_eq!(decoded, original);
    }
    let _ = RepoRelativePath::new(&original);
});

#[cfg(unix)]
fn native_path(input: &[u8]) -> PathBuf {
    use std::os::unix::ffi::OsStringExt as _;

    PathBuf::from(OsString::from_vec(input.to_vec()))
}

#[cfg(windows)]
fn native_path(input: &[u8]) -> PathBuf {
    use std::os::windows::ffi::OsStringExt as _;

    let mut chunks = input.chunks_exact(2);
    let mut wide = chunks
        .by_ref()
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    if let Some(byte) = chunks.remainder().first() {
        wide.push(u16::from(*byte));
    }
    PathBuf::from(OsString::from_wide(&wide))
}

#[cfg(not(any(unix, windows)))]
fn native_path(input: &[u8]) -> PathBuf {
    PathBuf::from(String::from_utf8_lossy(input).into_owned())
}
