#![no_main]

use forge_core::{GitObjectFormat, parse_status_porcelain_v2};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let _ = parse_status_porcelain_v2(input, GitObjectFormat::Sha1);
    let _ = parse_status_porcelain_v2(input, GitObjectFormat::Sha256);
});
