#![no_main]

use forge_detect::config::parse_forge_config_blob;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let _ = parse_forge_config_blob(input);
});
