#![no_main]

use forge_core::Digest;
use forge_core::ports::Hasher;
use forge_render::managed_block::{ManagedBlock, merge_markdown_block};
use libfuzzer_sys::fuzz_target;

#[derive(Debug)]
struct FuzzHasher;

impl Hasher for FuzzHasher {
    fn digest(&self, chunks: &[&[u8]]) -> Digest {
        let mut state = 0xcbf2_9ce4_8422_2325_u64;
        for chunk in chunks {
            state ^= chunk.len() as u64;
            state = state.wrapping_mul(0x0000_0100_0000_01b3);
            for byte in *chunk {
                state ^= u64::from(*byte);
                state = state.wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
        Digest::new(format!("fuzz:{state:016x}"))
    }
}

fuzz_target!(|input: &[u8]| {
    let body = std::str::from_utf8(input).unwrap_or("non-utf8 desired body");
    let desired = ManagedBlock {
        id: "fuzz-block",
        body,
    };

    let _ = desired.render_markdown(&FuzzHasher);
    let _ = merge_markdown_block(Some(input), &desired, &FuzzHasher, false);
    let _ = merge_markdown_block(Some(input), &desired, &FuzzHasher, true);
});
