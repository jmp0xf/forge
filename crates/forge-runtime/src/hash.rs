//! Deterministic BLAKE3 hashing with unambiguous chunk framing.

use forge_core::Digest;
use forge_core::ports::Hasher;

/// Forge's production content hasher.
#[derive(Debug, Default, Clone, Copy)]
pub struct Blake3Hasher;

impl Blake3Hasher {
    /// Hashes chunks with length prefixes so chunk boundaries cannot collide.
    #[must_use]
    pub fn digest_chunks(chunks: &[&[u8]]) -> Digest {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"forge.digest/v1\0");
        for chunk in chunks {
            hasher.update(&(chunk.len() as u64).to_le_bytes());
            hasher.update(chunk);
        }
        Digest::new(format!("blake3:{}", hasher.finalize().to_hex()))
    }
}

impl Hasher for Blake3Hasher {
    fn digest(&self, chunks: &[&[u8]]) -> Digest {
        Self::digest_chunks(chunks)
    }
}

#[cfg(test)]
mod tests {
    use forge_core::ports::Hasher as _;

    use super::Blake3Hasher;

    #[test]
    fn chunk_boundaries_are_part_of_the_digest() {
        let hasher = Blake3Hasher;
        let left = hasher.digest(&[b"ab", b"c"]);
        let right = hasher.digest(&[b"a", b"bc"]);

        assert_ne!(left, right);
        assert!(left.as_str().starts_with("blake3:"));
    }

    #[test]
    fn hashing_is_deterministic() {
        let hasher = Blake3Hasher;
        assert_eq!(
            hasher.digest(&[b"repository", b"scope"]),
            hasher.digest(&[b"repository", b"scope"])
        );
    }

    #[test]
    fn repository_identity_input_has_a_fixed_digest_vector() {
        let digest =
            Blake3Hasher::digest_chunks(&[b"forge.repository-id/v1", b"unix-bytes", b"/repo/.git"]);

        assert_eq!(
            digest.as_str(),
            "blake3:31595b9c96bff2671c0be809b6728fc16028a717f5fb81e4bd48617906b9f62c"
        );
    }
}
