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
    use std::collections::{BTreeMap, BTreeSet};
    use std::ffi::OsString;
    use std::time::Duration;

    use forge_core::domain::{
        CommandEnforcement, CommandSource, CommandSpec, Confidence, CoverageDimension, Intent,
        Mutability, NetworkIntent, Provenance, SuccessPredicate,
    };
    use forge_core::evidence::DependencyValue;
    use forge_core::fingerprint::command_dependency_digest;
    use forge_core::path::RepoRelativePath;
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

    #[test]
    fn command_dependency_has_a_fixed_production_digest_vector()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut command = CommandSpec::new(
            "rust.check",
            Intent::Check,
            "cargo",
            RepoRelativePath::new("crates/core")?,
            CommandSource::LanguageDefault {
                provider: String::from("rust"),
                rule: String::from("cargo-check"),
            },
        )
        .with_args(["check", "--workspace"]);
        command.env = BTreeMap::from([
            (OsString::from("CARGO_NET_OFFLINE"), OsString::from("true")),
            (OsString::from("RUSTUP_AUTO_INSTALL"), OsString::from("0")),
        ]);
        command.timeout = Duration::from_millis(12_345);
        command.mutability = Mutability::ReadOnly;
        command.network = NetworkIntent::OfflineRequested;
        command.enforcement = CommandEnforcement::Required;
        command.success = SuccessPredicate::All(vec![
            SuccessPredicate::ExitZero,
            SuccessPredicate::JsonHasNoErrors,
        ]);
        command.confidence = Confidence::High;
        command.coverage = BTreeSet::from([CoverageDimension::Compile, CoverageDimension::Lint]);
        let provenance = [Provenance {
            rule_id: String::from("command/base"),
            source_path: None,
            source_range: None,
            detail: String::from("source for command/base"),
        }];

        let DependencyValue::Known(digest) =
            command_dependency_digest(&Blake3Hasher, &command, &provenance)?
        else {
            return Err("authoritative command fixture unexpectedly became unknown".into());
        };
        // This production vector includes the command's lossless native cwd representation.
        #[cfg(not(windows))]
        let expected = "blake3:b6843661067f3213110e31343d11b80ce41b1e0367e85e9a8bd448f5dceb3392";
        #[cfg(windows)]
        let expected = "blake3:bb4a0ce356e61e06e24d2842ead6ea64a80268892ed3acf5cec1c94683597236";
        assert_eq!(digest.as_str(), expected);
        Ok(())
    }
}
