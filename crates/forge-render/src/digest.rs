//! Stable digest domains shared by planning, application, and adapter state.

use forge_core::Digest;
use forge_core::ports::Hasher;

const FILE_DIGEST_DOMAIN: &[u8] = b"forge.repository-file/v1";

/// Digests the complete bytes of one repository file under Forge's stable file domain.
pub fn repository_file_digest<H>(hasher: &H, bytes: &[u8]) -> Digest
where
    H: Hasher + ?Sized,
{
    hasher.digest(&[FILE_DIGEST_DOMAIN, bytes])
}
