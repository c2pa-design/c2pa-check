use sha2::{Digest, Sha256};

pub fn hex_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);

    hex::encode(hasher.finalize())
}
