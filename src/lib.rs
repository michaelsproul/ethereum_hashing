//! Optimized SHA256 for use in Ethereum.
//!
//! The initial purpose of this crate was to provide an abstraction over the hash function used in
//! the beacon chain. The hash function changed during the specification process, so defining it
//! once in this crate made it easy to replace.
//!
//! Now this crate serves primarily as a wrapper over two SHA256 crates: `sha2` and `ring` – which
//! it switches between at runtime based on the availability of SHA intrinsics.

#[cfg(feature = "zero_hash_cache")]
use lazy_static::lazy_static;

/// Length of a SHA256 hash in bytes.
pub const HASH_LEN: usize = 32;

pub use evercrypt_sha2::Context;

pub fn init() {
    evercrypt_sha2::init();
}

/// Returns the digest of `input` using the best available implementation.
pub fn hash(input: &[u8]) -> Vec<u8> {
    hash_fixed(input).to_vec()
}

/// Hash function returning a fixed-size array (to save on allocations).
///
/// Uses the best available implementation based on CPU features.
pub fn hash_fixed(input: &[u8]) -> [u8; HASH_LEN] {
    evercrypt_sha2::sha256(input)
}

/// Compute the hash of two hashes concatenated.
pub fn hash32_concat(h1: &[u8], h2: &[u8]) -> [u8; 32] {
    let mut ctxt = Context::new();
    ctxt.update(h1);
    ctxt.update(h2);
    ctxt.finalize()
}

/// Compute the hash of two hashes concatenated.
pub fn hash32_concat_fixed(h1: [u8; 32], h2: [u8; 32]) -> [u8; 32] {
    let mut input = [0; 64];
    input[..32].copy_from_slice(&h1);
    input[32..].copy_from_slice(&h2);
    hash_fixed(&input)
}

/// The max index that can be used with `ZERO_HASHES`.
#[cfg(feature = "zero_hash_cache")]
pub const ZERO_HASHES_MAX_INDEX: usize = 48;

#[cfg(feature = "zero_hash_cache")]
lazy_static! {
    /// Cached zero hashes where `ZERO_HASHES[i]` is the hash of a Merkle tree with 2^i zero leaves.
    pub static ref ZERO_HASHES: Vec<[u8; HASH_LEN]> = {
        let mut hashes = vec![[0; HASH_LEN]; ZERO_HASHES_MAX_INDEX + 1];

        for i in 0..ZERO_HASHES_MAX_INDEX {
            hashes[i + 1] = hash32_concat_fixed(hashes[i], hashes[i]);
        }

        hashes
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustc_hex::FromHex;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::*;

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_hashing() {
        let input: Vec<u8> = b"hello world".as_ref().into();

        let output = hash(input.as_ref());
        let expected_hex = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        let expected: Vec<u8> = expected_hex.from_hex().unwrap();
        assert_eq!(expected, output);
    }

    #[cfg(feature = "zero_hash_cache")]
    mod zero_hash {
        use super::*;

        #[test]
        fn zero_hash_zero() {
            assert_eq!(ZERO_HASHES[0], [0; 32]);
        }
    }
}
