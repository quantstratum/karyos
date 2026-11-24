// SPDX-License-Identifier: Apache-2.0

//! HMAC-SHA-256 (RFC 2104) keyed once, with every copy of the key erased.
//!
//! `hmac`'s key setup pads the key into a block on its own stack and does
//! not erase it. Here the padded key lives in one [`Zeroizing`] block while
//! the inner and outer SHA-256 states absorb it, and those states erase
//! themselves on drop (`sha2` feature `zeroize`). `zeroize` is built
//! without `alloc`. Used by the HMAC profile, by HKDF and by the keyed
//! fingerprints of the key state (quantstratum/karyos#648).

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The SHA-256 block length.
const BLOCK_LEN: usize = 64;
/// The SHA-256 output length.
pub const OUT_LEN: usize = 32;
const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;

/// An HMAC-SHA-256 key: the inner and outer hash states after the padded
/// key, both erased on drop.
#[derive(Clone)]
pub struct HmacKey {
    inner: Sha256,
    outer: Sha256,
}

impl core::fmt::Debug for HmacKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HmacKey(..)")
    }
}

impl HmacKey {
    /// Keys HMAC-SHA-256 with `key` of any length; a key longer than a
    /// block is hashed first, as RFC 2104 says.
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        let mut pad = Zeroizing::new([0_u8; BLOCK_LEN]);
        if key.len() > BLOCK_LEN {
            let mut hashed = Sha256::new();
            hashed.update(key);
            let mut digest = Zeroizing::new([0_u8; OUT_LEN]);
            hashed.finalize_into((&mut *digest).into());
            if let Some(slot) = pad.get_mut(..OUT_LEN) {
                slot.copy_from_slice(digest.as_slice());
            }
        } else if let Some(slot) = pad.get_mut(..key.len()) {
            slot.copy_from_slice(key);
        }
        for byte in pad.iter_mut() {
            *byte ^= IPAD;
        }
        let mut inner = Sha256::new();
        inner.update(pad.as_slice());
        for byte in pad.iter_mut() {
            *byte ^= IPAD ^ OPAD;
        }
        let mut outer = Sha256::new();
        outer.update(pad.as_slice());
        Self { inner, outer }
    }

    /// A MAC computation under this key.
    #[must_use]
    pub fn mac(&self) -> HmacState {
        HmacState {
            inner: self.inner.clone(),
            outer: self.outer.clone(),
        }
    }
}

/// One MAC computation in progress.
pub struct HmacState {
    inner: Sha256,
    outer: Sha256,
}

impl HmacState {
    /// Absorbs `bytes`.
    pub fn update(&mut self, bytes: &[u8]) {
        self.inner.update(bytes);
    }

    /// The 32-byte MAC, erased on drop.
    #[must_use]
    pub fn finalize(self) -> Zeroizing<[u8; OUT_LEN]> {
        let Self { inner, mut outer } = self;
        // Each digest is written straight into erased storage, never to a
        // plain temporary.
        let mut inner_out = Zeroizing::new([0_u8; OUT_LEN]);
        inner.finalize_into((&mut *inner_out).into());
        outer.update(inner_out.as_slice());
        let mut out = Zeroizing::new([0_u8; OUT_LEN]);
        outer.finalize_into((&mut *out).into());
        out
    }

    /// Whether the leftmost `tag.len()` bytes of the MAC equal `tag`, in
    /// constant time for a given length. An empty or over-long tag never
    /// matches.
    #[must_use]
    pub fn verify_truncated_left(self, tag: &[u8]) -> bool {
        let full = self.finalize();
        let Some(expected) = full.get(..tag.len()).filter(|_| !tag.is_empty()) else {
            return false;
        };
        let diff = expected
            .iter()
            .zip(tag)
            .fold(0_u8, |acc, (a, b)| acc | (a ^ b));
        core::hint::black_box(diff) == 0
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn rfc4231(key: &[u8], data: &[u8]) -> [u8; OUT_LEN] {
        let mut mac = HmacKey::new(key).mac();
        mac.update(data);
        *mac.finalize()
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(text.get(i..i + 2).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn the_rfc_4231_vectors_match() {
        // Test case 1: a 20-byte key.
        assert_eq!(
            rfc4231(&[0x0b; 20], b"Hi There").to_vec(),
            hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        );
        // Test case 2: a short key.
        assert_eq!(
            rfc4231(b"Jefe", b"what do ya want for nothing?").to_vec(),
            hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
        // Test case 6: a 131-byte key, hashed first.
        assert_eq!(
            rfc4231(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )
            .to_vec(),
            hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
        );
        // A key of exactly one block is used as it is.
        let mut a = HmacKey::new(&[7; 64]).mac();
        a.update(b"x");
        let mut b = HmacKey::new(&[7; 64]).mac();
        b.update(b"y");
        assert_ne!(*a.finalize(), *b.finalize());
    }

    #[test]
    fn truncated_tags_compare_by_prefix() {
        let mac = || {
            let mut mac = HmacKey::new(b"Jefe").mac();
            mac.update(b"what do ya want for nothing?");
            mac
        };
        let full = hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        assert!(mac().verify_truncated_left(&full[..16]));
        assert!(mac().verify_truncated_left(&full));
        let mut wrong = full[..16].to_vec();
        wrong[15] ^= 1;
        assert!(!mac().verify_truncated_left(&wrong));
        assert!(!mac().verify_truncated_left(&[]));
        let mut long = full.clone();
        long.push(0);
        assert!(!mac().verify_truncated_left(&long));
    }
}
