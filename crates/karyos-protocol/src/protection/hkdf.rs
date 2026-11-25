// SPDX-License-Identifier: Apache-2.0

//! HKDF-SHA-256 (RFC 5869) with every intermediate erased: the one HKDF of
//! the workspace.
//!
//! The algorithm is the one of karyos-driver's `wire_keys::Context::derive`,
//! generalised to any `info` split in slices and any output length up to
//! the RFC limit. Extract keys HMAC-SHA-256 with the salt (32 zero bytes
//! when there is none) over the `IKM`; expand computes `T(i) =
//! HMAC(PRK, T(i-1) || info || i)`. The PRK and every `T(i)` live only in
//! [`Zeroizing`] buffers, and the HMAC states erase themselves
//! ([`HmacKey`], `sha2` feature `zeroize`). Allocates nothing.

use zeroize::Zeroizing;

use super::hmac_key::{HmacKey, OUT_LEN};

/// The longest output RFC 5869 allows: 255 blocks of 32 bytes.
pub const MAX_OUTPUT: usize = 255 * OUT_LEN;

/// The requested output exceeds [`MAX_OUTPUT`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("HKDF-SHA-256 output of {requested} bytes exceeds {MAX_OUTPUT}")]
pub struct OutputTooLong {
    /// Bytes requested.
    pub requested: usize,
}

/// Fills `okm` with HKDF-SHA-256 of `ikm` under `salt` (`None` is 32 zero
/// bytes) and `info`, the concatenation of its slices. On an error `okm`
/// is left zeroed.
///
/// # Errors
///
/// [`OutputTooLong`] when `okm` is longer than [`MAX_OUTPUT`].
pub fn hkdf_sha256_into(
    salt: Option<&[u8]>,
    ikm: &[u8],
    info: &[&[u8]],
    okm: &mut [u8],
) -> Result<(), OutputTooLong> {
    if okm.len() > MAX_OUTPUT {
        zeroize::Zeroize::zeroize(okm);
        return Err(OutputTooLong {
            requested: okm.len(),
        });
    }
    let mut extract = HmacKey::new(salt.unwrap_or(&[0_u8; OUT_LEN])).mac();
    extract.update(ikm);
    let prk = HmacKey::new(extract.finalize().as_slice());
    let mut previous: Option<Zeroizing<[u8; OUT_LEN]>> = None;
    for (index, chunk) in okm.chunks_mut(OUT_LEN).enumerate() {
        let mut expand = prk.mac();
        if let Some(block) = &previous {
            expand.update(block.as_slice());
        }
        for part in info {
            expand.update(part);
        }
        // At most 255 blocks, checked above.
        expand.update(&[u8::try_from(index.saturating_add(1)).unwrap_or(u8::MAX)]);
        let block = expand.finalize();
        if let Some(value) = block.get(..chunk.len()) {
            chunk.copy_from_slice(value);
        }
        previous = Some(block);
    }
    Ok(())
}

/// HKDF-SHA-256 with an output of `N` bytes, in an erased buffer. `N`
/// above [`MAX_OUTPUT`] fails to compile.
#[must_use]
pub fn hkdf_sha256<const N: usize>(
    salt: Option<&[u8]>,
    ikm: &[u8],
    info: &[&[u8]],
) -> Zeroizing<[u8; N]> {
    const { assert!(N <= MAX_OUTPUT, "HKDF-SHA-256 output over 255 blocks") };
    let mut okm = Zeroizing::new([0_u8; N]);
    // Cannot fail: `N` is checked at compile time.
    let _ = hkdf_sha256_into(salt, ikm, info, okm.as_mut_slice());
    okm
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::unwrap_used)]

    use super::*;
    use proptest::prelude::*;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect()
    }

    fn reference(salt: Option<&[u8]>, ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
        let mut out = vec![0_u8; len];
        ::hkdf::Hkdf::<sha2::Sha256>::new(salt, ikm)
            .expand(info, &mut out)
            .unwrap();
        out
    }

    /// RFC 5869 appendix A, test cases 1 to 3 (SHA-256).
    #[test]
    fn the_rfc_5869_cases_match() {
        let ikm = [0x0b_u8; 22];
        let salt: Vec<u8> = (0x00..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let mut okm = [0_u8; 42];
        hkdf_sha256_into(Some(&salt), &ikm, &[&info], &mut okm).unwrap();
        assert_eq!(
            okm.to_vec(),
            hex(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
            )
        );

        let ikm: Vec<u8> = (0x00..=0x4f).collect();
        let salt: Vec<u8> = (0x60..=0xaf).collect();
        let info: Vec<u8> = (0xb0..=0xff).collect();
        let mut okm = [0_u8; 82];
        // The info split in two slices is the same as one.
        hkdf_sha256_into(Some(&salt), &ikm, &[&info[..30], &info[30..]], &mut okm).unwrap();
        assert_eq!(
            okm.to_vec(),
            hex(
                "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"
            )
        );

        let expected = hex(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        );
        let mut okm = [0_u8; 42];
        hkdf_sha256_into(Some(&[]), &[0x0b; 22], &[], &mut okm).unwrap();
        assert_eq!(okm.to_vec(), expected);
        // No salt is the same as 32 zero bytes, and as the empty salt.
        hkdf_sha256_into(None, &[0x0b; 22], &[], &mut okm).unwrap();
        assert_eq!(okm.to_vec(), expected);
    }

    /// K-1 and K-2 of karyos-driver's `wire_keys` tests: the output equals
    /// that crate's current derivation (`Context::derive`).
    #[test]
    fn the_wire_keys_vectors_match() {
        let ikm: [u8; 32] = core::array::from_fn(|i| u8::try_from(i).unwrap());
        let info = hex(
            "6b6172796f732d776972652d617574682d763100646174610300000000efcdab89674523011032547698badcfe07000000000000000100000000000000020403020101",
        );
        let mut salt = [0_u8; 32];
        for (slot, word) in salt.chunks_mut(8).zip([
            0xA1A2_A3A4_A5A6_A7A8_u64,
            0xB1B2_B3B4_B5B6_B7B8,
            0xC1C2_C3C4_C5C6_C7C8,
            0xD1D2_D3D4_D5D6_D7D8,
        ]) {
            slot.copy_from_slice(&word.to_le_bytes());
        }
        assert_eq!(
            hkdf_sha256::<32>(Some(&salt), &ikm, &[&info]).to_vec(),
            hex("7411775de7eb337a2d9274edab61b5f65ff00bc41b5e6493e7defaefb1f18cda")
        );
        assert_eq!(
            hkdf_sha256::<32>(None, &ikm, &[&info]).to_vec(),
            hex("3e5ce432b51269f83459806dd5b0db979adecea5529e16f7218ea2099c1188b4")
        );
    }

    #[test]
    fn an_output_over_the_limit_is_refused_and_zeroed() {
        let mut okm = vec![0xff_u8; MAX_OUTPUT + 1];
        assert_eq!(
            hkdf_sha256_into(None, b"k", &[], &mut okm),
            Err(OutputTooLong {
                requested: MAX_OUTPUT + 1
            })
        );
        assert!(okm.iter().all(|b| *b == 0));
        let mut okm = vec![0_u8; MAX_OUTPUT];
        hkdf_sha256_into(None, b"k", &[b"i"], &mut okm).unwrap();
        assert_eq!(okm, reference(None, b"k", b"i", MAX_OUTPUT));
    }

    #[test]
    fn it_allocates_nothing() {
        let mut okm = [0_u8; 96];
        let (_, seen) = karyos_sys::alloc_count::count(|| {
            let _ = hkdf_sha256_into(Some(b"salt"), b"ikm", &[b"a", b"b"], &mut okm);
            let _ = hkdf_sha256::<32>(None, b"ikm", &[b"info"]);
        });
        assert_eq!(seen, 0);
    }

    proptest! {
        /// Equals the `hkdf` crate over random salts, keys, info and lengths.
        #[test]
        fn matches_the_hkdf_crate(
            salt in proptest::option::of(proptest::collection::vec(any::<u8>(), 0..100)),
            ikm in proptest::collection::vec(any::<u8>(), 0..100),
            info in proptest::collection::vec(any::<u8>(), 0..100),
            split in any::<usize>(),
            len in 0_usize..400,
        ) {
            let at = split % (info.len() + 1);
            let mut okm = vec![0_u8; len];
            hkdf_sha256_into(salt.as_deref(), &ikm, &[&info[..at], &info[at..]], &mut okm).unwrap();
            prop_assert_eq!(okm, reference(salt.as_deref(), &ikm, &info, len));
        }
    }
}
