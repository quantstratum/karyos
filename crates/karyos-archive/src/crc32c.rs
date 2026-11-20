// SPDX-License-Identifier: Apache-2.0

//! CRC-32C (Castagnoli), table driven (slicing by 8: eight bytes a step
//! through eight tables, karyos#1045), as iSCSI and ext4 use it (RFC 3720,
//! B.4): reflected polynomial `0x82F63B78`, initial value and final XOR
//! `0xFFFF_FFFF`. Karyos computes it itself rather than take a dependency
//! (quantstratum-docs: karyos/design/archive-gap-analysis.md, A2).
//!
//! CRC-32C is corruption detection, not authenticated integrity: anyone
//! who changes the bytes can recompute it. Integrity is the SHA-256 seal
//! and its hash chain ([`crate::integrity`], SPEC.md §8.4), which sits
//! beside this checksum and never replaces it (karyos#662).

/// The reflected Castagnoli polynomial.
const POLYNOMIAL: u32 = 0x82F6_3B78;

/// The slicing tables, built once on first use: `TABLES[0]` is the
/// byte-wise table, and `TABLES[k][i]` the CRC of byte `i` followed by `k`
/// zero bytes.
static TABLES: std::sync::LazyLock<[[u32; 256]; 8]> = std::sync::LazyLock::new(tables);

fn tables() -> [[u32; 256]; 8] {
    let mut tables = [[0u32; 256]; 8];
    let mut first = [0u32; 256];
    for (index, slot) in (0u32..).zip(first.iter_mut()) {
        let mut crc = index;
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ POLYNOMIAL
            } else {
                crc >> 1
            };
        }
        *slot = crc;
    }
    let mut previous = first;
    for table in &mut tables {
        *table = previous;
        let mut next = [0u32; 256];
        for (slot, crc) in next.iter_mut().zip(previous) {
            *slot = (crc >> 8) ^ lookup(&first, crc);
        }
        previous = next;
    }
    tables
}

/// `table`'s entry for the low byte of `crc`: a `u8` index into 256
/// entries, always present.
#[inline]
fn lookup(table: &[u32; 256], crc: u32) -> u32 {
    let [low, ..] = crc.to_le_bytes();
    table.get(usize::from(low)).copied().unwrap_or(0)
}

/// An incremental CRC-32C.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Crc32c(u32);

impl Default for Crc32c {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc32c {
    /// A CRC over no bytes yet.
    #[must_use]
    pub const fn new() -> Self {
        Self(u32::MAX)
    }

    /// Adds `bytes`.
    pub fn update(&mut self, bytes: &[u8]) {
        let [t0, t1, t2, t3, t4, t5, t6, t7] = &*TABLES;
        let mut crc = self.0;
        let mut words = bytes.chunks_exact(8);
        for word in &mut words {
            let mut eight = [0u8; 8];
            eight.copy_from_slice(word);
            let [b0, b1, b2, b3, b4, b5, b6, b7] = eight;
            let low = crc ^ u32::from_le_bytes([b0, b1, b2, b3]);
            let [l0, l1, l2, l3] = low.to_le_bytes();
            crc = lookup(t7, u32::from(l0))
                ^ lookup(t6, u32::from(l1))
                ^ lookup(t5, u32::from(l2))
                ^ lookup(t4, u32::from(l3))
                ^ lookup(t3, u32::from(b4))
                ^ lookup(t2, u32::from(b5))
                ^ lookup(t1, u32::from(b6))
                ^ lookup(t0, u32::from(b7));
        }
        for &byte in words.remainder() {
            crc = (crc >> 8) ^ lookup(t0, crc ^ u32::from(byte));
        }
        self.0 = crc;
    }

    /// The CRC of every byte added.
    #[must_use]
    pub const fn finish(self) -> u32 {
        self.0 ^ u32::MAX
    }
}

/// The CRC-32C of `bytes`.
#[must_use]
pub fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = Crc32c::new();
    crc.update(bytes);
    crc.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 3720, B.4, and the common check value.
    #[test]
    fn it_matches_the_reference_vectors() {
        assert_eq!(crc32c(b""), 0);
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(&[0u8; 32]), 0x8A91_36AA);
        assert_eq!(crc32c(&[0xFFu8; 32]), 0x62A8_AB43);
        let ascending: Vec<u8> = (0u8..32).collect();
        assert_eq!(crc32c(&ascending), 0x46DD_794E);
        let descending: Vec<u8> = (0u8..32).rev().collect();
        assert_eq!(crc32c(&descending), 0x113F_DB5C);
    }

    /// The byte-at-a-time definition, for the slicing path to match.
    fn bytewise(bytes: &[u8]) -> u32 {
        let table = &TABLES[0];
        let mut crc = u32::MAX;
        for &byte in bytes {
            crc = (crc >> 8) ^ table[usize::from(crc.to_le_bytes()[0] ^ byte)];
        }
        crc ^ u32::MAX
    }

    /// karyos#1045: slicing by 8 equals the byte-wise CRC at every length
    /// and alignment of the remainder.
    #[test]
    fn slicing_matches_the_bytewise_crc() {
        let bytes: Vec<u8> = (0u32..4099)
            .map(|i| u8::try_from(i.wrapping_mul(2_654_435_761) >> 24).unwrap())
            .collect();
        for length in 0..=64 {
            assert_eq!(
                crc32c(&bytes[..length]),
                bytewise(&bytes[..length]),
                "{length}"
            );
        }
        for start in 0..8 {
            assert_eq!(
                crc32c(&bytes[start..]),
                bytewise(&bytes[start..]),
                "{start}"
            );
        }
    }

    /// Feeding the bytes in pieces gives the same CRC.
    #[test]
    fn it_is_incremental() {
        let bytes: Vec<u8> = (0u8..=255).cycle().take(1000).collect();
        let mut crc = Crc32c::new();
        for chunk in bytes.chunks(37) {
            crc.update(chunk);
        }
        assert_eq!(crc.finish(), crc32c(&bytes));
    }
}
