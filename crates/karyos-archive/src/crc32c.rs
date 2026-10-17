// SPDX-License-Identifier: Apache-2.0

//! CRC-32C (Castagnoli), table driven, as iSCSI and ext4 use it (RFC 3720,
//! B.4): reflected polynomial `0x82F63B78`, initial value and final XOR
//! `0xFFFF_FFFF`. Karyos computes it itself rather than take a dependency
//! (quantstratum-docs: karyos/design/archive-gap-analysis.md, A2).

/// The reflected Castagnoli polynomial.
const POLYNOMIAL: u32 = 0x82F6_3B78;

/// The byte-wise table, built once on first use.
static TABLE: std::sync::LazyLock<[u32; 256]> = std::sync::LazyLock::new(table);

fn table() -> [u32; 256] {
    let mut table = [0u32; 256];
    for (index, slot) in (0u32..).zip(table.iter_mut()) {
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
    table
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
        let table = &*TABLE;
        let mut crc = self.0;
        for &byte in bytes {
            let [low, ..] = crc.to_le_bytes();
            let index = usize::from(low ^ byte);
            crc = (crc >> 8) ^ table.get(index).copied().unwrap_or(0);
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
