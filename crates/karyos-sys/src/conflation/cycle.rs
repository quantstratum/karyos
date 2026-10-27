// SPDX-License-Identifier: Apache-2.0

//! Refresh and snapshot cycles of a conflated lane (`quantstratum-docs:
//! karyos/adr/0080-conflation-refresh-cycles-in-band.md`; karyos#634): the
//! encoding of their markers and values in a DATA message's reserved value,
//! and the markers' 24-byte payload. The frame format does not change.
//!
//! The reserved value read as 64 bits:
//!
//! | Bits | Live value | Refresh value | Marker |
//! | --- | --- | --- | --- |
//! | 63 | 0 | 1 | 1 |
//! | 62 to 32 | 0 | cycle id | cycle id |
//! | 31 to 0 | key | key | [`MARKER_KEY`] |
//!
//! A table's keys are below its key count, a `u32`, so [`MARKER_KEY`] is
//! never a key. A table interprets this encoding only when it opts in
//! (`ConflationConfig::refresh`); otherwise every reserved value outside
//! `0..keys` is a rejected key, as before.

/// Bit 63 of the reserved value: a refresh value or a marker.
const CYCLE_BIT: u64 = 1 << 63;
/// The key bits of the reserved value.
const KEY_BITS: u64 = 0xFFFF_FFFF;
/// The key field of a marker, never a key.
pub const MARKER_KEY: u32 = u32::MAX;
/// The length of a marker's payload in bytes: three little-endian words.
pub const MARKER_LENGTH: usize = 24;
/// Marker kind of a begin marker (word 0, bits 7 to 0).
const KIND_BEGIN: u64 = 1;
/// Marker kind of an end marker.
const KIND_END: u64 = 2;

/// A cycle id: 31 bits. Receivers compare ids only for equality, against
/// their one open cycle, so ids have no order and wrap freely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct CycleId(u32);

impl CycleId {
    /// The largest id.
    pub const MAX: Self = Self((1 << 31) - 1);

    /// The id `value`, or `None` above [`CycleId::MAX`].
    #[must_use]
    pub const fn new(value: u32) -> Option<Self> {
        if value <= Self::MAX.0 {
            Some(Self(value))
        } else {
            None
        }
    }

    /// The id as a number.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// The id after this one, wrapping from [`CycleId::MAX`] to 0.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(if self.0 == Self::MAX.0 { 0 } else { self.0 + 1 })
    }
}

/// What a cycle carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Scope {
    /// The keys the publisher chooses.
    Refresh,
    /// Every key the publisher holds.
    Snapshot,
}

impl Scope {
    const fn code(self) -> u64 {
        match self {
            Self::Refresh => 0,
            Self::Snapshot => 1,
        }
    }

    const fn from_code(code: u64) -> Option<Self> {
        match code {
            0 => Some(Self::Refresh),
            1 => Some(Self::Snapshot),
            _ => None,
        }
    }
}

/// A reserved value as a table that opts into cycles reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reserved {
    /// A live value of `key`; the caller checks the key against its table.
    Live {
        /// The key.
        key: u32,
    },
    /// A refresh value of `key` in cycle `cycle`.
    Value {
        /// The cycle.
        cycle: CycleId,
        /// The key; the caller checks it against its table.
        key: u32,
    },
    /// A marker of cycle `cycle`, whose payload says which.
    Marker {
        /// The cycle.
        cycle: CycleId,
    },
    /// Neither: a negative value with bit 63 clear cannot happen, so this is
    /// a live value above `u32::MAX`.
    Invalid,
}

impl Reserved {
    /// Reads `reserved_value`.
    #[must_use]
    pub const fn read(reserved_value: i64) -> Self {
        let bits = reserved_value.cast_unsigned();
        // The masks keep 32 and 31 bits, so the casts are exact.
        #[allow(clippy::cast_possible_truncation, reason = "masked to 32 bits")]
        let key = (bits & KEY_BITS) as u32;
        if bits & CYCLE_BIT == 0 {
            return if bits >> 32 == 0 {
                Self::Live { key }
            } else {
                Self::Invalid
            };
        }
        #[allow(clippy::cast_possible_truncation, reason = "masked to 31 bits")]
        let cycle = CycleId(((bits & !CYCLE_BIT) >> 32) as u32);
        if key == MARKER_KEY {
            Self::Marker { cycle }
        } else {
            Self::Value { cycle, key }
        }
    }
}

/// The reserved value of a refresh value of `key` in `cycle`, or `None` for
/// [`MARKER_KEY`].
#[must_use]
pub const fn value(cycle: CycleId, key: u32) -> Option<i64> {
    if key == MARKER_KEY {
        return None;
    }
    Some((CYCLE_BIT | (cycle.0 as u64) << 32 | key as u64).cast_signed())
}

/// The reserved value of a marker of `cycle`.
#[must_use]
pub const fn marker(cycle: CycleId) -> i64 {
    (CYCLE_BIT | (cycle.0 as u64) << 32 | MARKER_KEY as u64).cast_signed()
}

/// A marker's payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Marker {
    /// A cycle begins at this marker's position.
    Begin {
        /// What the cycle carries.
        scope: Scope,
    },
    /// The cycle that began at `begin` ends at this marker's position.
    End {
        /// What the cycle carried, as its begin marker said.
        scope: Scope,
        /// The begin marker's position in the lane.
        begin: u64,
        /// The number of refresh values the publisher offered in the cycle.
        values: u64,
    },
}

impl Marker {
    /// The payload: word 0 holds the kind (bits 7 to 0) and the scope (bits
    /// 15 to 8); an end marker's words 1 and 2 hold its begin position and
    /// its count, a begin marker's are 0.
    #[must_use]
    pub fn encode(&self) -> [u8; MARKER_LENGTH] {
        let (kind, scope, begin, values) = match *self {
            Self::Begin { scope } => (KIND_BEGIN, scope, 0, 0),
            Self::End {
                scope,
                begin,
                values,
            } => (KIND_END, scope, begin, values),
        };
        let mut out = [0u8; MARKER_LENGTH];
        for (chunk, word) in
            out.as_chunks_mut::<8>()
                .0
                .iter_mut()
                .zip([kind | scope.code() << 8, begin, values])
        {
            *chunk = word.to_le_bytes();
        }
        out
    }

    /// Reads a payload, or `None` for any length but [`MARKER_LENGTH`], an
    /// unknown kind or scope, a reserved bit set, or a begin marker whose
    /// words 1 and 2 are not 0.
    #[must_use]
    pub fn decode(payload: &[u8]) -> Option<Self> {
        let (words, []) = payload.as_chunks::<8>() else {
            return None;
        };
        let [head, begin, values] = words else {
            return None;
        };
        let [head, begin, values] = [head, begin, values].map(|word| u64::from_le_bytes(*word));
        if head >> 16 != 0 {
            return None;
        }
        let scope = Scope::from_code(head >> 8)?;
        match head & 0xFF {
            KIND_BEGIN if begin == 0 && values == 0 => Some(Self::Begin { scope }),
            KIND_END => Some(Self::End {
                scope,
                begin,
                values,
            }),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests, as ADR-0007 allows")]

    use super::*;

    /// ADR-0080's encoding, both ways, at the edges of each field.
    #[test]
    fn reserved_values_follow_the_encoding() {
        assert_eq!(Reserved::read(0), Reserved::Live { key: 0 });
        assert_eq!(
            Reserved::read(i64::from(u32::MAX)),
            Reserved::Live { key: u32::MAX }
        );
        assert_eq!(Reserved::read(1 << 32), Reserved::Invalid);
        assert_eq!(Reserved::read(i64::MAX), Reserved::Invalid);
        for cycle in [CycleId::default(), CycleId::new(7).unwrap(), CycleId::MAX] {
            for key in [0, 1, MARKER_KEY - 1] {
                let encoded = value(cycle, key).unwrap();
                assert!(encoded < 0);
                assert_eq!(Reserved::read(encoded), Reserved::Value { cycle, key });
            }
            assert_eq!(value(cycle, MARKER_KEY), None);
            assert_eq!(Reserved::read(marker(cycle)), Reserved::Marker { cycle });
        }
        assert_eq!(marker(CycleId::MAX), -1);
        assert_eq!(
            Reserved::read(i64::MIN),
            Reserved::Value {
                cycle: CycleId::default(),
                key: 0
            }
        );
    }

    /// Ids are 31 bits and wrap.
    #[test]
    fn cycle_ids_wrap() {
        assert_eq!(CycleId::new(1 << 31), None);
        assert_eq!(CycleId::MAX.get(), (1 << 31) - 1);
        assert_eq!(CycleId::MAX.next(), CycleId::default());
        assert_eq!(CycleId::new(4).unwrap().next().get(), 5);
    }

    /// Markers round trip; any other length, kind, scope or reserved bit is
    /// refused, and a begin marker carries no position or count.
    #[test]
    fn markers_are_decoded_strictly() {
        for marker in [
            Marker::Begin {
                scope: Scope::Refresh,
            },
            Marker::Begin {
                scope: Scope::Snapshot,
            },
            Marker::End {
                scope: Scope::Snapshot,
                begin: 4096,
                values: u64::MAX,
            },
        ] {
            assert_eq!(Marker::decode(&marker.encode()), Some(marker));
        }
        let good = Marker::End {
            scope: Scope::Refresh,
            begin: 64,
            values: 3,
        }
        .encode();
        assert_eq!(Marker::decode(&good[..16]), None);
        assert_eq!(Marker::decode(&[good.as_slice(), &[0; 8]].concat()), None);
        for (at, byte) in [(0, 3), (0, 0), (1, 2), (2, 1), (7, 1)] {
            let mut bad = good;
            bad[at] = byte;
            assert_eq!(Marker::decode(&bad), None, "byte {at} = {byte}");
        }
        let mut begin = Marker::Begin {
            scope: Scope::Refresh,
        }
        .encode();
        begin[8] = 1;
        assert_eq!(Marker::decode(&begin), None);
    }
}
