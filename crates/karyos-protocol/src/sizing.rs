// SPDX-License-Identifier: Apache-2.0

//! Term lengths, MTU and message sizing (SPEC.md §4, log buffer layout and
//! message sizes). All arithmetic is checked.

use crate::error::ProtocolError;
use crate::frame::{FRAME_ALIGNMENT, Flags};

/// Smallest term length (64 KiB).
pub const MIN_TERM_LENGTH: u32 = 64 * 1024;
/// Largest term length (1 GiB).
pub const MAX_TERM_LENGTH: u32 = 1024 * 1024 * 1024;
/// Default MTU: Karyos frame bytes per datagram.
pub const DEFAULT_MTU: u32 = 1408;

/// Length of one term partition: a power of two from 64 KiB to 1 GiB.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TermLength(u32);

impl TermLength {
    /// Validates a term length.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::InvalidTermLength`] when `value` is not a
    /// power of two in `65536..=1073741824`.
    #[inline]
    pub const fn try_new(value: u32) -> Result<Self, ProtocolError> {
        if value.is_power_of_two() && value >= MIN_TERM_LENGTH && value <= MAX_TERM_LENGTH {
            Ok(Self(value))
        } else {
            Err(ProtocolError::InvalidTermLength { value })
        }
    }

    /// The length in bytes.
    #[inline]
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// The largest allowed `max_reserved_length`: `term_length / 8`.
    #[inline]
    #[must_use]
    pub const fn max_reserved_limit(self) -> u32 {
        self.0 / 8
    }
}

/// Rounds `value` up to the frame alignment.
///
/// # Errors
///
/// Returns [`ProtocolError::LengthOverflow`] when the result exceeds `u32`.
#[inline]
pub const fn align_frame(value: u32) -> Result<u32, ProtocolError> {
    match value.checked_next_multiple_of(FRAME_ALIGNMENT) {
        Some(aligned) => Ok(aligned),
        None => Err(ProtocolError::LengthOverflow {
            value: value as u64,
        }),
    }
}

/// `frame_length = header_length(flags) + payload_length`.
///
/// # Errors
///
/// Returns [`ProtocolError::LengthOverflow`] when the sum exceeds `i32::MAX`,
/// the largest committed `frame_length`.
#[inline]
pub const fn frame_length(flags: Flags, payload_length: u32) -> Result<u32, ProtocolError> {
    match flags.header_length().checked_add(payload_length) {
        Some(length) if length <= i32::MAX as u32 => Ok(length),
        _ => Err(ProtocolError::LengthOverflow {
            value: payload_length as u64,
        }),
    }
}

/// `reserved_length = align_up(frame_length, 32)`: the bytes a frame occupies
/// in a term.
///
/// # Errors
///
/// Returns [`ProtocolError::LengthOverflow`] on overflow.
#[inline]
pub const fn reserved_length(flags: Flags, payload_length: u32) -> Result<u32, ProtocolError> {
    match frame_length(flags, payload_length) {
        Ok(length) => align_frame(length),
        Err(err) => Err(err),
    }
}

/// Fragmentation of messages for one MTU and header length.
///
/// This is arithmetic only. It does not enforce the channel's MTU limits
/// (default 1408, jumbo frames up to 8 KiB) or that every result fits a
/// positive `i32` wire length; channel and publication validation gate those
/// before a plan is used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FragmentPlan {
    header_length: u32,
    payload_per_fragment: u32,
    full_fragment_reserved: u32,
}

impl FragmentPlan {
    /// Plans fragments of at most `mtu` bytes with the header of `flags`.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::InvalidMtu`] when `align_down(mtu, 32)` leaves
    /// no room for the header and one payload byte.
    pub const fn new(mtu: u32, flags: Flags) -> Result<Self, ProtocolError> {
        let header_length = flags.header_length();
        let aligned_mtu = mtu - mtu % FRAME_ALIGNMENT;
        let payload_per_fragment = match aligned_mtu.checked_sub(header_length) {
            Some(c) if c >= 1 => c,
            _ => {
                return Err(ProtocolError::InvalidMtu {
                    value: mtu,
                    header_length,
                });
            }
        };
        // header + c = aligned_mtu, already a multiple of 32.
        Ok(Self {
            header_length,
            payload_per_fragment,
            full_fragment_reserved: aligned_mtu,
        })
    }

    /// Payload bytes per full fragment (`c`).
    #[inline]
    #[must_use]
    pub const fn payload_per_fragment(self) -> u32 {
        self.payload_per_fragment
    }

    /// Number of fragments for a message of `length` bytes. A length of 0 is
    /// one header-only fragment, the size of a header-only DATA heartbeat;
    /// whether `offer` accepts an empty application message is decided by the
    /// publication API, not here.
    #[inline]
    #[must_use]
    pub const fn fragments(self, length: u32) -> u32 {
        if length == 0 {
            1
        } else {
            length.div_ceil(self.payload_per_fragment)
        }
    }

    /// Bytes a message of `length` bytes reserves in a term:
    /// `(n - 1) × align_up(h + c, 32) + align_up(h + L - (n - 1) × c, 32)`.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::LengthOverflow`] when the result exceeds
    /// `u32`.
    pub const fn reserved(self, length: u32) -> Result<u32, ProtocolError> {
        let overflow = ProtocolError::LengthOverflow {
            value: length as u64,
        };
        let full = self.fragments(length) - 1;
        let Some(full_bytes) = full.checked_mul(self.full_fragment_reserved) else {
            return Err(overflow);
        };
        // `full * c <= length` by construction of `fragments`.
        let last_payload = length - full * self.payload_per_fragment;
        let Some(last_frame) = self.header_length.checked_add(last_payload) else {
            return Err(overflow);
        };
        let last = match align_frame(last_frame) {
            Ok(last) => last,
            Err(err) => return Err(err),
        };
        match full_bytes.checked_add(last) {
            Some(total) => Ok(total),
            None => Err(overflow),
        }
    }

    /// The largest message length `L` with `reserved(L) <= max_reserved`.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::InvalidMaxReservedLength`] when
    /// `max_reserved` cannot hold a one-byte message or exceeds
    /// `term_length / 8`.
    pub const fn max_message_length(
        self,
        max_reserved: u32,
        term_length: TermLength,
    ) -> Result<u32, ProtocolError> {
        let limit = term_length.max_reserved_limit();
        let invalid = ProtocolError::InvalidMaxReservedLength {
            value: max_reserved,
            limit,
        };
        let smallest = match align_frame(self.header_length + 1) {
            Ok(smallest) => smallest,
            Err(err) => return Err(err),
        };
        if max_reserved > limit || max_reserved < smallest {
            return Err(invalid);
        }
        // Use as many full fragments as leave room for a last fragment with
        // at least one payload byte, then fill the last fragment.
        let full = (max_reserved - smallest) / self.full_fragment_reserved;
        let room = max_reserved - full * self.full_fragment_reserved;
        let aligned_room = room - room % FRAME_ALIGNMENT;
        let last = aligned_room - self.header_length;
        let last = if last < self.payload_per_fragment {
            last
        } else {
            self.payload_per_fragment
        };
        Ok(full * self.payload_per_fragment + last)
    }

    /// Checks a message against `max_message_length`.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::MessageTooLarge`] when `length > max`.
    #[inline]
    pub const fn check_message(length: u32, max: u32) -> Result<(), ProtocolError> {
        if length <= max {
            Ok(())
        } else {
            Err(ProtocolError::MessageTooLarge { length, max })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::Lane;

    fn ext() -> Flags {
        Flags::new(false, false, false, true, Lane::default())
    }

    #[test]
    fn term_length_bounds() {
        assert!(TermLength::try_new(MIN_TERM_LENGTH).is_ok());
        assert!(TermLength::try_new(MAX_TERM_LENGTH).is_ok());
        for bad in [0, 32 * 1024, 96 * 1024, 2 * MAX_TERM_LENGTH] {
            assert!(TermLength::try_new(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn frame_and_reserved_lengths() {
        assert_eq!(frame_length(Flags::NONE, 0), Ok(32));
        assert_eq!(reserved_length(Flags::NONE, 1), Ok(64));
        assert_eq!(reserved_length(Flags::NONE, 32), Ok(64));
        assert_eq!(reserved_length(ext(), 1), Ok(128));
        assert!(frame_length(Flags::NONE, i32::MAX as u32).is_err());
    }

    /// The worked example of SPEC.md §4, message sizes.
    #[test]
    fn spec_example_64k_terms_mtu_1408() {
        let term = TermLength::try_new(64 * 1024).unwrap();
        let plan = FragmentPlan::new(DEFAULT_MTU, Flags::NONE).unwrap();
        assert_eq!(plan.payload_per_fragment(), 1376);
        assert_eq!(plan.fragments(8192), 6);
        assert_eq!(plan.reserved(8192), Ok(8384));
        assert_eq!(plan.reserved(8000), Ok(8192));
        let max = plan
            .max_message_length(term.max_reserved_limit(), term)
            .unwrap();
        assert_eq!(max, 8000);
        assert_eq!(FragmentPlan::check_message(8000, max), Ok(()));
        assert_eq!(
            FragmentPlan::check_message(8001, max),
            Err(ProtocolError::MessageTooLarge {
                length: 8001,
                max: 8000
            })
        );
    }

    #[test]
    fn spec_example_with_trace_extension() {
        let term = TermLength::try_new(64 * 1024).unwrap();
        let plan = FragmentPlan::new(DEFAULT_MTU, ext()).unwrap();
        assert_eq!(plan.payload_per_fragment(), 1408 - 96);
        let max = plan
            .max_message_length(term.max_reserved_limit(), term)
            .unwrap();
        assert_eq!(max, 7616);
        assert!(plan.reserved(7616).unwrap() <= 8192);
        assert!(plan.reserved(7617).unwrap() > 8192);
        assert_eq!(plan.reserved(0), Ok(96));
    }

    #[test]
    fn invalid_mtu_and_max_reserved() {
        assert!(FragmentPlan::new(32, Flags::NONE).is_err());
        assert!(FragmentPlan::new(63, Flags::NONE).is_err());
        assert!(FragmentPlan::new(64, Flags::NONE).is_ok());
        assert!(FragmentPlan::new(96, ext()).is_err());
        let term = TermLength::try_new(64 * 1024).unwrap();
        let plan = FragmentPlan::new(DEFAULT_MTU, Flags::NONE).unwrap();
        assert!(plan.max_message_length(63, term).is_err());
        assert!(plan.max_message_length(8193, term).is_err());
        assert_eq!(plan.max_message_length(64, term), Ok(32));
    }

    /// The closed form agrees with a brute-force search over small sizes.
    #[test]
    fn max_message_length_matches_brute_force() {
        let term = TermLength::try_new(MIN_TERM_LENGTH).unwrap();
        for flags in [Flags::NONE, ext()] {
            for mtu in [128, 160, 200, 1408, 4096] {
                let Ok(plan) = FragmentPlan::new(mtu, flags) else {
                    continue;
                };
                for max_reserved in (128..=term.max_reserved_limit()).step_by(96) {
                    let closed = plan.max_message_length(max_reserved, term).unwrap();
                    assert!(plan.reserved(closed).unwrap() <= max_reserved);
                    let mut brute = 0;
                    while plan.reserved(brute + 1).unwrap() <= max_reserved {
                        brute += 1;
                    }
                    assert_eq!(closed, brute, "mtu {mtu} max_reserved {max_reserved}");
                }
            }
        }
    }

    #[test]
    fn reserved_is_monotonic() {
        let plan = FragmentPlan::new(DEFAULT_MTU, Flags::NONE).unwrap();
        let mut previous = 0;
        for length in 0..20_000 {
            let reserved = plan.reserved(length).unwrap();
            assert!(reserved >= previous);
            assert_eq!(reserved % FRAME_ALIGNMENT, 0);
            previous = reserved;
        }
    }
}
