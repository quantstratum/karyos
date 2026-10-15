// SPDX-License-Identifier: Apache-2.0

//! Term lengths, MTU and message sizing (SPEC.md §4, log buffer layout and
//! message sizes). All arithmetic is checked.

use crate::error::LayoutError;
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
    /// Returns [`LayoutError::InvalidTermLength`] when `value` is not a
    /// power of two in `65536..=1073741824`.
    #[inline]
    pub const fn try_new(value: u32) -> Result<Self, LayoutError> {
        if value.is_power_of_two() && value >= MIN_TERM_LENGTH && value <= MAX_TERM_LENGTH {
            Ok(Self(value))
        } else {
            Err(LayoutError::InvalidTermLength { value })
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
/// Returns [`LayoutError::LengthOverflow`] when the result exceeds `u32`.
#[inline]
pub const fn align_frame(value: u32) -> Result<u32, LayoutError> {
    match value.checked_next_multiple_of(FRAME_ALIGNMENT) {
        Some(aligned) => Ok(aligned),
        None => Err(LayoutError::LengthOverflow {
            value: value as u64,
        }),
    }
}

/// `frame_length = header_length(flags) + payload_length`.
///
/// # Errors
///
/// Returns [`LayoutError::LengthOverflow`] when the sum exceeds `i32::MAX`,
/// the largest committed `frame_length`.
#[inline]
pub const fn frame_length(flags: Flags, payload_length: u32) -> Result<u32, LayoutError> {
    match flags.header_length().checked_add(payload_length) {
        Some(length) if length <= i32::MAX as u32 => Ok(length),
        _ => Err(LayoutError::LengthOverflow {
            value: payload_length as u64,
        }),
    }
}

/// `reserved_length = align_up(frame_length, 32)`: the bytes a frame occupies
/// in a term.
///
/// # Errors
///
/// Returns [`LayoutError::LengthOverflow`] on overflow.
#[inline]
pub const fn reserved_length(flags: Flags, payload_length: u32) -> Result<u32, LayoutError> {
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
    /// Returns [`LayoutError::InvalidMtu`] when `align_down(mtu, 32)` leaves
    /// no room for the header and one payload byte.
    pub const fn new(mtu: u32, flags: Flags) -> Result<Self, LayoutError> {
        let header_length = flags.header_length();
        let aligned_mtu = mtu - mtu % FRAME_ALIGNMENT;
        let payload_per_fragment = match aligned_mtu.checked_sub(header_length) {
            Some(c) if c >= 1 => c,
            _ => {
                return Err(LayoutError::InvalidMtu {
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
    /// Returns [`LayoutError::LengthOverflow`] when the result exceeds
    /// `u32`.
    pub const fn reserved(self, length: u32) -> Result<u32, LayoutError> {
        let overflow = LayoutError::LengthOverflow {
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
    /// Returns [`LayoutError::InvalidMaxReservedLength`] when
    /// `max_reserved` cannot hold a one-byte message or exceeds
    /// `term_length / 8`.
    pub const fn max_message_length(
        self,
        max_reserved: u32,
        term_length: TermLength,
    ) -> Result<u32, LayoutError> {
        let limit = term_length.max_reserved_limit();
        let invalid = LayoutError::InvalidMaxReservedLength {
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
    /// Returns [`LayoutError::MessageTooLarge`] when `length > max`.
    #[inline]
    pub const fn check_message(length: u32, max: u32) -> Result<(), LayoutError> {
        if length <= max {
            Ok(())
        } else {
            Err(LayoutError::MessageTooLarge { length, max })
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
            Err(LayoutError::MessageTooLarge {
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
        // Under Miri the same check runs on a bounded subset: interpreting the
        // full sweep would take minutes and the code has no unsafe parts.
        let (mtus, step): (&[u32], usize) = if cfg!(miri) {
            (&[160, 1408], 1504)
        } else {
            (&[128, 160, 200, 1408, 4096], 96)
        };
        for flags in [Flags::NONE, ext()] {
            for &mtu in mtus {
                let Ok(plan) = FragmentPlan::new(mtu, flags) else {
                    continue;
                };
                for max_reserved in (128..=term.max_reserved_limit()).step_by(step) {
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
    fn arithmetic_bounds() {
        let largest_aligned = u32::MAX - u32::MAX % FRAME_ALIGNMENT;
        assert_eq!(align_frame(largest_aligned), Ok(largest_aligned));
        assert!(align_frame(largest_aligned + 1).is_err());
        let max_payload = i32::MAX as u32 - 32;
        assert_eq!(frame_length(Flags::NONE, max_payload), Ok(i32::MAX as u32));
        assert!(frame_length(Flags::NONE, max_payload + 1).is_err());
        assert_eq!(reserved_length(Flags::NONE, max_payload), Ok(1 << 31));
        let plan = FragmentPlan::new(DEFAULT_MTU, Flags::NONE).unwrap();
        assert!(plan.reserved(u32::MAX).is_err());
        let max_term = TermLength::try_new(MAX_TERM_LENGTH).unwrap();
        let max = plan
            .max_message_length(max_term.max_reserved_limit(), max_term)
            .unwrap();
        assert!(plan.reserved(max).unwrap() <= max_term.max_reserved_limit());
        assert!(plan.reserved(max + 1).unwrap() > max_term.max_reserved_limit());
        // A budget that is not a multiple of 32 rounds down to whole frames.
        let term = TermLength::try_new(MIN_TERM_LENGTH).unwrap();
        assert_eq!(
            plan.max_message_length(1500, term),
            plan.max_message_length(1472, term)
        );
    }

    #[test]
    fn reserved_is_monotonic() {
        let plan = FragmentPlan::new(DEFAULT_MTU, Flags::NONE).unwrap();
        let mut previous = 0;
        let limit = if cfg!(miri) { 3_000 } else { 20_000 };
        for length in 0..limit {
            let reserved = plan.reserved(length).unwrap();
            assert!(reserved >= previous);
            assert_eq!(reserved % FRAME_ALIGNMENT, 0);
            previous = reserved;
        }
    }
}

/// Layout properties (SPEC.md §13, "Log buffers, codecs": base and EXT64
/// sizing, MTU boundaries, checked arithmetic and fragmentation), checked
/// against an explicit `u64` model of the formulas in SPEC.md §4.
#[cfg(test)]
mod properties {
    use proptest::prelude::*;

    use super::*;
    use crate::frame::Lane;

    fn flags() -> impl Strategy<Value = Flags> {
        (any::<[bool; 4]>(), 0..Lane::COUNT).prop_map(|([begin, end, eos, ext], lane)| {
            Flags::new(begin, end, eos, ext, Lane::try_new(lane).unwrap())
        })
    }

    /// Any `u32`, often near the boundaries where checked arithmetic fails.
    fn length() -> impl Strategy<Value = u32> {
        prop_oneof![
            any::<u32>(),
            0u32..=20_000,
            (i32::MAX as u32 - 200)..=(i32::MAX as u32 + 200),
            (u32::MAX - 200)..=u32::MAX,
        ]
    }

    fn align_model(value: u64) -> u64 {
        value.div_ceil(u64::from(FRAME_ALIGNMENT)) * u64::from(FRAME_ALIGNMENT)
    }

    /// Fragments of a `length`-byte message with `c` payload bytes each, by
    /// walking the message: the reserved bytes of every fragment.
    fn fragment_model(header: u32, c: u32, length: u32) -> Vec<u64> {
        let mut reserved = Vec::new();
        let mut left = u64::from(length);
        loop {
            let payload = left.min(u64::from(c));
            reserved.push(align_model(u64::from(header) + payload));
            left -= payload;
            if left == 0 {
                return reserved;
            }
        }
    }

    proptest! {
        #![proptest_config(crate::receive::tests_config())]

        #[test]
        fn align_frame_is_the_next_multiple_or_overflow(value in length()) {
            let model = align_model(u64::from(value));
            match align_frame(value) {
                Ok(aligned) => prop_assert_eq!(u64::from(aligned), model),
                Err(error) => {
                    prop_assert!(model > u64::from(u32::MAX));
                    prop_assert_eq!(error, LayoutError::LengthOverflow { value: u64::from(value) });
                }
            }
        }

        #[test]
        fn frame_and_reserved_lengths_follow_the_header(flags in flags(), payload in length()) {
            let header = u64::from(if flags.ext() { 96u32 } else { 32 });
            prop_assert_eq!(u64::from(flags.header_length()), header);
            let model = header + u64::from(payload);
            match (frame_length(flags, payload), reserved_length(flags, payload)) {
                (Ok(frame), Ok(reserved)) => {
                    prop_assert!(model <= i32::MAX as u64);
                    prop_assert_eq!(u64::from(frame), model);
                    prop_assert_eq!(u64::from(reserved), align_model(model));
                }
                (Err(frame), Err(reserved)) => {
                    prop_assert!(model > i32::MAX as u64);
                    prop_assert_eq!(frame, reserved);
                }
                (frame, reserved) => prop_assert!(false, "{frame:?} and {reserved:?} disagree"),
            }
        }

        #[test]
        fn a_plan_exists_exactly_when_the_aligned_mtu_holds_a_payload_byte(
            flags in flags(),
            mtu in prop_oneof![any::<u32>(), 0u32..=9000],
        ) {
            let aligned = mtu - mtu % FRAME_ALIGNMENT;
            match FragmentPlan::new(mtu, flags) {
                Ok(plan) => {
                    prop_assert!(aligned > flags.header_length());
                    prop_assert_eq!(plan.payload_per_fragment(), aligned - flags.header_length());
                }
                Err(error) => {
                    prop_assert!(aligned <= flags.header_length());
                    prop_assert_eq!(
                        error,
                        LayoutError::InvalidMtu { value: mtu, header_length: flags.header_length() }
                    );
                }
            }
        }

        #[test]
        fn fragmentation_matches_a_walk_of_the_message(
            flags in flags(),
            mtu in prop_oneof![Just(DEFAULT_MTU), 128u32..=9000],
            length in 0u32..=200_000,
        ) {
            let plan = FragmentPlan::new(mtu, flags).unwrap();
            let c = plan.payload_per_fragment();
            let fragments = fragment_model(flags.header_length(), c, length);
            prop_assert_eq!(plan.fragments(length) as usize, fragments.len());
            // Every fragment fits the aligned MTU; only the last may be short.
            let aligned = u64::from(mtu - mtu % FRAME_ALIGNMENT);
            for (index, reserved) in fragments.iter().enumerate() {
                prop_assert!(*reserved <= aligned);
                prop_assert_eq!(*reserved % u64::from(FRAME_ALIGNMENT), 0);
                if index + 1 < fragments.len() {
                    prop_assert_eq!(*reserved, aligned);
                }
            }
            let total: u64 = fragments.iter().sum();
            prop_assert_eq!(u64::from(plan.reserved(length).unwrap()), total);
            // One more byte never reserves less.
            prop_assert!(plan.reserved(length + 1).unwrap() >= plan.reserved(length).unwrap());
        }

        #[test]
        fn large_reservations_overflow_exactly_past_u32(
            flags in flags(),
            mtu in prop_oneof![Just(DEFAULT_MTU), 128u32..=9000],
            length in length(),
        ) {
            let plan = FragmentPlan::new(mtu, flags).unwrap();
            let c = u64::from(plan.payload_per_fragment());
            let n = u64::from(plan.fragments(length));
            let last = u64::from(length) - (n - 1) * c;
            let model = (n - 1) * u64::from(mtu - mtu % FRAME_ALIGNMENT)
                + align_model(u64::from(flags.header_length()) + last);
            match plan.reserved(length) {
                Ok(reserved) => prop_assert_eq!(u64::from(reserved), model),
                Err(error) => {
                    prop_assert!(model > u64::from(u32::MAX));
                    prop_assert_eq!(error, LayoutError::LengthOverflow { value: u64::from(length) });
                }
            }
        }

        #[test]
        fn the_maximum_message_is_the_largest_that_fits(
            flags in flags(),
            mtu in prop_oneof![Just(DEFAULT_MTU), 128u32..=9000],
            shift in 16u32..=30,
            max_reserved in prop_oneof![0u32..=4096, any::<u32>()],
        ) {
            let term_length = TermLength::try_new(1 << shift).unwrap();
            let plan = FragmentPlan::new(mtu, flags).unwrap();
            let max_reserved = max_reserved % (term_length.max_reserved_limit() + 64);
            let smallest = align_model(u64::from(flags.header_length()) + 1);
            match plan.max_message_length(max_reserved, term_length) {
                Ok(max) => {
                    prop_assert!(u64::from(max_reserved) >= smallest);
                    prop_assert!(max_reserved <= term_length.max_reserved_limit());
                    prop_assert!(plan.reserved(max).unwrap() <= max_reserved);
                    prop_assert!(plan.reserved(max + 1).unwrap() > max_reserved);
                    prop_assert!(FragmentPlan::check_message(max, max).is_ok());
                    prop_assert_eq!(
                        FragmentPlan::check_message(max + 1, max),
                        Err(LayoutError::MessageTooLarge { length: max + 1, max })
                    );
                }
                Err(error) => {
                    prop_assert!(
                        u64::from(max_reserved) < smallest
                            || max_reserved > term_length.max_reserved_limit()
                    );
                    prop_assert_eq!(
                        error,
                        LayoutError::InvalidMaxReservedLength {
                            value: max_reserved,
                            limit: term_length.max_reserved_limit(),
                        }
                    );
                }
            }
        }

        #[test]
        fn term_lengths_are_the_powers_of_two_in_range(value in prop_oneof![any::<u32>(), (16u32..=30).prop_map(|s| 1 << s)]) {
            let valid = value.is_power_of_two() && (MIN_TERM_LENGTH..=MAX_TERM_LENGTH).contains(&value);
            prop_assert_eq!(TermLength::try_new(value).is_ok(), valid);
        }
    }
}
