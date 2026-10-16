// SPDX-License-Identifier: Apache-2.0

//! The local gap record of a receive image (`quantstratum-docs:
//! karyos/design/local-gap-layout.md`, owner decision GP1, coordinator
//! approval ACS 14601 and 14623).
//!
//! A receive owner seals a term-local interval `[s, e)` that no real frame
//! covers with one 32-byte record at `s`: word 0 in the ABORTED pattern
//! (the extent as its positive length, the lane bits only, the local type
//! [`LOCAL_GAP_TYPE`]), then the base header's term offset, session,
//! stream and term id, then a word of its own: [`GAP_VERSION`], a
//! [`GapReason`] and six zero bytes. The rest of the interval is never
//! written or read.
//!
//! The type code lies in the range `0xFF00..=0xFFFF` that SPEC.md §5
//! reserves for records local to an image; it is not a [`FrameType`],
//! so every wire parser refuses it as an unknown type. Only an image
//! created with the `LOCAL_GAPS` capability may hold the record.
//!
//! [`FrameType`]: crate::frame::FrameType

use crate::frame::{FRAME_ALIGNMENT, Flags, Lane, PROTOCOL_VERSION, Word0};

/// The word 0 type of a local gap record.
pub const LOCAL_GAP_TYPE: u16 = 0xFF01;

/// The format version of the record's own word.
pub const GAP_VERSION: u8 = 1;

/// Bytes of the record after word 0: words 1 to 3.
pub const GAP_BODY_LENGTH: usize = 24;

/// Why the receive owner sealed an interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GapReason {
    /// The unreliable reorder interval expired.
    ReorderExpired,
    /// A reliable range was proven unrecoverable (`RANGE_UNAVAILABLE` of
    /// the right incarnation and authority) under a skip policy.
    RangeUnavailable,
}

impl GapReason {
    /// The record's reason code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::ReorderExpired => 1,
            Self::RangeUnavailable => 2,
        }
    }

    /// The reason of `code`; `None` for 0, the reserved `FarWindow` (3) and
    /// every unassigned code.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::ReorderExpired),
            2 => Some(Self::RangeUnavailable),
            _ => None,
        }
    }
}

/// Where a record is, and the image it belongs to: what its header must
/// name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GapSite {
    /// Its offset in the term.
    pub term_offset: u32,
    /// The term's id.
    pub term_id: i32,
    /// The image's session.
    pub session_id: i32,
    /// The image's stream.
    pub stream_id: i32,
}

/// The word 0 of a record of `extent` bytes on `lane`, or `None` when the
/// extent is not a positive multiple of 32 that fits the frame length.
#[must_use]
pub fn gap_word0(extent: u32, lane: Lane) -> Option<Word0> {
    if extent == 0 || !extent.is_multiple_of(FRAME_ALIGNMENT) {
        return None;
    }
    let length = i32::try_from(extent).ok()?;
    let flags = Flags::new(false, false, false, false, lane);
    let raw = u64::from(length.cast_unsigned())
        | (u64::from(PROTOCOL_VERSION) << 32)
        | (u64::from(flags.get()) << 40)
        | (u64::from(LOCAL_GAP_TYPE) << 48);
    Word0::unpack(raw).ok()
}

/// Words 1 to 3 of a record at `site` for `reason`, as the bytes stored
/// after word 0.
#[must_use]
pub fn gap_body(site: GapSite, reason: GapReason) -> [u8; GAP_BODY_LENGTH] {
    let mut body = [0u8; GAP_BODY_LENGTH];
    let fields: [(usize, &[u8]); 6] = [
        (0, &site.term_offset.to_le_bytes()),
        (4, &site.session_id.to_le_bytes()),
        (8, &site.stream_id.to_le_bytes()),
        (12, &site.term_id.to_le_bytes()),
        (16, &[GAP_VERSION]),
        (17, &[reason.code()]),
    ];
    for (at, bytes) in fields {
        if let Some(target) = body.get_mut(at..at + bytes.len()) {
            target.copy_from_slice(bytes);
        }
    }
    body
}

/// Checks a record's word 0 found at `offset` of a term of `term_length`
/// bytes on `lane`: the version, the lane bits only, and a positive
/// extent, multiple of 32, within the term. Returns the extent.
///
/// # Errors
///
/// Returns the reason the word is not a valid record word 0.
pub fn check_word0(
    word0: Word0,
    offset: u32,
    term_length: u32,
    lane: Lane,
) -> Result<u32, &'static str> {
    let flags = word0.flags();
    if word0.frame_type_code() != LOCAL_GAP_TYPE || word0.version() != PROTOCOL_VERSION {
        return Err("local gap type or version");
    }
    if flags.begin() || flags.end() || flags.eos() || flags.ext() || flags.lane() != lane {
        return Err("local gap flags");
    }
    let extent = u32::try_from(word0.frame_length()).map_err(|_| "local gap extent")?;
    if extent == 0
        || !extent.is_multiple_of(FRAME_ALIGNMENT)
        || offset
            .checked_add(extent)
            .is_none_or(|end| end > term_length)
    {
        return Err("local gap extent");
    }
    Ok(extent)
}

/// Checks a record's words 1 to 3 against `site`. Returns its reason.
///
/// # Errors
///
/// Returns the reason the body is not a valid record for `site`: a field
/// that disagrees with the site, an unknown version or reason, or a
/// nonzero reserved byte.
pub fn check_body(body: &[u8; GAP_BODY_LENGTH], site: GapSite) -> Result<GapReason, &'static str> {
    let (fields, own) = body.split_at(16);
    if fields
        != gap_body(site, GapReason::ReorderExpired)
            .get(..16)
            .unwrap_or(&[])
    {
        return Err("local gap site");
    }
    let [version, reason, reserved @ ..] = own else {
        return Err("local gap body");
    };
    if *version != GAP_VERSION {
        return Err("local gap version");
    }
    if reserved.iter().any(|byte| *byte != 0) {
        return Err("local gap reserved bytes");
    }
    GapReason::from_code(*reason).ok_or("local gap reason")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::FrameType;

    const SITE: GapSite = GapSite {
        term_offset: 96,
        term_id: -7,
        session_id: 5,
        stream_id: -2,
    };

    #[test]
    fn a_record_round_trips() {
        let lane = Lane::try_new(2).unwrap();
        let word0 = gap_word0(128, lane).unwrap();
        assert_eq!(word0.frame_type_code(), LOCAL_GAP_TYPE);
        assert_eq!(check_word0(word0, 96, 1024, lane), Ok(128));
        for reason in [GapReason::ReorderExpired, GapReason::RangeUnavailable] {
            assert_eq!(check_body(&gap_body(SITE, reason), SITE), Ok(reason));
        }
        // Not a wire frame type.
        assert!(FrameType::try_from_code(LOCAL_GAP_TYPE).is_err());
    }

    #[test]
    fn the_word0_is_checked() {
        let lane = Lane::ZERO;
        assert_eq!(gap_word0(0, lane), None);
        assert_eq!(gap_word0(40, lane), None);
        let word0 = gap_word0(64, lane).unwrap();
        // Past the term end, another lane, a frame flag, another version.
        assert!(check_word0(word0, 992, 1024, lane).is_err());
        assert!(check_word0(word0, 0, 1024, Lane::try_new(1).unwrap()).is_err());
        let with_begin = Word0::unpack(word0.pack() | (1 << 40)).unwrap();
        assert!(check_word0(with_begin, 0, 1024, lane).is_err());
        let version = Word0::unpack(word0.pack() ^ (1 << 33)).unwrap();
        assert!(check_word0(version, 0, 1024, lane).is_err());
        assert_eq!(check_word0(word0, 960, 1024, lane), Ok(64));
    }

    #[test]
    fn the_body_is_checked() {
        let good = gap_body(SITE, GapReason::RangeUnavailable);
        for other in [
            GapSite {
                term_offset: 128,
                ..SITE
            },
            GapSite { term_id: 8, ..SITE },
            GapSite {
                session_id: 6,
                ..SITE
            },
            GapSite {
                stream_id: 3,
                ..SITE
            },
        ] {
            assert_eq!(check_body(&good, other), Err("local gap site"));
        }
        for (at, value, error) in [
            (16, 2, "local gap version"),
            (17, 0, "local gap reason"),
            (17, 3, "local gap reason"),
            (23, 1, "local gap reserved bytes"),
        ] {
            let mut bad = good;
            bad[at] = value;
            assert_eq!(check_body(&bad, SITE), Err(error));
        }
    }
}
