// SPDX-License-Identifier: Apache-2.0

//! Binary vectors and property tests of stage 1 validation
//! (`quantstratum-docs: karyos/design/receive-publication.md`, tests
//! "Validation leaves the image untouched" and "MTU and strides"). The
//! property tests over arbitrary and mutated bytes are the parser's fuzz
//! harness until coverage-guided fuzzing is decided (issue #11).

#![allow(clippy::indexing_slicing, clippy::unwrap_used)]

use proptest::prelude::*;

use super::*;
use crate::frame::{EXTENSION_VERSION, FrameType};

const SESSION: i32 = 7;
const STREAM: i32 = 9;
const TERM: u32 = 64 * 1024;
const MTU: u32 = 1408;

fn params() -> ImageParams {
    ImageParams::new(SESSION, STREAM, 2, TermLength::try_new(TERM).unwrap(), MTU).unwrap()
}

fn header(word0: Word0, term_offset: i32, term_id: u32, reserved_value: i64) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&word0.pack().to_le_bytes());
    out.extend_from_slice(&term_offset.to_le_bytes());
    out.extend_from_slice(&SESSION.to_le_bytes());
    out.extend_from_slice(&STREAM.to_le_bytes());
    out.extend_from_slice(&term_id.to_le_bytes());
    out.extend_from_slice(&reserved_value.to_le_bytes());
    out
}

fn extension() -> Vec<u8> {
    let mut ext = vec![0u8; 64];
    ext[0] = EXTENSION_VERSION;
    ext[4..8].copy_from_slice(&64u32.to_le_bytes());
    ext[8..16].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
    ext
}

/// A DATA frame with `payload` bytes, padded to 32 unless `pad` is false.
fn data(term_offset: u32, payload: usize, flags: Flags, pad: bool) -> Vec<u8> {
    let length = flags.header_length() as usize + payload;
    let word0 = Word0::new(length as i32, flags, FrameType::Data);
    let mut out = header(word0, term_offset as i32, 3, 0x55);
    if flags.ext() {
        out.extend(extension());
    }
    out.extend((0..payload).map(|i| (i % 251) as u8));
    if pad {
        out.resize(length.next_multiple_of(32), 0);
    }
    out
}

fn record(frame_type: FrameType, term_offset: u32, extent: i64, lane: u8) -> Vec<u8> {
    let flags = Flags::new(false, false, false, false, Lane::try_new(lane).unwrap());
    header(
        Word0::new(32, flags, frame_type),
        term_offset as i32,
        3,
        extent,
    )
}

fn whole() -> Flags {
    Flags::new(true, true, false, false, Lane::ZERO)
}

fn frames(bytes: &[u8]) -> Vec<Item<'_>> {
    ValidatedDatagram::parse(bytes, &params())
        .unwrap()
        .items()
        .collect()
}

fn rejected(bytes: &[u8]) -> ParseError {
    ValidatedDatagram::parse(bytes, &params()).unwrap_err()
}

#[test]
fn a_data_frame_is_accepted_with_its_image_values() {
    let bytes = data(4096, 100, whole(), true);
    let items = frames(&bytes);
    assert_eq!(items.len(), 1);
    let Item::Frame(frame) = items[0] else {
        panic!("not a frame")
    };
    assert_eq!(frame.kind(), FrameKind::Data);
    assert_eq!(frame.term_offset(), 4096);
    assert_eq!(frame.term_id(), TermId::new(3));
    assert_eq!(frame.extent(), 160);
    assert_eq!(frame.image_word0().pack().to_le_bytes(), bytes[..8]);
    assert_eq!(frame.body(), &bytes[8..132]);
}

#[test]
fn a_batch_uses_the_wire_stride_of_each_frame() {
    let mut bytes = data(0, 40, whole(), true);
    bytes.extend(record(FrameType::Aborted, 96, 4096, 0));
    bytes.extend(data(4192, 1, whole(), false));
    let items = frames(&bytes);
    assert_eq!(items.len(), 3);
    let Item::Frame(aborted) = items[1] else {
        panic!("not a frame")
    };
    assert_eq!(aborted.kind(), FrameKind::Aborted);
    assert_eq!(aborted.extent(), 4096);
    assert_eq!(aborted.image_word0().frame_length(), 4096);
    assert_eq!(aborted.body(), &bytes[104..128]);
    let Item::Frame(last) = items[2] else {
        panic!("not a frame")
    };
    assert_eq!(last.term_offset(), 4192);
    assert_eq!(last.body().len(), 25);
}

#[test]
fn a_header_only_data_frame_is_a_heartbeat() {
    let bytes = data(64, 0, Flags::NONE, true);
    assert!(matches!(frames(&bytes)[..], [Item::Heartbeat(h)] if h.term_offset() == 64));
    let ext = Flags::new(false, false, false, true, Lane::ZERO);
    assert!(matches!(
        frames(&data(64, 0, ext, true))[..],
        [Item::Heartbeat(_)]
    ));
}

#[test]
fn a_traced_frame_needs_a_valid_extension() {
    let ext = Flags::new(true, true, false, true, Lane::ZERO);
    let good = data(0, 10, ext, true);
    assert!(matches!(frames(&good)[..], [Item::Frame(f)] if f.body().len() == 24 + 64 + 10));
    let cases: [(usize, u8, ExtensionFault); 4] = [
        (32, 2, ExtensionFault::Version),
        (33, 1, ExtensionFault::Reserved),
        (36, 65, ExtensionFault::Length),
        (95, 1, ExtensionFault::Reserved),
    ];
    for (at, value, fault) in cases {
        let mut bad = good.clone();
        bad[at] = value;
        assert_eq!(rejected(&bad), ParseError::Extension { offset: 0, fault });
    }
    let mut flags = good.clone();
    flags[34] = 1;
    assert_eq!(
        rejected(&flags),
        ParseError::Extension {
            offset: 0,
            fault: ExtensionFault::Flags
        }
    );
}

#[test]
fn pad_and_aborted_records_are_checked() {
    let pad = record(FrameType::Pad, TERM - 256, 256, 1);
    let [Item::Frame(frame)] = frames(&pad)[..] else {
        panic!("not one frame")
    };
    assert_eq!(frame.kind(), FrameKind::Pad);
    assert_eq!(frame.image_word0().frame_length(), 256);
    assert_eq!(frame.lane().get(), 1);

    let short_pad = record(FrameType::Pad, TERM - 256, 128, 0);
    assert!(matches!(rejected(&short_pad), ParseError::Extent { .. }));
    for extent in [0, -32, 48, i64::from(TERM) + 32, i64::MAX] {
        let bad = record(FrameType::Aborted, 0, extent, 0);
        assert!(
            matches!(rejected(&bad), ParseError::Extent { .. }),
            "{extent}"
        );
    }
    let past = record(FrameType::Aborted, TERM - 64, 96, 0);
    assert!(matches!(rejected(&past), ParseError::Extent { .. }));

    let mut long = record(FrameType::Aborted, 0, 64, 0);
    long[0] = 64;
    long.resize(64, 0);
    assert!(matches!(rejected(&long), ParseError::FrameLength { .. }));
    let mut begin = record(FrameType::Aborted, 0, 64, 0);
    begin[5] |= 0x01;
    assert!(matches!(rejected(&begin), ParseError::RecordFlags { .. }));
}

#[test]
fn the_mtu_bounds_the_datagram() {
    let exact = data(0, MTU as usize - 32, whole(), false);
    assert_eq!(exact.len(), MTU as usize);
    assert_eq!(frames(&exact).len(), 1);

    let mut over = data(0, 64, whole(), true);
    over.resize(MTU as usize + 1, 0);
    assert_eq!(
        rejected(&over),
        ParseError::TooLong {
            length: MTU as usize + 1,
            mtu: MTU
        }
    );
    assert_eq!(rejected(&[]), ParseError::Empty);
}

#[test]
fn one_bad_frame_rejects_the_whole_datagram() {
    let mut bytes = data(0, 40, whole(), true);
    let mut second = data(96, 40, whole(), true);
    second[16] ^= 0xff;
    bytes.extend(second);
    assert!(matches!(
        rejected(&bytes),
        ParseError::Stream { offset: 96, .. }
    ));

    let mut tail = data(0, 40, whole(), true);
    tail.extend([0u8; 16]);
    assert_eq!(rejected(&tail), ParseError::Truncated { offset: 96 });
}

#[test]
fn header_fields_are_checked() {
    let good = data(64, 40, whole(), true);
    let with = |at: usize, bytes: &[u8]| {
        let mut out = good.clone();
        out[at..at + bytes.len()].copy_from_slice(bytes);
        out
    };
    assert!(matches!(
        rejected(&with(4, &[2])),
        ParseError::Version { version: 2, .. }
    ));
    assert!(matches!(
        rejected(&with(5, &[0x43])),
        ParseError::ReservedFlags { .. }
    ));
    assert!(matches!(
        rejected(&with(5, &[0x23])),
        ParseError::Lane { lane: 2, .. }
    ));
    assert!(matches!(
        rejected(&with(6, &FrameType::Sm.code().to_le_bytes())),
        ParseError::FrameType { code: 0x03, .. }
    ));
    assert!(matches!(
        rejected(&with(6, &[0x09, 0])),
        ParseError::FrameType { code: 0x09, .. }
    ));
    assert!(matches!(
        rejected(&with(12, &[0; 4])),
        ParseError::Session { .. }
    ));
    for term_offset in [-32i32, 48, TERM as i32] {
        assert!(matches!(
            rejected(&with(8, &term_offset.to_le_bytes())),
            ParseError::TermOffset { .. }
        ));
    }
    assert!(matches!(
        rejected(&with(0, &31i32.to_le_bytes())),
        ParseError::FrameLength { .. }
    ));
    assert!(matches!(
        rejected(&with(0, &(-72i32).to_le_bytes())),
        ParseError::FrameLength { .. }
    ));
    assert!(matches!(
        rejected(&with(0, &500i32.to_le_bytes())),
        ParseError::PastDatagram { .. }
    ));
    let end = data(TERM - 32, 40, whole(), true);
    assert_eq!(rejected(&end), ParseError::PastTermEnd { offset: 0 });
}

#[test]
fn image_params_are_validated() {
    let term = TermLength::try_new(TERM).unwrap();
    assert!(ImageParams::new(1, 1, 0, term, MTU).is_err());
    assert!(ImageParams::new(1, 1, 5, term, MTU).is_err());
    assert!(ImageParams::new(1, 1, 4, term, 32).is_err());
    assert!(ImageParams::new(1, 1, 4, term, 64).is_ok());
}

/// A frame to place in a generated datagram.
#[derive(Debug, Clone)]
enum Spec {
    Data { payload: usize, ext: bool, lane: u8 },
    Aborted { extent_units: u32, lane: u8 },
    Heartbeat,
}

fn spec() -> impl Strategy<Value = Spec> {
    prop_oneof![
        (1usize..400, any::<bool>(), 0u8..2).prop_map(|(payload, ext, lane)| Spec::Data {
            payload,
            ext,
            lane
        }),
        (1u32..64, 0u8..2).prop_map(|(extent_units, lane)| Spec::Aborted { extent_units, lane }),
        Just(Spec::Heartbeat),
    ]
}

/// Builds a datagram of the specs that fit the MTU, with consecutive term
/// offsets from 0, and the expected (kind, term offset, extent) per item.
/// Expected item: frame kind (`None` for a heartbeat), term offset, extent.
type Expected = (Option<FrameKind>, u32, u32);

fn build(specs: &[Spec]) -> (Vec<u8>, Vec<Expected>) {
    let mut bytes = Vec::new();
    let mut expected = Vec::new();
    let mut term_offset = 0u32;
    for spec in specs {
        let (frame, kind, extent) = match *spec {
            Spec::Data { payload, ext, lane } => {
                let flags = Flags::new(true, true, false, ext, Lane::try_new(lane).unwrap());
                let length = flags.header_length() + payload as u32;
                (
                    data(term_offset, payload, flags, true),
                    Some(FrameKind::Data),
                    length.next_multiple_of(32),
                )
            }
            Spec::Aborted { extent_units, lane } => (
                record(
                    FrameType::Aborted,
                    term_offset,
                    i64::from(extent_units * 32),
                    lane,
                ),
                Some(FrameKind::Aborted),
                extent_units * 32,
            ),
            Spec::Heartbeat => (data(term_offset, 0, Flags::NONE, true), None, 32),
        };
        if bytes.len() + frame.len() > MTU as usize {
            break;
        }
        bytes.extend(frame);
        expected.push((kind, term_offset, extent));
        term_offset += extent;
    }
    (bytes, expected)
}

/// Every accepted frame lies inside its term and its datagram.
fn check_invariants(bytes: &[u8]) {
    let Ok(datagram) = ValidatedDatagram::parse(bytes, &params()) else {
        return;
    };
    for item in datagram.items() {
        if let Item::Frame(frame) = item {
            assert_eq!(frame.term_offset() % 32, 0);
            assert_eq!(frame.extent() % 32, 0);
            assert!(frame.extent() > 0);
            assert!(frame.term_offset() + frame.extent() <= TERM);
            assert!(frame.body().len() + 8 <= bytes.len());
            assert!(frame.body().len() + 8 <= frame.extent() as usize);
            assert!(frame.image_word0().frame_length() > 0);
        }
    }
}

/// Under Miri, fewer cases and no failure file (Miri's isolation forbids
/// the file system access that persistence needs).
fn config() -> ProptestConfig {
    if cfg!(miri) {
        ProptestConfig {
            cases: 8,
            failure_persistence: None,
            ..ProptestConfig::default()
        }
    } else {
        ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn generated_datagrams_parse_to_their_frames(specs in prop::collection::vec(spec(), 1..12)) {
        let (bytes, expected) = build(&specs);
        prop_assume!(!bytes.is_empty());
        let datagram = ValidatedDatagram::parse(&bytes, &params()).unwrap();
        let items: Vec<_> = datagram.items().collect();
        prop_assert_eq!(items.len(), expected.len());
        for (item, (kind, term_offset, extent)) in items.iter().zip(expected) {
            match (item, kind) {
                (Item::Frame(frame), Some(kind)) => {
                    prop_assert_eq!(frame.kind(), kind);
                    prop_assert_eq!(frame.term_offset(), term_offset);
                    prop_assert_eq!(frame.extent(), extent);
                }
                (Item::Heartbeat(h), None) => prop_assert_eq!(h.term_offset(), term_offset),
                _ => prop_assert!(false, "item kind differs"),
            }
        }
    }

    #[test]
    fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..1500)) {
        check_invariants(&bytes);
    }

    #[test]
    fn mutated_datagrams_never_panic(
        specs in prop::collection::vec(spec(), 1..12),
        flips in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..4),
    ) {
        let (mut bytes, _) = build(&specs);
        prop_assume!(!bytes.is_empty());
        for (at, value) in flips {
            let at = at.index(bytes.len());
            bytes[at] ^= value;
        }
        check_invariants(&bytes);
    }
}
