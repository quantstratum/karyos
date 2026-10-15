// SPDX-License-Identifier: Apache-2.0

//! Receive owner tests on heap terms (`quantstratum-docs: karyos/design/receive-publication.md`,
//! tests "Overlap", "Duplicates", "Stale terms", "Window", "Activation",
//! "Image positions", "Comparison horizon", "ABORTED and PAD", "Arbitrary
//! arrival orders" and the concurrent reader under Miri).

#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::panic)]

use proptest::prelude::*;

use super::*;
use crate::frame::{Flags, FrameType, Word0};
use crate::log_buffer::{DEFAULT_CLAIM_DEADLINE, LogBufferConfig, PollOutcome, Role, SkipReason};
use crate::receive::{Item, ValidatedDatagram};
use crate::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use crate::term::TermId;

const SESSION: i32 = 3;
const STREAM: i32 = 4;
const TERM: u32 = MIN_TERM_LENGTH;
const INITIAL: u32 = u32::MAX - 1;

fn params() -> ImageParams {
    ImageParams::new(
        SESSION,
        STREAM,
        1,
        TermLength::try_new(TERM).unwrap(),
        DEFAULT_MTU,
    )
    .unwrap()
}

fn image(join: u64) -> Arc<LogBuffer<HeapTerms>> {
    Arc::new(
        LogBuffer::new(LogBufferConfig {
            term_length: TermLength::try_new(TERM).unwrap(),
            spare_slots: 5,
            max_subscribers: 2,
            mtu: DEFAULT_MTU,
            max_reserved: TERM / 8,
            initial_term_id: TermId::new(INITIAL),
            lane: Lane::ZERO,
            session_id: SESSION,
            stream_id: STREAM,
            claim_deadline: DEFAULT_CLAIM_DEADLINE,
            publication: PublicationMode::Image { join },
        })
        .unwrap(),
    )
}

fn owner(buffer: &Arc<LogBuffer<HeapTerms>>) -> ReceiveOwner {
    ReceiveOwner::new(params(), vec![Arc::clone(buffer)]).unwrap()
}

fn term_id(count: u32) -> u32 {
    INITIAL.wrapping_add(count)
}

fn header(word0: Word0, term: u32, offset: u32, reserved_value: i64) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&word0.pack().to_le_bytes());
    out.extend_from_slice(&(offset as i32).to_le_bytes());
    out.extend_from_slice(&SESSION.to_le_bytes());
    out.extend_from_slice(&STREAM.to_le_bytes());
    out.extend_from_slice(&term_id(term).to_le_bytes());
    out.extend_from_slice(&reserved_value.to_le_bytes());
    out
}

/// A single-fragment DATA frame occupying `extent` bytes (a multiple of 32,
/// at least 64), with payload bytes derived from `fill`.
fn data(term: u32, offset: u32, extent: u32, fill: u8) -> Vec<u8> {
    data_with(
        term,
        offset,
        extent,
        fill,
        Flags::new(true, true, false, false, Lane::ZERO),
        0,
    )
}

fn data_with(term: u32, offset: u32, extent: u32, fill: u8, flags: Flags, rv: i64) -> Vec<u8> {
    let payload = extent as usize - 32 - 7;
    let word0 = Word0::new(32 + payload as i32, flags, FrameType::Data);
    let mut out = header(word0, term, offset, rv);
    out.extend((0..payload).map(|i| fill.wrapping_add(i as u8)));
    out
}

fn record(frame_type: FrameType, term: u32, offset: u32, extent: u32) -> Vec<u8> {
    header(
        Word0::new(32, Flags::NONE, frame_type),
        term,
        offset,
        i64::from(extent),
    )
}

fn pad(term: u32, offset: u32) -> Vec<u8> {
    record(FrameType::Pad, term, offset, TERM - offset)
}

fn recv(owner: &mut ReceiveOwner, bytes: &[u8]) -> Result<Received, ReceiveError> {
    let datagram = ValidatedDatagram::parse(bytes, &params()).unwrap();
    let Some(Item::Frame(frame)) = datagram.items().next() else {
        panic!("no frame")
    };
    owner.receive(&frame)
}

fn committed(position: u64, extent: u32) -> Result<Received, ReceiveError> {
    Ok(Received::Committed { position, extent })
}

fn conflict(position: u64, extent: u32) -> Result<Received, ReceiveError> {
    Err(ReceiveError::Conflict {
        lane: Lane::ZERO,
        position,
        extent,
    })
}

/// Fills term `count` from `offset` to its end with one PAD.
fn finish(owner: &mut ReceiveOwner, count: u32, offset: u32) {
    let start = u64::from(count) * u64::from(TERM) + u64::from(offset);
    assert_eq!(
        recv(owner, &pad(count, offset)),
        committed(start, TERM - offset)
    );
}

#[test]
fn a_frame_is_published_and_read() {
    let buffer = image(0);
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut owner = owner(&buffer);
    let frame = data(0, 0, 128, 7);
    assert_eq!(recv(&mut owner, &frame), committed(0, 128));
    assert_eq!(owner.rebuild_position(Lane::ZERO), Some(128));
    assert_eq!(buffer.reserved_head().load(Ordering::Acquire), 128);
    let mut out = [0u8; 256];
    let PollOutcome::Message {
        position, length, ..
    } = subscription.poll(&mut out).unwrap()
    else {
        panic!("no message")
    };
    assert_eq!((position, length), (0, 89));
    assert_eq!(&out[..89], &frame[32..]);
    assert_eq!(owner.counters().frames_committed, 1);
}

#[test]
fn an_overlapping_frame_is_refused_and_the_committed_one_kept() {
    let buffer = image(0);
    let mut owner = owner(&buffer);
    let a = data(0, 128, 128, 1);
    assert_eq!(recv(&mut owner, &a), committed(128, 128));
    for (offset, extent) in [(160, 64), (192, 128), (64, 128), (128, 64), (64, 256)] {
        let b = data(0, offset, extent, 9);
        assert_eq!(
            recv(&mut owner, &b),
            conflict(u64::from(offset), extent),
            "{offset}"
        );
    }
    assert_eq!(recv(&mut owner, &a), Ok(Received::Duplicate));
    assert_eq!(recv(&mut owner, &data(0, 256, 64, 2)), committed(256, 64));
    assert_eq!(recv(&mut owner, &data(0, 64, 64, 3)), committed(64, 64));
    assert_eq!(owner.counters().frames_conflicting, 5);
    // Nothing contiguous from 0 yet.
    assert_eq!(owner.rebuild_position(Lane::ZERO), Some(0));
    assert_eq!(recv(&mut owner, &data(0, 0, 64, 4)), committed(0, 64));
    assert_eq!(owner.rebuild_position(Lane::ZERO), Some(320));
    assert_eq!(owner.high_water(Lane::ZERO), Some(320));
}

#[test]
fn a_duplicate_is_compared_on_every_stored_byte() {
    let buffer = image(0);
    let mut owner = owner(&buffer);
    let original = data(0, 0, 160, 5);
    assert_eq!(recv(&mut owner, &original), committed(0, 160));
    assert_eq!(recv(&mut owner, &original), Ok(Received::Duplicate));
    let mut payload = original.clone();
    payload[100] ^= 1;
    let eos = Flags::new(true, true, true, false, Lane::ZERO);
    let variants = [
        payload,
        data_with(
            0,
            0,
            160,
            5,
            Flags::new(true, true, false, false, Lane::ZERO),
            1,
        ),
        data_with(0, 0, 160, 5, eos, 0),
    ];
    for variant in variants {
        assert_eq!(recv(&mut owner, &variant), conflict(0, 160));
    }
    assert_eq!(recv(&mut owner, &original), Ok(Received::Duplicate));
    assert_eq!(owner.counters().frames_duplicate, 2);
}

#[test]
fn aborted_and_pad_records_state_their_extent() {
    let buffer = image(0);
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut owner = owner(&buffer);
    assert_eq!(
        recv(&mut owner, &record(FrameType::Aborted, 0, 0, 4096)),
        committed(0, 4096)
    );
    let mut out = [0u8; 64];
    assert_eq!(
        subscription.poll(&mut out).unwrap(),
        PollOutcome::Aborted {
            position: 0,
            extent: 4096
        }
    );
    // Inside the aborted extent: a conflict, never a write.
    assert_eq!(recv(&mut owner, &data(0, 64, 64, 1)), conflict(64, 64));
    finish(&mut owner, 0, 4096);
    assert_eq!(owner.rebuild_position(Lane::ZERO), Some(u64::from(TERM)));
}

#[test]
fn the_window_is_two_terms() {
    let buffer = image(0);
    let mut owner = owner(&buffer);
    let t = u64::from(TERM);
    assert_eq!(recv(&mut owner, &data(2, 0, 64, 1)), Ok(Received::Ahead));
    assert_eq!(recv(&mut owner, &data(1, 0, 64, 1)), committed(t, 64));
    let last = data(0, 0, 64, 2);
    assert_eq!(recv(&mut owner, &last), committed(0, 64));
    finish(&mut owner, 0, 64);
    // r = 1: the trailing term is compared, the one before it is late.
    assert_eq!(owner.rebuild_position(Lane::ZERO), Some(t + 64));
    assert_eq!(recv(&mut owner, &last), Ok(Received::Duplicate));
    assert_eq!(recv(&mut owner, &data(0, 0, 64, 3)), conflict(0, 64));
    assert_eq!(recv(&mut owner, &data(0, 128, 64, 3)), conflict(128, 64));
    // Term 2 is not prepared until the conductor runs.
    assert_eq!(recv(&mut owner, &data(2, 0, 64, 4)), Ok(Received::NotReady));
    assert_eq!(owner.counters().cleaner_lag, 1);
    let mut conductor = buffer.conductor().unwrap();
    conductor.duty_cycle().unwrap();
    assert_eq!(recv(&mut owner, &data(2, 0, 64, 4)), committed(2 * t, 64));
}

#[test]
fn an_in_order_stream_activates_each_term_on_its_first_write() {
    let buffer = image(0);
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut owner = owner(&buffer);
    let mut out = [0u8; 256];
    // Across the 32-bit rollover of term ids (INITIAL = 2^32 - 2).
    for count in 0..6u32 {
        let start = u64::from(count) * u64::from(TERM);
        assert_eq!(
            recv(&mut owner, &data(count, 0, 96, count as u8)),
            committed(start, 96)
        );
        // An optional reader keeps up: the floor trails the rebuild
        // position by half a term without required readers.
        let polled = subscription.poll(&mut out).unwrap();
        assert!(
            matches!(polled, PollOutcome::Message { position, .. } if position == start),
            "term {count}: {polled:?}"
        );
        finish(&mut owner, count, 96);
        assert_eq!(subscription.poll(&mut out).unwrap(), PollOutcome::Pending);
        conductor.duty_cycle().unwrap();
        while owner.duty() {}
    }
    assert_eq!(
        owner.rebuild_position(Lane::ZERO),
        Some(6 * u64::from(TERM))
    );
}

#[test]
fn a_double_window_move_waits_for_a_clean_set() {
    let buffer = image(0);
    let mut conductor = buffer.conductor().unwrap();
    let mut owner = owner(&buffer);
    let t = u64::from(TERM);
    // r = 1, term 0 trailing.
    assert_eq!(recv(&mut owner, &data(0, 0, 64, 1)), committed(0, 64));
    finish(&mut owner, 0, 64);
    conductor.duty_cycle().unwrap();
    // Term 2 complete, term 1 complete except its first frame.
    assert_eq!(recv(&mut owner, &data(1, 64, 64, 2)), committed(t + 64, 64));
    finish(&mut owner, 1, 128);
    conductor.duty_cycle().unwrap();
    assert_eq!(recv(&mut owner, &data(2, 0, 64, 3)), committed(2 * t, 64));
    finish(&mut owner, 2, 64);
    // One arrival fills the gap: the window moves from {1, 2} to {3, 4}.
    assert_eq!(recv(&mut owner, &data(1, 0, 64, 4)), committed(t, 64));
    assert_eq!(owner.rebuild_position(Lane::ZERO), Some(3 * t));
    conductor.duty_cycle().unwrap();
    assert_eq!(recv(&mut owner, &data(3, 0, 64, 5)), committed(3 * t, 64));
    conductor.duty_cycle().unwrap();
    // Terms 0 and 1 were released at once; only one set was clean.
    let lag = owner.counters().cleaner_lag;
    assert_eq!(recv(&mut owner, &data(4, 0, 64, 6)), Ok(Received::NotReady));
    assert_eq!(owner.counters().cleaner_lag, lag);
    while owner.duty() {}
    assert_eq!(recv(&mut owner, &data(4, 0, 64, 6)), committed(4 * t, 64));
}

#[test]
fn copies_half_a_term_behind_are_compared_even_with_a_caught_up_reader() {
    let buffer = image(0);
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Required).unwrap();
    let mut owner = owner(&buffer);
    let t = u64::from(TERM);
    let mut out = [0u8; 256];
    let mut catch_up =
        |subscription: &mut crate::log_buffer::Subscription<&LogBuffer<HeapTerms>>| loop {
            match subscription.poll(&mut out).unwrap() {
                PollOutcome::Pending => break,
                _ => subscription.acknowledge(),
            }
        };
    let last = data(0, TERM - 64, 64, 1);
    assert_eq!(
        recv(&mut owner, &record(FrameType::Aborted, 0, 0, TERM - 64)),
        committed(0, TERM - 64)
    );
    assert_eq!(recv(&mut owner, &last), committed(t - 64, 64));
    assert_eq!(recv(&mut owner, &data(1, 0, 64, 2)), committed(t, 64));
    // The required reader catches up exactly to the rebuild position.
    catch_up(&mut subscription);
    conductor.duty_cycle().unwrap();
    assert!(buffer.floor().load(Ordering::Acquire) <= t + 64 - t / 2);
    // Behind the rebuild position, in the trailing term: compared.
    assert_eq!(recv(&mut owner, &last), Ok(Received::Duplicate));
    assert_eq!(
        recv(&mut owner, &data(0, TERM - 64, 64, 9)),
        conflict(t - 64, 64)
    );
    // More than half a term behind, with the reader caught up, term 0 is
    // reclaimed and a copy is late.
    assert_eq!(
        recv(&mut owner, &record(FrameType::Aborted, 1, 64, TERM / 2)),
        committed(t + 64, TERM / 2)
    );
    catch_up(&mut subscription);
    conductor.duty_cycle().unwrap();
    conductor.duty_cycle().unwrap();
    assert_eq!(recv(&mut owner, &last), Ok(Received::Late));
}

#[test]
fn an_image_starts_at_its_join_point() {
    let t = u64::from(TERM);
    let join = t + 4096;
    let buffer = image(join);
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut owner = owner(&buffer);
    assert_eq!(owner.rebuild_position(Lane::ZERO), Some(join));
    assert_eq!(recv(&mut owner, &data(1, 4032, 64, 1)), Ok(Received::Late));
    assert_eq!(recv(&mut owner, &data(0, 0, 64, 1)), Ok(Received::Late));
    assert_eq!(recv(&mut owner, &data(1, 4096, 64, 2)), committed(join, 64));
    let mut out = [0u8; 256];
    assert!(
        matches!(subscription.poll(&mut out).unwrap(), PollOutcome::Message { position, .. } if position == join)
    );
}

#[test]
fn a_frame_for_another_image_is_refused() {
    let buffer = image(0);
    let mut owner = owner(&buffer);
    let other = ImageParams::new(
        SESSION,
        STREAM,
        1,
        TermLength::try_new(TERM * 2).unwrap(),
        DEFAULT_MTU,
    )
    .unwrap();
    let bytes = data(0, 0, 64, 1);
    let datagram = ValidatedDatagram::parse(&bytes, &other).unwrap();
    let Some(Item::Frame(frame)) = datagram.items().next() else {
        panic!("no frame")
    };
    assert_eq!(owner.receive(&frame), Err(ReceiveError::Foreign));
    assert!(ReceiveOwner::<HeapTerms>::new(params(), vec![Arc::clone(&buffer)]).is_err());
}

#[test]
fn reused_slots_never_show_old_frames() {
    let buffer = image(0);
    let mut conductor = buffer.conductor().unwrap();
    let mut owner = owner(&buffer);
    // More terms than slots (3 + 5), with the same layout in every term.
    for count in 0..12u32 {
        let start = u64::from(count) * u64::from(TERM);
        assert_eq!(
            recv(&mut owner, &data(count, 0, 64, 1)),
            committed(start, 64)
        );
        assert_eq!(
            recv(&mut owner, &data(count, 64, 64, 2)),
            committed(start + 64, 64)
        );
        finish(&mut owner, count, 128);
        conductor.duty_cycle().unwrap();
        conductor.duty_cycle().unwrap();
        while owner.duty() {}
    }
    // A frame naming an old term is late, never compared with what reused
    // its slot.
    assert_eq!(recv(&mut owner, &data(3, 0, 64, 1)), Ok(Received::Late));
}

#[test]
fn an_image_issues_no_publication() {
    let buffer = image(0);
    assert!(matches!(
        buffer.publication(),
        Err(SysError::InvalidPublicationMode { .. })
    ));
    let mut conductor = buffer.conductor().unwrap();
    assert!(matches!(
        conductor.register_publication(1),
        Err(SysError::InvalidPublicationMode { .. })
    ));
    // The owner flag is still free for the receive owner.
    let _owner = owner(&buffer);
}

#[test]
fn an_image_needs_spare_slots_for_its_owner() {
    let config = LogBufferConfig {
        spare_slots: 3,
        ..image(0).config
    };
    assert_eq!(
        LogBuffer::new(config).map(|_| ()),
        Err(SysError::ResourcesUnavailable)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn an_image_configuration_round_trips() {
    let buffer = image(u64::from(TERM) + 4096);
    let words = crate::log_buffer::config_words(
        &buffer.config,
        buffer.generation,
        buffer.max_message_length,
    );
    let (config, generation, max) = crate::log_buffer::parse_config(&words).unwrap();
    assert_eq!(
        (config, generation, max),
        (buffer.config, buffer.generation, buffer.max_message_length)
    );
}

#[test]
fn bitmap_helpers_work_across_words() {
    let mut bits = vec![0u64; 4];
    set_range(&mut bits, 60, 10);
    assert!(
        any_set(&bits, 69, 1)
            && any_set(&bits, 0, 61)
            && !any_set(&bits, 0, 60)
            && !any_set(&bits, 70, 100)
    );
    assert_eq!(first_zero(&bits, 60, 256), 70);
    assert_eq!(first_zero(&bits, 0, 256), 0);
    set_range(&mut bits, 0, 256);
    assert_eq!(first_zero(&bits, 3, 256), 256);
    assert_eq!(first_zero(&bits, 3, 100), 100);
}

/// A frame of the generated tiling: offset, extent, and its fill.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Piece {
    offset: u32,
    extent: u32,
    fill: u8,
}

fn tiling() -> impl Strategy<Value = Vec<Piece>> {
    prop::collection::vec(1u32..20, 1..24).prop_map(|units| {
        let mut offset = 0;
        let mut pieces = Vec::new();
        for (i, u) in units.into_iter().enumerate() {
            let extent = (u + 1) * 32;
            if offset + extent > TERM {
                break;
            }
            pieces.push(Piece {
                offset,
                extent,
                fill: i as u8,
            });
            offset += extent;
        }
        pieces
    })
}

/// The sequential reference model of the classification rules.
#[derive(Default)]
struct Model {
    committed: Vec<Piece>,
}

impl Model {
    fn apply(&mut self, piece: Piece) -> Result<Received, ReceiveError> {
        let (start, end) = (piece.offset, piece.offset + piece.extent);
        let outcome_conflict = conflict(u64::from(start), piece.extent);
        if let Some(found) = self.committed.iter().find(|c| c.offset == start) {
            return if *found == piece {
                Ok(Received::Duplicate)
            } else {
                outcome_conflict
            };
        }
        if self
            .committed
            .iter()
            .any(|c| c.offset < end && start < c.offset + c.extent)
        {
            return outcome_conflict;
        }
        self.committed.push(piece);
        committed(u64::from(start), piece.extent)
    }

    fn prefix(&self) -> u64 {
        let mut end = 0;
        while let Some(next) = self.committed.iter().find(|c| c.offset == end) {
            end += next.extent;
        }
        u64::from(end)
    }
}

proptest! {
    #![proptest_config(crate::receive::tests_config())]

    #[test]
    fn arbitrary_arrival_orders_match_the_model(
        pieces in tiling(),
        order in prop::collection::vec(any::<prop::sample::Index>(), 1..64),
        tamper in prop::collection::vec((any::<prop::sample::Index>(), 0u32..3), 0..8),
    ) {
        let buffer = image(0);
        let mut owner = owner(&buffer);
        let mut model = Model::default();
        let mut arrivals: Vec<Piece> = order.iter().map(|i| *i.get(&pieces)).collect();
        for (i, kind) in tamper {
            let mut piece = *i.get(&pieces);
            match kind {
                0 => piece.fill = piece.fill.wrapping_add(1),
                1 if piece.extent > 64 => piece.extent -= 32,
                _ => piece.offset += 32,
            }
            if piece.offset + piece.extent <= TERM {
                arrivals.push(piece);
            }
        }
        for piece in arrivals {
            let expected = model.apply(piece);
            let got = recv(&mut owner, &data(0, piece.offset, piece.extent, piece.fill));
            prop_assert_eq!(got, expected);
            prop_assert_eq!(owner.rebuild_position(Lane::ZERO), Some(model.prefix()));
        }
        for piece in &model.committed {
            let again = recv(&mut owner, &data(0, piece.offset, piece.extent, piece.fill));
            prop_assert_eq!(again, Ok(Received::Duplicate));
        }
    }
}

#[test]
fn a_concurrent_reader_sees_only_complete_frames() {
    let buffer = image(0);
    let mut conductor = buffer.conductor_owned().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut owner = owner(&buffer);
    let frames: u32 = if cfg!(miri) { 6 } else { 200 };
    let writer = std::thread::spawn(move || {
        for i in 0..frames {
            let bytes = data(0, i * 160, 160, i as u8);
            assert_eq!(recv(&mut owner, &bytes), committed(u64::from(i * 160), 160));
        }
    });
    let mut out = [0u8; 256];
    let mut seen = 0u32;
    while seen < frames {
        if let PollOutcome::Message { length, .. } = subscription.poll(&mut out).unwrap() {
            let expected = data(0, seen * 160, 160, seen as u8);
            assert_eq!(&out[..length as usize], &expected[32..]);
            seen += 1;
        } else {
            std::thread::yield_now();
        }
    }
    writer.join().unwrap();
}

// Image read mode (batch r3): fragments published one by one.

/// A DATA fragment of `payload` bytes with explicit BEGIN and END flags.
fn fragment(term: u32, offset: u32, payload: usize, begin: bool, end: bool, fill: u8) -> Vec<u8> {
    let flags = Flags::new(begin, end, false, false, Lane::ZERO);
    let word0 = Word0::new(32 + payload as i32, flags, FrameType::Data);
    let mut out = header(word0, term, offset, 0);
    out.extend((0..payload).map(|i| fill.wrapping_add(i as u8)));
    out
}

fn poll(subscription: &mut crate::log_buffer::Subscription<&LogBuffer<HeapTerms>>) -> PollOutcome {
    let mut out = vec![0u8; 16 * 1024];
    subscription.poll(&mut out).unwrap()
}

fn skipped(position: u64, extent: u32, reason: SkipReason) -> PollOutcome {
    PollOutcome::Skipped {
        position,
        extent,
        reason,
    }
}

#[test]
fn a_message_is_delivered_once_every_fragment_arrived() {
    let buffer = image(0);
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut owner = owner(&buffer);
    // Three fragments of 64 bytes each: END first, then BEGIN, then the middle.
    let parts = [
        fragment(0, 0, 32, true, false, 1),
        fragment(0, 64, 32, false, false, 2),
        fragment(0, 128, 32, false, true, 3),
    ];
    assert_eq!(recv(&mut owner, &parts[2]), committed(128, 64));
    assert_eq!(poll(&mut subscription), PollOutcome::Pending);
    assert_eq!(recv(&mut owner, &parts[0]), committed(0, 64));
    assert_eq!(poll(&mut subscription), PollOutcome::Pending);
    assert_eq!(recv(&mut owner, &parts[1]), committed(64, 64));
    let mut out = [0u8; 256];
    let PollOutcome::Message {
        position, length, ..
    } = subscription.poll(&mut out).unwrap()
    else {
        panic!("no message")
    };
    assert_eq!((position, length), (0, 96));
    let expected: Vec<u8> = parts.iter().flat_map(|p| p[32..].to_vec()).collect();
    assert_eq!(&out[..96], &expected[..]);
}

#[test]
fn an_interrupted_message_is_skipped_up_to_the_interruption() {
    let buffer = image(0);
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut owner = owner(&buffer);
    recv(&mut owner, &fragment(0, 0, 32, true, false, 1)).unwrap();
    recv(&mut owner, &record(FrameType::Aborted, 0, 64, 64)).unwrap();
    assert_eq!(
        poll(&mut subscription),
        skipped(0, 64, SkipReason::Interrupted)
    );
    assert_eq!(
        poll(&mut subscription),
        PollOutcome::Aborted {
            position: 64,
            extent: 64
        }
    );
    // A new BEGIN interrupts too.
    recv(&mut owner, &fragment(0, 128, 32, true, false, 2)).unwrap();
    recv(&mut owner, &fragment(0, 192, 32, true, true, 3)).unwrap();
    assert_eq!(
        poll(&mut subscription),
        skipped(128, 64, SkipReason::Interrupted)
    );
    assert!(matches!(
        poll(&mut subscription),
        PollOutcome::Message { position: 192, .. }
    ));
}

#[test]
fn a_message_over_the_bound_is_skipped() {
    let buffer = image(0);
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut owner = owner(&buffer);
    // Six full 1408-byte fragments reserve 8448 bytes, over TERM / 8.
    let full = 1408 - 32;
    for i in 0..6u32 {
        let bytes = fragment(0, i * 1408, full, i == 0, false, i as u8);
        recv(&mut owner, &bytes).unwrap();
    }
    assert_eq!(
        poll(&mut subscription),
        skipped(0, 6 * 1408, SkipReason::MessageTooLarge)
    );
}

#[test]
fn a_message_without_end_is_skipped_to_the_term_end() {
    let buffer = image(0);
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut owner = owner(&buffer);
    recv(&mut owner, &record(FrameType::Aborted, 0, 0, TERM - 128)).unwrap();
    recv(&mut owner, &fragment(0, TERM - 128, 96, true, false, 1)).unwrap();
    recv(&mut owner, &data(1, 0, 64, 2)).unwrap();
    assert!(matches!(
        poll(&mut subscription),
        PollOutcome::Aborted { .. }
    ));
    assert_eq!(
        poll(&mut subscription),
        skipped(u64::from(TERM - 128), 128, SkipReason::MissingEnd)
    );
    assert!(
        matches!(poll(&mut subscription), PollOutcome::Message { position, .. } if position == u64::from(TERM))
    );
}

#[test]
fn orphans_where_a_reader_joined_are_not_a_fault() {
    // The image joins between two fragments of one message.
    let buffer = image(64);
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut owner = owner(&buffer);
    recv(&mut owner, &fragment(0, 64, 32, false, false, 1)).unwrap();
    // The run stops at the uncommitted END; it arrives later.
    assert_eq!(
        poll(&mut subscription),
        skipped(64, 64, SkipReason::JoinedMidMessage)
    );
    recv(&mut owner, &fragment(0, 128, 32, false, true, 2)).unwrap();
    assert_eq!(
        poll(&mut subscription),
        skipped(128, 64, SkipReason::JoinedMidMessage)
    );
    recv(&mut owner, &data(0, 192, 64, 3)).unwrap();
    assert!(matches!(
        poll(&mut subscription),
        PollOutcome::Message { position: 192, .. }
    ));
    // After a BEGIN, the same shape is a peer fault.
    recv(&mut owner, &fragment(0, 256, 32, false, true, 4)).unwrap();
    assert_eq!(
        poll(&mut subscription),
        skipped(256, 64, SkipReason::Orphan)
    );
}

#[test]
fn a_late_joiner_inside_a_partial_message_skips_its_rest() {
    let buffer = image(0);
    let mut conductor = buffer.conductor().unwrap();
    let mut owner = owner(&buffer);
    recv(&mut owner, &fragment(0, 0, 32, true, false, 1)).unwrap();
    recv(&mut owner, &fragment(0, 64, 32, false, false, 2)).unwrap();
    // Joins at the rebuild position, 128, inside the message.
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    recv(&mut owner, &fragment(0, 128, 32, false, true, 3)).unwrap();
    assert_eq!(
        poll(&mut subscription),
        skipped(128, 64, SkipReason::JoinedMidMessage)
    );
}
