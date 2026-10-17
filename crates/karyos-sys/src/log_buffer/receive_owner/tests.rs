// SPDX-License-Identifier: Apache-2.0

// Receive owner tests (`quantstratum-docs: karyos/design/receive-publication.md`,
// tests "Overlap", "Duplicates", "Stale terms", "Window", "Activation",
// "Image positions", "Comparison horizon", "ABORTED and PAD", "Arbitrary
// arrival orders", the fragments and the concurrent readers), included once
// per term backing by `receive_owner.rs`; the including module defines
// `Terms` and `new_image`.

use proptest::prelude::*;

use crate::frame::{Flags, FrameType, Word0};
use crate::log_buffer::IMAGE_OWNER_CELLS;
use crate::log_buffer::Lookup;
use crate::log_buffer::{DEFAULT_CLAIM_DEADLINE, LogBufferConfig, PollOutcome, Role, SkipReason};
use crate::publication::observe_block;
use crate::receive::{Item, ValidatedDatagram};
use crate::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use crate::term::{TERM_COUNT_LIMIT, TermCount, TermId};
use crate::term_bytes::sealed::Access as _;

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

fn image(join: u64) -> Arc<LogBuffer<Terms>> {
    Arc::new(
        new_image(LogBufferConfig {
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
            publication: PublicationMode::Image { join, local_gaps: false },
            schedule_capacity: 0,
        })
        .unwrap(),
    )
}

fn owner(buffer: &Arc<LogBuffer<Terms>>) -> ReceiveOwner<Terms> {
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

fn recv(owner: &mut ReceiveOwner<Terms>, bytes: &[u8]) -> Result<Received, ReceiveError> {
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
fn finish(owner: &mut ReceiveOwner<Terms>, count: u32, offset: u32) {
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

/// Dropping the owner releases the image's publication (W3): a terminal
/// seal is then positioned at the committed head, so a subscriber reads
/// what was committed and then sees the seal and its reason.
#[test]
fn a_dropped_owner_lets_the_seal_be_positioned() {
    use crate::log_buffer::SealReason;

    let buffer = image(0);
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut owner = owner(&buffer);
    assert_eq!(recv(&mut owner, &data(0, 0, 128, 7)), committed(0, 128));
    conductor.seal_with_reason(SealReason::ImageRetired).unwrap();
    let _ = conductor.duty_cycle().unwrap();
    // The owner still holds the publication: the seal waits.
    let mut out = [0u8; 256];
    assert!(matches!(
        subscription.poll(&mut out).unwrap(),
        PollOutcome::Message { .. }
    ));
    assert!(!matches!(
        subscription.poll(&mut out).unwrap(),
        PollOutcome::Closed { .. }
    ));
    drop(owner);
    let _ = conductor.duty_cycle().unwrap();
    assert!(
        matches!(
            subscription.poll(&mut out).unwrap(),
            PollOutcome::Closed {
                reason: SealReason::ImageRetired,
                ..
            }
        ),
        "the seal is positioned at the committed head"
    );
}

/// An image's consumption is its rebuild position, lowered to its least
/// required subscriber's; optional subscribers bound nothing.
#[test]
fn consumption_is_held_by_a_required_subscriber() {
    let buffer = image(0);
    let mut conductor = buffer.conductor().unwrap();
    let _optional = conductor.subscribe(Role::Optional).unwrap();
    let mut owner = owner(&buffer);
    assert_eq!(buffer.required_position(), None);
    assert_eq!(recv(&mut owner, &data(0, 0, 128, 7)), committed(0, 128));
    assert_eq!(owner.consumption(Lane::ZERO), Some(128));
    // A required subscriber joins at the head and holds it.
    let mut required = conductor.subscribe(Role::Required).unwrap();
    assert_eq!(buffer.required_position(), Some(128));
    assert_eq!(recv(&mut owner, &data(0, 128, 128, 8)), committed(128, 128));
    assert_eq!(owner.rebuild_position(Lane::ZERO), Some(256));
    assert_eq!(owner.consumption(Lane::ZERO), Some(128));
    let mut out = [0u8; 256];
    assert!(matches!(
        required.poll(&mut out).unwrap(),
        PollOutcome::Message { .. }
    ));
    required.acknowledge();
    assert_eq!(owner.consumption(Lane::ZERO), Some(256));
    assert_eq!(owner.consumption(Lane::try_new(1).unwrap()), None);
}

/// A head raised between the conductor's head read and the admission of a
/// required reader moves its join (`join_after_admit`): the cell's
/// position, the subscription's position and its acknowledged position are
/// all the raised head, and the image's consumption never reports past it.
#[test]
fn a_head_raised_during_admission_moves_the_join() {
    let buffer = image(0);
    let mut conductor = buffer.conductor().unwrap();
    let mut owner = owner(&buffer);
    assert_eq!(recv(&mut owner, &data(0, 0, 128, 7)), committed(0, 128));
    let raised = {
        let buffer = Arc::clone(&buffer);
        move || buffer.reserved_head().store(256, Ordering::Release)
    };
    let required = conductor.subscribe_pausing(Role::Required, raised).unwrap();
    assert_eq!(required.position(), 256);
    assert_eq!(required.acknowledged_position(), 256);
    let cell = buffer.cells().get(required.cell()).unwrap();
    assert_eq!(cell.position.load(Ordering::Acquire), 256);
    assert_eq!(buffer.required_position(), Some(256));
    // Without a raise the join is the head read.
    let second = conductor.subscribe_pausing(Role::Optional, || {}).unwrap();
    assert_eq!(second.position(), 256);
}

/// Consumption reports the published head, not the owner's rebuild
/// position: a rebuild move whose head store did not happen (the
/// `split_end` error path, simulated by lowering the head) is never
/// reported.
#[test]
fn consumption_reports_the_published_head() {
    let buffer = image(0);
    let mut owner = owner(&buffer);
    assert_eq!(recv(&mut owner, &data(0, 0, 128, 7)), committed(0, 128));
    assert_eq!(owner.rebuild_position(Lane::ZERO), Some(128));
    buffer.reserved_head().store(64, Ordering::Release);
    assert_eq!(owner.consumption(Lane::ZERO), Some(64));
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
        |subscription: &mut crate::log_buffer::Subscription<&LogBuffer<Terms>>| loop {
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
    // A copy that would conflict is late too once its term is gone.
    assert_eq!(recv(&mut owner, &data(0, 32, 64, 9)), Ok(Received::Late));
}

#[test]
fn a_counter_overflow_is_reported_and_the_outcome_stands() {
    let buffer = image(0);
    let mut owner = owner(&buffer);
    owner.counters.frames_committed = u64::MAX;
    owner.counters.frames_duplicate = u64::MAX - 1;
    let frame = data(0, 0, 64, 1);
    assert_eq!(recv(&mut owner, &frame), committed(0, 64));
    let counters = owner.counters();
    assert_eq!(counters.frames_committed, u64::MAX);
    assert_eq!(counters.bytes_committed, 64);
    assert_eq!(counters.overflowed, Some(ReceiveCounter::FramesCommitted));
    assert_eq!(recv(&mut owner, &frame), Ok(Received::Duplicate));
    assert_eq!(recv(&mut owner, &frame), Ok(Received::Duplicate));
    let counters = owner.counters();
    assert_eq!(counters.frames_duplicate, u64::MAX);
    // The first overflow stays reported.
    assert_eq!(counters.overflowed, Some(ReceiveCounter::FramesCommitted));
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
    assert!(ReceiveOwner::<Terms>::new(params(), vec![Arc::clone(&buffer)]).is_err());
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
        new_image(config).map(|_| ()),
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

/// What a piece of the generated tiling is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// A DATA fragment with its BEGIN and END flags and payload fill.
    Data {
        begin: bool,
        end: bool,
        fill: u8,
    },
    Aborted,
    Pad,
}

/// One frame of a generated term: offset, extent and kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Piece {
    offset: u32,
    extent: u32,
    kind: Kind,
}

impl Piece {
    /// The frame on the wire.
    fn bytes(&self) -> Vec<u8> {
        match self.kind {
            Kind::Data { begin, end, fill } => {
                fragment(0, self.offset, self.extent as usize - 39, begin, end, fill)
            }
            Kind::Aborted => record(FrameType::Aborted, 0, self.offset, self.extent),
            Kind::Pad => record(FrameType::Pad, 0, self.offset, self.extent),
        }
    }

    /// The image word 0 and the bytes after it, as the image must hold them.
    fn image(&self) -> (u64, Vec<u8>) {
        let wire = self.bytes();
        let word0 = Word0::unpack(u64::from_le_bytes(wire[..8].try_into().unwrap())).unwrap();
        let stored = match self.kind {
            Kind::Data { .. } => word0,
            Kind::Aborted => Word0::new(self.extent as i32, Flags::NONE, FrameType::Aborted),
            Kind::Pad => Word0::new(self.extent as i32, Flags::NONE, FrameType::Pad),
        };
        (stored.pack(), wire[8..].to_vec())
    }
}

/// A whole term: messages of one to three DATA fragments and ABORTED
/// records, then a final PAD to the term end.
fn tiling() -> impl Strategy<Value = Vec<Piece>> {
    let message = prop_oneof![
        3 => prop::collection::vec(2u32..=44, 1..=3).prop_map(Some),
        1 => Just(None),
    ];
    prop::collection::vec((message, 1u32..400), 1..60).prop_map(|items| {
        let mut pieces = Vec::new();
        let mut offset = 0u32;
        for (i, (message, aborted_units)) in items.into_iter().enumerate() {
            match message {
                Some(fragments) => {
                    let total: u32 = fragments.iter().map(|u| u * 32).sum();
                    if offset + total > TERM {
                        break;
                    }
                    let last = fragments.len() - 1;
                    for (f, units) in fragments.into_iter().enumerate() {
                        pieces.push(Piece {
                            offset,
                            extent: units * 32,
                            kind: Kind::Data {
                                begin: f == 0,
                                end: f == last,
                                fill: (i * 3 + f) as u8,
                            },
                        });
                        offset += units * 32;
                    }
                }
                None => {
                    let extent = aborted_units * 32;
                    if offset + extent > TERM {
                        break;
                    }
                    pieces.push(Piece {
                        offset,
                        extent,
                        kind: Kind::Aborted,
                    });
                    offset += extent;
                }
            }
        }
        if offset < TERM {
            pieces.push(Piece {
                offset,
                extent: TERM - offset,
                kind: Kind::Pad,
            });
        }
        pieces
    })
}

/// A valid frame that differs from `piece` in content, extent or offset.
fn tampered(piece: Piece, how: u32) -> Option<Piece> {
    let mut out = piece;
    match (how, piece.kind) {
        (0, Kind::Data { begin, end, fill }) => {
            out.kind = Kind::Data {
                begin,
                end,
                fill: fill.wrapping_add(1),
            }
        }
        (0, Kind::Aborted) if piece.extent > 32 => out.extent -= 32,
        (1, Kind::Data { .. }) if piece.extent > 64 => out.extent -= 32,
        (1, Kind::Aborted) => out.extent += 32,
        (_, Kind::Pad) if piece.extent > 32 => {
            out.offset += 32;
            out.extent -= 32;
        }
        (_, Kind::Data { .. } | Kind::Aborted) => out.offset += 32,
        _ => return None,
    }
    (out.offset + out.extent <= TERM).then_some(out)
}

/// The sequential reference model of the classification rules.
#[derive(Default)]
struct Model {
    committed: Vec<Piece>,
}

impl Model {
    fn apply(&mut self, piece: Piece) -> Result<Received, ReceiveError> {
        let (start, end) = (piece.offset, piece.offset + piece.extent);
        let refused = conflict(u64::from(start), piece.extent);
        if let Some(found) = self.committed.iter().find(|c| c.offset == start) {
            return if *found == piece {
                Ok(Received::Duplicate)
            } else {
                refused
            };
        }
        if self
            .committed
            .iter()
            .any(|c| c.offset < end && start < c.offset + c.extent)
        {
            return refused;
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

/// Reads the image independently of the owner: every committed piece's
/// word 0 and bytes, and a zero word 0 at every piece not committed.
fn check_image(buffer: &LogBuffer<Terms>, pieces: &[Piece], model: &Model) {
    let Lookup::Slot(slot) = buffer.lookup(TermCount::ZERO).unwrap() else {
        panic!("term 0 is not in the table")
    };
    for piece in pieces {
        let covered = model
            .committed
            .iter()
            .any(|c| c.offset <= piece.offset && piece.offset < c.offset + c.extent);
        if covered {
            continue;
        }
        // SAFETY: single-threaded test without a conductor, so term 0 stays
        // in its slot; nothing committed covers `offset`, a 32-byte frame
        // start of the generated layout that the owner never wrote.
        let word0 = observe_block(unsafe { buffer.regions.word0(slot, piece.offset) });
        assert_eq!(word0, 0, "uncommitted piece at {}", piece.offset);
    }
    for piece in &model.committed {
        let (expected_word0, expected) = piece.image();
        // SAFETY: as above; a committed frame starts at `offset`.
        let word0 = observe_block(unsafe { buffer.regions.word0(slot, piece.offset) });
        assert_eq!(word0, expected_word0, "word 0 at {}", piece.offset);
        let mut body = vec![0u8; expected.len()];
        // SAFETY: as above; the range follows the committed word 0 inside
        // the frame, at a multiple of 8, and holds no other word 0.
        unsafe { buffer.regions.read_bytes(slot, piece.offset + 8, &mut body) };
        assert_eq!(body, expected, "bytes at {}", piece.offset);
    }
}

/// Under Miri the full-term model, which reads the image after every
/// arrival, runs two cases; elsewhere the shared settings apply.
fn model_config() -> ProptestConfig {
    let config = crate::receive::tests_config();
    if cfg!(miri) {
        ProptestConfig { cases: 2, ..config }
    } else {
        config
    }
}

proptest! {
    #![proptest_config(model_config())]

    #[test]
    fn arbitrary_arrival_orders_match_the_model(
        pieces in tiling(),
        order in prop::collection::vec(any::<prop::sample::Index>(), 1..96),
        tamper in prop::collection::vec((any::<prop::sample::Index>(), 0u32..3), 0..12),
    ) {
        let buffer = image(0);
        let mut owner = owner(&buffer);
        let mut model = Model::default();
        let mut arrivals: Vec<Piece> = order.iter().map(|i| *i.get(&pieces)).collect();
        for (i, how) in tamper {
            if let Some(piece) = tampered(*i.get(&pieces), how) {
                arrivals.push(piece);
            }
        }
        // Every piece arrives at least once, after the shuffled ones.
        arrivals.extend(pieces.iter().copied());
        for piece in arrivals {
            let expected = model.apply(piece);
            prop_assert_eq!(recv(&mut owner, &piece.bytes()), expected);
            prop_assert_eq!(owner.rebuild_position(Lane::ZERO), Some(model.prefix()));
            check_image(&buffer, &pieces, &model);
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

fn poll(subscription: &mut crate::log_buffer::Subscription<&LogBuffer<Terms>>) -> PollOutcome {
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

#[test]
fn a_join_point_off_the_frame_alignment_is_refused() {
    for join in [1, 8, 16, u64::from(TERM) + 40] {
        let config = LogBufferConfig {
            publication: PublicationMode::Image { join, local_gaps: false },
            ..image(0).config
        };
        assert!(
            matches!(
                new_image(config),
                Err(SysError::InvalidPublicationMode { .. })
            ),
            "{join}"
        );
    }
}

#[test]
fn an_image_can_start_in_the_last_term() {
    let last = TERM_COUNT_LIMIT - 1;
    let start = u64::from(last) * u64::from(TERM);
    let buffer = image(start);
    let mut owner = owner(&buffer);
    assert_eq!(
        recv(&mut owner, &data(last, 0, 64, 1)),
        committed(start, 64)
    );
    assert_eq!(owner.rebuild_position(Lane::ZERO), Some(start + 64));
}

#[test]
fn finishing_the_last_term_ends_the_window_there() {
    let last = TERM_COUNT_LIMIT - 1;
    let t = u64::from(TERM);
    let buffer = image(u64::from(last - 1) * t);
    let mut conductor = buffer.conductor().unwrap();
    let mut owner = owner(&buffer);
    let first_pad = pad(last - 1, 0);
    assert_eq!(
        recv(&mut owner, &first_pad),
        committed(u64::from(last - 1) * t, TERM)
    );
    conductor.duty_cycle().unwrap();
    let last_pad = pad(last, 0);
    assert_eq!(
        recv(&mut owner, &last_pad),
        committed(u64::from(last) * t, TERM)
    );
    let end = u64::from(TERM_COUNT_LIMIT) * t;
    assert_eq!(owner.rebuild_position(Lane::ZERO), Some(end));
    assert_eq!(buffer.reserved_head().load(Ordering::Acquire), end);
    // Repeated calls stay consistent: copies are compared, nothing is
    // written, and the owner keeps only the last term's write loan.
    for _ in 0..2 {
        assert_eq!(recv(&mut owner, &last_pad), Ok(Received::Duplicate));
        assert_eq!(recv(&mut owner, &first_pad), Ok(Received::Duplicate));
        assert_eq!(
            recv(&mut owner, &data(last, 0, 64, 1)),
            conflict(u64::from(last) * t, 64)
        );
    }
    let held: Vec<bool> = (0..IMAGE_OWNER_CELLS)
        .map(|cell| buffer.cell(cell).unwrap().loan.load(Ordering::Acquire) != 0)
        .collect();
    assert_eq!(held, [false, true, false]);
    drop(owner);
    assert!(
        (0..IMAGE_OWNER_CELLS)
            .all(|cell| buffer.cell(cell).unwrap().loan.load(Ordering::Acquire) == 0)
    );
}

#[test]
fn a_concurrent_reader_sees_only_complete_fragmented_messages() {
    let buffer = image(0);
    let mut conductor = buffer.conductor_owned().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut owner = owner(&buffer);
    let messages: u32 = if cfg!(miri) { 3 } else { 100 };
    // Each message: three 64-byte fragments, published one by one.
    let parts = |m: u32| -> Vec<Vec<u8>> {
        (0..3u32)
            .map(|f| fragment(0, m * 192 + f * 64, 32, f == 0, f == 2, (m * 3 + f) as u8))
            .collect()
    };
    let writer = std::thread::spawn(move || {
        for m in 0..messages {
            for part in parts(m) {
                recv(&mut owner, &part).unwrap();
            }
        }
    });
    let mut out = [0u8; 256];
    let mut seen = 0u32;
    while seen < messages {
        match subscription.poll(&mut out).unwrap() {
            PollOutcome::Message { length, .. } => {
                let expected: Vec<u8> = parts(seen).iter().flat_map(|p| p[32..].to_vec()).collect();
                assert_eq!(&out[..length as usize], &expected[..]);
                seen += 1;
            }
            PollOutcome::Pending => std::thread::yield_now(),
            other => panic!("unexpected {other:?}"),
        }
    }
    writer.join().unwrap();
}

#[test]
fn a_reader_that_rejoins_after_an_overrun_is_joining_again() {
    let buffer = image(0);
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut owner = owner(&buffer);
    recv(&mut owner, &data(0, 0, 64, 1)).unwrap();
    assert!(matches!(
        poll(&mut subscription),
        PollOutcome::Message { position: 0, .. }
    ));
    // The rebuild position moves more than half a term past the reader,
    // into the middle of a message.
    recv(&mut owner, &record(FrameType::Aborted, 0, 64, TERM / 2)).unwrap();
    let begin = 64 + TERM / 2;
    recv(&mut owner, &fragment(0, begin, 32, true, false, 2)).unwrap();
    recv(&mut owner, &fragment(0, begin + 64, 32, false, false, 3)).unwrap();
    conductor.duty_cycle().unwrap();
    let resume = u64::from(begin + 128);
    assert!(matches!(
        poll(&mut subscription),
        PollOutcome::Overrun { resume: at, .. } if at == resume
    ));
    recv(&mut owner, &fragment(0, begin + 128, 32, false, true, 4)).unwrap();
    assert_eq!(
        poll(&mut subscription),
        skipped(resume, 64, SkipReason::JoinedMidMessage)
    );
}

/// An image whose owner may seal local gaps.
fn gap_image(join: u64) -> Arc<LogBuffer<Terms>> {
    let plain = image(join);
    Arc::new(
        new_image(LogBufferConfig {
            publication: PublicationMode::Image {
                join,
                local_gaps: true,
            },
            ..plain.config
        })
        .unwrap(),
    )
}

fn seal(
    owner: &mut ReceiveOwner<Terms>,
    position: u64,
    extent: u32,
) -> Result<Received, ReceiveError> {
    owner.seal_gap(
        Lane::ZERO,
        position,
        extent,
        crate::local_gap::GapReason::ReorderExpired,
    )
}

const LOST: SkipReason = SkipReason::LocalGap(crate::local_gap::GapReason::ReorderExpired);

/// A sealed interval is published as one record, advances the rebuild
/// position across it, and a reader skips it as a local gap, then reads
/// the next message.
#[test]
fn a_sealed_gap_is_skipped_by_a_reader() {
    let buffer = gap_image(0);
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut owner = owner(&buffer);
    assert_eq!(recv(&mut owner, &data(0, 128, 64, 1)), committed(128, 64));
    assert_eq!(owner.rebuild_position(Lane::ZERO), Some(0));
    assert_eq!(seal(&mut owner, 0, 128), committed(0, 128));
    assert_eq!(owner.rebuild_position(Lane::ZERO), Some(192));
    assert_eq!(poll(&mut subscription), skipped(0, 128, LOST));
    assert!(matches!(
        poll(&mut subscription),
        PollOutcome::Message { position: 128, .. }
    ));
    // The record is final: a late copy into it is late after the skip,
    // counted and not written (GU-7).
    assert_eq!(
        recv(&mut owner, &data(0, 64, 64, 2)),
        Ok(Received::LateAfterSkip)
    );
    assert_eq!(owner.counters().frames_late_after_skip, 1);
    // A record's reason is reported as sealed.
    let reason = crate::local_gap::GapReason::RangeUnavailable;
    assert_eq!(
        owner.seal_gap(Lane::ZERO, 192, 64, reason),
        committed(192, 64)
    );
    assert_eq!(
        poll(&mut subscription),
        skipped(192, 64, SkipReason::LocalGap(reason))
    );
}

/// A gap interrupts a message in progress, which is skipped up to it; a
/// gap never covers a committed frame.
#[test]
fn a_gap_interrupts_a_message_and_never_covers_a_frame() {
    let buffer = gap_image(0);
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut owner = owner(&buffer);
    recv(&mut owner, &fragment(0, 0, 32, true, false, 1)).unwrap();
    assert_eq!(seal(&mut owner, 0, 64), conflict(0, 64));
    assert_eq!(seal(&mut owner, 32, 64), conflict(32, 64));
    assert_eq!(seal(&mut owner, 64, 64), committed(64, 64));
    assert_eq!(
        poll(&mut subscription),
        skipped(0, 64, SkipReason::Interrupted)
    );
    assert_eq!(poll(&mut subscription), skipped(64, 64, LOST));
    assert_eq!(poll(&mut subscription), PollOutcome::Pending);
    // The reader resumes at the next BEGIN after the gap.
    recv(&mut owner, &fragment(0, 128, 32, true, false, 2)).unwrap();
    recv(&mut owner, &fragment(0, 192, 32, false, true, 3)).unwrap();
    assert!(matches!(
        poll(&mut subscription),
        PollOutcome::Message {
            position: 128,
            length: 64,
            ..
        }
    ));
}

/// Only an image with the capability takes a gap, and only an interval of
/// whole 32-byte units inside one term of the window.
#[test]
fn a_gap_needs_the_capability_and_a_valid_interval() {
    let plain = image(0);
    let mut plain_owner = owner(&plain);
    assert_eq!(seal(&mut plain_owner, 0, 64), Err(ReceiveError::NoLocalGaps));
    let t = u64::from(TERM);
    let buffer = gap_image(0);
    let mut owner = owner(&buffer);
    let invalid = |position, extent| {
        Err(ReceiveError::InvalidGap {
            lane: Lane::ZERO,
            position,
            extent,
        })
    };
    assert_eq!(seal(&mut owner, 0, 0), invalid(0, 0));
    assert_eq!(seal(&mut owner, 0, 40), invalid(0, 40));
    assert_eq!(seal(&mut owner, 8, 64), invalid(8, 64));
    assert_eq!(seal(&mut owner, t - 32, 64), invalid(t - 32, 64));
    assert_eq!(seal(&mut owner, 2 * t, 64), Ok(Received::Ahead));
    // Up to the end of the term is valid.
    assert_eq!(seal(&mut owner, t - 64, 64), committed(t - 64, 64));
    assert_eq!(
        owner.seal_gap(
            Lane::try_new(1).unwrap(),
            0,
            64,
            crate::local_gap::GapReason::ReorderExpired
        ),
        Err(ReceiveError::Foreign)
    );
    // Below the join point is late.
    let joined = gap_image(t);
    let mut joined_owner = owner_of(&joined);
    assert_eq!(seal(&mut joined_owner, 0, 64), Ok(Received::Late));
}

fn owner_of(buffer: &Arc<LogBuffer<Terms>>) -> ReceiveOwner<Terms> {
    ReceiveOwner::new(params(), vec![Arc::clone(buffer)]).unwrap()
}

/// A released set's three bitmaps are cleared within the scaled cleaning
/// budget, so a gap's start never survives into a reused set.
#[test]
fn cleaning_clears_the_gap_bitmap_too() {
    let buffer = gap_image(0);
    let mut conductor = buffer.conductor().unwrap();
    let mut owner = owner(&buffer);
    assert_eq!(seal(&mut owner, 0, 64), committed(0, 64));
    finish(&mut owner, 0, 64);
    conductor.duty_cycle().unwrap();
    for term in 1..3 {
        finish(&mut owner, term, 0);
        conductor.duty_cycle().unwrap();
    }
    let lane = &owner.lanes[0];
    assert!(lane.sets.iter().any(|set| set.dirty));
    // One duty cleans every word of a minimum-term set (32 words each).
    assert!(!owner.duty());
    for set in &owner.lanes[0].sets {
        assert!(!set.dirty);
        if set.term.is_none() {
            assert!(set.gap_starts.iter().all(|word| *word == 0));
            assert!(set.covered.iter().all(|word| *word == 0));
        }
    }
}

/// The capability survives the configuration block, and a block an older
/// layout would write without it still parses; a capability on a log that
/// is not an image, or an unknown capability bit, is refused.
#[cfg(target_os = "linux")]
#[test]
fn the_capability_is_in_the_configuration_block() {
    let buffer = gap_image(0);
    let words = crate::log_buffer::config_words(
        &buffer.config,
        buffer.generation,
        buffer.max_message_length,
    );
    let (config, _, _) = crate::log_buffer::parse_config(&words).unwrap();
    assert_eq!(config.publication, buffer.config.publication);
    // The word after `join`.
    assert_eq!(words[17], 1);
    let mut unknown = words;
    unknown[17] = 2;
    assert!(crate::log_buffer::parse_config(&unknown).is_none());
    let mut not_image = words;
    not_image[11] = 1;
    not_image[16] = 0;
    assert!(crate::log_buffer::parse_config(&not_image).is_none());
}

/// The slot of term 0 under the owner's write loan.
fn held(owner: &ReceiveOwner<Terms>) -> u8 {
    owner.lanes[0].held_slot(TermCount::try_new(0).unwrap()).unwrap()
}

/// A local gap word 0 in an image without the capability, or in a
/// publication log, is an unknown frame type, never a gap.
#[test]
fn a_gap_record_without_the_capability_is_corrupt() {
    let buffer = image(0);
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut owner = owner(&buffer);
    assert_eq!(recv(&mut owner, &data(0, 64, 64, 1)), committed(64, 64));
    let slot = held(&owner);
    // SAFETY: the owner holds the write loan on `slot`'s term 0; offset 0
    // is a frame start no one has written in this incarnation.
    let word0 = unsafe { buffer.regions.word0(slot, 0) };
    crate::publication::publish_block(
        word0,
        crate::local_gap::gap_word0(64, Lane::ZERO).unwrap(),
    );
    let mut out = vec![0u8; 16 * 1024];
    assert!(matches!(
        subscription.poll(&mut out),
        Err(SysError::CorruptTerm {
            offset: 0,
            reason: "frame type"
        })
    ));

    let plain = image(0);
    let log = Arc::new(
        new_image(LogBufferConfig {
            publication: PublicationMode::Exclusive,
            ..plain.config
        })
        .unwrap(),
    );
    let mut conductor = log.conductor().unwrap();
    let mut reader = conductor.subscribe(Role::Optional).unwrap();
    let Lookup::Slot(slot) = log.lookup(TermCount::try_new(0).unwrap()).unwrap() else {
        panic!("no term 0");
    };
    // SAFETY: a test of one thread: term 0 is active and nothing else
    // writes or reads offset 0 while the store runs.
    let word0 = unsafe { log.regions.word0(slot, 0) };
    crate::publication::publish_block(
        word0,
        crate::local_gap::gap_word0(64, Lane::ZERO).unwrap(),
    );
    assert!(matches!(
        reader.poll(&mut out),
        Err(SysError::CorruptTerm { offset: 0, .. })
    ));
}

/// A sealed record whose header disagrees with its site, or carries an
/// unknown version, is corrupt when a reader meets it.
#[test]
fn a_corrupted_gap_record_is_refused_by_a_reader() {
    for (at, byte, reason) in [
        (8, 0x20, "local gap site"),
        (8 + 16, 2, "local gap version"),
        (8 + 18, 1, "local gap reserved bytes"),
    ] {
        let buffer = gap_image(0);
        let mut conductor = buffer.conductor().unwrap();
        let mut subscription = conductor.subscribe(Role::Optional).unwrap();
        let mut owner = owner(&buffer);
        assert_eq!(seal(&mut owner, 0, 64), committed(0, 64));
        // The record's eight bytes at `at & !7`, with one byte changed.
        let base = at & !7;
        let mut word = [0u8; 8];
        let slot = held(&owner);
        // SAFETY: loan held by the owner; a test of one thread; `base` is a
        // multiple of 8 inside the record, after its word 0.
        unsafe { buffer.regions.read_bytes(slot, base, &mut word) };
        word[(at - base) as usize] = byte;
        // SAFETY: as above; nothing reads while this runs.
        unsafe { buffer.regions.write_bytes(slot, base, &word) };
        let mut out = vec![0u8; 16 * 1024];
        assert!(
            matches!(
                subscription.poll(&mut out),
                Err(SysError::CorruptTerm { offset: 0, reason: found }) if found == reason
            ),
            "{reason}"
        );
    }
}

/// Paths of a seal that leave the image as it was, and one that crosses
/// into the next term.
#[test]
fn a_seal_outside_the_window_changes_nothing_and_one_at_the_term_end_advances() {
    let t = u64::from(TERM);
    let buffer = gap_image(0);
    let mut conductor = buffer.conductor().unwrap();
    let mut owner = owner(&buffer);
    // Ahead: nothing written, no position moved.
    assert_eq!(seal(&mut owner, 3 * t, 64), Ok(Received::Ahead));
    assert_eq!(owner.rebuild_position(Lane::ZERO), Some(0));
    assert_eq!(owner.high_water(Lane::ZERO), Some(0));
    // A gap from the rebuild position to the term's end moves the rebuild
    // position into the next term.
    assert_eq!(seal(&mut owner, 0, TERM), committed(0, TERM));
    assert_eq!(owner.rebuild_position(Lane::ZERO), Some(t));
    conductor.duty_cycle().unwrap();
    finish(&mut owner, 1, 0);
    conductor.duty_cycle().unwrap();
    // Term 0 is now the trailing term: a seal there is late.
    assert_eq!(seal(&mut owner, 64, 64), Ok(Received::Late));
    assert_eq!(owner.rebuild_position(Lane::ZERO), Some(2 * t));
}

/// The cleaning span is 1024 indexes in every bitmap: a set of 1024 words
/// per bitmap (a 2 MiB term) is clean in one duty cycle, as before the
/// third bitmap.
#[test]
fn a_set_is_clean_in_as_many_duty_cycles_as_before() {
    const BIG: u32 = 2 * 1024 * 1024;
    let term = TermLength::try_new(BIG).unwrap();
    let plain = image(0);
    let buffer = Arc::new(
        new_image(LogBufferConfig {
            term_length: term,
            max_reserved: BIG / 8,
            publication: PublicationMode::Image {
                join: 0,
                local_gaps: true,
            },
            ..plain.config
        })
        .unwrap(),
    );
    let params = ImageParams::new(SESSION, STREAM, 1, term, DEFAULT_MTU).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut owner = ReceiveOwner::new(params, vec![Arc::clone(&buffer)]).unwrap();
    assert_eq!(owner.lanes[0].sets[0].covered.len(), 1024);
    let b = u64::from(BIG);
    for count in 0..3u64 {
        let reason = crate::local_gap::GapReason::ReorderExpired;
        assert_eq!(
            owner.seal_gap(Lane::ZERO, count * b, BIG, reason),
            committed(count * b, BIG)
        );
        conductor.duty_cycle().unwrap();
    }
    let dirty = owner.lanes[0].sets.iter().filter(|set| set.dirty).count();
    assert!(dirty >= 1);
    let mut duties = 1;
    while owner.duty() {
        duties += 1;
    }
    assert_eq!(duties, dirty);
}

// Positions and resynchronization after loss (GU-1, GU-3).

/// GU-1: a sealed gap advances the resolved prefix and the covered end but
/// never the received high-water mark, and the first loss is the lowest gap
/// start, kept once set.
#[test]
fn a_gap_moves_the_resolved_prefix_not_the_received_high_water() {
    let buffer = gap_image(0);
    let mut owner = owner(&buffer);
    assert_eq!(recv(&mut owner, &data(0, 0, 64, 1)), committed(0, 64));
    assert_eq!(owner.received_high_water(Lane::ZERO), Some(64));
    assert_eq!(owner.first_loss(Lane::ZERO), Some(None));
    assert_eq!(seal(&mut owner, 128, 64), committed(128, 64));
    assert_eq!(owner.high_water(Lane::ZERO), Some(192));
    assert_eq!(owner.received_high_water(Lane::ZERO), Some(64));
    assert_eq!(owner.first_loss(Lane::ZERO), Some(Some(128)));
    assert_eq!(seal(&mut owner, 64, 64), committed(64, 64));
    assert_eq!(owner.rebuild_position(Lane::ZERO), Some(192));
    assert_eq!(owner.first_loss(Lane::ZERO), Some(Some(64)), "the lowest gap");
    assert_eq!(recv(&mut owner, &data(0, 192, 64, 2)), committed(192, 64));
    assert_eq!(owner.received_high_water(Lane::ZERO), Some(256));
    assert_eq!(owner.first_loss(Lane::ZERO), Some(Some(64)), "never cleared");
}

/// GU-1: a gap sealed above an earlier one leaves the first loss at the
/// lower start (the minimum, not the latest seal).
#[test]
fn a_higher_gap_sealed_later_keeps_the_lower_first_loss() {
    let buffer = gap_image(0);
    let mut owner = owner(&buffer);
    assert_eq!(seal(&mut owner, 64, 64), committed(64, 64));
    assert_eq!(owner.first_loss(Lane::ZERO), Some(Some(64)));
    assert_eq!(seal(&mut owner, 192, 64), committed(192, 64));
    assert_eq!(owner.first_loss(Lane::ZERO), Some(Some(64)), "the lowest gap");
}

/// GU-1: the cursor's first loss is kept since the join; an overrun
/// rejoin does not clear it.
#[test]
fn a_rejoin_after_an_overrun_keeps_the_cursor_first_loss() {
    let buffer = gap_image(0);
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut owner = owner(&buffer);
    assert_eq!(seal(&mut owner, 0, 64), committed(0, 64));
    assert_eq!(poll(&mut subscription), skipped(0, 64, LOST));
    assert_eq!(subscription.first_loss(), Some(0));
    // The rebuild position moves more than half a term past the reader.
    recv(&mut owner, &record(FrameType::Aborted, 0, 64, TERM / 2)).unwrap();
    let begin = 64 + TERM / 2;
    recv(&mut owner, &data(0, begin, 64, 1)).unwrap();
    recv(&mut owner, &data(0, begin + 64, 64, 2)).unwrap();
    conductor.duty_cycle().unwrap();
    assert!(matches!(
        poll(&mut subscription),
        PollOutcome::Overrun { .. }
    ));
    assert_eq!(subscription.first_loss(), Some(0), "kept across the rejoin");
}

/// GU-3: fragments without BEGIN after a reported gap are `AfterLoss`,
/// never `Orphan`; the reader resynchronizes at the next BEGIN, and a later
/// run without BEGIN and without a gap is an `Orphan` again. The cursor's
/// first loss is the gap's start, kept once set.
#[test]
fn a_run_after_a_gap_is_after_loss_and_a_later_one_is_orphan() {
    let buffer = gap_image(0);
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut owner = owner(&buffer);
    assert_eq!(seal(&mut owner, 0, 64), committed(0, 64));
    recv(&mut owner, &fragment(0, 64, 32, false, false, 1)).unwrap();
    recv(&mut owner, &fragment(0, 128, 32, false, true, 2)).unwrap();
    recv(&mut owner, &fragment(0, 192, 32, true, true, 3)).unwrap();
    recv(&mut owner, &fragment(0, 256, 32, false, true, 4)).unwrap();
    assert_eq!(poll(&mut subscription), skipped(0, 64, LOST));
    assert_eq!(
        poll(&mut subscription),
        skipped(64, 128, SkipReason::AfterLoss)
    );
    assert!(matches!(
        poll(&mut subscription),
        PollOutcome::Message { position: 192, .. }
    ));
    assert_eq!(
        poll(&mut subscription),
        skipped(256, 64, SkipReason::Orphan)
    );
    assert_eq!(subscription.first_loss(), Some(0));
}

/// GU-1: a message interrupted by a gap is lost from its BEGIN: the
/// cursor's first loss is the interrupted range's start, not the gap's.
#[test]
fn a_message_interrupted_by_a_gap_is_lost_from_its_begin() {
    let buffer = gap_image(0);
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut owner = owner(&buffer);
    recv(&mut owner, &data(0, 0, 64, 1)).unwrap();
    recv(&mut owner, &fragment(0, 64, 32, true, false, 2)).unwrap();
    assert_eq!(seal(&mut owner, 128, 64), committed(128, 64));
    assert!(matches!(
        poll(&mut subscription),
        PollOutcome::Message { position: 0, .. }
    ));
    assert_eq!(subscription.first_loss(), None);
    assert_eq!(
        poll(&mut subscription),
        skipped(64, 64, SkipReason::Interrupted)
    );
    // Not a loss on its own: a peer fault until the gap ends it.
    assert_eq!(subscription.first_loss(), None);
    assert_eq!(poll(&mut subscription), skipped(128, 64, LOST));
    assert_eq!(subscription.first_loss(), Some(64));
}

/// The frame reader keeps the same state: a run after a gap is
/// `AfterLoss`, and its subscription's first loss is set.
#[test]
fn a_frame_reader_reports_after_loss_too() {
    use crate::log_buffer::{FrameReader, FrameStep, Stepped};
    let buffer = gap_image(0);
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = FrameReader::new(conductor.subscribe(Role::Optional).unwrap());
    let mut owner = owner(&buffer);
    assert_eq!(seal(&mut owner, 0, 64), committed(0, 64));
    recv(&mut owner, &fragment(0, 64, 32, false, true, 1)).unwrap();
    let mut reasons = Vec::new();
    for _ in 0..4 {
        match reader.serve_frame().unwrap() {
            FrameStep::Stepped {
                kind: Stepped::Skipped { reason, .. },
                ..
            } => reasons.push(reason),
            FrameStep::Pending => break,
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(reasons, [LOST, SkipReason::AfterLoss]);
    assert_eq!(reader.subscription().first_loss(), Some(0));
}

/// GU-7: a late copy is classified in order: an overlap with a committed
/// real frame is a conflict (or a duplicate), even when it also overlaps a
/// gap; an overlap with retained gap records alone is `LateAfterSkip`,
/// counted and not written, so the sealed interval stays sealed; a term no
/// longer retained is `Late`.
#[test]
fn a_late_copy_is_classified_real_overlap_first() {
    let buffer = gap_image(0);
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut owner = owner(&buffer);
    assert_eq!(recv(&mut owner, &data(0, 0, 64, 1)), committed(0, 64));
    assert_eq!(seal(&mut owner, 64, 128), committed(64, 128));
    assert_eq!(recv(&mut owner, &data(0, 192, 64, 2)), committed(192, 64));
    // Inside the gap alone, at its start and in its middle.
    for offset in [64, 128] {
        assert_eq!(
            recv(&mut owner, &data(0, offset, 64, 3)),
            Ok(Received::LateAfterSkip),
            "at {offset}"
        );
    }
    // Across the gap and the real frame after it: a conflict.
    assert_eq!(recv(&mut owner, &data(0, 160, 64, 4)), conflict(160, 64));
    // Across the real frame before it and the gap: a conflict.
    assert_eq!(recv(&mut owner, &data(0, 32, 64, 5)), conflict(32, 64));
    // The real frames still answer as before.
    assert_eq!(recv(&mut owner, &data(0, 0, 64, 1)), Ok(Received::Duplicate));
    assert_eq!(owner.counters().frames_late_after_skip, 2);
    // Nothing was written into the gap: the reader sees it whole.
    assert!(matches!(
        poll(&mut subscription),
        PollOutcome::Message { position: 0, .. }
    ));
    assert_eq!(poll(&mut subscription), skipped(64, 128, LOST));
}

/// GU-7 in the trailing term: a copy into a retained gap of the term
/// behind the window is `LateAfterSkip`, one into a real frame of it is a
/// duplicate or a conflict.
#[test]
fn a_late_copy_into_the_trailing_term_is_classified_too() {
    let buffer = gap_image(0);
    let mut conductor = buffer.conductor().unwrap();
    let mut owner = owner(&buffer);
    assert_eq!(recv(&mut owner, &data(0, 0, 64, 1)), committed(0, 64));
    assert_eq!(seal(&mut owner, 64, 128), committed(64, 128));
    finish(&mut owner, 0, 192);
    conductor.duty_cycle().unwrap();
    assert_eq!(recv(&mut owner, &data(1, 0, 64, 2)), committed(u64::from(TERM), 64));
    assert_eq!(
        recv(&mut owner, &data(0, 64, 64, 3)),
        Ok(Received::LateAfterSkip)
    );
    assert_eq!(recv(&mut owner, &data(0, 0, 64, 1)), Ok(Received::Duplicate));
    assert_eq!(recv(&mut owner, &data(0, 0, 64, 9)), conflict(0, 64));
}

/// GU-11: the owner counts its sealed gaps per lane, by reason, and the
/// late copies it dropped; a reader counts the bytes it lost by kind.
#[test]
fn gaps_and_reader_losses_are_counted() {
    let buffer = gap_image(0);
    let mut conductor = buffer.conductor().unwrap();
    let mut subscription = conductor.subscribe(Role::Optional).unwrap();
    let mut owner = owner(&buffer);
    recv(&mut owner, &fragment(0, 0, 32, true, false, 1)).unwrap();
    assert_eq!(seal(&mut owner, 64, 64), committed(64, 64));
    recv(&mut owner, &fragment(0, 128, 32, false, true, 2)).unwrap();
    let range = crate::local_gap::GapReason::RangeUnavailable;
    assert_eq!(owner.seal_gap(Lane::ZERO, 192, 64, range), committed(192, 64));
    assert_eq!(
        recv(&mut owner, &data(0, 64, 64, 3)),
        Ok(Received::LateAfterSkip)
    );
    let counters = owner.gap_counters(Lane::ZERO).unwrap();
    assert_eq!(
        (
            counters.gaps_sealed,
            counters.gap_bytes,
            counters.reorder_expired,
            counters.range_unavailable_skips,
            counters.late_after_skip,
            counters.overflowed,
        ),
        (2, 128, 1, 1, 1, false)
    );
    // Interrupted [0, 64), gap [64, 128), after loss [128, 192), gap.
    for _ in 0..4 {
        let _ = poll(&mut subscription);
    }
    let loss = subscription.loss_counters();
    assert_eq!(
        (loss.discarded_partial_bytes, loss.gap_bytes, loss.after_loss_bytes),
        (64, 128, 64)
    );
}

/// The word-wise `overlaps_real` agrees with a bit-by-bit reference on
/// pseudo-random maps of three words, for every first unit and several
/// lengths, including records that start one or two words below.
#[test]
fn overlaps_real_matches_a_bitwise_reference() {
    fn reference(set: &Set, unit: usize, units: usize) -> bool {
        if bit(&set.covered, unit) {
            let mut at = unit;
            loop {
                if bit(&set.starts, at) {
                    return true;
                }
                if bit(&set.gap_starts, at) {
                    break;
                }
                match at.checked_sub(1) {
                    Some(below) if bit(&set.covered, below) => at = below,
                    _ => return true,
                }
            }
        }
        // No start lies past the map, so stop at its end.
        let end = unit.saturating_add(units).min(set.starts.len() * WORD_BITS);
        (unit..end).any(|at| bit(&set.starts, at))
    }
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for round in 0..400 {
        // Dense coverage with sparse starts, so runs cross words.
        let covered: Vec<u64> = (0..3).map(|_| next() | next() | next()).collect();
        let mut sparse = |value: u64| {
            let thin = value & next() & next();
            if round % 2 == 0 { thin } else { thin & next() & next() }
        };
        let starts: Vec<u64> = covered.iter().map(|&c| sparse(c)).collect();
        let gap_starts: Vec<u64> = covered
            .iter()
            .zip(&starts)
            .map(|(&c, &s)| sparse(c) & !s)
            .collect();
        let set = Set {
            term: None,
            covered,
            starts,
            gap_starts,
            dirty: false,
            cursor: 0,
        };
        for unit in 0..3 * WORD_BITS {
            for units in [1, 2, 7, 64, 130, usize::MAX] {
                assert_eq!(
                    overlaps_real(&set, unit, units),
                    reference(&set, unit, units),
                    "round {round} unit {unit} units {units}"
                );
            }
        }
    }
}

/// `last_one` finds the highest set bit at or below a position across
/// words, and `None` when there is none.
#[test]
fn last_one_scans_down_whole_words() {
    let bits = [1u64 << 5, 0, 1u64 << 63];
    let word = |index: usize| bits.get(index).copied().unwrap_or(0);
    assert_eq!(last_one(4, word), None);
    assert_eq!(last_one(5, word), Some(5));
    assert_eq!(last_one(64 + 63, word), Some(5));
    assert_eq!(last_one(128 + 62, word), Some(5));
    assert_eq!(last_one(128 + 63, word), Some(128 + 63));
    assert_eq!(last_one(1000, word), Some(128 + 63));
}

/// GU-11: a gap counter increment that would overflow keeps the value and
/// sets the sticky flag; other counters still count.
#[test]
fn gap_counters_never_wrap() {
    let mut counters = GapCounters {
        gap_bytes: u64::MAX - 10,
        ..GapCounters::default()
    };
    counters.sealed(64, crate::local_gap::GapReason::ReorderExpired);
    assert_eq!(counters.gap_bytes, u64::MAX - 10);
    assert!(counters.overflowed);
    assert_eq!((counters.gaps_sealed, counters.reorder_expired), (1, 1));
    counters.sealed(32, crate::local_gap::GapReason::RangeUnavailable);
    assert_eq!(counters.range_unavailable_skips, 1);
    assert!(counters.overflowed, "sticky");
}
