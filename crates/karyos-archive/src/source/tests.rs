// SPDX-License-Identifier: Apache-2.0

// Recordings of a real lane log (a heap log buffer): the frames recorded
// as the log holds them, a term end's padding as a fill, and an optional
// reader lapped, recorded as a gap and resumed.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::cast_possible_truncation,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::path::Path;

use karyos_sys::frame::{FrameType, Lane, Word0};
use karyos_sys::log_buffer::{
    AppendOptions, AppendOutcome, DEFAULT_CLAIM_DEADLINE, LogBuffer, LogBufferConfig,
    PublicationMode, Role, SenderRead,
};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

use crate::catalog::StopReason;
use crate::fault::FaultDisk;
use crate::recorder::{FrameSource, Frames, Mode, OnLap, Recorder};
use crate::segment::{Geometry, SegmentStore, SyncPolicy};

fn config() -> LogBufferConfig {
    LogBufferConfig {
        term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
        spare_slots: 3,
        max_subscribers: 4,
        mtu: DEFAULT_MTU,
        max_reserved: MIN_TERM_LENGTH / 8,
        initial_term_id: TermId::new(7),
        lane: Lane::ZERO,
        session_id: 3,
        stream_id: 4,
        claim_deadline: DEFAULT_CLAIM_DEADLINE,
        publication: PublicationMode::Exclusive,
        schedule_capacity: 0,
    }
}

fn message(sequence: u32, length: usize) -> Vec<u8> {
    let mut data: Vec<u8> = (0..length).map(|i| (i as u8) ^ (sequence as u8)).collect();
    data[..4].copy_from_slice(&sequence.to_le_bytes());
    data
}

fn store(start: u64) -> SegmentStore<FaultDisk> {
    let geometry = Geometry::new(MIN_TERM_LENGTH, u64::from(MIN_TERM_LENGTH) * 4).unwrap();
    SegmentStore::create(
        FaultDisk::default(),
        Path::new("/archive"),
        1,
        geometry,
        SyncPolicy::None,
        start,
    )
    .unwrap()
}

/// Walks the recorded bytes `[start, end)` as the log's frames: the
/// messages reassembled, and how many padding blocks were stepped.
fn walk(store: &mut SegmentStore<FaultDisk>, start: u64, end: u64) -> (Vec<Vec<u8>>, u32) {
    let mut bytes = vec![0u8; (end - start) as usize];
    store.read(start, &mut bytes).unwrap();
    let (mut messages, mut pads, mut partial) = (Vec::new(), 0, None::<Vec<u8>>);
    let mut offset = 0usize;
    while offset < bytes.len() {
        let word = Word0::unpack(u64::from_le_bytes(
            bytes[offset..offset + 8].try_into().unwrap(),
        ))
        .unwrap();
        let length = word.frame_length() as usize;
        if word.frame_type_code() == FrameType::Pad.code() {
            pads += 1;
            // A padding block runs to the term end.
            let term = MIN_TERM_LENGTH as usize;
            let position = start as usize + offset;
            offset += term - position % term;
            continue;
        }
        let flags = word.flags();
        let payload = &bytes[offset + flags.header_length() as usize..offset + length];
        if flags.begin() {
            partial = Some(Vec::new());
        }
        partial.as_mut().unwrap().extend_from_slice(payload);
        if flags.end() {
            messages.push(partial.take().unwrap());
        }
        offset += length.div_ceil(32) * 32;
    }
    (messages, pads)
}

/// A required recording of a lane across a term end: every message is
/// recorded where the log holds it, fragmented ones included, and the
/// padding at the term end is a fill; the recorder's consumption lets the
/// publisher go on.
#[test]
fn a_required_recording_holds_the_lane_as_the_log_does() {
    let buffer = LogBuffer::new(config()).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let source =
        SenderRead::for_recording(conductor.subscribe_as(Role::Required, true, 1).unwrap(), 3)
            .unwrap();
    let mut recorder = Recorder::new(store(0), source, Mode::Required, 1 << 16, 1 << 20).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let mut published = Vec::new();
    let mut sequence = 0u32;
    // A bit more than a term: the last message does not fit, so the term
    // ends in padding.
    while (published.iter().map(Vec::len).sum::<usize>() as u32) < MIN_TERM_LENGTH + 4000 {
        let length = if sequence % 5 == 4 { 3000 } else { 900 };
        let data = message(sequence, length);
        loop {
            match publication.append(&data, AppendOptions::default()).unwrap() {
                AppendOutcome::Appended { .. } => break,
                _ => {
                    let _ = recorder.duty(0).unwrap();
                    let _ = conductor.duty_cycle().unwrap();
                }
            }
        }
        published.push(data);
        sequence += 1;
        let _ = recorder.duty(0).unwrap();
        let _ = conductor.duty_cycle().unwrap();
    }
    let _ = recorder.duty(0).unwrap();
    let written = recorder.store().written();
    let (messages, pads) = walk(recorder.store_mut(), 0, written);
    assert_eq!(messages, published);
    assert!(pads >= 1, "the term end is a fill");
    assert_eq!(recorder.store().gaps(), []);
}

/// An async recording the publisher laps (it writes on while the
/// recorder does not run, and the conductor reclaims the terms behind it)
/// records the lost range as a gap up to where its reader rejoins (the
/// head), and records what follows intact.
#[test]
fn a_lapped_async_recording_rejoins_at_the_head() {
    let buffer = LogBuffer::new(config()).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let source =
        SenderRead::for_recording(conductor.subscribe_as(Role::Optional, false, 1).unwrap(), 3)
            .unwrap();
    let mut recorder = Recorder::new(
        store(0),
        source,
        Mode::Async {
            on_lap: OnLap::Resume,
        },
        1 << 16,
        1 << 20,
    )
    .unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let mut published = Vec::new();
    // Five terms of messages, the recorder idle: its terms are reclaimed.
    let mut sequence = 0u32;
    while (published.iter().map(Vec::len).sum::<usize>() as u32) < MIN_TERM_LENGTH * 5 {
        let data = message(sequence, 500);
        loop {
            match publication.append(&data, AppendOptions::default()).unwrap() {
                AppendOutcome::Appended { .. } => break,
                _ => {
                    let _ = conductor.duty_cycle().unwrap();
                }
            }
        }
        published.push(data);
        sequence += 1;
        let _ = conductor.duty_cycle().unwrap();
    }
    let _ = recorder.duty(0).unwrap();
    let gaps = recorder.store().gaps().to_vec();
    assert_eq!(gaps.len(), 1, "{gaps:?}");
    let (from, resumed) = gaps[0];
    assert_eq!(from, 0);
    // The reader rejoined at the head: everything before it is the gap.
    assert_eq!(resumed, recorder.store().written());
    // What the publisher writes after the rejoin is recorded intact.
    let mut after = Vec::new();
    for sequence in 1000..1003u32 {
        let data = message(sequence, 700);
        let _ = publication.append(&data, AppendOptions::default()).unwrap();
        after.push(data);
    }
    let _ = recorder.duty(0).unwrap();
    let written = recorder.store().written();
    let (messages, _) = walk(recorder.store_mut(), resumed, written);
    assert_eq!(messages, after);
    assert!(!published.is_empty());
}

/// Records its name when dropped.
struct Noisy(
    &'static str,
    std::rc::Rc<std::cell::RefCell<Vec<&'static str>>>,
);

impl Drop for Noisy {
    fn drop(&mut self) {
        self.1.borrow_mut().push(self.0);
    }
}

/// A guarded source drops its source before its guard, so a reader never
/// outlives the lease on its stream.
#[test]
fn a_guarded_source_drops_the_source_first() {
    let order = std::rc::Rc::default();
    drop(super::Guarded::new(
        Noisy("source", std::rc::Rc::clone(&order)),
        Noisy("guard", std::rc::Rc::clone(&order)),
    ));
    assert_eq!(*order.borrow(), ["source", "guard"]);
}

/// #351 review P1: a term longer than the copy buffer, so a copy can end
/// inside a fragmented message. The publisher is released to the last
/// whole message, the recording goes on, and every byte is recorded.
#[test]
fn a_copy_ending_inside_a_message_releases_the_last_whole_one() {
    for prefix in (100..3100).step_by(100) {
        let mut config = config();
        config.term_length = TermLength::try_new(MIN_TERM_LENGTH * 4).unwrap();
        let buffer = LogBuffer::new(config).unwrap();
        let mut conductor = buffer.conductor().unwrap();
        let source =
            SenderRead::for_recording(conductor.subscribe_as(Role::Required, true, 1).unwrap(), 3)
                .unwrap();
        // The agent's default copy buffer, shorter than the term.
        let mut recorder =
            Recorder::new(store(0), source, Mode::Required, 64 * 1024, 1 << 20).unwrap();
        let mut publication = buffer.publication().unwrap().unwrap();
        let mut end = 0;
        for (sequence, length) in (0..30u32).map(|i| (i, if i == 0 { prefix } else { 3000 })) {
            match publication
                .append(&message(sequence, length), AppendOptions::default())
                .unwrap()
            {
                AppendOutcome::Appended { position, .. } => end = position,
                other => panic!("{other:?}"),
            }
        }
        let _ = conductor.duty_cycle().unwrap();
        while recorder
            .duty(0)
            .unwrap_or_else(|error| panic!("prefix {prefix}: {error:?}"))
            .recorded
            > 0
        {}
        assert!(recorder.store().written() >= end, "prefix {prefix}");
    }
}

/// #351 review P2: a copy buffer off the 32-byte stride still records: it
/// is rounded up, and a source given one copies whole strides only.
#[test]
fn a_copy_buffer_off_the_stride_still_records() {
    let buffer = LogBuffer::new(config()).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let source =
        SenderRead::for_recording(conductor.subscribe_as(Role::Required, true, 1).unwrap(), 3)
            .unwrap();
    let mut recorder = Recorder::new(store(0), source, Mode::Required, 940, 1 << 20).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    for sequence in 0..2u32 {
        let _ = publication
            .append(&message(sequence, 900), AppendOptions::default())
            .unwrap();
    }
    while recorder.duty(0).unwrap().recorded > 0 {}
    assert_eq!(recorder.store().written(), 2 * 960);
    // The source alone: two 932-byte frames at 960-byte strides, and a
    // buffer that holds the second frame but not its stride. The copy
    // stops at the first, whole with its padding.
    let buffer = LogBuffer::new(config()).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut source =
        SenderRead::for_recording(conductor.subscribe_as(Role::Required, true, 1).unwrap(), 3)
            .unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    for sequence in 0..2u32 {
        let _ = publication
            .append(&message(sequence, 900), AppendOptions::default())
            .unwrap();
    }
    let mut out = vec![0u8; 1900];
    assert_eq!(
        FrameSource::read(&mut source, &mut out).unwrap(),
        Frames::Copied {
            position: 0,
            len: 960,
            next: 960
        }
    );
}

/// Gap 6: a lane sealed for a cutover is a seal with a successor. A bare
/// reader, with no link to follow it, is fenced there: the recording
/// ends at the seal, incomplete, where a final seal ends it normally.
#[test]
fn a_seal_for_a_cutover_fences_the_recording_where_a_final_seal_ends_it() {
    for cutover in [false, true] {
        let buffer = LogBuffer::new(config()).unwrap();
        let mut conductor = buffer.conductor().unwrap();
        let source =
            SenderRead::for_recording(conductor.subscribe_as(Role::Optional, true, 1).unwrap(), 3)
                .unwrap();
        let mut recorder = Recorder::new(
            store(0),
            source,
            Mode::Async {
                on_lap: OnLap::Stop,
            },
            1 << 16,
            1 << 20,
        )
        .unwrap();
        let mut publication = buffer.publication().unwrap().unwrap();
        let mut published = Vec::new();
        for sequence in 0..4 {
            let data = message(sequence, 900);
            assert!(matches!(
                publication.append(&data, AppendOptions::default()).unwrap(),
                AppendOutcome::Appended { .. }
            ));
            published.push(data);
        }
        drop(publication);
        if cutover {
            conductor.seal_for_cutover().unwrap();
        } else {
            conductor.seal().unwrap();
        }
        let mut ended = None;
        for _ in 0..8 {
            let _ = conductor.duty_cycle().unwrap();
            let duty = recorder.duty(0).unwrap();
            assert_eq!(duty.fenced, cutover && duty.ended.is_some());
            if let Some(end) = duty.ended {
                ended = Some(end);
                break;
            }
        }
        let ended = ended.expect("the recording never ended");
        let written = recorder.store().written();
        assert_eq!(ended.position, written);
        assert_eq!(
            (ended.reason, ended.incomplete),
            if cutover {
                (StopReason::Lapped, true)
            } else {
                (StopReason::Normal, false)
            }
        );
        let (messages, _) = walk(recorder.store_mut(), 0, written);
        assert_eq!(messages, published, "cutover {cutover}");
    }
}

/// Gap 6, option B: a `Following` source of an `async` recording that
/// resumes after a lap, fenced at a cutover, asks its hook to rejoin.
/// While the host has not answered, the recording waits. Answered, it
/// rejoins the successor at its head: the messages published there before
/// the rejoin are a plain gap, and the ones after it are recorded. A
/// refused rejoin ends the recording at the seal, as a fence does.
#[test]
fn a_fenced_following_source_rejoins_at_the_head_past_a_gap() {
    use std::sync::{Arc, Mutex};

    use karyos_client::GenerationLink;

    use crate::recorder::Ended;
    use crate::source::{Following, Rejoin};

    for refused in [false, true] {
        // The predecessor: four messages, then a seal for a cutover the
        // reader is fenced from.
        let old = Arc::new(LogBuffer::new(config()).unwrap());
        let mut old_conductor = old.conductor_owned().unwrap();
        let reader = SenderRead::for_recording(
            old_conductor.subscribe_as(Role::Optional, true, 1).unwrap(),
            3,
        )
        .unwrap();
        let link = GenerationLink::new();
        let mut published = Vec::new();
        let mut publication = old.publication().unwrap().unwrap();
        for sequence in 0..4 {
            let data = message(sequence, 900);
            let _ = publication.append(&data, AppendOptions::default()).unwrap();
            published.push(data);
        }
        drop(publication);
        old_conductor.seal_for_cutover().unwrap();
        let _ = link.fence();
        let seal = 4 * 960;

        // The successor, based at the seal: two messages published before
        // the rejoin are lost, and the rejoined reader starts at the head.
        let new = Arc::new(LogBuffer::new(config()).unwrap());
        let mut new_conductor = new.conductor_owned().unwrap();
        let mut successor = Some(new.publication().unwrap().unwrap());
        for sequence in 10..12 {
            let _ = successor
                .as_mut()
                .unwrap()
                .append(&message(sequence, 900), AppendOptions::default())
                .unwrap();
        }
        let answers = Arc::new(Mutex::new(0u32));
        let asked = Arc::clone(&answers);
        let mut joined = Some((
            SenderRead::for_recording(
                new_conductor.subscribe_as(Role::Optional, true, 2).unwrap(),
                3,
            )
            .unwrap(),
            GenerationLink::new(),
        ));
        let hook = Box::new(move || {
            let mut asked = asked.lock().unwrap();
            *asked += 1;
            if *asked == 1 {
                return Rejoin::Waiting;
            }
            if refused {
                return Rejoin::Refused;
            }
            let (reader, link) = joined.take().unwrap();
            Rejoin::Joined {
                reader,
                link,
                base: seal,
                guard: Box::new(()),
            }
        });
        let mut recorder = Recorder::new(
            store(0),
            Following::rejoining(reader, link, 0, hook),
            Mode::Async {
                on_lap: OnLap::Resume,
            },
            1 << 16,
            1 << 20,
        )
        .unwrap();
        let mut rejoined = 0;
        let mut ended = None;
        for _ in 0..12 {
            let _ = old_conductor.duty_cycle().unwrap();
            let _ = new_conductor.duty_cycle().unwrap();
            let duty = recorder.duty(0).unwrap();
            if duty.rejoined {
                rejoined += 1;
                // After the rejoin, two more messages, then the end.
                let mut publication = successor.take().unwrap();
                for sequence in 20..22 {
                    let data = message(sequence, 900);
                    let _ = publication.append(&data, AppendOptions::default()).unwrap();
                    published.push(data);
                }
                drop(publication);
                new_conductor.seal().unwrap();
            }
            if let Some(end) = duty.ended {
                ended = Some(end);
                break;
            }
        }
        let ended = ended.expect("the recording never ended");
        // The hook was asked again after it waited.
        assert!(*answers.lock().unwrap() >= 2);
        if refused {
            assert_eq!(rejoined, 0);
            assert_eq!(
                ended,
                Ended {
                    position: seal,
                    reason: StopReason::Lapped,
                    incomplete: true
                }
            );
            assert!(recorder.store().gaps().is_empty());
            continue;
        }
        assert_eq!(rejoined, 1);
        let head = seal + 2 * 960;
        let end = head + 2 * 960;
        assert_eq!(
            ended,
            Ended {
                position: end,
                reason: StopReason::Normal,
                incomplete: true
            }
        );
        assert_eq!(recorder.store().gaps(), [(seal, head)]);
        let (before, _) = walk(recorder.store_mut(), 0, seal);
        let (after, _) = walk(recorder.store_mut(), head, end);
        assert_eq!(before, published[..4]);
        assert_eq!(after, published[4..]);
    }
}
