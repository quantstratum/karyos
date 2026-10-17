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
