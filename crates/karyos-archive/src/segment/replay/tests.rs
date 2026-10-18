// SPDX-License-Identifier: Apache-2.0

// A recording's range read back: entries in order and byte-exact, starts
// at frame boundaries only, the range's end, frame-bounded pieces with
// their CRC, segments crossed, and the three paces.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::num::NonZeroU32;
use std::path::Path;

use super::*;
use crate::fault::FaultDisk;
use crate::segment::{SegmentStore, SyncPolicy};

const DIR: &str = "/archive";
const RECORDING: u64 = 5;

fn geometry() -> Geometry {
    Geometry::new(1024, 2048).unwrap()
}

/// Frames of `lengths` bytes each, every one but the last padded to 32
/// bytes, with its length in its first word and `fill` after it.
fn frames(lengths: &[u32], fill: u8) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (index, &length) in lengths.iter().enumerate() {
        let mut frame = vec![fill; usize::try_from(length).unwrap()];
        frame[..4].copy_from_slice(&i32::try_from(length).unwrap().to_le_bytes());
        bytes.extend_from_slice(&frame);
        if index + 1 < lengths.len() {
            let padded = bytes.len().div_ceil(32) * 32;
            bytes.resize(padded, 0);
        }
    }
    bytes
}

fn fill_record(position: u64) -> [u8; 32] {
    let mut record = [0u8; 32];
    record[..4].copy_from_slice(&32i32.to_le_bytes());
    record[8..16].copy_from_slice(&position.to_le_bytes());
    record
}

/// A recording: two frames (100 and 60 bytes, stamped 1000), a padding
/// block of 96 (2000), a gap of 64 (3000), then three frames (4000).
/// Returns the disk and the recording's end.
fn recorded() -> (FaultDisk, Vec<u8>, Vec<u8>, u64) {
    let disk = FaultDisk::default();
    let mut store = SegmentStore::create(
        disk.clone(),
        Path::new(DIR),
        RECORDING,
        geometry(),
        SyncPolicy::PerSegment,
        0,
    )
    .unwrap();
    let first = frames(&[100, 60], 0xA1);
    let last = frames(&[40, 200, 50], 0xB2);
    store.stamp(1000);
    let mut position = store.append(0, &first).unwrap();
    store.stamp(2000);
    position = store
        .append_fill(position, &fill_record(position), 96)
        .unwrap();
    store.stamp(3000);
    position = store.append_gap(position, position + 64).unwrap();
    store.stamp(4000);
    position = store.append(position, &last).unwrap();
    store.close().unwrap();
    (disk, first, last, position)
}

fn open_source(
    disk: &FaultDisk,
    from: u64,
    to: u64,
    rate: Rate,
    buffer: usize,
) -> ReplaySource<FaultDisk> {
    ReplaySource::open(
        disk.clone(),
        Path::new(DIR),
        RECORDING,
        geometry(),
        from,
        to,
        rate,
        buffer,
    )
    .unwrap()
}

/// What a step was, owned.
#[derive(Debug, PartialEq, Eq)]
enum Seen {
    Frames(u64, Vec<u8>),
    Fill(u64, Vec<u8>, u32),
    Gap(u64, u64),
    Wait(u64),
    End(u64),
}

fn seen(step: Step<'_>) -> Seen {
    match step {
        Step::Frames { position, bytes } => Seen::Frames(position, bytes.to_vec()),
        Step::Fill {
            position,
            record,
            extent,
        } => Seen::Fill(position, record.to_vec(), extent),
        Step::Gap { from, to } => Seen::Gap(from, to),
        Step::Wait { until_ns } => Seen::Wait(until_ns),
        Step::End { position } => Seen::End(position),
    }
}

/// More steps than any replay here takes: a replay that never ends fails
/// fast instead of hanging the suite.
const MAX_STEPS: usize = 1000;

/// Every step at a fixed clock until the end.
fn drain(source: &mut ReplaySource<FaultDisk>, now: u64) -> Vec<Seen> {
    let mut steps = Vec::new();
    loop {
        assert!(steps.len() < MAX_STEPS, "no end after {MAX_STEPS} steps");
        let step = seen(source.poll(now).unwrap());
        let done = matches!(step, Seen::End(_));
        steps.push(step);
        if done {
            return steps;
        }
    }
}

#[test]
fn a_full_replay_yields_every_entry_byte_exact() {
    let (disk, first, last, end) = recorded();
    let first_len = u64::try_from(first.len()).unwrap();
    let mut source = open_source(&disk, 0, end, Rate::Full, 4096);
    assert_eq!(
        drain(&mut source, 0),
        vec![
            Seen::Frames(0, first.clone()),
            Seen::Fill(first_len, fill_record(first_len).to_vec(), 96),
            Seen::Gap(first_len + 96, first_len + 160),
            Seen::Frames(first_len + 160, last.clone()),
            Seen::End(end),
        ]
    );
    // Polled again, it stays at its end.
    assert_eq!(seen(source.poll(0).unwrap()), Seen::End(end));
}

#[test]
fn a_replay_starts_at_frame_boundaries_only() {
    let (disk, first, _, end) = recorded();
    let first_len = u64::try_from(first.len()).unwrap();
    // The second frame of the first entry.
    let mut inside = open_source(&disk, 128, end, Rate::Full, 4096);
    assert_eq!(
        seen(inside.poll(0).unwrap()),
        Seen::Frames(128, first[128..].to_vec())
    );
    // Inside a gap: the rest of the gap.
    let mut gap = open_source(&disk, first_len + 100, end, Rate::Full, 4096);
    assert_eq!(
        seen(gap.poll(0).unwrap()),
        Seen::Gap(first_len + 100, first_len + 160)
    );
    // Not a frame start, inside a fill, past the end, an empty range.
    for (from, to) in [(32, end), (first_len + 32, end)] {
        assert!(matches!(
            ReplaySource::open(
                disk.clone(),
                Path::new(DIR),
                RECORDING,
                geometry(),
                from,
                to,
                Rate::Full,
                4096
            ),
            Err(ReplayError::NotAFrameBoundary { .. })
        ));
    }
    for (from, to) in [(end, end + 64), (64, 64)] {
        assert!(matches!(
            ReplaySource::open(
                disk.clone(),
                Path::new(DIR),
                RECORDING,
                geometry(),
                from,
                to,
                Rate::Full,
                4096
            ),
            Err(ReplayError::OutOfRange { .. })
        ));
    }
}

#[test]
fn a_replay_ends_at_the_last_whole_frame_below_its_end() {
    let (disk, first, last, _) = recorded();
    let first_len = u64::try_from(first.len()).unwrap();
    let last_at = first_len + 160;
    // Inside the third entry's second frame (40 bytes padded to 64, then
    // 200): only the first frame is replayed.
    let to = last_at + 64 + 100;
    let mut source = open_source(&disk, last_at, to, Rate::Full, 4096);
    assert_eq!(
        drain(&mut source, 0),
        vec![
            Seen::Frames(last_at, last[..64].to_vec()),
            Seen::End(last_at + 64),
        ]
    );
    // Inside the fill: replay ends before it.
    let mut before_fill = open_source(&disk, 0, first_len + 50, Rate::Full, 4096);
    assert_eq!(
        drain(&mut before_fill, 0),
        vec![Seen::Frames(0, first), Seen::End(first_len)]
    );
}

#[test]
fn an_entry_larger_than_the_buffer_comes_in_frame_bounded_pieces() {
    let (disk, _, last, end) = recorded();
    let last_at = end - u64::try_from(last.len()).unwrap();
    // 256 bytes: the 64-byte frame, then the 224-byte frame alone, then
    // the last.
    let mut source = open_source(&disk, last_at, end, Rate::Full, 256);
    assert_eq!(
        drain(&mut source, 0),
        vec![
            Seen::Frames(last_at, last[..64].to_vec()),
            Seen::Frames(last_at + 64, last[64..288].to_vec()),
            Seen::Frames(last_at + 288, last[288..].to_vec()),
            Seen::End(end),
        ]
    );
    // A buffer below a frame is refused when the frame comes.
    let mut tiny = source_with(&disk, last_at, end, 128);
    assert!(matches!(tiny.poll(0), Ok(Step::Frames { .. })));
    assert!(matches!(
        tiny.poll(0),
        Err(ReplayError::BufferTooSmall { length: 224 })
    ));
}

fn source_with(disk: &FaultDisk, from: u64, to: u64, buffer: usize) -> ReplaySource<FaultDisk> {
    open_source(disk, from, to, Rate::Full, buffer)
}

#[test]
fn damaged_data_is_reported_whole_or_in_pieces() {
    for buffer in [4096, 256] {
        let (disk, _, last, end) = recorded();
        let last_at = end - u64::try_from(last.len()).unwrap();
        // One byte of the third entry's last frame, in the data file.
        let mut raw = disk.clone();
        let data = raw
            .open(&Path::new(DIR).join(data_name(RECORDING, 0)))
            .unwrap();
        raw.write_at(&data, last_at + 300, &[0xEE]).unwrap();
        let mut source = open_source(&disk, last_at, end, Rate::Full, buffer);
        let mut steps = 0;
        let error = loop {
            steps += 1;
            assert!(steps < MAX_STEPS, "no end after {MAX_STEPS} steps");
            match source.poll(0) {
                Ok(Step::End { .. }) => panic!("buffer {buffer}: no error"),
                Ok(_) => {}
                Err(error) => break error,
            }
        };
        assert!(
            matches!(error, ReplayError::Corrupt { position } if position == last_at),
            "buffer {buffer}: {error:?}"
        );
    }
}

#[test]
fn a_replay_crosses_segments() {
    let disk = FaultDisk::default();
    let mut store = SegmentStore::create(
        disk.clone(),
        Path::new(DIR),
        RECORDING,
        geometry(),
        SyncPolicy::PerSegment,
        0,
    )
    .unwrap();
    // Four 1024-byte terms of two 512-byte frames each, over two segments.
    let term = frames(&[512, 512], 0xC3);
    let mut position = 0;
    for _ in 0..4 {
        position = store.append(position, &term).unwrap();
    }
    store.close().unwrap();
    let mut source = open_source(&disk, 0, position, Rate::Full, 4096);
    let steps = drain(&mut source, 0);
    let starts: Vec<u64> = steps
        .iter()
        .filter_map(|step| match step {
            Seen::Frames(position, bytes) => {
                assert_eq!(bytes, &term);
                Some(*position)
            }
            _ => None,
        })
        .collect();
    assert_eq!(starts, [0, 1024, 2048, 3072]);
    assert_eq!(steps.last(), Some(&Seen::End(4096)));
}

#[test]
fn a_paced_replay_waits_for_each_record_time() {
    let (disk, _, _, end) = recorded();
    // As recorded: entries 1000 ns apart, then 1000, then 1000.
    let mut paced = open_source(&disk, 0, end, Rate::AsRecorded, 4096);
    assert!(matches!(seen(paced.poll(50).unwrap()), Seen::Frames(0, _)));
    assert_eq!(seen(paced.poll(500).unwrap()), Seen::Wait(1050));
    assert!(matches!(seen(paced.poll(1050).unwrap()), Seen::Fill(..)));
    assert_eq!(seen(paced.poll(1051).unwrap()), Seen::Wait(2050));
    assert!(matches!(seen(paced.poll(2050).unwrap()), Seen::Gap(..)));
    assert!(matches!(seen(paced.poll(3050).unwrap()), Seen::Frames(..)));
    // Twice as fast: half the gaps.
    let mut fast = open_source(&disk, 0, end, scaled(2_000_000), 4096);
    assert!(matches!(seen(fast.poll(0).unwrap()), Seen::Frames(0, _)));
    assert_eq!(seen(fast.poll(1).unwrap()), Seen::Wait(500));
}

fn scaled(ppm: u32) -> Rate {
    Rate::Scaled {
        ppm: NonZeroU32::new(ppm).unwrap(),
    }
}

#[test]
fn entries_without_a_record_time_refuse_a_paced_replay() {
    let disk = FaultDisk::default();
    let mut store = SegmentStore::create(
        disk.clone(),
        Path::new(DIR),
        RECORDING,
        geometry(),
        SyncPolicy::PerSegment,
        0,
    )
    .unwrap();
    let end = store.append(0, &frames(&[100], 0xD4)).unwrap();
    store.close().unwrap();
    for rate in [Rate::AsRecorded, scaled(1)] {
        let mut paced = open_source(&disk, 0, end, rate, 4096);
        assert!(matches!(
            paced.poll(0),
            Err(ReplayError::RecordTimeUnknown { position: 0 })
        ));
    }
    let mut full = open_source(&disk, 0, end, Rate::Full, 4096);
    assert!(matches!(full.poll(0), Ok(Step::Frames { position: 0, .. })));
}

/// A stamp of 0 is written as 1, never as "unknown".
#[test]
fn a_stamp_of_zero_is_a_known_time() {
    let disk = FaultDisk::default();
    let mut store = SegmentStore::create(
        disk.clone(),
        Path::new(DIR),
        RECORDING,
        geometry(),
        SyncPolicy::PerSegment,
        0,
    )
    .unwrap();
    store.stamp(0);
    let end = store.append(0, &frames(&[100], 0xD4)).unwrap();
    store.close().unwrap();
    let mut paced = open_source(&disk, 0, end, Rate::AsRecorded, 4096);
    assert!(matches!(paced.poll(0), Ok(Step::Frames { .. })));
}

/// A fill's record is checked against its CRC too.
#[test]
fn a_damaged_fill_record_is_reported() {
    let (disk, first, _, end) = recorded();
    let fill_at = u64::try_from(first.len()).unwrap();
    let mut raw = disk.clone();
    let data = raw
        .open(&Path::new(DIR).join(data_name(RECORDING, 0)))
        .unwrap();
    raw.write_at(&data, fill_at + 9, &[0xEE]).unwrap();
    let mut source = open_source(&disk, fill_at, end, Rate::Full, 4096);
    assert!(matches!(
        source.poll(0),
        Err(ReplayError::Corrupt { position }) if position == fill_at
    ));
}

/// Writes `byte` over the data file of the segment at `base`, at
/// `position`.
fn damage(disk: &FaultDisk, base: u64, position: u64, byte: u8) {
    let mut raw = disk.clone();
    let data = raw
        .open(&Path::new(DIR).join(data_name(RECORDING, base)))
        .unwrap();
    raw.write_at(&data, position - base, &[byte]).unwrap();
}

/// Every step until the end or an error.
fn until_error(source: &mut ReplaySource<FaultDisk>) -> (Vec<Seen>, Option<ReplayError>) {
    let mut steps = Vec::new();
    loop {
        assert!(steps.len() < MAX_STEPS, "no end after {MAX_STEPS} steps");
        match source.poll(0) {
            Ok(step) => {
                let step = seen(step);
                let done = matches!(step, Seen::End(_));
                steps.push(step);
                if done {
                    return (steps, None);
                }
            }
            Err(error) => return (steps, Some(error)),
        }
    }
}

/// #364 review P1: a range that starts or stops inside an entry still has
/// the entry's CRC checked, before any of its bytes is delivered.
#[test]
fn damage_inside_an_entry_is_caught_wherever_the_range_starts_or_stops() {
    // Starts at the first entry's second frame; damage after it.
    let (disk, _, _, end) = recorded();
    damage(&disk, 0, 150, 0xEE);
    let inside = open_source_result(&disk, 128, end, 4096);
    assert!(
        matches!(inside, Err(ReplayError::Corrupt { position: 0 })),
        "{inside:?}"
    );
    // Starts at the entry; stops inside it; damage in what is delivered.
    let (disk, _, _, _) = recorded();
    damage(&disk, 0, 50, 0xEE);
    let mut source = open_source(&disk, 0, 150, Rate::Full, 4096);
    let (steps, error) = until_error(&mut source);
    assert_eq!(steps, []);
    assert!(matches!(error, Some(ReplayError::Corrupt { position: 0 })));
    // And damage in what is not delivered.
    let (disk, _, _, _) = recorded();
    damage(&disk, 0, 140, 0xEE);
    let mut source = open_source(&disk, 0, 120, Rate::Full, 4096);
    let (steps, error) = until_error(&mut source);
    assert_eq!(steps, []);
    assert!(matches!(error, Some(ReplayError::Corrupt { position: 0 })));
}

fn open_source_result(
    disk: &FaultDisk,
    from: u64,
    to: u64,
    buffer: usize,
) -> Result<ReplaySource<FaultDisk>, ReplayError> {
    ReplaySource::open(
        disk.clone(),
        Path::new(DIR),
        RECORDING,
        geometry(),
        from,
        to,
        Rate::Full,
        buffer,
    )
}

/// #364 review P2: an entry read in pieces yields none of them before its
/// CRC holds, wherever the damage is.
#[test]
fn no_piece_comes_before_its_entry_is_checked() {
    for offset in [10, 100, 300] {
        let (disk, _, last, end) = recorded();
        let last_at = end - u64::try_from(last.len()).unwrap();
        damage(&disk, 0, last_at + offset, 0xEE);
        let mut source = open_source(&disk, last_at, end, Rate::Full, 256);
        let (steps, error) = until_error(&mut source);
        assert_eq!(steps, [], "damage at {offset}");
        assert!(
            matches!(error, Some(ReplayError::Corrupt { position }) if position == last_at),
            "damage at {offset}: {error:?}"
        );
    }
}

/// A recording in the store, of `terms` terms of two 512-byte frames, as
/// `a_replay_crosses_segments` writes it; the store stays open.
fn open_store(terms: usize) -> (FaultDisk, SegmentStore<FaultDisk>, Vec<u8>, u64) {
    let disk = FaultDisk::default();
    let mut store = SegmentStore::create(
        disk.clone(),
        Path::new(DIR),
        RECORDING,
        geometry(),
        SyncPolicy::PerSegment,
        0,
    )
    .unwrap();
    let term = frames(&[512, 512], 0xC3);
    let mut position = 0;
    for _ in 0..terms {
        position = store.append(position, &term).unwrap();
    }
    (disk, store, term, position)
}

/// #364 review P2: what a replay reads is fixed at open. Entries written
/// after, in the same segment or past a roll, are not delivered, and do not
/// make the replay fail; a `to` past what the recording held is clamped.
#[test]
fn a_replay_reads_what_the_recording_held_at_open() {
    for (terms, more) in [(1, 1), (1, 3), (2, 2), (3, 1)] {
        let (disk, mut store, term, held) = open_store(terms);
        let mut source = open_source(&disk, 0, u64::MAX, Rate::Full, 4096);
        let mut position = held;
        for _ in 0..more {
            position = store.append(position, &term).unwrap();
        }
        let steps = drain(&mut source, 0);
        let delivered: u64 = steps
            .iter()
            .map(|step| match step {
                Seen::Frames(_, bytes) => u64::try_from(bytes.len()).unwrap(),
                _ => 0,
            })
            .sum();
        assert_eq!(delivered, held, "{terms} terms, {more} more");
        assert_eq!(steps.last(), Some(&Seen::End(held)));
        store.close().unwrap();
    }
}

/// #364 review P3: a segment missing inside the range is reported, not
/// taken for the recording's end.
#[test]
fn a_missing_segment_is_not_the_end() {
    let (disk, mut store, term, mut position) = open_store(6);
    for _ in 0..2 {
        position = store.append(position, &term).unwrap();
    }
    store.close().unwrap();
    let mut raw = disk.clone();
    raw.remove(&Path::new(DIR).join(data_name(RECORDING, 2048)))
        .unwrap();
    raw.remove(&Path::new(DIR).join(index_name(RECORDING, 2048)))
        .unwrap();
    assert!(matches!(
        open_source_result(&disk, 0, position, 4096),
        Err(ReplayError::MissingSegment { base: 2048 })
    ));
    // Removed after open: found when the replay reaches it.
    let (disk, mut store, term, mut position) = open_store(6);
    for _ in 0..2 {
        position = store.append(position, &term).unwrap();
    }
    store.close().unwrap();
    let mut source = open_source(&disk, 0, position, Rate::Full, 4096);
    let mut raw = disk.clone();
    raw.remove(&Path::new(DIR).join(index_name(RECORDING, 4096)))
        .unwrap();
    let (_, error) = until_error(&mut source);
    assert!(
        matches!(error, Some(ReplayError::MissingSegment { base: 4096 })),
        "{error:?}"
    );
}

/// #364 review P3: a version 1 index is foreign, as recovery says.
#[test]
fn a_version_1_index_is_foreign() {
    let (disk, store, _, end) = open_store(1);
    drop(store);
    let mut raw = disk.clone();
    let index = raw
        .open(&Path::new(DIR).join(index_name(RECORDING, 0)))
        .unwrap();
    let mut header = [0u8; 48];
    raw.read_at(&index, 0, &mut header).unwrap();
    // Version 1 (u32 at 4), with the header's CRC (at 44) redone.
    header[4..8].copy_from_slice(&1u32.to_le_bytes());
    let crc = crate::crc32c::crc32c(&header[..44]);
    header[44..48].copy_from_slice(&crc.to_le_bytes());
    raw.write_at(&index, 0, &header).unwrap();
    assert!(matches!(
        open_source_result(&disk, 0, end, 4096),
        Err(ReplayError::Segment(SegmentError::BadHeader {
            problem: HeaderProblem::Foreign,
            ..
        }))
    ));
}

/// #364 review P3: pacing applies only to entries that deliver, and its
/// arithmetic fails typed.
#[test]
fn pacing_applies_to_delivered_entries_and_fails_typed() {
    // A frame stamped 0 past the end of a paced replay: the end, not
    // RecordTimeUnknown.
    let disk = FaultDisk::default();
    let mut store = SegmentStore::create(
        disk.clone(),
        Path::new(DIR),
        RECORDING,
        geometry(),
        SyncPolicy::PerSegment,
        0,
    )
    .unwrap();
    store.stamp(10);
    let mut position = store.append(0, &frames(&[64], 0xE5)).unwrap();
    let unstamped = position;
    store.stamp(0);
    position = store.append(position, &frames(&[64, 64], 0xE6)).unwrap();
    store.close().unwrap();
    let mut paced = open_source(&disk, 0, unstamped + 32, Rate::AsRecorded, 4096);
    assert!(matches!(
        paced.poll(0),
        Ok(Step::Frames { position: 0, .. })
    ));
    assert!(matches!(paced.poll(0), Ok(Step::End { position }) if position == unstamped));
    // Stamped 0 is written as 1: before 10, so recorded backward.
    let mut backward = open_source(&disk, 0, position, Rate::AsRecorded, 4096);
    assert!(matches!(backward.poll(0), Ok(Step::Frames { .. })));
    assert!(matches!(
        backward.poll(0),
        Err(ReplayError::RecordTimeBackward { position }) if position == unstamped
    ));
    // A gap of nearly the clock's range at the slowest scale.
    let disk = FaultDisk::default();
    let mut store = SegmentStore::create(
        disk.clone(),
        Path::new(DIR),
        RECORDING,
        geometry(),
        SyncPolicy::PerSegment,
        0,
    )
    .unwrap();
    store.stamp(1);
    let mut position = store.append(0, &frames(&[64], 0xE7)).unwrap();
    let late = position;
    store.stamp(20_000_000_000_000);
    position = store.append(position, &frames(&[64], 0xE8)).unwrap();
    store.close().unwrap();
    let mut slow = open_source(&disk, 0, position, scaled(1), 4096);
    assert!(matches!(slow.poll(0), Ok(Step::Frames { .. })));
    assert!(matches!(
        slow.poll(0),
        Err(ReplayError::PacingOverflow { position }) if position == late
    ));
}

/// A frame length that does not hold, under a valid CRC (the recorder
/// wrote what its source gave), is caught before any frame of the entry
/// goes out.
#[test]
fn a_frame_that_does_not_hold_is_caught_before_delivery() {
    let disk = FaultDisk::default();
    let mut store = SegmentStore::create(
        disk.clone(),
        Path::new(DIR),
        RECORDING,
        geometry(),
        SyncPolicy::PerSegment,
        0,
    )
    .unwrap();
    // Two good frames, then one whose length passes the entry's end.
    let mut bytes = frames(&[64, 64], 0xF1);
    let mut bad = vec![0xF2u8; 64];
    bad[..4].copy_from_slice(&1000i32.to_le_bytes());
    bytes.extend_from_slice(&bad);
    let end = store.append(0, &bytes).unwrap();
    store.close().unwrap();
    // Read in pieces (64, 128) or whole (192, 4096): refused either way.
    for buffer in [64, 128, 192, 4096] {
        let mut source = open_source(&disk, 0, end, Rate::Full, buffer);
        let (steps, error) = until_error(&mut source);
        assert_eq!(steps, [], "buffer {buffer}");
        assert!(
            matches!(error, Some(ReplayError::Corrupt { position: 128 })),
            "buffer {buffer}: {error:?}"
        );
    }
}

/// #364 re-check P1: valid entries replay whole whatever the buffer, down
/// to one frame: a frame that does not fit what is left of a window waits
/// for the next one, never reads as corrupt.
#[test]
fn valid_entries_replay_whatever_the_buffer() {
    for (lengths, buffer) in [
        (&[512u32, 512][..], 512usize),
        (&[128, 128, 128, 128][..], 256),
        (&[32, 32, 32, 32][..], 64),
        (&[32, 32, 32, 32][..], 98),
        (&[100, 60, 40][..], 128),
    ] {
        let disk = FaultDisk::default();
        let mut store = SegmentStore::create(
            disk.clone(),
            Path::new(DIR),
            RECORDING,
            geometry(),
            SyncPolicy::PerSegment,
            0,
        )
        .unwrap();
        let bytes = frames(lengths, 0xAB);
        let end = store.append(0, &bytes).unwrap();
        store.close().unwrap();
        let mut source = open_source(&disk, 0, end, Rate::Full, buffer);
        let (steps, error) = until_error(&mut source);
        assert!(error.is_none(), "{lengths:?}/{buffer}: {error:?}");
        let mut replayed = Vec::new();
        for step in &steps {
            if let Seen::Frames(position, frames) = step {
                assert_eq!(*position, replayed.len() as u64);
                replayed.extend_from_slice(frames);
            }
        }
        assert_eq!(replayed, bytes, "{lengths:?}/{buffer}");
        assert_eq!(steps.last(), Some(&Seen::End(end)));
    }
}

/// #364 re-check P3: an error is final; the next poll does not carry on.
#[test]
fn an_error_is_final() {
    let (disk, mut store, term, mut position) = open_store(6);
    for _ in 0..2 {
        position = store.append(position, &term).unwrap();
    }
    store.close().unwrap();
    let mut source = open_source(&disk, 0, position, Rate::Full, 4096);
    let mut raw = disk.clone();
    raw.remove(&Path::new(DIR).join(index_name(RECORDING, 4096)))
        .unwrap();
    let (_, error) = until_error(&mut source);
    assert!(matches!(error, Some(ReplayError::MissingSegment { .. })));
    for _ in 0..3 {
        assert!(matches!(source.poll(0), Err(ReplayError::Failed)));
    }
}

/// #364 re-check P3: a paced replay that ends inside a fill ends there,
/// with no wait for the fill it does not deliver.
#[test]
fn a_paced_replay_ending_in_a_fill_does_not_wait_for_it() {
    let (disk, first, _, _) = recorded();
    let first_len = u64::try_from(first.len()).unwrap();
    let mut paced = open_source(&disk, 0, first_len + 50, Rate::AsRecorded, 4096);
    assert!(matches!(
        paced.poll(0),
        Ok(Step::Frames { position: 0, .. })
    ));
    assert_eq!(seen(paced.poll(0).unwrap()), Seen::End(first_len));
}

/// An index whose next entry does not start where the last ended is
/// corrupt, not a jump.
#[test]
fn entries_that_do_not_follow_each_other_are_corrupt() {
    let (disk, _, _, end) = recorded();
    let mut raw = disk.clone();
    let index = raw
        .open(&Path::new(DIR).join(index_name(RECORDING, 0)))
        .unwrap();
    // The fill (entry 1) moved 32 bytes on, its own CRC redone.
    let at = entry_offset(1).unwrap();
    let mut bytes = [0u8; ENTRY as usize];
    raw.read_at(&index, at, &mut bytes).unwrap();
    let Some(Ok(mut entry)) = Entry::decode(&bytes) else {
        panic!("entry 1");
    };
    let fill_at = entry.start;
    entry.start += 32;
    raw.write_at(&index, at, &entry.encode()).unwrap();
    let mut source = open_source(&disk, 0, end, Rate::Full, 4096);
    assert!(matches!(source.poll(0), Ok(Step::Frames { .. })));
    assert!(matches!(
        source.poll(0),
        Err(ReplayError::Corrupt { position }) if position == fill_at
    ));
}

/// A due time past the caller's clock range is an error, not a wait that
/// never ends.
#[test]
fn a_due_time_past_the_clock_is_an_error() {
    let (disk, _, _, end) = recorded();
    let mut paced = open_source(&disk, 0, end, Rate::AsRecorded, 4096);
    let late = u64::MAX - 10;
    assert!(matches!(paced.poll(late), Ok(Step::Frames { .. })));
    assert!(matches!(
        paced.poll(late),
        Err(ReplayError::PacingOverflow { .. })
    ));
}

/// An entry whose last frame's length word is cut by the entry's end is
/// corrupt, read whole or in pieces, before any of it goes out.
#[test]
fn a_frame_cut_by_its_entry_end_is_caught_before_delivery() {
    let disk = FaultDisk::default();
    let mut store = SegmentStore::create(
        disk.clone(),
        Path::new(DIR),
        RECORDING,
        geometry(),
        SyncPolicy::PerSegment,
        0,
    )
    .unwrap();
    let mut bytes = frames(&[128], 0xC1);
    bytes.extend_from_slice(&[0x10, 0x00]);
    let end = store.append(0, &bytes).unwrap();
    store.close().unwrap();
    for buffer in [64, 4096] {
        let mut source = open_source(&disk, 0, end, Rate::Full, buffer);
        let (steps, error) = until_error(&mut source);
        assert_eq!(steps, [], "buffer {buffer}");
        assert!(
            matches!(error, Some(ReplayError::Corrupt { position: 128 })),
            "buffer {buffer}: {error:?}"
        );
    }
}
