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

/// Every step at a fixed clock until the end.
fn drain(source: &mut ReplaySource<FaultDisk>, now: u64) -> Vec<Seen> {
    let mut steps = Vec::new();
    loop {
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
        let error = loop {
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
    let mut fast = open_source(&disk, 0, end, Rate::Scaled { ppm: 2_000_000 }, 4096);
    assert!(matches!(seen(fast.poll(0).unwrap()), Seen::Frames(0, _)));
    assert_eq!(seen(fast.poll(1).unwrap()), Seen::Wait(500));
    // A scale of 0 is refused.
    assert!(matches!(
        ReplaySource::open(
            disk.clone(),
            Path::new(DIR),
            RECORDING,
            geometry(),
            0,
            end,
            Rate::Scaled { ppm: 0 },
            4096
        ),
        Err(ReplayError::InvalidScale)
    ));
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
    for rate in [Rate::AsRecorded, Rate::Scaled { ppm: 1 }] {
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
