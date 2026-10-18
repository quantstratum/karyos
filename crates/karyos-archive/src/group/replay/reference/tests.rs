// SPDX-License-Identifier: Apache-2.0

// A payload by reference read back: one frame or several fragments
// reassembled byte for byte; a lost range, a wrong length, fragments out
// of order or a recording that is gone leave it unavailable.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use karyos_sys::frame::{Flags, FrameType, Lane};

use super::*;
use crate::fault::FaultDisk;
use crate::segment::{SegmentStore, SyncPolicy};

const DIR: &str = "/archive";
const RECORDING: u64 = 5;

fn geometry() -> Geometry {
    Geometry::new(4096, 8192).unwrap()
}

/// One data frame of `payload` with the flags `begin` and `end`, padded to
/// the alignment.
fn frame(payload: &[u8], begin: bool, end: bool) -> Vec<u8> {
    let length = 32 + payload.len();
    let word0 = Word0::new(
        i32::try_from(length).unwrap(),
        Flags::new(begin, end, false, false, Lane::ZERO),
        FrameType::Data,
    );
    let mut bytes = vec![0u8; length.next_multiple_of(32)];
    bytes[..8].copy_from_slice(&word0.pack().to_le_bytes());
    bytes[32..length].copy_from_slice(payload);
    bytes
}

/// A recording holding `blocks` back to back from 0, each frames or a
/// gap of that many bytes.
fn recorded(blocks: &[Result<Vec<u8>, u64>]) -> FaultDisk {
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
    let mut position = 0;
    for block in blocks {
        store.stamp(1);
        position = match block {
            Ok(bytes) => store.append(position, bytes).unwrap(),
            Err(gap) => store.append_gap(position, position + gap).unwrap(),
        };
    }
    store.close().unwrap();
    disk
}

fn recording() -> Recording<'static> {
    Recording {
        dir: Path::new(DIR),
        recording_id: RECORDING,
        geometry: geometry(),
    }
}

fn read(disk: &FaultDisk, frames: Frames) -> Option<Vec<u8>> {
    let mut out = [0u8; 512];
    read_message(disk.clone(), &recording(), frames, &mut out).map(|length| out[..length].to_vec())
}

#[test]
fn a_message_is_read_back_whole() {
    let one = frame(b"order 42", true, true);
    let mut two = frame(&[1u8; 100], true, false);
    two.extend(frame(&[2u8; 30], false, true));
    let mut blocks = one.clone();
    blocks.extend(&two);
    let disk = recorded(&[Ok(blocks)]);
    assert_eq!(
        read(
            &disk,
            Frames {
                position: 0,
                extent: u32::try_from(one.len()).unwrap(),
                length: 8,
            }
        ),
        Some(b"order 42".to_vec())
    );
    let mut wanted = vec![1u8; 100];
    wanted.extend([2u8; 30]);
    assert_eq!(
        read(
            &disk,
            Frames {
                position: u64::try_from(one.len()).unwrap(),
                extent: u32::try_from(two.len()).unwrap(),
                length: 130,
            }
        ),
        Some(wanted)
    );
}

#[test]
fn what_the_recording_cannot_give_is_unavailable() {
    let one = frame(b"order 42", true, true);
    let extent = u32::try_from(one.len()).unwrap();
    let disk = recorded(&[Ok(one.clone()), Err(64)]);
    let at = |position, extent, length| Frames {
        position,
        extent,
        length,
    };
    // Another length than recorded.
    assert_eq!(read(&disk, at(0, extent, 9)), None);
    // A range across the lost one.
    assert_eq!(read(&disk, at(0, extent + 64, 8)), None);
    // A recording that is gone.
    assert_eq!(read(&FaultDisk::default(), at(0, extent, 8)), None);
    // A continuation first, or a second beginning.
    let mut wrong = frame(b"tail", false, true);
    wrong.extend(frame(b"head", true, true));
    let disk = recorded(&[Ok(wrong.clone())]);
    let half = u32::try_from(wrong.len() / 2).unwrap();
    assert_eq!(read(&disk, at(0, half, 4)), None);
    let mut twice = frame(b"head", true, false);
    twice.extend(frame(b"head", true, true));
    let disk = recorded(&[Ok(twice.clone())]);
    assert_eq!(
        read(&disk, at(0, u32::try_from(twice.len()).unwrap(), 8)),
        None
    );
}

/// A padding block inside the range, or a message whose last fragment
/// is not there, leaves the payload unavailable.
#[test]
fn a_fill_or_a_missing_end_is_unavailable() {
    // A first fragment only: no end.
    let open = frame(b"head", true, false);
    let disk = recorded(&[Ok(open.clone())]);
    let extent = u32::try_from(open.len()).unwrap();
    assert_eq!(
        read(
            &disk,
            Frames {
                position: 0,
                extent,
                length: 4
            }
        ),
        None
    );
    // A padding block after a whole message, inside the range: the
    // extent names more than the message's frames.
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
    let whole = frame(b"head", true, true);
    let at = store.append(0, &whole).unwrap();
    let mut fill = [0u8; 32];
    fill[..4].copy_from_slice(&32i32.to_le_bytes());
    fill[8..16].copy_from_slice(&at.to_le_bytes());
    let end = store.append_fill(at, &fill, 64).unwrap();
    store.close().unwrap();
    assert_eq!(
        read(
            &disk,
            Frames {
                position: 0,
                extent: u32::try_from(end).unwrap(),
                length: 4
            }
        ),
        None
    );
}

/// A frame with the trace extension has a 96-byte header: the payload is
/// read after it, and the source's buffer holds such a frame whole.
#[test]
fn a_frame_with_the_trace_extension_is_read() {
    let payload = [5u8; 200];
    let length = 96 + payload.len();
    let word0 = Word0::new(
        i32::try_from(length).unwrap(),
        Flags::new(true, true, false, true, Lane::ZERO),
        FrameType::Data,
    );
    let mut frame = vec![0u8; length.next_multiple_of(32)];
    frame[..8].copy_from_slice(&word0.pack().to_le_bytes());
    frame[96..length].copy_from_slice(&payload);
    let disk = recorded(&[Ok(frame.clone())]);
    assert_eq!(
        read(
            &disk,
            Frames {
                position: 0,
                extent: u32::try_from(frame.len()).unwrap(),
                length: 200,
            }
        ),
        Some(payload.to_vec())
    );
}
