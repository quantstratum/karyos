// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use std::path::Path;

use super::*;
use crate::catalog::StopReason;
use crate::fault::FaultDisk;
use crate::recorder::{Mode, Recorder};
use crate::segment::{SegmentStore, SyncPolicy};

/// Terms of 64 bytes: a frame holds at most 32 payload bytes.
fn geometry() -> Geometry {
    Geometry::new(64, 128).unwrap()
}

fn queue(max_bytes: u64) -> QueueSource {
    QueueSource::new(QueueConfig::new(geometry(), 7, 9, max_bytes), 0).unwrap()
}

fn recorder(source: QueueSource) -> Recorder<FaultDisk, QueueSource> {
    let store = SegmentStore::create(
        FaultDisk::default(),
        Path::new("/journal"),
        1,
        geometry(),
        SyncPolicy::PerSegment,
        0,
    )
    .unwrap();
    Recorder::new(store, source, Mode::Required, 64, 1 << 20).unwrap()
}

/// The header fields of the frame at the start of `bytes`.
fn header(bytes: &[u8]) -> (Word0, i32, i32, i32, i32, i64) {
    let word = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
    let int = |at: usize| i32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
    (
        Word0::unpack(word(0)).unwrap(),
        int(8),
        int(12),
        int(16),
        int(20),
        i64::from_le_bytes(bytes[24..32].try_into().unwrap()),
    )
}

/// Records are laid out as a log holds them: one DATA frame each, with
/// its header, payload and alignment zeros, and a frame that does not fit
/// the term's rest goes in the next term after a padding block. The
/// recorder records them, the sync makes them durable, and a seal ends the
/// recording at the tail.
#[test]
fn records_are_recorded_as_frames_of_a_log() {
    let mut source = queue(1 << 10);
    // 32 + 5 = 37 bytes, 64 aligned: the whole first term.
    assert_eq!(source.push(b"close").unwrap(), 64);
    // 32 + 1 = 33 bytes, 64 aligned: the second term.
    assert_eq!(source.push(b"a").unwrap(), 128);
    // 32 + 0: half the third term; then 32 + 20 = 52 does not fit the 32
    // left, so a 32-byte padding block ends the term first.
    assert_eq!(source.push(b"").unwrap(), 160);
    assert_eq!(source.push(&[0xAB; 20]).unwrap(), 256);
    assert_eq!(source.queued(), 256);
    let mut recorder = recorder(source);
    let duty = recorder.duty(1).unwrap();
    assert_eq!((duty.recorded, duty.ended), (256, None));
    // The finished segment is durable; the open one waits for a sync.
    assert_eq!(recorder.store().durable(), 128);
    assert_eq!(recorder.sync().unwrap(), 256);
    let mut store_bytes = vec![0u8; 64];
    let mut read = |recorder: &mut Recorder<FaultDisk, QueueSource>, at: u64, len: usize| {
        store_bytes.resize(len, 0);
        // The store, read back as a replay would.
        let store = recorder_store(recorder);
        store.read(at, &mut store_bytes).unwrap();
        store_bytes.clone()
    };
    let first = read(&mut recorder, 0, 64);
    let (word0, offset, session, stream, term, reserved) = header(&first);
    assert_eq!(word0.frame_length(), 37);
    assert_eq!(word0.frame_type_code(), FrameType::Data.code());
    assert!(word0.flags().begin() && word0.flags().end());
    assert_eq!((offset, session, stream, term, reserved), (0, 9, 7, 0, 0));
    assert_eq!(&first[32..37], b"close");
    assert!(first[37..].iter().all(|byte| *byte == 0));
    let fill = read(&mut recorder, 160, 32);
    let (word0, offset, _, _, term, extent) = header(&fill);
    assert_eq!(word0.frame_type_code(), FrameType::Pad.code());
    assert_eq!((offset, term, extent), (32, 2, 32));
    let last = read(&mut recorder, 192, 64);
    let (word0, offset, _, _, term, _) = header(&last);
    assert_eq!((word0.frame_length(), offset, term), (52, 0, 3));
    assert_eq!(&last[32..52], &[0xAB; 20]);
}

fn recorder_store(recorder: &mut Recorder<FaultDisk, QueueSource>) -> &mut SegmentStore<FaultDisk> {
    recorder.store_mut()
}

/// A sealed queue ends the recording normally at its tail once read, and
/// takes no more records.
#[test]
fn a_sealed_queue_ends_the_recording_at_its_tail() {
    let mut source = queue(1 << 10);
    let _ = source.push(b"x").unwrap();
    source.seal();
    assert_eq!(source.push(b"y"), Err(QueueError::Sealed));
    let mut recorder = recorder(source);
    let ended = recorder.duty(1).unwrap().ended.unwrap();
    assert_eq!((ended.position, ended.reason), (64, StopReason::Normal));
}

/// A record longer than a term, or past the queue's bound, is refused and
/// changes nothing; consumption frees room.
#[test]
fn records_beyond_a_term_or_the_bound_are_refused() {
    let mut source = queue(128);
    assert_eq!(
        source.push(&[0; 33]),
        Err(QueueError::TooLarge { length: 33 })
    );
    assert_eq!(source.push(&[0; 32]).unwrap(), 64);
    assert_eq!(source.push(&[0; 32]).unwrap(), 128);
    assert_eq!(source.push(b""), Err(QueueError::Full));
    assert_eq!(source.tail(), 128);
    let mut recorder = recorder(source);
    let _ = recorder.duty(1).unwrap();
    // Recorded and consumed: the queue is empty again.
    assert_eq!(recorder.store().written(), 128);
}

/// The source holds the recorder to its contract: only the end of the
/// entry a read returned is consumed, and it is never lapped.
#[test]
fn the_source_refuses_what_its_reads_did_not_return() {
    let mut source = queue(1 << 10);
    let _ = source.push(b"x").unwrap();
    let mut out = [0u8; 64];
    assert!(matches!(
        source.read(&mut out).unwrap(),
        Frames::Copied {
            position: 0,
            len: 64,
            next: 64
        }
    ));
    assert_eq!(source.consumed(32), Err(SourceError::Invariant));
    assert_eq!(source.consumed(64), Ok(()));
    assert_eq!(source.position(), 64);
    assert_eq!(source.read(&mut out).unwrap(), Frames::Pending);
    assert_eq!(source.resume(64), Err(SourceError::Invariant));
    // A buffer too small for the frame.
    let _ = source.push(b"y").unwrap();
    assert_eq!(source.read(&mut out[..32]), Err(SourceError::Invariant));
    // A queue must start at a frame boundary.
    assert_eq!(
        QueueSource::new(QueueConfig::new(geometry(), 7, 9, 64), 8).unwrap_err(),
        QueueError::Exhausted
    );
}
