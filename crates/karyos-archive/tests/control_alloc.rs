// SPDX-License-Identifier: Apache-2.0

//! Decoding and encoding the Archive's control messages allocate and free
//! nothing, on success and on every error path (ADR-0036, validation), over
//! a counting global allocator.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use karyos_archive::catalog::StopReason;
use karyos_archive::control::{
    ControlMessage, ControlResponse, RecordingSignal, Replay, ReplayRate, ResponseCode, Signal,
    StartRecording,
};
use karyos_archive::recorder::{Mode, OnLap};
use karyos_archive::segment::SyncPolicy;
use karyos_sys::alloc_count::{CountingAllocator, count};

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn messages() -> [ControlMessage<'static>; 3] {
    [
        ControlMessage::StartRecording(StartRecording {
            correlation_id: 1,
            stream_id: 10,
            session_id: 3,
            mode: Mode::Async {
                on_lap: OnLap::Resume,
            },
            sync_policy: SyncPolicy::Every { interval_ns: 1000 },
            segment_length: 0,
            channel: "aeron:udp?endpoint=host:4000",
        }),
        ControlMessage::Replay(Replay {
            correlation_id: 2,
            recording_id: 7,
            position: 0,
            length: u64::MAX,
            rate: ReplayRate::Scaled { ppm: 2_000_000 },
            target_stream_id: 20,
            target_channel: "ipc",
        }),
        ControlMessage::ControlResponse(ControlResponse {
            correlation_id: 3,
            id: 0,
            code: ResponseCode::InvalidRequest,
            message: "bad range",
        }),
    ]
}

#[test]
fn encoding_and_decoding_allocate_nothing() {
    let mut out = [0u8; 2048];
    for message in messages() {
        let (length, allocations) = count(|| message.encode(&mut out).unwrap());
        assert_eq!(allocations, 0, "encode {message:?}");
        let (decoded, allocations) = count(|| ControlMessage::decode(&out[..length]).unwrap());
        assert_eq!(allocations, 0, "decode {message:?}");
        assert_eq!(decoded, message);
        // Every truncation fails, without allocating.
        for cut in 0..length {
            let (result, allocations) = count(|| ControlMessage::decode(&out[..cut]).is_err());
            assert!(result);
            assert_eq!(allocations, 0, "truncated at {cut}");
        }
    }
}

#[test]
fn errors_allocate_nothing() {
    let mut out = [0u8; 2048];
    let signal = ControlMessage::RecordingSignal(RecordingSignal {
        correlation_id: 0,
        recording_id: 1,
        position: 9,
        signal: Signal::Stopped {
            reason: StopReason::Normal,
            incomplete: false,
        },
    });
    let length = signal.encode(&mut out).unwrap();
    // An invalid signal, an unknown template and a short capacity.
    out[12 + 24] = 9;
    let (result, allocations) = count(|| ControlMessage::decode(&out[..length]).is_err());
    assert!(result);
    assert_eq!(allocations, 0);
    out[2] = 99;
    let (result, allocations) = count(|| ControlMessage::decode(&out[..length]).is_err());
    assert!(result);
    assert_eq!(allocations, 0);
    let mut short = [0u8; 8];
    let (result, allocations) = count(|| signal.encode(&mut short).is_err());
    assert!(result);
    assert_eq!(allocations, 0);
}

/// Schema 4, the durability query (R-CORE-12): the same, on success and
/// on an error path.
#[test]
fn durability_messages_allocate_nothing() {
    use karyos_archive::durable::{DurabilityMessage, QueryDurable};
    let mut out = [0u8; 64];
    let query = DurabilityMessage::QueryDurable(QueryDurable {
        correlation_id: 1,
        recording_id: 7,
    });
    let (length, allocations) = count(|| query.encode(&mut out).unwrap());
    assert_eq!(allocations, 0, "encode");
    let (decoded, allocations) = count(|| DurabilityMessage::decode(&out[..length]).unwrap());
    assert_eq!(allocations, 0, "decode");
    assert_eq!(decoded, query);
    for cut in 0..length {
        let (result, allocations) = count(|| DurabilityMessage::decode(&out[..cut]).is_err());
        assert!(result);
        assert_eq!(allocations, 0, "truncated at {cut}");
    }
}
