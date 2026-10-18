// SPDX-License-Identifier: Apache-2.0

// The Archive's control messages: the design note's vectors, a sample of
// every template and variant round trip, truncation at every boundary,
// unsupported tuples, and every invalid field value as a mutated vector.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use proptest::prelude::*;

use super::*;
use crate::catalog::FailKind;

fn hex(text: &str) -> Vec<u8> {
    text.split_whitespace()
        .map(|byte| u8::from_str_radix(byte, 16).unwrap())
        .collect()
}

fn encoded(message: &ControlMessage<'_>) -> Vec<u8> {
    let mut out = vec![0u8; 2048];
    let length = message.encode(&mut out).unwrap();
    out.truncate(length);
    out
}

fn geometry() -> Geometry {
    Geometry::new(64 * 1024, 4 * 64 * 1024).unwrap()
}

fn source() -> SourceIncarnation {
    SourceIncarnation {
        driver: [0x0102_0304_0506_0708, 0x1112_1314_1516_1718],
        registration: 21,
        incarnation: 2,
    }
}

/// One message of every template, every enum variant among them.
fn samples() -> Vec<ControlMessage<'static>> {
    vec![
        ControlMessage::StartRecording(StartRecording {
            correlation_id: 1,
            stream_id: 10,
            session_id: 3,
            mode: Mode::Required,
            sync_policy: SyncPolicy::PerSegment,
            segment_length: 0,
            channel: "ipc",
        }),
        ControlMessage::StartRecording(StartRecording {
            correlation_id: u64::MAX,
            stream_id: -1,
            session_id: i32::MIN,
            mode: Mode::Async {
                on_lap: OnLap::Stop,
            },
            sync_policy: SyncPolicy::None,
            segment_length: 1 << 27,
            channel: "aeron:udp?endpoint=host:4000",
        }),
        ControlMessage::StartRecording(StartRecording {
            correlation_id: 2,
            stream_id: 1,
            session_id: 1,
            mode: Mode::Async {
                on_lap: OnLap::Resume,
            },
            sync_policy: SyncPolicy::Every {
                interval_ns: 1_000_000,
            },
            segment_length: 0,
            channel: "é",
        }),
        ControlMessage::StopRecording(StopRecording {
            correlation_id: 3,
            recording_id: 42,
        }),
        ControlMessage::ListRecordings(ListRecordings {
            correlation_id: 4,
            from_id: 0,
            max_count: MAX_LIST_COUNT,
        }),
        ControlMessage::Replay(Replay {
            correlation_id: 5,
            recording_id: 7,
            position: 4096,
            length: u64::MAX,
            rate: ReplayRate::Full,
            target_stream_id: 20,
            target_channel: "ipc",
        }),
        ControlMessage::Replay(Replay {
            correlation_id: 6,
            recording_id: 7,
            position: 0,
            length: 100,
            rate: ReplayRate::AsRecorded,
            target_stream_id: 21,
            target_channel: "ipc",
        }),
        ControlMessage::Replay(Replay {
            correlation_id: 7,
            recording_id: 7,
            position: 0,
            length: 100,
            rate: ReplayRate::Scaled { ppm: MAX_SCALE_PPM },
            target_stream_id: 22,
            target_channel: "ipc",
        }),
        ControlMessage::StopReplay(StopReplay {
            correlation_id: 8,
            replay_id: 9,
        }),
        ControlMessage::ControlResponse(ControlResponse {
            correlation_id: 9,
            id: 42,
            code: ResponseCode::Ok,
            message: "",
        }),
        ControlMessage::ControlResponse(ControlResponse {
            correlation_id: 10,
            id: 0,
            code: ResponseCode::UnsupportedSchema,
            message: "schema 2",
        }),
        ControlMessage::RecordingDescriptor(RecordingDescriptor {
            correlation_id: 11,
            recording_id: 1,
            start: 0,
            start_time_ns: 5,
            state: RecordingState::Recording {
                written: 4096,
                incomplete: false,
            },
            geometry: geometry(),
            source: source(),
            stream_id: 10,
            session_id: 3,
            channel: "ipc",
        }),
        ControlMessage::RecordingDescriptor(RecordingDescriptor {
            correlation_id: 12,
            recording_id: 2,
            start: 64,
            start_time_ns: 5,
            state: RecordingState::Stopped(Stop {
                position: 9000,
                time_ns: 6,
                reason: StopReason::Failed(FailKind::Invalid),
                incomplete: true,
            }),
            geometry: geometry(),
            source: source(),
            stream_id: 10,
            session_id: 3,
            channel: "ipc",
        }),
        ControlMessage::RecordingSignal(RecordingSignal {
            correlation_id: 1,
            recording_id: 1,
            position: 0,
            signal: Signal::Started,
        }),
        ControlMessage::RecordingSignal(RecordingSignal {
            correlation_id: 0,
            recording_id: 1,
            position: 9000,
            signal: Signal::Stopped {
                reason: StopReason::Lapped,
                incomplete: true,
            },
        }),
        ControlMessage::RecordingSignal(RecordingSignal {
            correlation_id: 0,
            recording_id: 1,
            position: 64,
            signal: Signal::Failed,
        }),
        // An async recording that lapped and resumed, still recording.
        ControlMessage::RecordingDescriptor(RecordingDescriptor {
            correlation_id: 13,
            recording_id: 3,
            start: 0,
            start_time_ns: 5,
            state: RecordingState::Recording {
                written: 0,
                incomplete: true,
            },
            geometry: geometry(),
            source: SourceIncarnation {
                driver: [u64::MAX, 0],
                registration: u64::MAX,
                incarnation: 0,
            },
            stream_id: 10,
            session_id: 3,
            channel: "ipc",
        }),
    ]
}

/// The design note's two vectors, and one for `StartRecording`.
#[test]
fn the_vectors_decode_and_encode_exactly() {
    let stop = hex("01 00 02 00 01 00 10 00 1c 00 00 00
         08 07 06 05 04 03 02 01
         2a 00 00 00 00 00 00 00");
    let message = ControlMessage::StopRecording(StopRecording {
        correlation_id: 0x0102_0304_0506_0708,
        recording_id: 42,
    });
    assert_eq!(ControlMessage::decode(&stop).unwrap(), message);
    assert_eq!(encoded(&message), stop);

    let response = hex("01 00 65 00 01 00 11 00 30 00 00 00
         07 00 00 00 00 00 00 00
         00 00 00 00 00 00 00 00
         02
         11 00
         6e 6f 20 73 75 63 68 20 72 65 63 6f 72 64 69 6e 67");
    let message = ControlMessage::ControlResponse(ControlResponse {
        correlation_id: 7,
        id: 0,
        code: ResponseCode::UnknownRecording,
        message: "no such recording",
    });
    assert_eq!(ControlMessage::decode(&response).unwrap(), message);
    assert_eq!(encoded(&message), response);

    let start = hex("01 00 01 00 01 00 23 00 34 00 00 00
         01 00 00 00 00 00 00 00
         00 00 00 00 00 00 00 00
         00 00 00 00 00 00 00 00
         0a 00 00 00
         03 00 00 00
         01 00 01
         03 00 69 70 63");
    assert_eq!(ControlMessage::decode(&start).unwrap(), samples()[0]);
    assert_eq!(encoded(&samples()[0]), start);
}

/// One hand-written vector for each remaining template, against the
/// sample it encodes.
#[test]
fn every_template_has_a_vector() {
    let vectors = [
        (
            4,
            "01 00 03 00 01 00 14 00 20 00 00 00
             04 00 00 00 00 00 00 00
             00 00 00 00 00 00 00 00
             e8 03 00 00",
        ),
        (
            5,
            "01 00 04 00 01 00 29 00 3a 00 00 00
             05 00 00 00 00 00 00 00
             07 00 00 00 00 00 00 00
             00 10 00 00 00 00 00 00
             ff ff ff ff ff ff ff ff
             00 00 00 00
             14 00 00 00
             01
             03 00 69 70 63",
        ),
        (
            8,
            "01 00 05 00 01 00 10 00 1c 00 00 00
             08 00 00 00 00 00 00 00
             09 00 00 00 00 00 00 00",
        ),
        (
            11,
            "01 00 66 00 01 00 6e 00 7f 00 00 00
             0b 00 00 00 00 00 00 00
             01 00 00 00 00 00 00 00
             00 00 00 00 00 00 00 00
             ff ff ff ff ff ff ff ff
             00 10 00 00 00 00 00 00
             05 00 00 00 00 00 00 00
             00 00 00 00 00 00 00 00
             00 00 04 00 00 00 00 00
             08 07 06 05 04 03 02 01
             18 17 16 15 14 13 12 11
             15 00 00 00 00 00 00 00
             02 00 00 00 00 00 00 00
             00 00 01 00
             0a 00 00 00
             03 00 00 00
             00 00
             03 00 69 70 63",
        ),
        (
            14,
            "01 00 67 00 01 00 1b 00 27 00 00 00
             00 00 00 00 00 00 00 00
             01 00 00 00 00 00 00 00
             28 23 00 00 00 00 00 00
             02 04 01",
        ),
    ];
    let samples = samples();
    for (index, text) in vectors {
        let bytes = hex(text);
        assert_eq!(
            ControlMessage::decode(&bytes).unwrap(),
            samples[index],
            "{index}"
        );
        assert_eq!(encoded(&samples[index]), bytes, "{index}");
    }
}

#[test]
fn every_sample_round_trips() {
    for sample in samples() {
        let bytes = encoded(&sample);
        assert_eq!(ControlMessage::decode(&bytes).unwrap(), sample);
    }
}

#[test]
fn every_truncation_is_refused() {
    for sample in samples() {
        let bytes = encoded(&sample);
        for cut in 0..bytes.len() {
            assert!(
                ControlMessage::decode(&bytes[..cut]).is_err(),
                "{sample:?} cut at {cut}"
            );
            let mut short = vec![0u8; cut];
            assert!(
                matches!(sample.encode(&mut short), Err(CodecError::Truncated { .. })),
                "{sample:?} capacity {cut}"
            );
        }
    }
}

#[test]
fn only_the_supported_tuples_decode() {
    let bytes = encoded(&samples()[3]);
    // Another schema, version or template (one unlisted below 100 and one
    // above), and another block length.
    for (at, value) in [(0, 2u8), (4, 2), (2, 6), (2, 104), (6, 17)] {
        let mut bad = bytes.clone();
        bad[at] = value;
        assert!(
            matches!(
                ControlMessage::decode(&bad),
                Err(CodecError::UnsupportedSchema { .. })
            ),
            "byte {at} = {value}"
        );
    }
}

/// Decodes `bytes` with `byte` at `at` (an offset in the block) replaced.
fn with_byte(bytes: &[u8], at: usize, byte: u8) -> Result<ControlMessage<'_>, CodecError> {
    // Leaks the mutated copy so the decoded value can borrow it.
    let mut copy = bytes.to_vec();
    copy[12 + at] = byte;
    let copy: &'static [u8] = Vec::leak(copy);
    ControlMessage::decode(copy)
}

fn field_error(result: Result<ControlMessage<'_>, CodecError>) -> &'static str {
    match result {
        Err(
            CodecError::InvalidEnum { field, .. }
            | CodecError::InvalidBool { field, .. }
            | CodecError::ValueOutOfRange { field }
            | CodecError::InvalidUtf8 { field }
            | CodecError::LengthOutOfRange { field, .. },
        ) => field,
        other => panic!("{other:?}"),
    }
}

#[test]
fn every_invalid_field_is_refused_by_name() {
    let samples = samples();
    let start = encoded(&samples[0]);
    let every = encoded(&samples[2]);
    let replay_full = encoded(&samples[5]);
    let replay_scaled = encoded(&samples[7]);
    let ok = encoded(&samples[9]);
    let error = encoded(&samples[10]);
    let recording = encoded(&samples[11]);
    let stopped = encoded(&samples[12]);
    let started = encoded(&samples[13]);
    let lapped = encoded(&samples[14]);
    let failed = encoded(&samples[15]);
    let stop = encoded(&samples[3]);
    let stop_replay = encoded(&samples[8]);
    let cases: Vec<(&[u8], usize, u8, &str)> = vec![
        (&start, 32, 3, "mode"),
        (&start, 33, 1, "on_lap"),
        (&every, 33, 0, "on_lap"),
        (&stop, 8, 0, "recording_id"),
        (&stop_replay, 8, 0, "replay_id"),
        (&start, 34, 3, "sync_policy"),
        (&start, 8, 1, "sync_interval_ns"),
        (&replay_full, 40, 4, "rate"),
        (&replay_full, 32, 1, "scale_ppm"),
        (&replay_full, 8, 0, "recording_id"),
        (&replay_scaled, 35, 0xFF, "scale_ppm"),
        (&ok, 16, 6, "code"),
        (&error, 8, 1, "id"),
        (&recording, 108, 10, "stop_reason"),
        (&recording, 24, 0, "stop"),
        (&recording, 48, 1, "stop"),
        (&recording, 109, 2, "incomplete"),
        (&recording, 8, 0, "recording_id"),
        (&recording, 96, 3, "segment_length"),
        (&recording, 98, 0, "term_length"),
        (&recording, 56, 1, "segment_length"),
        // Written below the start, and a stop other than the written.
        (&recording, 17, 0xFF, "written"),
        (&stopped, 32, 1, "written"),
        (&stopped, 108, 0, "stop"),
        (&started, 24, 4, "signal"),
        (&started, 25, 4, "stop_reason"),
        (&started, 26, 1, "incomplete"),
        (&failed, 25, 4, "stop_reason"),
        (&failed, 26, 1, "incomplete"),
        (&started, 8, 0, "recording_id"),
        (&lapped, 0, 1, "correlation_id"),
        (&failed, 0, 1, "correlation_id"),
    ];
    for (bytes, at, byte, field) in cases {
        assert_eq!(
            field_error(with_byte(bytes, at, byte)),
            field,
            "{field} at {at}"
        );
    }
    // An on_lap value never listed is an invalid enum, not a mismatch.
    assert!(matches!(
        with_byte(&start, 33, 3),
        Err(CodecError::InvalidEnum {
            field: "on_lap",
            value: 3
        })
    ));
    // An interval of 0 under the interval policy.
    let mut no_interval = every.clone();
    no_interval[12 + 8..12 + 16].copy_from_slice(&0u64.to_le_bytes());
    assert_eq!(
        field_error(ControlMessage::decode(&no_interval)),
        "sync_interval_ns"
    );
    // A scaled replay at 0 ppm.
    let mut zero = replay_scaled.clone();
    zero[12 + 32..12 + 36].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(field_error(ControlMessage::decode(&zero)), "scale_ppm");
    let mut over = replay_scaled.clone();
    over[12 + 32..12 + 36].copy_from_slice(&(MAX_SCALE_PPM + 1).to_le_bytes());
    assert_eq!(field_error(ControlMessage::decode(&over)), "scale_ppm");
    // A list count of 0 or above the maximum.
    let list = encoded(&samples[4]);
    for count in [0, MAX_LIST_COUNT + 1] {
        let mut bad = list.clone();
        bad[12 + 16..12 + 20].copy_from_slice(&count.to_le_bytes());
        assert_eq!(field_error(ControlMessage::decode(&bad)), "max_count");
    }
    // A success with a message, and invalid UTF-8 in a channel.
    let mut chatty = ok.clone();
    chatty[12 + 17] = 1;
    chatty.push(b'x');
    let length = u32::try_from(chatty.len()).unwrap();
    chatty[8..12].copy_from_slice(&length.to_le_bytes());
    assert_eq!(field_error(ControlMessage::decode(&chatty)), "message");
    let mut garbled = start.clone();
    let last = garbled.len() - 1;
    garbled[last] = 0xFF;
    assert_eq!(field_error(ControlMessage::decode(&garbled)), "channel");
}

#[test]
fn encoding_refuses_what_decoding_would() {
    let mut out = [0u8; 2048];
    let long = "x".repeat(MAX_CHANNEL + 1);
    let replay = |rate, recording_id| {
        ControlMessage::Replay(Replay {
            correlation_id: 1,
            recording_id,
            position: 0,
            length: 100,
            rate,
            target_stream_id: 1,
            target_channel: "ipc",
        })
    };
    let signal = |correlation_id, recording_id, signal| {
        ControlMessage::RecordingSignal(RecordingSignal {
            correlation_id,
            recording_id,
            position: 0,
            signal,
        })
    };
    let stopped = Signal::Stopped {
        reason: StopReason::Normal,
        incomplete: false,
    };
    let cases: Vec<(ControlMessage<'_>, &str)> = vec![
        (
            ControlMessage::StartRecording(StartRecording {
                channel: "",
                ..start_sample()
            }),
            "channel",
        ),
        (
            ControlMessage::StartRecording(StartRecording {
                channel: &long,
                ..start_sample()
            }),
            "channel",
        ),
        (
            ControlMessage::StartRecording(StartRecording {
                sync_policy: SyncPolicy::Every { interval_ns: 0 },
                ..start_sample()
            }),
            "sync_interval_ns",
        ),
        (
            ControlMessage::StopRecording(StopRecording {
                correlation_id: 1,
                recording_id: 0,
            }),
            "recording_id",
        ),
        (
            ControlMessage::StopReplay(StopReplay {
                correlation_id: 1,
                replay_id: 0,
            }),
            "replay_id",
        ),
        (
            ControlMessage::ListRecordings(ListRecordings {
                correlation_id: 1,
                from_id: 1,
                max_count: 0,
            }),
            "max_count",
        ),
        (
            ControlMessage::ControlResponse(ControlResponse {
                correlation_id: 1,
                id: 1,
                code: ResponseCode::Error,
                message: "",
            }),
            "id",
        ),
        (
            ControlMessage::ControlResponse(ControlResponse {
                correlation_id: 1,
                id: 1,
                code: ResponseCode::Ok,
                message: "x",
            }),
            "message",
        ),
        (replay(ReplayRate::Scaled { ppm: 0 }, 1), "scale_ppm"),
        (
            replay(
                ReplayRate::Scaled {
                    ppm: MAX_SCALE_PPM + 1,
                },
                1,
            ),
            "scale_ppm",
        ),
        (replay(ReplayRate::Full, 0), "recording_id"),
        (
            ControlMessage::RecordingDescriptor(RecordingDescriptor {
                recording_id: 0,
                ..descriptor_sample()
            }),
            "recording_id",
        ),
        // Written to 4096, from a start after it.
        (
            ControlMessage::RecordingDescriptor(RecordingDescriptor {
                start: 8192,
                ..descriptor_sample()
            }),
            "written",
        ),
        (signal(0, 0, Signal::Started), "recording_id"),
        (signal(1, 1, stopped), "correlation_id"),
        (signal(1, 1, Signal::Failed), "correlation_id"),
    ];
    // Each into a buffer that holds a valid message: the failed encoding
    // leaves no message behind.
    let earlier = samples()[5];
    for (message, field) in cases {
        let length = earlier.encode(&mut out).unwrap();
        assert!(ControlMessage::decode(&out[..length]).is_ok());
        assert_eq!(
            field_error(message.encode(&mut out).map(|_| message)),
            field
        );
        assert_eq!(&out[8..12], &[0, 0, 0, 0], "{field}: no length written");
        assert!(ControlMessage::decode(&out[..length]).is_err(), "{field}");
    }
}

/// A buffer too short for a message, holding an earlier one, no longer
/// holds it after the refused encoding.
#[test]
fn a_truncated_encoding_leaves_no_message_behind() {
    let earlier = samples()[3];
    let mut out = encoded(&earlier);
    for message in samples() {
        let length = earlier.encode(&mut out).unwrap();
        assert_eq!(length, out.len());
        if encoded(&message).len() <= out.len() {
            continue;
        }
        assert!(matches!(
            message.encode(&mut out),
            Err(CodecError::Truncated { .. })
        ));
        assert_eq!(&out[8..12], &[0, 0, 0, 0], "{message:?}");
        assert!(ControlMessage::decode(&out).is_err(), "{message:?}");
    }
}

/// Every variable field at its maximum gives the template's maximum
/// length, and one byte more is refused.
#[test]
fn the_maximum_sizes_hold() {
    let channel = "x".repeat(MAX_CHANNEL);
    let message = "m".repeat(MAX_RESPONSE_MESSAGE);
    let longest = [
        (
            ControlMessage::StartRecording(StartRecording {
                channel: &channel,
                ..start_sample()
            }),
            START_RECORDING,
        ),
        (
            ControlMessage::Replay(Replay {
                correlation_id: 1,
                recording_id: 1,
                position: 0,
                length: 1,
                rate: ReplayRate::Full,
                target_stream_id: 1,
                target_channel: &channel,
            }),
            REPLAY,
        ),
        (
            ControlMessage::ControlResponse(ControlResponse {
                correlation_id: 1,
                id: 0,
                code: ResponseCode::Error,
                message: &message,
            }),
            CONTROL_RESPONSE,
        ),
        (
            ControlMessage::RecordingDescriptor(RecordingDescriptor {
                channel: &channel,
                ..descriptor_sample()
            }),
            RECORDING_DESCRIPTOR,
        ),
    ];
    for (message, template) in longest {
        let bytes = encoded(&message);
        assert_eq!(bytes.len(), usize::try_from(template.max_length).unwrap());
        assert_eq!(ControlMessage::decode(&bytes).unwrap(), message);
    }
    for (index, template) in [
        (3, STOP_RECORDING),
        (4, LIST_RECORDINGS),
        (8, STOP_REPLAY),
        (13, RECORDING_SIGNAL),
    ] {
        let bytes = encoded(&samples()[index]);
        assert_eq!(bytes.len(), usize::try_from(template.max_length).unwrap());
    }
    let long_message = "m".repeat(MAX_RESPONSE_MESSAGE + 1);
    let response = ControlMessage::ControlResponse(ControlResponse {
        correlation_id: 1,
        id: 0,
        code: ResponseCode::Error,
        message: &long_message,
    });
    let mut out = vec![0u8; 2048];
    assert_eq!(
        field_error(response.encode(&mut out).map(|_| response)),
        "message"
    );
}

fn descriptor_sample() -> RecordingDescriptor<'static> {
    match samples()[11] {
        ControlMessage::RecordingDescriptor(descriptor) => descriptor,
        _ => unreachable!(),
    }
}

fn start_sample() -> StartRecording<'static> {
    match samples()[0] {
        ControlMessage::StartRecording(start) => start,
        _ => unreachable!(),
    }
}

proptest! {
    #[test]
    fn start_recording_round_trips(
        correlation_id: u64,
        stream_id: i32,
        session_id: i32,
        segment_length: u64,
        interval in 1u64..,
        policy in 0u8..3,
        mode in 0u8..3,
        channel in "[a-z:/?=0-9]{1,64}",
    ) {
        let message = StartRecording {
            correlation_id,
            stream_id,
            session_id,
            mode: match mode {
                0 => Mode::Required,
                1 => Mode::Async { on_lap: OnLap::Stop },
                _ => Mode::Async { on_lap: OnLap::Resume },
            },
            sync_policy: match policy {
                0 => SyncPolicy::None,
                1 => SyncPolicy::PerSegment,
                _ => SyncPolicy::Every { interval_ns: interval },
            },
            segment_length,
            channel: &channel,
        };
        let mut out = [0u8; 2048];
        let length = message.encode(&mut out).unwrap();
        prop_assert_eq!(
            ControlMessage::decode(&out[..length]).unwrap(),
            ControlMessage::StartRecording(message)
        );
    }

    #[test]
    fn replay_round_trips(
        correlation_id: u64,
        recording_id in 1u64..,
        position: u64,
        length: u64,
        ppm in 1..=MAX_SCALE_PPM,
        rate in 0u8..3,
        target_stream_id: i32,
    ) {
        let message = Replay {
            correlation_id,
            recording_id,
            position,
            length,
            rate: match rate {
                0 => ReplayRate::Full,
                1 => ReplayRate::AsRecorded,
                _ => ReplayRate::Scaled { ppm },
            },
            target_stream_id,
            target_channel: "ipc",
        };
        let mut out = [0u8; 2048];
        let encoded = message.encode(&mut out).unwrap();
        prop_assert_eq!(
            ControlMessage::decode(&out[..encoded]).unwrap(),
            ControlMessage::Replay(message)
        );
    }

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        let _ = ControlMessage::decode(&bytes);
    }
}
