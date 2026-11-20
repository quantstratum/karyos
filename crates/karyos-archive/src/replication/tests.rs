// SPDX-License-Identifier: Apache-2.0

//! ADR-0091's vectors P-1 to P-6, byte for byte, and the rules.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use super::*;

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

const P1: &str =
    "06000100010021002d000000070000000000000003000000000000000000000000000000ffffffffffffffff01";
const P2: &str = "06000200010010001c00000008000000000000000300000000000000";
const P3: &str =
    "0600650001001800290000000700000000000000030000000000000000100000000000000300010203";
const P4: &str = "060066000100780084000000070000000000000001000200000000000500000000000000030000000000000000000000000000000010000000000000111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222224bc01d8f00000000";
const P5: &str = "0600670001002900350000000700000000000000030000000000000000000000000000000010000000000000002000000000000001";
const P6: &str =
    "06000100010021002d000000070000000000000003000000000000000a00000000000000090000000000000001";

fn seal() -> SealRecord {
    SealRecord {
        kind: SealKind::ClosedSegment,
        counter: 5,
        subject: 3,
        start: 0,
        end: 4096,
        content: [0x11; 32],
        previous: [0x22; 32],
    }
}

fn encoded(message: &ReplicationMessage<'_>) -> Vec<u8> {
    let mut out = vec![0u8; 16422];
    let length = message.encode(&mut out).unwrap();
    out.truncate(length);
    out
}

#[test]
fn the_vectors_decode_and_encode_exactly() {
    let bytes = [1u8, 2, 3];
    let vectors = [
        (
            P1,
            ReplicationMessage::ReplicateRecording(ReplicateRecording {
                correlation_id: 7,
                recording_id: 3,
                from: 0,
                until: u64::MAX,
                mode: Mode::Continuous,
            }),
        ),
        (
            P2,
            ReplicationMessage::StopReplication(StopReplication {
                correlation_id: 8,
                recording_id: 3,
            }),
        ),
        (
            P3,
            ReplicationMessage::RecordingBytes(RecordingBytes {
                correlation_id: 7,
                recording_id: 3,
                start: 4096,
                bytes: &bytes,
            }),
        ),
        (
            P4,
            ReplicationMessage::SourceSeal(SourceSeal {
                correlation_id: 7,
                seal: seal(),
            }),
        ),
        (
            P5,
            ReplicationMessage::ReplicationStatus(ReplicationStatus {
                correlation_id: 7,
                recording_id: 3,
                source_start: 0,
                sealed_end: 4096,
                written: 8192,
                state: State::Streaming,
            }),
        ),
    ];
    for (vector, message) in vectors {
        let wire = hex(vector);
        assert_eq!(ReplicationMessage::decode(&wire).unwrap(), message);
        assert_eq!(encoded(&message), wire);
    }
    assert_eq!(
        ReplicationMessage::decode(&hex(P6)),
        Err(CodecError::ValueOutOfRange { field: "from" })
    );
}

#[test]
fn refusals_follow_the_rules() {
    // A Cluster log seal, or a seal of another recording, is refused.
    let mut cluster = seal();
    cluster.kind = SealKind::ClusterLog;
    let message = SourceSeal {
        correlation_id: 7,
        seal: cluster,
    };
    assert!(message.encode(&mut [0u8; 132]).is_err());
    assert!(check_seal(&cluster, 3).is_err());
    assert!(check_seal(&seal(), 4).is_err());
    assert!(check_seal(&seal(), 3).is_ok());
    // Positions out of order in a status.
    let mut wire = hex(P5);
    wire[12 + 24] = 0;
    wire[12 + 25] = 0x30; // sealed_end 12288 > written 8192
    assert_eq!(
        ReplicationMessage::decode(&wire),
        Err(CodecError::ValueOutOfRange {
            field: "sealed_end"
        })
    );
    // An end past u64::MAX.
    let bytes = [1u8, 2];
    let overflow = RecordingBytes {
        correlation_id: 0,
        recording_id: 3,
        start: u64::MAX,
        bytes: &bytes,
    };
    assert_eq!(
        overflow.encode(&mut [0u8; 64]),
        Err(CodecError::ValueOutOfRange { field: "start" })
    );
    // A damaged seal CRC.
    let mut wire = hex(P4);
    wire[12 + 8 + 30] ^= 1;
    assert_eq!(
        ReplicationMessage::decode(&wire),
        Err(CodecError::ValueOutOfRange { field: "seal" })
    );
}

#[test]
fn a_request_must_start_and_end_on_seal_boundaries() {
    let seals = [seal()];
    let request = |from, until| ReplicateRecording {
        correlation_id: 1,
        recording_id: 3,
        from,
        until,
        mode: Mode::OnDemand,
    };
    assert_eq!(check_request(&request(0, 4096), 0, &seals), Ok(()));
    assert_eq!(check_request(&request(4096, u64::MAX), 0, &seals), Ok(()));
    assert_eq!(
        check_request(&request(10, u64::MAX), 0, &seals),
        Err(RequestRefusal::FromOffBoundary)
    );
    assert_eq!(
        check_request(&request(0, 100), 0, &seals),
        Err(RequestRefusal::UntilOffBoundary)
    );
    assert_eq!(
        check_request(&request(0, u64::MAX), 4096, &seals),
        Err(RequestRefusal::BelowStart)
    );
}
