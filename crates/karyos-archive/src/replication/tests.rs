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

mod transport {
    //! karyos#1072: a source's sender and a replica's receiver over the
    //! schema 6 messages, encoded and decoded between them.

    use std::path::PathBuf;

    use super::super::transport::{Outgoing, Receiver, Refusal, Sender};
    use super::super::*;
    use crate::control::ResponseCode;
    use crate::disk::StdDisk;
    use crate::integrity::copies::{CopyCatalog, Enforcement};
    use crate::integrity::journal::IntegrityJournal;
    use crate::integrity::replication::{Replica, Verdict};
    use crate::segment::{Geometry, SegmentStore, SyncPolicy};

    const RECORDING: u64 = 3;

    struct Dirs(PathBuf);

    impl Drop for Dirs {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn dirs(name: &str) -> (Dirs, PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!("karyos-repl-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (source, replica) = (root.join("source"), root.join("replica"));
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir_all(&replica).unwrap();
        (Dirs(root), source, replica)
    }

    fn store(dir: &std::path::Path) -> SegmentStore<StdDisk> {
        SegmentStore::create(
            StdDisk,
            dir,
            RECORDING,
            Geometry::new(4096, 1 << 16).unwrap(),
            SyncPolicy::None,
            0,
        )
        .unwrap()
    }

    /// A source of three sealed ranges, the middle one 40 000 bytes (three
    /// chunks), and its seals.
    fn source(dir: &std::path::Path) -> (SegmentStore<StdDisk>, Vec<SealRecord>) {
        let mut store = store(dir);
        let mut journal = IntegrityJournal::open(StdDisk, dir).unwrap().journal;
        let mut position = 0u64;
        for (index, length) in [100usize, 40_000, 7].into_iter().enumerate() {
            let bytes = vec![u8::try_from(index + 1).unwrap(); length];
            store.append(position, &bytes).unwrap();
            journal
                .seal_segment(RECORDING, position, &bytes, false)
                .unwrap();
            position += u64::try_from(length).unwrap();
        }
        store.sync().unwrap();
        (store, journal.records().unwrap())
    }

    fn request(from: u64, until: u64, mode: Mode) -> ReplicateRecording {
        ReplicateRecording {
            correlation_id: 7,
            recording_id: RECORDING,
            from,
            until,
            mode,
        }
    }

    /// Each outgoing message through the codec, as the streams carry it.
    fn wire(outgoing: &Outgoing, buf: &mut [u8]) -> usize {
        let message = match outgoing {
            Outgoing::Bytes { start, bytes } => {
                ReplicationMessage::RecordingBytes(RecordingBytes {
                    correlation_id: 7,
                    recording_id: RECORDING,
                    start: *start,
                    bytes,
                })
            }
            Outgoing::Seal(seal) => ReplicationMessage::SourceSeal(SourceSeal {
                correlation_id: 7,
                seal: *seal,
            }),
            Outgoing::Status(status) => ReplicationMessage::ReplicationStatus(*status),
        };
        message.encode(buf).unwrap()
    }

    /// Applies what arrived; returns the verdicts and the last status.
    fn deliver(
        outgoing: &[Outgoing],
        replica_dir: &std::path::Path,
        tamper: bool,
        counted: (u64, u64),
    ) -> (Vec<Verdict>, Option<ReplicationStatus>, u64) {
        let mut store = store(replica_dir);
        let mut journal = IntegrityJournal::open(StdDisk, replica_dir)
            .unwrap()
            .journal;
        let mut copies = CopyCatalog::open(StdDisk, replica_dir, &mut journal).unwrap();
        let receiver = Receiver::new(
            RECORDING,
            Replica::new([9; 32], 0, Enforcement::Unsupported),
        );
        let mut buf = vec![0u8; 16422];
        let (mut verdicts, mut last) = (Vec::new(), None);
        let mut tampered = !tamper;
        for message in outgoing {
            let length = wire(message, &mut buf);
            match ReplicationMessage::decode(&buf[..length]).unwrap() {
                ReplicationMessage::RecordingBytes(bytes) => {
                    let mut owned = bytes.bytes.to_vec();
                    if !tampered {
                        owned[0] ^= 1;
                        tampered = true;
                    }
                    receiver
                        .bytes(
                            bytes.recording_id,
                            bytes.start,
                            &owned,
                            &mut store,
                            &mut copies,
                            &mut journal,
                        )
                        .unwrap();
                }
                ReplicationMessage::SourceSeal(seal) => verdicts.push(
                    receiver
                        .seal(&seal.seal, &mut store, &mut copies, &mut journal)
                        .unwrap(),
                ),
                ReplicationMessage::ReplicationStatus(status) => last = Some(status),
                _ => panic!("not a source message"),
            }
        }
        let counted = copies
            .verified_copies(RECORDING, counted.0, counted.1)
            .unwrap();
        (verdicts, last, counted)
    }

    #[test]
    fn a_recording_replicates_and_counts_only_after_verifying() {
        let (_dirs, source_dir, replica_dir) = dirs("whole");
        let (mut store, seals) = source(&source_dir);
        let mut sender =
            Sender::accept(request(0, u64::MAX, Mode::OnDemand), true, 0, &seals).unwrap();
        let mut out = Vec::new();
        sender
            .poll(&mut store, &seals, false, usize::MAX, &mut out)
            .unwrap();
        // Bytes before their seal, in chunks of at most 16 KiB.
        let chunks = out
            .iter()
            .filter(|message| matches!(message, Outgoing::Bytes { .. }))
            .count();
        assert_eq!(chunks, 1 + 3 + 1);
        assert!(
            matches!(out.last(), Some(Outgoing::Status(status)) if status.state == State::CaughtUp && status.sealed_end == 40_107)
        );
        assert_eq!(sender.done(), Some(State::CaughtUp));
        let (verdicts, status, counted) = deliver(&out, &replica_dir, false, (100, 40_100));
        assert_eq!(verdicts.len(), 3);
        assert!(
            verdicts
                .iter()
                .all(|verdict| matches!(verdict, Verdict::Counted(_)))
        );
        assert_eq!(status.unwrap().state, State::CaughtUp);
        assert_eq!(counted, 1);
    }

    #[test]
    fn a_corrupted_arrival_never_counts() {
        let (_dirs, source_dir, replica_dir) = dirs("tampered");
        let (mut store, seals) = source(&source_dir);
        let mut sender =
            Sender::accept(request(0, u64::MAX, Mode::OnDemand), true, 0, &seals).unwrap();
        let mut out = Vec::new();
        sender
            .poll(&mut store, &seals, false, usize::MAX, &mut out)
            .unwrap();
        let (verdicts, _, counted) = deliver(&out, &replica_dir, true, (0, 100));
        assert!(matches!(verdicts[0], Verdict::Corrupt(_)));
        assert_eq!(counted, 0);
    }

    #[test]
    fn requests_are_refused_with_their_codes() {
        let (_dirs, source_dir, _) = dirs("refused");
        let (_, seals) = source(&source_dir);
        let unknown = Sender::accept(request(0, u64::MAX, Mode::Continuous), false, 0, &seals);
        assert_eq!(unknown.unwrap_err().code(), ResponseCode::UnknownRecording);
        // Off a boundary, and a continuous `until` no seal reaches yet.
        for (from, until) in [(50, u64::MAX), (0, 50_000)] {
            let refused = Sender::accept(request(from, until, Mode::Continuous), true, 0, &seals);
            assert_eq!(refused.unwrap_err().code(), ResponseCode::InvalidRequest);
        }
        // A request from a seal boundary sends only what follows.
        let mut store = store_with(&source_dir);
        let mut sender =
            Sender::accept(request(100, 40_100, Mode::Continuous), true, 0, &seals).unwrap();
        let mut out = Vec::new();
        sender
            .poll(&mut store, &seals, false, usize::MAX, &mut out)
            .unwrap();
        assert!(matches!(
            out.first(),
            Some(Outgoing::Bytes { start: 100, .. })
        ));
        assert!(
            matches!(out.last(), Some(Outgoing::Status(status)) if status.state == State::CaughtUp)
        );
        let _ = Refusal::UnknownRecording;
    }

    /// The source's store, reopened.
    fn store_with(dir: &std::path::Path) -> SegmentStore<StdDisk> {
        SegmentStore::recover(
            StdDisk,
            dir,
            RECORDING,
            Geometry::new(4096, 1 << 16).unwrap(),
            SyncPolicy::None,
        )
        .unwrap()
        .store
    }

    /// Continuous: what is sealed is sent, then more as it is sealed, and
    /// the end once the recording stopped.
    #[test]
    fn a_continuous_replication_follows_the_seals_to_the_end() {
        let (_dirs, source_dir, _) = dirs("continuous");
        let (mut store, seals) = source(&source_dir);
        let mut sender =
            Sender::accept(request(0, u64::MAX, Mode::Continuous), true, 0, &seals[..1]).unwrap();
        let mut out = Vec::new();
        sender
            .poll(&mut store, &seals[..1], false, usize::MAX, &mut out)
            .unwrap();
        assert_eq!(sender.done(), None, "continuous keeps going");
        out.clear();
        sender
            .poll(&mut store, &seals, true, usize::MAX, &mut out)
            .unwrap();
        assert!(
            matches!(out.last(), Some(Outgoing::Status(status)) if status.state == State::Ended)
        );
    }

    /// A poll sends at most its budget; the rest follows at the next.
    #[test]
    fn a_poll_buffers_no_more_than_its_budget() {
        let (_dirs, source_dir, replica_dir) = dirs("budget");
        let (mut store, seals) = source(&source_dir);
        let mut sender =
            Sender::accept(request(0, u64::MAX, Mode::OnDemand), true, 0, &seals).unwrap();
        let mut all = Vec::new();
        let mut polls = 0;
        while sender.done().is_none() {
            let mut out = Vec::new();
            sender
                .poll(&mut store, &seals, false, MAX_CHUNK, &mut out)
                .unwrap();
            let bytes: usize = out
                .iter()
                .map(|message| match message {
                    Outgoing::Bytes { bytes, .. } => bytes.len(),
                    _ => 0,
                })
                .sum();
            assert!(bytes <= MAX_CHUNK, "{bytes}");
            all.extend(out);
            polls += 1;
            assert!(polls < 100);
        }
        assert!(polls >= 3, "{polls}");
        let (verdicts, status, counted) = deliver(&all, &replica_dir, false, (100, 40_100));
        assert_eq!(verdicts.len(), 3);
        assert!(
            verdicts
                .iter()
                .all(|verdict| matches!(verdict, Verdict::Counted(_)))
        );
        assert_eq!(status.unwrap().state, State::CaughtUp);
        assert_eq!(counted, 1);
    }

    /// ADR-0094: a purge past the next position interrupts the request,
    /// whose status names the store's start above the last range sent;
    /// it decodes, and the same order in another state does not (P-7).
    #[test]
    fn an_interrupted_status_names_the_start_after_a_purge() {
        let interrupted = ReplicationStatus {
            correlation_id: 7,
            recording_id: 3,
            source_start: 8192,
            sealed_end: 4096,
            written: 12_288,
            state: State::Interrupted,
        };
        let mut buf = [0u8; 64];
        let length = interrupted.encode(&mut buf).unwrap();
        // P-7, as design/archive-replication.md section 5 publishes it.
        assert_eq!(
            buf[..length].to_vec(),
            super::hex(
                "0600670001002900350000000700000000000000030000000000000000200000000000000010000000000000003000000000000005"
            )
        );
        let mut state_one = super::hex(
            "0600670001002900350000000700000000000000030000000000000000200000000000000010000000000000003000000000000001",
        );
        assert_eq!(
            ReplicationMessage::decode(&state_one),
            Err(CodecError::ValueOutOfRange {
                field: "sealed_end"
            })
        );
        // An unknown state is refused before the order.
        let last = state_one.len() - 1;
        state_one[last] = 9;
        assert!(matches!(
            ReplicationMessage::decode(&state_one),
            Err(CodecError::InvalidEnum { field: "state", .. })
        ));
        assert_eq!(
            ReplicationMessage::decode(&buf[..length]).unwrap(),
            ReplicationMessage::ReplicationStatus(interrupted)
        );
        let streaming = ReplicationStatus {
            state: State::Streaming,
            ..interrupted
        };
        assert_eq!(
            streaming.encode(&mut buf),
            Err(CodecError::ValueOutOfRange {
                field: "sealed_end"
            })
        );
    }
}
