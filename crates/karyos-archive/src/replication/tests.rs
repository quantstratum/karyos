// SPDX-License-Identifier: Apache-2.0

//! ADR-0091's vectors P-1 to P-6 and ADR-0120's P-8, byte for byte, and
//! the rules.

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

/// ADR-0120's P-8: P-4's inputs with `kind` 3 (`ClusterLog`) and
/// `subject` 2, the Cluster log's seal epoch.
const P8_BYTES: &str = "060066000100780084000000070000000000000001000300000000000500000000000000020000000000000000000000000000000010000000000000111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222220620ed5900000000";

/// The Cluster log recording of the Cluster log scope's tests
/// (karyos-cluster's `LOG_RECORDING`), and the seal epoch of P-8.
const LOG: u64 = 1;
const EPOCH: u64 = 2;

fn log_seal() -> SealRecord {
    SealRecord {
        kind: SealKind::ClusterLog,
        subject: EPOCH,
        ..seal()
    }
}

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
fn p8_a_cluster_log_seal_decodes_and_encodes_exactly() {
    let message = ReplicationMessage::SourceSeal(SourceSeal {
        correlation_id: 7,
        seal: log_seal(),
    });
    let wire = hex(P8_BYTES);
    assert_eq!(wire.len(), 132);
    assert_eq!(encoded(&message), wire);
    assert_eq!(ReplicationMessage::decode(&wire).unwrap(), message);
    // Only the kind, the subject and the CRC differ from P-4.
    let p4 = hex(P4);
    let differ: Vec<usize> = (0..132).filter(|&at| p4[at] != wire[at]).collect();
    assert_eq!(differ, [22, 36, 124, 125, 126, 127]);
}

#[test]
fn a_source_seal_carries_only_range_kinds_of_a_replication() {
    for kind in [
        SealKind::OpenSegment,
        SealKind::ClosedSegment,
        SealKind::ClusterLog,
    ] {
        let message = ReplicationMessage::SourceSeal(SourceSeal {
            correlation_id: 7,
            seal: SealRecord { kind, ..seal() },
        });
        assert_eq!(
            ReplicationMessage::decode(&encoded(&message)).unwrap(),
            message
        );
    }
    let catalog = SourceSeal {
        correlation_id: 7,
        seal: SealRecord {
            kind: SealKind::Catalog,
            ..seal()
        },
    };
    assert_eq!(
        catalog.encode(&mut [0u8; 132]),
        Err(CodecError::ValueOutOfRange { field: "seal" })
    );
    // A catalog record on the wire, its CRC right: refused on decode.
    let mut wire = hex(P4);
    let record = catalog.seal.encode();
    wire[20..132].copy_from_slice(&record);
    assert_eq!(
        ReplicationMessage::decode(&wire),
        Err(CodecError::ValueOutOfRange { field: "seal" })
    );
}

#[test]
fn a_cluster_log_scope_counts_only_its_epochs_log_seals() {
    let scope = SealScope::cluster_log(LOG, EPOCH);
    assert_eq!(scope.recording_id(), LOG);
    assert!(check_seal_in(&log_seal(), scope).is_ok());
    // Another epoch, or a segment seal of any subject, is refused.
    let other_epoch = SealRecord {
        subject: EPOCH + 1,
        ..log_seal()
    };
    assert!(check_seal_in(&other_epoch, scope).is_err());
    for kind in [SealKind::OpenSegment, SealKind::ClosedSegment] {
        for subject in [LOG, EPOCH] {
            let segment = SealRecord {
                kind,
                subject,
                ..seal()
            };
            assert!(check_seal_in(&segment, scope).is_err());
        }
    }
    // A log seal is never one of an ordinary recording, whatever its
    // subject.
    assert!(check_seal(&log_seal(), EPOCH).is_err());
    assert!(check_seal_in(&log_seal(), SealScope::segments(EPOCH)).is_err());
    assert!(check_seal_in(&seal(), SealScope::segments(3)).is_ok());
}

#[test]
fn a_cluster_log_request_starts_and_ends_on_its_epochs_seals() {
    let scope = SealScope::cluster_log(LOG, EPOCH);
    let request = |recording_id, from, until| ReplicateRecording {
        correlation_id: 1,
        recording_id,
        from,
        until,
        mode: Mode::OnDemand,
    };
    let older = SealRecord {
        subject: EPOCH - 1,
        end: 8192,
        ..log_seal()
    };
    let segment = SealRecord {
        subject: LOG,
        end: 12288,
        ..seal()
    };
    let seals = [log_seal(), older, segment];
    let check = |request: &ReplicateRecording| check_request_in(request, scope, 0, &seals);
    assert_eq!(check(&request(LOG, 0, 4096)), Ok(()));
    assert_eq!(check(&request(LOG, 4096, u64::MAX)), Ok(()));
    // Another epoch's boundary, or a segment seal's, is no boundary here.
    assert_eq!(
        check(&request(LOG, 8192, u64::MAX)),
        Err(RequestRefusal::FromOffBoundary)
    );
    assert_eq!(
        check(&request(LOG, 0, 12288)),
        Err(RequestRefusal::UntilOffBoundary)
    );
    assert_eq!(
        check(&request(LOG + 5, 0, 4096)),
        Err(RequestRefusal::OutOfScope)
    );
    // An ordinary recording's request never takes a log seal as a boundary.
    assert_eq!(
        check_request(&request(EPOCH, 4096, u64::MAX), 0, &seals),
        Err(RequestRefusal::FromOffBoundary)
    );
    assert_eq!(
        check_request(&request(LOG, 12288, u64::MAX), 0, &seals),
        Ok(())
    );
}

#[test]
fn refusals_follow_the_rules() {
    // A Cluster log seal, or a seal of another recording, is refused for
    // an ordinary recording.
    let mut cluster = seal();
    cluster.kind = SealKind::ClusterLog;
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

    use super::super::transport::{Arrival, Outgoing, ReceiveError, Receiver, Refusal, Sender};
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
                    let _ = receiver
                        .bytes(bytes.recording_id, bytes.start, &owned, &mut store)
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
    fn a_replayed_recording_changes_nothing_and_differing_bytes_never_overwrite() {
        let (_dirs, source_dir, replica_dir) = dirs("replayed");
        let (mut source_store, seals) = source(&source_dir);
        let mut sender =
            Sender::accept(request(0, u64::MAX, Mode::OnDemand), true, 0, &seals).unwrap();
        let mut out = Vec::new();
        sender
            .poll(&mut source_store, &seals, false, usize::MAX, &mut out)
            .unwrap();
        let mut store = store(&replica_dir);
        let mut journal = IntegrityJournal::open(StdDisk, &replica_dir)
            .unwrap()
            .journal;
        let mut copies = CopyCatalog::open(StdDisk, &replica_dir, &mut journal).unwrap();
        let receiver = Receiver::new(
            RECORDING,
            Replica::new([9; 32], 0, Enforcement::Unsupported),
        );
        let apply = |store: &mut SegmentStore<StdDisk>,
                     copies: &mut CopyCatalog<StdDisk>,
                     journal: &mut IntegrityJournal<StdDisk>| {
            let mut arrivals = Vec::new();
            let mut verdicts = Vec::new();
            for message in &out {
                match message {
                    Outgoing::Bytes { start, bytes } => {
                        arrivals.push(receiver.bytes(RECORDING, *start, bytes, store).unwrap())
                    }
                    Outgoing::Seal(seal) => {
                        verdicts.push(receiver.seal(seal, store, copies, journal).unwrap());
                    }
                    Outgoing::Status(_) => {}
                }
            }
            (arrivals, verdicts)
        };
        let (arrivals, verdicts) = apply(&mut store, &mut copies, &mut journal);
        assert!(arrivals.iter().all(|arrival| *arrival == Arrival::Stored));
        assert!(
            verdicts
                .iter()
                .all(|verdict| matches!(verdict, Verdict::Counted(_)))
        );
        let records = copies.records().len();
        // The source resends from its start: identical bytes and verified
        // seals change nothing.
        let (arrivals, verdicts) = apply(&mut store, &mut copies, &mut journal);
        assert!(
            arrivals
                .iter()
                .all(|arrival| *arrival == Arrival::AlreadyStored)
        );
        assert!(
            verdicts
                .iter()
                .all(|verdict| *verdict == Verdict::AlreadyCounted)
        );
        assert_eq!(copies.records().len(), records);
        // Differing bytes at a stored position are refused, and the stored
        // bytes stay.
        assert!(matches!(
            receiver.bytes(RECORDING, 50, &[0xee; 10], &mut store),
            Err(ReceiveError::Mismatch { start: 50 })
        ));
        let mut stored = [0u8; 10];
        store.read(50, &mut stored).unwrap();
        assert_eq!(stored, [1u8; 10]);
        // Bytes past the tail would leave a hole: refused as a gap.
        let tail = store.written();
        assert!(matches!(
            receiver.bytes(RECORDING, tail + 1, &[1], &mut store),
            Err(ReceiveError::PastTail { .. })
        ));
        assert_eq!(store.written(), tail);
        // Bytes straddling the tail: the held part is compared, the rest
        // appended.
        let mut straddle = vec![3u8; 7];
        straddle.extend_from_slice(&[4u8; 5]);
        assert_eq!(
            receiver
                .bytes(RECORDING, tail - 7, &straddle, &mut store)
                .unwrap(),
            Arrival::Stored
        );
        assert_eq!(store.written(), tail + 5);
        assert_eq!(copies.verified_copies(RECORDING, 100, 40_100).unwrap(), 1);
    }

    /// A seal whose range the store does not hold whole is refused before
    /// anything is read or allocated.
    #[test]
    fn a_seal_outside_the_stored_bytes_is_refused_before_reading() {
        let (_dirs, source_dir, replica_dir) = dirs("seal-range");
        let (_, seals) = source(&source_dir);
        let mut store = store(&replica_dir);
        let mut journal = IntegrityJournal::open(StdDisk, &replica_dir)
            .unwrap()
            .journal;
        let mut copies = CopyCatalog::open(StdDisk, &replica_dir, &mut journal).unwrap();
        let receiver = Receiver::new(
            RECORDING,
            Replica::new([9; 32], 0, Enforcement::Unsupported),
        );
        let _ = receiver.bytes(RECORDING, 0, &[1; 100], &mut store).unwrap();
        // The second range, [100, 40100), is not stored.
        assert!(matches!(
            receiver.seal(&seals[1], &mut store, &mut copies, &mut journal),
            Err(ReceiveError::SealOutOfRange { tail: 100, .. })
        ));
        let mut huge = seals[0];
        huge.end = u64::MAX;
        assert!(matches!(
            receiver.seal(&huge, &mut store, &mut copies, &mut journal),
            Err(ReceiveError::SealOutOfRange { .. })
        ));
        assert!(copies.records().is_empty());
    }

    /// ADR-0102 decision 6: a request's first message is its `streaming`
    /// status, with the start, before any bytes; it is not sent again.
    #[test]
    fn the_start_comes_before_any_bytes() {
        let (_dirs, source_dir, _) = dirs("start-first");
        let (mut store, seals) = source(&source_dir);
        let mut sender =
            Sender::accept(request(0, u64::MAX, Mode::Continuous), true, 0, &seals).unwrap();
        let mut out = Vec::new();
        sender
            .poll(&mut store, &seals, false, 50, &mut out)
            .unwrap();
        let Some(Outgoing::Status(first)) = out.first() else {
            panic!("{out:?}");
        };
        assert_eq!((first.state, first.source_start), (State::Streaming, 0));
        assert!(matches!(out.get(1), Some(Outgoing::Bytes { start: 0, .. })));
        out.clear();
        sender
            .poll(&mut store, &seals, false, 50, &mut out)
            .unwrap();
        assert!(matches!(
            out.first(),
            Some(Outgoing::Bytes { start: 50, .. })
        ));
    }

    /// Codex P2 1 (#1219): a purge between the accept and the first poll
    /// interrupts the request before any start marker, so the purged start
    /// is never advertised as the request's.
    #[test]
    fn a_purge_before_the_first_poll_interrupts_without_a_start_marker() {
        let (_dirs, source_dir, _) = dirs("purge-first");
        let (mut store, seals) = source(&source_dir);
        let mut sender =
            Sender::accept(request(0, u64::MAX, Mode::Continuous), true, 0, &seals).unwrap();
        assert_eq!(store.purge_before(100).unwrap(), 100);
        let mut out = Vec::new();
        sender
            .poll(&mut store, &seals, false, usize::MAX, &mut out)
            .unwrap();
        assert!(
            matches!(out.as_slice(), [Outgoing::Status(status)] if status.state == State::Interrupted && status.source_start == 100),
            "{out:?}"
        );
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
        // The start marker first, then the bytes from `from`.
        assert!(
            matches!(out.first(), Some(Outgoing::Status(status)) if status.state == State::Streaming)
        );
        assert!(matches!(
            out.get(1),
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

    /// karyos#1113: a budget below one chunk is kept, a budget of 0 sends
    /// no bytes, and each chunk fits the sender's chunk; the whole still
    /// arrives and counts.
    /// Codex review of #1178: a poll never has more than `CHUNK_POOL`
    /// chunk buffers out. With a large budget and small chunks, a poll
    /// stops at the pool's size while none come back, and goes on from
    /// there once they do, every byte once and in order.
    #[test]
    fn a_poll_waits_for_chunks_to_come_back() {
        use crate::replication::transport::CHUNK_POOL;
        let (_dirs, source_dir, _replica_dir) = dirs("pool");
        let (mut store, seals) = source(&source_dir);
        let mut sender = Sender::accept(request(0, u64::MAX, Mode::OnDemand), true, 0, &seals)
            .unwrap()
            .with_chunk(16);
        let mut out = Vec::new();
        sender
            .poll(&mut store, &seals, false, usize::MAX, &mut out)
            .unwrap();
        let held = |out: &Vec<Outgoing>| {
            out.iter()
                .filter(|message| matches!(message, Outgoing::Bytes { .. }))
                .count()
        };
        assert_eq!(held(&out), CHUNK_POOL, "stopped at the pool's size");
        // Only the start marker, first: no final status while chunks wait.
        assert_eq!(
            out.iter()
                .filter(|message| matches!(message, Outgoing::Status(_)))
                .count(),
            1
        );
        assert!(
            matches!(out.first(), Some(Outgoing::Status(status)) if status.state == State::Streaming)
        );
        // Still held: nothing more.
        let mut more = Vec::new();
        sender
            .poll(&mut store, &seals, false, usize::MAX, &mut more)
            .unwrap();
        assert!(more.is_empty(), "no chunk while every buffer is out");
        let mut next = 0u64;
        let mut done = false;
        for _ in 0..10_000 {
            for message in &out {
                if let Outgoing::Bytes { start, bytes } = message {
                    assert_eq!(*start, next, "in order, once");
                    next += u64::try_from(bytes.len()).unwrap();
                }
                done |=
                    matches!(message, Outgoing::Status(status) if status.state == State::CaughtUp);
            }
            // The chunks are dropped: their buffers come back.
            out.clear();
            if done {
                break;
            }
            sender
                .poll(&mut store, &seals, false, usize::MAX, &mut out)
                .unwrap();
            assert!(held(&out) <= CHUNK_POOL);
        }
        assert!(done, "caught up");
        assert_eq!(next, 40_107);
    }

    #[test]
    fn a_poll_keeps_a_small_budget_and_the_chunk_size() {
        let (_dirs, source_dir, replica_dir) = dirs("small-budget");
        let (mut store, seals) = source(&source_dir);
        let mut sender = Sender::accept(request(0, u64::MAX, Mode::OnDemand), true, 0, &seals)
            .unwrap()
            .with_chunk(1000);
        let mut out = Vec::new();
        sender.poll(&mut store, &seals, false, 0, &mut out).unwrap();
        assert!(
            !out.iter()
                .any(|message| matches!(message, Outgoing::Bytes { .. })),
            "a budget of 0 sends no bytes"
        );
        let mut all = out;
        let mut polls = 0;
        while sender.done().is_none() {
            let mut out = Vec::new();
            sender
                .poll(&mut store, &seals, false, 2500, &mut out)
                .unwrap();
            let mut bytes = 0;
            for message in &out {
                if let Outgoing::Bytes { bytes: chunk, .. } = message {
                    assert!(chunk.len() <= 1000, "{}", chunk.len());
                    bytes += chunk.len();
                }
            }
            assert!(bytes <= 2500, "{bytes}");
            all.extend(out);
            polls += 1;
            assert!(polls < 1000);
        }
        let (verdicts, status, counted) = deliver(&all, &replica_dir, false, (100, 40_100));
        assert_eq!(verdicts.len(), 3);
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

mod cluster_log {
    //! ADR-0120 decision 2: a Cluster log replication sends and counts
    //! only its `ClusterLog` seals of one epoch, and its copies are
    //! recorded under the log's recording id, not the epoch.

    use std::path::PathBuf;

    use super::super::transport::{Outgoing, ReceiveError, Receiver, Sender};
    use super::super::*;
    use crate::disk::StdDisk;
    use crate::integrity::copies::{CopyCatalog, Enforcement};
    use crate::integrity::journal::IntegrityJournal;
    use crate::integrity::replication::{Replica, ReplicationError, Verdict};
    use crate::segment::{Geometry, SegmentStore, SyncPolicy};

    const LOG: u64 = super::LOG;
    const EPOCH: u64 = super::EPOCH;

    struct Dirs(PathBuf);

    impl Drop for Dirs {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn dirs(name: &str) -> (Dirs, PathBuf, PathBuf) {
        let root =
            std::env::temp_dir().join(format!("karyos-repl-log-{name}-{}", std::process::id()));
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
            LOG,
            Geometry::new(4096, 1 << 16).unwrap(),
            SyncPolicy::None,
            0,
        )
        .unwrap()
    }

    /// A log of three ranges: the first sealed in epoch 1, the next two
    /// in [`EPOCH`], plus a segment seal of the log's recording id over
    /// the last range that no Cluster log replication may take.
    fn source(dir: &std::path::Path) -> (SegmentStore<StdDisk>, Vec<SealRecord>) {
        let mut store = store(dir);
        let mut journal = IntegrityJournal::open(StdDisk, dir).unwrap().journal;
        let mut position = 0u64;
        for (index, (epoch, length)) in [(EPOCH - 1, 64usize), (EPOCH, 100), (EPOCH, 20_000)]
            .into_iter()
            .enumerate()
        {
            let bytes = vec![u8::try_from(index + 1).unwrap(); length];
            store.append(position, &bytes).unwrap();
            let end = position + u64::try_from(length).unwrap();
            journal
                .seal_cluster_log(epoch, position, &bytes, end)
                .unwrap()
                .unwrap();
            position = end;
        }
        store.sync().unwrap();
        (store, journal.records().unwrap())
    }

    fn request(from: u64) -> ReplicateRecording {
        ReplicateRecording {
            correlation_id: 7,
            recording_id: LOG,
            from,
            until: u64::MAX,
            mode: Mode::OnDemand,
        }
    }

    fn replica() -> Replica {
        Replica::new([9; 32], 0, Enforcement::Unsupported)
    }

    #[test]
    fn a_cluster_log_replicates_under_its_epochs_seals() {
        let (_dirs, source_dir, replica_dir) = dirs("whole");
        let (mut source_store, seals) = source(&source_dir);
        let scope = SealScope::cluster_log(LOG, EPOCH);
        // The epoch starts at 64: below it is another epoch's range.
        assert!(Sender::accept_in(request(0), scope, true, 64, &seals).is_err());
        let mut sender = Sender::accept_in(request(64), scope, true, 64, &seals).unwrap();
        assert_eq!(sender.scope(), scope);
        let mut out = Vec::new();
        sender
            .poll(&mut source_store, &seals, false, usize::MAX, &mut out)
            .unwrap();
        let sent: Vec<SealRecord> = out
            .iter()
            .filter_map(|message| match message {
                Outgoing::Seal(seal) => Some(*seal),
                _ => None,
            })
            .collect();
        assert_eq!(sent.len(), 2);
        assert!(
            sent.iter()
                .all(|seal| seal.kind == SealKind::ClusterLog && seal.subject == EPOCH)
        );
        assert!(matches!(
            out.last(),
            Some(Outgoing::Status(status))
                if status.state == State::CaughtUp && status.sealed_end == 20_164
        ));

        // The replica holds the log from the epoch's start.
        let mut store = SegmentStore::create(
            StdDisk,
            &replica_dir,
            LOG,
            Geometry::new(4096, 1 << 16).unwrap(),
            SyncPolicy::None,
            64,
        )
        .unwrap();
        let mut journal = IntegrityJournal::open(StdDisk, &replica_dir)
            .unwrap()
            .journal;
        let mut copies = CopyCatalog::open(StdDisk, &replica_dir, &mut journal).unwrap();
        let receiver = Receiver::in_scope(scope, replica());
        assert_eq!(receiver.scope(), scope);
        let mut buf = vec![0u8; 16422];
        let mut verdicts = Vec::new();
        for message in &out {
            let message = match message {
                Outgoing::Bytes { start, bytes } => {
                    ReplicationMessage::RecordingBytes(RecordingBytes {
                        correlation_id: 7,
                        recording_id: LOG,
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
            let length = message.encode(&mut buf).unwrap();
            match ReplicationMessage::decode(&buf[..length]).unwrap() {
                ReplicationMessage::RecordingBytes(bytes) => {
                    let _ = receiver
                        .bytes(bytes.recording_id, bytes.start, bytes.bytes, &mut store)
                        .unwrap();
                }
                ReplicationMessage::SourceSeal(seal) => verdicts.push(
                    receiver
                        .seal(&seal.seal, &mut store, &mut copies, &mut journal)
                        .unwrap(),
                ),
                ReplicationMessage::ReplicationStatus(_) => {}
                _ => panic!("not a source message"),
            }
        }
        assert!(
            verdicts
                .iter()
                .all(|verdict| matches!(verdict, Verdict::Counted(_)))
        );
        // Recorded under the log's recording id, never the epoch.
        for (start, end) in [(64, 164), (164, 20_164)] {
            assert_eq!(copies.verified_copies(LOG, start, end).unwrap(), 1);
            assert_eq!(copies.verified_copies(EPOCH, start, end).unwrap(), 0);
        }
        let lag = receiver
            .replica()
            .lag_in(&copies, scope, 64, 20_164)
            .unwrap();
        assert_eq!((lag.verified_end, lag.behind), (20_164, 0));
        let short = receiver
            .replica()
            .lag_in(&copies, scope, 64, 30_000)
            .unwrap();
        assert_eq!(short.behind, 30_000 - 20_164);
        assert_eq!(
            receiver.replica().lag(&copies, LOG, 64, 20_164).unwrap(),
            lag
        );

        // A seal of another epoch, or a segment seal of the log's id, is
        // foreign to this replication and records nothing.
        let records = copies.records().len();
        let other = seals
            .iter()
            .find(|seal| seal.subject == EPOCH - 1)
            .copied()
            .unwrap();
        let segment = SealRecord {
            kind: SealKind::OpenSegment,
            subject: LOG,
            ..sent[0]
        };
        for foreign in [other, segment] {
            assert!(matches!(
                receiver.seal(&foreign, &mut store, &mut copies, &mut journal),
                Err(ReceiveError::ForeignSeal)
            ));
            assert!(matches!(
                replica().verify_in(&mut copies, &mut journal, scope, &foreign, &[]),
                Err(ReplicationError::OutOfScope { .. })
            ));
        }
        assert_eq!(copies.records().len(), records);
    }

    #[test]
    fn an_ordinary_replication_of_the_log_sends_no_log_seal() {
        let (_dirs, source_dir, _replica_dir) = dirs("ordinary");
        let (mut source_store, seals) = source(&source_dir);
        // ADR-0091's scope: no segment seal covers the log, so nothing is
        // sent and no log seal is a boundary.
        let mut sender = Sender::accept(request(0), true, 0, &seals).unwrap();
        let mut out = Vec::new();
        sender
            .poll(&mut source_store, &seals, false, usize::MAX, &mut out)
            .unwrap();
        assert!(
            !out.iter()
                .any(|message| matches!(message, Outgoing::Seal(_) | Outgoing::Bytes { .. }))
        );
        assert!(Sender::accept(request(64), true, 0, &seals).is_err());
    }
}
