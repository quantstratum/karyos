// SPDX-License-Identifier: Apache-2.0

// `replay diff` (recording-group-replay.md section 11, A8-2): identical
// journals exit 0; each kind of first difference exits 1 with its line
// and its JSON; each not comparable case exits 2; a journal that does not
// recover read only, and bad arguments, exit 3. Journals are written to
// a temporary directory with the operating system's files.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use karyos_archive::disk::StdDisk;
use karyos_archive::group::checkpoint::recorded_end;
use karyos_archive::group::journal::{GroupJournal, JournalConfig, MIN_SEGMENT_LENGTH};
use karyos_archive::group::record::{
    CONTRACT_VERSION, Capture, CheckpointRecord, Clock, EndOutcome, EventEnd, GapMarker, GapReason,
    GroupRecord, JournalHeader, MAX_RECORD, MessageEvent, Operation, Outcome, OutcomeObservation,
    Payload, TimerAction, TimerEvent, TimerObservation,
};
use karyos_archive::segment::SyncPolicy;
use karyos_sys::frame::Lane;

use super::*;

/// A fresh directory under the system's temporary one, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "karyos-replay-diff-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn side(&self, name: &str) -> PathBuf {
        let dir = self.0.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn header(capture: Capture, manifest: &'static [u8]) -> JournalHeader<'static> {
    JournalHeader {
        group_id: 1,
        first_group_seq: 1,
        inline_threshold: 4096,
        contract_version: CONTRACT_VERSION,
        clock: Clock::HostMonotonic,
        capture,
        reopen_hold: 0,
        manifest,
    }
}

fn write(dir: &Path, header: &JournalHeader<'_>, records: &[GroupRecord<'_>]) {
    let config = JournalConfig::new(MIN_SEGMENT_LENGTH, SyncPolicy::PerSegment);
    let mut journal = GroupJournal::create(StdDisk, dir, header, config).unwrap();
    let mut out = vec![0u8; MAX_RECORD];
    for record in records {
        let length = record.encode(&mut out).unwrap();
        let _ = journal.append(&out[..length]).unwrap();
    }
    let _ = journal.close().unwrap();
}

fn message(seq: u64, payload: Payload<'static>) -> GroupRecord<'static> {
    GroupRecord::Message(MessageEvent {
        group_seq: seq,
        logical_time: seq * 10,
        incarnation: 1,
        position: seq * 64,
        extent: 64,
        stream_id: 10,
        session_id: 3,
        lane: Lane::ZERO,
        reserved_value: 0,
        end_of_stream: false,
        extension: None,
        payload,
        image: 0,
    })
}

fn offer(seq: u64, index: u32, payload: &[u8]) -> GroupRecord<'static> {
    GroupRecord::Outcome(OutcomeObservation {
        group_seq: seq,
        index,
        stream_id: 20,
        session_id: 5,
        operation: Operation::Offer,
        outcome: Outcome::Accepted {
            lane: Lane::ZERO,
            position: 0,
        },
        length: u32::try_from(payload.len()).unwrap(),
        crc32c: karyos_archive::crc32c::crc32c(payload),
    })
}

fn schedule(seq: u64, index: u32, deadline: u64) -> GroupRecord<'static> {
    GroupRecord::TimerOperation(TimerObservation {
        group_seq: seq,
        index,
        timer_id: 2,
        deadline,
        action: TimerAction::Create,
    })
}

fn end(seq: u64, observations: u32, outcome: EndOutcome) -> GroupRecord<'static> {
    GroupRecord::End(EventEnd {
        group_seq: seq,
        observations,
        outcome,
    })
}

/// Three events: a message with an offer, a timer with a schedule, a
/// message with none.
fn recorded() -> Vec<GroupRecord<'static>> {
    vec![
        message(1, Payload::Inline(b"a")),
        offer(1, 0, b"out 1"),
        end(1, 1, EndOutcome::Complete),
        GroupRecord::Timer(TimerEvent {
            group_seq: 2,
            logical_time: 20,
            timer_id: 2,
        }),
        schedule(2, 0, 100),
        end(2, 1, EndOutcome::Complete),
        message(3, Payload::Inline(b"c")),
        end(3, 0, EndOutcome::Complete),
    ]
}

/// Diffs `left` against `right` (both strict, manifest `m`) with
/// `options` applied to the arguments.
fn run(
    left: &[GroupRecord<'_>],
    right: &[GroupRecord<'_>],
    options: impl FnOnce(&mut DiffArgs),
) -> Report {
    run_with(
        (&header(Capture::Strict, b"m"), left),
        (&header(Capture::Strict, b"m"), right),
        options,
    )
}

fn run_with(
    left: (&JournalHeader<'_>, &[GroupRecord<'_>]),
    right: (&JournalHeader<'_>, &[GroupRecord<'_>]),
    options: impl FnOnce(&mut DiffArgs),
) -> Report {
    let scratch = Scratch::new();
    let (left_dir, right_dir) = (scratch.side("left"), scratch.side("right"));
    write(&left_dir, left.0, left.1);
    write(&right_dir, right.0, right.1);
    let mut args = DiffArgs {
        left: Journal {
            dir: left_dir,
            group: 1,
        },
        right: Journal {
            dir: right_dir,
            group: 1,
        },
        from: None,
        to: None,
        json: false,
        accept_manifest: false,
        from_checkpoint: None,
    };
    options(&mut args);
    diff(&args)
}

#[test]
fn identical_journals_exit_0() {
    let report = run(&recorded(), &recorded(), |_| {});
    assert_eq!(
        report,
        Report::Identical {
            from: 1,
            to: Some(3),
            events: 3
        }
    );
    assert_eq!(report.exit_code(), 0);
    assert_eq!(report.text(), "identical: group_seq 1 to 3, 3 events\n");
    assert!(report.json().starts_with("{\"result\":\"identical\""));
    assert!(
        report
            .json()
            .ends_with(",\"from\":1,\"to\":3,\"events\":3}\n")
    );
    // A range inside both.
    let report = run(&recorded(), &recorded(), |args| {
        args.from = Some(2);
        args.to = Some(2);
    });
    assert_eq!(
        report,
        Report::Identical {
            from: 2,
            to: Some(2),
            events: 1
        }
    );
}

/// Each kind of first difference, with its line and its JSON.
#[test]
fn each_difference_exits_1_with_its_kind() {
    let base = recorded();
    let changed = |index: usize, record: GroupRecord<'static>| {
        let mut records = recorded();
        records[index] = record;
        records
    };
    let cases: [(Vec<GroupRecord<'static>>, Kind, u64, Option<u32>); 5] = [
        (
            changed(0, message(1, Payload::Inline(b"b"))),
            Kind::InputEvent,
            1,
            None,
        ),
        (
            changed(1, offer(1, 0, b"out 2")),
            Kind::OutputIntent,
            1,
            Some(0),
        ),
        (
            changed(4, schedule(2, 0, 101)),
            Kind::Observation,
            2,
            Some(0),
        ),
        (
            {
                let mut records = recorded();
                records.splice(1..3, [end(1, 0, EndOutcome::Complete)]);
                records
            },
            Kind::MissingObservation,
            1,
            Some(0),
        ),
        (
            {
                let mut records = recorded();
                records.splice(
                    6..8,
                    [
                        message(3, Payload::Inline(b"c")),
                        schedule(3, 0, 5),
                        end(3, 1, EndOutcome::Complete),
                    ],
                );
                records
            },
            Kind::ExtraObservation,
            3,
            Some(0),
        ),
    ];
    for (right, kind, group_seq, index) in cases {
        let report = run(&base, &right, |_| {});
        let Report::Diverged {
            group_seq: at,
            index: found_index,
            kind: found,
            ..
        } = &report
        else {
            panic!("{kind:?}: {report:?}");
        };
        assert_eq!((*at, *found_index, *found), (group_seq, index, kind));
        assert_eq!(report.exit_code(), 1);
        let line = report.text();
        assert!(line.contains(kind.name()), "{line}");
        assert!(line.contains("  expected: "), "{line}");
        assert!(line.contains("  found:    "), "{line}");
        let json = report.json();
        assert!(
            json.contains(&format!("\"kind\":\"{}\"", kind.name())),
            "{json}"
        );
        assert!(json.starts_with("{\"result\":\"diverged\""), "{json}");
    }
    // An output intent names the operation, length and digest.
    let report = run(&base, &changed(1, offer(1, 0, b"out 2")), |_| {});
    let text = report.text();
    assert!(
        text.starts_with("diverged at group_seq 1, observation 0: output intent\n"),
        "{text}"
    );
    assert!(text.contains("offer, stream 20 session 5"), "{text}");
    assert!(text.contains("length 5, crc32c 0x"), "{text}");
    // The end: another outcome.
    let mut incomplete_end = recorded();
    incomplete_end.truncate(7);
    incomplete_end.push(end(3, 0, EndOutcome::Incomplete));
    let report = run(&recorded()[..], &incomplete_end, |args| args.to = Some(2));
    assert!(
        matches!(report, Report::Identical { events: 2, .. }),
        "{report:?}"
    );
}

/// Every not comparable case exits 2.
#[test]
fn what_cannot_be_compared_exits_2() {
    let base = recorded();
    // Manifests that differ, unless accepted.
    let other = header(Capture::Strict, b"n");
    let report = run_with(
        (&header(Capture::Strict, b"m"), &base),
        (&other, &base),
        |_| {},
    );
    assert_eq!(report.exit_code(), 2, "{report:?}");
    let report = run_with(
        (&header(Capture::Strict, b"m"), &base),
        (&other, &base),
        |args| args.accept_manifest = true,
    );
    assert_eq!(report.exit_code(), 0, "{report:?}");
    // A range past either complete prefix.
    let report = run(&base, &base, |args| args.to = Some(4));
    assert_eq!(report.exit_code(), 2, "{report:?}");
    assert!(
        report.text().contains("complete prefix"),
        "{}",
        report.text()
    );
    // A strict journal ended incomplete before the end of the range.
    let mut incomplete = recorded();
    incomplete.truncate(7);
    incomplete.push(end(3, 0, EndOutcome::Incomplete));
    let report = run(&base, &incomplete, |args| args.to = Some(3));
    assert_eq!(report.exit_code(), 2, "{report:?}");
    assert!(
        report.text().contains("ended incomplete"),
        "{}",
        report.text()
    );
    // A gap marker in the range (best effort).
    let effort = header(Capture::BestEffort, b"m");
    let gapped = [
        message(1, Payload::Inline(b"a")),
        end(1, 0, EndOutcome::Complete),
        GroupRecord::Gap(GapMarker {
            from_seq: 2,
            to_seq: 2,
            reason: GapReason::RingFull,
        }),
        message(3, Payload::Inline(b"c")),
        end(3, 0, EndOutcome::Complete),
    ];
    let report = run_with((&effort, &gapped), (&effort, &gapped), |args| {
        args.to = Some(3);
    });
    assert_eq!(report.exit_code(), 2, "{report:?}");
    assert!(report.text().contains("gap marker"), "{}", report.text());
    // A payload not captured in the range.
    let GroupRecord::Message(event) = message(1, Payload::Unavailable { length: 70_000 }) else {
        panic!("a message");
    };
    let uncaptured = [
        GroupRecord::Message(MessageEvent {
            extent: 70_080,
            ..event
        }),
        end(1, 0, EndOutcome::Complete),
    ];
    let report = run_with((&effort, &uncaptured), (&effort, &uncaptured), |_| {});
    assert_eq!(report.exit_code(), 2, "{report:?}");
    assert!(report.text().contains("not captured"), "{}", report.text());
    let json = report.json();
    assert!(json.starts_with("{\"result\":\"not_comparable\""), "{json}");
    assert!(json.contains("\"reason\":\""), "{json}");
}

/// A journal that is not there, or that recovery would repair, exits 3;
/// so do bad arguments. Nothing is written.
#[test]
fn errors_exit_3() {
    let scratch = Scratch::new();
    let missing = DiffArgs {
        left: Journal {
            dir: scratch.side("none"),
            group: 1,
        },
        right: Journal {
            dir: scratch.side("none"),
            group: 1,
        },
        from: None,
        to: None,
        json: true,
        accept_manifest: false,
        from_checkpoint: None,
    };
    let report = diff(&missing);
    assert_eq!(report.exit_code(), 3, "{report:?}");
    assert!(report.json().starts_with("{\"result\":\"error\""));
    // A torn tail: bytes past the last whole record in the data file.
    let torn = scratch.side("torn");
    write(&torn, &header(Capture::Strict, b"m"), &recorded());
    let data = std::fs::read_dir(&torn)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|ext| ext == "seg"))
        .unwrap();
    let before = std::fs::read(&data).unwrap();
    let index = data.with_extension("idx");
    let index_before = std::fs::read(&index).unwrap();
    // Corrupt the last entry's bytes: its CRC no longer holds.
    let mut bytes = before.clone();
    let last = bytes.iter().rposition(|byte| *byte != 0).unwrap();
    bytes[last] ^= 0xFF;
    std::fs::write(&data, &bytes).unwrap();
    let args = DiffArgs {
        left: Journal {
            dir: torn.clone(),
            group: 1,
        },
        right: Journal {
            dir: torn,
            group: 1,
        },
        from: None,
        to: None,
        json: false,
        accept_manifest: false,
        from_checkpoint: None,
    };
    let report = diff(&args);
    assert_eq!(report.exit_code(), 3, "{report:?}");
    assert_eq!(std::fs::read(&data).unwrap(), bytes, "the diff wrote");
    assert_eq!(
        std::fs::read(&index).unwrap(),
        index_before,
        "the diff wrote"
    );
    for bad in [
        &["a", "1", "b"][..],
        &["a", "x", "b", "1"],
        &["a", "1", "b", "1", "--from", "3", "--to", "2"],
        &["a", "1", "b", "1", "--frob"],
    ] {
        assert!(
            parse_diff(bad.iter().map(OsString::from)).is_err(),
            "{bad:?}"
        );
    }
    assert_eq!(parse_diff([OsString::from("--help")]), Ok(None));
}

/// `count` timer events from `first`, each with no observation.
fn timers(first: u64, count: u64) -> Vec<GroupRecord<'static>> {
    (first..first + count)
        .flat_map(|seq| {
            [
                GroupRecord::Timer(TimerEvent {
                    group_seq: seq,
                    logical_time: seq,
                    timer_id: 1,
                }),
                end(seq, 0, EndOutcome::Complete),
            ]
        })
        .collect()
}

/// The default range runs to the longer complete prefix: events on one
/// side only are the `end` kind, exit 1, with the side that ended named.
#[test]
fn the_longer_prefix_is_compared_and_one_sided_events_are_the_end() {
    let report = run(&timers(1, 3), &timers(1, 2), |_| {});
    let Report::Diverged {
        group_seq,
        index,
        kind,
        found,
        ..
    } = &report
    else {
        panic!("{report:?}");
    };
    assert_eq!((*group_seq, *index, *kind), (3, None, Kind::End));
    assert!(
        found.contains("right journal's complete prefix ends at group_seq 2"),
        "{found}"
    );
    assert_eq!(report.exit_code(), 1);
    // An empty journal against a full one.
    let report = run(&[], &timers(1, 2), |_| {});
    assert!(
        matches!(
            report,
            Report::Diverged {
                kind: Kind::End,
                group_seq: 1,
                ..
            }
        ),
        "{report:?}"
    );
    // The side that stopped at a gap is not comparable, the left one too.
    let effort = header(Capture::BestEffort, b"m");
    let mut gapped = timers(1, 1);
    gapped.push(GroupRecord::Gap(GapMarker {
        from_seq: 2,
        to_seq: 2,
        reason: GapReason::RingFull,
    }));
    let report = run_with((&effort, &gapped), (&effort, &timers(1, 3)), |_| {});
    assert_eq!(report.exit_code(), 2, "{report:?}");
    assert!(
        report.text().contains("left journal: a gap marker"),
        "{}",
        report.text()
    );
}

/// A range past a complete prefix is not comparable, `--from` alone too;
/// the prefix's last event itself is in it.
#[test]
fn a_range_past_a_prefix_is_not_comparable() {
    let (long, short) = (timers(1, 7), timers(1, 3));
    for options in [(Some(5), None), (Some(5), Some(6)), (None, Some(4))] {
        let report = run(&long, &short, |args| (args.from, args.to) = options);
        assert_eq!(report.exit_code(), 2, "{options:?}: {report:?}");
    }
    // To the prefix's last event exactly: compared, and identical.
    let report = run(&long, &short, |args| args.to = Some(3));
    assert_eq!(
        report,
        Report::Identical {
            from: 1,
            to: Some(3),
            events: 3
        }
    );
}

/// Empty and inverted ranges, and a `--from` before a journal's first
/// event, are not comparable; the default `--from` is the later first.
#[test]
fn empty_ranges_and_early_starts_are_not_comparable() {
    let both = timers(1, 3);
    let report = run(&both, &both, |args| args.to = Some(0));
    assert_eq!(report.exit_code(), 2, "{report:?}");
    let later = JournalHeader {
        first_group_seq: 2,
        ..header(Capture::Strict, b"m")
    };
    let left = (&header(Capture::Strict, b"m"), &both[..]);
    let from_two = timers(2, 2);
    let report = run_with(left, (&later, &from_two), |_| {});
    assert_eq!(
        report,
        Report::Identical {
            from: 2,
            to: Some(3),
            events: 2
        }
    );
    let report = run_with(left, (&later, &from_two), |args| args.from = Some(1));
    assert_eq!(report.exit_code(), 2, "{report:?}");
    assert!(
        report.text().contains("before a journal's first event"),
        "{}",
        report.text()
    );
    let report = run_with(left, (&later, &from_two), |args| args.to = Some(1));
    assert_eq!(report.exit_code(), 2, "{report:?}");
}

/// A reference unavailable in the range is not comparable.
#[test]
fn a_reference_unavailable_in_the_range_is_not_comparable() {
    use karyos_archive::group::record::ReferenceUnavailable;

    let effort = header(Capture::BestEffort, b"m");
    let referenced = [
        message(
            1,
            Payload::Reference {
                recording_id: 8,
                length: 10,
            },
        ),
        end(1, 0, EndOutcome::Complete),
        GroupRecord::Unavailable(ReferenceUnavailable {
            group_seq: 1,
            recording_id: 8,
        }),
    ];
    let report = run_with((&effort, &referenced), (&effort, &referenced), |_| {});
    assert_eq!(report.exit_code(), 2, "{report:?}");
    assert!(
        report.text().contains("reference is unavailable"),
        "{}",
        report.text()
    );
}

/// A journal of another capture contract is not comparable, not a
/// corrupt one: its header names the contract.
#[test]
fn another_contract_is_not_comparable() {
    use karyos_archive::group::journal::MIN_SEGMENT_LENGTH;
    use karyos_archive::segment::{Geometry, SegmentStore};

    let scratch = Scratch::new();
    let (left, right) = (scratch.side("left"), scratch.side("right"));
    write(&left, &header(Capture::Strict, b"m"), &timers(1, 1));
    // The right journal's header, under contract 2, appended raw.
    let mut bytes = vec![0u8; MAX_RECORD];
    let length = GroupRecord::Header(header(Capture::Strict, b"m"))
        .encode(&mut bytes)
        .unwrap();
    bytes.truncate(length);
    bytes[12 + 20..12 + 22].copy_from_slice(&2u16.to_le_bytes());
    let length = u64::from(MIN_SEGMENT_LENGTH);
    let mut store = SegmentStore::create(
        StdDisk,
        &right,
        1,
        Geometry::new(MIN_SEGMENT_LENGTH, length).unwrap(),
        SyncPolicy::PerSegment,
        0,
    )
    .unwrap();
    let _ = store.append(0, &bytes).unwrap();
    let _ = store.close().unwrap();
    let report = diff(&DiffArgs {
        left: Journal {
            dir: left,
            group: 1,
        },
        right: Journal {
            dir: right,
            group: 1,
        },
        from: None,
        to: None,
        json: false,
        accept_manifest: false,
        from_checkpoint: None,
    });
    assert_eq!(report.exit_code(), 2, "{report:?}");
    assert!(report.text().contains("contract 2"), "{}", report.text());
}

/// JSON strings escape quotes, backslashes and control characters.
#[test]
fn json_escapes_what_it_must() {
    assert_eq!(quoted("a\"b\\c\nd\u{1}é"), "\"a\\\"b\\\\c\\nd\\u0001é\"");
}

/// A payload is shown by its length and digest, never as its bytes.
#[test]
fn a_payload_is_shown_by_length_and_digest() {
    let big = vec![7u8; 4000];
    let leaked: &'static [u8] = Box::leak(big.into_boxed_slice());
    let mut changed = timers(1, 1);
    let GroupRecord::Message(event) = message(1, Payload::Inline(leaked)) else {
        panic!("a message");
    };
    changed[0] = GroupRecord::Message(MessageEvent {
        extent: 4064,
        ..event
    });
    let mut original = timers(1, 1);
    original[0] = message(1, Payload::Inline(b"a"));
    let report = run(&original, &changed, |_| {});
    let text = report.text();
    assert!(
        text.contains("payload inline, length 4000, crc32c 0x"),
        "{text}"
    );
    assert!(text.len() < 1000, "{} bytes", text.len());
}

/// An explicit `--from` at a prefix's first event left out is past it,
/// for prefixes of equal or different lengths; the default `--from` on
/// an empty journal is the `end` kind (above).
#[test]
fn a_from_one_past_a_prefix_is_not_comparable() {
    for (left, right) in [(timers(1, 3), timers(1, 3)), (timers(1, 7), timers(1, 3))] {
        let report = run(&left, &right, |args| args.from = Some(4));
        assert_eq!(report.exit_code(), 2, "{report:?}");
    }
}

/// A difference in any compared field is shown: two messages that
/// differ only in their logical time print different lines.
#[test]
fn every_compared_field_is_shown() {
    let GroupRecord::Message(event) = message(1, Payload::Inline(b"a")) else {
        panic!("a message");
    };
    let mut later = timers(1, 1);
    later[0] = GroupRecord::Message(MessageEvent {
        logical_time: event.logical_time + 1,
        ..event
    });
    let mut original = timers(1, 1);
    original[0] = GroupRecord::Message(event);
    let Report::Diverged {
        expected, found, ..
    } = run(&original, &later, |_| {})
    else {
        panic!("not diverged");
    };
    assert_ne!(expected, found);
    assert!(expected.contains("logical time 10"), "{expected}");
}

/// An event of more than 16384 records is an error, exit 3.
#[test]
fn an_event_past_the_record_bound_is_an_error() {
    let observations = 16_383u32;
    let mut records = vec![GroupRecord::Timer(TimerEvent {
        group_seq: 1,
        logical_time: 1,
        timer_id: 1,
    })];
    records.extend((0..observations).map(|index| schedule(1, index, 100)));
    records.push(end(1, observations, EndOutcome::Complete));
    assert_eq!(records.len(), 16_385);
    let report = run(&records, &records, |_| {});
    assert_eq!(report.exit_code(), 3, "{report:?}");
    assert!(report.text().contains("16384 records"), "{}", report.text());
}

/// Writes `records` to a journal in `dir`, with a checkpoint of each
/// `snapshot` taken after its event, its store in `dir/checkpoints`.
fn write_with_checkpoints(
    dir: &Path,
    header: &JournalHeader<'_>,
    records: &[GroupRecord<'_>],
    checkpoints: &[(u64, &[u8])],
) {
    use karyos_archive::group::checkpoint::{CheckpointSlot, CheckpointStore, CheckpointWriter};

    let config = JournalConfig::new(
        karyos_archive::group::journal::MIN_SEGMENT_LENGTH,
        SyncPolicy::PerSegment,
    );
    let mut journal = GroupJournal::create(StdDisk, dir, header, config).unwrap();
    let store_dir = dir.join(CHECKPOINTS);
    std::fs::create_dir_all(&store_dir).unwrap();
    let store = CheckpointStore::create(StdDisk, &store_dir, header.group_id, config).unwrap();
    let mut writer = CheckpointWriter::new(store, &journal).unwrap();
    let mut slot = CheckpointSlot::new(1024);
    let mut out = vec![0u8; MAX_RECORD];
    for record in records {
        let length = record.encode(&mut out).unwrap();
        let _ = journal.append(&out[..length]).unwrap();
        if let GroupRecord::End(end) = record {
            for (_, snapshot) in checkpoints
                .iter()
                .filter(|(after, _)| *after == end.group_seq)
            {
                let request = slot
                    .take(end.group_seq, 1, |buffer| {
                        buffer[..snapshot.len()].copy_from_slice(snapshot);
                        snapshot.len()
                    })
                    .unwrap();
                let written = writer.write(&mut journal, &request);
                slot.returned(request, &written);
                let _ = written.unwrap();
            }
        }
    }
    let _ = journal.close().unwrap();
}

/// Diffs two journals written with checkpoints.
fn run_checkpoints(
    left: (&[GroupRecord<'_>], &[(u64, &[u8])]),
    right: (&[GroupRecord<'_>], &[(u64, &[u8])]),
    options: impl FnOnce(&mut DiffArgs),
) -> Report {
    let scratch = Scratch::new();
    let (left_dir, right_dir) = (scratch.side("left"), scratch.side("right"));
    let header = header(Capture::Strict, b"m");
    write_with_checkpoints(&left_dir, &header, left.0, left.1);
    write_with_checkpoints(&right_dir, &header, right.0, right.1);
    let mut args = DiffArgs {
        left: Journal {
            dir: left_dir,
            group: 1,
        },
        right: Journal {
            dir: right_dir,
            group: 1,
        },
        from: None,
        to: None,
        json: false,
        accept_manifest: false,
        from_checkpoint: None,
    };
    options(&mut args);
    diff(&args)
}

/// Checkpoints are compared as records, matched by `group_seq`: equal
/// ones are identical; a different snapshot, or one on one side only, is
/// the `state checkpoint` kind at its `group_seq`.
#[test]
fn checkpoints_are_compared_as_records() {
    let events = timers(1, 4);
    let same: &[(u64, &[u8])] = &[(2, b"state at 2")];
    let report = run_checkpoints((&events, same), (&events, same), |_| {});
    assert_eq!(
        report,
        Report::Identical {
            from: 1,
            to: Some(4),
            events: 4
        }
    );
    let other: &[(u64, &[u8])] = &[(2, b"state at 2!")];
    let report = run_checkpoints((&events, same), (&events, other), |_| {});
    let Report::Diverged {
        group_seq,
        kind,
        expected,
        found,
        ..
    } = &report
    else {
        panic!("{report:?}");
    };
    assert_eq!((*group_seq, *kind), (2, Kind::StateCheckpoint));
    assert!(
        expected.contains("length 10") && found.contains("length 11"),
        "{expected} / {found}"
    );
    assert!(
        report.json().contains("\"kind\":\"state checkpoint\""),
        "{}",
        report.json()
    );
    let report = run_checkpoints((&events, same), (&events, &[]), |_| {});
    assert!(
        matches!(&report, Report::Diverged { kind: Kind::StateCheckpoint, group_seq: 2, found, .. } if found == "none"),
        "{report:?}"
    );
    // Matched by `group_seq`: at another event it differs there, the
    // earlier one first.
    let later: &[(u64, &[u8])] = &[(3, b"state at 2")];
    let report = run_checkpoints((&events, same), (&events, later), |_| {});
    assert!(
        matches!(
            &report,
            Report::Diverged {
                kind: Kind::StateCheckpoint,
                group_seq: 2,
                ..
            }
        ),
        "{report:?}"
    );
}

/// `--from-checkpoint` compares from the event after it: events before
/// it may differ. An unknown checkpoint, or a store that is not there,
/// is not comparable.
#[test]
fn from_a_checkpoint_the_range_starts_after_it() {
    let mut left = timers(1, 4);
    let mut right = timers(1, 4);
    // Event 1 differs, before the checkpoint after event 2.
    left[0] = GroupRecord::Timer(TimerEvent {
        group_seq: 1,
        logical_time: 1,
        timer_id: 5,
    });
    right[0] = GroupRecord::Timer(TimerEvent {
        group_seq: 1,
        logical_time: 1,
        timer_id: 6,
    });
    let at_two: &[(u64, &[u8])] = &[(2, b"state at 2")];
    let report = run_checkpoints((&left, at_two), (&right, at_two), |_| {});
    assert_eq!(report.exit_code(), 1, "{report:?}");
    let report = run_checkpoints((&left, at_two), (&right, at_two), |args| {
        args.from_checkpoint = Some(1);
    });
    assert_eq!(
        report,
        Report::Identical {
            from: 3,
            to: Some(4),
            events: 2
        }
    );
    let report = run_checkpoints((&left, at_two), (&right, at_two), |args| {
        args.from_checkpoint = Some(9);
    });
    assert_eq!(report.exit_code(), 2, "{report:?}");
    // The two checkpoints differ: the state checkpoint kind, first.
    let other: &[(u64, &[u8])] = &[(2, b"state at 2!")];
    let report = run_checkpoints((&left, at_two), (&right, other), |args| {
        args.from_checkpoint = Some(1);
    });
    assert!(
        matches!(
            report,
            Report::Diverged {
                kind: Kind::StateCheckpoint,
                ..
            }
        ),
        "{report:?}"
    );
    // A store that is not there.
    let scratch = Scratch::new();
    let (left_dir, right_dir) = (scratch.side("left"), scratch.side("right"));
    let header = header(Capture::Strict, b"m");
    write_with_checkpoints(&left_dir, &header, &left, at_two);
    write_with_checkpoints(&right_dir, &header, &right, at_two);
    std::fs::remove_dir_all(right_dir.join(CHECKPOINTS)).unwrap();
    let report = diff(&DiffArgs {
        left: Journal {
            dir: left_dir,
            group: 1,
        },
        right: Journal {
            dir: right_dir,
            group: 1,
        },
        from: None,
        to: None,
        json: false,
        accept_manifest: false,
        from_checkpoint: Some(1),
    });
    assert_eq!(report.exit_code(), 2, "{report:?}");
}

#[test]
fn from_checkpoint_parses() {
    let args = parse_diff(
        ["a", "1", "b", "1", "--from-checkpoint", "3"]
            .iter()
            .map(OsString::from),
    )
    .unwrap()
    .unwrap();
    assert_eq!(args.from_checkpoint, Some(3));
}

/// Diffs `left_dir` and `right_dir`, group 1, from checkpoint `id`.
fn diff_from_checkpoint(left_dir: &Path, right_dir: &Path, id: u64) -> Report {
    diff(&DiffArgs {
        left: Journal {
            dir: left_dir.to_path_buf(),
            group: 1,
        },
        right: Journal {
            dir: right_dir.to_path_buf(),
            group: 1,
        },
        from: None,
        to: None,
        json: false,
        accept_manifest: false,
        from_checkpoint: Some(id),
    })
}

/// The store's data file in `dir`: one segment.
fn store_data(dir: &Path) -> std::path::PathBuf {
    let mut data = std::fs::read_dir(dir.join(CHECKPOINTS))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "seg"));
    let path = data.next().unwrap();
    assert!(data.next().is_none());
    path
}

/// #430 P1: a damaged store is read as its recovery would leave it,
/// never repaired: a checkpoint it lost is not comparable (exit 2), an
/// earlier intact one still compares, and bytes no record names (a crash
/// between the store write and the record) are passed over.
#[test]
fn a_damaged_checkpoint_store_is_not_comparable_never_an_error() {
    let events = timers(1, 4);
    let two: &[(u64, &[u8])] = &[(1, b"first state"), (3, b"second state")];
    let write = |scratch: &Scratch, checkpoints: &[(u64, &[u8])]| {
        let (left, right) = (scratch.side("left"), scratch.side("right"));
        let header = header(Capture::Strict, b"m");
        write_with_checkpoints(&left, &header, &events, two);
        write_with_checkpoints(&right, &header, &events, checkpoints);
        (left, right)
    };
    let length = |path: &Path| std::fs::metadata(path).unwrap().len();
    // One flipped byte of the second snapshot, its last.
    let scratch = Scratch::new();
    let (left, right) = write(&scratch, two);
    let data = store_data(&right);
    let mut bytes = std::fs::read(&data).unwrap();
    let last = bytes.iter().rposition(|byte| *byte == b'e').unwrap();
    bytes[last] ^= 0x01;
    std::fs::write(&data, &bytes).unwrap();
    let before = (length(&data), bytes.clone());
    let report = diff_from_checkpoint(&left, &right, 2);
    assert_eq!(report.exit_code(), 2, "{report:?}");
    assert!(report.text().contains("corrupt"), "{}", report.text());
    assert_eq!(diff_from_checkpoint(&left, &right, 1).exit_code(), 0);
    // Read only: the store is as it was.
    assert_eq!((length(&data), std::fs::read(&data).unwrap()), before);
    // A store cut in the middle of the second snapshot.
    let scratch = Scratch::new();
    let (left, right) = write(&scratch, two);
    let data = store_data(&right);
    let file = std::fs::OpenOptions::new().write(true).open(&data).unwrap();
    file.set_len(length(&data) - 4).unwrap();
    assert_eq!(diff_from_checkpoint(&left, &right, 2).exit_code(), 2);
    assert_eq!(diff_from_checkpoint(&left, &right, 1).exit_code(), 0);
    // The second snapshot written, its record never appended: the right
    // journal names the first only, over a store holding both.
    let scratch = Scratch::new();
    let (left, right) = write(&scratch, &two[..1]);
    let other = scratch.side("both");
    write_with_checkpoints(&other, &header(Capture::Strict, b"m"), &events, two);
    std::fs::copy(store_data(&other), store_data(&right)).unwrap();
    let report = diff_from_checkpoint(&left, &right, 1);
    assert_eq!(report.exit_code(), 1, "{report:?}");
    assert!(
        matches!(
            report,
            Report::Diverged {
                kind: Kind::StateCheckpoint,
                group_seq: 3,
                ..
            }
        ),
        "{report:?}"
    );
}

/// The records of `timers(1, 4)` with `checkpoint` after event 2's end.
fn with_checkpoint(checkpoint: CheckpointRecord) -> Vec<GroupRecord<'static>> {
    let mut records = timers(1, 4);
    records.insert(4, GroupRecord::Checkpoint(checkpoint));
    records
}

/// #430 P2: each field of the record is compared alone: the crc32c, the
/// format and the length.
#[test]
fn each_checkpoint_field_is_compared() {
    let recorded = CheckpointRecord {
        group_seq: 2,
        checkpoint_id: 1,
        position: 0,
        length: 8,
        crc32c: 0x1234_5678,
        format: 1,
    };
    let left = with_checkpoint(recorded);
    assert_eq!(run(&left, &left, |_| {}).exit_code(), 0);
    for other in [
        CheckpointRecord {
            crc32c: 0x1234_5679,
            ..recorded
        },
        CheckpointRecord {
            format: 2,
            ..recorded
        },
        CheckpointRecord {
            length: 9,
            ..recorded
        },
    ] {
        let report = run(&left, &with_checkpoint(other), |_| {});
        assert!(
            matches!(
                report,
                Report::Diverged {
                    kind: Kind::StateCheckpoint,
                    group_seq: 2,
                    ..
                }
            ),
            "{other:?}: {report:?}"
        );
    }
}

/// #430 P2: `--from-checkpoint <id>` names the left journal's checkpoint;
/// the right one opens at its checkpoint with the same `group_seq`,
/// whatever its id. None there is not comparable.
#[test]
fn from_checkpoint_matches_the_right_journal_by_group_seq() {
    let events = timers(1, 4);
    let left: &[(u64, &[u8])] = &[(1, b"one"), (3, b"three")];
    let right: &[(u64, &[u8])] = &[(3, b"three")];
    let report = run_checkpoints((&events, left), (&events, right), |args| {
        args.from_checkpoint = Some(2);
    });
    assert_eq!(
        report,
        Report::Identical {
            from: 4,
            to: Some(4),
            events: 1
        }
    );
    let report = run_checkpoints((&events, left), (&events, right), |args| {
        args.from_checkpoint = Some(1);
    });
    assert_eq!(report.exit_code(), 2, "{report:?}");
    assert!(
        report.text().contains("no checkpoint at group_seq 1"),
        "{}",
        report.text()
    );
}

/// #430 P3: the prefix is recovered with the store as it holds the
/// checkpoints. A gap, an intact checkpoint A, a second gap, then a lost
/// checkpoint B: B opens no range, so A's range is the current one and
/// replays, to the second gap; B itself, lost, is not comparable.
#[test]
fn a_lost_checkpoint_opens_no_range() {
    let gap = |seq| {
        GroupRecord::Gap(GapMarker {
            from_seq: seq,
            to_seq: seq,
            reason: GapReason::RingFull,
        })
    };
    let mut records = Vec::new();
    for seq in 1..=7 {
        if seq == 2 || seq == 5 {
            records.push(gap(seq));
        } else {
            records.extend(timers(seq, 1));
        }
    }
    let checkpoints: &[(u64, &[u8])] = &[(3, b"state A"), (6, b"state B")];
    let scratch = Scratch::new();
    let effort = header(Capture::BestEffort, b"m");
    let dirs = [scratch.side("left"), scratch.side("right")];
    for dir in &dirs {
        write_with_checkpoints(dir, &effort, &records, checkpoints);
        let data = store_data(dir);
        let mut bytes = std::fs::read(&data).unwrap();
        let last = bytes.iter().rposition(|byte| *byte == b'B').unwrap();
        bytes[last] ^= 0x01;
        std::fs::write(&data, &bytes).unwrap();
    }
    // A's range replays up to the second gap, its end: compared to it.
    let report = diff_from_checkpoint(&dirs[0], &dirs[1], 1);
    assert_eq!(
        report,
        Report::Identical {
            from: 4,
            to: Some(4),
            events: 1
        }
    );
    // B itself, lost, opens no range: not comparable.
    let report = diff_from_checkpoint(&dirs[0], &dirs[1], 2);
    assert_eq!(report.exit_code(), 2, "{report:?}");
}

/// #430 re-check: a store that a recovery already marked lost (a cut
/// store, then `CheckpointStore::recover` on it) is read with its lost
/// range: that checkpoint is not comparable, the earlier one compares.
#[test]
fn a_store_marked_lost_by_recovery_is_not_comparable() {
    use karyos_archive::group::checkpoint::CheckpointStore;

    let events = timers(1, 4);
    let two: &[(u64, &[u8])] = &[(1, b"first state"), (3, b"second state")];
    let scratch = Scratch::new();
    let (left, right) = (scratch.side("left"), scratch.side("right"));
    let header = header(Capture::Strict, b"m");
    write_with_checkpoints(&left, &header, &events, two);
    write_with_checkpoints(&right, &header, &events, two);
    let data = store_data(&right);
    let file = std::fs::OpenOptions::new().write(true).open(&data).unwrap();
    file.set_len(std::fs::metadata(&data).unwrap().len() - 4)
        .unwrap();
    let config = JournalConfig::new(MIN_SEGMENT_LENGTH, SyncPolicy::PerSegment);
    let mut journal = GroupJournal::recover(StdDisk, &right, 1, config)
        .unwrap()
        .journal;
    let end = recorded_end(&mut journal).unwrap();
    drop(journal);
    let store =
        CheckpointStore::recover(StdDisk, &right.join(CHECKPOINTS), 1, config, end).unwrap();
    drop(store);
    let report = diff_from_checkpoint(&left, &right, 2);
    assert_eq!(report.exit_code(), 2, "{report:?}");
    assert_eq!(diff_from_checkpoint(&left, &right, 1).exit_code(), 0);
}

/// A checkpoint directory with no store in it is not comparable, as a
/// missing directory is.
#[test]
fn an_empty_checkpoint_directory_is_not_comparable() {
    let events = timers(1, 4);
    let at_two: &[(u64, &[u8])] = &[(2, b"state at 2")];
    let scratch = Scratch::new();
    let (left, right) = (scratch.side("left"), scratch.side("right"));
    let header = header(Capture::Strict, b"m");
    write_with_checkpoints(&left, &header, &events, at_two);
    write_with_checkpoints(&right, &header, &events, at_two);
    for entry in std::fs::read_dir(right.join(CHECKPOINTS)).unwrap() {
        std::fs::remove_file(entry.unwrap().path()).unwrap();
    }
    let report = diff_from_checkpoint(&left, &right, 1);
    assert!(
        matches!(&report, Report::NotComparable { reason } if reason.contains("store is not there")),
        "{report:?}"
    );
}

/// #437 review P2: `--from-checkpoint` recovers with the hold the
/// journal's header records, not the reader's capacity. A best-effort
/// run: event 1, a gap at 2, then events 3 to 8 written while the
/// checkpoint at 2 was, its record after them. Recorded with a hold of 8,
/// the range opens over the six events; with a hold of 2 the run let
/// them go, and so does the diff.
#[test]
fn from_checkpoint_takes_the_recorded_hold() {
    use karyos_archive::group::checkpoint::{CheckpointSlot, CheckpointStore, CheckpointWriter};

    let write = |dir: &Path, hold: u32| {
        let header = JournalHeader {
            reopen_hold: hold,
            ..header(Capture::BestEffort, b"m")
        };
        let config = JournalConfig::new(
            karyos_archive::group::journal::MIN_SEGMENT_LENGTH,
            SyncPolicy::PerSegment,
        );
        let mut journal = GroupJournal::create(StdDisk, dir, &header, config).unwrap();
        let store_dir = dir.join(CHECKPOINTS);
        std::fs::create_dir_all(&store_dir).unwrap();
        let store = CheckpointStore::create(StdDisk, &store_dir, 1, config).unwrap();
        let mut writer = CheckpointWriter::new(store, &journal).unwrap();
        let mut records = timers(1, 1);
        records.push(GroupRecord::Gap(GapMarker {
            from_seq: 2,
            to_seq: 2,
            reason: GapReason::RingFull,
        }));
        records.extend(timers(3, 6));
        let mut out = vec![0u8; MAX_RECORD];
        for record in &records {
            let length = record.encode(&mut out).unwrap();
            let _ = journal.append(&out[..length]).unwrap();
        }
        let mut slot = CheckpointSlot::new(64);
        let request = slot
            .take(2, 1, |buffer| {
                buffer[..5].copy_from_slice(b"state");
                5
            })
            .unwrap();
        let written = writer.write(&mut journal, &request);
        slot.returned(request, &written);
        let _ = written.unwrap();
        let _ = journal.close().unwrap();
    };
    let mut reports = Vec::new();
    for hold in [8, 2] {
        let scratch = Scratch::new();
        let (left, right) = (scratch.side("left"), scratch.side("right"));
        write(&left, hold);
        write(&right, hold);
        reports.push(diff_from_checkpoint(&left, &right, 1));
    }
    assert_eq!(
        reports[0],
        Report::Identical {
            from: 3,
            to: Some(8),
            events: 6
        }
    );
    // The range stays at the checkpoint: nothing after it to compare.
    assert_eq!(
        reports[1],
        Report::Identical {
            from: 3,
            to: None,
            events: 0
        }
    );
}

/// #430 follow-up: a record that names intact store bytes with another
/// crc32c is held by the store, so its digest is what refuses it: the
/// checkpoint is corrupt, not comparable (exit 2), never an error.
#[test]
fn a_record_whose_digest_differs_from_intact_bytes_is_corrupt() {
    let events = timers(1, 4);
    let at_two: &[(u64, &[u8])] = &[(2, b"state at 2")];
    let scratch = Scratch::new();
    let (left, right, source) = (
        scratch.side("left"),
        scratch.side("right"),
        scratch.side("source"),
    );
    let header = header(Capture::Strict, b"m");
    write_with_checkpoints(&left, &header, &events, at_two);
    // The store's bytes, written for a journal whose record is right.
    write_with_checkpoints(&source, &header, &events, at_two);
    let config = JournalConfig::new(MIN_SEGMENT_LENGTH, SyncPolicy::PerSegment);
    let mut journal = GroupJournal::recover(StdDisk, &source, 1, config)
        .unwrap()
        .journal;
    let mut recorded = None;
    let _ = journal
        .walk(0, |_, _, record| {
            if let GroupRecord::Checkpoint(checkpoint) = record {
                recorded = Some(*checkpoint);
            }
            true
        })
        .unwrap();
    drop(journal);
    let recorded = recorded.unwrap();
    // The right journal names the same bytes with another digest.
    let mut records = events.clone();
    let after_two = records
        .iter()
        .position(|record| matches!(record, GroupRecord::End(end) if end.group_seq == 2))
        .unwrap();
    records.insert(
        after_two + 1,
        GroupRecord::Checkpoint(CheckpointRecord {
            crc32c: recorded.crc32c ^ 1,
            ..recorded
        }),
    );
    write(&right, &header, &records);
    std::fs::create_dir_all(right.join(CHECKPOINTS)).unwrap();
    for entry in std::fs::read_dir(source.join(CHECKPOINTS)).unwrap() {
        let path = entry.unwrap().path();
        std::fs::copy(
            &path,
            right.join(CHECKPOINTS).join(path.file_name().unwrap()),
        )
        .unwrap();
    }
    let report = diff_from_checkpoint(&left, &right, 1);
    assert_eq!(report.exit_code(), 2, "{report:?}");
    assert!(report.text().contains("corrupt"), "{}", report.text());
}

/// Writes a best-effort journal of `events` (each `Some(seq)` a timer
/// event, each `None` at `seq` a gap), with a checkpoint after each
/// `group_seq` in `checkpoints`, its record right after that one.
fn write_ranges(dir: &Path, steps: &[(u64, bool)], checkpoints: &[u64]) {
    use karyos_archive::group::checkpoint::{CheckpointSlot, CheckpointStore, CheckpointWriter};

    let header = header(Capture::BestEffort, b"m");
    let config = JournalConfig::new(
        karyos_archive::group::journal::MIN_SEGMENT_LENGTH,
        SyncPolicy::PerSegment,
    );
    let mut journal = GroupJournal::create(StdDisk, dir, &header, config).unwrap();
    let store_dir = dir.join(CHECKPOINTS);
    std::fs::create_dir_all(&store_dir).unwrap();
    let store = CheckpointStore::create(StdDisk, &store_dir, 1, config).unwrap();
    let mut writer = CheckpointWriter::new(store, &journal).unwrap();
    let mut slot = CheckpointSlot::new(64);
    let mut out = vec![0u8; MAX_RECORD];
    for &(seq, event) in steps {
        let records = if event {
            timers(seq, 1)
        } else {
            vec![GroupRecord::Gap(GapMarker {
                from_seq: seq,
                to_seq: seq,
                reason: GapReason::RingFull,
            })]
        };
        for record in &records {
            let length = record.encode(&mut out).unwrap();
            let _ = journal.append(&out[..length]).unwrap();
        }
        if checkpoints.contains(&seq) {
            let request = slot
                .take(seq, 1, |buffer| {
                    buffer[0] = u8::try_from(seq).unwrap();
                    1
                })
                .unwrap();
            let written = writer.write(&mut journal, &request);
            slot.returned(request, &written);
            let _ = written.unwrap();
        }
    }
    let _ = journal.close().unwrap();
}

/// A8 middle ranges: `--from-checkpoint` at a middle range's checkpoint
/// compares that range, to its end before the next gap; an empty middle
/// range, its prefix ending at its checkpoint, compares nothing.
#[test]
fn from_checkpoint_compares_a_middle_range() {
    // 1, gap 2 (checkpoint 1 at 2), 3, 4, gap 5 (checkpoint 2 at 5), 6.
    let steps = [
        (1, true),
        (2, false),
        (3, true),
        (4, true),
        (5, false),
        (6, true),
    ];
    let scratch = Scratch::new();
    let (left, right) = (scratch.side("left"), scratch.side("right"));
    write_ranges(&left, &steps, &[2, 5]);
    write_ranges(&right, &steps, &[2, 5]);
    assert_eq!(
        diff_from_checkpoint(&left, &right, 1),
        Report::Identical {
            from: 3,
            to: Some(4),
            events: 2
        }
    );
    // 1, gap 2 (checkpoint 1 at 2), gap 3 (checkpoint 2 at 3), 4.
    let steps = [(1, true), (2, false), (3, false), (4, true)];
    let scratch = Scratch::new();
    let (left, right) = (scratch.side("left"), scratch.side("right"));
    write_ranges(&left, &steps, &[2, 3]);
    write_ranges(&right, &steps, &[2, 3]);
    let report = diff_from_checkpoint(&left, &right, 1);
    assert!(
        matches!(report, Report::Identical { events: 0, .. }),
        "{report:?}"
    );
}

/// A8 middle ranges, #437 decision: the stop that ends the opened range
/// ends the comparison only when both sides stop there. One side's range
/// ends at a gap where the other's goes on: the `end` kind, at that
/// event.
#[test]
fn a_range_end_on_one_side_only_is_a_difference() {
    let scratch = Scratch::new();
    let (left, right) = (scratch.side("left"), scratch.side("right"));
    // Left: 1, gap 2 (checkpoint 1), 3, 4, gap 5 (checkpoint 2), 6.
    write_ranges(
        &left,
        &[
            (1, true),
            (2, false),
            (3, true),
            (4, true),
            (5, false),
            (6, true),
        ],
        &[2, 5],
    );
    // Right: the same, but event 5 where the left had its gap.
    write_ranges(
        &right,
        &[
            (1, true),
            (2, false),
            (3, true),
            (4, true),
            (5, true),
            (6, true),
        ],
        &[2, 5],
    );
    let report = diff_from_checkpoint(&left, &right, 1);
    assert!(
        matches!(
            report,
            Report::Diverged {
                group_seq: 5,
                kind: Kind::End,
                ..
            }
        ),
        "{report:?}"
    );
}

/// #448 review P2: with `--to` past a middle range's end, the gap that
/// ends it lies inside the range asked for: not comparable (code 2), as
/// section 7 says, even when only one journal stops there (without
/// `--to` that is the `end` kind).
#[test]
fn a_middle_range_gap_before_to_is_not_comparable() {
    let scratch = Scratch::new();
    let (left, right) = (scratch.side("left"), scratch.side("right"));
    write_ranges(
        &left,
        &[
            (1, true),
            (2, false),
            (3, true),
            (4, true),
            (5, false),
            (6, true),
        ],
        &[2, 5],
    );
    write_ranges(
        &right,
        &[
            (1, true),
            (2, false),
            (3, true),
            (4, true),
            (5, true),
            (6, true),
        ],
        &[2, 5],
    );
    let report = diff(&DiffArgs {
        left: Journal {
            dir: left.clone(),
            group: 1,
        },
        right: Journal {
            dir: right.clone(),
            group: 1,
        },
        from: None,
        to: Some(6),
        json: false,
        accept_manifest: false,
        from_checkpoint: Some(1),
    });
    assert_eq!(report.exit_code(), 2, "{report:?}");
    assert!(
        report.text().contains("a gap marker from group_seq 5"),
        "{}",
        report.text()
    );
}

/// `karyos-replay diff` and its alias `karyos-tools replay diff` run the
/// same command (archive-host.md, H5): the same report and exit status for
/// the same journals, help under each name, and an argument error naming
/// the command it came through.
#[test]
fn both_names_run_the_same_diff() {
    let scratch = Scratch::new();
    let (left, right) = (scratch.side("left"), scratch.side("right"));
    let records = recorded();
    write(&left, &header(Capture::Strict, b"m"), &records);
    write(&right, &header(Capture::Strict, b"m"), &records);
    let args = || {
        [
            left.as_os_str().to_owned(),
            OsString::from("1"),
            right.as_os_str().to_owned(),
            OsString::from("1"),
        ]
    };
    let run = |command: &str, args: Vec<OsString>| {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let status = run_diff(command, args, &mut out, &mut err);
        (
            status,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    };
    let replay = run("karyos-replay diff", args().to_vec());
    let alias = run("karyos-tools replay diff", args().to_vec());
    assert_eq!(replay, alias);
    assert_eq!(
        replay,
        (
            0,
            "identical: group_seq 1 to 3, 3 events\n".to_owned(),
            String::new()
        )
    );
    let (status, out, _) = run("karyos-replay diff", vec![OsString::from("--help")]);
    assert_eq!(status, 0);
    assert!(
        out.starts_with("karyos-replay diff: the first difference"),
        "{out}"
    );
    assert!(
        out.contains("Usage: karyos-replay diff <left-dir>"),
        "{out}"
    );
    let (status, out, _) = run("karyos-tools replay diff", vec![OsString::from("-h")]);
    assert_eq!(status, 0);
    assert!(
        out.contains("Usage: karyos-tools replay diff <left-dir>"),
        "{out}"
    );
    let (status, _, err) = run("karyos-replay diff", vec![OsString::from("--bogus")]);
    assert_eq!(status, EXIT_ERROR);
    assert_eq!(
        err,
        "karyos-replay: unknown option --bogus (karyos-replay diff --help for the usage)\n"
    );
}

/// karyos#675: the comparison excludes nothing at compare time, so an
/// exclusion cannot widen unnoticed. A change of any recorded field of the
/// input event diverges as `input event`, the trace extension included (an
/// input recorded with the message, and not excluded in version 1); a
/// change of any recorded field of an observation diverges at it, as
/// `output intent` when an offer's length and digest differ and as
/// `observation` otherwise. The excluded metadata of recording-group-
/// records.md (the `&'static str` reasons, error detail below one level)
/// has no field in a version 1 record, so it cannot make two journals
/// differ.
#[test]
fn test_replay_diff_every_recorded_field_diverges_and_nothing_is_excluded() {
    static EXTENSION: [u8; 64] = [7; 64];
    let input = |change: fn(&mut MessageEvent<'static>)| {
        let mut records = recorded();
        let GroupRecord::Message(event) = &mut records[0] else {
            panic!("the first record is a message");
        };
        change(event);
        records
    };
    let inputs: [(&str, Vec<GroupRecord<'static>>); 11] = [
        ("logical_time", input(|e| e.logical_time += 1)),
        ("incarnation", input(|e| e.incarnation += 1)),
        ("position", input(|e| e.position += 32)),
        ("extent", input(|e| e.extent += 32)),
        ("stream_id", input(|e| e.stream_id += 1)),
        ("session_id", input(|e| e.session_id += 1)),
        ("lane", input(|e| e.lane = Lane::try_new(1).unwrap())),
        ("reserved_value", input(|e| e.reserved_value += 1)),
        ("end_of_stream", input(|e| e.end_of_stream = true)),
        ("payload", input(|e| e.payload = Payload::Inline(b"z"))),
        ("extension", input(|e| e.extension = Some(&EXTENSION))),
    ];
    for (field, right) in inputs {
        let report = run(&recorded(), &right, |_| {});
        assert!(
            matches!(
                report,
                Report::Diverged {
                    group_seq: 1,
                    index: None,
                    kind: Kind::InputEvent,
                    ..
                }
            ),
            "{field}: {report:?}"
        );
    }
    let observation = |change: fn(&mut OutcomeObservation)| {
        let mut records = recorded();
        let GroupRecord::Outcome(outcome) = &mut records[1] else {
            panic!("the second record is an offer");
        };
        change(outcome);
        records
    };
    let observations: [(&str, Vec<GroupRecord<'static>>, Kind); 6] = [
        (
            "stream_id",
            observation(|o| o.stream_id += 1),
            Kind::Observation,
        ),
        (
            "session_id",
            observation(|o| o.session_id += 1),
            Kind::Observation,
        ),
        (
            "operation",
            observation(|o| o.operation = Operation::Commit),
            Kind::Observation,
        ),
        (
            "outcome",
            observation(|o| {
                o.outcome = Outcome::Accepted {
                    lane: Lane::ZERO,
                    position: 64,
                };
            }),
            Kind::Observation,
        ),
        ("length", observation(|o| o.length += 1), Kind::OutputIntent),
        ("crc32c", observation(|o| o.crc32c ^= 1), Kind::OutputIntent),
    ];
    for (field, right, kind) in observations {
        let report = run(&recorded(), &right, |_| {});
        let Report::Diverged {
            group_seq,
            index,
            kind: found,
            ..
        } = &report
        else {
            panic!("{field}: {report:?}");
        };
        assert_eq!((*group_seq, *index, *found), (1, Some(0), kind), "{field}");
    }
}

/// karyos#675: with several differences, the first is the one reported:
/// the lowest `group_seq` across events, and within an event the lowest
/// observation index.
#[test]
fn test_replay_diff_of_several_differences_reports_the_first() {
    // Event 1's offer and event 2's schedule both differ: event 1's.
    let mut right = recorded();
    right[1] = offer(1, 0, b"out 2");
    right[4] = schedule(2, 0, 101);
    let report = run(&recorded(), &right, |_| {});
    assert!(
        matches!(
            report,
            Report::Diverged {
                group_seq: 1,
                index: Some(0),
                kind: Kind::OutputIntent,
                ..
            }
        ),
        "{report:?}"
    );
    // Event 2's schedule and event 3's input both differ: event 2's.
    let mut right = recorded();
    right[4] = schedule(2, 0, 101);
    right[6] = message(3, Payload::Inline(b"d"));
    let report = run(&recorded(), &right, |_| {});
    assert!(
        matches!(
            report,
            Report::Diverged {
                group_seq: 2,
                index: Some(0),
                kind: Kind::Observation,
                ..
            }
        ),
        "{report:?}"
    );
    // One event with two offers, both different: the first offer's.
    let two = |first: &'static [u8], second: &'static [u8]| {
        vec![
            message(1, Payload::Inline(b"a")),
            offer(1, 0, first),
            offer(1, 1, second),
            end(1, 2, EndOutcome::Complete),
        ]
    };
    let report = run(&two(b"x", b"y"), &two(b"x2", b"y2"), |_| {});
    assert!(
        matches!(
            report,
            Report::Diverged {
                group_seq: 1,
                index: Some(0),
                kind: Kind::OutputIntent,
                ..
            }
        ),
        "{report:?}"
    );
    // Only the second differs: its index is reported.
    let report = run(&two(b"x", b"y"), &two(b"x", b"y2"), |_| {});
    assert!(
        matches!(
            report,
            Report::Diverged {
                group_seq: 1,
                index: Some(1),
                kind: Kind::OutputIntent,
                ..
            }
        ),
        "{report:?}"
    );
}

/// karyos#919 review P2: an event on one side only whose reference is
/// unavailable makes the range not comparable, as it does in a pair,
/// never a divergence at the end.
#[test]
fn a_one_sided_event_with_an_unavailable_reference_is_not_comparable() {
    use karyos_archive::group::record::ReferenceUnavailable;

    let effort = header(Capture::BestEffort, b"m");
    let shared = [
        message(1, Payload::Inline(b"a")),
        end(1, 0, EndOutcome::Complete),
    ];
    let mut longer = shared.to_vec();
    longer.extend([
        message(
            2,
            Payload::Reference {
                recording_id: 8,
                length: 10,
            },
        ),
        end(2, 0, EndOutcome::Complete),
        GroupRecord::Unavailable(ReferenceUnavailable {
            group_seq: 2,
            recording_id: 8,
        }),
    ]);
    for (left, right) in [(&longer[..], &shared[..]), (&shared[..], &longer[..])] {
        let report = run_with((&effort, left), (&effort, right), |_| {});
        assert_eq!(report.exit_code(), 2, "{report:?}");
        assert!(
            report.text().contains("reference is unavailable"),
            "{}",
            report.text()
        );
    }
}
