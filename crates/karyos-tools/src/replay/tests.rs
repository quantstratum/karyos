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
use karyos_archive::group::journal::MIN_SEGMENT_LENGTH;
use karyos_archive::group::record::{
    CONTRACT_VERSION, Capture, Clock, EndOutcome, EventEnd, GapMarker, GapReason, JournalHeader,
    MAX_RECORD, MessageEvent, Outcome, OutcomeObservation, Payload, TimerAction, TimerEvent,
    TimerObservation,
};
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
        manifest,
    }
}

fn write(dir: &Path, header: &JournalHeader<'_>, records: &[GroupRecord<'_>]) {
    let config = JournalConfig {
        segment_length: MIN_SEGMENT_LENGTH,
        policy: SyncPolicy::PerSegment,
    };
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

    let config = JournalConfig {
        segment_length: karyos_archive::group::journal::MIN_SEGMENT_LENGTH,
        policy: SyncPolicy::PerSegment,
    };
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
