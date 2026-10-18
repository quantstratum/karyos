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
