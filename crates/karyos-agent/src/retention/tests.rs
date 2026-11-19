// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::*;
use crate::journal::{GapReason, Journal};

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("karyos-retention-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// What the Archive saw, shared with the test.
#[derive(Debug, Default)]
struct Seen {
    sent: Vec<&'static str>,
    held: Vec<u64>,
}

/// An Archive that records what it was sent and holds recordings.
#[derive(Debug, Default, Clone)]
struct Archive {
    seen: Arc<Mutex<Seen>>,
    silent: bool,
    slow: Option<Duration>,
}

impl Archive {
    fn sent(&self) -> Vec<&'static str> {
        self.seen.lock().unwrap().sent.clone()
    }

    fn held(&self) -> Vec<u64> {
        self.seen.lock().unwrap().held.clone()
    }
}

/// The Archive's refusal code for a purge under hold, as it names it.
const LEGAL_HOLD: u64 = 2;

impl RetentionBackend for Archive {
    fn hold(&mut self, recording: u64, _: u64, _: u32) -> RetentionReply {
        let mut seen = self.seen.lock().unwrap();
        seen.sent.push("hold");
        seen.held.push(recording);
        RetentionReply::Done { evidenced: true }
    }

    fn release(&mut self, recording: u64, _: u64, _: u32) -> RetentionReply {
        let mut seen = self.seen.lock().unwrap();
        seen.sent.push("release");
        seen.held.retain(|held| *held != recording);
        RetentionReply::Done { evidenced: true }
    }

    fn purge(&mut self, recording: u64, _: u64, _: u64, _: u32) -> RetentionReply {
        let mut seen = self.seen.lock().unwrap();
        seen.sent.push("purge");
        if self.silent {
            return RetentionReply::NoAnswer;
        }
        if seen.held.contains(&recording) {
            return RetentionReply::Refused {
                code: LEGAL_HOLD,
                reason: "legal_hold".to_owned(),
            };
        }
        RetentionReply::Done { evidenced: true }
    }

    fn verify(&mut self, _: u64) -> Option<Vec<RangeOutcome>> {
        self.seen.lock().unwrap().sent.push("verify");
        if let Some(slow) = self.slow {
            std::thread::sleep(slow);
        }
        Some(vec![RangeOutcome {
            start: 0,
            end: 64,
            outcome: "inconsistent".to_owned(),
            reasons: vec!["untrusted_evidence".to_owned()],
        }])
    }
}

fn command(operation: Operation, id: u64) -> Command<'static> {
    Command {
        operation,
        recording: 7,
        id,
        operator: 1000,
        relay: 0,
        reason: b"case 12",
    }
}

fn run(
    journal: Option<&mut Journal>,
    archive: &mut Archive,
    command: &Command<'_>,
) -> RetentionAnswer {
    let backend = shared(Box::new(archive.clone()));
    let mut time = 100;
    retention_command(
        journal,
        Some(&backend),
        command,
        Duration::from_secs(5),
        || {
            time += 1;
            time
        },
    )
}

#[test]
fn a_hold_applies_while_the_journal_is_unavailable() {
    let dir = dir("hold-down");
    let mut journal = Journal::open(&dir, 10).unwrap();
    journal.break_recorder();
    let mut archive = Archive::default();
    let answer = run(
        Some(&mut journal),
        &mut archive,
        &command(Operation::Hold, 1),
    );
    assert_eq!(
        answer,
        RetentionAnswer::Done {
            operation: 1,
            evidenced: true
        }
    );
    assert_eq!(archive.held(), vec![7]);
    // With no journal at all, too.
    let answer = run(None, &mut archive, &command(Operation::Hold, 2));
    assert!(matches!(answer, RetentionAnswer::Done { .. }));
}

#[test]
fn a_release_refuses_while_the_journal_is_unavailable() {
    let dir = dir("release-down");
    let mut journal = Journal::open(&dir, 10).unwrap();
    journal.break_recorder();
    let mut archive = Archive::default();
    archive.seen.lock().unwrap().held.push(7);
    let answer = run(
        Some(&mut journal),
        &mut archive,
        &command(Operation::Release, 1),
    );
    assert_eq!(answer, RetentionAnswer::JournalUnavailable);
    assert!(archive.sent().is_empty(), "nothing was sent");
    assert_eq!(archive.held(), vec![7]);
    let answer = run(None, &mut archive, &command(Operation::Release, 2));
    assert_eq!(answer, RetentionAnswer::JournalUnavailable);
}

#[test]
fn a_purge_refuses_while_the_journal_is_unavailable() {
    let dir = dir("purge-down");
    let mut journal = Journal::open(&dir, 10).unwrap();
    journal.break_recorder();
    let mut archive = Archive::default();
    let answer = run(
        Some(&mut journal),
        &mut archive,
        &command(Operation::Purge { before: 4096 }, 1),
    );
    assert_eq!(answer, RetentionAnswer::JournalUnavailable);
    assert!(archive.sent().is_empty(), "nothing was sent");
}

#[test]
fn a_purge_under_a_legal_hold_is_refused_and_journalled() {
    let dir = dir("purge-held");
    let mut journal = Journal::open(&dir, 10).unwrap();
    let mut archive = Archive::default();
    let _ = run(
        Some(&mut journal),
        &mut archive,
        &command(Operation::Hold, 1),
    );
    let answer = run(
        Some(&mut journal),
        &mut archive,
        &command(Operation::Purge { before: 4096 }, 2),
    );
    assert_eq!(
        answer,
        RetentionAnswer::Refused {
            operation: 2,
            code: LEGAL_HOLD,
            reason: "legal_hold".to_owned()
        }
    );
    journal.stop(200).unwrap();
    drop(journal);
    let records = Journal::open(&dir, 300).unwrap().scanned;
    let kinds: Vec<Kind> = records.iter().map(|record| record.kind).collect();
    assert!(kinds.contains(&Kind::HoldRequest));
    assert!(kinds.contains(&Kind::HoldOutcome));
    let request = records
        .iter()
        .find(|record| record.kind == Kind::PurgeRequest)
        .unwrap();
    assert_eq!(
        (request.guard, request.expected, request.operator),
        (7, 4096, 1000)
    );
    assert_eq!(request.reason, b"case 12");
    assert_ne!(request.parameters, 0);
    let outcome = records
        .iter()
        .find(|record| record.kind == Kind::PurgeOutcome)
        .unwrap();
    assert_eq!(outcome.code, LEGAL_HOLD);
}

#[test]
fn an_unanswered_purge_leaves_an_unknown_interval() {
    let dir = dir("purge-silent");
    let mut journal = Journal::open(&dir, 10).unwrap();
    let mut archive = Archive {
        silent: true,
        ..Archive::default()
    };
    // The agent dies after the durable request, before any outcome.
    let record = command(Operation::Purge { before: 64 }, 1).record(Kind::PurgeRequest, 20);
    journal.append_durable(&record, 20).unwrap();
    drop(journal);
    let journal = Journal::open(&dir, 50).unwrap();
    assert_eq!(
        journal.gap().map(|gap| gap.reason),
        Some(GapReason::RequestWithoutOutcome)
    );
    drop(journal);
    let mut journal = Journal::open(&dir, 60).unwrap();
    let answer = run(
        Some(&mut journal),
        &mut archive,
        &command(Operation::Purge { before: 64 }, 2),
    );
    assert_eq!(answer, RetentionAnswer::NoAnswer { operation: 2 });
}

#[test]
fn a_verification_reports_the_archives_outcomes_verbatim() {
    let mut archive = Archive::default();
    let answer = run(None, &mut archive, &command(Operation::Verify, 3));
    let RetentionAnswer::Verified { operation, ranges } = answer else {
        panic!("verified: {answer:?}");
    };
    assert_eq!(operation, 3);
    assert_eq!(ranges[0].outcome, "inconsistent");
    assert_eq!(ranges[0].reasons, vec!["untrusted_evidence".to_owned()]);
}

#[test]
fn without_an_archive_nothing_is_journalled_or_sent() {
    let dir = dir("no-archive");
    let mut journal = Journal::open(&dir, 10).unwrap();
    let answer = retention_command(
        Some(&mut journal),
        None,
        &command(Operation::Hold, 1),
        Duration::from_secs(1),
        || 0,
    );
    assert_eq!(answer, RetentionAnswer::NoArchive);
}

/// A slow verification is waited for at most its bound: it answers no
/// answer, and the call still running makes the next one busy.
#[test]
fn a_slow_archive_is_waited_for_at_most_the_bound() {
    let archive = Archive {
        slow: Some(Duration::from_millis(500)),
        ..Archive::default()
    };
    let backend = shared(Box::new(archive));
    let started = Instant::now();
    let answer = retention_command(
        None,
        Some(&backend),
        &command(Operation::Verify, 1),
        Duration::from_millis(20),
        || 0,
    );
    assert_eq!(answer, RetentionAnswer::NoAnswer { operation: 1 });
    assert!(started.elapsed() < Duration::from_millis(400));
    let answer = retention_command(
        None,
        Some(&backend),
        &command(Operation::Hold, 2),
        Duration::from_millis(20),
        || 0,
    );
    assert_eq!(answer, RetentionAnswer::Busy);
}

/// A relayed operation journals its operator and its relay apart.
#[test]
fn a_relayed_operation_journals_the_relay_apart() {
    let dir = dir("relayed");
    let mut journal = Journal::open(&dir, 10).unwrap();
    let mut archive = Archive::default();
    let relayed = Command {
        relay: 77,
        ..command(Operation::Hold, 1)
    };
    let _ = run(Some(&mut journal), &mut archive, &relayed);
    journal.stop(200).unwrap();
    drop(journal);
    let records = Journal::open(&dir, 300).unwrap().scanned;
    let request = records
        .iter()
        .find(|record| record.kind == Kind::HoldRequest)
        .unwrap();
    assert_eq!((request.operator, request.relay), (1000, 77));
    let outcome = records
        .iter()
        .find(|record| record.kind == Kind::HoldOutcome)
        .unwrap();
    assert_eq!(outcome.relay, 77);
}
