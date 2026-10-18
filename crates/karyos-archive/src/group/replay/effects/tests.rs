// SPDX-License-Identifier: Apache-2.0

// The per-call checks of replay: a handler that repeats its recorded calls
// gets the recorded results and nothing is performed; one that changes an
// output byte, a call's arguments, or the number of its calls diverges at
// that observation.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::path::Path;

use karyos_sys::frame::Lane;

use super::*;
use crate::fault::{FaultDisk, Survives};
use crate::group::gateway::ClaimCommit;
use crate::group::journal::{GroupJournal, JournalConfig, MIN_SEGMENT_LENGTH};
use crate::group::prefix::{Coverage, recover};
use crate::group::record::{
    CONTRACT_VERSION, Capture, Clock, EndOutcome, EventEnd, ExternalObservation, JournalHeader,
    MAX_RECORD, TimerEvent,
};
use crate::group::replay::{CursorConfig, ReplayConfig, ReplayCursor, Step};
use crate::segment::SyncPolicy;

const CONFIG: JournalConfig = JournalConfig {
    segment_length: MIN_SEGMENT_LENGTH,
    policy: SyncPolicy::PerSegment,
};
/// Publication 0 is stream 20, session 5; publication 1 is stream 21.
const PUBLICATIONS: [(i32, i32); 2] = [(20, 5), (21, 5)];
const SEQ: u64 = 1;
const TIME: u64 = 777;
const PAYLOAD: &[u8] = b"order 42";
const CLAIMED: &[u8] = b"claimed bytes";
const LANE: Lane = Lane::ZERO;

struct Nothing;

impl Coverage for Nothing {
    fn positions(&self, _recording_id: u64) -> Option<(u64, u64)> {
        None
    }

    fn ended(&self, _recording_id: u64) -> Option<u64> {
        None
    }
}

fn header() -> JournalHeader<'static> {
    JournalHeader {
        group_id: 1,
        first_group_seq: SEQ,
        inline_threshold: 4096,
        contract_version: CONTRACT_VERSION,
        clock: Clock::HostMonotonic,
        capture: Capture::Strict,
        manifest: b"m",
    }
}

fn outcome(
    index: u32,
    operation: Operation,
    outcome: Outcome,
    intent: &[u8],
) -> GroupRecord<'static> {
    let (length, crc32c) = match operation {
        Operation::Claim => (0, 0),
        _ => digest(intent),
    };
    GroupRecord::Outcome(OutcomeObservation {
        group_seq: SEQ,
        index,
        stream_id: 20,
        session_id: 5,
        operation,
        outcome,
        length,
        crc32c,
    })
}

fn accepted(position: u64) -> Outcome {
    Outcome::Accepted {
        lane: LANE,
        position,
    }
}

fn delivery_record(index: u32, start: u64) -> GroupRecord<'static> {
    GroupRecord::Delivery(DeliveryObservation {
        group_seq: SEQ,
        index,
        stream_id: 20,
        session_id: 5,
        kind: 1,
        lane: LANE,
        receiver: 0,
        incarnation: 1,
        start,
        end: start + 64,
        epoch: 1,
        reason: 0,
        lost: 0,
    })
}

/// Every kind of observation, in this order: an offer, a claim and its
/// commit, a delivery poll of two, a schedule, a cancel, an external
/// value.
fn observations() -> Vec<GroupRecord<'static>> {
    vec![
        outcome(0, Operation::Offer, accepted(0), PAYLOAD),
        outcome(1, Operation::Claim, accepted(64), &[]),
        outcome(2, Operation::Commit, accepted(64), CLAIMED),
        GroupRecord::Poll(DeliveryPoll {
            group_seq: SEQ,
            index: 3,
            max: 8,
            count: 2,
            stream_id: 20,
            session_id: 5,
        }),
        delivery_record(4, 0),
        delivery_record(5, 64),
        GroupRecord::TimerOperation(TimerObservation {
            group_seq: SEQ,
            index: 6,
            timer_id: 3,
            deadline: 1000,
            action: TimerAction::Create,
        }),
        GroupRecord::TimerOperation(TimerObservation {
            group_seq: SEQ,
            index: 7,
            timer_id: 3,
            deadline: 1000,
            action: TimerAction::Cancel,
        }),
        GroupRecord::ExternalObservation(ExternalObservation {
            group_seq: SEQ,
            index: 8,
            kind: 9,
            value: b"quote",
        }),
    ]
}

fn encode(record: &GroupRecord<'_>) -> Vec<u8> {
    let mut out = vec![0u8; MAX_RECORD];
    let length = record.encode(&mut out).unwrap();
    out.truncate(length);
    out
}

/// A cursor over one timer event with `observations`.
fn cursor(observations: &[GroupRecord<'_>]) -> ReplayCursor<FaultDisk> {
    let disk = FaultDisk::default();
    let mut journal =
        GroupJournal::create(disk.clone(), Path::new("/g"), &header(), CONFIG).unwrap();
    let mut records = vec![GroupRecord::Timer(TimerEvent {
        group_seq: SEQ,
        logical_time: TIME,
        timer_id: 1,
    })];
    records.extend_from_slice(observations);
    records.push(GroupRecord::End(EventEnd {
        group_seq: SEQ,
        observations: u32::try_from(observations.len()).unwrap(),
        outcome: EndOutcome::Complete,
    }));
    for record in &records {
        journal.append(&encode(record)).unwrap();
    }
    journal.close().unwrap();
    let mut journal = GroupJournal::recover(
        disk.after_crash(Survives::Synced),
        Path::new("/g"),
        1,
        CONFIG,
    )
    .unwrap()
    .journal;
    let recovery = recover(&mut journal, &Nothing, 8).unwrap();
    let expected = ReplayConfig {
        manifest: b"m",
        accept_manifest: false,
    };
    let room = CursorConfig {
        bytes: 16 * 256,
        records: 16,
    };
    ReplayCursor::open(journal, &recovery, &expected, room).unwrap()
}

/// Replays the one event of `observations` through `handler`; returns
/// how it ended.
fn replay(
    observations: &[GroupRecord<'_>],
    handler: impl FnOnce(&mut ReplayEffects<'_, '_>),
) -> Result<(), Divergence> {
    let mut cursor = cursor(observations);
    let Step::Event(event) = cursor.step().unwrap() else {
        panic!("no event");
    };
    let mut scratch = [0u8; 64];
    let mut effects = ReplayEffects::new(event, &PUBLICATIONS, &mut scratch).unwrap();
    handler(&mut effects);
    effects.finish()
}

/// The recorded calls, as the handler makes them, with the claim's bytes
/// `claimed`.
fn handler(effects: &mut ReplayEffects<'_, '_>) {
    let (payload, claimed) = (PAYLOAD, CLAIMED);
    assert_eq!(effects.offer(PublicationId(0), payload), accepted(0));
    let committed = effects.claim(PublicationId(0), claimed.len(), &mut |bytes| {
        bytes.copy_from_slice(claimed);
        true
    });
    assert_eq!(
        committed,
        ClaimCommit {
            claim: accepted(64),
            commit: Some(accepted(64)),
        }
    );
    let mut seen = Vec::new();
    assert_eq!(
        effects.poll_outcomes(PublicationId(0), 8, &mut |outcome| seen.push(outcome.start)),
        2
    );
    assert_eq!(seen, [0, 64]);
    effects.schedule(TimerId(3), 1000);
    effects.cancel(TimerId(3));
    let value = effects.external(9, &mut |_| panic!("read runs under replay"));
    assert_eq!(value, b"quote");
}

#[test]
fn the_recorded_calls_get_the_recorded_results() {
    let recorded = observations();
    assert_eq!(
        replay(&recorded, |effects| {
            assert_eq!((effects.clock(), effects.clock()), (TIME, TIME));
            handler(effects);
            assert_eq!(effects.clock(), TIME);
        }),
        Ok(())
    );
}

#[test]
fn an_output_byte_changed_diverges_at_its_intent() {
    let recorded = observations();
    let divergence = replay(&recorded, |effects| {
        let _ = effects.offer(PublicationId(0), b"order 43");
    })
    .unwrap_err();
    assert_eq!((divergence.group_seq, divergence.index), (SEQ, 0));
    assert!(matches!(
        divergence.kind,
        DivergenceKind::Call {
            found: Call::Offer { length: 8, .. },
            expected: Recorded::Outcome {
                operation: Operation::Offer,
                length: 8,
                ..
            },
        }
    ));
    let gateway: gateway::Divergence = divergence.into();
    assert_eq!(
        (gateway.index, gateway.expected, gateway.found),
        (0, 11, 11)
    );
    // A claim's bytes are checked at its commit.
    let divergence = replay(&recorded, |effects| {
        let _ = effects.offer(PublicationId(0), PAYLOAD);
        let committed = effects.claim(PublicationId(0), CLAIMED.len(), &mut |bytes| {
            bytes.copy_from_slice(b"claimed bytez");
            true
        });
        assert_eq!(committed.commit, Some(Outcome::Gated));
    })
    .unwrap_err();
    assert_eq!(divergence.index, 2);
    assert!(matches!(
        divergence.kind,
        DivergenceKind::Call {
            found: Call::Commit { .. },
            ..
        }
    ));
}

/// After the divergence nothing more is checked: the later calls get
/// neutral answers and the first divergence stays.
#[test]
fn the_first_divergence_stays() {
    let recorded = observations();
    let divergence = replay(&recorded, |effects| {
        let _ = effects.offer(PublicationId(1), PAYLOAD);
        assert_eq!(effects.offer(PublicationId(0), PAYLOAD), Outcome::Gated);
        assert!(effects.external(9, &mut |_| panic!("never run")).is_empty());
    })
    .unwrap_err();
    assert_eq!(divergence.index, 0);
    assert!(matches!(
        divergence.kind,
        DivergenceKind::Call {
            found: Call::Offer {
                publication: PublicationId(1),
                ..
            },
            ..
        }
    ));
}

#[test]
fn an_extra_or_a_missing_call_diverges() {
    let recorded = observations();
    let extra = replay(&recorded[..1], |effects| {
        let _ = effects.offer(PublicationId(0), PAYLOAD);
        effects.schedule(TimerId(3), 1000);
    })
    .unwrap_err();
    assert_eq!(extra.index, 1);
    assert!(matches!(
        extra.kind,
        DivergenceKind::Extra {
            found: Call::Schedule { .. }
        }
    ));
    let missing = replay(&recorded[..1], |_| {}).unwrap_err();
    assert_eq!(missing.index, 0);
    assert!(matches!(
        missing.kind,
        DivergenceKind::Missing {
            expected: Recorded::Outcome { .. }
        }
    ));
    let gateway: gateway::Divergence = missing.into();
    assert_eq!((gateway.expected, gateway.found), (11, 0));
}

#[test]
fn a_call_of_another_kind_or_other_arguments_diverges() {
    let recorded = observations();
    // The recorded poll's max is 8.
    let poll = replay(&recorded, |effects| {
        let _ = effects.offer(PublicationId(0), PAYLOAD);
        let _ = effects.claim(PublicationId(0), CLAIMED.len(), &mut |bytes| {
            bytes.copy_from_slice(CLAIMED);
            true
        });
        let _ = effects.poll_outcomes(PublicationId(0), 4, &mut |_| panic!("presented"));
    })
    .unwrap_err();
    assert_eq!(poll.index, 3);
    // A timer of another deadline.
    let timers = [GroupRecord::TimerOperation(TimerObservation {
        group_seq: SEQ,
        index: 0,
        timer_id: 3,
        deadline: 1000,
        action: TimerAction::Create,
    })];
    let timer = replay(&timers, |effects| effects.schedule(TimerId(3), 1001)).unwrap_err();
    assert!(matches!(
        timer.kind,
        DivergenceKind::Call {
            found: Call::Schedule { deadline: 1001, .. },
            expected: Recorded::Timer { deadline: 1000, .. },
        }
    ));
    // A cancel where a create was recorded.
    let cancel = replay(&timers, |effects| effects.cancel(TimerId(3))).unwrap_err();
    assert!(matches!(
        cancel.kind,
        DivergenceKind::Call {
            found: Call::Cancel { .. },
            ..
        }
    ));
    // An external value of another kind: its read never runs.
    let values = [GroupRecord::ExternalObservation(ExternalObservation {
        group_seq: SEQ,
        index: 0,
        kind: 9,
        value: b"quote",
    })];
    let external = replay(&values, |effects| {
        assert!(
            effects
                .external(10, &mut |_| panic!("read runs under replay"))
                .is_empty()
        );
    })
    .unwrap_err();
    assert!(matches!(
        external.kind,
        DivergenceKind::Call {
            found: Call::External { kind: 10 },
            expected: Recorded::External { kind: 9 },
        }
    ));
}

/// A claim longer than the scratch claim diverges; a refused claim is
/// returned as recorded and hands out nothing.
#[test]
fn claims_follow_the_record_and_the_scratch() {
    let long = [outcome(0, Operation::Claim, accepted(0), &[])];
    let divergence = replay(&long, |effects| {
        let committed = effects.claim(PublicationId(0), 65, &mut |_| panic!("written"));
        assert_eq!(
            committed,
            ClaimCommit {
                claim: Outcome::Gated,
                commit: None
            }
        );
    })
    .unwrap_err();
    assert_eq!(divergence.index, 0);
    let refused = [outcome(0, Operation::Claim, Outcome::BackPressured, &[])];
    assert_eq!(
        replay(&refused, |effects| {
            let committed = effects.claim(PublicationId(0), 8, &mut |_| panic!("written"));
            assert_eq!(
                committed,
                ClaimCommit {
                    claim: Outcome::BackPressured,
                    commit: None
                }
            );
        }),
        Ok(())
    );
}

/// An abort (`write` returns false) is checked against a recorded aborted
/// commit, with the bytes as written; aborting where a commit was
/// recorded diverges.
#[test]
fn an_abort_is_checked_as_an_aborted_commit() {
    let aborted = Outcome::Aborted {
        lane: LANE,
        position: 64,
    };
    let records = [
        outcome(0, Operation::Claim, accepted(64), &[]),
        outcome(1, Operation::Commit, aborted, b"half"),
    ];
    assert_eq!(
        replay(&records, |effects| {
            let committed = effects.claim(PublicationId(0), 4, &mut |bytes| {
                bytes.copy_from_slice(b"half");
                false
            });
            assert_eq!(committed.commit, Some(aborted));
        }),
        Ok(())
    );
    let committed = [
        outcome(0, Operation::Claim, accepted(64), &[]),
        outcome(1, Operation::Commit, accepted(64), b"half"),
    ];
    let divergence = replay(&committed, |effects| {
        let _ = effects.claim(PublicationId(0), 4, &mut |bytes| {
            bytes.copy_from_slice(b"half");
            false
        });
    })
    .unwrap_err();
    assert!(matches!(
        divergence.kind,
        DivergenceKind::Call {
            found: Call::Commit { aborted: true, .. },
            ..
        }
    ));
}
