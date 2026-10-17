// SPDX-License-Identifier: Apache-2.0

//! The repair path over the scripted `SocketOps`: what a NAK makes it send.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use karyos_io::backend::{InstanceId, TxReport};
use karyos_io::sockets::endpoint::{Retired, SocketsConfig, SocketsEndpoint, SocketsRx, SocketsTx};
use karyos_io::sockets::ops::SendResult;
use karyos_io::sockets::scripted::ScriptedSocket;
use karyos_protocol::frame::Lane;
use karyos_protocol::network::{
    Alias, Identity, Nak, NakRange, NakReplyReason, Receiver, TermParams,
};
use karyos_sys::log_buffer::AppendOptions;

use super::super::EndpointId;
use super::super::data::Outbound;
use super::super::data::testing::{TestLog, outbound};
use super::{NakOutcome, RepairConfig};
use crate::repair::admission::Requester;
use crate::repair::scheduler::RepairBudget;

/// The aligned length of one 1000-byte message's frame.
const FRAME: u64 = 1056;

const BUDGET: karyos_protocol::lanes::drr::Budget = karyos_protocol::lanes::drr::Budget {
    work: 64,
    bytes: 1 << 20,
};

fn identity() -> Identity {
    Identity {
        driver_id: [1, 2],
        registration_id: 1,
        incarnation: 1,
    }
}

fn alias() -> Alias {
    Alias {
        session_id: 5,
        stream_id: 6,
    }
}

/// A member at the start of the stream with a large window.
const MEMBER: Requester = Requester::Member {
    join: 0,
    consumption: 0,
    window: 1 << 20,
};

/// A reliable one-lane publication with its repair path, over a socket
/// that sends everything and records every datagram.
struct Rig {
    tx: SocketsTx<ScriptedSocket>,
    rx: SocketsRx<ScriptedSocket>,
    observer: ScriptedSocket,
    path: Box<Outbound>,
    log: TestLog,
    sent: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl Rig {
    fn new(config: &RepairConfig) -> Self {
        let socket = ScriptedSocket::new();
        let observer = socket.observer();
        let sent = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&sent);
        observer.set_send_hook(Box::new(move |_, datagrams| {
            for datagram in datagrams {
                record.lock().unwrap().push(datagram.to_vec());
            }
        }));
        let rig_socket = observer.observer();
        let local = SocketsConfig::new(SocketAddr::from(([127, 0, 0, 1], 0)));
        let endpoint = SocketsEndpoint::open(&local, InstanceId::FIRST, socket).unwrap();
        let (tx, rx) = endpoint.split().unwrap();
        let term = TermParams {
            term_length: 65_536,
            initial_term_id: 9,
            mtu: 1408,
        };
        let destination = SocketAddr::from(([127, 0, 0, 1], 41_000));
        let (mut path, log) = outbound(EndpointId(1), alias(), destination, term, 1, true);
        path.enable_repair(config, term.term_length, identity())
            .unwrap();
        Self {
            tx,
            rx,
            observer: rig_socket,
            path,
            log,
            sent,
        }
    }

    /// Appends `count` 1000-byte messages and sends them all.
    fn publish(&mut self, count: u8) {
        for i in 0..count {
            let _ = self.log.publications[0]
                .append(&[i; 1000], AppendOptions::default())
                .unwrap();
        }
        self.scripted(usize::from(count));
        let _ = self.path.serve(&mut self.tx, BUDGET, None, 0).unwrap();
    }

    /// Scripts `count` sends that the kernel takes.
    fn scripted(&self, count: usize) {
        for _ in 0..count {
            self.observer.push_send(SendResult::Sent {
                sent: 1,
                error: None,
            });
        }
    }

    fn nak(&mut self, start: u64, length: u32, now: u64) -> NakOutcome {
        let nak = Nak {
            alias: alias(),
            identity: identity(),
            receiver: Receiver {
                receiver_boot_id: [7, 8],
                receiver_id: 1,
            },
            range: NakRange {
                lane: Lane::ZERO,
                length,
                start,
            },
        };
        self.path.nak(&nak, MEMBER, now)
    }

    fn repair(&mut self, budget: &mut RepairBudget, now: u64) -> u32 {
        self.path.serve_repair(&mut self.tx, budget, now)
    }

    fn datagrams(&self) -> Vec<Vec<u8>> {
        self.sent.lock().unwrap().clone()
    }

    /// Retires the endpoint, returning what it still holds.
    fn finish(self) {
        drop(self.log);
        let mut endpoint = SocketsEndpoint::join(self.tx, self.rx).ok().unwrap();
        let mut report = TxReport::new();
        while !matches!(endpoint.retire(&mut report), Retired::Complete { .. }) {
            while report.pop_front().is_some() {}
        }
    }
}

/// A NAK for submitted frames sends each of them again, byte for byte,
/// on the publication's route; the job then lingers, so an exact duplicate
/// sends nothing.
#[test]
fn a_nak_resends_the_frames_it_names() {
    let mut rig = Rig::new(&RepairConfig::default());
    rig.publish(4);
    let first = rig.datagrams();
    assert_eq!(first.len(), 4);
    assert_eq!(rig.nak(FRAME, 2 * 1056, 1), NakOutcome::Queued);
    rig.scripted(2);
    let mut budget = RepairBudget::default();
    assert_eq!(rig.repair(&mut budget, 2), 2);
    let all = rig.datagrams();
    assert_eq!(&all[4..], &first[1..3]);
    assert_eq!(budget.bytes, RepairBudget::default().bytes - 2 * FRAME);
    assert!(budget.loads < RepairBudget::default().loads);
    assert_eq!(rig.path.repair().unwrap().counts().submitted, 2);
    // Within the linger: dropped, nothing sent.
    assert_eq!(rig.nak(FRAME, 2 * 1056, 3), NakOutcome::Dropped);
    assert_eq!(rig.path.repair().unwrap().counts().lingering, 1);
    rig.finish();
}

/// Admission's ERRs: a range beyond what was sent is invalid; one below
/// the retention floor is unavailable at the floor the reads enforce.
#[test]
fn admission_answers_ranges_it_cannot_serve() {
    let mut rig = Rig::new(&RepairConfig::default());
    rig.publish(2);
    match rig.nak(2 * FRAME, 1056, 1) {
        NakOutcome::Reply(reply) => assert_eq!(reply.reason, NakReplyReason::RangeInvalid),
        other => panic!("{other:?}"),
    }
    // The sender's registration bounds the floor: register the first
    // frame as sent and let the conductor raise the floor to it.
    rig.path.readers_mut()[0].sent(FRAME).unwrap();
    let _ = rig.log.conductors[0].duty_cycle().unwrap();
    assert_eq!(rig.path.readers()[0].floor(), FRAME);
    match rig.nak(0, 1056, 2) {
        NakOutcome::Reply(reply) => assert_eq!(
            reply.reason,
            NakReplyReason::RangeUnavailable {
                lowest_retained: FRAME
            }
        ),
        other => panic!("{other:?}"),
    }
    rig.finish();
}

/// A NAK that is not a frame boundary is refused at its first head (step
/// 8) with RANGE_INVALID, through the ERR list.
#[test]
fn a_misaligned_nak_is_invalid_at_its_head() {
    let mut rig = Rig::new(&RepairConfig::default());
    rig.publish(3);
    assert_eq!(rig.nak(FRAME + 32, 1024, 1), NakOutcome::Queued);
    let mut budget = RepairBudget::default();
    assert_eq!(rig.repair(&mut budget, 2), 0);
    let mut replies = Vec::new();
    rig.path.drain_repair_replies(|reply| replies.push(*reply));
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].reason, NakReplyReason::RangeInvalid);
    assert_eq!(replies[0].range.start, FRAME + 32);
    // The same NAK again within `nak_reply_linger`: a new job, refused at
    // its head again, and its ERR held back by the linger.
    assert_eq!(rig.nak(FRAME + 32, 1024, 3), NakOutcome::Queued);
    assert_eq!(rig.repair(&mut RepairBudget::default(), 4), 0);
    rig.path.drain_repair_replies(|reply| replies.push(*reply));
    assert_eq!(replies.len(), 1, "held by the ERR linger");
    rig.finish();
}

/// Step 8 ERRs wait in a bounded list: past it they are dropped and
/// counted, never grown.
#[test]
fn step_8_errs_are_bounded() {
    let mut rig = Rig::new(&RepairConfig {
        replies: 1,
        ..RepairConfig::default()
    });
    rig.publish(3);
    for id in 1..=2 {
        let nak = Nak {
            alias: alias(),
            identity: identity(),
            receiver: Receiver {
                receiver_boot_id: [7, 8],
                receiver_id: id,
            },
            range: NakRange {
                lane: Lane::ZERO,
                length: 1024,
                start: FRAME + 32,
            },
        };
        assert_eq!(rig.path.nak(&nak, MEMBER, 1), NakOutcome::Queued);
    }
    assert_eq!(rig.repair(&mut RepairBudget::default(), 2), 0);
    let mut replies = Vec::new();
    rig.path.drain_repair_replies(|reply| replies.push(*reply));
    assert_eq!(replies.len(), 1);
    assert_eq!(rig.path.repair().unwrap().counts().replies_full, 1);
    rig.finish();
}

/// Out of word 0 loads, a repair waits: nothing is refused, and the next
/// cycle's budget sends it.
#[test]
fn a_repair_waits_for_loads() {
    let mut rig = Rig::new(&RepairConfig::default());
    rig.publish(3);
    assert_eq!(rig.nak(2 * FRAME, 1056, 1), NakOutcome::Queued);
    let mut budget = RepairBudget {
        bytes: 1 << 16,
        loads: 1,
    };
    assert_eq!(rig.repair(&mut budget, 2), 0);
    let mut replies = Vec::new();
    rig.path.drain_repair_replies(|reply| replies.push(*reply));
    assert!(replies.is_empty());
    rig.scripted(1);
    assert_eq!(rig.repair(&mut RepairBudget::default(), 3), 1);
    rig.finish();
}

/// A repair the kernel does not take is cancelled, not left in the queue:
/// the job keeps its cursor and the next call sends it once.
#[test]
fn an_unsent_repair_is_cancelled_and_retried() {
    let mut rig = Rig::new(&RepairConfig::default());
    rig.publish(2);
    let first = rig.datagrams();
    assert_eq!(rig.nak(0, 1056, 1), NakOutcome::Queued);
    // No scripted send: the kernel would block.
    assert_eq!(rig.repair(&mut RepairBudget::default(), 2), 0);
    assert_eq!(rig.path.repair().unwrap().counts().cancelled, 1);
    rig.scripted(1);
    assert_eq!(rig.repair(&mut RepairBudget::default(), 3), 1);
    let all = rig.datagrams();
    // The blocked attempt and the retry offered the same frame.
    assert_eq!(all.last(), first.first());
    assert_eq!(rig.path.repair().unwrap().counts().submitted, 1);
    rig.finish();
}

/// An open guard word at epoch 2, the guard's first open epoch after
/// creation.
fn open_guard() -> Arc<karyos_client::HeapWords> {
    use karyos_sys::sync::Ordering;

    let word = Arc::new(karyos_client::HeapWords::zeroed(1));
    let cell = &word.words()[0];
    cell.store(karyos_sys::guard::created(), Ordering::Release);
    assert_eq!(karyos_sys::guard::reopen(cell, 1), Ok(2));
    word
}

/// A guarded network publication runs the local close only (O-11, GC-6):
/// until the close it sends as before; after it, nothing at all leaves the
/// sender, first sends and repairs alike, no control is sent, and its
/// applied epoch, with the last positions submitted, reaches the close
/// acknowledgement's cell.
#[test]
fn a_guard_close_stops_every_submission() {
    use karyos_sys::applied_epoch::AppliedEpoch;

    let mut rig = Rig::new(&RepairConfig::default());
    let word = open_guard();
    let cell = Arc::new(AppliedEpoch::new());
    rig.path
        .guard(
            super::super::data::GuardSpec {
                word: Arc::clone(&word) as Arc<dyn karyos_client::SharedWords>,
                cell: Arc::clone(&cell),
                epoch: 2,
                rate: None,
            },
            0,
        )
        .unwrap();
    rig.publish(2);
    assert_eq!(rig.datagrams().len(), 2, "open: sent as before");
    let _ = karyos_sys::guard::close(&word.words()[0]).unwrap();
    // More is published, and a NAK names a frame already sent.
    for i in 0..2u8 {
        let _ = rig.log.publications[0]
            .append(&[i; 1000], AppendOptions::default())
            .unwrap();
    }
    rig.scripted(4);
    let _ = rig.path.serve(&mut rig.tx, BUDGET, None, 1).unwrap();
    assert_eq!(rig.nak(0, 1056, 2), NakOutcome::Queued);
    assert_eq!(rig.repair(&mut RepairBudget::default(), 3), 0);
    let _ = rig.path.serve(&mut rig.tx, BUDGET, None, 4).unwrap();
    assert_eq!(rig.datagrams().len(), 2, "closed: nothing at all left");
    let mut replies = Vec::new();
    rig.path.drain_repair_replies(|reply| replies.push(*reply));
    assert!(replies.is_empty(), "no ERR either");
    let gate = rig.path.guard_gate().unwrap();
    assert!(gate.abort_cause(0).is_some());
    let applied = cell.try_read().unwrap();
    assert_eq!(applied.epoch, 3, "the closed epoch is applied");
    assert_eq!(applied.positions[0], 2 * FRAME);
    assert_eq!(applied.in_flight, 0);
    rig.finish();
}

/// A guard word that closes itself right after its next `armed` Acquire
/// loads: a close that lands between a lane's probe and its exposure.
#[derive(Debug)]
struct ClosingWords {
    words: karyos_client::HeapWords,
    armed: karyos_sys::sync::AtomicU64,
}

impl karyos_sys::load_words::LoadWords for ClosingWords {
    fn len(&self) -> usize {
        self.words.len()
    }

    fn load(&self, index: usize) -> Option<u64> {
        self.words.load(index)
    }

    fn load_acquire(&self, index: usize) -> Option<u64> {
        use karyos_sys::sync::Ordering;

        let value = self.words.load_acquire(index);
        if self.armed.load(Ordering::Relaxed) == 1 {
            let _ = karyos_sys::guard::close(&self.words.words()[0]);
        }
        let armed = self.armed.load(Ordering::Relaxed);
        if armed > 0 {
            self.armed.store(armed - 1, Ordering::Relaxed);
        }
        value
    }
}

fn guard_spec(
    word: &Arc<impl karyos_client::SharedWords + 'static>,
    rate: Option<karyos_sys::rate_limit::RatePolicy>,
) -> (
    super::super::data::GuardSpec,
    Arc<karyos_sys::applied_epoch::AppliedEpoch>,
) {
    let cell = Arc::new(karyos_sys::applied_epoch::AppliedEpoch::new());
    (
        super::super::data::GuardSpec {
            word: Arc::clone(word) as Arc<dyn karyos_client::SharedWords>,
            cell: Arc::clone(&cell),
            epoch: 2,
            rate,
        },
        cell,
    )
}

/// The gate decides the exposure too, not only the probe: a close that
/// lands after the lane was found eligible still sends nothing; and a lane
/// found closed at its probe is never offered for exposure at all.
#[test]
fn a_close_between_probe_and_exposure_sends_nothing() {
    use karyos_sys::sync::Ordering;

    let mut rig = Rig::new(&RepairConfig::default());
    let word = Arc::new(ClosingWords {
        words: karyos_client::HeapWords::zeroed(1),
        armed: karyos_sys::sync::AtomicU64::new(0),
    });
    word.words.words()[0].store(karyos_sys::guard::created(), Ordering::Release);
    assert_eq!(karyos_sys::guard::reopen(&word.words.words()[0], 1), Ok(2));
    let (spec, _cell) = guard_spec(&word, None);
    rig.path.guard(spec, 0).unwrap();
    let _ = rig.log.publications[0]
        .append(&[1; 1000], AppendOptions::default())
        .unwrap();
    rig.scripted(1);
    // The probe's load sees the guard open; the exposure's sees it closed.
    word.armed.store(1, Ordering::Relaxed);
    let _ = rig.path.serve(&mut rig.tx, BUDGET, None, 1).unwrap();
    assert!(rig.datagrams().is_empty());
    let counts = rig.path.guard_gate().unwrap().counts();
    assert_eq!((counts.checks, counts.guard_denied), (1, 1));
    // Closed now: later probes find it closed and offer nothing.
    let _ = rig.path.serve(&mut rig.tx, BUDGET, None, 2).unwrap();
    assert_eq!(rig.path.guard_gate().unwrap().counts().checks, 1);
    rig.finish();
}

/// The guard's rate is the publication's: a datagram starting a message
/// costs one message token, and one over the bucket waits.
#[test]
fn a_guard_rate_holds_messages() {
    use karyos_sys::rate_limit::{Rate, RatePolicy};

    let mut rig = Rig::new(&RepairConfig::default());
    let word = open_guard();
    let (spec, _cell) = guard_spec(
        &word,
        Some(RatePolicy {
            messages: Rate {
                per_second: 1,
                burst: 1,
            },
            bytes: None,
        }),
    );
    rig.path.guard(spec, 0).unwrap();
    rig.publish(2);
    assert_eq!(rig.datagrams().len(), 1, "one message token");
    rig.finish();
}

/// After an endpoint reset a guarded lane reopens through its gate: the
/// heads the old queue held are settled there too, so the lane stages and
/// sends again.
#[test]
fn a_guarded_lane_sends_again_after_a_reset() {
    let rig = Rig::new(&RepairConfig::default());
    let Rig {
        tx,
        rx,
        observer,
        mut path,
        mut log,
        sent,
    } = rig;
    let word = open_guard();
    let (spec, _cell) = guard_spec(&word, None);
    path.guard(spec, 0).unwrap();
    let _ = log.publications[0]
        .append(&[1; 1000], AppendOptions::default())
        .unwrap();
    let mut tx = tx;
    // The kernel would block: the head stays pending in the old queue.
    let _ = path.serve(&mut tx, BUDGET, None, 1).unwrap();
    assert_eq!(path.counters().submitted, 0);
    let local = SocketsConfig::new(SocketAddr::from(([127, 0, 0, 1], 0)));
    let mut endpoint = SocketsEndpoint::join(tx, rx).ok().unwrap();
    let mut report = TxReport::new();
    while endpoint.reset(&mut report).more {
        while report.pop_front().is_some() {}
    }
    while report.pop_front().is_some() {}
    let _ = endpoint.reopen(&local).unwrap();
    let (tx, rx) = endpoint.split().unwrap();
    let mut rig = Rig {
        tx,
        rx,
        observer,
        path,
        log,
        sent,
    };
    rig.scripted(1);
    let _ = rig.path.serve(&mut rig.tx, BUDGET, None, 2).unwrap();
    assert_eq!(
        rig.observer.remaining_sends(),
        0,
        "sent again after the reset"
    );
    assert_eq!(rig.path.counters().submitted, 1);
    assert_eq!(rig.path.counters().staged_refused, 0);
    rig.finish();
}

/// A guarded publication not served yet still applies a close: its applied
/// epoch reaches the close acknowledgement's cell.
#[test]
fn an_unserved_guarded_publication_applies_a_close() {
    let mut rig = Rig::new(&RepairConfig::default());
    let word = open_guard();
    let (spec, cell) = guard_spec(&word, None);
    rig.path.guard(spec, 0).unwrap();
    let _ = karyos_sys::guard::close(&word.words()[0]).unwrap();
    rig.path.guard_tick(1);
    let applied = cell.try_read().unwrap();
    assert_eq!((applied.epoch, applied.in_flight), (3, 0));
    rig.finish();
}
