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

/// Out of word 0 loads, a repair waits: the head read meets `Budget`
/// (six frames from the term's checkpoint, four loads to walk), the call
/// suspends with the job kept, nothing is refused, and the next cycle's
/// budget sends it.
#[test]
fn a_repair_waits_for_loads() {
    let mut rig = Rig::new(&RepairConfig::default());
    rig.publish(6);
    assert_eq!(rig.nak(5 * FRAME, 1056, 1), NakOutcome::Queued);
    let mut budget = RepairBudget {
        bytes: 1 << 16,
        loads: 3,
    };
    assert_eq!(rig.repair(&mut budget, 2), 0);
    let suspended = |rig: &Rig| {
        rig.path
            .repair()
            .unwrap()
            .parts()
            .2
            .counts()
            .budget_suspended
    };
    assert_eq!(suspended(&rig), 1);
    let mut replies = Vec::new();
    rig.path.drain_repair_replies(|reply| replies.push(*reply));
    assert!(replies.is_empty());
    rig.scripted(1);
    assert_eq!(rig.repair(&mut RepairBudget::default(), 3), 1);
    assert_eq!(suspended(&rig), 1);
    rig.finish();
}

/// Admission refuses below the retention floor, not below the registered
/// position: a NAK between the two is served.
#[test]
fn a_nak_below_the_registered_position_is_served() {
    let mut rig = Rig::new(&RepairConfig::default());
    rig.publish(4);
    let first = rig.datagrams();
    // Registered at the third frame; no conductor cycle raised the floor.
    rig.path.readers_mut()[0].sent(3 * FRAME).unwrap();
    assert_eq!(rig.path.readers()[0].floor(), 0);
    assert_eq!(rig.nak(FRAME, 1056, 1), NakOutcome::Queued);
    rig.scripted(1);
    assert_eq!(rig.repair(&mut RepairBudget::default(), 2), 1);
    assert_eq!(rig.datagrams().last(), first.get(1));
    rig.finish();
}

/// Repairs go on the publication's repair queue, outside the lane's: with
/// two lane frames staged in the lane's queue (the kernel refused them),
/// a repair call offers only the repaired frame and leaves the lane's read
/// position as it was; the lane's next send offers its two frames, in
/// order, and the repair is not among them.
#[test]
fn a_repair_leaves_the_lane_alone() {
    let mut rig = Rig::new(&RepairConfig::default());
    rig.publish(2);
    for i in 2..4u8 {
        let _ = rig.log.publications[0]
            .append(&[i; 1000], AppendOptions::default())
            .unwrap();
    }
    // No scripted send: frames 2 and 3 are staged, the first offer refused.
    let _ = rig.path.serve(&mut rig.tx, BUDGET, None, 0).unwrap();
    let position = rig.path.readers()[0].position();
    assert_eq!(position, 4 * FRAME);
    // The message number each datagram from `from` on carries.
    let offered = |rig: &Rig, from: usize| -> Vec<u8> {
        rig.datagrams()[from..]
            .iter()
            .map(|bytes| bytes[32])
            .collect()
    };
    let before = rig.datagrams().len();
    assert_eq!(rig.nak(0, 1056, 1), NakOutcome::Queued);
    rig.scripted(1);
    assert_eq!(rig.repair(&mut RepairBudget::default(), 2), 1);
    assert_eq!(offered(&rig, before), [0]);
    assert_eq!(rig.path.readers()[0].position(), position);
    let before = rig.datagrams().len();
    rig.scripted(2);
    let _ = rig.path.serve(&mut rig.tx, BUDGET, None, 0).unwrap();
    assert_eq!(offered(&rig, before), [2, 3]);
    rig.finish();
}

/// A repair whose exposure the backend cannot prove (a send result out of
/// its ABI) ends its job unresolved: counted, never retried, and no ERR.
#[test]
fn an_uncertain_repair_ends_its_job() {
    let mut rig = Rig::new(&RepairConfig::default());
    rig.publish(2);
    assert_eq!(rig.nak(0, 1056, 1), NakOutcome::Queued);
    rig.observer.push_send(SendResult::OutOfAbi { proven: 0 });
    let _ = rig.repair(&mut RepairBudget::default(), 2);
    let unresolved = |rig: &Rig| rig.path.repair().unwrap().parts().2.counts().unresolved;
    assert_eq!(unresolved(&rig), 1);
    let sent = rig.datagrams().len();
    rig.scripted(1);
    assert_eq!(rig.repair(&mut RepairBudget::default(), 3), 0);
    assert_eq!(rig.datagrams().len(), sent);
    let mut replies = Vec::new();
    rig.path.drain_repair_replies(|reply| replies.push(*reply));
    assert!(replies.is_empty());
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
