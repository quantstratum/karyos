// SPDX-License-Identifier: Apache-2.0

//! The proptest model of section 12: random claim, commit, drop, flush,
//! cancel, retry, reset and scripted results, checking slot conservation
//! through the queue charge, FIFO order (each queue's items leave only from
//! its head, so its submitted sequence is a subsequence of its commit
//! sequence in order: "Lane order" for the backend half), and at most one
//! terminal report per ticket. A second property runs documented results
//! only and checks that none is `Unknown`.
//!
//! The model runs one queue over the whole pool, and two queues that
//! share the pool (review P3-10): their operations interleave at random
//! and freed slots are reused by either queue, so each slot moves between
//! the two FIFOs under new generations. Reset entries span both queues;
//! each entry is matched to its own queue's FIFO.

use std::collections::{HashMap, VecDeque};

use proptest::prelude::*;

use super::*;
use crate::backend::{BackendFailure, ClaimError, FlushStop, TxItemOutcome};
use crate::sockets::ops::{Errno, SendResult};

/// The pool of [`config`], split evenly over the model's queues.
const POOL: usize = 8;

#[derive(Debug, Clone, Copy)]
enum Script {
    /// `Error(errno)`.
    Error(u8),
    /// `Sent { sent, error }`, with `sent` reduced into the permitted
    /// count as the documented ABI allows.
    Sent { sent: u8, error: Option<u8> },
    /// Outside the ABI: `OutOfAbi` or a count above the request.
    OutOfAbi { proven: u8, above: bool },
}

/// One operation; `lane` picks the queue, reduced modulo the queue count.
#[derive(Debug, Clone, Copy)]
enum Op {
    Commit {
        lane: u8,
        len: u8,
    },
    DropClaim {
        lane: u8,
    },
    Flush {
        lane: u8,
        script: Script,
        permit: Option<u8>,
    },
    Cancel {
        lane: u8,
    },
    Retry {
        lane: u8,
    },
    Reset,
}

/// The errnos of the send column of 4.7; the last four stop the half.
const ERRNOS: [Errno; 12] = [
    Errno::AGAIN,
    Errno::INTR,
    Errno::NOBUFS,
    Errno::NOMEM,
    Errno::CONNREFUSED,
    Errno::MSGSIZE,
    Errno::HOSTUNREACH,
    Errno::ADDRNOTAVAIL,
    Errno::BADF,
    Errno::NOTSOCK,
    Errno::FAULT,
    Errno::INVAL,
];

fn errno(index: u8) -> Errno {
    ERRNOS[usize::from(index) % ERRNOS.len()]
}

fn documented() -> impl Strategy<Value = Script> {
    prop_oneof![
        (0..12_u8).prop_map(Script::Error),
        (1..9_u8, proptest::option::of(0..12_u8))
            .prop_map(|(sent, error)| Script::Sent { sent, error }),
    ]
}

fn any_script() -> impl Strategy<Value = Script> {
    prop_oneof![
        4 => documented(),
        1 => (0..9_u8, any::<bool>()).prop_map(|(proven, above)| Script::OutOfAbi { proven, above }),
    ]
}

fn op(script: BoxedStrategy<Script>, resets: bool) -> impl Strategy<Value = Op> {
    let reset_weight = if resets { 1 } else { 0 };
    prop_oneof![
        5 => (any::<u8>(), 1..=255_u8).prop_map(|(lane, len)| Op::Commit { lane, len }),
        1 => any::<u8>().prop_map(|lane| Op::DropClaim { lane }),
        4 => (any::<u8>(), script, proptest::option::of(1..9_u8))
            .prop_map(|(lane, script, permit)| Op::Flush { lane, script, permit }),
        1 => any::<u8>().prop_map(|lane| Op::Cancel { lane }),
        1 => any::<u8>().prop_map(|lane| Op::Retry { lane }),
        reset_weight => Just(Op::Reset),
    ]
}

/// The send result a script gives for `permitted` exposed items.
fn result(script: Script, permitted: usize) -> SendResult {
    match script {
        Script::Error(index) => SendResult::Error(errno(index)),
        // Documented: a count with no error accepts at least one item and
        // at most the request; an error follows fewer than the request.
        Script::Sent { sent, error: None } => SendResult::Sent {
            sent: usize::from(sent).clamp(1, permitted),
            error: None,
        },
        Script::Sent {
            sent,
            error: Some(index),
        } => SendResult::Sent {
            sent: usize::from(sent) % permitted,
            error: Some(errno(index)),
        },
        Script::OutOfAbi { above: true, .. } => SendResult::Sent {
            sent: permitted + 1,
            error: None,
        },
        Script::OutOfAbi { proven, .. } => SendResult::OutOfAbi {
            proven: usize::from(proven),
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    Send,
    Invariant,
}

/// The model of one queue.
struct Lane {
    queue: TxQueueId,
    fault: Fault,
    /// The queue's pending tokens, in commit order.
    fifo: VecDeque<u64>,
    /// Unknown items still charged to the queue until reset.
    quarantined: usize,
}

impl Lane {
    fn new(queue: TxQueueId) -> Self {
        Self {
            queue,
            fault: Fault::None,
            fifo: VecDeque::new(),
            quarantined: 0,
        }
    }
}

struct Model {
    h: Option<Harness>,
    lanes: Vec<Lane>,
    /// `max_pending` of each queue: an even share of the pool.
    max_pending: usize,
    next_token: u64,
    tickets: HashMap<u64, TxTicket>,
    /// The lane each token was committed to.
    owner: HashMap<u64, usize>,
    /// Terminal reports per token.
    terminal: HashMap<u64, u32>,
    unknown_seen: bool,
    /// A `Failed(Os)` result stopped the TX half until the next reset.
    half_failed: bool,
}

/// Opens `count` queues of `max_pending` on the harness route, after its
/// first queue.
fn open_lanes(h: &mut Harness, count: usize, max_pending: u16) -> Vec<Lane> {
    let mut lanes = vec![Lane::new(h.queue)];
    while lanes.len() < count {
        let queue =
            h.tx.open_queue(TxQueueConfig {
                authority: Authority::FIRST,
                route: h.route,
                max_pending: nz(max_pending),
                etf: None,
            })
            .unwrap();
        lanes.push(Lane::new(queue));
    }
    lanes
}

impl Model {
    fn new(count: usize) -> Self {
        let max_pending = POOL / count;
        let share = u16::try_from(max_pending).unwrap();
        let mut h = Harness::open(config(), share);
        let lanes = open_lanes(&mut h, count, share);
        Self {
            h: Some(h),
            lanes,
            max_pending,
            next_token: 0,
            tickets: HashMap::new(),
            owner: HashMap::new(),
            terminal: HashMap::new(),
            unknown_seen: false,
            half_failed: false,
        }
    }

    fn h(&mut self) -> &mut Harness {
        self.h.as_mut().unwrap()
    }

    fn lane(&self, lane: u8) -> usize {
        usize::from(lane) % self.lanes.len()
    }

    fn terminal(&mut self, token: u64) -> Result<(), TestCaseError> {
        let count = self.terminal.entry(token).or_insert(0);
        *count += 1;
        prop_assert_eq!(*count, 1, "one terminal report per ticket");
        Ok(())
    }

    /// Entries that leave a queue must be its head, in order; pending
    /// entries name the next items of their queue in order and are never
    /// followed by a submission of the same queue in the same report.
    fn apply(&mut self, entries: &[TxEntry]) -> Result<(), TestCaseError> {
        let mut seen_pending = vec![false; self.lanes.len()];
        let mut cursor = vec![0_usize; self.lanes.len()];
        for entry in entries {
            let token = entry.token.get();
            prop_assert_eq!(Some(entry.ticket), self.tickets.get(&token).copied());
            let lane = self.owner[&token];
            match entry.outcome {
                TxItemOutcome::Pending { .. } => {
                    prop_assert_eq!(self.lanes[lane].fifo.get(cursor[lane]), Some(&token));
                    cursor[lane] += 1;
                    seen_pending[lane] = true;
                }
                TxItemOutcome::Submitted { .. }
                | TxItemOutcome::Returned { .. }
                | TxItemOutcome::Unknown => {
                    prop_assert!(!seen_pending[lane], "no item leaves behind a pending one");
                    prop_assert_eq!(
                        self.lanes[lane].fifo.pop_front(),
                        Some(token),
                        "FIFO order of each queue"
                    );
                    if entry.outcome == TxItemOutcome::Unknown {
                        self.lanes[lane].quarantined += 1;
                        self.unknown_seen = true;
                    }
                    self.terminal(token)?;
                }
            }
        }
        Ok(())
    }

    fn held(&self, lane: usize) -> usize {
        self.lanes[lane].fifo.len() + self.lanes[lane].quarantined
    }

    fn step(&mut self, op: Op) -> Result<(), TestCaseError> {
        match op {
            Op::Commit { lane, len } => {
                let lane = self.lane(lane);
                let held = self.held(lane);
                let queue = self.lanes[lane].queue;
                let full = held >= self.max_pending;
                let h = self.h.as_mut().unwrap();
                let claim = h.tx.claim_tx(queue, usize::from(len));
                if full {
                    let full = matches!(claim.err(), Some(ClaimError::QueueFull { .. }));
                    prop_assert!(full, "QueueFull at capacity");
                } else {
                    let mut frame =
                        claim.map_err(|error| TestCaseError::fail(format!("{error}")))?;
                    frame.bytes_mut().fill(len);
                    let token = self.next_token;
                    self.next_token += 1;
                    let ticket = frame
                        .commit(Commit {
                            len: usize::from(len),
                            token: SenderToken::new(token),
                            options: TxOptions::none(),
                        })
                        .map_err(|rejected| TestCaseError::fail(format!("{}", rejected.error)))?;
                    self.tickets.insert(token, ticket);
                    self.owner.insert(token, lane);
                    self.lanes[lane].fifo.push_back(token);
                }
            }
            Op::DropClaim { lane } => {
                let lane = self.lane(lane);
                if self.held(lane) < self.max_pending {
                    let queue = self.lanes[lane].queue;
                    let h = self.h();
                    drop(h.tx.claim_tx(queue, 1));
                }
            }
            Op::Flush {
                lane,
                script,
                permit,
            } => self.flush(self.lane(lane), script, permit)?,
            Op::Cancel { lane } => {
                let queue = self.lanes[self.lane(lane)].queue;
                let mut report = TxReport::new();
                let h = self.h();
                if h.tx.cancel_pending(queue, &mut report).is_ok() {
                    let entries = drain(&mut report);
                    self.apply(&entries)?;
                }
            }
            Op::Retry { lane } => {
                let lane = self.lane(lane);
                let queue = self.lanes[lane].queue;
                let h = self.h.as_mut().unwrap();
                let retried = h.tx.retry_queue(queue);
                if self.lanes[lane].fault == Fault::Invariant {
                    prop_assert_eq!(retried, Err(crate::backend::QueueError::NeedsReset));
                } else {
                    prop_assert_eq!(retried, Ok(()));
                    self.lanes[lane].fault = Fault::None;
                }
            }
            Op::Reset => self.reset()?,
        }
        // Conservation: every pending ticket resolves, every terminal one
        // does not.
        let tx = &self.h.as_ref().unwrap().tx;
        let pending: usize = self.lanes.iter().map(|lane| lane.fifo.len()).sum();
        prop_assert_eq!(tx.pending(), Some(pending));
        for token in self.lanes.iter().flat_map(|lane| &lane.fifo) {
            prop_assert!(tx.is_pending(self.tickets[token]));
        }
        for token in self.terminal.keys() {
            prop_assert!(!tx.is_pending(self.tickets[token]));
        }
        Ok(())
    }

    fn flush(
        &mut self,
        lane: usize,
        script: Script,
        permit: Option<u8>,
    ) -> Result<(), TestCaseError> {
        let queue = self.lanes[lane].queue;
        let fault = self.lanes[lane].fault;
        let candidates = self.lanes[lane].fifo.len().min(8);
        let permitted = permit.map_or(candidates, |permit| usize::from(permit).min(candidates));
        let half_failed = self.half_failed;
        let exposes = permitted > 0 && fault == Fault::None && !half_failed;
        if exposes {
            self.h().socket.push_send(result(script, permitted));
        }
        let mut gate = match permit {
            Some(permit) if candidates > 0 => {
                Gate::permit(u16::from(permit).min(u16::try_from(candidates).unwrap()))
            }
            _ => Gate::default(),
        };
        let calls = self.h().socket.send_calls();
        let (outcome, entries) = self.h().flush_queue(queue, &mut gate);
        let sent = self.h().socket.send_calls() - calls;
        prop_assert!(sent <= 1, "at most one exposure per flush");
        prop_assert!(gate.calls <= 1, "at most one gate check per flush");
        prop_assert_eq!(
            self.h().socket.remaining_sends(),
            0,
            "the model predicts every exposure"
        );
        prop_assert_eq!(sent, u64::from(exposes));
        if half_failed {
            // A stopped half makes no gate check, no call and no report.
            let stopped = matches!(outcome.stop, FlushStop::Failed(BackendFailure::Os { .. }));
            prop_assert!(stopped, "a stopped half returns its failure");
            prop_assert_eq!(gate.calls, 0);
            prop_assert!(entries.is_empty());
        }
        match outcome.stop {
            FlushStop::Faulted(_) => {
                prop_assert!(fault != Fault::Invariant);
                self.lanes[lane].fault = Fault::Send;
            }
            FlushStop::Failed(BackendFailure::Os { .. }) => self.half_failed = true,
            FlushStop::Failed(_) => self.lanes[lane].fault = Fault::Invariant,
            _ => {}
        }
        prop_assert!(outcome.spent.ops <= 1);
        if outcome.stop == FlushStop::QueueEmpty {
            prop_assert!(self.lanes[lane].fifo.is_empty());
        }
        self.apply(&entries)
    }

    fn reset(&mut self) -> Result<(), TestCaseError> {
        let (mut endpoint, socket) = self.h.take().unwrap().join();
        let entries = reset_all(&mut endpoint);
        self.apply(&entries)?;
        prop_assert!(self.lanes.iter().all(|lane| lane.fifo.is_empty()));
        self.half_failed = false;
        endpoint
            .reopen(&config())
            .map_err(|error| TestCaseError::fail(format!("{error}")))?;
        let (mut tx, rx) = endpoint.split().unwrap();
        let route = tx.add_route(peer()).unwrap();
        let share = u16::try_from(self.max_pending).unwrap();
        let queue = tx
            .open_queue(TxQueueConfig {
                authority: Authority::FIRST,
                route,
                max_pending: nz(share),
                etf: None,
            })
            .unwrap();
        let mut h = Harness {
            tx,
            rx,
            socket,
            route,
            queue,
        };
        self.lanes = open_lanes(&mut h, self.lanes.len(), share);
        self.h = Some(h);
        Ok(())
    }

    fn finish(mut self) -> Result<(), TestCaseError> {
        let entries = self.h.take().unwrap().shutdown();
        self.apply(&entries)?;
        prop_assert!(self.lanes.iter().all(|lane| lane.fifo.is_empty()));
        // Every committed ticket got exactly one terminal report.
        prop_assert_eq!(self.terminal.len(), self.tickets.len());
        Ok(())
    }
}

fn run(count: usize, ops: Vec<Op>) -> Result<Model, TestCaseError> {
    let mut model = Model::new(count);
    for op in ops {
        model.step(op)?;
    }
    Ok(model)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// The state machine model with every scripted result, invariant
    /// violations and resets included; also the backend half of "Lane
    /// order": items leave each queue only from its head, in commit order.
    #[test]
    fn state_machine_model_and_lane_order(
        ops in proptest::collection::vec(op(any_script().boxed(), true), 0..120),
    ) {
        run(1, ops)?.finish()?;
    }

    /// "Lane order" over two queues sharing the pool (review P3-10): the
    /// FIFOs interleave and reuse each other's freed slots; each queue's
    /// submitted sequence stays a subsequence of its commit sequence and
    /// no slot is released, quarantined or reported on the wrong queue.
    #[test]
    fn two_queue_model_and_lane_order(
        ops in proptest::collection::vec(op(any_script().boxed(), true), 0..160),
    ) {
        run(2, ops)?.finish()?;
    }

    /// No documented result is Unknown: every ticket is Submitted or
    /// Returned at most once, and nothing is quarantined.
    #[test]
    fn no_documented_result_is_unknown(
        ops in proptest::collection::vec(op(documented().boxed(), false), 0..120),
    ) {
        let model = run(1, ops)?;
        prop_assert!(!model.unknown_seen);
        model.finish()?;
    }

    /// The same over two queues.
    #[test]
    fn no_documented_result_is_unknown_over_two_queues(
        ops in proptest::collection::vec(op(documented().boxed(), false), 0..160),
    ) {
        let model = run(2, ops)?;
        prop_assert!(!model.unknown_seen);
        model.finish()?;
    }
}
