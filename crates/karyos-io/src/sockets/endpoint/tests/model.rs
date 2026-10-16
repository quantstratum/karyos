// SPDX-License-Identifier: Apache-2.0

//! The proptest model of section 12: random claim, commit, drop, flush,
//! cancel, retry, reset and scripted results, checking slot conservation
//! through the queue charge, FIFO order (each queue's items leave only from
//! its head, so its submitted sequence is a subsequence of its commit
//! sequence in order: "Lane order" for the backend half), and at most one
//! terminal report per ticket. A second property runs documented results
//! only and checks that none is `Unknown`.

use std::collections::{HashMap, VecDeque};

use proptest::prelude::*;

use super::*;
use crate::backend::{ClaimError, FlushStop, TxItemOutcome};
use crate::sockets::ops::{Errno, SendResult};

/// Queue capacity of the model: the whole pool of [`config`].
const MAX_PENDING: usize = 8;

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

#[derive(Debug, Clone, Copy)]
enum Op {
    Commit { len: u8 },
    DropClaim,
    Flush { script: Script, permit: Option<u8> },
    Cancel,
    Retry,
    Reset,
}

const ERRNOS: [Errno; 8] = [
    Errno::AGAIN,
    Errno::INTR,
    Errno::NOBUFS,
    Errno::NOMEM,
    Errno::CONNREFUSED,
    Errno::MSGSIZE,
    Errno::HOSTUNREACH,
    Errno::ADDRNOTAVAIL,
];

fn errno(index: u8) -> Errno {
    ERRNOS[usize::from(index) % ERRNOS.len()]
}

fn documented() -> impl Strategy<Value = Script> {
    prop_oneof![
        (0..8_u8).prop_map(Script::Error),
        (1..9_u8, proptest::option::of(0..8_u8))
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
        5 => (1..=255_u8).prop_map(|len| Op::Commit { len }),
        1 => Just(Op::DropClaim),
        4 => (script, proptest::option::of(1..9_u8))
            .prop_map(|(script, permit)| Op::Flush { script, permit }),
        1 => Just(Op::Cancel),
        1 => Just(Op::Retry),
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

struct Model {
    h: Option<Harness>,
    fault: Fault,
    /// The queue's pending tokens, in commit order.
    fifo: VecDeque<u64>,
    /// Unknown items still charged to the queue until reset.
    quarantined: usize,
    next_token: u64,
    tickets: HashMap<u64, TxTicket>,
    /// Terminal reports per token.
    terminal: HashMap<u64, u32>,
    unknown_seen: bool,
}

impl Model {
    fn new() -> Self {
        Self {
            h: Some(Harness::new()),
            fault: Fault::None,
            fifo: VecDeque::new(),
            quarantined: 0,
            next_token: 0,
            tickets: HashMap::new(),
            terminal: HashMap::new(),
            unknown_seen: false,
        }
    }

    fn h(&mut self) -> &mut Harness {
        self.h.as_mut().unwrap()
    }

    fn terminal(&mut self, token: u64) -> Result<(), TestCaseError> {
        let count = self.terminal.entry(token).or_insert(0);
        *count += 1;
        prop_assert_eq!(*count, 1, "one terminal report per ticket");
        Ok(())
    }

    /// Entries that leave the queue must be its head, in order; pending
    /// entries name the next items in order and are never followed by a
    /// submission in the same report.
    fn apply(&mut self, entries: &[TxEntry]) -> Result<(), TestCaseError> {
        let mut seen_pending = false;
        let mut cursor = 0_usize;
        for entry in entries {
            let token = entry.token.get();
            prop_assert_eq!(Some(entry.ticket), self.tickets.get(&token).copied());
            match entry.outcome {
                TxItemOutcome::Pending { .. } => {
                    prop_assert_eq!(self.fifo.get(cursor), Some(&token));
                    cursor += 1;
                    seen_pending = true;
                }
                TxItemOutcome::Submitted { .. }
                | TxItemOutcome::Returned { .. }
                | TxItemOutcome::Unknown => {
                    prop_assert!(!seen_pending, "no item leaves behind a pending one");
                    prop_assert_eq!(self.fifo.pop_front(), Some(token), "FIFO order");
                    if entry.outcome == TxItemOutcome::Unknown {
                        self.quarantined += 1;
                        self.unknown_seen = true;
                    }
                    self.terminal(token)?;
                }
            }
        }
        Ok(())
    }

    fn step(&mut self, op: Op) -> Result<(), TestCaseError> {
        match op {
            Op::Commit { len } => {
                let held = self.fifo.len() + self.quarantined;
                let h = self.h.as_mut().unwrap();
                let claim = h.tx.claim_tx(h.queue, usize::from(len));
                if held >= MAX_PENDING {
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
                    self.fifo.push_back(token);
                }
            }
            Op::DropClaim => {
                if self.fifo.len() + self.quarantined < MAX_PENDING {
                    let h = self.h();
                    drop(h.tx.claim_tx(h.queue, 1));
                }
            }
            Op::Flush { script, permit } => {
                let candidates = self.fifo.len().min(8);
                let permitted =
                    permit.map_or(candidates, |permit| usize::from(permit).min(candidates));
                if permitted > 0 && self.fault == Fault::None {
                    self.h().socket.push_send(result(script, permitted));
                }
                let mut gate = match permit {
                    Some(permit) if candidates > 0 => {
                        Gate::permit(u16::from(permit).min(u16::try_from(candidates).unwrap()))
                    }
                    _ => Gate::default(),
                };
                let calls = self.h().socket.send_calls();
                let (outcome, entries) = self.h().flush(&mut gate);
                let sent = self.h().socket.send_calls() - calls;
                prop_assert!(sent <= 1, "at most one exposure per flush");
                prop_assert!(gate.calls <= 1, "at most one gate check per flush");
                prop_assert_eq!(
                    self.h().socket.remaining_sends(),
                    0,
                    "the model predicts every exposure"
                );
                prop_assert_eq!(sent, u64::from(permitted > 0 && self.fault == Fault::None));
                match outcome.stop {
                    FlushStop::Faulted(_) => {
                        prop_assert!(self.fault != Fault::Invariant);
                        self.fault = Fault::Send;
                    }
                    FlushStop::Failed(_) => self.fault = Fault::Invariant,
                    _ => {}
                }
                prop_assert!(outcome.spent.ops <= 1);
                if outcome.stop == FlushStop::QueueEmpty {
                    prop_assert!(self.fifo.is_empty());
                }
                self.apply(&entries)?;
            }
            Op::Cancel => {
                let mut report = TxReport::new();
                let h = self.h();
                if h.tx.cancel_pending(h.queue, &mut report).is_ok() {
                    let entries = drain(&mut report);
                    self.apply(&entries)?;
                }
            }
            Op::Retry => {
                let h = self.h.as_mut().unwrap();
                let retried = h.tx.retry_queue(h.queue);
                if self.fault == Fault::Invariant {
                    prop_assert_eq!(retried, Err(crate::backend::QueueError::NeedsReset));
                } else {
                    prop_assert_eq!(retried, Ok(()));
                    self.fault = Fault::None;
                }
            }
            Op::Reset => self.reset()?,
        }
        // Conservation: every pending ticket resolves, every terminal one
        // does not.
        let tx = &self.h.as_ref().unwrap().tx;
        prop_assert_eq!(tx.pending(), self.fifo.len());
        for token in &self.fifo {
            prop_assert!(tx.is_pending(self.tickets[token]));
        }
        for token in self.terminal.keys() {
            prop_assert!(!tx.is_pending(self.tickets[token]));
        }
        Ok(())
    }

    fn reset(&mut self) -> Result<(), TestCaseError> {
        let (mut endpoint, socket) = self.h.take().unwrap().join();
        let entries = reset_all(&mut endpoint);
        self.apply(&entries)?;
        prop_assert!(self.fifo.is_empty());
        self.quarantined = 0;
        self.fault = Fault::None;
        endpoint
            .reopen(&config())
            .map_err(|error| TestCaseError::fail(format!("{error}")))?;
        let (mut tx, rx) = endpoint.split().unwrap();
        let route = tx.add_route(peer()).unwrap();
        let queue = tx
            .open_queue(TxQueueConfig {
                authority: Authority::FIRST,
                route,
                max_pending: nz(8),
            })
            .unwrap();
        self.h = Some(Harness {
            tx,
            rx,
            socket,
            route,
            queue,
        });
        Ok(())
    }

    fn finish(mut self) -> Result<(), TestCaseError> {
        let entries = self.h.take().unwrap().shutdown();
        self.apply(&entries)?;
        prop_assert!(self.fifo.is_empty());
        // Every committed ticket got exactly one terminal report.
        prop_assert_eq!(self.terminal.len(), self.tickets.len());
        Ok(())
    }
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
        let mut model = Model::new();
        for op in ops {
            model.step(op)?;
        }
        model.finish()?;
    }

    /// No documented result is Unknown: every ticket is Submitted or
    /// Returned at most once, and nothing is quarantined.
    #[test]
    fn no_documented_result_is_unknown(
        ops in proptest::collection::vec(op(documented().boxed(), false), 0..120),
    ) {
        let mut model = Model::new();
        for op in ops {
            model.step(op)?;
        }
        prop_assert!(!model.unknown_seen);
        model.finish()?;
    }
}
