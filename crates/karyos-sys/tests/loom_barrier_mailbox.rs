// SPDX-License-Identifier: Apache-2.0

//! The combined Loom model of a conflated network image's freshness
//! (`quantstratum-docs: karyos/design/conflated-network-images.md`, (d);
//! GP5's proof gate): the receive owner, the view's feeder and a reader
//! over the production [`BarrierMailbox`], [`BarrierWords`],
//! [`FreshSlotWords`] and [`TerminalCell`] together.
//!
//! - **Owner:** posts the interval it intends to seal, waits for the
//!   acknowledgement or times out, then seals (the marker becomes visible),
//!   after publishing the terminal cell if it timed out. If the feeder
//!   claimed the cell first, the owner seals only once the feeder's
//!   publication is visible: until then its gate answers Pending.
//! - **Feeder:** takes the request, appends the loss and publishes the
//!   barrier, acknowledges, reconciles the slot and retires the record;
//!   with its ring full, it publishes the terminal cell instead.
//! - **Reader:** reads the marker, the terminal cell, a barrier snapshot,
//!   the slot, then the terminal cell again, and classifies the value.
//!
//! Scenarios:
//!
//! 1. the acknowledgement path: the owner seals only after the ack;
//! 2. the timeout: the owner checks the ack once, and either seals or
//!    publishes the terminal cell and seals, while the feeder still serves
//!    the request;
//! 3. the ring-full race: the feeder's ring is full, so it publishes the
//!    terminal cell, racing the owner's timeout;
//! 4. the attach race: the feeder attaches while the owner decides; the
//!    owner either posts through the mailbox or, seeing no feeder, seals
//!    at once, and the feeder meets the committed marker while catching up.
//!
//! Properties:
//!
//! - once the marker is visible, no reader classifies the value, which lies
//!   below the interval's end, as Fresh (scenarios 1 to 3); in the attach
//!   race, a feeder that never saw the request has not reached the gap
//!   yet, so the property holds from the feeder's frontier: a reader that
//!   sees a value published past the interval never classifies the value
//!   below it as Fresh;
//! - exactly one terminal publication wins, and a published body is
//!   complete;
//! - the acknowledgement is never observed before the barrier record.
//!
//! Negative controls, each of which must fail: the ack before the append;
//! the seal before the ack; a terminal body written after its publication;
//! a Relaxed terminal publication; a second terminal claim that succeeds;
//! a seal after a failed claim, before the winner's publication is visible
//! (the claimed cell then reads as unpublished); and, for the attach race,
//! a value published past the marker before the feeder appends the gap.
//!
//! Run with `make loom`.

#![cfg(loom)]
#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test model, as ADR-0007 allows in tests"
)]

use karyos_sys::conflation::{FreshRead, FreshSlotWords};
use karyos_sys::freshness::{
    BarrierMailbox, BarrierSnapshot, BarrierWords, Freshness, FreshnessError, MAILBOX_WORDS, STALE,
    SlotFreshness, TERMINAL_WORDS, Terminal, TerminalCell, barrier_words,
};
use karyos_sys::sync::{AtomicU64, Ordering};
use loom::sync::Arc;
use loom::thread;

const RING: usize = 2;
/// The interval the owner seals.
const GAP: (u64, u64) = (8, 16);
/// The value's position: below the interval's end.
const POSITION: u64 = 2;
/// The position of a value the feeder publishes past the interval.
const PAST: u64 = 20;
/// Two gaps above the value, filling the ring in scenario 3.
const FULL: [(u64, u64); 2] = [(24, 32), (40, 48)];
/// The close reasons of the two terminal publishers.
const BARRIER_TIMEOUT: u64 = 1;
const FRESHNESS_EXHAUSTED: u64 = 2;
/// A slot's words: five header words and one value word.
const SLOT_WORDS: usize = 6;

/// Which rule a control removes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Fault {
    None,
    AckBeforeAppend,
    SealBeforeAck,
    TerminalBodyAfterPublication,
    RelaxedTerminalPublication,
    SecondClaimSucceeds,
    PastValueBeforeAppend,
    SealAfterFailedClaim,
}

/// The scenario's starting state and the owner's and feeder's programs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Scenario {
    AckPath,
    Timeout,
    RingFull,
    AttachRace,
}

struct View {
    mailbox: Vec<AtomicU64>,
    barrier: Vec<AtomicU64>,
    /// The value's slot, then the slot of a value past the interval.
    slots: [Vec<AtomicU64>; 2],
    terminal: Vec<AtomicU64>,
    /// The owner's seal: the committed gap marker.
    marker: AtomicU64,
    /// The terminal publications that won.
    winners: AtomicU64,
}

fn zeroed(len: usize) -> Vec<AtomicU64> {
    (0..len).map(|_| AtomicU64::new(0)).collect()
}

impl View {
    fn new(scenario: Scenario) -> Self {
        let view = Self {
            mailbox: zeroed(MAILBOX_WORDS),
            barrier: zeroed(barrier_words(RING).unwrap()),
            slots: [zeroed(SLOT_WORDS), zeroed(SLOT_WORDS)],
            terminal: zeroed(TERMINAL_WORDS),
            marker: AtomicU64::new(0),
            winners: AtomicU64::new(0),
        };
        let slot = FreshSlotWords::new(&view.slots[0]).unwrap();
        assert_eq!(slot.write(&POSITION.to_le_bytes()), Ok(2));
        if scenario == Scenario::RingFull {
            // Two unretired losses above the value: the ring is full, and
            // the value is still Fresh.
            let barrier = BarrierWords::new(&view.barrier, RING).unwrap();
            for (start, end) in FULL {
                let _ = barrier.append_loss(start, end).unwrap();
            }
            slot.set_freshness(SlotFreshness {
                loss_applied: 2,
                stale_since: 0,
            })
            .unwrap();
        }
        if scenario != Scenario::AttachRace {
            BarrierMailbox::new(&view.mailbox).unwrap().attach();
        }
        view
    }

    fn mailbox(&self) -> BarrierMailbox<'_> {
        BarrierMailbox::new(&self.mailbox).unwrap()
    }

    fn barrier(&self) -> BarrierWords<'_> {
        BarrierWords::new(&self.barrier, RING).unwrap()
    }

    fn seal(&self) {
        self.marker.store(1, Ordering::Release);
    }

    /// Publishes the terminal cell, or a control's faulty publication;
    /// whether this publisher won the claim.
    fn publish_terminal(&self, reason: u64, fault: Fault) -> bool {
        let terminal = Terminal {
            start: GAP.0,
            end: GAP.1,
            reason,
        };
        let [state, start, end, code] = &self.terminal[..] else {
            unreachable!()
        };
        let won = match fault {
            Fault::TerminalBodyAfterPublication => {
                let claimed = state
                    .compare_exchange(0, 1, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok();
                if claimed {
                    state.store(2, Ordering::Release);
                    start.store(terminal.start, Ordering::Relaxed);
                    end.store(terminal.end, Ordering::Relaxed);
                    code.store(terminal.reason, Ordering::Relaxed);
                }
                claimed
            }
            Fault::RelaxedTerminalPublication => {
                let claimed = state
                    .compare_exchange(0, 1, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok();
                if claimed {
                    start.store(terminal.start, Ordering::Relaxed);
                    end.store(terminal.end, Ordering::Relaxed);
                    code.store(terminal.reason, Ordering::Relaxed);
                    state.store(2, Ordering::Relaxed);
                }
                claimed
            }
            Fault::SecondClaimSucceeds => {
                // A check, then a store: two publishers can both claim.
                let claimed = state.load(Ordering::Relaxed) == 0;
                if claimed {
                    state.store(1, Ordering::Relaxed);
                    start.store(terminal.start, Ordering::Relaxed);
                    end.store(terminal.end, Ordering::Relaxed);
                    code.store(terminal.reason, Ordering::Relaxed);
                    state.store(2, Ordering::Release);
                }
                claimed
            }
            _ => TerminalCell::new(&self.terminal).unwrap().publish(terminal),
        };
        if won {
            self.winners.fetch_add(1, Ordering::Relaxed);
        }
        won
    }
}

fn owner(view: &View, scenario: Scenario, fault: Fault) {
    let mailbox = view.mailbox();
    if scenario == Scenario::AttachRace && !mailbox.is_attached() {
        // No view to protect: seal at once.
        view.seal();
        return;
    }
    let request = mailbox.post(GAP.0, GAP.1).unwrap();
    match scenario {
        Scenario::AckPath | Scenario::AttachRace => {
            if fault != Fault::SealBeforeAck {
                while !mailbox.is_acknowledged(request) {
                    thread::yield_now();
                }
                // The ack is never observed before the barrier record.
                assert!(view.barrier().loss_seq() >= 1, "ack before the record");
            }
            view.seal();
        }
        Scenario::Timeout | Scenario::RingFull => {
            // One check stands for the bound: the ack came in time, or not.
            let acked = mailbox.is_acknowledged(request);
            if acked {
                assert!(view.barrier().loss_seq() >= 1, "ack before the record");
            } else if !view.publish_terminal(BARRIER_TIMEOUT, fault)
                && fault != Fault::SealAfterFailedClaim
            {
                // The feeder claimed first: the gate answers Pending until
                // its publication is visible (Acquire), then seals.
                while TerminalCell::read(&view.terminal.as_slice()).is_none() {
                    thread::yield_now();
                }
            }
            view.seal();
        }
    }
}

/// The feeder's append, acknowledgement, reconciliation and retirement of
/// one request; `false` with a full ring, after publishing the terminal
/// cell.
fn serve(view: &View, request: Option<u64>, fault: Fault) -> bool {
    let mailbox = view.mailbox();
    if fault == Fault::AckBeforeAppend
        && let Some(request) = request
    {
        mailbox.acknowledge(request).unwrap();
    }
    let seq = match view.barrier().append_loss(GAP.0, GAP.1) {
        Ok(seq) => seq,
        Err(FreshnessError::RingFull { .. }) => {
            let _ = view.publish_terminal(FRESHNESS_EXHAUSTED, fault);
            return false;
        }
        Err(error) => panic!("{error:?}"),
    };
    if fault != Fault::AckBeforeAppend
        && let Some(request) = request
    {
        mailbox.acknowledge(request).unwrap();
    }
    FreshSlotWords::new(&view.slots[0])
        .unwrap()
        .set_freshness(SlotFreshness {
            loss_applied: seq | STALE,
            stale_since: GAP.0,
        })
        .unwrap();
    view.barrier().retire_through(seq).unwrap();
    true
}

fn feeder(view: &View, scenario: Scenario, fault: Fault) {
    let mailbox = view.mailbox();
    if scenario != Scenario::AttachRace {
        let request = loop {
            if let Some(request) = mailbox.pending() {
                break request;
            }
            thread::yield_now();
        };
        assert_eq!((request.start, request.end), GAP, "torn request");
        let _ = serve(view, Some(request.request), fault);
        return;
    }
    mailbox.attach();
    // Catching up from the image log: the feeder stops at the hole until
    // it is resolved, through the mailbox or by the committed marker.
    let past = FreshSlotWords::new(&view.slots[1]).unwrap();
    if fault == Fault::PastValueBeforeAppend {
        let _ = past.write(&PAST.to_le_bytes()).unwrap();
    }
    loop {
        if let Some(request) = mailbox.pending() {
            let _ = serve(view, Some(request.request), fault);
            break;
        }
        if view.marker.load(Ordering::Acquire) == 1 {
            // Sealed before the attach: the feeder meets the marker itself.
            let _ = serve(view, None, fault);
            break;
        }
        thread::yield_now();
    }
    if fault != Fault::PastValueBeforeAppend {
        let _ = past.write(&PAST.to_le_bytes()).unwrap();
    }
}

/// The published terminal cell; a published body is complete.
fn terminal(view: &View) -> Option<Terminal> {
    let terminal = TerminalCell::read(&view.terminal.as_slice())?;
    assert!(
        (terminal.start, terminal.end) == GAP
            && [BARRIER_TIMEOUT, FRESHNESS_EXHAUSTED].contains(&terminal.reason),
        "incomplete terminal cell: {terminal:?}"
    );
    Some(terminal)
}

/// The value's position and freshness, or `None` to copy again.
fn read_value(view: &View) -> Option<Freshness> {
    let before = terminal(view);
    let words = view.barrier.as_slice();
    let snapshot = BarrierSnapshot::take(&words, RING).ok()?;
    let mut out = [0u8; 8];
    let FreshRead::Value { freshness, .. } =
        FreshSlotWords::new(&view.slots[0]).unwrap().read(&mut out)
    else {
        return None;
    };
    let position = u64::from_le_bytes(out);
    assert_eq!(position, POSITION, "torn value");
    let classified = snapshot.classify(&words, freshness, position);
    let after = terminal(view);
    // A published terminal cell makes every value below its end stale.
    if let Some(terminal) = before.or(after)
        && position < terminal.end
    {
        return Some(Freshness::Stale {
            since: terminal.start,
        });
    }
    Some(classified)
}

fn reader(view: &View, scenario: Scenario) {
    if scenario == Scenario::AttachRace {
        // The feeder's frontier: a value past the interval.
        let mut out = [0u8; 8];
        let past = matches!(
            FreshSlotWords::new(&view.slots[1]).unwrap().read(&mut out),
            FreshRead::Value { .. }
        );
        if let Some(freshness) = read_value(view)
            && past
        {
            assert_ne!(freshness, Freshness::Fresh, "fresh past the frontier");
        }
        return;
    }
    let marked = view.marker.load(Ordering::Acquire) == 1;
    if let Some(freshness) = read_value(view)
        && marked
    {
        assert_ne!(freshness, Freshness::Fresh, "fresh after a committed gap");
    }
}

fn model(scenario: Scenario, fault: Fault) {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(2);
    builder.check(move || {
        let view = Arc::new(View::new(scenario));
        let threads = [owner, feeder].map(|program| {
            let view = Arc::clone(&view);
            thread::spawn(move || program(&view, scenario, fault))
        });
        let reading = {
            let view = Arc::clone(&view);
            thread::spawn(move || reader(&view, scenario))
        };
        for thread in threads {
            thread.join().unwrap();
        }
        reading.join().unwrap();
        // Exactly one terminal publication wins where one is due.
        let winners = view.winners.load(Ordering::Relaxed);
        match scenario {
            Scenario::RingFull => assert_eq!(winners, 1, "exactly one terminal publication"),
            Scenario::AckPath | Scenario::AttachRace => assert_eq!(winners, 0),
            Scenario::Timeout => assert!(winners <= 1, "exactly one terminal publication"),
        }
    });
}

#[test]
fn the_ack_path_never_shows_a_sealed_value_fresh() {
    model(Scenario::AckPath, Fault::None);
}

#[test]
fn a_timeout_publishes_the_terminal_cell_before_the_seal() {
    model(Scenario::Timeout, Fault::None);
}

#[test]
fn a_full_ring_and_a_timeout_publish_one_terminal_cell() {
    model(Scenario::RingFull, Fault::None);
}

#[test]
fn an_attach_racing_a_seal_never_shows_a_value_fresh_past_the_frontier() {
    model(Scenario::AttachRace, Fault::None);
}

#[test]
#[should_panic(expected = "ack before the record")]
fn control_an_ack_before_the_append_is_observed_without_its_record() {
    model(Scenario::AckPath, Fault::AckBeforeAppend);
}

#[test]
#[should_panic(expected = "fresh after a committed gap")]
fn control_a_seal_before_the_ack_shows_a_sealed_value_fresh() {
    model(Scenario::AckPath, Fault::SealBeforeAck);
}

#[test]
#[should_panic(expected = "incomplete terminal cell")]
fn control_a_terminal_body_after_its_publication_is_incomplete() {
    model(Scenario::Timeout, Fault::TerminalBodyAfterPublication);
}

#[test]
#[should_panic(expected = "incomplete terminal cell")]
fn control_a_relaxed_terminal_publication_is_incomplete() {
    model(Scenario::Timeout, Fault::RelaxedTerminalPublication);
}

#[test]
#[should_panic(expected = "exactly one terminal publication")]
fn control_a_second_terminal_claim_that_succeeds_publishes_twice() {
    model(Scenario::RingFull, Fault::SecondClaimSucceeds);
}

#[test]
#[should_panic(expected = "fresh after a committed gap")]
fn control_a_seal_after_a_failed_claim_without_its_publication_reads_fresh() {
    model(Scenario::RingFull, Fault::SealAfterFailedClaim);
}

#[test]
#[should_panic(expected = "fresh past the frontier")]
fn control_a_value_past_the_marker_before_the_append_reads_fresh() {
    model(Scenario::AttachRace, Fault::PastValueBeforeAppend);
}
