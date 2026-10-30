// SPDX-License-Identifier: Apache-2.0

//! The borrowed-term TX operation (R-CORE-45): the sockets backend stages
//! a lease through the trait's default, sending the very bytes a copy read
//! sends; and the [`LeaseLedger`] a borrowing backend keeps its leases in.

use std::sync::{Arc, Mutex};

use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{
    AppendOptions, DEFAULT_CLAIM_DEADLINE, DEFAULT_CORRUPT_RETRIES, LeaseOutcome, LogBuffer,
    LogBufferConfig, PublicationMode, ReadLease, ReadOrigin, ReadOutcome, Role, SenderRead,
};
use karyos_sys::sizing::{MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

use super::*;
use crate::backend::{BorrowError, LeaseLedger, ResetDrain, TxBackend as _, TxItemOutcome};
use crate::sockets::ops::SendResult;

/// A datagram of the harness: [`config`]'s 256 bytes.
const DATAGRAM: usize = 256;

fn buffer() -> Arc<LogBuffer> {
    let buffer = Arc::new(
        LogBuffer::new(LogBufferConfig {
            term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
            spare_slots: 3,
            max_subscribers: 2,
            mtu: DATAGRAM as u32,
            max_reserved: MIN_TERM_LENGTH / 8,
            initial_term_id: TermId::new(0),
            lane: Lane::ZERO,
            session_id: 1,
            stream_id: 2,
            publication: PublicationMode::Exclusive,
            claim_deadline: DEFAULT_CLAIM_DEADLINE,
            schedule_capacity: 0,
        })
        .unwrap(),
    );
    buffer.install_leases(4).unwrap();
    buffer
}

/// The sender's reader of `buffer`, joined before three messages are
/// published.
fn reader(buffer: &Arc<LogBuffer>) -> SenderRead<Arc<LogBuffer>> {
    let mut conductor = buffer.conductor_owned().unwrap();
    let reader = SenderRead::new(
        conductor.subscribe_as(Role::Required, true, 1).unwrap(),
        DEFAULT_CORRUPT_RETRIES,
    )
    .unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    for (index, len) in [40usize, 73, 21, 90, 33].into_iter().enumerate() {
        let message: Vec<u8> = (0..len).map(|i| (i as u8) ^ (index as u8 * 31)).collect();
        let _ = publication
            .append(&message, AppendOptions::default())
            .unwrap();
    }
    reader
}

fn lease(reader: &mut SenderRead<Arc<LogBuffer>>) -> ReadLease {
    match reader.lease_committed(reader.position(), ReadOrigin::Cursor, DATAGRAM) {
        Ok(LeaseOutcome::Leased(lease)) => lease,
        other => panic!("not leased: {other:?}"),
    }
}

/// A harness whose sends succeed and whose sent datagrams are recorded.
fn recording() -> (Harness, Arc<Mutex<Vec<Vec<u8>>>>) {
    let h = Harness::new();
    let sent = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&sent);
    h.socket.set_send_hook(Box::new(move |_route, datagrams| {
        for datagram in datagrams {
            log.lock().unwrap().push(datagram.to_vec());
        }
    }));
    for _ in 0..8 {
        h.socket.push_send(SendResult::Sent {
            sent: 1,
            error: None,
        });
    }
    (h, sent)
}

/// The sockets backend does not borrow: `submit_borrowed` stages through
/// the default, and the datagram on the wire is byte for byte the one a
/// copy read and an ordinary claim and commit send. The lease ends once
/// staged.
#[test]
fn a_staged_lease_sends_what_a_copy_sends() {
    // Copied.
    let copied_buffer = buffer();
    let mut copying = reader(&copied_buffer);
    let mut out = vec![0u8; DATAGRAM];
    let Ok(ReadOutcome::Copied { len, .. }) =
        copying.read_committed(copying.position(), ReadOrigin::Cursor, &mut out)
    else {
        panic!("not copied");
    };
    let (mut h, sent_copied) = recording();
    let _ = h.commit_to(h.queue, &out[..len], 1);
    let _ = h.flush(&mut Gate::default());
    // Leased, then staged by the default.
    let leased_buffer = buffer();
    let mut leasing = reader(&leased_buffer);
    let leased = lease(&mut leasing);
    assert_eq!(leased.len(), len);
    let (mut h2, sent_leased) = recording();
    let queue = h2.queue;
    assert!(
        h2.tx
            .submit_borrowed(queue, leased, SenderToken::new(1), TxOptions::none())
            .is_ok()
    );
    assert_eq!(leased_buffer.leases_live(), 0, "ended once staged");
    let _ = h2.flush(&mut Gate::default());
    let copied = sent_copied.lock().unwrap().clone();
    let leased = sent_leased.lock().unwrap().clone();
    assert_eq!(copied.len(), 1);
    assert_eq!(leased, copied, "byte for byte");
}

/// A staged lease the claim refuses comes back, still held, with why.
#[test]
fn a_refused_staging_hands_the_lease_back() {
    let buffer = buffer();
    let mut leasing = reader(&buffer);
    let leased = lease(&mut leasing);
    let mut h = Harness::open(config(), 1);
    // The queue's one place taken.
    let _ = h.commit_n(0, 1);
    let queue = h.queue;
    let rejected =
        h.tx.submit_borrowed(queue, leased, SenderToken::new(2), TxOptions::none())
            .unwrap_err();
    assert!(matches!(
        rejected.error,
        BorrowError::Claim(ClaimError::QueueFull { .. })
    ));
    assert_eq!(buffer.leases_live(), 1, "still held");
    drop(rejected);
    assert_eq!(buffer.leases_live(), 0);
}

/// A borrowing backend's ledger: a lease is held until its ticket is
/// released, at most `capacity` at once (one more is handed back), and
/// each ends exactly once.
#[test]
fn a_ledger_holds_each_lease_until_released() {
    let buffer = buffer();
    let mut leasing = reader(&buffer);
    let mut h = Harness::new();
    let tickets = h.commit_n(0, 2);
    let mut ledger = LeaseLedger::new(1, 1_000);
    ledger.hold(tickets[0], lease(&mut leasing)).unwrap();
    assert_eq!((ledger.live(), buffer.leases_live()), (1, 1));
    // Full: the next is handed back, still held, and counted.
    let next = lease(&mut leasing);
    let back = ledger.hold(tickets[1], next).unwrap_err();
    assert_eq!(buffer.leases_live(), 2);
    drop(back);
    assert_eq!(ledger.counters().refused, 1);
    assert!(!ledger.release(tickets[1]), "not held");
    assert!(ledger.release(tickets[0]));
    assert!(!ledger.release(tickets[0]), "once");
    assert_eq!((ledger.live(), buffer.leases_live()), (0, 0));
    let counters = ledger.counters();
    assert_eq!((counters.held, counters.released), (1, 1));
}

/// A reset waits for every lease: within the retirement bound it waits;
/// past it the endpoint is stuck, counted once, and the lease is kept, so
/// its term stays pinned; once released the reset is done. A clock behind
/// the first check counts as no time elapsed.
#[test]
fn a_reset_past_the_bound_with_a_lease_held_is_stuck() {
    let buffer = buffer();
    let mut leasing = reader(&buffer);
    let mut h = Harness::new();
    let ticket = h.commit_n(0, 1)[0];
    let mut ledger = LeaseLedger::new(2, 1_000);
    assert_eq!(ledger.reset_drain(5), ResetDrain::Done);
    ledger.hold(ticket, lease(&mut leasing)).unwrap();
    assert_eq!(
        ledger.reset_drain(100),
        ResetDrain::Waiting { outstanding: 1 }
    );
    assert_eq!(
        ledger.reset_drain(50),
        ResetDrain::Waiting { outstanding: 1 }
    );
    assert_eq!(
        ledger.reset_drain(1_099),
        ResetDrain::Waiting { outstanding: 1 }
    );
    assert_eq!(
        ledger.reset_drain(1_100),
        ResetDrain::Stuck { outstanding: 1 }
    );
    assert_eq!(
        ledger.reset_drain(9_000),
        ResetDrain::Stuck { outstanding: 1 }
    );
    assert_eq!(ledger.counters().stuck, 1, "counted once");
    assert_eq!(buffer.leases_live(), 1, "never freed on a timeout");
    assert!(ledger.release(ticket));
    assert_eq!(ledger.reset_drain(9_001), ResetDrain::Done);
    assert_eq!(buffer.leases_live(), 0);
}

/// A borrowing backend for the contract's lifecycle: it sends through the
/// scripted sockets backend, and keeps each lease in its ledger as a
/// device would, past submission, until a completion or a returned item
/// proves the bytes are no longer referenced.
struct Borrowing<'h> {
    tx: &'h mut SocketsTx<ScriptedSocket>,
    ledger: LeaseLedger,
    /// Items submitted whose completion has not come yet.
    in_flight: Vec<TxTicket>,
}

impl<'h> Borrowing<'h> {
    fn new(tx: &'h mut SocketsTx<ScriptedSocket>, capacity: usize) -> Self {
        Self {
            tx,
            ledger: LeaseLedger::new(capacity, 1_000),
            in_flight: Vec::new(),
        }
    }

    /// Queues the lease's frames; the lease stays held.
    fn submit(&mut self, queue: TxQueueId, lease: ReadLease) -> TxTicket {
        let mut frame = self.tx.claim_tx(queue, lease.len()).unwrap();
        let len = lease.copy_to(frame.bytes_mut()).unwrap();
        let ticket = frame
            .commit(Commit {
                len,
                token: SenderToken::new(7),
                options: TxOptions::none(),
            })
            .unwrap();
        self.ledger.hold(ticket, lease).unwrap();
        ticket
    }

    /// Flushes: a submitted item is in flight, a returned one ends its
    /// lease at once.
    fn flush(&mut self, queue: TxQueueId) {
        let mut report = TxReport::new();
        let _ = self.tx.flush(
            FlushRequest {
                queue,
                max_datagrams: nz(64),
                max_bytes: u32::MAX,
            },
            &mut Gate::default(),
            &mut report,
        );
        self.settle(&mut report);
    }

    /// Cancels `queue`'s pending items: each returned one ends its lease.
    fn cancel(&mut self, queue: TxQueueId) {
        let mut report = TxReport::new();
        let _ = self.tx.cancel_pending(queue, &mut report).unwrap();
        self.settle(&mut report);
    }

    fn settle(&mut self, report: &mut TxReport) {
        while let Some(entry) = report.pop_front() {
            match entry.outcome {
                TxItemOutcome::Submitted { .. } => self.in_flight.push(entry.ticket),
                TxItemOutcome::Returned { .. } => {
                    assert!(self.ledger.release(entry.ticket));
                }
                _ => {}
            }
        }
    }

    /// The device's completion of every item in flight.
    fn complete(&mut self) {
        for ticket in self.in_flight.drain(..) {
            assert!(self.ledger.release(ticket));
        }
    }
}

/// A borrowing backend keeps its lease past submission and ends it at the
/// completion: the term stays pinned while the device may read it.
#[test]
fn a_borrowed_lease_lives_until_its_completion() {
    let buffer = buffer();
    let mut leasing = reader(&buffer);
    let (mut h, sent) = recording();
    let queue = h.queue;
    let mut backend = Borrowing::new(&mut h.tx, 4);
    let _ = backend.submit(queue, lease(&mut leasing));
    assert_eq!(buffer.leases_live(), 1, "held at commit");
    backend.flush(queue);
    assert_eq!(sent.lock().unwrap().len(), 1, "on the wire");
    assert_eq!(buffer.leases_live(), 1, "held past submission");
    backend.complete();
    assert_eq!(buffer.leases_live(), 0, "ended at the completion");
    assert_eq!(backend.ledger.reset_drain(0), ResetDrain::Done);
}

/// Items returned before exposure (cancelled, or by a reset) end their
/// leases at once: the reset that follows finds none.
#[test]
fn returned_items_end_their_leases() {
    let buffer = buffer();
    let mut leasing = reader(&buffer);
    let mut h = Harness::new();
    let queue = h.queue;
    let mut backend = Borrowing::new(&mut h.tx, 4);
    let _ = backend.submit(queue, lease(&mut leasing));
    let _ = backend.submit(queue, lease(&mut leasing));
    assert_eq!(buffer.leases_live(), 2);
    backend.cancel(queue);
    assert_eq!(buffer.leases_live(), 0);
    assert_eq!(backend.ledger.reset_drain(0), ResetDrain::Done);
}

/// A device that never completes: the reset waits within the bound, then
/// reports the endpoint stuck, and the lease is kept, its term pinned.
#[test]
fn a_lease_never_completed_leaves_the_reset_stuck() {
    let buffer = buffer();
    let mut leasing = reader(&buffer);
    let (mut h, _sent) = recording();
    let queue = h.queue;
    let mut backend = Borrowing::new(&mut h.tx, 4);
    let _ = backend.submit(queue, lease(&mut leasing));
    backend.flush(queue);
    assert_eq!(
        backend.ledger.reset_drain(10),
        ResetDrain::Waiting { outstanding: 1 }
    );
    assert_eq!(
        backend.ledger.reset_drain(1_010),
        ResetDrain::Stuck { outstanding: 1 }
    );
    assert_eq!(buffer.leases_live(), 1, "pinned, never freed on a timeout");
    backend.complete();
    assert_eq!(backend.ledger.reset_drain(1_011), ResetDrain::Done);
}

/// Taking a lease, staging it through the default, and a ledger's hold
/// and release allocate nothing: the data path stays allocation free.
#[test]
fn leasing_and_staging_allocate_nothing() {
    let buffer = buffer();
    let mut leasing = reader(&buffer);
    let mut h = Harness::new();
    let queue = h.queue;
    let tickets = h.commit_n(0, 1);
    let mut ledger = LeaseLedger::new(1, 1_000);
    let ((), allocations) = karyos_sys::alloc_count::count(|| {
        let staged = lease(&mut leasing);
        assert!(
            h.tx.submit_borrowed(queue, staged, SenderToken::new(3), TxOptions::none())
                .is_ok()
        );
        let kept = lease(&mut leasing);
        ledger.hold(tickets[0], kept).unwrap();
        assert!(ledger.release(tickets[0]));
    });
    assert_eq!(allocations, 0);
}
