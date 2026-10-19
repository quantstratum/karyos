// SPDX-License-Identifier: Apache-2.0

//! The generation link of a client handle (`quantstratum-docs: karyos/design/mapping-generations.md`,
//! g2): how a handle learns of, and moves to, the successor of the mapping it
//! uses.
//!
//! Each handle shares one link with the driver. The driver marks a cutover
//! pending, offers a successor capability with its base once the cutover
//! opens, or fences the handle. The handle reads the link only after its sys
//! handle reported the end of its mapping (`Closed` from a publisher, the seal
//! position from a subscriber), which is the slow path; the data path never
//! touches it. The state sits behind a mutex: the driver's fence and the
//! handle's move are both transitions under it, so exactly one of them wins
//! for an offered successor.
//!
//! A remote handle's link is fed by its client's control path instead
//! (`quantstratum-docs: karyos/design/ipc-data-path.md`, Generations across
//! processes). Its successor arrives prepared, not adopted: the handle
//! activates it when it reaches the seal, a bounded and allocation-free
//! step, and leaves its predecessor in the link's retired slot, which the
//! control path drops later (unmapping it and sending its `Detach`). A
//! remote handle learns of a cutover only from the driver's broadcast, which
//! can come after its data path sees the seal; the seal word marks whether
//! a successor exists (owner decision 2026-10-15, ACS 13103). A remote link
//! reports a seal with a successor as pending until the control path offers
//! the successor or closes the link, and a seal without one as the end.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use karyos_sys::log_buffer::{
    ConcurrentPublication, LogBuffer, PreparedConcurrentPublication, PreparedPublication,
    PreparedSubscription, Publication, SenderRead, Subscription,
};
use karyos_sys::term_bytes::{HeapTerms, TermBytes};

use crate::link::Export;

/// Stream positions stay below `2^63` (SPEC.md §4).
pub const POSITION_LIMIT: u64 = 1 << 63;

/// Whether a mapping of `buffer` starting at stream position `base` keeps
/// every position it can report below [`POSITION_LIMIT`]: a mapping spans
/// fewer than `2^31` terms, so its local positions stay below
/// `2^31 × term_length`. Handles accept only such bases, so their
/// `base + local` additions never overflow.
#[must_use]
pub fn representable<T: TermBytes>(base: u64, buffer: &LogBuffer<T>) -> bool {
    let span = (1u64 << 31) * u64::from(buffer.term_length());
    base.checked_add(span)
        .is_some_and(|end| end <= POSITION_LIMIT)
}

/// A successor capability reserved for one handle.
#[derive(Debug)]
#[non_exhaustive]
pub enum Successor<T: TermBytes = HeapTerms> {
    /// The successor's exclusive publication.
    Publication(Publication<Arc<LogBuffer<T>>>),
    /// A publisher slot of the successor.
    Concurrent(ConcurrentPublication<Arc<LogBuffer<T>>>),
    /// A subscriber cell of the successor, with the private copy buffer for
    /// its largest message, allocated by the driver on the control path.
    Subscription {
        /// The cell.
        inner: Subscription<Arc<LogBuffer<T>>>,
        /// The copy buffer.
        scratch: Box<[u8]>,
    },
    /// A recording reader's cell of the successor (mapping-generations.md,
    /// "Recordings"), its read capability built by the driver on the
    /// control path.
    Recording(Box<SenderRead<Arc<LogBuffer<T>>>>),
    /// A remote grant's exclusive publication, prepared on the control path
    /// and activated by the handle at the seal.
    PreparedPublication {
        /// The prepared adoption.
        prepared: PreparedPublication<Arc<LogBuffer<T>>>,
        /// The successor grant's export, sent `Detach` when dropped.
        export: Export,
    },
    /// A remote grant's publisher slot, prepared as
    /// [`Successor::PreparedPublication`].
    PreparedConcurrent {
        /// The prepared adoption.
        prepared: PreparedConcurrentPublication<Arc<LogBuffer<T>>>,
        /// The successor grant's export.
        export: Export,
    },
    /// A remote grant's subscriber cell, prepared as
    /// [`Successor::PreparedPublication`], with its copy buffer.
    PreparedSubscription {
        /// The prepared adoption.
        prepared: PreparedSubscription<Arc<LogBuffer<T>>>,
        /// The copy buffer.
        scratch: Box<[u8]>,
        /// The successor grant's export.
        export: Export,
    },
}

impl<T: TermBytes> Successor<T> {
    /// The successor mapping's buffer.
    #[must_use]
    pub fn buffer(&self) -> &LogBuffer<T> {
        match self {
            Self::Publication(inner) => inner.buffer(),
            Self::Concurrent(inner) => inner.buffer(),
            Self::Subscription { inner, .. } => inner.buffer(),
            Self::Recording(inner) => inner.buffer(),
            Self::PreparedPublication { prepared, .. } => prepared.buffer(),
            Self::PreparedConcurrent { prepared, .. } => prepared.buffer(),
            Self::PreparedSubscription { prepared, .. } => prepared.buffer(),
        }
    }
}

/// What a remote handle leaves behind when it moves or fails to: dropped
/// by the control path, never by a data call. The handle goes first, so
/// the mapping is gone before the export's drop sends `Detach`.
#[derive(Debug)]
pub(crate) struct Retired<T: TermBytes = HeapTerms> {
    /// Held only for its drop.
    pub(crate) _handle: Option<RetiredHandle<T>>,
    /// Held only for its drop, after the handle's.
    pub(crate) _export: Option<Export>,
}

/// The sys handle of a [`Retired`] entry, held only for its drop.
#[derive(Debug)]
#[allow(dead_code, reason = "held only for its drop")]
pub(crate) enum RetiredHandle<T: TermBytes = HeapTerms> {
    /// A predecessor's exclusive publication.
    Publication(Publication<Arc<LogBuffer<T>>>),
    /// A predecessor's publisher slot.
    Concurrent(ConcurrentPublication<Arc<LogBuffer<T>>>),
    /// A predecessor's subscriber cell and copy buffer.
    Subscription {
        inner: Subscription<Arc<LogBuffer<T>>>,
        scratch: Box<[u8]>,
    },
    /// A successor whose activation failed.
    Successor(Successor<T>),
}

/// The link's state, as the driver sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LinkStatus {
    /// No cutover concerns the handle: it uses the stream's current mapping
    /// (after moving, if a cutover just opened).
    Current,
    /// A cutover is pending: the successor's base is not known yet.
    Pending,
    /// A successor capability is offered and not taken yet.
    Offered,
    /// Fenced: the handle will not move; its mapping is its last.
    Fenced,
    /// Closed: its mapping is its last and no successor can be offered.
    Closed,
}

#[derive(Debug)]
enum State<T: TermBytes = HeapTerms> {
    Current,
    Pending,
    Offered { base: u64, successor: Successor<T> },
    Fenced,
    Closed,
}

#[derive(Debug)]
struct Inner<T: TermBytes = HeapTerms> {
    state: State<T>,
    /// A remote handle's predecessor, until the control path drops it.
    retired: Option<Retired<T>>,
}

/// What a handle finds when its mapping ended.
#[derive(Debug)]
#[non_exhaustive]
pub enum Next<T: TermBytes = HeapTerms> {
    /// The cutover is pending: retry later.
    Wait,
    /// Moved: the successor and its base, now the handle's.
    Moved {
        /// The successor's base: the stream position of its first byte.
        base: u64,
        /// The successor capability.
        successor: Successor<T>,
    },
    /// No successor will come: fenced, or a seal without a successor.
    End,
}

/// What an ended mapping means for the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum End {
    /// A successor exists or will: `AdminAction`, retry.
    Retry,
    /// No successor: `Closed`.
    Closed,
}

impl End {
    /// The outcome the link announces, without moving.
    pub(crate) fn peek<T: TermBytes>(link: Option<&GenerationLink<T>>) -> Self {
        let Some(link) = link else {
            return Self::Closed;
        };
        match link.status() {
            LinkStatus::Pending | LinkStatus::Offered => Self::Retry,
            // Read before the seal word is: retry, and the next call decides
            // from the seal's successor mark.
            LinkStatus::Current if link.remote => Self::Retry,
            _ => Self::Closed,
        }
    }
}

/// The link shared by one handle and its driver.
#[derive(Debug)]
pub struct GenerationLink<T: TermBytes = HeapTerms> {
    inner: Mutex<Inner<T>>,
    /// Fed by a remote client's control path rather than by the driver.
    remote: bool,
}

impl<T: TermBytes> GenerationLink<T> {
    /// A link in the `Current` state.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Self::with_remote(false)
    }

    /// A remote handle's link, in the `Current` state: an unresolved seal
    /// reads as pending, and its control path offers prepared successors
    /// without a `Pending` step.
    #[cfg_attr(
        not(any(test, target_os = "linux")),
        allow(dead_code, reason = "remote clients exist only on Linux")
    )]
    #[must_use]
    pub(crate) fn new_remote() -> Arc<Self> {
        Self::with_remote(true)
    }

    fn with_remote(remote: bool) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                state: State::Current,
                retired: None,
            }),
            remote,
        })
    }

    fn lock(&self) -> MutexGuard<'_, Inner<T>> {
        // Every transition below is a single assignment, so a panic in
        // another holder never leaves a partial state.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The link's state.
    #[must_use]
    pub fn status(&self) -> LinkStatus {
        match self.lock().state {
            State::Current => LinkStatus::Current,
            State::Pending => LinkStatus::Pending,
            State::Offered { .. } => LinkStatus::Offered,
            State::Fenced => LinkStatus::Fenced,
            State::Closed => LinkStatus::Closed,
        }
    }

    /// Driver: a cutover started. Only a `Current` link becomes `Pending`;
    /// returns whether it did.
    pub fn set_pending(&self) -> bool {
        let mut inner = self.lock();
        if matches!(inner.state, State::Current) {
            inner.state = State::Pending;
            true
        } else {
            false
        }
    }

    /// Driver: the cutover opened at `base`. A `Pending` link, or a remote
    /// one still `Current`, is offered `successor`; any other state gives
    /// it back.
    ///
    /// # Errors
    ///
    /// Returns the successor when the link cannot take it, or when its
    /// mapping starting at `base` is not [`representable`].
    #[expect(
        clippy::result_large_err,
        reason = "the error gives the successor back by value, with its ownership; boxing it would allocate on the cutover path"
    )]
    pub fn offer(&self, base: u64, successor: Successor<T>) -> Result<(), Successor<T>> {
        if !representable(base, successor.buffer()) {
            return Err(successor);
        }
        let mut inner = self.lock();
        let takes = match inner.state {
            State::Pending => true,
            State::Current => self.remote,
            _ => false,
        };
        if takes {
            inner.state = State::Offered { base, successor };
            Ok(())
        } else {
            Err(successor)
        }
    }

    /// Driver: fences a `Pending` or `Offered` link and returns the
    /// successor it reserved, if any, for the driver to drop or reissue. A
    /// `Current` link (the handle already moved) or a `Fenced` one is left
    /// as it is, and `None` is returned. A `Closed` link stays closed.
    pub fn fence(&self) -> Option<Successor<T>> {
        let mut inner = self.lock();
        match core::mem::replace(&mut inner.state, State::Fenced) {
            State::Offered { successor, .. } => Some(successor),
            State::Pending | State::Fenced => None,
            kept @ (State::Current | State::Closed) => {
                inner.state = kept;
                None
            }
        }
    }

    /// Closes the link for good, whatever its state: the handle's mapping
    /// is its last. Returns the offered successor, if any, for the caller
    /// to drop outside the link.
    pub fn close(&self) -> Option<Successor<T>> {
        match core::mem::replace(&mut self.lock().state, State::Closed) {
            State::Offered { successor, .. } => Some(successor),
            _ => None,
        }
    }

    /// Handle: its mapping ended, with a seal that marks a `successor` or
    /// not. Takes an offered successor (the link is `Current` again, for a
    /// later cutover), or reports a pending cutover or the end. A `Current`
    /// link means no cutover was started: the end, except for a remote link
    /// whose seal marks a successor, whose control path has not heard of
    /// the cutover yet. A remote handle whose retired slot is still full
    /// waits until its control path empties it.
    pub fn next(&self, successor: bool) -> Next<T> {
        let mut inner = self.lock();
        if self.remote && inner.retired.is_some() && matches!(inner.state, State::Offered { .. }) {
            return Next::Wait;
        }
        match core::mem::replace(&mut inner.state, State::Current) {
            State::Offered { base, successor } => Next::Moved { base, successor },
            State::Pending => {
                inner.state = State::Pending;
                Next::Wait
            }
            State::Current if self.remote && successor => Next::Wait,
            ended @ (State::Fenced | State::Closed) => {
                inner.state = ended;
                Next::End
            }
            State::Current => Next::End,
        }
    }

    /// Remote handle: keeps what it left behind for the control path. The
    /// slot is empty when the handle moves ([`GenerationLink::next`] waits
    /// otherwise), so nothing is dropped here.
    pub(crate) fn retire(&self, retired: Retired<T>) {
        let mut inner = self.lock();
        debug_assert!(inner.retired.is_none(), "one retired entry at a time");
        if inner.retired.is_none() {
            inner.retired = Some(retired);
        }
    }

    /// Remote handle: its successor's activation failed (the driver's
    /// fence won): the link closes, keeping the successor for the control
    /// path.
    pub(crate) fn fail_activation(&self, retired: Retired<T>) {
        let mut inner = self.lock();
        inner.state = State::Closed;
        debug_assert!(inner.retired.is_none(), "one retired entry at a time");
        if inner.retired.is_none() {
            inner.retired = Some(retired);
        }
    }

    /// Control path: takes what the handle left behind, to drop it.
    #[cfg_attr(
        not(any(test, target_os = "linux")),
        allow(dead_code, reason = "remote clients exist only on Linux")
    )]
    pub(crate) fn take_retired(&self) -> Option<Retired<T>> {
        self.lock().retired.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use karyos_sys::frame::Lane;
    use karyos_sys::log_buffer::{DEFAULT_CLAIM_DEADLINE, LogBufferConfig, PublicationMode};
    use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
    use karyos_sys::term::TermId;

    fn successor() -> Successor {
        tracked().0
    }

    /// A successor whose buffer only it holds, and a weak reference that
    /// fails to upgrade once the successor is dropped.
    fn tracked() -> (Successor, std::sync::Weak<LogBuffer>) {
        let buffer = Arc::new(
            LogBuffer::new(LogBufferConfig {
                term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                spare_slots: 3,
                max_subscribers: 3,
                mtu: DEFAULT_MTU,
                max_reserved: MIN_TERM_LENGTH / 8,
                initial_term_id: TermId::new(7),
                lane: Lane::ZERO,
                session_id: 1,
                stream_id: 2,
                claim_deadline: DEFAULT_CLAIM_DEADLINE,
                publication: PublicationMode::Exclusive,
                schedule_capacity: 0,
            })
            .unwrap(),
        );
        let weak = Arc::downgrade(&buffer);
        let successor = Successor::Publication(buffer.publication_owned().unwrap().unwrap());
        drop(buffer);
        (successor, weak)
    }

    #[test]
    fn a_link_moves_through_pending_and_offered_to_current() {
        let link = GenerationLink::<HeapTerms>::new();
        assert_eq!(link.status(), LinkStatus::Current);
        assert!(matches!(link.next(true), Next::End));
        assert!(link.offer(5, successor()).is_err());
        assert!(link.set_pending());
        assert!(!link.set_pending());
        assert!(matches!(link.next(true), Next::Wait));
        assert!(link.offer(5, successor()).is_ok());
        assert_eq!(link.status(), LinkStatus::Offered);
        assert!(matches!(link.next(true), Next::Moved { base: 5, .. }));
        assert_eq!(link.status(), LinkStatus::Current);
        // Admitted: a late fence changes nothing.
        assert!(link.fence().is_none());
        assert_eq!(link.status(), LinkStatus::Current);
    }

    #[test]
    fn a_fence_wins_over_a_later_move_and_returns_the_successor() {
        let link = GenerationLink::<HeapTerms>::new();
        assert!(link.set_pending());
        assert!(link.offer(5, successor()).is_ok());
        assert!(matches!(link.fence(), Some(Successor::Publication(_))));
        assert_eq!(link.status(), LinkStatus::Fenced);
        assert!(matches!(link.next(true), Next::End));
        assert!(matches!(link.next(true), Next::End));
        assert!(!link.set_pending());
        assert!(link.offer(9, successor()).is_err());
    }

    #[test]
    fn a_remote_link_waits_at_an_unresolved_seal_and_takes_an_offer_without_pending() {
        let link = GenerationLink::<HeapTerms>::new_remote();
        assert!(matches!(link.next(true), Next::Wait));
        assert_eq!(End::peek(Some(&link)), End::Retry);
        assert!(link.offer(5, successor()).is_ok());
        assert!(matches!(link.next(true), Next::Moved { base: 5, .. }));
        assert_eq!(link.status(), LinkStatus::Current);
        // The next mapping's seal is unresolved again.
        assert!(matches!(link.next(true), Next::Wait));
    }

    #[test]
    fn a_remote_link_ends_at_a_seal_without_a_successor() {
        let link = GenerationLink::<HeapTerms>::new_remote();
        assert!(matches!(link.next(false), Next::End));
        // An offer that came first is still taken.
        assert!(link.offer(5, successor()).is_ok());
        assert!(matches!(link.next(false), Next::Moved { base: 5, .. }));
        // The in-process link ignores the mark.
        let link = GenerationLink::<HeapTerms>::new();
        assert!(matches!(link.next(true), Next::End));
    }

    #[test]
    fn a_remote_link_does_not_move_while_its_retired_slot_is_full() {
        let link = GenerationLink::<HeapTerms>::new_remote();
        link.retire(Retired {
            _handle: None,
            _export: None,
        });
        assert!(link.offer(5, successor()).is_ok());
        assert!(matches!(link.next(true), Next::Wait));
        assert_eq!(link.status(), LinkStatus::Offered);
        assert!(link.take_retired().is_some());
        assert!(link.take_retired().is_none());
        assert!(matches!(link.next(true), Next::Moved { base: 5, .. }));
    }

    #[test]
    fn the_counting_allocator_sees_an_allocation_and_its_free() {
        let ((), operations) = karyos_sys::alloc_count::count(|| {
            drop(std::hint::black_box(vec![0u8; 64]));
        });
        assert_eq!(operations, 2);
    }

    #[test]
    fn a_failed_activation_closes_the_link_and_keeps_what_it_held() {
        let link = GenerationLink::<HeapTerms>::new_remote();
        link.fail_activation(Retired {
            _handle: None,
            _export: None,
        });
        assert_eq!(link.status(), LinkStatus::Closed);
        assert!(matches!(link.next(true), Next::End));
        assert!(link.take_retired().is_some());
    }

    #[test]
    fn a_pending_link_can_be_fenced_before_any_offer() {
        let link = GenerationLink::<HeapTerms>::new();
        assert!(link.set_pending());
        assert!(link.fence().is_none());
        assert_eq!(link.status(), LinkStatus::Fenced);
        assert!(matches!(link.next(true), Next::End));
    }

    /// The link's states, reached from `Current`.
    #[derive(Debug, Clone, Copy)]
    enum Start {
        Current,
        Pending,
        Offered,
        Fenced,
    }

    /// Drives `link` to `start`; returns the weak reference of an offered
    /// successor.
    fn drive(link: &GenerationLink, start: Start) -> Option<std::sync::Weak<LogBuffer>> {
        match start {
            Start::Current => None,
            Start::Pending => {
                assert!(link.set_pending());
                None
            }
            Start::Offered => {
                assert!(link.set_pending());
                let (successor, weak) = tracked();
                assert!(link.offer(5, successor).is_ok());
                Some(weak)
            }
            Start::Fenced => {
                assert!(link.set_pending());
                assert!(link.fence().is_none());
                None
            }
        }
    }

    /// rejoin-policies.md, Tests: with a retained clone of the link, `close`
    /// from each of `Current`, `Pending`, `Offered` and `Fenced` is terminal;
    /// an offered successor is handed back and dropped.
    #[test]
    fn test_generation_link_close_is_terminal() {
        for remote in [false, true] {
            for start in [
                Start::Current,
                Start::Pending,
                Start::Offered,
                Start::Fenced,
            ] {
                let link = GenerationLink::<HeapTerms>::with_remote(remote);
                let retained = Arc::clone(&link);
                let offered = drive(&link, start);
                let returned = retained.close();
                assert_eq!(returned.is_some(), offered.is_some(), "{start:?}");
                drop(returned);
                if let Some(weak) = offered {
                    assert!(weak.upgrade().is_none(), "the offered successor is dropped");
                }
                drop(link);
                assert_eq!(retained.status(), LinkStatus::Closed, "{start:?}");
                assert_eq!(End::peek(Some(&retained)), End::Closed, "{start:?}");
                assert!(!retained.set_pending());
                let (late, weak) = tracked();
                let refused = retained.offer(9, late);
                assert!(refused.is_err(), "{start:?}: a late offer is given back");
                drop(refused);
                assert!(weak.upgrade().is_none());
                assert!(matches!(retained.next(true), Next::End));
                assert!(matches!(retained.next(false), Next::End));
                assert!(retained.fence().is_none());
                assert!(retained.close().is_none());
                assert_eq!(retained.status(), LinkStatus::Closed, "{start:?}");
            }
        }
    }

    /// `close` races the driver's cutover (`set_pending`, `offer`), its fence
    /// and the handle's move: every successor offered ends up with exactly
    /// one owner and is dropped, and the link ends `Closed`.
    #[test]
    fn close_races_the_cutover_the_fence_and_the_move() {
        for round in 0..500 {
            for remote in [false, true] {
                let link = GenerationLink::<HeapTerms>::with_remote(remote);
                let (successor, weak) = tracked();
                let start = std::sync::Barrier::new(4);
                std::thread::scope(|scope| {
                    scope.spawn(|| {
                        start.wait();
                        let _ = link.set_pending();
                        drop(link.offer(5, successor));
                    });
                    scope.spawn(|| {
                        start.wait();
                        drop(link.fence());
                    });
                    scope.spawn(|| {
                        start.wait();
                        drop(link.close());
                    });
                    scope.spawn(|| {
                        start.wait();
                        for _ in 0..4 {
                            match link.next(true) {
                                Next::Moved { successor, .. } => drop(successor),
                                Next::Wait => std::thread::yield_now(),
                                Next::End => break,
                            }
                        }
                    });
                });
                assert!(
                    weak.upgrade().is_none(),
                    "round {round}: the successor was kept"
                );
                // Close is terminal whatever won; a move before it left the
                // link `Current`, which close then ended.
                assert_eq!(link.status(), LinkStatus::Closed, "round {round}");
                assert!(!link.set_pending());
                assert!(matches!(link.next(true), Next::End));
            }
        }
    }
}
