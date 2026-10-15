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

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use karyos_sys::log_buffer::{ConcurrentPublication, LogBuffer, Publication, Subscription};
use karyos_sys::term_bytes::{HeapTerms, TermBytes};

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
}

impl<T: TermBytes> Successor<T> {
    /// The successor mapping's buffer.
    #[must_use]
    pub fn buffer(&self) -> &LogBuffer<T> {
        match self {
            Self::Publication(inner) => inner.buffer(),
            Self::Concurrent(inner) => inner.buffer(),
            Self::Subscription { inner, .. } => inner.buffer(),
        }
    }
}

/// The link's state, as the driver sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
}

#[derive(Debug)]
enum State<T: TermBytes = HeapTerms> {
    Current,
    Pending,
    Offered { base: u64, successor: Successor<T> },
    Fenced,
}

/// What a handle finds when its mapping ended.
#[derive(Debug)]
pub(crate) enum Next<T: TermBytes = HeapTerms> {
    /// The cutover is pending: retry later.
    Wait,
    /// Moved: the successor and its base, now the handle's.
    Moved { base: u64, successor: Successor<T> },
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
        match link.map(GenerationLink::status) {
            Some(LinkStatus::Pending | LinkStatus::Offered) => Self::Retry,
            _ => Self::Closed,
        }
    }
}

/// The link shared by one handle and its driver.
#[derive(Debug)]
pub struct GenerationLink<T: TermBytes = HeapTerms> {
    state: Mutex<State<T>>,
}

impl<T: TermBytes> GenerationLink<T> {
    /// A link in the `Current` state.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State::Current),
        })
    }

    fn lock(&self) -> MutexGuard<'_, State<T>> {
        // Every transition below is a single assignment, so a panic in
        // another holder never leaves a partial state.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The link's state.
    #[must_use]
    pub fn status(&self) -> LinkStatus {
        match *self.lock() {
            State::Current => LinkStatus::Current,
            State::Pending => LinkStatus::Pending,
            State::Offered { .. } => LinkStatus::Offered,
            State::Fenced => LinkStatus::Fenced,
        }
    }

    /// Driver: a cutover started. Only a `Current` link becomes `Pending`;
    /// returns whether it did.
    pub fn set_pending(&self) -> bool {
        let mut state = self.lock();
        if matches!(*state, State::Current) {
            *state = State::Pending;
            true
        } else {
            false
        }
    }

    /// Driver: the cutover opened at `base`. A `Pending` link is offered
    /// `successor`; any other state gives it back.
    ///
    /// # Errors
    ///
    /// Returns the successor when the link is not pending, or when its
    /// mapping starting at `base` is not [`representable`].
    pub fn offer(&self, base: u64, successor: Successor<T>) -> Result<(), Successor<T>> {
        if !representable(base, successor.buffer()) {
            return Err(successor);
        }
        let mut state = self.lock();
        if matches!(*state, State::Pending) {
            *state = State::Offered { base, successor };
            Ok(())
        } else {
            Err(successor)
        }
    }

    /// Driver: fences a `Pending` or `Offered` link and returns the
    /// successor it reserved, if any, for the driver to drop or reissue. A
    /// `Current` link (the handle already moved) or a `Fenced` one is left
    /// as it is, and `None` is returned.
    pub fn fence(&self) -> Option<Successor<T>> {
        let mut state = self.lock();
        match core::mem::replace(&mut *state, State::Fenced) {
            State::Offered { successor, .. } => Some(successor),
            State::Pending | State::Fenced => None,
            current @ State::Current => {
                *state = current;
                None
            }
        }
    }

    /// Handle: its mapping ended. Takes an offered successor (the link is
    /// `Current` again, for a later cutover), or reports a pending cutover
    /// or the end. A `Current` link means no cutover was started: the end.
    pub(crate) fn next(&self) -> Next<T> {
        let mut state = self.lock();
        match core::mem::replace(&mut *state, State::Current) {
            State::Offered { base, successor } => Next::Moved { base, successor },
            State::Pending => {
                *state = State::Pending;
                Next::Wait
            }
            State::Fenced => {
                *state = State::Fenced;
                Next::End
            }
            State::Current => Next::End,
        }
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
            })
            .unwrap(),
        );
        Successor::Publication(buffer.publication_owned().unwrap().unwrap())
    }

    #[test]
    fn a_link_moves_through_pending_and_offered_to_current() {
        let link = GenerationLink::<HeapTerms>::new();
        assert_eq!(link.status(), LinkStatus::Current);
        assert!(matches!(link.next(), Next::End));
        assert!(link.offer(5, successor()).is_err());
        assert!(link.set_pending());
        assert!(!link.set_pending());
        assert!(matches!(link.next(), Next::Wait));
        assert!(link.offer(5, successor()).is_ok());
        assert_eq!(link.status(), LinkStatus::Offered);
        assert!(matches!(link.next(), Next::Moved { base: 5, .. }));
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
        assert!(matches!(link.next(), Next::End));
        assert!(matches!(link.next(), Next::End));
        assert!(!link.set_pending());
        assert!(link.offer(9, successor()).is_err());
    }

    #[test]
    fn a_pending_link_can_be_fenced_before_any_offer() {
        let link = GenerationLink::<HeapTerms>::new();
        assert!(link.set_pending());
        assert!(link.fence().is_none());
        assert_eq!(link.status(), LinkStatus::Fenced);
        assert!(matches!(link.next(), Next::End));
    }
}
