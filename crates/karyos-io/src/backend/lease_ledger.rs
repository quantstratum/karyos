// SPDX-License-Identifier: Apache-2.0

//! The leases a borrowing backend holds (R-CORE-45; SPEC.md §16.6, §16.7;
//! `quantstratum-docs: karyos/design/backend-contract.md`, borrowed-term
//! TX).
//!
//! A backend that implements [`super::TxBackend::submit_borrowed`] keeps
//! each lease here, keyed by its item's ticket, until its contract proves
//! the bytes are no longer referenced: a completion's release, a returned
//! item, or a reset that resolved it. The ledger is allocated at creation
//! for the sender's declared bound of pinned terms and never grows: one
//! past it is refused, with its lease. A reset waits for every lease to
//! end; past the retirement bound it reports the endpoint stuck, typed,
//! and keeps the leases, so the terms stay pinned: a timeout never frees
//! bytes a device may still read.

use karyos_sys::host_clock::age_ns;
use karyos_sys::log_buffer::ReadLease;

use super::TxTicket;

/// The leases a borrowing backend holds, keyed by ticket.
#[derive(Debug)]
pub struct LeaseLedger {
    held: Vec<Option<(TxTicket, ReadLease)>>,
    /// How long a reset may wait for its leases to end, in nanoseconds of
    /// the caller's clock.
    retirement_bound: u64,
    /// When the current reset first found a lease outstanding.
    draining_since: Option<u64>,
    /// The current reset was counted stuck.
    stuck_counted: bool,
    counters: LeaseLedgerCounters,
}

/// A [`LeaseLedger`]'s counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LeaseLedgerCounters {
    /// Leases taken into the ledger.
    pub held: u64,
    /// Leases ended by the ledger.
    pub released: u64,
    /// Leases refused with the ledger full.
    pub refused: u64,
    /// Resets that outlived the retirement bound with leases outstanding.
    pub stuck: u64,
    /// An increment did not apply.
    pub overflowed: bool,
}

impl LeaseLedgerCounters {
    fn bump(&mut self, field: fn(&mut Self) -> &mut u64) {
        let value = field(self);
        match value.checked_add(1) {
            Some(next) => *value = next,
            None => self.overflowed = true,
        }
    }
}

/// Where a reset's leases stand ([`LeaseLedger::reset_drain`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
pub enum ResetDrain {
    /// No lease is held: the reset may complete.
    Done,
    /// Leases are still held within the retirement bound: call again.
    Waiting {
        /// The leases held.
        outstanding: usize,
    },
    /// Leases are still held past the retirement bound: the endpoint
    /// fails, and its terms stay pinned until the leases end.
    Stuck {
        /// The leases held.
        outstanding: usize,
    },
}

impl LeaseLedger {
    /// A ledger for at most `capacity` leases, allocated here, whose
    /// resets wait at most `retirement_bound` nanoseconds for them.
    #[must_use]
    pub fn new(capacity: usize, retirement_bound: u64) -> Self {
        let mut held = Vec::with_capacity(capacity);
        held.resize_with(capacity, || None);
        Self {
            held,
            retirement_bound,
            draining_since: None,
            stuck_counted: false,
            counters: LeaseLedgerCounters::default(),
        }
    }

    /// Keeps `lease` for the item `ticket`.
    ///
    /// # Errors
    ///
    /// The lease back, still held, when the ledger is full.
    pub fn hold(&mut self, ticket: TxTicket, lease: ReadLease) -> Result<(), ReadLease> {
        let Some(free) = self.held.iter_mut().find(|entry| entry.is_none()) else {
            self.counters.bump(|c| &mut c.refused);
            return Err(lease);
        };
        *free = Some((ticket, lease));
        self.counters.bump(|c| &mut c.held);
        Ok(())
    }

    /// Ends the lease of `ticket`, once its contract proved the bytes are
    /// no longer referenced (a release, a returned item). `false` when no
    /// lease is held for it.
    pub fn release(&mut self, ticket: TxTicket) -> bool {
        let Some(entry) = self
            .held
            .iter_mut()
            .find(|entry| entry.as_ref().is_some_and(|(held, _)| *held == ticket))
        else {
            return false;
        };
        // Dropping the lease ends it.
        *entry = None;
        self.counters.bump(|c| &mut c.released);
        true
    }

    /// The leases held.
    #[must_use]
    pub fn live(&self) -> usize {
        self.held.iter().filter(|entry| entry.is_some()).count()
    }

    /// A reset's check at `now`: [`ResetDrain::Done`] once no lease is
    /// held; otherwise waiting, and stuck once `retirement_bound` has
    /// passed since the first check that found one (each stuck reset
    /// counted once). A clock behind that check counts as no time elapsed.
    pub fn reset_drain(&mut self, now: u64) -> ResetDrain {
        let outstanding = self.live();
        if outstanding == 0 {
            self.draining_since = None;
            self.stuck_counted = false;
            return ResetDrain::Done;
        }
        let since = *self.draining_since.get_or_insert(now);
        if age_ns(now, since) < self.retirement_bound {
            return ResetDrain::Waiting { outstanding };
        }
        if !self.stuck_counted {
            self.stuck_counted = true;
            self.counters.bump(|c| &mut c.stuck);
        }
        ResetDrain::Stuck { outstanding }
    }

    /// The counters.
    #[must_use]
    pub fn counters(&self) -> LeaseLedgerCounters {
        self.counters
    }
}
