// SPDX-License-Identifier: Apache-2.0

//! The effective-close acknowledgement (`quantstratum-docs:
//! karyos/design/guards-and-abort.md`, "The effective-close
//! acknowledgement"; `driver-network-agents.md` 6.3, DN-7; G-e4).
//!
//! Each sender gate serving a guard registers its [`AppliedEpoch`] cell
//! with the guard's owner, the driver
//! ([`EmbeddedDriver::register_guard_sender`]), and deregisters it when
//! the gate retires or its sender session ends. On a close the owner reads
//! every registered cell ([`EmbeddedDriver::close_guard_ack`]) and reports
//! each sender as applied, with its last submitted positions and the work
//! it still has in flight, or pending. A pending sender is never reported
//! as closed: past `DriverConfig::guard_ack_timeout` it is reported
//! overdue, still pending.
//!
//! A close is **effective** at a sender once the sender applied it and has
//! no work in flight; applied with work in flight is a distinct state,
//! never folded into either.

use std::sync::Arc;

use karyos_sys::applied_epoch::{Applied, AppliedEpoch};
use karyos_sys::frame::Lane;
use karyos_sys::guard::{GuardError, GuardState};

use crate::embedded::{EmbeddedDriver, StreamTerms};
use crate::error::DriverError;
use crate::guards::GuardHandle;

/// Attempts to read a cell whole before its sender is reported pending: a
/// writer that stays in the middle of a publication longer than this many
/// reads is not waited for.
pub const ACK_READ_ATTEMPTS: u32 = 8;

/// Names a registered sender gate of one driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GuardSenderId(u64);

impl GuardSenderId {
    /// The id, from 1, never reused within the driver.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// One sender's state in an acknowledgement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SenderAck {
    /// The sender applied the close: the last positions it submitted per
    /// lane under the closed epoch, and the backend work still in flight.
    Applied {
        /// The last position submitted per lane.
        positions: [u64; Lane::COUNT as usize],
        /// Work exposed and not yet settled.
        in_flight: u64,
    },
    /// The sender has not applied the close yet, or its cell could not be
    /// read whole; `overdue` once `guard_ack_timeout` has passed since the
    /// close.
    Pending {
        /// Whether the timeout passed.
        overdue: bool,
    },
}

impl SenderAck {
    /// Whether the close is effective at this sender: applied, and nothing
    /// in flight.
    #[must_use]
    pub const fn effective(&self) -> bool {
        matches!(self, Self::Applied { in_flight: 0, .. })
    }
}

/// Receivers the acknowledgement could not reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unreachable {
    /// No receiver membership is tracked yet: the network agents' sender
    /// sessions (phase 7 of driver-network-agents.md) will report it.
    NotTracked,
}

/// The effective-close acknowledgement of one close.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseAck {
    /// The close epoch acknowledged.
    pub epoch: u64,
    /// Every sender registered with the guard, in registration order.
    pub senders: Vec<(GuardSenderId, SenderAck)>,
    /// Receivers that could not be reached.
    pub unreachable: Unreachable,
}

impl CloseAck {
    /// Whether the close is effective at every registered sender; `None`
    /// when no sender is registered, which says nothing about one.
    #[must_use]
    pub fn effective(&self) -> Option<bool> {
        (!self.senders.is_empty()).then(|| self.senders.iter().all(|(_, ack)| ack.effective()))
    }
}

#[derive(Debug)]
struct Entry {
    id: GuardSenderId,
    guard: GuardHandle,
    cell: Arc<AppliedEpoch>,
}

/// The sender gates registered with their guards: bounded, in registration
/// order.
#[derive(Debug)]
pub(crate) struct GuardSenders {
    max: usize,
    entries: Vec<Entry>,
    next: u64,
}

impl GuardSenders {
    pub(crate) fn new(max: usize) -> Self {
        Self {
            max,
            entries: Vec::with_capacity(max),
            next: 1,
        }
    }
}

/// One whole read of `cell` within [`ACK_READ_ATTEMPTS`].
fn read(cell: &AppliedEpoch) -> Option<Applied> {
    (0..ACK_READ_ATTEMPTS).find_map(|_| cell.try_read())
}

impl<T: StreamTerms> EmbeddedDriver<T> {
    /// Registers a sender gate serving `guard`: the returned cell is the
    /// gate's, written by it alone, and read by
    /// [`EmbeddedDriver::close_guard_ack`] until
    /// [`EmbeddedDriver::deregister_guard_sender`].
    ///
    /// # Errors
    ///
    /// [`DriverError::UnknownGuard`]; [`DriverError::TooManyGuardSenders`]
    /// past `DriverConfig::max_guard_senders`;
    /// [`DriverError::GuardSenderIdsExhausted`] once ids run out.
    pub fn register_guard_sender(
        &mut self,
        guard: GuardHandle,
    ) -> Result<(GuardSenderId, Arc<AppliedEpoch>), DriverError> {
        let _ = self.guards.state(guard)?;
        let senders = &mut self.guard_senders;
        if senders.entries.len() >= senders.max {
            return Err(DriverError::TooManyGuardSenders);
        }
        let id = GuardSenderId(senders.next);
        senders.next = senders
            .next
            .checked_add(1)
            .ok_or(DriverError::GuardSenderIdsExhausted)?;
        let cell = Arc::new(AppliedEpoch::new());
        senders.entries.push(Entry {
            id,
            guard,
            cell: Arc::clone(&cell),
        });
        Ok((id, cell))
    }

    /// Deregisters a sender gate whose gate retired or whose sender session
    /// ended: later acknowledgements no longer list it.
    ///
    /// # Errors
    ///
    /// [`DriverError::UnknownGuardSender`] for a sender not registered.
    pub fn deregister_guard_sender(&mut self, sender: GuardSenderId) -> Result<(), DriverError> {
        let entries = &mut self.guard_senders.entries;
        let index = entries
            .iter()
            .position(|entry| entry.id == sender)
            .ok_or(DriverError::UnknownGuardSender { sender: sender.0 })?;
        let _ = entries.remove(index);
        Ok(())
    }

    /// The effective-close acknowledgement of `guard`'s close at `epoch`:
    /// every registered sender, applied (with its positions and in-flight
    /// work) or pending (overdue past `guard_ack_timeout`, measured from
    /// the close by the driver clock).
    ///
    /// # Errors
    ///
    /// [`DriverError::UnknownGuard`], and [`DriverError::Guard`] with
    /// `NotClosedAt` when the guard did not close at `epoch` (or later).
    pub fn close_guard_ack(
        &mut self,
        guard: GuardHandle,
        epoch: u64,
    ) -> Result<CloseAck, DriverError> {
        let current = self.guards.state(guard)?;
        let Some(closed_at) = self.guards.closed_since(guard, epoch)? else {
            return Err(not_closed(epoch, current));
        };
        if epoch.is_multiple_of(2) {
            return Err(not_closed(epoch, current));
        }
        let now = self.clock.now();
        let overdue = now
            .checked_sub(closed_at)
            .is_some_and(|elapsed| elapsed >= self.config.guard_ack_timeout);
        let senders = self
            .guard_senders
            .entries
            .iter()
            .filter(|entry| entry.guard == guard)
            .map(|entry| {
                let ack = match read(&entry.cell) {
                    Some(applied) if applied.epoch >= epoch => SenderAck::Applied {
                        positions: applied.positions,
                        in_flight: applied.in_flight,
                    },
                    _ => SenderAck::Pending { overdue },
                };
                (entry.id, ack)
            })
            .collect();
        Ok(CloseAck {
            epoch,
            senders,
            unreachable: Unreachable::NotTracked,
        })
    }
}

fn not_closed(expected: u64, current: GuardState) -> DriverError {
    DriverError::Guard(GuardError::NotClosedAt { expected, current })
}

#[cfg(test)]
mod tests;
