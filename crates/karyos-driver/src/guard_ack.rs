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

use karyos_sys::counters::{Counter, CounterKeys, KIND_GUARD};

use crate::counters::{DriverCounters, TYPE_GAUGE};
use crate::embedded::{EmbeddedDriver, StreamTerms};
use crate::error::DriverError;
use crate::guards::GuardHandle;

/// Attempts to read a cell whole before its sender is reported pending: a
/// writer that stays in the middle of a publication longer than this many
/// reads is not waited for.
pub const ACK_READ_ATTEMPTS: u32 = 8;

/// Names a registered sender gate of one driver, as a `GuardHandle`
/// names a guard: another driver's id is unknown here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GuardSenderId {
    driver: u64,
    id: u64,
}

impl GuardSenderId {
    /// The id, from 1, never reused within the driver.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.id
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
    /// The guard's epoch when the sender registered: a close at or before
    /// it is none of this sender's concern.
    registered: u64,
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

    /// The senders of `guard`'s close at `epoch`, counted as
    /// [`EmbeddedDriver::close_guard_ack`] reports them, without
    /// allocating (M4b): applied with nothing in flight, applied with work
    /// in flight, pending, and pending past the timeout (`overdue`).
    pub(crate) fn counts(&self, guard: GuardHandle, epoch: u64, overdue: bool) -> AckCounts {
        let mut counts = AckCounts::default();
        for entry in self
            .entries
            .iter()
            .filter(|entry| entry.guard == guard && entry.registered < epoch)
        {
            let slot = match read(&entry.cell) {
                Some(applied) if applied.epoch >= epoch && applied.in_flight == 0 => {
                    &mut counts.applied
                }
                Some(applied) if applied.epoch >= epoch => &mut counts.in_flight,
                _ if overdue => &mut counts.overdue,
                _ => &mut counts.pending,
            };
            // At most `max_guard_senders`: never past `u64`.
            if let Some(next) = slot.checked_add(1) {
                *slot = next;
            }
        }
        counts
    }
}

/// A close's senders by acknowledgement state (M4b): the gauges tools read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct AckCounts {
    /// Applied, nothing in flight: the close is effective there.
    pub(crate) applied: u64,
    /// Applied, with work still in flight.
    pub(crate) in_flight: u64,
    /// Not applied yet, within the timeout.
    pub(crate) pending: u64,
    /// Not applied past `guard_ack_timeout`: still pending, overdue.
    pub(crate) overdue: u64,
}

/// One whole read of `cell` within [`ACK_READ_ATTEMPTS`].
fn read(cell: &AppliedEpoch) -> Option<Applied> {
    (0..ACK_READ_ATTEMPTS).find_map(|_| cell.try_read())
}

impl<T: StreamTerms> EmbeddedDriver<T> {
    /// Registers a sender gate serving `guard` (phase 7 of
    /// driver-network-agents.md wires it from `AddSenderSession`): the
    /// returned cell is the gate's, written by it alone, and read by
    /// [`EmbeddedDriver::close_guard_ack`] until
    /// [`EmbeddedDriver::deregister_guard_sender`]. A sender is concerned
    /// only by closes after its registration: the guard's epoch is recorded
    /// with it.
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
        let registered = self.guards.state(guard)?.epoch;
        let driver = self.id;
        let senders = &mut self.guard_senders;
        if senders.entries.len() >= senders.max {
            return Err(DriverError::TooManyGuardSenders);
        }
        let id = GuardSenderId {
            driver,
            id: senders.next,
        };
        senders.next = senders
            .next
            .checked_add(1)
            .ok_or(DriverError::GuardSenderIdsExhausted)?;
        let cell = Arc::new(AppliedEpoch::new());
        senders.entries.push(Entry {
            id,
            guard,
            registered,
            cell: Arc::clone(&cell),
        });
        Ok((id, cell))
    }

    /// Deregisters a sender gate whose gate retired or whose sender session
    /// ended: later acknowledgements no longer list it.
    ///
    /// # Errors
    ///
    /// [`DriverError::UnknownGuardSender`] for a sender not registered
    /// here (another driver's included).
    pub fn deregister_guard_sender(&mut self, sender: GuardSenderId) -> Result<(), DriverError> {
        let entries = &mut self.guard_senders.entries;
        let index = entries
            .iter()
            .position(|entry| entry.id == sender)
            .ok_or(DriverError::UnknownGuardSender { sender: sender.id })?;
        let _ = entries.remove(index);
        Ok(())
    }

    /// The effective-close acknowledgement of `guard`'s close at `epoch`:
    /// every sender registered before that close, applied (with its
    /// positions and in-flight work) or pending (overdue past
    /// `guard_ack_timeout`, measured from the close by the driver clock).
    /// A clock read behind the close is never overdue. For a close older
    /// than the guard's kept history (`guards::CLOSE_HISTORY`), the time of
    /// a later close is used, so overdue can only come late, never early.
    ///
    /// # Errors
    ///
    /// [`DriverError::UnknownGuard`], and [`DriverError::Guard`] with
    /// `NotClosedAt` when `epoch` is not a close of the guard: an even
    /// (open) epoch, the initial epoch 1, or one the guard never reached.
    pub fn close_guard_ack(
        &mut self,
        guard: GuardHandle,
        epoch: u64,
    ) -> Result<CloseAck, DriverError> {
        let current = self.guards.state(guard)?;
        let Some(closed_at) = self.guards.closed_since(guard, epoch)? else {
            return Err(not_closed(epoch, current));
        };
        // Closed epochs are odd; epoch 1 is the guard's creation, no close.
        if epoch.is_multiple_of(2) || epoch < 3 {
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
            .filter(|entry| entry.guard == guard && entry.registered < epoch)
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

/// The labels of a guard's acknowledgement gauges, in [`AckCells`] order
/// (M4b): the close epoch they count (0 while no close is in effect), then
/// its senders applied, applied with work in flight, pending and overdue.
pub(crate) const ACK_LABELS: [&str; 5] = [
    "guard ack epoch",
    "guard senders applied",
    "guard senders in flight",
    "guard senders pending",
    "guard senders overdue",
];

/// The label of a guard's acknowledgement pass cell: the gauges are
/// written inside a sampling pass on it, so a tool reads them as one.
pub(crate) const ACK_PASS_LABEL: &str = "guard ack pass";

/// One guard's acknowledgement gauges.
#[derive(Debug)]
struct AckCells {
    id: u64,
    /// Whether an allocation was tried (a refusal counts once).
    tried: bool,
    pass: Option<Counter>,
    /// The last even pass value.
    passes: u64,
    cells: Vec<Option<Counter>>,
    stored: [u64; 5],
}

/// Each guard's close acknowledgement as gauges for tools (M4b), keyed by
/// participant kind `KIND_GUARD` and the guard id, beside its word gauge.
/// While a guard is closed by a close (epoch 3 or later, odd), the gauges
/// count its registered senders as [`EmbeddedDriver::close_guard_ack`]
/// would report them, recomputed at every conductor duty cycle without
/// allocating, since a pending sender becomes overdue with time alone.
/// They are written inside a pass on the guard's `guard ack pass` cell,
/// and only when a value changed. The driver clock is read only while
/// such a close exists. The six cells are allocated together or not at
/// all; a refusal is counted once and retried every
/// [`crate::guards::GUARD_CELL_RETRY`] syncs.
#[derive(Debug, Default)]
pub(crate) struct GuardAckCells {
    guards: Vec<AckCells>,
    retry_in: u32,
}

impl GuardAckCells {
    /// Brings the gauges in line (control path, each duty cycle); `now`
    /// reads the driver clock, `timeout` is `guard_ack_timeout`.
    pub(crate) fn sync(
        &mut self,
        guards: &crate::guards::Guards,
        senders: &GuardSenders,
        counters: &mut DriverCounters,
        now: &mut dyn FnMut() -> u64,
        timeout: u64,
    ) {
        let retry = match self.retry_in.checked_sub(1) {
            Some(left) => {
                self.retry_in = left;
                false
            }
            None => true,
        };
        let mut refused = false;
        let mut clock: Option<u64> = None;
        for (index, id) in guards.ids().enumerate() {
            if self.guards.get(index).is_none() {
                self.guards.push(AckCells {
                    id,
                    tried: false,
                    pass: None,
                    passes: 0,
                    cells: Vec::new(),
                    stored: [0; 5],
                });
            }
            let Some(entry) = self.guards.get_mut(index) else {
                continue;
            };
            if entry.pass.is_none() && (retry || !entry.tried) {
                let keys = CounterKeys {
                    kind: KIND_GUARD,
                    participant: entry.id,
                    ..CounterKeys::DRIVER
                };
                let mut allocate = |label: &str| {
                    if entry.tried {
                        counters.retry_keyed(TYPE_GAUGE, label, keys)
                    } else {
                        counters.allocate_keyed(TYPE_GAUGE, label, keys)
                    }
                };
                let pass = allocate(ACK_PASS_LABEL);
                let cells: Vec<Option<Counter>> = match &pass {
                    Some(_) => ACK_LABELS.iter().map(|label| allocate(label)).collect(),
                    None => Vec::new(),
                };
                entry.tried = true;
                // All or nothing: a group a reader cannot trust is not left
                // half allocated.
                if pass.is_some() && cells.iter().all(Option::is_some) {
                    entry.pass = pass;
                    entry.cells = cells;
                    entry.stored = [0; 5];
                } else {
                    for cell in pass.into_iter().chain(cells.into_iter().flatten()) {
                        counters.free(cell);
                    }
                    refused = true;
                }
            }
            let Some(pass) = &entry.pass else {
                continue;
            };
            let values = guards
                .by_id(entry.id)
                .and_then(|handle| {
                    let state = guards.state(handle).ok()?;
                    // Epoch 1 is the guard's creation, not a close.
                    if state.open || state.epoch < 3 {
                        return None;
                    }
                    let closed_at = guards.closed_since(handle, state.epoch).ok()?;
                    let now = *clock.get_or_insert_with(&mut *now);
                    let overdue = closed_at
                        .and_then(|at| now.checked_sub(at))
                        .is_some_and(|elapsed| elapsed >= timeout);
                    let counts = senders.counts(handle, state.epoch, overdue);
                    Some([
                        state.epoch,
                        counts.applied,
                        counts.in_flight,
                        counts.pending,
                        counts.overdue,
                    ])
                })
                .unwrap_or([0; 5]);
            if values == entry.stored {
                continue;
            }
            // Checked: 2^63 changes of one guard's counts never come; at
            // the end the gauges are written without a pass.
            let odd = entry.passes.checked_add(1);
            let even = odd.and_then(|odd| odd.checked_add(1));
            if let Some(odd) = odd {
                pass.begin_pass(odd);
            }
            for (cell, value) in entry.cells.iter().zip(values) {
                if let Some(cell) = cell {
                    cell.set(value);
                }
            }
            if let Some(even) = even {
                pass.end_pass(even);
                entry.passes = even;
            }
            entry.stored = values;
        }
        if refused {
            self.retry_in = crate::guards::GUARD_CELL_RETRY;
        }
    }
}

#[cfg(test)]
mod tests;
