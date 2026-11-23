// SPDX-License-Identifier: Apache-2.0

//! The `io_uring` RX half over the [`RxRingOps`] seam (`quantstratum-docs:
//! karyos/design/io-uring-backend.md` sections 3.6, 6.2, 6.3 and 10.2):
//! one multishot `RECVMSG` arm that takes a provided buffer per datagram.
//!
//! **Ownership.** A buffer goes back to the kernel only after the
//! completion that named it was reaped and its datagram was lent to the
//! handler, or dropped: [`RxRingOps::lend`] reposts it when the lend
//! returns or unwinds, never on a submission path, and lends nothing the
//! kernel may still write.
//!
//! **Validation.** A completion resolves only if it names the current arm
//! generation; a data completion must carry a buffer, and its
//! `io_uring_recvmsg_out` header, name and payload must fit the bytes the
//! kernel wrote. `MSG_TRUNC` or a payload over `max_datagram` is a drop
//! (`Oversize`), with the buffer reposted undelivered.
//!
//! **Exhaustion and reset.** `-ENOBUFS` ends the arm: the poll returns
//! [`RxStop::NoBuffers`], the `no_buffers` counter counts it, and the
//! next poll re-arms. [`UringRx::reset`] cancels the arm, reaps to its
//! terminal completion, and re-registers the buffer ring with every buffer
//! posted once again.
//!
//! No method of this module allocates after [`UringRx::open`].

#![forbid(unsafe_code)]

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::num::NonZeroU16;

use super::ops::{
    CONTROL_SLOTS, CQE_F_MORE, CancelTarget, Cqe, EAGAIN, EBADR, EBUSY, EINTR, ENOBUFS,
    RECVMSG_OUT, RX_NAME_LEN, RxRingOps, UserData, buffer_id,
};
use crate::backend::{
    BackendEpoch, BackendFailure, Budget, InstanceId, OpenError, PathId, RxBackend, RxDatagram,
    RxDrop, RxDropReason, RxHandler, RxOutcome, RxStop, Spent,
};

/// The `user_data` index of the arm; control slots follow it (design 3.4).
const ARM: u16 = 0;
/// `MSG_TRUNC` in the recvmsg header flags.
const MSG_TRUNC: u32 = 0x20;
/// Consecutive terminal arm errors before the half stops (design 3.6:
/// one re-arm per cycle, a repeated failure is `Failed`).
const ARM_FAILURES: u8 = 2;
/// The operation named by RX failures.
const RECVMSG: &str = "io_uring_recvmsg";
/// The operation named by a CQ overflow.
const OVERFLOW: &str = "uring_cq_overflow";

/// The default provided buffers (`R`, design 5.3).
pub const DEFAULT_RX_BUFFERS: NonZeroU16 = match NonZeroU16::new(256) {
    Some(value) => value,
    None => NonZeroU16::MIN,
};

/// The configuration of one `io_uring` RX half.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UringRxConfig {
    /// The largest payload delivered; larger datagrams are dropped.
    pub max_datagram: NonZeroU16,
    /// Provided buffers (`R`), a power of two from 8 to 32768.
    pub rx_buffers: NonZeroU16,
    /// The path the datagrams of this half arrive on.
    pub path: PathId,
}

impl Default for UringRxConfig {
    fn default() -> Self {
        Self {
            max_datagram: super::tx::DEFAULT_MAX_DATAGRAM,
            rx_buffers: DEFAULT_RX_BUFFERS,
            path: PathId::new(0),
        }
    }
}

impl UringRxConfig {
    /// Checks `rx_buffers`.
    ///
    /// # Errors
    ///
    /// [`OpenError::InvalidConfig`] naming the field.
    pub fn validate(&self) -> Result<(), OpenError> {
        let buffers = self.rx_buffers.get();
        if !buffers.is_power_of_two() || !(8..=32768).contains(&buffers) {
            return Err(OpenError::InvalidConfig {
                field: "rx_buffers",
                value: u64::from(buffers),
            });
        }
        Ok(())
    }

    /// Bytes of each buffer: the recvmsg header, the name area and one
    /// byte over `max_datagram` (so truncation shows), rounded up to 64
    /// (design 5.3).
    #[must_use]
    pub fn buffer_len(&self) -> u32 {
        let raw = u32::try_from(RECVMSG_OUT).unwrap_or(16)
            + RX_NAME_LEN
            + u32::from(self.max_datagram.get())
            + 1;
        raw.next_multiple_of(64)
    }

    /// The SQ entries of the RX ring: `K` rounded up (design 5.1).
    #[must_use]
    pub fn sq_entries(&self) -> u32 {
        u32::from(CONTROL_SLOTS).next_power_of_two()
    }

    /// The CQ entries of the RX ring: `R + K` rounded up (design 5.1).
    #[must_use]
    pub fn cq_entries(&self) -> u32 {
        (u32::from(self.rx_buffers.get()) + u32::from(CONTROL_SLOTS)).next_power_of_two()
    }
}

/// The counters of one RX half; every increment saturates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UringRxCounters {
    /// Arms ended by `-ENOBUFS`: the buffer ring ran dry.
    pub no_buffers: u64,
    /// Datagrams dropped as truncated or over `max_datagram`.
    pub oversize: u64,
    /// Datagrams dropped for a source that is not IPv4 or IPv6.
    pub unsupported_source: u64,
    /// Completions that named no operation in flight.
    pub stale_completions: u64,
    /// Data completions that broke the buffer or header rules.
    pub invariants: u64,
    /// Arms ended by another error.
    pub arm_errors: u64,
    /// Arms published.
    pub arms: u64,
    /// Buffer ring registrations after the first (resets).
    pub reregistrations: u64,
}

/// The result of one [`UringRx::reset`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UringRxReset {
    /// The arm or a cancel is still in flight: call again. Nothing is
    /// re-registered meanwhile.
    pub more: bool,
    /// Buffers posted after this call.
    pub posted: u16,
    /// Buffers of the ring.
    pub buffers: u16,
}

#[derive(Debug, Clone, Copy)]
struct Control {
    generation: u64,
    in_flight: bool,
}

/// What one completion did to the poll.
enum Flow {
    Continue,
    Stop(RxStop),
}

/// The `io_uring` RX half. One owning agent (SPEC.md §16.4).
#[derive(Debug)]
pub struct UringRx<R: RxRingOps> {
    epoch: BackendEpoch,
    config: UringRxConfig,
    ring: R,
    /// The generation of the current or last arm; 0 before the first.
    arm_generation: u64,
    /// Whether the current arm was published and not ended.
    armed: bool,
    arm_failures: u8,
    control: [Control; CONTROL_SLOTS as usize],
    resetting: bool,
    counters: UringRxCounters,
    failed: Option<BackendFailure>,
}

fn decode_source(name: &[u8], len: u32) -> Option<SocketAddr> {
    let family = u16::from_ne_bytes(name.get(..2)?.try_into().ok()?);
    let port = u16::from_be_bytes(name.get(2..4)?.try_into().ok()?);
    match (family, len) {
        (2, 16..) => {
            let octets: [u8; 4] = name.get(4..8)?.try_into().ok()?;
            Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(octets),
                port,
            )))
        }
        (10, 28..) => {
            let flowinfo = u32::from_be_bytes(name.get(4..8)?.try_into().ok()?);
            let octets: [u8; 16] = name.get(8..24)?.try_into().ok()?;
            let scope = u32::from_ne_bytes(name.get(24..28)?.try_into().ok()?);
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(octets),
                port,
                flowinfo,
                scope,
            )))
        }
        _ => None,
    }
}

fn field(header: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    Some(u32::from_ne_bytes(header.get(at..end)?.try_into().ok()?))
}

/// One datagram as a buffer holds it.
enum Parsed<'a> {
    Datagram {
        payload: &'a [u8],
        source: SocketAddr,
    },
    Drop(RxDrop),
    /// The header or its lengths do not fit the bytes written.
    Invalid,
}

fn parse(buffer: &[u8], written: usize, max_datagram: u16) -> Parsed<'_> {
    let Some(written) = buffer.get(..written) else {
        return Parsed::Invalid;
    };
    let (Some(namelen), Some(controllen), Some(payloadlen), Some(flags)) = (
        field(written, 0),
        field(written, 4),
        field(written, 8),
        field(written, 12),
    ) else {
        return Parsed::Invalid;
    };
    let name_area = usize::try_from(RX_NAME_LEN).unwrap_or(usize::MAX);
    let start = RECVMSG_OUT.saturating_add(name_area);
    let (Some(name), Some(available)) = (
        written.get(RECVMSG_OUT..start),
        written.len().checked_sub(start),
    ) else {
        return Parsed::Invalid;
    };
    if controllen != 0 {
        // No control area was requested.
        return Parsed::Invalid;
    }
    let source = decode_source(name, namelen.min(RX_NAME_LEN));
    let payload_len = usize::try_from(payloadlen).unwrap_or(usize::MAX);
    if flags & MSG_TRUNC != 0 || payload_len > available || payload_len > usize::from(max_datagram)
    {
        return Parsed::Drop(RxDrop {
            reason: RxDropReason::Oversize {
                limit: max_datagram,
                received: Some(payload_len),
            },
            source,
        });
    }
    let Some(source) = source else {
        return Parsed::Drop(RxDrop {
            reason: RxDropReason::UnsupportedSource,
            source: None,
        });
    };
    match written.get(start..start.saturating_add(payload_len)) {
        Some(payload) => Parsed::Datagram { payload, source },
        None => Parsed::Invalid,
    }
}

impl<R: RxRingOps> UringRx<R> {
    /// Checks `config` against `ring`, whose buffers are registered and
    /// posted. The first poll arms.
    ///
    /// # Errors
    ///
    /// [`OpenError::InvalidConfig`].
    pub fn open(config: UringRxConfig, _instance: InstanceId, ring: R) -> Result<Self, OpenError> {
        config.validate()?;
        if ring.buffers() != config.rx_buffers.get() || ring.buffer_len() != config.buffer_len() {
            return Err(OpenError::InvalidConfig {
                field: "rx_buffers",
                value: u64::from(ring.buffers()),
            });
        }
        Ok(Self {
            epoch: BackendEpoch::FIRST,
            config,
            ring,
            arm_generation: 0,
            armed: false,
            arm_failures: 0,
            control: [Control {
                generation: 0,
                in_flight: false,
            }; CONTROL_SLOTS as usize],
            resetting: false,
            counters: UringRxCounters::default(),
            failed: None,
        })
    }

    /// The ring seam.
    #[must_use]
    pub fn ring(&self) -> &R {
        &self.ring
    }

    /// The ring seam, mutably: tests script completions through it.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn ring_mut(&mut self) -> &mut R {
        &mut self.ring
    }

    /// The half's counters.
    #[must_use]
    pub fn counters(&self) -> UringRxCounters {
        self.counters
    }

    /// The failure that stopped the half, if any.
    #[must_use]
    pub fn failure(&self) -> Option<BackendFailure> {
        self.failed
    }

    /// Buffers posted now; equal to the ring's buffers whenever no
    /// datagram is being lent and no completion awaits its reap.
    #[must_use]
    pub fn posted(&self) -> u16 {
        self.ring.posted()
    }

    fn arm_user_data(&self) -> UserData {
        UserData::new(ARM, self.arm_generation)
    }

    /// Publishes a new arm generation; false if none could be published.
    fn arm(&mut self) -> bool {
        let Some(generation) = self.arm_generation.checked_add(1) else {
            return false;
        };
        if self.ring.arm(UserData::new(ARM, generation)).is_err() {
            return false;
        }
        self.arm_generation = generation;
        self.armed = true;
        self.counters.arms = self.counters.arms.saturating_add(1);
        true
    }

    fn enter(&mut self) -> Option<RxStop> {
        match self.ring.enter() {
            Ok(_) => None,
            Err(errno) => Some(match errno.0 {
                EINTR => RxStop::Interrupted,
                EAGAIN => RxStop::WouldBlock,
                EBUSY | EBADR => RxStop::Failed(self.overflowed()),
                errno => {
                    let failure = BackendFailure::Os {
                        operation: "io_uring_enter",
                        errno,
                    };
                    RxStop::Failed(*self.failed.get_or_insert(failure))
                }
            }),
        }
    }

    fn overflowed(&mut self) -> BackendFailure {
        *self.failed.get_or_insert(BackendFailure::Invariant {
            operation: OVERFLOW,
        })
    }

    /// Resets the RX ring (design 10.2): cancels the arm once, reaps
    /// within `budget` (a datagram reaped now is dropped, its buffer
    /// reposted), and once the arm has ended re-registers the buffer ring
    /// with every buffer posted. Call until `more` is false; the next poll
    /// arms again.
    pub fn reset(&mut self, budget: Budget) -> UringRxReset {
        self.resetting = true;
        let control_free = self.control.iter().all(|control| !control.in_flight);
        if self.ring.arm_live() && control_free {
            let target = CancelTarget::One(self.arm_user_data());
            if let Some((index, control)) = self.control.iter_mut().enumerate().next()
                && let Some(generation) = control.generation.checked_add(1)
                && let Ok(index) = u16::try_from(index)
                && let Some(index) = ARM.checked_add(1).and_then(|one| one.checked_add(index))
                && self
                    .ring
                    .push_cancel(target, UserData::new(index, generation))
                    .is_ok()
            {
                control.generation = generation;
                control.in_flight = true;
            }
        }
        if self.ring.needs_enter() {
            let _ = self.ring.enter();
        }
        let limit = budget.datagrams();
        let mut one = [Cqe::EMPTY; 1];
        for _ in 0..limit {
            if self.ring.reap(&mut one) == 0 {
                break;
            }
            let [cqe] = one;
            self.complete_during_reset(cqe);
        }
        let busy = self.ring.arm_live() || self.control.iter().any(|control| control.in_flight);
        let buffers = self.ring.buffers();
        if busy {
            return UringRxReset {
                more: true,
                posted: self.ring.posted(),
                buffers,
            };
        }
        if self.ring.reregister().is_err() {
            return UringRxReset {
                more: true,
                posted: self.ring.posted(),
                buffers,
            };
        }
        self.counters.reregistrations = self.counters.reregistrations.saturating_add(1);
        self.resetting = false;
        self.armed = false;
        self.arm_failures = 0;
        self.failed = None;
        UringRxReset {
            more: false,
            posted: self.ring.posted(),
            buffers,
        }
    }

    fn complete_during_reset(&mut self, cqe: Cqe) {
        if self.complete_control(cqe) {
            return;
        }
        if cqe.user_data == self.arm_user_data() {
            if cqe.flags & CQE_F_MORE == 0 {
                self.armed = false;
            }
            if let Some(id) = buffer_id(cqe.flags) {
                // Dropped by the reset; the lend reposts it.
                let _ = self.ring.lend(id, |_| ());
            }
            return;
        }
        self.counters.stale_completions = self.counters.stale_completions.saturating_add(1);
    }

    /// A completion of a control slot; false if it names none.
    fn complete_control(&mut self, cqe: Cqe) -> bool {
        let index = cqe.user_data.index();
        let Some(slot) = index.checked_sub(1).filter(|_| index > ARM) else {
            return false;
        };
        match self.control.get_mut(usize::from(slot)) {
            Some(control)
                if control.in_flight && cqe.user_data.names(index, control.generation) =>
            {
                control.in_flight = false;
                true
            }
            _ => false,
        }
    }

    fn complete<H: RxHandler>(
        &mut self,
        cqe: Cqe,
        handler: &mut H,
        outcome: &mut RxOutcome,
    ) -> Flow {
        if self.complete_control(cqe) {
            return Flow::Continue;
        }
        if cqe.user_data != self.arm_user_data() {
            self.counters.stale_completions = self.counters.stale_completions.saturating_add(1);
            // A stale completion that names a buffer still moved it to
            // Completed; give it back.
            if let Some(id) = buffer_id(cqe.flags) {
                let _ = self.ring.lend(id, |_| ());
            }
            return Flow::Continue;
        }
        if cqe.flags & CQE_F_MORE == 0 {
            self.armed = false;
        }
        if cqe.result < 0 {
            let errno = cqe.result.checked_neg().unwrap_or(i32::MAX);
            if errno == ENOBUFS {
                self.counters.no_buffers = self.counters.no_buffers.saturating_add(1);
                return Flow::Stop(RxStop::NoBuffers);
            }
            self.counters.arm_errors = self.counters.arm_errors.saturating_add(1);
            self.arm_failures = self.arm_failures.saturating_add(1);
            if self.arm_failures >= ARM_FAILURES {
                let failure = BackendFailure::Os {
                    operation: RECVMSG,
                    errno,
                };
                return Flow::Stop(RxStop::Failed(*self.failed.get_or_insert(failure)));
            }
            return Flow::Continue;
        }
        self.arm_failures = 0;
        let Some(id) = buffer_id(cqe.flags) else {
            self.counters.invariants = self.counters.invariants.saturating_add(1);
            return Flow::Continue;
        };
        let written = usize::try_from(cqe.result).unwrap_or(usize::MAX);
        let max_datagram = self.config.max_datagram.get();
        let (path, epoch) = (self.config.path, self.epoch);
        let lent = self
            .ring
            .lend(id, |buffer| match parse(buffer, written, max_datagram) {
                Parsed::Datagram { payload, source } => {
                    let flow =
                        handler.datagram(RxDatagram::new(payload, source, path, epoch, None));
                    (Some((payload.len(), flow)), None, false)
                }
                Parsed::Drop(drop) => {
                    handler.dropped(drop);
                    (None, Some(drop.reason), false)
                }
                Parsed::Invalid => (None, None, true),
            });
        let Some((delivered, dropped, invalid)) = lent else {
            // Not Completed: the buffer was not handed back to us.
            self.counters.invariants = self.counters.invariants.saturating_add(1);
            return Flow::Continue;
        };
        if invalid {
            self.counters.invariants = self.counters.invariants.saturating_add(1);
        }
        match dropped {
            Some(RxDropReason::Oversize { .. }) => {
                self.counters.oversize = self.counters.oversize.saturating_add(1);
                outcome.dropped = outcome.dropped.saturating_add(1);
            }
            Some(RxDropReason::UnsupportedSource) => {
                self.counters.unsupported_source =
                    self.counters.unsupported_source.saturating_add(1);
                outcome.dropped = outcome.dropped.saturating_add(1);
            }
            None => {}
        }
        if let Some((len, flow)) = delivered {
            outcome.delivered = outcome.delivered.saturating_add(1);
            outcome.spent.bytes = outcome
                .spent
                .bytes
                .saturating_add(u64::try_from(len).unwrap_or(u64::MAX));
            if flow.is_break() {
                return Flow::Stop(RxStop::HandlerStopped);
            }
        }
        Flow::Continue
    }
}

impl<R: RxRingOps> RxBackend for UringRx<R> {
    /// Re-arms at most once per call when the arm ended, enters when the
    /// ring needs it, then reaps one completion at a time within
    /// `budget`, so a handler that stops leaves the rest in the CQ.
    fn poll_rx<H: RxHandler>(&mut self, budget: Budget, handler: &mut H) -> RxOutcome {
        let mut outcome = RxOutcome {
            delivered: 0,
            dropped: 0,
            spent: Spent::default(),
            stop: RxStop::WouldBlock,
        };
        if let Some(failure) = self.failed {
            outcome.stop = RxStop::Failed(failure);
            return outcome;
        }
        if self.resetting {
            outcome.stop = RxStop::Failed(BackendFailure::NotActive);
            return outcome;
        }
        if !self.armed && !self.ring.arm_live() {
            self.arm();
        }
        if budget.ops() > 0 && self.ring.needs_enter() {
            outcome.spent.ops = 1;
            if let Some(stop) = self.enter() {
                outcome.stop = stop;
                return outcome;
            }
        }
        let mut one = [Cqe::EMPTY; 1];
        loop {
            if outcome.spent.datagrams >= budget.datagrams() {
                outcome.stop = RxStop::Budget;
                break;
            }
            if self.ring.reap(&mut one) == 0 {
                break;
            }
            let [cqe] = one;
            outcome.spent.datagrams = outcome.spent.datagrams.saturating_add(1);
            if let Flow::Stop(stop) = self.complete(cqe, handler, &mut outcome) {
                outcome.stop = stop;
                break;
            }
        }
        if self.ring.cq_overflowed() {
            outcome.stop = RxStop::Failed(self.overflowed());
        }
        outcome
    }
}

#[cfg(test)]
mod tests;
