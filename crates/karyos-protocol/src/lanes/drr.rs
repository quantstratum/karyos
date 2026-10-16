// SPDX-License-Identifier: Apache-2.0

//! Persistent deficit round robin over priority lanes (SPEC.md §7.4;
//! `quantstratum-docs: karyos/design/aggregate-lanes.md`, "Proposed
//! persistent DRR state machine").
//!
//! One [`Drr`] is the private state of one sender scheduler or one
//! aggregate subscriber: a deficit per lane, a cursor and whether the
//! visit under the cursor has received its quantum. Nothing in it is
//! shared. [`Drr::run`] serves the lanes a [`LaneSource`] exposes, frame
//! by frame, within one call's [`Budget`], and the state persists across
//! calls: a round may span many calls.
//!
//! One visit follows the design's seven steps:
//!
//! 1. With no work or no bytes left the call suspends before any probe;
//!    the round is untouched.
//! 2. The lane is probed (one unit of work). A head whose charge does not
//!    fit the remaining byte budget suspends the call as budget limited,
//!    before any credit (owner decision P3: budget exhaustion suspends the
//!    visit and keeps the deficit). A lane with nothing eligible loses its
//!    unused deficit, which the report counts as forfeited, and the cursor
//!    advances without crediting it.
//! 3. An eligible visit not yet credited receives the lane's quantum once,
//!    with a checked sum; a visit resumed by a later call is not credited
//!    again.
//! 4. and 5. The head is served when it fits the deficit; only a frame the
//!    source confirms served is debited. A failed attempt costs work, not
//!    deficit or bytes, and the lane is probed again.
//! 6. A head larger than the residual deficit ends the visit; the residual
//!    carries into the lane's next visit.
//! 7. The cursor advances in lane order; wrapping it starts a new round.
//!
//! A charge of zero or above the validated maximum is a typed error,
//! never a wait for impossible credit. Since every quantum is at least
//! the maximum charge, a credited visit always serves its first eligible
//! head, and a lane's deficit at the end of a visit is below the maximum
//! charge: after `k` visits a continuously eligible lane has been served
//! at least `k * Q - F_max` bytes (conservation: credits equal service,
//! forfeits and the current deficit).
//!
//! The configuration is fixed: there is no way to change a quantum, the
//! profile or the lane set of a live state (coordinator decision L8,
//! ACS 14548). A new configuration is a new [`Drr`].

use thiserror::Error;

/// Most lanes a scheduler serves (SPEC.md §7.4: lanes 0 to 3).
pub const MAX_LANES: usize = 4;

/// Errors of lane scheduling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DrrError {
    /// No lane, more than [`MAX_LANES`], a zero maximum charge, a quantum
    /// below the maximum charge, or a quantum whose deficit bound does not
    /// fit `u64`.
    #[error("invalid lane scheduling configuration")]
    InvalidConfig,
    /// A head's charge is zero or above the validated maximum: a geometry
    /// or protocol error, never a wait for credit that cannot come.
    #[error("lane {lane} head charge {charge} is outside 1..={max}")]
    InvalidCharge {
        /// The lane.
        lane: usize,
        /// The head's charge.
        charge: u64,
        /// The validated maximum charge.
        max: u64,
    },
    /// A deficit or a report count would not fit `u64`; nothing was
    /// credited or served for it.
    #[error("lane {lane} scheduling arithmetic overflowed")]
    Overflow {
        /// The lane.
        lane: usize,
    },
}

/// The validated configuration of a scheduler: the lanes, one fixed
/// quantum per lane and the largest charge of one frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrrConfig {
    lanes: usize,
    quanta: [u64; MAX_LANES],
    max_charge: u64,
}

impl DrrConfig {
    /// A configuration of `quanta.len()` lanes, lane `l` with quantum
    /// `quanta[l]`, whose frames are charged at most `max_charge` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DrrError::InvalidConfig`] for no lane or more than
    /// [`MAX_LANES`], a zero `max_charge`, a quantum below `max_charge`
    /// (a head could then never fit a visit), or a quantum such that
    /// `quantum + max_charge`, the bound of a deficit, does not fit `u64`.
    pub fn new(quanta: &[u64], max_charge: u64) -> Result<Self, DrrError> {
        let lanes = quanta.len();
        if lanes == 0 || lanes > MAX_LANES || max_charge == 0 {
            return Err(DrrError::InvalidConfig);
        }
        let mut stored = [0; MAX_LANES];
        for (slot, &quantum) in stored.iter_mut().zip(quanta) {
            if quantum < max_charge || quantum.checked_add(max_charge).is_none() {
                return Err(DrrError::InvalidConfig);
            }
            *slot = quantum;
        }
        Ok(Self {
            lanes,
            quanta: stored,
            max_charge,
        })
    }

    /// The number of lanes.
    #[must_use]
    pub fn lanes(&self) -> usize {
        self.lanes
    }

    /// The quantum of `lane`; `None` past the last lane.
    #[must_use]
    pub fn quantum(&self, lane: usize) -> Option<u64> {
        (lane < self.lanes)
            .then(|| self.quanta.get(lane).copied())
            .flatten()
    }

    /// The largest charge of one frame.
    #[must_use]
    pub fn max_charge(&self) -> u64 {
        self.max_charge
    }
}

/// What a lane offers at a probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    /// Its head frame is eligible under every non-budget predicate and is
    /// charged `charge` bytes.
    Eligible {
        /// The head's charge.
        charge: u64,
    },
    /// Nothing eligible: no committed or terminal head, a future head
    /// time, a closed guard or window, or an inadmissible backend.
    Ineligible,
}

/// The confirmed result of serving a lane's head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    /// The head probed last was served and is debited.
    Served,
    /// It was not served (a known failed attempt); nothing is debited.
    NotServed,
    /// Whether it was served is unknown (an unproven backend exposure,
    /// `quantstratum-docs: karyos/design/lane-sender.md`, LS-3): nothing is
    /// debited, since the fairness bound counts confirmed service only, but
    /// its charge is taken from the call's byte budget, so uncertainty can
    /// never overrun it. The source makes the lane ineligible until the
    /// control path resolves it.
    Uncertain,
    /// The backend had no room for it (a shared socket's `EAGAIN` or
    /// `ENOBUFS`, `quantstratum-docs: karyos/design/lane-sender.md`, LS-4):
    /// nothing is debited, the lane forfeits its deficit as for any
    /// inadmissible backend (owner decision P3) and its visit ends, and the
    /// call stops with [`Stop::Backpressure`], the cursor on the next lane,
    /// so a backend that never has room for one lane's quantum cannot hold
    /// the cursor on it.
    Backpressure,
    /// The source cannot go on (a broken backend, queue state or caller):
    /// nothing is debited or forfeited, the visit is kept, and the call
    /// stops with [`Stop::Halted`] rather than a full ineligible pass.
    Halt,
}

/// The lanes a scheduler serves.
pub trait LaneSource {
    /// The head of `lane` now. Called once per step; a later probe may
    /// see another head.
    fn probe(&mut self, lane: usize) -> Probe;

    /// Serves the head of `lane` the last probe returned.
    fn serve(&mut self, lane: usize) -> Service;
}

/// What one call may spend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    /// Probes, one unit each (a failed attempt costs its probe).
    pub work: u32,
    /// Bytes of charged frames served.
    pub bytes: u64,
}

/// Why a call returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    /// The work budget ran out; the visit under the cursor is kept.
    WorkExhausted,
    /// The byte budget ran out (or was zero); the visit under the cursor is
    /// kept.
    BytesExhausted,
    /// The head of `lane` is charged more than the remaining byte budget;
    /// the visit is kept, uncredited if it was not credited yet.
    BytesLimited {
        /// The lane under the cursor.
        lane: usize,
        /// Its head's charge.
        charge: u64,
    },
    /// A full pass found no lane eligible.
    Idle,
    /// The source halted while serving `lane` ([`Service::Halt`]): the
    /// visit is kept and no deficit was forfeited.
    Halted {
        /// The lane under the cursor.
        lane: usize,
    },
    /// The backend had no room for `lane`'s head ([`Service::Backpressure`]):
    /// the lane forfeited its deficit and the cursor is on the next lane,
    /// with no extra empty pass (a wrap from the last lane counts a round
    /// as usual).
    Backpressure {
        /// The lane whose head found no room.
        lane: usize,
    },
    /// A step failed (see [`DrrError`]): nothing was credited or served
    /// for it, and the report still counts the steps before it.
    Failed(DrrError),
}

/// What one call did for one lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LaneReport {
    /// Charged bytes served.
    pub served_bytes: u64,
    /// Frames served.
    pub served_frames: u64,
    /// Quanta credited.
    pub credits: u64,
    /// Deficit lost because the lane had nothing eligible.
    pub forfeited: u64,
    /// Failed service attempts.
    pub failed: u64,
    /// Charged bytes of uncertain attempts, taken from the byte budget and
    /// never debited.
    pub uncertain_bytes: u64,
}

/// What one call did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    /// Why it returned.
    pub stop: Stop,
    /// Per lane, in lane order; lanes past the configured ones stay zero.
    pub lanes: [LaneReport; MAX_LANES],
    /// Rounds completed (cursor wraps).
    pub rounds: u64,
}

/// Rule removals the tests use as negative controls.
#[cfg(test)]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Faults {
    /// Credit a resumed visit again at every call.
    pub(crate) credit_on_resume: bool,
    /// Forfeit the deficit of the lane under the cursor when a call ends
    /// on its budget.
    pub(crate) reset_on_budget: bool,
    /// Restart every call at lane 0 with a new visit.
    pub(crate) restart_cursor: bool,
}

/// The persistent state of one scheduler.
#[derive(Debug, Clone)]
pub struct Drr {
    config: DrrConfig,
    deficit: [u64; MAX_LANES],
    cursor: usize,
    credited: bool,
    #[cfg(test)]
    pub(crate) faults: Faults,
}

impl Drr {
    /// A scheduler at lane 0 with every deficit zero.
    #[must_use]
    pub fn new(config: DrrConfig) -> Self {
        Self {
            config,
            deficit: [0; MAX_LANES],
            cursor: 0,
            credited: false,
            #[cfg(test)]
            faults: Faults::default(),
        }
    }

    /// Its configuration.
    #[must_use]
    pub fn config(&self) -> &DrrConfig {
        &self.config
    }

    /// The deficit of `lane`; `None` past the last lane.
    #[must_use]
    pub fn deficit(&self, lane: usize) -> Option<u64> {
        (lane < self.config.lanes)
            .then(|| self.deficit.get(lane).copied())
            .flatten()
    }

    /// The lane under the cursor.
    #[must_use]
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Whether the visit under the cursor has received its quantum.
    #[must_use]
    pub fn in_visit(&self) -> bool {
        self.credited
    }

    /// Serves `source` within `budget`, resuming the round where the last
    /// call stopped. A budget with no work or no bytes left suspends before
    /// any probe, so a zero budget changes nothing.
    ///
    /// The report's [`Report::stop`] is [`Stop::Failed`] with
    /// [`DrrError::InvalidCharge`] for a head charged zero or above the
    /// maximum, or [`DrrError::Overflow`] if a deficit or a report count
    /// would not fit `u64`. Nothing is credited or served for the step that
    /// failed; the report counts the steps before it, whose service stands.
    pub fn run(&mut self, budget: Budget, source: &mut impl LaneSource) -> Report {
        #[cfg(test)]
        self.inject_call_faults();
        let mut report = Report {
            stop: Stop::WorkExhausted,
            lanes: [LaneReport::default(); MAX_LANES],
            rounds: 0,
        };
        report.stop = match self.serve(budget, source, &mut report) {
            Ok(stop) => stop,
            Err(error) => Stop::Failed(error),
        };
        report
    }

    /// The steps of [`Drr::run`]; returns why they stopped.
    fn serve(
        &mut self,
        budget: Budget,
        source: &mut impl LaneSource,
        report: &mut Report,
    ) -> Result<Stop, DrrError> {
        let (mut work, mut bytes) = (budget.work, budget.bytes);
        // Consecutive lanes found with nothing eligible: a full pass of
        // them ends the call.
        let mut ineligible = 0;
        loop {
            // No budget left: suspend before any probe (step 1).
            let Some(left) = work.checked_sub(1) else {
                #[cfg(test)]
                self.inject_budget_fault();
                return Ok(Stop::WorkExhausted);
            };
            if bytes == 0 {
                #[cfg(test)]
                self.inject_budget_fault();
                return Ok(Stop::BytesExhausted);
            }
            work = left;
            let lane = self.cursor;
            let overflow = DrrError::Overflow { lane };
            match source.probe(lane) {
                Probe::Ineligible => {
                    let lost = self.deficit.get(lane).copied().unwrap_or(0);
                    let entry = report.lanes.get_mut(lane).ok_or(overflow)?;
                    entry.forfeited = entry.forfeited.checked_add(lost).ok_or(overflow)?;
                    if let Some(deficit) = self.deficit.get_mut(lane) {
                        *deficit = 0;
                    }
                    self.advance(report)?;
                    ineligible += 1;
                    if ineligible >= self.config.lanes {
                        return Ok(Stop::Idle);
                    }
                }
                Probe::Eligible { charge } => {
                    ineligible = 0;
                    if charge == 0 || charge > self.config.max_charge {
                        return Err(DrrError::InvalidCharge {
                            lane,
                            charge,
                            max: self.config.max_charge,
                        });
                    }
                    if charge > bytes {
                        #[cfg(test)]
                        self.inject_budget_fault();
                        return Ok(Stop::BytesLimited { lane, charge });
                    }
                    let deficit = self.deficit.get(lane).copied().unwrap_or(0);
                    let deficit = if self.credited {
                        deficit
                    } else {
                        let quantum = self.config.quantum(lane).ok_or(overflow)?;
                        let credited = deficit.checked_add(quantum).ok_or(overflow)?;
                        let entry = report.lanes.get_mut(lane).ok_or(overflow)?;
                        entry.credits = entry.credits.checked_add(1).ok_or(overflow)?;
                        self.credited = true;
                        credited
                    };
                    if let Some(slot) = self.deficit.get_mut(lane) {
                        *slot = deficit;
                    }
                    let Some(residual) = deficit.checked_sub(charge) else {
                        // The head exceeds the residual: the visit ends and
                        // the residual carries into the next one.
                        self.advance(report)?;
                        continue;
                    };
                    let entry = report.lanes.get_mut(lane).ok_or(overflow)?;
                    match source.serve(lane) {
                        Service::Served => {
                            let served_bytes =
                                entry.served_bytes.checked_add(charge).ok_or(overflow)?;
                            let served_frames =
                                entry.served_frames.checked_add(1).ok_or(overflow)?;
                            entry.served_bytes = served_bytes;
                            entry.served_frames = served_frames;
                            if let Some(slot) = self.deficit.get_mut(lane) {
                                *slot = residual;
                            }
                            // `charge <= bytes` was checked above.
                            bytes = bytes.checked_sub(charge).ok_or(overflow)?;
                        }
                        Service::NotServed => {
                            entry.failed = entry.failed.checked_add(1).ok_or(overflow)?;
                        }
                        Service::Backpressure => {
                            let lost = self.deficit.get(lane).copied().unwrap_or(0);
                            entry.forfeited = entry.forfeited.checked_add(lost).ok_or(overflow)?;
                            if let Some(deficit) = self.deficit.get_mut(lane) {
                                *deficit = 0;
                            }
                            // The visit ends and the cursor moves on, with no
                            // extra empty pass; a wrap from the last lane
                            // counts a round as usual.
                            self.advance(report)?;
                            return Ok(Stop::Backpressure { lane });
                        }
                        Service::Halt => return Ok(Stop::Halted { lane }),
                        Service::Uncertain => {
                            entry.uncertain_bytes =
                                entry.uncertain_bytes.checked_add(charge).ok_or(overflow)?;
                            // `charge <= bytes` was checked above.
                            bytes = bytes.checked_sub(charge).ok_or(overflow)?;
                        }
                    }
                }
            }
        }
    }

    /// Ends the visit under the cursor and moves to the next lane;
    /// wrapping completes a round.
    fn advance(&mut self, report: &mut Report) -> Result<(), DrrError> {
        let lane = self.cursor;
        self.credited = false;
        match lane.checked_add(1).filter(|next| *next < self.config.lanes) {
            Some(next) => self.cursor = next,
            None => {
                report.rounds = report
                    .rounds
                    .checked_add(1)
                    .ok_or(DrrError::Overflow { lane })?;
                self.cursor = 0;
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn inject_call_faults(&mut self) {
        if self.faults.credit_on_resume {
            self.credited = false;
        }
        if self.faults.restart_cursor {
            self.cursor = 0;
            self.credited = false;
        }
    }

    #[cfg(test)]
    fn inject_budget_fault(&mut self) {
        if self.faults.reset_on_budget
            && let Some(deficit) = self.deficit.get_mut(self.cursor)
        {
            *deficit = 0;
        }
    }
}

#[cfg(test)]
mod tests;
