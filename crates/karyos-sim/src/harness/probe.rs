// SPDX-License-Identifier: Apache-2.0

//! The C5 allocation gate's probe (karyos#691; quantstratum-docs:
//! karyos/evaluations/c5-raft-comparison-v1.md, Hard gates: "0 allocations
//! and 0 frees per replicated entry on the declared replication path after
//! initialisation").
//!
//! - **The declared path** (decided 2026-10-30 by QS-COORDINATOR) is at
//!   least every [`ConsensusCore`] call, and any thread the adapter
//!   declares besides (an executor's tasks, a background thread), which
//!   enrolls itself with `karyos_sys::alloc_count::enroll` and is named in
//!   the run record. [`Probed`] enrolls the calling thread for each call of
//!   the core it wraps, the read-only ones (`term`, `leads`, `received`,
//!   `committed`, `configuration`) and its own queries included, so the
//!   harness's own work between calls (the simulator, the recorder, the
//!   traces) is never counted, and nothing of the core is missed.
//! - **After initialisation**: once the core it wraps has committed
//!   [`WARMUP`] entries, every call of it counts, for the rest of the run.
//! - **Per replicated entry**: the counts over the entries the leaders
//!   committed past the warm-up ([`AllocationReport::entries`]).
//! - Counting needs `karyos_sys::alloc_count::CountingAllocator` as the
//!   global allocator, which a test binary installs. One measurement at a
//!   time in a process: a second one while a window is open is refused
//!   ([`MeasureError::WindowOpen`]). The simulator runs on the calling
//!   thread, so the window ends when its work does.

use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};

use karyos_sys::alloc_count::{SetCounts, enroll, window};

use super::core::{ConsensusCore, Limits, LogView, Persisted, Ready, Refused, Unsupported};
use super::workloads::{Case, Outcome, RunError, run};
use crate::net::NodeId;

/// Entries a core commits before its calls count: initialisation.
pub const WARMUP: u64 = 16;

/// The highest commit index any leader reached in the measurement.
static LEADER_COMMITTED: AtomicU64 = AtomicU64::new(0);

/// A core whose every call, once it has committed [`WARMUP`] entries,
/// counts toward the allocation gate.
#[derive(Debug)]
pub struct Probed<C> {
    core: C,
    /// Past the warm-up: from then on, every call of `core` counts.
    past: Cell<bool>,
}

impl<C: ConsensusCore> Probed<C> {
    /// Runs `read` on the inner core, counted once it is past the warm-up.
    fn read<R>(&self, read: impl FnOnce(&C) -> R) -> R {
        let _enrolled = self.past.get().then(enroll);
        read(&self.core)
    }

    /// Runs `call` on the inner core, counted once it is past the warm-up,
    /// and notes a leader's commit index; that query is counted as well
    /// once past, and is the warm-up's own test before.
    fn counted<R>(&mut self, call: impl FnOnce(&mut C) -> R) -> R {
        let _enrolled = self.past.get().then(enroll);
        let result = call(&mut self.core);
        let committed = self.core.committed();
        if self.core.leads()
            && let Some(committed) = committed
        {
            LEADER_COMMITTED.fetch_max(committed, Ordering::Relaxed);
        }
        if committed.is_some_and(|committed| committed >= WARMUP) {
            self.past.set(true);
        }
        result
    }
}

impl<C: ConsensusCore> ConsensusCore for Probed<C> {
    type Message = C::Message;

    fn recover(id: NodeId, peers: &[NodeId], log: &mut LogView<'_>) -> Self {
        Self {
            core: C::recover(id, peers, log),
            past: Cell::new(false),
        }
    }

    fn recover_with(
        id: NodeId,
        peers: &[NodeId],
        limits: &Limits,
        log: &mut LogView<'_>,
    ) -> Result<Self, Unsupported> {
        Ok(Self {
            core: C::recover_with(id, peers, limits, log)?,
            past: Cell::new(false),
        })
    }

    fn propose(&mut self, command: Vec<u8>, log: &mut LogView<'_>) -> Result<(), Refused> {
        self.counted(|core| core.propose(command, log))
    }

    fn step(&mut self, from: NodeId, message: Self::Message, log: &mut LogView<'_>) {
        self.counted(|core| core.step(from, message, log));
    }

    fn tick(&mut self, now: u64, log: &mut LogView<'_>) {
        self.counted(|core| core.tick(now, log));
    }

    fn ready(&mut self, log: &mut LogView<'_>) -> Option<Ready<Self::Message>> {
        self.counted(|core| core.ready(log))
    }

    fn advance(&mut self, persisted: Persisted, log: &mut LogView<'_>) {
        self.counted(|core| core.advance(persisted, log));
    }

    fn term(&self) -> u64 {
        self.read(C::term)
    }

    fn leads(&self) -> bool {
        self.read(C::leads)
    }

    fn received(&self) -> Option<u64> {
        self.read(C::received)
    }

    fn committed(&self) -> Option<u64> {
        self.read(C::committed)
    }

    fn configuration(&self) -> Option<super::core::Configuration> {
        self.read(C::configuration)
    }

    fn propose_change(
        &mut self,
        change: super::core::Change,
        log: &mut LogView<'_>,
    ) -> Result<(), super::core::ChangeRefused> {
        self.counted(|core| core.propose_change(change, log))
    }
}

/// One measurement of the allocation gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllocationReport {
    /// Allocations and frees on the declared path after the warm-up.
    pub counts: SetCounts,
    /// Entries the leaders committed past the warm-up.
    pub entries: u64,
    /// The run itself.
    pub outcome: Outcome,
}

impl AllocationReport {
    /// Allocations and frees per replicated entry, rounded up; `None`
    /// with no entry past the warm-up (nothing was measured).
    #[must_use]
    pub fn per_entry(&self) -> Option<(u64, u64)> {
        (self.entries > 0).then(|| {
            (
                self.counts.allocations.div_ceil(self.entries),
                self.counts.frees.div_ceil(self.entries),
            )
        })
    }
}

/// Why a measurement gave no report.
#[derive(Debug)]
pub enum MeasureError {
    /// The run could not be set up or stepped.
    Run(RunError),
    /// Another measurement's window is open in this process.
    WindowOpen,
}

/// Measures `case` of core `C` under `seed`: its run with every call of
/// `C` past the warm-up counted.
///
/// # Errors
///
/// [`MeasureError`].
pub fn measure<C: ConsensusCore>(case: &Case, seed: u64) -> Result<AllocationReport, MeasureError> {
    // The leaders' commit index is the window's, as its counts are: reset
    // and read while this measurement holds it.
    let ((outcome, committed), counts) = window(|| {
        LEADER_COMMITTED.store(0, Ordering::SeqCst);
        let outcome = run::<Probed<C>>(case, seed);
        (outcome, LEADER_COMMITTED.load(Ordering::SeqCst))
    })
    .map_err(|_| MeasureError::WindowOpen)?;
    let outcome = outcome.map_err(MeasureError::Run)?;
    let entries = committed.saturating_sub(WARMUP);
    Ok(AllocationReport {
        counts,
        entries,
        outcome,
    })
}
