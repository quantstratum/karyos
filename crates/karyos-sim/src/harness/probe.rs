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
//! - **Per stage** (karyos#691): each count is also attributed to the
//!   [`Stage`] of the call that made it, the call and whether the core led
//!   when it was made, so a report shows which part of the replication
//!   path allocates ([`AllocationReport::stages`]).
//! - Counting needs `karyos_sys::alloc_count::CountingAllocator` as the
//!   global allocator, which a test binary installs. One measurement at a
//!   time in a process: a second one while a window is open is refused
//!   ([`MeasureError::WindowOpen`]). The simulator runs on the calling
//!   thread, so the window ends when its work does.

use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};

use karyos_sys::alloc_count::{SetCounts, count, count_allocations, enroll, window};

use super::core::{
    ConsensusCore, InstallRefused, Limits, LogView, Persisted, Ready, ReadyBuf, Refused,
    SnapshotBase, TransferRefused, Unsupported,
};
use super::workloads::{Case, Outcome, RunError, run};
use crate::net::NodeId;

/// Entries a core commits before its calls count: initialisation.
pub const WARMUP: u64 = 16;

/// The highest commit index any leader reached in the measurement.
static LEADER_COMMITTED: AtomicU64 = AtomicU64::new(0);

/// The part of the declared replication path a counted call belongs to:
/// the call, and whether the core led when it was made (karyos#691).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stage {
    /// `propose` or `propose_slice` on a leader: leader append.
    Propose,
    /// `step` on a leader: acknowledgements and commit advance.
    StepLeader,
    /// `step` on a follower: replication receive.
    StepFollower,
    /// `tick`.
    Tick,
    /// `ready` or `ready_into` on a leader: replication send and the
    /// committed entries to apply.
    ReadyLeader,
    /// `ready` or `ready_into` on a follower: its writes, acknowledgements
    /// and the committed entries to apply.
    ReadyFollower,
    /// `advance` on a leader: its own persistence reported.
    AdvanceLeader,
    /// `advance` on a follower: persistence acknowledgement.
    AdvanceFollower,
    /// The read-only queries and every other call.
    Other,
}

impl Stage {
    /// Every stage, in order.
    pub const ALL: [Self; 9] = [
        Self::Propose,
        Self::StepLeader,
        Self::StepFollower,
        Self::Tick,
        Self::ReadyLeader,
        Self::ReadyFollower,
        Self::AdvanceLeader,
        Self::AdvanceFollower,
        Self::Other,
    ];

    /// The stage of a call, by whether the core led: `(leader, follower)`.
    fn of(leads: bool, (leader, follower): (Self, Self)) -> Self {
        if leads { leader } else { follower }
    }

    /// Its position in [`Stage::ALL`].
    fn slot(self) -> usize {
        self as usize
    }

    /// Its name in a report.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Propose => "propose",
            Self::StepLeader => "step_leader",
            Self::StepFollower => "step_follower",
            Self::Tick => "tick",
            Self::ReadyLeader => "ready_leader",
            Self::ReadyFollower => "ready_follower",
            Self::AdvanceLeader => "advance_leader",
            Self::AdvanceFollower => "advance_follower",
            Self::Other => "other",
        }
    }
}

/// Allocations per stage in the measurement, by [`Stage::slot`].
static STAGE_ALLOCATIONS: [AtomicU64; 9] = [const { AtomicU64::new(0) }; 9];
/// Frees per stage in the measurement, by [`Stage::slot`].
static STAGE_FREES: [AtomicU64; 9] = [const { AtomicU64::new(0) }; 9];

/// Adds one counted call's operations to its stage.
fn note_stage(stage: Stage, operations: u64, allocations: u64) {
    let slot = stage.slot();
    if let (Some(allocated), Some(freed)) = (STAGE_ALLOCATIONS.get(slot), STAGE_FREES.get(slot)) {
        let _ = allocated.fetch_add(allocations, Ordering::Relaxed);
        let _ = freed.fetch_add(operations.saturating_sub(allocations), Ordering::Relaxed);
    }
}

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
        if !self.past.get() {
            return read(&self.core);
        }
        let _enrolled = enroll();
        let ((result, allocations), operations) = count(|| count_allocations(|| read(&self.core)));
        note_stage(Stage::Other, operations, allocations);
        result
    }

    /// Runs `call` on the inner core, counted once it is past the warm-up,
    /// and notes a leader's commit index; that query is counted as well
    /// once past, and is the warm-up's own test before.
    fn counted<R>(&mut self, stages: (Stage, Stage), call: impl FnOnce(&mut C) -> R) -> R {
        let result = if self.past.get() {
            // The stage is read before the window counts anything.
            let stage = Stage::of(self.core.leads(), stages);
            let _enrolled = enroll();
            let ((result, allocations), operations) =
                count(|| count_allocations(|| call(&mut self.core)));
            note_stage(stage, operations, allocations);
            result
        } else {
            call(&mut self.core)
        };
        let (leads, committed) = self.read(|core| (core.leads(), core.committed()));
        if leads && let Some(committed) = committed {
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
        self.counted((Stage::Propose, Stage::Other), |core| {
            core.propose(command, log)
        })
    }

    fn propose_slice(&mut self, command: &[u8], log: &mut LogView<'_>) -> Result<(), Refused> {
        self.counted((Stage::Propose, Stage::Other), |core| {
            core.propose_slice(command, log)
        })
    }

    fn ready_into(&mut self, out: &mut ReadyBuf<Self::Message>, log: &mut LogView<'_>) -> bool {
        self.counted((Stage::ReadyLeader, Stage::ReadyFollower), |core| {
            core.ready_into(out, log)
        })
    }

    fn step(&mut self, from: NodeId, message: Self::Message, log: &mut LogView<'_>) {
        self.counted((Stage::StepLeader, Stage::StepFollower), |core| {
            core.step(from, message, log)
        });
    }

    fn tick(&mut self, now: u64, log: &mut LogView<'_>) {
        self.counted((Stage::Tick, Stage::Tick), |core| core.tick(now, log));
    }

    fn ready(&mut self, log: &mut LogView<'_>) -> Option<Ready<Self::Message>> {
        self.counted((Stage::ReadyLeader, Stage::ReadyFollower), |core| {
            core.ready(log)
        })
    }

    fn advance(&mut self, persisted: Persisted, log: &mut LogView<'_>) {
        self.counted((Stage::AdvanceLeader, Stage::AdvanceFollower), |core| {
            core.advance(persisted, log)
        });
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

    fn compacted(&mut self, base: SnapshotBase, log: &mut LogView<'_>) -> Result<(), Unsupported> {
        self.counted((Stage::Other, Stage::Other), |core| {
            core.compacted(base, log)
        })
    }

    fn install(&mut self, base: SnapshotBase, log: &mut LogView<'_>) -> Result<(), InstallRefused> {
        self.counted((Stage::Other, Stage::Other), |core| core.install(base, log))
    }

    fn transfer_leadership(
        &mut self,
        to: NodeId,
        log: &mut LogView<'_>,
    ) -> Result<(), TransferRefused> {
        self.counted((Stage::Other, Stage::Other), |core| {
            core.transfer_leadership(to, log)
        })
    }

    fn propose_change(
        &mut self,
        change: super::core::Change,
        log: &mut LogView<'_>,
    ) -> Result<(), super::core::ChangeRefused> {
        self.counted((Stage::Other, Stage::Other), |core| {
            core.propose_change(change, log)
        })
    }
}

/// One measurement of the allocation gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllocationReport {
    /// Allocations and frees on the declared path after the warm-up.
    pub counts: SetCounts,
    /// Entries the leaders committed past the warm-up.
    pub entries: u64,
    /// The counts by stage, every stage listed, summing to `counts`.
    pub stages: Vec<(Stage, SetCounts)>,
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
        for counter in STAGE_ALLOCATIONS.iter().chain(STAGE_FREES.iter()) {
            counter.store(0, Ordering::SeqCst);
        }
        let outcome = run::<Probed<C>>(case, seed);
        (outcome, LEADER_COMMITTED.load(Ordering::SeqCst))
    })
    .map_err(|_| MeasureError::WindowOpen)?;
    let outcome = outcome.map_err(MeasureError::Run)?;
    let entries = committed.saturating_sub(WARMUP);
    let stages = Stage::ALL
        .iter()
        .zip(STAGE_ALLOCATIONS.iter().zip(STAGE_FREES.iter()))
        .map(|(&stage, (allocations, frees))| {
            (
                stage,
                SetCounts {
                    allocations: allocations.load(Ordering::SeqCst),
                    frees: frees.load(Ordering::SeqCst),
                },
            )
        })
        .collect();
    Ok(AllocationReport {
        counts,
        entries,
        stages,
        outcome,
    })
}
