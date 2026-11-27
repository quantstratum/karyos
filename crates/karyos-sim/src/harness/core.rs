// SPDX-License-Identifier: Apache-2.0

//! The consensus core a harness node drives, and the one driver that
//! orders its persistence: `karyos_cluster::driver`, re-exported here so
//! the harness, its candidates and fixtures, and the shipped node share
//! one interface (C6, quantstratum/karyos#681). This module adds only the
//! harness's run seed.

use std::cell::Cell;

pub use karyos_cluster::driver::*;

thread_local! {
    /// The seed of the workload run on this thread, 0 outside one.
    static RUN_SEED: Cell<u64> = const { Cell::new(0) };
}

/// The seed of the workload run this thread is in ([`super::workloads::run`]),
/// or 0 outside one: an adapter seeds each node's election timeout draw
/// from it and the node's id, so the timing differs from seed to seed
/// and stays a function of the seed (C5 v2 manifest, Timing; karyos#691).
#[must_use]
pub fn run_seed() -> u64 {
    RUN_SEED.with(Cell::get)
}

/// Sets [`run_seed`] for the life of the guard, and puts the previous
/// value back when it drops.
#[must_use = "the seed is set only while the guard lives"]
pub struct RunSeed(u64);

impl RunSeed {
    /// Sets the thread's run seed to `seed`.
    pub fn set(seed: u64) -> Self {
        Self(RUN_SEED.with(|cell| cell.replace(seed)))
    }
}

impl Drop for RunSeed {
    fn drop(&mut self) {
        RUN_SEED.with(|cell| cell.set(self.0));
    }
}

/// The seed of node `id`'s election timeout draw in the run seeded
/// `seed`: the id alone outside a run (`seed` 0), so a path with no run
/// seed keeps its old draw.
#[must_use]
pub const fn node_seed(seed: u64, id: u64) -> u64 {
    // The multiplication wraps by design: a spread of the seed's bits.
    id ^ seed.wrapping_mul(0xD1B5_4A32_D192_ED03)
}

#[cfg(test)]
mod run_seed_tests {
    use super::{RunSeed, node_seed, run_seed};

    /// The guard sets the seed for its life and puts the previous one
    /// back, nested or not; outside a run it is 0.
    #[test]
    fn a_run_seed_lives_as_long_as_its_guard() {
        assert_eq!(run_seed(), 0);
        {
            let _outer = RunSeed::set(7);
            assert_eq!(run_seed(), 7);
            {
                let _inner = RunSeed::set(9);
                assert_eq!(run_seed(), 9);
            }
            assert_eq!(run_seed(), 7);
        }
        assert_eq!(run_seed(), 0);
    }

    /// Outside a run a node keeps its id as its seed; under a run every
    /// seed of the corpus gives each node another draw, and no two nodes
    /// of a run share one.
    #[test]
    fn each_run_seed_gives_each_node_its_own_draw() {
        for id in 0..5 {
            assert_eq!(node_seed(0, id), id);
        }
        let mut seen = std::collections::BTreeSet::new();
        for seed in 1..=1_000 {
            for id in 0..5 {
                assert!(seen.insert(node_seed(seed, id)), "seed {seed} node {id}");
            }
        }
    }
}
