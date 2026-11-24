// SPDX-License-Identifier: Apache-2.0

//! Which build of a candidate a run used (ADR-0043, baseline and patched
//! variants): every run record names it, so patch eligibility is evidenced
//! rather than asserted.

/// A candidate's build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    /// The crates.io release exactly as admitted, no local patch.
    Baseline,
    /// The release with the local patches its [`PatchRecord`]s list.
    Patched(&'static [PatchRecord]),
    /// The custom core (ADR-0105), built from this repository's
    /// `karyos-cluster` at the run's commit: no external release, so no
    /// patch (C5 version 2; karyos#681, karyos#691).
    InTree,
}

/// The build of the custom core the comparison runs:
/// [`karyos_sim::harness::custom::Custom`] over `karyos-cluster`'s
/// [`Core`](karyos_cluster::consensus::Core).
pub const CUSTOM: Variant = Variant::InTree;

impl Variant {
    /// The patches it carries: none for the baseline.
    #[must_use]
    pub fn patches(&self) -> &'static [PatchRecord] {
        match self {
            Self::Baseline | Self::InTree => &[],
            Self::Patched(patches) => patches,
        }
    }

    /// A one-line label for a run record.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::Patched(_) => "patched",
            Self::InTree => "in-tree",
        }
    }
}

/// One local patch of a candidate: what it changes and why, for the
/// evaluation manifest (admission record, condition 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PatchRecord {
    /// The crate patched.
    pub krate: &'static str,
    /// What the patch changes.
    pub change: &'static str,
    /// The gate or finding that needs it.
    pub reason: &'static str,
}
