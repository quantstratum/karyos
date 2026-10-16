// SPDX-License-Identifier: Apache-2.0

//! Publications, subscriptions, the client conductor, conflation and lanes.
//!
//! That is the planned scope from `quantstratum-docs: karyos/SPEC.md` §14. Implemented so far: the
//! embedded-mode publication and subscription API over one lane's log buffer
//! (copy delivery), a bounded client view over the keyed conflation table,
//! and the client conductor that requests capabilities from the driver.
//! The driver feeder and lanes beyond one do not yet exist. Linux IPC
//! attachment is implemented.

/// Counts this test binary's allocations, for the data calls that must not
/// allocate (`karyos_sys::alloc_count`).
#[cfg(test)]
#[global_allocator]
static ALLOCATOR: karyos_sys::alloc_count::CountingAllocator =
    karyos_sys::alloc_count::CountingAllocator;

pub mod aggregate;
pub mod concurrent;
pub mod conductor;
pub mod conflated_subscription;
pub mod counter;
pub mod error;
pub mod generation;
pub mod guarded;
#[cfg(target_os = "linux")]
pub mod ipc;
pub mod journal;
pub mod link;
pub mod loss;
pub mod publication;
pub mod subscription;
#[cfg(target_os = "linux")]
pub mod tool;
pub mod trace;

pub use concurrent::{
    ClientConcurrentClaim, ClientConcurrentPublication, ConcurrentClaimOutcome,
    ConcurrentOfferOutcome,
};
pub use conductor::{
    ClientConductor, Completion, ConductorError, ConductorPoll, DEFAULT_DRIVER_TIMEOUT,
    DEFAULT_HEARTBEAT_INTERVAL, EVENT_QUEUE, Fetchable, FetchableConflated, Outcome, Request,
};
pub use conflated_subscription::{
    CONFLATION_BUDGETS_EXHAUSTED, CONFLATION_SKIPS, ConflatedSubscription, ReaderCounts,
};
pub use counter::{ClientCounterHandle, CounterReleases};
pub use error::ClientError;
pub use generation::{GenerationLink, LinkStatus, Successor};
pub use guarded::{ConsumedCell, GuardBinding, HeapWords, SharedWords};
pub use journal::{ClientJournal, FetchableJournal};
pub use loss::{LOSS_REPORT_QUEUE, LossReports};
pub use publication::{ClaimOutcome, ClientClaim, ClientPublication, CommitOutcome, OfferOutcome};
pub use subscription::{
    Aborted, ClientSubscription, InvalidExtensions, MessageInfo, MessageLimit, Overrun, PollError,
    PollSummary, RejoinOutcome, RejoinPolicy, ReplayFallbackReason, Secondary, SecondaryOutcome,
    Skipped, SnapshotFailed, SnapshotSource,
};
pub use trace::TraceDecision;
