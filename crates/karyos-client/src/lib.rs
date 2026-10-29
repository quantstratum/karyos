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
pub mod capabilities;
pub mod client;
pub mod concurrent;
pub mod conductor;
pub mod conflated_subscription;
pub mod counter;
pub mod error;
pub mod generation;
pub mod groups;
pub mod guard_acks;
pub mod guarded;
#[cfg(target_os = "linux")]
pub mod ipc;
pub mod journal;
pub mod link;
pub mod loss;
pub mod merge;
#[cfg(target_os = "linux")]
pub mod probe;
pub mod publication;
pub mod refresh;
pub mod schedule;
pub mod subscription;
#[cfg(target_os = "linux")]
pub mod tool;
pub mod trace;

pub use client::{
    Accepted, Claim, Client, Connection, Context, ContextBuilder, DEFAULT_MAX_IMAGES,
    DEFAULT_MAX_PENDING, DEFAULT_TIMEOUT, IdleStrategy, ImageChange, ImageEnd, ImageStop,
    MessageLength, NotRejoinable, OfferError, OfferOptions, Publication, RejoiningSubscription,
    ReplayTargetSubscriber, Subscription, SubscriptionError, SubscriptionOptions, SubscriptionPoll,
};
pub use concurrent::{
    ClientConcurrentClaim, ClientConcurrentPublication, ConcurrentClaimOutcome,
    ConcurrentOfferOutcome,
};
pub use conductor::{
    ClientConductor, Completion, ConductorError, ConductorPoll, DEFAULT_DRIVER_TIMEOUT,
    DEFAULT_HEARTBEAT_INTERVAL, EVENT_QUEUE, Fetchable, FetchableConflated, Outcome, Request,
};
pub use conflated_subscription::{
    CONFLATION_BUDGETS_EXHAUSTED, CONFLATION_SKIPS, ConflatedLimits, ConflatedOptions,
    ConflatedSubscription, ConflatedValue, ReaderCounts, ViewClosed,
};
pub use counter::{ClientCounterHandle, CounterKind, CounterReleases, TracePointHandle};
pub use error::ClientError;
pub use generation::{GenerationLink, LinkStatus, Next, Successor};
pub use guarded::{ConsumedCell, GuardBinding, HeapWords, SharedWords};
pub use journal::{ClientJournal, FetchableJournal};
pub use karyos_protocol::cnc::{NetworkAdmission, StreamId, SubscriberRole};

/// The admission protocol version this client announces in its `Hello`
/// (karyos#752, R-CORE-33): a driver of another version refuses the attach
/// with `AttachError::IncompatibleVersion`, naming its own. Written out,
/// not aliased, so a protocol change has to update the public value on
/// purpose; it is asserted equal at compile time.
pub const PROTOCOL_VERSION: u64 = 3;
const _: () = assert!(PROTOCOL_VERSION == karyos_protocol::admission::VERSION);
pub use karyos_protocol::roles::{PublicationRoles, ReceiverIdentity, Strategy};
/// The publication identity a replay and a live merge name (merge module).
pub use karyos_protocol::trace_hook::PublicationIdentity;
pub use karyos_sys::conflation::Budget as ConflatedBudget;
pub use karyos_sys::frame::Lane;
pub use karyos_sys::freshness::Freshness;
/// Why a stream sealed, as a retired image's end reports it ([`ImageEnd`]).
pub use karyos_sys::log_buffer::SealReason;
pub use loss::{LOSS_REPORT_QUEUE, LossReports};
pub use merge::{
    LiveMerge, MergeError, MergeFailed, MergePoll, Replay, ReplayProvider, ReplayRejoin,
    ReplayRequest, ReplayStatus, ReplayStop, ReplayUnavailable,
};
pub use publication::{ClaimOutcome, ClientClaim, ClientPublication, CommitOutcome, OfferOutcome};
pub use refresh::{CycleError, CycleId, RefreshCycle, Scope as CycleScope};
pub use subscription::{
    Aborted, ClientSubscription, InvalidExtensions, MessageInfo, MessageLimit, Overrun, PollError,
    PollSummary, RejoinOutcome, RejoinPolicy, ReplayFallbackReason, Secondary, SecondaryOutcome,
    Skipped, SnapshotFailed, SnapshotSource,
};
pub use trace::TraceDecision;
