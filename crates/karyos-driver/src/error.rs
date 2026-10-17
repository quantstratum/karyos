// SPDX-License-Identifier: Apache-2.0

//! Errors of the driver.

use karyos_client::ClientError;
use karyos_sys::conflation::ConflationError;
use karyos_sys::error::SysError;
use thiserror::Error;

/// Why `guard_stream` could not admit a stream's walker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum WalkerUnavailable {
    /// Every spare-slot credit the stream's `spare_slots` allows is in
    /// use: size `spare_slots` for the readers plus one.
    #[error("no spare-slot credit")]
    NoSpareCredit,
    /// Every reader cell of the stream is taken.
    #[error("no reader cell")]
    NoReaderCell,
}

/// Errors returned by the embedded driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DriverError {
    /// A network agent failed or panicked; fatal for the driver (DN-9).
    #[error("the {agent:?} network agent failed")]
    NetworkAgent {
        /// The agent.
        agent: crate::agents::AgentKind,
    },
    /// A network agent thread could not start.
    #[error("cannot start the network agent threads")]
    NetworkStart,
    /// The driver has no network configured (`DriverConfig::network`).
    #[error("no network is configured")]
    NetworkUnavailable,
    /// The channel uses a feature this driver does not wire yet (multi
    /// destination, redundant paths, an interface name).
    #[error("unsupported network channel")]
    UnsupportedChannel,
    /// A second subscription of one endpoint and stream asks for another
    /// reliability than the first: they would share one receiver entry,
    /// and a reliable subscriber must not get gap-tolerant delivery.
    #[error("the stream is already subscribed with another reliability")]
    ReliabilityMismatch,
    /// A second subscription of one endpoint and stream names another
    /// receiver identity than the first, or one where the first has none,
    /// or none where the first has one: they would share one receiver
    /// entry, whose images name one identity (MC-1).
    #[error("the stream is already subscribed with another receiver identity")]
    ReceiverIdentityMismatch,
    /// A second subscription of one endpoint and stream asks for another
    /// conflated lane than the first, or one where the first has none, or
    /// none where the first has one: they would share one receiver entry,
    /// whose images gate one lane's seals (conflated-network-images.md).
    #[error("the stream is already subscribed with another conflated lane")]
    ConflationMismatch,
    /// A network endpoint could not be opened or its table is full.
    #[error("network endpoint unavailable")]
    NetworkEndpoint,
    /// `AgentConfig::publications` network publications are held (being
    /// added, active or being removed).
    #[error("too many network publications")]
    NetworkPublicationsFull,
    /// `AgentConfig::subscriptions` distinct network subscriptions are
    /// held: the receiver's table is full.
    #[error("too many network subscriptions")]
    NetworkSubscriptionsFull,
    /// A network agent's command ring is full; retry later.
    #[error("network agent busy")]
    NetworkBusy,
    /// The driver's export and occupant ids are exhausted.
    #[error("export ids exhausted")]
    ExportIdsExhausted,
    /// A network publication's lanes cannot be reconfigured yet: the
    /// sender's readers follow one mapping.
    #[error("stream {stream} is a network publication; it cannot be reconfigured")]
    NetworkCutover {
        /// The stream.
        stream: u64,
    },
    /// The stream handle does not name a live stream of this driver.
    #[error("unknown stream {stream}")]
    UnknownStream {
        /// The handle's stream id.
        stream: u64,
    },
    /// The stream is being removed: it accepts no new publication or
    /// subscription.
    #[error("stream {stream} is retiring")]
    StreamRetiring {
        /// The handle's stream id.
        stream: u64,
    },
    /// `max_streams` streams are configured (active or retiring).
    #[error("too many streams")]
    TooManyStreams,
    /// Stream identities are exhausted.
    #[error("stream identities exhausted")]
    StreamIdsExhausted,
    /// The stream is one lane of an aggregate of several: it is removed or
    /// reconfigured with its aggregate.
    #[error("stream {stream} is a lane of an aggregate; act on the aggregate")]
    LaneOfAggregate {
        /// The stream.
        stream: u64,
    },
    /// A stream with the same wire stream id and session already exists.
    #[error("stream {stream_id} session {session_id} already exists")]
    DuplicateStream {
        /// Wire stream id.
        stream_id: i32,
        /// Session alias.
        session_id: i32,
    },
    /// A control-channel limit or size is invalid.
    #[error("invalid driver configuration")]
    InvalidConfig,
    /// No such guard: a foreign handle or an unknown id.
    #[error("unknown guard")]
    UnknownGuard,
    /// A guard of that name already exists.
    #[error("a guard of that name already exists")]
    DuplicateGuard,
    /// `max_guards` guards exist.
    #[error("too many guards")]
    TooManyGuards,
    /// Guard ids are exhausted; they are never reused.
    #[error("guard ids exhausted")]
    GuardIdsExhausted,
    /// The stream's guard is not open: a guarded publication is bound to
    /// an open epoch when it is issued.
    #[error("guard {guard} is not open")]
    GuardNotOpen {
        /// The guard id.
        guard: u64,
    },
    /// The stream was sealed by a guard close and the guard is open again,
    /// but the fresh incarnation could not be created yet: the sealed
    /// incarnation's publication has not released, or the stream is
    /// conflated or held by a remote client (remote incarnations: G-d2b).
    #[error("stream {stream} was sealed by a guard close")]
    GuardSealed {
        /// The stream id.
        stream: u64,
    },
    /// `guard_stream` could not admit the stream's walker, a reader that
    /// holds one spare-slot credit for the stream's life
    /// (`quantstratum-docs: karyos/design/guards-and-abort.md`, The
    /// walker's credit).
    #[error("stream {stream}'s guard walker is unavailable: {reason}")]
    GuardWalkerUnavailable {
        /// The stream id.
        stream: u64,
        /// What is missing.
        reason: WalkerUnavailable,
    },
    /// A rate limit names a scope other than the publication's, which
    /// Phase 2 does not support (GC-5).
    #[error("rate limits of scope {scope} are not supported")]
    RateScopeUnsupported {
        /// The scope named.
        scope: crate::guards::RateScope,
    },
    /// A rate limit policy was refused: a zero rate or burst, or a byte
    /// burst below the stream's largest frame.
    #[error(transparent)]
    InvalidRatePolicy(karyos_sys::rate_limit::RatePolicyError),
    /// Every sender slot of the guards' owner is taken
    /// (`DriverConfig::max_guard_senders`).
    #[error("too many guard senders")]
    TooManyGuardSenders,
    /// Guard sender ids are exhausted; they are never reused.
    #[error("guard sender ids exhausted")]
    GuardSenderIdsExhausted,
    /// The sender is not registered with this driver (never, or no more).
    #[error("unknown guard sender {sender}")]
    UnknownGuardSender {
        /// The sender id.
        sender: u64,
    },
    /// The stream is not a timed lane: its buffer has no schedule ring
    /// (`quantstratum-docs: karyos/design/timed-tx.md`).
    #[error("stream {stream} is not a timed lane")]
    NotTimed {
        /// The stream id.
        stream: u64,
    },
    /// A cutover of a timed lane: its schedule ring belongs to one
    /// incarnation's buffer and is never carried to a successor
    /// (`quantstratum-docs: karyos/design/timed-tx.md`, section 2 step 5),
    /// so timed lanes take no cutover until a design covers it.
    #[error("stream {stream} is a timed lane, which takes no cutover yet")]
    TimedCutover {
        /// The stream id.
        stream: u64,
    },
    /// A cutover of a network image's lane: the lane follows the remote
    /// sender's geometry and the receive owner writes the mapping it was
    /// given, so an image takes no cutover (`quantstratum-docs:
    /// karyos/design/network-shared-terms.md`, N-4a).
    #[error("stream {stream} is a network image's lane, which takes no cutover")]
    ImageCutover {
        /// The stream id.
        stream: u64,
    },
    /// The stream's incarnation numbers are exhausted; they are never
    /// reused.
    #[error("stream {stream}'s incarnations are exhausted")]
    IncarnationsExhausted {
        /// The stream id.
        stream: u64,
    },
    /// A guarded publication's outcome ring could not be sized or written.
    #[error(transparent)]
    Outcomes(karyos_sys::outcome_ring::OutcomeError),
    /// A guard transition was refused (`karyos_sys::guard`).
    #[error(transparent)]
    Guard(#[from] karyos_sys::guard::GuardError),

    /// A cutover of the stream is in progress
    /// (`quantstratum-docs: karyos/design/mapping-generations.md`): new handles wait for the
    /// successor, and a further reconfiguration waits for the cutover to
    /// end.
    #[error("stream {stream} has a cutover in progress")]
    CutoverPending {
        /// The stream id.
        stream: u64,
    },

    /// The successor would need generation `2^24`.
    #[error("mapping generations exhausted")]
    GenerationsExhausted,

    /// The successor could reach a stream position at or above `2^63`.
    #[error("stream positions exhausted")]
    PositionsExhausted,
    /// `max_clients` clients are admitted.
    #[error("too many clients")]
    TooManyClients,
    /// Client identities are exhausted.
    #[error("client identities exhausted")]
    ClientIdsExhausted,
    /// The driver is in its terminal state: its broadcast buffer is closed.
    #[error("the driver is in its terminal state")]
    Terminal,
    /// The driver stopped admitting clients
    /// ([`crate::EmbeddedDriver::stop_admitting`]).
    #[error("the driver is not admitting clients")]
    NotAdmitting,
    /// The process has used every driver identity.
    #[error("driver identities exhausted")]
    DriverIdsExhausted,
    /// Every trace number of this driver instance was handed out.
    #[error("trace numbers exhausted")]
    TraceNumbersExhausted,
    /// The driver has used every shared region identity.
    #[error("region identities exhausted")]
    RegionIdsExhausted,
    /// An IPC driver with a network could hold more descriptors than this
    /// process may open (`RLIMIT_NOFILE`): its image lanes, stream
    /// mappings and clients at their configured bounds. Checked at start.
    #[error("the driver may need {needed} descriptors, above the limit of {limit}")]
    DescriptorLimit {
        /// Descriptors the configured bounds can hold.
        needed: u64,
        /// The process's soft limit.
        limit: u64,
    },
    /// Every publication the stream can issue is out: its exclusive
    /// publication, or all `P` publisher slots of a concurrent stream.
    #[error("the stream's publication has already been taken")]
    PublicationTaken,
    /// The requested publication kind does not match the stream's mode: an
    /// exclusive publication of a concurrent stream, or a concurrent
    /// handle of an exclusive one.
    #[error("the publication kind does not match the stream's mode")]
    InvalidPublicationMode,
    /// The stream has no keyed conflation table.
    #[error("the stream is not configured for conflation")]
    NotConflated,
    /// A keyed conflation operation failed.
    #[error(transparent)]
    Conflation(#[from] ConflationError),
    /// A duty cycle's work count does not fit `u32`; the work was done
    /// and the count keeps its previous value.
    #[error("work count overflow: {count} + {delta}")]
    WorkCountOverflow {
        /// The count before the failed addition.
        count: u32,
        /// The work that did not fit.
        delta: u32,
    },
    /// A client-level error.
    #[error(transparent)]
    Client(#[from] ClientError),
    /// A lower layer failed.
    #[error(transparent)]
    Sys(#[from] SysError),
}
