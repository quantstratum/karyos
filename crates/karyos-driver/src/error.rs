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
