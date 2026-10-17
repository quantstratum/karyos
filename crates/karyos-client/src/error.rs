// SPDX-License-Identifier: Apache-2.0

//! Errors of the client API.

use karyos_sys::conflation::ConflationError;
use karyos_sys::error::{LayoutError, SysError};
use karyos_sys::outcome_ring::OutcomeError;
use thiserror::Error;

/// Errors returned by publications and subscriptions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ClientError {
    /// The message exceeds the publication's maximum message length.
    #[error("message of {length} bytes exceeds the maximum of {max}")]
    MessageTooLarge {
        /// The message length.
        length: u32,
        /// The maximum message length.
        max: u32,
    },
    /// An application message must carry at least one byte.
    #[error("empty application message")]
    EmptyMessage,
    /// A mapping starting at `base` could report a stream position at or
    /// above `2^63` (`quantstratum-docs: karyos/design/mapping-generations.md`).
    #[error("a mapping starting at {base} exceeds the stream position range")]
    PositionsExhausted {
        /// The rejected base.
        base: u64,
    },
    /// The subscription was closed by its rejoin policy after an overrun
    /// (`quantstratum-docs: karyos/design/rejoin-policies.md`): it takes no
    /// generation link.
    #[error("the subscription was closed by its rejoin policy")]
    ClosedByOverrun,
    /// A conflated publication rejected its key or value size.
    #[error(transparent)]
    Conflation(#[from] ConflationError),
    /// The driver faulted this guarded handle's outcome stream: it wrote
    /// the final `OutcomesLost` record, so outstanding reservations can no
    /// longer be resolved. The handle is terminal; take a new one
    /// (`quantstratum-docs: karyos/design/guards-and-abort.md`, G5).
    #[error("the guarded publication's outcomes were lost; the handle is terminal")]
    OutcomesLost,
    /// A guarded publication's outcome ring is invalid or corrupt
    /// (`quantstratum-docs: karyos/design/guards-and-abort.md`, G5).
    #[error(transparent)]
    Outcomes(#[from] OutcomeError),
    /// A timed send was refused before reservation
    /// (`quantstratum-docs: karyos/design/timed-tx.md`, section 7): a
    /// requested time below the lane's last accepted one (times within a
    /// timed lane never go backwards), a plain offer or claim on a timed
    /// lane, a timed offer on a lane that is not timed, or a clock domain
    /// this host does not have.
    #[error("invalid schedule: {reason}")]
    InvalidSchedule {
        /// What is wrong.
        reason: &'static str,
    },
    /// The requested time is beyond the publication's `max_horizon`.
    #[error("requested time {tx_time} is beyond the horizon {limit}")]
    ScheduleTooFar {
        /// The requested time.
        tx_time: u64,
        /// The latest time accepted now.
        limit: u64,
    },
    /// A deadline sum (`now + max_horizon`, `tx_time + lateness_tolerance`)
    /// overflows the time type: refused, never wrapped.
    #[error("a schedule deadline overflows the time type")]
    ScheduleOverflow,
    /// A lower layer failed.
    #[error(transparent)]
    Sys(SysError),
    /// The facade's context is not usable (`client::ContextBuilder::build`).
    #[error("invalid context: {reason}")]
    InvalidContext {
        /// What is wrong.
        reason: &'static str,
    },
    /// `Client::connect` needs the driver's directory.
    #[error("the context names no driver directory")]
    NoDirectory,
    /// Attaching to the driver, or taking a grant from it, failed.
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Attach(#[from] crate::ipc::AttachError),
    /// A request could not be submitted.
    #[error(transparent)]
    Conductor(#[from] crate::conductor::ConductorError),
    /// A request did not complete within the context's timeout. What its
    /// late answer grants is released when it arrives
    /// (`Client::late_grants_released`).
    #[error("the driver did not answer in time")]
    Timeout,
    /// The driver does not serve this channel on this connection: a
    /// network channel of a remote client (D3), no network, or a feature
    /// not wired yet.
    #[error("the driver does not serve this channel (detail {detail})")]
    UnsupportedChannel {
        /// The refusal's detail.
        detail: u64,
    },
    /// The driver refused the request.
    #[error("the driver refused the request ({code:?}, detail {detail})")]
    Refused {
        /// Why.
        code: karyos_protocol::cnc::ErrorCode,
        /// The refusal's detail.
        detail: u64,
    },
    /// A request ended without a usable answer: the driver was lost, or it
    /// answered with a grant of another kind.
    #[error("the request ended without a usable answer")]
    Unknown,
    /// A conflated view closed for good (SPEC.md §7.1): its table published
    /// a terminal invalidation.
    #[error(transparent)]
    ViewClosed(#[from] crate::conflated_subscription::ViewClosed),
    /// Driver events were lost, so a network subscription can no longer
    /// know its images: it is closed.
    #[error("driver events were lost; the subscription is closed")]
    EventsLost,
}

impl From<SysError> for ClientError {
    fn from(error: SysError) -> Self {
        match error {
            SysError::EmptyMessage => Self::EmptyMessage,
            SysError::Layout(LayoutError::MessageTooLarge { length, max }) => {
                Self::MessageTooLarge { length, max }
            }
            SysError::Schedule(karyos_sys::schedule_ring::ScheduleError::NotScheduled) => {
                Self::InvalidSchedule {
                    reason: "a timed lane takes timed offers only, and only a timed lane does",
                }
            }
            SysError::Schedule(karyos_sys::schedule_ring::ScheduleError::Backwards) => {
                Self::InvalidSchedule {
                    reason: "a requested time below the lane's last",
                }
            }
            other => Self::Sys(other),
        }
    }
}
