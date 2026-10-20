// SPDX-License-Identifier: Apache-2.0

//! The C ABI's status codes and their mapping from the Rust errors
//! (quantstratum-docs: karyos/design/ffi-gap-analysis.md §4.3).
//!
//! `0` is success. The other codes are grouped by range so a binding can
//! classify a code a newer minor version adds: 1-99 data-path outcomes,
//! 100-199 usage, 200-299 lifecycle, 300-399 resource and driver, 400-499
//! compatibility, 500 internal. A number never changes once a header with
//! it is released. `include/karyos.h` repeats every code; a test checks it.

use core::ffi::CStr;

use karyos_client::ClientError;
use karyos_client::OfferError;
use karyos_client::SubscriptionError;
use karyos_client::conductor::ConductorError;
use karyos_sys::conflation::ConflationError;
use karyos_sys::error::SysError;

/// Defines [`Status`], its codes, its C names and its static messages.
macro_rules! statuses {
    ($($variant:ident = $code:literal, $name:literal, $message:literal;)+) => {
        /// A C ABI status code.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #[repr(i32)]
        pub(crate) enum Status {
            $(
                #[doc = $name]
                $variant = $code,
            )+
        }

        impl Status {
            /// Every status, in code order.
            #[cfg(test)]
            pub(crate) const ALL: &[Self] = &[$(Self::$variant),+];

            /// The name the header gives the code.
            #[cfg(test)]
            pub(crate) const fn name(self) -> &'static str {
                match self {
                    $(Self::$variant => $name,)+
                }
            }

            /// The status of `code`, when it is one.
            pub(crate) const fn from_code(code: i32) -> Option<Self> {
                match code {
                    $($code => Some(Self::$variant),)+
                    _ => None,
                }
            }

            /// The status's static text.
            pub(crate) const fn message(self) -> &'static CStr {
                match self {
                    $(Self::$variant => $message,)+
                }
            }
        }
    };
}

statuses! {
    Ok = 0, "KARYOS_OK", c"success";
    BackPressured = 1, "KARYOS_E_BACK_PRESSURED", c"back pressured: the subscribers are behind";
    NotConnected = 2, "KARYOS_E_NOT_CONNECTED", c"no subscriber is connected";
    AdminAction = 3, "KARYOS_E_ADMIN_ACTION", c"an administrative action is in progress; retry";
    ClosedPublication = 4, "KARYOS_E_CLOSED_PUBLICATION", c"the publication is closed";
    Gated = 5, "KARYOS_E_GATED", c"the guard is closed";
    RateLimited = 6, "KARYOS_E_RATE_LIMITED", c"the rate limit refused the message";
    Aborted = 7, "KARYOS_E_ABORTED", c"the block was aborted";
    InvalidArgument = 100, "KARYOS_E_INVALID_ARGUMENT", c"invalid argument";
    InvalidHandle = 101, "KARYOS_E_INVALID_HANDLE", c"not a handle of this kind";
    MessageTooLarge = 102, "KARYOS_E_MESSAGE_TOO_LARGE", c"the message exceeds the maximum length";
    EmptyMessage = 103, "KARYOS_E_EMPTY_MESSAGE", c"empty message";
    InvalidLane = 104, "KARYOS_E_INVALID_LANE", c"the lane is not configured";
    InvalidSchedule = 105, "KARYOS_E_INVALID_SCHEDULE", c"invalid schedule";
    InvalidChannel = 106, "KARYOS_E_INVALID_CHANNEL", c"invalid channel URI";
    InvalidContext = 107, "KARYOS_E_INVALID_CONTEXT", c"invalid context";
    Reentrant = 108, "KARYOS_E_REENTRANT", c"the handle is in use by this thread's callback";
    Busy = 109, "KARYOS_E_BUSY", c"the handle is in use by another thread";
    Conflation = 110, "KARYOS_E_CONFLATION", c"conflation error";
    Unsupported = 111, "KARYOS_E_UNSUPPORTED", c"not supported on this platform";
    ClaimOutstanding = 112, "KARYOS_E_CLAIM_OUTSTANDING", c"the publication has a claim outstanding; commit or abort it first";
    Closed = 200, "KARYOS_E_CLOSED", c"closed";
    ClosedByOverrun = 201, "KARYOS_E_CLOSED_BY_OVERRUN", c"the subscription was closed by its rejoin policy";
    PositionsExhausted = 202, "KARYOS_E_POSITIONS_EXHAUSTED", c"the stream position range is exhausted";
    OutcomesLost = 203, "KARYOS_E_OUTCOMES_LOST", c"the publication's outcomes were lost";
    EventsLost = 204, "KARYOS_E_EVENTS_LOST", c"driver events were lost";
    Outcomes = 205, "KARYOS_E_OUTCOMES", c"the outcome stream failed";
    HandlesExhausted = 300, "KARYOS_E_HANDLES_EXHAUSTED", c"no free handle of this kind";
    CommandRingFull = 301, "KARYOS_E_COMMAND_RING_FULL", c"the command ring is full; retry";
    TooManyPending = 302, "KARYOS_E_TOO_MANY_PENDING", c"too many pending requests";
    Timeout = 303, "KARYOS_E_TIMEOUT", c"the driver did not answer in time";
    Refused = 304, "KARYOS_E_REFUSED", c"the driver refused the request";
    UnsupportedChannel = 305, "KARYOS_E_UNSUPPORTED_CHANNEL", c"the driver does not serve this channel";
    Unknown = 306, "KARYOS_E_UNKNOWN", c"unknown failure";
    System = 307, "KARYOS_E_SYSTEM", c"a system call or a region check failed";
    ResourcesUnavailable = 308, "KARYOS_E_RESOURCES_UNAVAILABLE", c"resources unavailable";
    IncompatibleDriver = 400, "KARYOS_E_INCOMPATIBLE_DRIVER", c"the driver runs another protocol version";
    AdmissionRefused = 401, "KARYOS_E_ADMISSION_REFUSED", c"the driver refused the client";
    Protocol = 402, "KARYOS_E_PROTOCOL", c"admission protocol error";
    Internal = 500, "KARYOS_E_INTERNAL", c"internal error; the handle is poisoned";
}

/// The text of a status code that is none.
pub(crate) const UNKNOWN_CODE: &CStr = c"unknown status code";

impl Status {
    /// The code.
    pub(crate) const fn code(self) -> i32 {
        self as i32
    }
}

/// A failure with the detail the Rust error carries: the code and value of
/// the C `karyos_detail` out-parameter (zero when it carries none).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Failure {
    /// The status.
    pub(crate) status: Status,
    /// A code the status defines, such as the driver's refusal code.
    pub(crate) code: u64,
    /// A value the status defines, such as a length or an `errno`.
    pub(crate) value: u64,
}

impl Failure {
    /// A failure without detail.
    pub(crate) const fn of(status: Status) -> Self {
        Self {
            status,
            code: 0,
            value: 0,
        }
    }

    /// A failure with a code and a value.
    pub(crate) const fn with(status: Status, code: u64, value: u64) -> Self {
        Self {
            status,
            code,
            value,
        }
    }
}

impl From<Status> for Failure {
    fn from(status: Status) -> Self {
        Self::of(status)
    }
}

impl From<&OfferError> for Failure {
    fn from(error: &OfferError) -> Self {
        match error {
            OfferError::NotConnected => Status::NotConnected.into(),
            OfferError::BackPressured => Status::BackPressured.into(),
            OfferError::AdminAction => Status::AdminAction.into(),
            OfferError::Closed => Status::ClosedPublication.into(),
            OfferError::Gated => Status::Gated.into(),
            OfferError::RateLimited => Status::RateLimited.into(),
            OfferError::MessageTooLarge { length, max } => {
                Self::with(Status::MessageTooLarge, u64::from(*length), u64::from(*max))
            }
            OfferError::Aborted { lane, position } => {
                Self::with(Status::Aborted, u64::from(lane.get()), *position)
            }
            OfferError::InvalidSchedule { .. } => Status::InvalidSchedule.into(),
            OfferError::InvalidLane { lane } => {
                Self::with(Status::InvalidLane, u64::from(lane.get()), 0)
            }
            OfferError::Client(error) => error.into(),
            _ => Status::Unknown.into(),
        }
    }
}

impl From<&ClientError> for Failure {
    fn from(error: &ClientError) -> Self {
        match error {
            ClientError::MessageTooLarge { length, max } => {
                Self::with(Status::MessageTooLarge, u64::from(*length), u64::from(*max))
            }
            ClientError::EmptyMessage => Status::EmptyMessage.into(),
            ClientError::PositionsExhausted { base } => {
                Self::with(Status::PositionsExhausted, 0, *base)
            }
            ClientError::ClosedByOverrun => Status::ClosedByOverrun.into(),
            ClientError::Conflation(error) => error.into(),
            ClientError::OutcomesLost => Status::OutcomesLost.into(),
            ClientError::Outcomes(_) => Status::Outcomes.into(),
            ClientError::InvalidSchedule { .. }
            | ClientError::ScheduleTooFar { .. }
            | ClientError::ScheduleOverflow => Status::InvalidSchedule.into(),
            ClientError::Sys(error) => error.into(),
            ClientError::InvalidContext { .. } | ClientError::NoDirectory => {
                Status::InvalidContext.into()
            }
            ClientError::InvalidOptions { .. } => Status::InvalidArgument.into(),
            #[cfg(target_os = "linux")]
            ClientError::Attach(error) => error.into(),
            ClientError::Conductor(error) => error.into(),
            ClientError::Timeout => Status::Timeout.into(),
            ClientError::UnsupportedChannel { detail } => {
                Self::with(Status::UnsupportedChannel, 0, *detail)
            }
            ClientError::Refused { code, detail } => {
                Self::with(Status::Refused, code.code(), *detail)
            }
            ClientError::ViewClosed(_) => Status::Closed.into(),
            ClientError::EventsLost => Status::EventsLost.into(),
            _ => Status::Unknown.into(),
        }
    }
}

impl From<&ConductorError> for Failure {
    fn from(error: &ConductorError) -> Self {
        match error {
            ConductorError::Full => Status::CommandRingFull.into(),
            ConductorError::Closed => Status::Closed.into(),
            ConductorError::TooManyPending => Status::TooManyPending.into(),
            ConductorError::SequencesExhausted => Status::ResourcesUnavailable.into(),
            ConductorError::ForeignHandle => Status::InvalidHandle.into(),
            ConductorError::LabelTooLong
            | ConductorError::InvalidJournal
            | ConductorError::CommandTooLarge => Status::InvalidArgument.into(),
            ConductorError::UriTooLong | ConductorError::EmptyUri => Status::InvalidChannel.into(),
            ConductorError::InvalidChannel { code } => Self::with(Status::InvalidChannel, *code, 0),
            _ => Status::Unknown.into(),
        }
    }
}

impl From<&SubscriptionError> for Failure {
    fn from(error: &SubscriptionError) -> Self {
        match error {
            SubscriptionError::Poll { error, .. } => (&error.cause).into(),
            SubscriptionError::Closed(_) => Status::Closed.into(),
            _ => Status::Unknown.into(),
        }
    }
}

impl From<&ConflationError> for Failure {
    fn from(error: &ConflationError) -> Self {
        match error {
            ConflationError::Closed => Status::Closed.into(),
            _ => Status::Conflation.into(),
        }
    }
}

impl From<&SysError> for Failure {
    fn from(error: &SysError) -> Self {
        match error {
            SysError::Os { errno, .. } => {
                Self::with(Status::System, 0, u64::from(errno.cast_unsigned()))
            }
            SysError::MaxPositionExceeded { count } => {
                Self::with(Status::PositionsExhausted, 0, *count)
            }
            SysError::ResourcesUnavailable => Status::ResourcesUnavailable.into(),
            SysError::EmptyMessage => Status::EmptyMessage.into(),
            _ => Status::System.into(),
        }
    }
}

#[cfg(target_os = "linux")]
impl From<&karyos_client::ipc::AttachError> for Failure {
    fn from(error: &karyos_client::ipc::AttachError) -> Self {
        use karyos_client::ipc::AttachError;
        match error {
            AttachError::Refused { code } => Self::with(Status::AdmissionRefused, *code, 0),
            // The driver's version when it admitted the client at another
            // one; zero, never a version, when it refused.
            AttachError::IncompatibleVersion { driver } => {
                Self::with(Status::IncompatibleDriver, 0, driver.unwrap_or(0))
            }
            AttachError::Protocol => Status::Protocol.into(),
            AttachError::Timeout => Status::Timeout.into(),
            AttachError::Sys(error) => error.into(),
            AttachError::TooLarge => Status::Conflation.into(),
            _ => Status::Unknown.into(),
        }
    }
}

#[cfg(test)]
mod tests;
