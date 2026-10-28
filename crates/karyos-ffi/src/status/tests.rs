// SPDX-License-Identifier: Apache-2.0

use karyos_client::MessageLimit;
use karyos_protocol::cnc::ErrorCode;
use karyos_sys::frame::Lane;

use super::*;

#[test]
fn codes_are_unique_and_in_their_ranges() {
    let mut seen = std::collections::HashSet::new();
    for status in Status::ALL {
        assert!(seen.insert(status.code()), "{status:?} repeats a code");
        assert_eq!(Status::from_code(status.code()), Some(*status));
        let range = match status.code() {
            0 => "ok",
            1..=99 => "outcome",
            100..=199 => "usage",
            200..=299 => "lifecycle",
            300..=399 => "resource",
            400..=499 => "compatibility",
            500 => "internal",
            other => panic!("{status:?} has code {other} outside every range"),
        };
        let prefix = if range == "ok" {
            "KARYOS_OK"
        } else {
            "KARYOS_E_"
        };
        assert!(status.name().starts_with(prefix));
        assert!(!status.message().is_empty());
    }
    assert_eq!(Status::from_code(-1), None);
    assert_eq!(Status::from_code(99), None);
}

/// Every known Rust error maps to a status of its own: none falls back to
/// `UNKNOWN` but `ClientError::Unknown`.
#[test]
fn every_known_error_has_a_status() {
    let lane = Lane::try_new(1).unwrap();
    let offers = [
        (OfferError::NotConnected, Status::NotConnected),
        (OfferError::BackPressured, Status::BackPressured),
        (OfferError::AdminAction, Status::AdminAction),
        (OfferError::Closed, Status::ClosedPublication),
        (OfferError::Gated, Status::Gated),
        (OfferError::RateLimited, Status::RateLimited),
        (
            OfferError::MessageTooLarge { length: 9, max: 8 },
            Status::MessageTooLarge,
        ),
        (OfferError::Aborted { lane, position: 64 }, Status::Aborted),
        (
            OfferError::InvalidSchedule { reason: "r" },
            Status::InvalidSchedule,
        ),
        (OfferError::InvalidLane { lane }, Status::InvalidLane),
        (OfferError::Client(ClientError::Timeout), Status::Timeout),
    ];
    for (error, status) in offers {
        assert_eq!(Failure::from(&error).status, status, "{error:?}");
    }
    let clients = [
        (
            ClientError::MessageTooLarge { length: 9, max: 8 },
            Status::MessageTooLarge,
        ),
        (ClientError::EmptyMessage, Status::EmptyMessage),
        (
            ClientError::PositionsExhausted { base: 1 },
            Status::PositionsExhausted,
        ),
        (ClientError::ClosedByOverrun, Status::ClosedByOverrun),
        (
            ClientError::Conflation(ConflationError::Closed),
            Status::Closed,
        ),
        (
            ClientError::Conflation(ConflationError::InvalidConfig),
            Status::Conflation,
        ),
        (ClientError::OutcomesLost, Status::OutcomesLost),
        (
            ClientError::InvalidSchedule { reason: "r" },
            Status::InvalidSchedule,
        ),
        (
            ClientError::ScheduleTooFar {
                tx_time: 2,
                limit: 1,
            },
            Status::InvalidSchedule,
        ),
        (ClientError::ScheduleOverflow, Status::InvalidSchedule),
        (
            ClientError::Sys(SysError::ResourcesUnavailable),
            Status::ResourcesUnavailable,
        ),
        (
            ClientError::InvalidContext { reason: "r" },
            Status::InvalidContext,
        ),
        (ClientError::NoDirectory, Status::InvalidContext),
        (
            ClientError::Conductor(ConductorError::Full),
            Status::CommandRingFull,
        ),
        (ClientError::Timeout, Status::Timeout),
        (
            ClientError::UnsupportedChannel { detail: 3 },
            Status::UnsupportedChannel,
        ),
        (
            ClientError::Refused {
                code: ErrorCode::UnknownStream,
                detail: 5,
            },
            Status::Refused,
        ),
        (ClientError::Unknown, Status::Unknown),
        (ClientError::EventsLost, Status::EventsLost),
    ];
    for (error, status) in clients {
        assert_eq!(Failure::from(&error).status, status, "{error:?}");
    }
    let conductors = [
        (ConductorError::Full, Status::CommandRingFull),
        (ConductorError::Closed, Status::Closed),
        (ConductorError::TooManyPending, Status::TooManyPending),
        (
            ConductorError::SequencesExhausted,
            Status::ResourcesUnavailable,
        ),
        (ConductorError::ForeignHandle, Status::InvalidHandle),
        (ConductorError::LabelTooLong, Status::InvalidArgument),
        (ConductorError::InvalidJournal, Status::InvalidArgument),
        (ConductorError::UriTooLong, Status::InvalidChannel),
        (ConductorError::EmptyUri, Status::InvalidChannel),
        (
            ConductorError::InvalidChannel { code: 4 },
            Status::InvalidChannel,
        ),
        (ConductorError::CommandTooLarge, Status::InvalidArgument),
    ];
    for (error, status) in conductors {
        assert_eq!(Failure::from(&error).status, status, "{error:?}");
    }
    let closed = SubscriptionError::Closed(ClientError::ClosedByOverrun);
    assert_eq!(Failure::from(&closed).status, Status::Closed);
    // The limit type the poll will take is the core's.
    assert_eq!(MessageLimit::new(1).get(), 1);
}

#[test]
fn failures_carry_their_detail() {
    let too_large = Failure::from(&OfferError::MessageTooLarge { length: 9, max: 8 });
    assert_eq!((too_large.code, too_large.value), (9, 8));
    let refused = Failure::from(&ClientError::Refused {
        code: ErrorCode::LaneMismatch,
        detail: 2,
    });
    assert_eq!(
        (refused.code, refused.value),
        (ErrorCode::LaneMismatch.code(), 2)
    );
    // A code this peer does not define (karyos#819): KARYOS_E_REFUSED with
    // the raw wire code, as for any refusal.
    let unknown = Failure::from(&ClientError::Refused {
        code: ErrorCode::from_wire(1000).unwrap(),
        detail: 7,
    });
    assert_eq!(
        (unknown.status, unknown.code, unknown.value),
        (Status::Refused, 1000, 7)
    );
    let os = Failure::from(&SysError::Os {
        operation: "mmap",
        errno: 12,
    });
    assert_eq!(os, Failure::with(Status::System, 0, 12));
    let poll = SubscriptionError::Poll {
        session_id: None,
        delivered: 0,
        error: karyos_client::PollError::new(
            karyos_client::PollSummary::default(),
            ClientError::EventsLost,
        ),
    };
    assert_eq!(Failure::from(&poll).status, Status::EventsLost);
}

#[cfg(target_os = "linux")]
#[test]
fn attach_failures_map_to_compatibility_statuses() {
    use karyos_client::ipc::AttachError;
    let refused = Failure::from(&AttachError::IncompatibleVersion { driver: None });
    assert_eq!(refused, Failure::with(Status::IncompatibleDriver, 0, 0));
    let other = Failure::from(&AttachError::IncompatibleVersion { driver: Some(3) });
    assert_eq!(other, Failure::with(Status::IncompatibleDriver, 0, 3));
    let attach = ClientError::Attach(AttachError::Refused { code: 7 });
    assert_eq!(
        Failure::from(&attach),
        Failure::with(Status::AdmissionRefused, 7, 0)
    );
    assert_eq!(
        Failure::from(&AttachError::Protocol).status,
        Status::Protocol
    );
    assert_eq!(Failure::from(&AttachError::Timeout).status, Status::Timeout);
    assert_eq!(
        Failure::from(&AttachError::TooLarge).status,
        Status::Conflation
    );
}
