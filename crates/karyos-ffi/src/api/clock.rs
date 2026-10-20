// SPDX-License-Identifier: Apache-2.0

//! The clock a timed lane's requested times are read in (`quantstratum-docs:
//! karyos/design/timed-tx.md`, TT-2): `karyos_clock_now`.

use karyos_client::schedule::ClockDomain;

use crate::abi::{CLOCK_MONOTONIC, CLOCK_TAI};
use crate::status::{Failure, Status};

/// The current time in the domain `raw` (`KARYOS_CLOCK_*`, which the
/// header test holds equal to [`ClockDomain::code`]): the time `karyos_publication_offer_at` expects
/// for a lane of that domain.
///
/// # Errors
///
/// [`Status::InvalidArgument`] for a domain this build does not know, and
/// [`Status::Unsupported`] for a domain this platform cannot read (`Tai`
/// off Linux, or a kernel that refuses `CLOCK_TAI`).
pub(crate) fn now(raw: u32) -> Result<u64, Failure> {
    let domain = match raw {
        CLOCK_MONOTONIC => ClockDomain::Monotonic,
        CLOCK_TAI => ClockDomain::Tai,
        _ => return Err(Failure::with(Status::InvalidArgument, u64::from(raw), 0)),
    };
    karyos_client::schedule::now(domain).map_err(|_| Failure::of(Status::Unsupported))
}
