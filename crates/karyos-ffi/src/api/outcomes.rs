// SPDX-License-Identifier: Apache-2.0

//! The outcome streams of guarded publications (F7a-2;
//! quantstratum-docs: karyos/design/ffi-gap-analysis.md §6, and
//! karyos/design/guards-and-abort.md, "The outcome stream", G5).
//!
//! A guarded publication's lane has an outcome ring its driver writes; the
//! poll hands its records to the caller in sequence order, through the
//! facade's `Publication::poll_outcomes_on`, with the publication's slot
//! held. A guarded publication reaches the C ABI through a remote client:
//! a client of the in-process command ring is refused a guarded stream.
//! After the driver's final `OutcomesLost` record, the stream has ended:
//! later polls deliver nothing, and offers and claims fail with
//! `OUTCOMES_LOST`.

use karyos_sys::outcome_ring::Record;

use crate::api::publication::{lane, table};
use crate::handles::Handle;
use crate::status::Failure;

/// Delivers up to `limit` outcome records of `lane_raw` of `publication`
/// to `handler`, each with its sequence; returns how many were delivered,
/// also with a failure.
///
/// # Errors
///
/// [`crate::status::Status::InvalidLane`] for a lane the publication does
/// not configure, the handle's failures, and the outcome stream's, such as
/// a corrupt record; each with the records delivered before it.
pub(crate) fn poll(
    publication: Handle,
    lane_raw: u32,
    limit: u32,
    handler: &mut dyn FnMut(u64, &Record),
) -> Result<u32, (Failure, u32)> {
    let lane = lane(lane_raw).map_err(|failure| (failure, 0))?;
    // A `u32` fits a `usize` on every target the ABI supports; a larger
    // limit than records is no limit.
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    table()
        .with(publication, |entry| {
            entry
                .usable()
                .map_err(|status| (Failure::from(status), 0))?;
            // At most `limit` records, so never past a `u32`.
            let mut delivered = 0u32;
            let polled = entry
                .lanes
                .poll_outcomes_on(lane, limit, |sequence, record| {
                    handler(sequence, &record);
                    delivered = delivered.saturating_add(1);
                });
            match polled {
                Ok(_) => Ok(delivered),
                Err(error) => Err((Failure::from(&error), delivered)),
            }
        })
        .map_err(|status| (Failure::from(status), 0))?
}
