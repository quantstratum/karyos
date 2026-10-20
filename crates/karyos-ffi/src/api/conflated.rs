// SPDX-License-Identifier: Apache-2.0

//! Conflated subscriptions of an embedded driver's streams (F7b-2b;
//! quantstratum-docs: karyos/design/ffi-gap-analysis.md,
//! karyos/design/conflation-end-to-end.md).
//!
//! A conflated subscription handle wraps the driver's
//! `ConflatedSubscription` of a stream created with a conflation table. It
//! records its driver's state, which it follows as a subscription does: a
//! closed or lost driver answers [`Status::Closed`] or
//! [`Status::Internal`], with no lock.
//!
//! The poll hands each changed key's latest value to the caller's handler
//! from the reader's private copy, never from the table (SPEC.md §10.2).
//! A view whose table published a terminal invalidation answers
//! [`Status::Closed`] on that poll and every later one.
//!
//! The handler runs while the handle's slot is held: a handler that polls
//! or closes its own conflated subscription gets [`Status::Reentrant`].

use std::sync::OnceLock;

use karyos_client::{ClientError, ConflatedOptions, ConflatedSubscription, StreamId};
use karyos_driver::{DriverConfig, DriverError};
use karyos_sys::conflation::Budget;
use karyos_sys::freshness::Freshness;

use crate::api::client::{Ended, with_client};
use crate::api::driver::{self, DriverState};
use crate::handles::{Handle, Kind, Table};
use crate::status::{Failure, Status};

/// The most conflated subscriptions open at once
/// (`KARYOS_MAX_CONFLATED_SUBSCRIPTIONS`).
pub(crate) const MAX_CONFLATED_SUBSCRIPTIONS: u32 = 4096;

/// `KARYOS_FRESH`: the freshness of a value no committed gap covers; any
/// other value is the start of the gap that made it stale.
pub(crate) const FRESH: u64 = u64::MAX;

/// A conflated subscription handle's object.
pub(crate) struct Entry {
    /// An embedded driver's view (F7b-2b): the driver's state, whose
    /// failure and close it follows.
    driver: Option<DriverState>,
    /// A remote client's view (F7b-2c): the client, whose close closes it.
    client: Option<Handle>,
    view: ConflatedSubscription,
    /// Read attempts per served key: the driver's.
    retries: u32,
}

/// The table of conflated subscriptions, allocated on first use.
pub(crate) fn table() -> &'static Table<Entry> {
    static CONFLATED: OnceLock<Table<Entry>> = OnceLock::new();
    CONFLATED.get_or_init(|| Table::new(Kind::ConflatedSubscription, MAX_CONFLATED_SUBSCRIPTIONS))
}

/// What a poll hands each value to: its key, its bytes, its version and
/// its freshness code.
pub(crate) type ValueHandler<'a> = dyn FnMut(u32, &[u8], u64, u64) + 'a;

/// `freshness` as the C ABI hands it over.
fn freshness_code(freshness: Freshness) -> u64 {
    match freshness {
        Freshness::Stale { since } => since,
        // A reader never delivers `Retry` (it copies the slot again).
        Freshness::Fresh | Freshness::Retry => FRESH,
    }
}

/// Subscribes to the conflation table of `driver`'s stream `stream_id`.
///
/// # Errors
///
/// [`Status::InvalidArgument`] for a stream id the driver does not have,
/// [`Status::Conflation`] for a stream without a conflation table,
/// [`Status::Closed`] for a stream being removed, the driver's handle
/// failures, and [`Status::HandlesExhausted`].
pub(crate) fn subscribe(driver: Handle, stream_id: i32) -> Result<Handle, Failure> {
    let (view, state) = driver::with_stream(driver, stream_id, |embedded, stream| {
        embedded.subscribe_conflated(stream)
    })?;
    let view = view.map_err(|error| match error {
        DriverError::NotConflated => Failure::from(Status::Conflation),
        DriverError::StreamRetiring { .. } | DriverError::UnknownStream { .. } => {
            Status::Closed.into()
        }
        other => Failure::from(&other),
    })?;
    let retries = DriverConfig::default()
        .conflated_subscription_budget
        .retries;
    Ok(table().insert(Entry {
        driver: Some(state),
        client: None,
        view,
        retries,
    })?)
}

/// Adds a view of the conflation table of the `karyos:ipc` stream
/// `stream_id` to `client` (F7b-2c), tracked by the client, whose close
/// closes it.
///
/// # Errors
///
/// The client's handle and control call failures (a client of an
/// embedded driver is refused by the driver: [`Status::Refused`]), and
/// [`Status::HandlesExhausted`], with the view released.
pub(crate) fn add(client: Handle, uri: &str, stream_id: i32) -> Result<Handle, Failure> {
    with_client(client, |entry| {
        entry.usable()?;
        let view = entry
            .client
            .add_conflated_subscription(uri, StreamId::new(stream_id))?;
        let retries = ConflatedOptions::default().budget.retries;
        let added = table().insert_or_return(Entry {
            driver: None,
            client: Some(client),
            view,
            retries,
        });
        match added {
            Ok(handle) => {
                entry.conflated.push(handle);
                Ok(handle)
            }
            // Dropping the view releases it.
            Err((status, _)) => Err(status.into()),
        }
    })?
}

/// Delivers the latest value of at most `key_budget` changed keys of
/// `conflated` to `handler(key, value, version, freshness)`, and returns
/// how many it delivered.
///
/// # Errors
///
/// The handle's failures, the driver's state, and [`Status::Closed`] once
/// the view closed, with the values delivered before it.
pub(crate) fn poll(
    conflated: Handle,
    key_budget: u32,
    handler: &mut ValueHandler<'_>,
) -> Result<u32, (Failure, u32)> {
    table()
        .with(conflated, |entry| {
            if let Some(driver) = &entry.driver {
                driver
                    .usable()
                    .map_err(|status| (Failure::from(status), 0))?;
            }
            let budget = Budget {
                keys: key_budget,
                retries: entry.retries,
            };
            let mut delivered = 0u32;
            let polled = entry.view.poll_changed_with(budget, |key, value| {
                handler(
                    key,
                    value.payload(),
                    value.version(),
                    freshness_code(value.freshness()),
                );
                // At most `key_budget` values: never past a u32.
                if let Some(next) = delivered.checked_add(1) {
                    delivered = next;
                }
            });
            // A closed view (`ClientError::ViewClosed`) is `Closed` on every
            // later poll too: the reader reports its terminal again.
            polled
                .map(|_| delivered)
                .map_err(|error: ClientError| (Failure::from(&error), delivered))
        })
        .map_err(|status| (Failure::from(status), 0))?
}

/// Closes `conflated`.
///
/// # Errors
///
/// The handle's failures.
pub(crate) fn close(conflated: Handle) -> Result<(), Status> {
    // A remote view is closed through its client, which forgets it; its
    // client, written at the add and never changed, is read even from a
    // poisoned handle, as a subscription's is.
    match table().read_even_poisoned(conflated, |entry| entry.client)? {
        Some(client) => {
            crate::api::client::close_child(client, table(), conflated, |handle, entry| {
                Ended::Conflated(handle, Box::new(entry))
            })
        }
        None => {
            let _ = table().remove(conflated)?;
            Ok(())
        }
    }
}
