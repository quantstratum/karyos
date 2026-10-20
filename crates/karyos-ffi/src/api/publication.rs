// SPDX-License-Identifier: Apache-2.0

//! Exclusive publications and their staged claims (F3; quantstratum-docs:
//! karyos/design/ffi-gap-analysis.md §4.4, D1).
//!
//! A publication handle wraps the facade's `Publication` of its client's
//! connection, and records the client, whose handle closes it. Offers copy
//! the caller's bytes as Rust offers do.
//!
//! A C claim is staged (SPEC.md §10.2; D1, ruled (a)): the caller writes
//! into a buffer owned by `karyos-ffi`, never into a term, and the commit
//! claims in the term, copies the staged bytes and commits in one call. The
//! buffer is allocated once per publication, at its creation, with the
//! largest message any of its lanes accepts, so a publication has at most
//! one outstanding claim. Its bytes are `AtomicU8` behind an `Arc`: the
//! caller writes them through a raw pointer while the publication's slot
//! may be held by another call, which only ever reads them through a shared
//! reference, so no Rust reference claims them exclusively. When the commit
//! meets a data-path outcome that can clear (back pressure, no subscriber,
//! an administrative action, the rate limit, a closed guard), the claim
//! stays staged for a retry; any other outcome releases it.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, OnceLock};

use karyos_client::{Accepted, MessageLength, OfferError, Publication};
use karyos_sys::frame::Lane;
use karyos_sys::term_bytes::HeapTerms;

use crate::api::client::{AnyClient, clients};
use crate::handles::{Handle, Kind, Table};
use crate::status::{Failure, Status};

/// The most publications open at once (`KARYOS_MAX_PUBLICATIONS`).
pub(crate) const MAX_PUBLICATIONS: u32 = 4096;
/// The most claims outstanding at once (`KARYOS_MAX_CLAIMS`): at most one
/// per publication.
pub(crate) const MAX_CLAIMS: u32 = MAX_PUBLICATIONS;

/// A publication's lanes over either connection.
#[derive(Debug)]
pub(crate) enum Lanes {
    /// Of a client attached to a driver in another process.
    #[cfg(target_os = "linux")]
    Remote(Publication<karyos_sys::term_bytes::SharedTerms>),
    /// Of a client over an embedded driver's conductor.
    Embedded(Publication<HeapTerms>),
}

/// Runs `$body` on the publication of either connection.
macro_rules! lanes {
    ($lanes:expr, $publication:ident => $body:expr) => {
        match $lanes {
            #[cfg(target_os = "linux")]
            Lanes::Remote($publication) => $body,
            Lanes::Embedded($publication) => $body,
        }
    };
}

impl Lanes {
    /// The largest message any lane accepts.
    fn max_message_length(&self) -> u32 {
        lanes!(self, publication => (0..Lane::COUNT)
            .filter_map(|lane| Lane::try_new(lane).ok())
            .filter_map(|lane| publication.max_message_length(lane))
            .max()
            .unwrap_or(0))
    }

    /// The largest message `lane` accepts; `None` for an unconfigured lane.
    fn lane_max(&self, lane: Lane) -> Option<u32> {
        lanes!(self, publication => publication.max_message_length(lane))
    }

    fn offer_on(&mut self, lane: Lane, payload: &[u8]) -> Result<Accepted, OfferError> {
        lanes!(self, publication => publication.offer_on(lane, payload))
    }

    /// Claims `length` in `lane`'s term, copies `staged` into it and
    /// commits it.
    fn commit_staged(
        &mut self,
        lane: Lane,
        length: MessageLength,
        staged: &[AtomicU8],
    ) -> Result<Accepted, OfferError> {
        lanes!(self, publication => {
            let mut claim = publication.try_claim_on(lane, length)?;
            for (byte, staged) in claim.payload().iter_mut().zip(staged) {
                *byte = staged.load(Ordering::Relaxed);
            }
            claim.commit()
        })
    }
}

/// The outstanding claim of a publication.
#[derive(Debug, Clone, Copy)]
struct Staged {
    /// Its claim handle.
    handle: Handle,
    lane: Lane,
    length: MessageLength,
}

/// A publication handle's object.
#[derive(Debug)]
pub(crate) struct Entry {
    /// The client handle it belongs to.
    client: Handle,
    /// Its client's embedded driver, if the C ABI created it: the
    /// publication follows its failure and its close
    /// (`crate::api::driver::usable`).
    driver: Option<Handle>,
    lanes: Lanes,
    /// The staging buffer of its claims.
    staged: Arc<[AtomicU8]>,
    claim: Option<Staged>,
}

impl Entry {
    /// Whether the publication may act: its client's embedded driver,
    /// if any, is neither poisoned nor closed.
    fn usable(&self) -> Result<(), Status> {
        self.driver.map_or(Ok(()), crate::api::driver::usable)
    }

    /// Releases the publication to `client`, and its outstanding claim.
    pub(crate) fn release(self, client: &mut AnyClient) {
        if let Some(staged) = self.claim {
            // A claim's slot is held only while a call reads it: waiting
            // never leaks it.
            let _ = claims().remove_waiting(staged.handle);
        }
        client.remove_publication(self.lanes);
    }
}

/// The table of publications, allocated on first use.
pub(crate) fn table() -> &'static Table<Entry> {
    static PUBLICATIONS: OnceLock<Table<Entry>> = OnceLock::new();
    PUBLICATIONS.get_or_init(|| Table::new(Kind::Publication, MAX_PUBLICATIONS))
}

/// The table of claims: each names its publication.
fn claims() -> &'static Table<Handle> {
    static CLAIMS: OnceLock<Table<Handle>> = OnceLock::new();
    CLAIMS.get_or_init(|| Table::new(Kind::Claim, MAX_CLAIMS))
}

/// The lane `raw`, or [`Status::InvalidLane`].
fn lane(raw: u32) -> Result<Lane, Failure> {
    u8::try_from(raw)
        .ok()
        .and_then(|lane| Lane::try_new(lane).ok())
        .ok_or_else(|| Failure::with(Status::InvalidLane, u64::from(raw), 0))
}

/// Adds the exclusive publication of `stream_id` on `uri` to `client`.
///
/// # Errors
///
/// The client's handle and control call failures, and
/// [`Status::HandlesExhausted`], with the publication released.
pub(crate) fn add(client: Handle, uri: &str, stream_id: i32) -> Result<Handle, Failure> {
    clients().with(client, |entry| {
        entry.usable()?;
        let lanes = entry
            .client
            .add_publication(uri, karyos_client::StreamId::new(stream_id))?;
        let staged: Arc<[AtomicU8]> = (0..lanes.max_message_length())
            .map(|_| AtomicU8::new(0))
            .collect();
        let publication = Entry {
            client,
            driver: entry.driver,
            lanes,
            staged,
            claim: None,
        };
        match table().insert_or_return(publication) {
            Ok(handle) => {
                entry.publications.push(handle);
                Ok(handle)
            }
            Err((status, publication)) => {
                publication.release(&mut entry.client);
                Err(status.into())
            }
        }
    })?
}

/// Offers `payload` on `lane`.
///
/// # Errors
///
/// The handle's and the offer's failures.
pub(crate) fn offer(
    publication: Handle,
    lane_raw: u32,
    payload: &[u8],
) -> Result<Accepted, Failure> {
    let lane = lane(lane_raw)?;
    table().with(publication, |entry| {
        entry.usable()?;
        entry
            .lanes
            .offer_on(lane, payload)
            .map_err(|error| Failure::from(&error))
    })?
}

/// Stages a claim of `length` bytes on `lane`: its handle, and the buffer
/// the caller fills until it commits or aborts.
///
/// # Errors
///
/// [`Status::ClaimOutstanding`] while one is, [`Status::EmptyMessage`],
/// [`Status::InvalidLane`], [`Status::MessageTooLarge`],
/// [`Status::HandlesExhausted`], and the handle's failures.
pub(crate) fn claim(
    publication: Handle,
    lane_raw: u32,
    length: u32,
) -> Result<(Handle, *mut u8), Failure> {
    let lane = lane(lane_raw)?;
    table().with(publication, |entry| {
        entry.usable()?;
        if entry.claim.is_some() {
            return Err(Status::ClaimOutstanding.into());
        }
        let length = MessageLength::try_new(length).map_err(|error| Failure::from(&error))?;
        let max = entry
            .lanes
            .lane_max(lane)
            .ok_or_else(|| Failure::with(Status::InvalidLane, u64::from(lane.get()), 0))?;
        if length.get() > max {
            return Err(Failure::with(
                Status::MessageTooLarge,
                u64::from(length.get()),
                u64::from(max),
            ));
        }
        let bytes = usize::try_from(length.get()).map_err(|_| Status::MessageTooLarge)?;
        // A claim starts zeroed, as a Rust claim does.
        for byte in entry.staged.iter().take(bytes) {
            byte.store(0, Ordering::Relaxed);
        }
        let handle = claims().insert(publication)?;
        entry.claim = Some(Staged {
            handle,
            lane,
            length,
        });
        Ok((handle, entry.staged.as_ptr().cast::<u8>().cast_mut()))
    })?
}

/// The largest message `lane` of `publication` accepts (tests).
#[cfg(test)]
pub(crate) fn lane_max(publication: Handle, lane: Lane) -> Option<u32> {
    table()
        .with(publication, |entry| entry.lanes.lane_max(lane))
        .ok()
        .flatten()
}

/// Whether a commit that met `error` keeps its claim staged for a retry.
fn retryable(error: &OfferError) -> bool {
    matches!(
        error,
        OfferError::BackPressured
            | OfferError::NotConnected
            | OfferError::AdminAction
            | OfferError::RateLimited
            | OfferError::Gated
    )
}

/// Commits `claim`: claims in the term, copies the staged bytes, commits.
///
/// # Errors
///
/// The commit's failures; a retryable one keeps the claim staged.
pub(crate) fn commit(claim: Handle) -> Result<Accepted, Failure> {
    let publication = claims().with(claim, |publication| *publication)?;
    table().with(publication, |entry| {
        entry.usable()?;
        let staged = entry
            .claim
            .filter(|staged| staged.handle == claim)
            .ok_or(Status::Closed)?;
        let committed = entry
            .lanes
            .commit_staged(staged.lane, staged.length, &entry.staged);
        if !committed.as_ref().is_err_and(retryable) {
            entry.claim = None;
            let _ = claims().remove_waiting(claim);
        }
        committed.map_err(|error| Failure::from(&error))
    })?
}

/// Aborts `claim`: nothing reaches the term.
///
/// # Errors
///
/// The handle's failures.
pub(crate) fn abort(claim: Handle) -> Result<(), Status> {
    let publication = claims().with(claim, |publication| *publication)?;
    table().with(publication, |entry| {
        if entry.claim.is_some_and(|staged| staged.handle == claim) {
            entry.claim = None;
            claims().remove_waiting(claim).map(drop)
        } else {
            Err(Status::Closed)
        }
    })?
}

/// Closes `publication` through its client, and its outstanding claim.
///
/// # Errors
///
/// The handle's failures, its client's included.
pub(crate) fn close(publication: Handle) -> Result<(), Status> {
    let client = table().with(publication, |entry| entry.client)?;
    clients().with(client, |entry| {
        let removed = table().remove(publication)?;
        entry.publications.retain(|handle| *handle != publication);
        removed.release(&mut entry.client);
        Ok(())
    })?
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The outcomes that can clear keep a claim staged; every other one
    /// releases it.
    #[test]
    fn only_outcomes_that_can_clear_keep_a_claim_staged() {
        let lane = Lane::ZERO;
        for kept in [
            OfferError::BackPressured,
            OfferError::NotConnected,
            OfferError::AdminAction,
            OfferError::RateLimited,
            OfferError::Gated,
        ] {
            assert!(retryable(&kept), "{kept:?}");
        }
        for released in [
            OfferError::Closed,
            OfferError::Aborted { lane, position: 0 },
            OfferError::InvalidLane { lane },
            OfferError::MessageTooLarge { length: 2, max: 1 },
            OfferError::InvalidSchedule { reason: "r" },
            OfferError::Client(karyos_client::ClientError::Timeout),
        ] {
            assert!(!retryable(&released), "{released:?}");
        }
    }
}
