// SPDX-License-Identifier: Apache-2.0

//! Exclusive and concurrent publications and their staged claims (F3, F7a-1;
//! quantstratum-docs: karyos/design/ffi-gap-analysis.md §4.4, D1).
//!
//! A publication handle wraps the facade's `Publication` of its client's
//! connection, or a concurrent handle on lane 0 of a `karyos:ipc` stream
//! shared with other publishers, and records the client, whose handle
//! closes it. Offers copy the caller's bytes as Rust offers do. Both kinds
//! answer the same calls: a concurrent handle has lane 0 only.
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

use karyos_client::{
    ClientConcurrentPublication, ClientError, CommitOutcome, ConcurrentClaimOutcome,
    ConcurrentOfferOutcome, MessageLength, OfferError, Publication,
};
use karyos_sys::frame::Lane;
use karyos_sys::term_bytes::HeapTerms;

use crate::api::client::{AnyClient, ClientEntry, Ended, with_client};
use crate::handles::{Handle, Kind, Table};
use crate::status::{Failure, Status};

/// The most publications open at once (`KARYOS_MAX_PUBLICATIONS`).
pub(crate) const MAX_PUBLICATIONS: u32 = 4096;
/// The most claims outstanding at once (`KARYOS_MAX_CLAIMS`): at most one
/// per publication.
pub(crate) const MAX_CLAIMS: u32 = MAX_PUBLICATIONS;

/// Where an accepted message went: its lane and its position there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Placed {
    /// The lane.
    pub(crate) lane: Lane,
    /// The position in it.
    pub(crate) position: u64,
}

/// A publication over either connection: an exclusive one's lanes, or a
/// concurrent handle on lane 0 (boxed: it is larger than the others).
#[derive(Debug)]
pub(crate) enum Lanes {
    /// Of a client attached to a driver in another process.
    #[cfg(target_os = "linux")]
    Remote(Publication<karyos_sys::term_bytes::SharedTerms>),
    /// Of a client over an embedded driver's conductor.
    Embedded(Publication<HeapTerms>),
    /// A concurrent handle of a client in another process.
    #[cfg(target_os = "linux")]
    ConcurrentRemote(Box<ClientConcurrentPublication<karyos_sys::term_bytes::SharedTerms>>),
    /// A concurrent handle of a client over an embedded conductor.
    ConcurrentEmbedded(Box<ClientConcurrentPublication<HeapTerms>>),
}

/// Runs `$exclusive` on an exclusive publication, `$concurrent` on a
/// concurrent handle, of either connection.
macro_rules! lanes {
    ($lanes:expr, $publication:ident => $exclusive:expr, $handle:ident => $concurrent:expr) => {
        match $lanes {
            #[cfg(target_os = "linux")]
            Lanes::Remote($publication) => $exclusive,
            Lanes::Embedded($publication) => $exclusive,
            #[cfg(target_os = "linux")]
            Lanes::ConcurrentRemote($handle) => $concurrent,
            Lanes::ConcurrentEmbedded($handle) => $concurrent,
        }
    };
}

/// An exclusive offer's or commit's acceptance as a [`Placed`].
fn placed(accepted: karyos_client::Accepted) -> Placed {
    Placed {
        lane: accepted.lane(),
        position: accepted.position(),
    }
}

/// A concurrent offer's outcome as an exclusive one's result.
fn concurrent_offered(outcome: ConcurrentOfferOutcome) -> Result<Placed, OfferError> {
    match outcome {
        ConcurrentOfferOutcome::Accepted { lane, position } => Ok(Placed { lane, position }),
        ConcurrentOfferOutcome::BackPressured => Err(OfferError::BackPressured),
        ConcurrentOfferOutcome::AdminAction => Err(OfferError::AdminAction),
        ConcurrentOfferOutcome::NotConnected => Err(OfferError::NotConnected),
        ConcurrentOfferOutcome::Aborted { lane, position } => {
            Err(OfferError::Aborted { lane, position })
        }
        ConcurrentOfferOutcome::Closed => Err(OfferError::Closed),
        _ => Err(OfferError::Client(ClientError::Unknown)),
    }
}

/// A commit's outcome as an offer's result.
fn committed(outcome: CommitOutcome) -> Result<Placed, OfferError> {
    match outcome {
        CommitOutcome::Accepted { lane, position } => Ok(Placed { lane, position }),
        CommitOutcome::Aborted { lane, position } => Err(OfferError::Aborted { lane, position }),
    }
}

impl Lanes {
    /// The largest message any lane accepts.
    fn max_message_length(&self) -> u32 {
        lanes!(self,
            publication => (0..Lane::COUNT)
                .filter_map(|lane| Lane::try_new(lane).ok())
                .filter_map(|lane| publication.max_message_length(lane))
                .max()
                .unwrap_or(0),
            handle => handle.max_message_length())
    }

    /// The largest message `lane` accepts; `None` for an unconfigured lane
    /// (any lane but 0 of a concurrent handle).
    fn lane_max(&self, lane: Lane) -> Option<u32> {
        lanes!(self,
            publication => publication.max_message_length(lane),
            handle => (lane == Lane::ZERO).then(|| handle.max_message_length()))
    }

    fn offer_on(&mut self, lane: Lane, payload: &[u8]) -> Result<Placed, OfferError> {
        lanes!(self,
        publication => publication.offer_on(lane, payload).map(placed),
        handle => {
            if lane != Lane::ZERO {
                return Err(OfferError::InvalidLane { lane });
            }
            concurrent_offered(handle.offer(payload)?)
        })
    }

    /// An offer on `lane` with `options` (F7b-2a): its reserved value.
    fn offer_on_with(
        &mut self,
        lane: Lane,
        payload: &[u8],
        options: karyos_client::OfferOptions,
    ) -> Result<Placed, OfferError> {
        lanes!(self,
        publication => publication.offer_on_with(lane, payload, options).map(placed),
        handle => {
            if lane != Lane::ZERO {
                return Err(OfferError::InvalidLane { lane });
            }
            let append = karyos_sys::log_buffer::AppendOptions {
                reserved_value: options.reserved_value,
                ..karyos_sys::log_buffer::AppendOptions::default()
            };
            concurrent_offered(handle.offer_with(payload, append)?)
        })
    }

    /// Delivers up to `limit` outcome records of `lane` to `handler`
    /// (F7a-2): a lane that is not guarded has none. A concurrent handle
    /// is never guarded (GC-7): lane 0 has none, any other is invalid.
    pub(super) fn poll_outcomes_on(
        &mut self,
        lane: Lane,
        limit: usize,
        handler: impl FnMut(u64, karyos_sys::outcome_ring::Record),
    ) -> Result<usize, OfferError> {
        lanes!(self,
        publication => publication.poll_outcomes_on(lane, limit, handler),
        _handle => {
            if lane != Lane::ZERO {
                return Err(OfferError::InvalidLane { lane });
            }
            Ok(0)
        })
    }

    /// A timed offer on `lane`: timed lanes are exclusive (GC-7), so a
    /// concurrent handle has no schedule.
    fn offer_at_on(
        &mut self,
        lane: Lane,
        payload: &[u8],
        tx_time: u64,
    ) -> Result<Placed, OfferError> {
        lanes!(self,
        publication => publication.offer_at_on(lane, payload, tx_time).map(placed),
        handle => {
            let _ = handle;
            if lane != Lane::ZERO {
                return Err(OfferError::InvalidLane { lane });
            }
            Err(OfferError::InvalidSchedule {
                reason: "a concurrent publication is never timed",
            })
        })
    }

    /// Claims `length` in `lane`'s term, copies `staged` into it and
    /// commits it.
    fn commit_staged(
        &mut self,
        lane: Lane,
        length: MessageLength,
        staged: &[AtomicU8],
    ) -> Result<Placed, OfferError> {
        lanes!(self,
        publication => {
            let mut claim = publication.try_claim_on(lane, length)?;
            for (byte, staged) in claim.payload().iter_mut().zip(staged) {
                *byte = staged.load(Ordering::Relaxed);
            }
            claim.commit().map(placed)
        },
        handle => {
            if lane != Lane::ZERO {
                return Err(OfferError::InvalidLane { lane });
            }
            let mut claim = match handle.try_claim(length.get())? {
                ConcurrentClaimOutcome::Claimed(claim) => claim,
                ConcurrentClaimOutcome::BackPressured => return Err(OfferError::BackPressured),
                ConcurrentClaimOutcome::AdminAction => return Err(OfferError::AdminAction),
                ConcurrentClaimOutcome::NotConnected => return Err(OfferError::NotConnected),
                ConcurrentClaimOutcome::Aborted { lane, position } => {
                    return Err(OfferError::Aborted { lane, position });
                }
                ConcurrentClaimOutcome::Closed => return Err(OfferError::Closed),
                _ => return Err(OfferError::Client(ClientError::Unknown)),
            };
            for (byte, staged) in claim.payload().iter_mut().zip(staged) {
                *byte = staged.load(Ordering::Relaxed);
            }
            committed(claim.commit())
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
    /// Its client's embedded driver's state, if the C ABI created it: the
    /// publication follows its failure and its close
    /// (`crate::api::driver::DriverState::usable`), with no lock.
    driver: Option<crate::api::driver::DriverState>,
    pub(super) lanes: Lanes,
    /// The staging buffer of its claims.
    staged: Arc<[AtomicU8]>,
    claim: Option<Staged>,
}

impl Entry {
    /// Whether the publication may act: its client's embedded driver,
    /// if any, is neither poisoned nor closed.
    pub(super) fn usable(&self) -> Result<(), Status> {
        self.driver
            .as_ref()
            .map_or(Ok(()), crate::api::driver::DriverState::usable)
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
pub(super) fn lane(raw: u32) -> Result<Lane, Failure> {
    u8::try_from(raw)
        .ok()
        .and_then(|lane| Lane::try_new(lane).ok())
        .ok_or_else(|| Failure::with(Status::InvalidLane, u64::from(raw), 0))
}

/// Adds the exclusive publication of `stream_id` on `uri` to `client`, or
/// with `concurrent` a concurrent handle on lane 0 of a `karyos:ipc`
/// stream.
///
/// # Errors
///
/// The client's handle and control call failures, and
/// [`Status::HandlesExhausted`], with the publication released.
pub(crate) fn add(
    client: Handle,
    uri: &str,
    stream_id: i32,
    concurrent: bool,
) -> Result<Handle, Failure> {
    with_client(client, |entry| {
        entry.usable()?;
        let lanes = entry.client.add_publication(
            uri,
            karyos_client::StreamId::new(stream_id),
            concurrent,
        )?;
        insert(client, entry, lanes)
    })?
}

/// As [`add`], an exclusive network publication whose receivers have
/// `roles` (owner item 7, karyos#637).
///
/// # Errors
///
/// As [`add`].
pub(crate) fn add_with_roles(
    client: Handle,
    uri: &str,
    stream_id: i32,
    roles: &karyos_client::PublicationRoles,
) -> Result<Handle, Failure> {
    with_client(client, |entry| {
        entry.usable()?;
        let lanes = entry.client.add_publication_with_roles(
            uri,
            karyos_client::StreamId::new(stream_id),
            roles,
        )?;
        insert(client, entry, lanes)
    })?
}

/// Opens a handle over `lanes` of `client`, whose `entry` lists it.
///
/// # Errors
///
/// [`Status::HandlesExhausted`], with the publication released.
fn insert(client: Handle, entry: &mut ClientEntry, lanes: Lanes) -> Result<Handle, Failure> {
    let staged: Arc<[AtomicU8]> = (0..lanes.max_message_length())
        .map(|_| AtomicU8::new(0))
        .collect();
    let publication = Entry {
        client,
        driver: entry.driver.clone(),
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
}

/// Adds `publication`, built from an in-process driver's handles
/// (`Publication::from_handles`), to `client`: the outcome poll's path
/// under Miri, since a guarded publication reaches the C ABI only through
/// a remote client (F7a-2).
///
/// # Errors
///
/// The client's handle failures, and [`Status::HandlesExhausted`].
#[cfg(test)]
pub(crate) fn insert_local(
    client: Handle,
    publication: Publication<HeapTerms>,
) -> Result<Handle, Failure> {
    with_client(client, |entry| {
        insert(client, entry, Lanes::Embedded(publication))
    })?
}

/// Offers `payload` on `lane`.
///
/// # Errors
///
/// The handle's and the offer's failures.
pub(crate) fn offer(publication: Handle, lane_raw: u32, payload: &[u8]) -> Result<Placed, Failure> {
    let lane = lane(lane_raw)?;
    table().with(publication, |entry| {
        entry.usable()?;
        entry
            .lanes
            .offer_on(lane, payload)
            .map_err(|error| Failure::from(&error))
    })?
}

/// Offers `payload` on `lane` with `options` (F7b-2a).
///
/// # Errors
///
/// As [`offer`]; a key outside a conflated stream's table, or a value
/// larger than its capacity, as [`Status::Conflation`].
pub(crate) fn offer_with(
    publication: Handle,
    lane_raw: u32,
    payload: &[u8],
    options: karyos_client::OfferOptions,
) -> Result<Placed, Failure> {
    let lane = lane(lane_raw)?;
    table().with(publication, |entry| {
        entry.usable()?;
        entry
            .lanes
            .offer_on_with(lane, payload, options)
            .map_err(|error| Failure::from(&error))
    })?
}

/// Offers `payload` on the timed `lane` with its requested not-before time
/// `tx_time`, in the lane's clock domain (`quantstratum-docs:
/// karyos/design/timed-tx.md`).
///
/// # Errors
///
/// The handle's and the timed offer's failures; [`Status::InvalidSchedule`]
/// for a lane that is not timed, a time below the lane's last, one past the
/// horizon or an overflowing deadline.
pub(crate) fn offer_at(
    publication: Handle,
    lane_raw: u32,
    payload: &[u8],
    tx_time: u64,
) -> Result<Placed, Failure> {
    let lane = lane(lane_raw)?;
    table().with(publication, |entry| {
        entry.usable()?;
        entry
            .lanes
            .offer_at_on(lane, payload, tx_time)
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
pub(crate) fn commit(claim: Handle) -> Result<Placed, Failure> {
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

/// Closes `publication` and its outstanding claim
/// ([`crate::api::client::close_child`]).
///
/// # Errors
///
/// The handle's failures, its client's included.
pub(crate) fn close(publication: Handle) -> Result<(), Status> {
    // A poisoned handle is closed too, and released like any other: its client,
    // written at the add and never changed, is read regardless
    // (`Table::read_even_poisoned`); the table hands the poisoned object over,
    // and its outstanding claim is removed from the claims table and its lanes
    // are released to the client (`remove_publication`). What a release touches
    // cannot be left invalid by a panic inside a call: at worst it releases
    // what that call left half-done, as a drop would.
    let client = table().read_even_poisoned(publication, |entry| entry.client)?;
    crate::api::client::close_child(client, table(), publication, |handle, entry| {
        Ended::Publication(handle, Box::new(entry))
    })
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

    /// Each concurrent offer outcome and commit outcome maps to its
    /// exclusive counterpart, so a concurrent handle answers as an
    /// exclusive one does (REVIEWER-01's P3 on #504).
    #[test]
    fn concurrent_outcomes_map_to_their_exclusive_counterparts() {
        let lane = Lane::ZERO;
        let placed = Placed { lane, position: 9 };
        assert_eq!(
            concurrent_offered(ConcurrentOfferOutcome::Accepted { lane, position: 9 }).ok(),
            Some(placed)
        );
        let offered = |outcome| concurrent_offered(outcome).unwrap_err();
        assert!(matches!(
            offered(ConcurrentOfferOutcome::BackPressured),
            OfferError::BackPressured
        ));
        assert!(matches!(
            offered(ConcurrentOfferOutcome::AdminAction),
            OfferError::AdminAction
        ));
        assert!(matches!(
            offered(ConcurrentOfferOutcome::NotConnected),
            OfferError::NotConnected
        ));
        assert!(matches!(
            offered(ConcurrentOfferOutcome::Aborted { lane, position: 9 }),
            OfferError::Aborted { position: 9, .. }
        ));
        assert!(matches!(
            offered(ConcurrentOfferOutcome::Closed),
            OfferError::Closed
        ));
        assert_eq!(
            committed(CommitOutcome::Accepted { lane, position: 9 }).ok(),
            Some(placed)
        );
        assert!(matches!(
            committed(CommitOutcome::Aborted { lane, position: 9 }),
            Err(OfferError::Aborted { position: 9, .. })
        ));
    }
}
