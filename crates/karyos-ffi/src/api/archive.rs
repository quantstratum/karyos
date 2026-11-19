// SPDX-License-Identifier: Apache-2.0

//! Archive connections (F9a; quantstratum-docs:
//! karyos/design/ffi-archive.md): a client's control streams to an
//! Archive (`karyos_archive::client::connection::ArchiveConnection`) and
//! its catalog listing (`RecordingLister`).
//!
//! An Archive handle belongs to the client that opened it: the client's
//! close closes it first, and closing it removes its two handles from the
//! client. A listing is a control call: it holds the Archive handle and its
//! client while it serves the client and polls the lister, so another
//! thread meets [`Status::Busy`] and the handler [`Status::Reentrant`].
//!
//! A replay's start and stop (F9c, B6; quantstratum-docs:
//! karyos/design/archive-replay-control.md) are control calls too, over a
//! [`Replayer`] the handle opens on its first replay call: control streams
//! of its own, as a rejoin's (F9b), with the next requester id the handle
//! hands out, so its answers and correlation ids never mix with the
//! listing's. The handle's close releases them with the listing's.

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use karyos_archive::client::connection::{ArchiveConnection, ControlStreams};
use karyos_archive::client::list::{ListPoll, ListedRecording, ListerConfig, RecordingLister};
use karyos_archive::client::replay::{
    ReplaySpec, Replayer, ReplayerConfig, ReplayerError, ReplayerEvent, RequestId,
};
#[cfg(test)]
use karyos_archive::client::{ControlRequests, ControlResponses};
use karyos_archive::control::ResponseCode;

use crate::api::client::{AnyClient, Ended, with_client};
use crate::handles::{Handle, Kind, Table};
use crate::status::{Failure, Status};

/// The most Archive connections open at once (`KARYOS_MAX_ARCHIVES`).
pub(crate) const MAX_ARCHIVES: u32 = 64;

/// The lister of one connection, over either client's terms; boxed, as
/// its buffers differ in size by the terms.
pub(crate) enum Lister {
    /// Of a client attached to a driver in another process.
    #[cfg(target_os = "linux")]
    Remote(
        Box<
            RecordingLister<
                karyos_archive::client::connection::Requests<karyos_sys::term_bytes::SharedTerms>,
                karyos_archive::client::connection::Responses<karyos_sys::term_bytes::SharedTerms>,
            >,
        >,
    ),
    /// Of a client over an embedded driver's conductor.
    Embedded(
        Box<
            RecordingLister<
                karyos_archive::client::connection::Requests<karyos_sys::term_bytes::HeapTerms>,
                karyos_archive::client::connection::Responses<karyos_sys::term_bytes::HeapTerms>,
            >,
        >,
    ),
    /// In-memory transports with no client (tests: the driverless Miri
    /// path of ffi-archive.md §4).
    #[cfg(test)]
    Memory(Box<RecordingLister<MemoryRequests, MemoryResponses>>),
}

impl Lister {
    fn start_from(&mut self, from_id: u64, count: usize) {
        match self {
            #[cfg(target_os = "linux")]
            Self::Remote(lister) => lister.start_from(from_id, count),
            Self::Embedded(lister) => lister.start_from(from_id, count),
            #[cfg(test)]
            Self::Memory(lister) => lister.start_from(from_id, count),
        }
    }

    fn poll(&mut self) -> ListPoll {
        match self {
            #[cfg(target_os = "linux")]
            Self::Remote(lister) => lister.poll(),
            Self::Embedded(lister) => lister.poll(),
            #[cfg(test)]
            Self::Memory(lister) => lister.poll(),
        }
    }
}

/// The replayer of one connection, over either client's terms (F9c).
pub(crate) enum Replays {
    /// Of a client attached to a driver in another process.
    #[cfg(target_os = "linux")]
    Remote(
        Box<
            Replayer<
                karyos_archive::client::connection::Requests<karyos_sys::term_bytes::SharedTerms>,
                karyos_archive::client::connection::Responses<karyos_sys::term_bytes::SharedTerms>,
            >,
        >,
    ),
    /// Of a client over an embedded driver's conductor.
    Embedded(
        Box<
            Replayer<
                karyos_archive::client::connection::Requests<karyos_sys::term_bytes::HeapTerms>,
                karyos_archive::client::connection::Responses<karyos_sys::term_bytes::HeapTerms>,
            >,
        >,
    ),
    /// In-memory transports with no client (tests: the driverless path).
    #[cfg(test)]
    Memory(Box<Replayer<MemoryRequests, MemoryResponses>>),
}

/// Runs `$body` on the replayer of any transports.
macro_rules! replays {
    ($replays:expr, $replayer:ident => $body:expr) => {
        match $replays {
            #[cfg(target_os = "linux")]
            Replays::Remote($replayer) => $body,
            Replays::Embedded($replayer) => $body,
            #[cfg(test)]
            Replays::Memory($replayer) => $body,
        }
    };
}

impl Replays {
    fn start(&mut self, spec: &ReplaySpec, now: Instant) -> Result<RequestId, ReplayerError> {
        replays!(self, replayer => replayer.start(spec, now))
    }

    fn stop(&mut self, replay_id: u64, now: Instant) -> Result<RequestId, ReplayerError> {
        replays!(self, replayer => replayer.stop(replay_id, now))
    }

    fn poll(&mut self, now: Instant) -> Option<ReplayerEvent> {
        replays!(self, replayer => replayer.poll(now))
    }

    /// Removes its handles from `client`, which opened them.
    fn release(self, client: &mut AnyClient) {
        match (self, client) {
            #[cfg(target_os = "linux")]
            (Self::Remote(replayer), AnyClient::Remote(client)) => {
                let (requests, responses) = (*replayer).into_transports();
                requests.close(client);
                responses.close(client);
            }
            (Self::Embedded(replayer), AnyClient::Embedded(client)) => {
                let (requests, responses) = (*replayer).into_transports();
                requests.close(client);
                responses.close(client);
            }
            // A replayer of another kind than its client is never built;
            // the handles drop, ending their leases.
            #[cfg(any(target_os = "linux", test))]
            _ => {}
        }
    }
}

/// An Archive handle's object.
pub(crate) struct Entry {
    /// The client that opened it; `None` for the tests' in-memory one.
    client: Option<Handle>,
    lister: Lister,
    /// Its replayer, once a replay call opened it (F9c).
    replays: Option<Replays>,
    /// How long a listing waits: the options' deadline, or the client's
    /// timeout.
    deadline: Duration,
    /// The Archive's control streams, which a rejoin opens again for
    /// itself (F9b).
    streams: ControlStreams,
    /// The requester id the next rejoin made from this handle takes when
    /// its caller leaves the choice to the library: this connection's id
    /// plus one, and up from there; `None` once past `u32::MAX`.
    next_client_id: Option<u32>,
}

/// What a rejoin made from an Archive handle takes of it (F9b).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RejoinSource {
    /// The Archive's control streams.
    pub(crate) streams: ControlStreams,
    /// The rejoin's own requester id.
    pub(crate) client_id: u32,
    /// How long a replay request waits.
    pub(crate) deadline: Duration,
}

impl Entry {
    /// Removes the connection's handles from `client`, which opened them,
    /// the replayer's included.
    pub(crate) fn release(self, client: &mut AnyClient) {
        if let Some(replays) = self.replays {
            replays.release(client);
        }
        match (self.lister, client) {
            #[cfg(target_os = "linux")]
            (Lister::Remote(lister), AnyClient::Remote(client)) => {
                let (requests, responses) = (*lister).into_transports();
                requests.close(client);
                responses.close(client);
            }
            (Lister::Embedded(lister), AnyClient::Embedded(client)) => {
                let (requests, responses) = (*lister).into_transports();
                requests.close(client);
                responses.close(client);
            }
            // A lister of another kind than its client is never built; the
            // handles drop, ending their leases.
            #[cfg(any(target_os = "linux", test))]
            _ => {}
        }
    }
}

/// The table of Archive connections, allocated on first use.
pub(crate) fn table() -> &'static Table<Entry> {
    static ARCHIVES: OnceLock<Table<Entry>> = OnceLock::new();
    ARCHIVES.get_or_init(|| Table::new(Kind::Archive, MAX_ARCHIVES))
}

/// A connection's options, as `karyos_archive_options` carries them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Options {
    /// The request stream, which its host configures concurrent.
    pub(crate) requests: i32,
    /// The response stream.
    pub(crate) responses: i32,
    /// The requester's id: the high 32 bits of its correlation ids, at
    /// most `u32::MAX`, unique among the Archive's requesters.
    pub(crate) client_id: u64,
    /// How long a listing waits, in nanoseconds; 0 for the client's
    /// timeout.
    pub(crate) deadline_ns: u64,
}

/// Opens a connection of `client` to the Archive whose control streams
/// `options` names: a concurrent publication on its request stream and an
/// optional subscription on its response stream. A control call.
///
/// # Errors
///
/// [`Status::InvalidArgument`] for a client id above `u32::MAX`; the
/// client's handle failures; the driver's refusal of either stream
/// ([`Status::Refused`] among them), and [`Status::HandlesExhausted`] with
/// both handles released.
pub(crate) fn connect(client: Handle, options: Options) -> Result<Handle, Failure> {
    let client_id = u32::try_from(options.client_id).map_err(|_| Status::InvalidArgument)?;
    let config = ListerConfig::new(client_id);
    let next_client_id = client_id.checked_add(1);
    let streams = ControlStreams::new(options.requests, options.responses);
    with_client(client, |entry| {
        entry.usable()?;
        let deadline = if options.deadline_ns == 0 {
            entry.timeout
        } else {
            Duration::from_nanos(options.deadline_ns)
        };
        let lister = match &mut entry.client {
            #[cfg(target_os = "linux")]
            AnyClient::Remote(remote) => {
                let (requests, responses) = ArchiveConnection::open(remote, streams)
                    .map_err(open_failure)?
                    .into_transports();
                Lister::Remote(Box::new(RecordingLister::new(config, requests, responses)))
            }
            AnyClient::Embedded(embedded) => {
                let (requests, responses) = ArchiveConnection::open(embedded, streams)
                    .map_err(open_failure)?
                    .into_transports();
                Lister::Embedded(Box::new(RecordingLister::new(config, requests, responses)))
            }
        };
        match table().insert_or_return(Entry {
            client: Some(client),
            lister,
            replays: None,
            deadline,
            streams,
            next_client_id,
        }) {
            Ok(handle) => {
                entry.archives.push(handle);
                Ok(handle)
            }
            Err((status, refused)) => {
                refused.release(&mut entry.client);
                Err(status.into())
            }
        }
    })?
}

/// What a listing hands each recording to: `false` when it cannot take
/// the recording, which refuses the call.
pub(crate) type ListingHandler<'a> = dyn FnMut(&ListedRecording) -> bool + 'a;

/// The recordings of `archive`'s catalog whose id is above `after_id`, in
/// id order, at most `limit`, each handed to `handler`; returns how many.
/// A control call: it serves the client and polls the listing until it is
/// complete or the connection's deadline passes, then hands the
/// recordings over. A page costs at most `limit` recordings.
///
/// # Errors
///
/// [`Status::Timeout`] with nothing delivered; [`Status::Refused`] with
/// the Archive's response code; the handles' failures.
pub(crate) fn list(
    archive: Handle,
    after_id: u64,
    limit: u32,
    handler: &mut ListingHandler<'_>,
) -> Result<u32, Failure> {
    let client = table().with(archive, |entry| entry.client)?;
    match client {
        Some(client) => with_client(client, |client_entry| {
            client_entry.usable()?;
            table().with(archive, |entry| {
                list_entry(
                    entry,
                    Some(&mut client_entry.client),
                    after_id,
                    limit,
                    handler,
                )
            })?
        })?,
        None => table().with(archive, |entry| {
            list_entry(entry, None, after_id, limit, handler)
        })?,
    }
}

fn list_entry(
    entry: &mut Entry,
    mut client: Option<&mut AnyClient>,
    after_id: u64,
    limit: u32,
    handler: &mut ListingHandler<'_>,
) -> Result<u32, Failure> {
    // Nothing past the last id, and nothing for a limit of 0.
    let (Some(from_id), Ok(count)) = (after_id.checked_add(1), usize::try_from(limit)) else {
        return Ok(0);
    };
    if count == 0 {
        return Ok(0);
    }
    entry.lister.start_from(from_id, count);
    let start = Instant::now();
    let listing = loop {
        if let Some(client) = client.as_deref_mut() {
            let _ = client.poll();
        }
        match entry.lister.poll() {
            ListPoll::Done(listing) => break listing,
            ListPoll::Refused { code, .. } => {
                return Err(Failure::with(Status::Refused, response_code(code), 0));
            }
            ListPoll::Idle => return Ok(0),
            _ => {
                if start.elapsed() >= entry.deadline {
                    return Err(Status::Timeout.into());
                }
                std::thread::yield_now();
            }
        }
    };
    // A state or stop reason a later Archive version decodes has no C code:
    // the page is refused as an unsupported schema, nothing delivered
    // (owner item 41). The check is the handler's own conversion.
    let unsupported = || {
        Failure::with(
            Status::Refused,
            response_code(ResponseCode::UnsupportedSchema),
            0,
        )
    };
    if !listing
        .recordings
        .iter()
        .take(count)
        .all(crate::abi::expressible)
    {
        return Err(unsupported());
    }
    let mut delivered = 0u32;
    for recording in listing.recordings.iter().take(count) {
        // Never after the check above, which converts the same way; were
        // it to happen, the call is refused rather than a recording
        // skipped.
        if !handler(recording) {
            return Err(unsupported());
        }
        // At most `limit`: never past a u32.
        if let Some(next) = delivered.checked_add(1) {
            delivered = next;
        }
    }
    Ok(delivered)
}

/// The wire code of an Archive's response (archive-control-codec.md).
fn response_code(code: ResponseCode) -> u64 {
    match code {
        ResponseCode::Ok => 0,
        ResponseCode::UnknownRecording => 2,
        ResponseCode::UnknownReplay => 3,
        ResponseCode::InvalidRequest => 4,
        ResponseCode::UnsupportedSchema => 5,
        // `Error`, and a code a later build adds.
        _ => 1,
    }
}

/// The failure of an [`ArchiveConnection::open`]: the client's failure
/// on the stream it could not take.
pub(crate) fn open_failure(error: karyos_archive::client::connection::OpenError) -> Failure {
    let (karyos_archive::client::connection::OpenError::Requests(error)
    | karyos_archive::client::connection::OpenError::Responses(error)) = error
    else {
        return Failure::from(Status::Internal);
    };
    Failure::from(&error)
}

/// What a rejoin of `client`'s subscription takes of `archive` (F9b): its
/// control streams, a requester id and the wait. A `client_id` of 0 leaves
/// the id to the library, which hands out this connection's id plus one
/// and up; another value is the caller's, which keeps it unique among the
/// Archive's requesters. Called with `client`'s entry held, so the lock
/// order is the client's, then the Archive's, as for a listing.
///
/// # Errors
///
/// [`Status::InvalidArgument`] for an Archive of another client, a
/// `client_id` above `u32::MAX`, or ids the library has run out of; the
/// handle's failures.
pub(crate) fn rejoin_source(
    archive: Handle,
    client: Handle,
    client_id: u64,
) -> Result<RejoinSource, Status> {
    let chosen = u32::try_from(client_id).map_err(|_| Status::InvalidArgument)?;
    table().with(archive, |entry| {
        if entry.client != Some(client) {
            return Err(Status::InvalidArgument);
        }
        let client_id = if chosen != 0 {
            chosen
        } else {
            let assigned = entry.next_client_id.ok_or(Status::InvalidArgument)?;
            entry.next_client_id = assigned.checked_add(1);
            assigned
        };
        Ok(RejoinSource {
            streams: entry.streams,
            client_id,
            deadline: entry.deadline,
        })
    })?
}

/// What a replay call asks once its replayer is open.
enum ReplayCall<'a> {
    Start(&'a ReplaySpec),
    Stop(u64),
}

/// What a replay call's answer was.
enum Answered {
    Started { replay_id: u64, session_id: i32 },
    Stopped,
}

/// Starts a replay of `spec` on `archive` (F9c): returns the replay id and
/// its target's session id, `replay_session_id` of the id. A control call:
/// it serves the client and polls the replayer until the answer comes or
/// the connection's deadline passes.
///
/// # Errors
///
/// [`Status::Refused`] with the Archive's response code;
/// [`Status::Timeout`] (a late start is stopped by the replayer);
/// [`Status::Busy`] while `MAX_PENDING` requests wait;
/// [`Status::InvalidArgument`] for a bad spec, or requester ids the handle
/// has run out of; the replayer's opening failures; the handles'.
pub(crate) fn replay(archive: Handle, spec: &ReplaySpec) -> Result<(u64, i32), Failure> {
    match replay_call(archive, &ReplayCall::Start(spec))? {
        Answered::Started {
            replay_id,
            session_id,
        } => Ok((replay_id, session_id)),
        Answered::Stopped => Err(Status::Internal.into()),
    }
}

/// Stops replay `replay_id` on `archive` (F9c). A control call, as
/// [`replay`].
///
/// # Errors
///
/// As [`replay`]; [`Status::Refused`] with `UnknownReplay`'s code for a
/// replay the Archive does not run.
pub(crate) fn stop_replay(archive: Handle, replay_id: u64) -> Result<(), Failure> {
    match replay_call(archive, &ReplayCall::Stop(replay_id))? {
        Answered::Stopped => Ok(()),
        Answered::Started { .. } => Err(Status::Internal.into()),
    }
}

fn replay_call(archive: Handle, call: &ReplayCall<'_>) -> Result<Answered, Failure> {
    let client = table().with(archive, |entry| entry.client)?;
    match client {
        Some(client) => with_client(client, |client_entry| {
            client_entry.usable()?;
            table().with(archive, |entry| {
                replay_entry(entry, Some(&mut client_entry.client), call)
            })?
        })?,
        None => table().with(archive, |entry| replay_entry(entry, None, call))?,
    }
}

/// Opens `entry`'s replayer on `client`: the connection's control streams
/// again, with the next requester id the handle hands out.
fn open_replays(entry: &mut Entry, client: &mut AnyClient) -> Result<Replays, Failure> {
    let client_id = entry.next_client_id.ok_or(Status::InvalidArgument)?;
    let mut config = ReplayerConfig::new(client_id);
    config.deadline = entry.deadline;
    let replays = match client {
        #[cfg(target_os = "linux")]
        AnyClient::Remote(remote) => {
            let (requests, responses) = ArchiveConnection::open(remote, entry.streams)
                .map_err(open_failure)?
                .into_transports();
            Replays::Remote(Box::new(Replayer::new(config, requests, responses)))
        }
        AnyClient::Embedded(embedded) => {
            let (requests, responses) = ArchiveConnection::open(embedded, entry.streams)
                .map_err(open_failure)?
                .into_transports();
            Replays::Embedded(Box::new(Replayer::new(config, requests, responses)))
        }
    };
    entry.next_client_id = client_id.checked_add(1);
    Ok(replays)
}

fn replay_entry(
    entry: &mut Entry,
    mut client: Option<&mut AnyClient>,
    call: &ReplayCall<'_>,
) -> Result<Answered, Failure> {
    if entry.replays.is_none() {
        let Some(client) = client.as_deref_mut() else {
            // An in-memory handle comes with its replayer.
            return Err(Status::Internal.into());
        };
        entry.replays = Some(open_replays(entry, client)?);
    }
    let deadline = entry.deadline;
    let Some(replays) = entry.replays.as_mut() else {
        return Err(Status::Internal.into());
    };
    let start = Instant::now();
    let request = match call {
        ReplayCall::Start(spec) => replays.start(spec, start),
        ReplayCall::Stop(replay_id) => replays.stop(*replay_id, start),
    }
    .map_err(|error| match error {
        ReplayerError::Busy => Status::Busy,
        _ => Status::InvalidArgument,
    })?;
    loop {
        if let Some(client) = client.as_deref_mut() {
            let _ = client.poll();
        }
        let now = Instant::now();
        // An event of another request is dropped: none waits between
        // calls, which each wait for their own.
        match replays.poll(now) {
            Some(ReplayerEvent::Started {
                request: answered,
                replay_id,
                session_id,
            }) if answered == request => {
                return Ok(Answered::Started {
                    replay_id,
                    session_id,
                });
            }
            Some(ReplayerEvent::Stopped {
                request: answered, ..
            }) if answered == request => return Ok(Answered::Stopped),
            Some(ReplayerEvent::Refused {
                request: answered,
                code,
                ..
            }) if answered == request => {
                return Err(Failure::with(Status::Refused, response_code(code), 0));
            }
            Some(ReplayerEvent::Expired { request: answered }) if answered == request => {
                return Err(Status::Timeout.into());
            }
            Some(_) => {}
            // The replayer expires the request at the deadline; this only
            // bounds a call whose clock never reaches it (twice the wait).
            None if now
                .checked_duration_since(start)
                .and_then(|waited| waited.checked_sub(deadline))
                .is_some_and(|past| past > deadline) =>
            {
                return Err(Status::Timeout.into());
            }
            None => std::thread::yield_now(),
        }
    }
}

/// Closes `archive`: its handles are removed from its client.
///
/// # Errors
///
/// The handles' failures.
pub(crate) fn close(archive: Handle) -> Result<(), Status> {
    match table().read_even_poisoned(archive, |entry| entry.client)? {
        Some(client) => {
            crate::api::client::close_child(client, table(), archive, |handle, entry| {
                Ended::Archive(handle, Box::new(entry))
            })
        }
        None => {
            let _ = table().remove(archive)?;
            Ok(())
        }
    }
}

/// Opens an Archive handle over in-memory transports (tests: the
/// driverless path).
#[cfg(test)]
pub(crate) fn insert_memory(
    requests: MemoryRequests,
    responses: MemoryResponses,
    deadline: Duration,
) -> Result<Handle, Status> {
    table().insert(Entry {
        client: None,
        lister: Lister::Memory(Box::new(RecordingLister::new(
            ListerConfig::new(1),
            requests,
            responses,
        ))),
        replays: None,
        deadline,
        streams: ControlStreams::new(0, 0),
        next_client_id: Some(2),
    })
}

/// Opens an Archive handle over in-memory transports whose replayer runs
/// on `replays` (tests: the driverless path of F9c).
#[cfg(test)]
pub(crate) fn insert_memory_replaying(
    listing: (MemoryRequests, MemoryResponses),
    replays: (MemoryRequests, MemoryResponses),
    deadline: Duration,
) -> Result<Handle, Status> {
    let mut config = ReplayerConfig::new(2);
    config.deadline = deadline;
    table().insert(Entry {
        client: None,
        lister: Lister::Memory(Box::new(RecordingLister::new(
            ListerConfig::new(1),
            listing.0,
            listing.1,
        ))),
        replays: Some(Replays::Memory(Box::new(Replayer::new(
            config, replays.0, replays.1,
        )))),
        deadline,
        streams: ControlStreams::new(0, 0),
        next_client_id: Some(3),
    })
}

/// A request stream in memory (tests): `send` hands each request over.
#[cfg(test)]
pub(crate) struct MemoryRequests(pub(crate) Box<SendRequest>);

/// What a [`MemoryRequests`] does with a request.
#[cfg(test)]
pub(crate) type SendRequest = dyn FnMut(&[u8]) -> bool + Send;

#[cfg(test)]
impl ControlRequests for MemoryRequests {
    fn send(&mut self, message: &[u8]) -> bool {
        (self.0)(message)
    }
}

/// A response stream in memory (tests): `next` copies the next message.
#[cfg(test)]
pub(crate) struct MemoryResponses(pub(crate) Box<NextResponse>);

/// Where a [`MemoryResponses`] takes its next message from.
#[cfg(test)]
pub(crate) type NextResponse = dyn FnMut(&mut [u8]) -> Option<usize> + Send;

#[cfg(test)]
impl ControlResponses for MemoryResponses {
    fn next(&mut self, out: &mut [u8]) -> Option<usize> {
        (self.0)(out)
    }
}
