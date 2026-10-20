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

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use karyos_archive::client::connection::{ArchiveConnection, ControlStreams};
use karyos_archive::client::list::{ListPoll, ListedRecording, ListerConfig, RecordingLister};
#[cfg(test)]
use karyos_archive::client::{ControlRequests, ControlResponses};
use karyos_archive::control::ResponseCode;

use crate::api::client::{AnyClient, clients};
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

/// An Archive handle's object.
pub(crate) struct Entry {
    /// The client that opened it; `None` for the tests' in-memory one.
    client: Option<Handle>,
    lister: Lister,
    /// How long a listing waits: the options' deadline, or the client's
    /// timeout.
    deadline: Duration,
}

impl Entry {
    /// Removes the connection's handles from `client`, which opened them.
    pub(crate) fn release(self, client: &mut AnyClient) {
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
    let streams = ControlStreams::new(options.requests, options.responses);
    clients().with(client, |entry| {
        entry.usable()?;
        let deadline = if options.deadline_ns == 0 {
            entry.timeout
        } else {
            Duration::from_nanos(options.deadline_ns)
        };
        let opened = |error: karyos_archive::client::connection::OpenError| {
            let (karyos_archive::client::connection::OpenError::Requests(error)
            | karyos_archive::client::connection::OpenError::Responses(error)) = error
            else {
                return Failure::from(Status::Internal);
            };
            Failure::from(&error)
        };
        let lister = match &mut entry.client {
            #[cfg(target_os = "linux")]
            AnyClient::Remote(remote) => {
                let (requests, responses) = ArchiveConnection::open(remote, streams)
                    .map_err(opened)?
                    .into_transports();
                Lister::Remote(Box::new(RecordingLister::new(config, requests, responses)))
            }
            AnyClient::Embedded(embedded) => {
                let (requests, responses) = ArchiveConnection::open(embedded, streams)
                    .map_err(opened)?
                    .into_transports();
                Lister::Embedded(Box::new(RecordingLister::new(config, requests, responses)))
            }
        };
        match table().insert_or_return(Entry {
            client: Some(client),
            lister,
            deadline,
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

/// What a listing hands each recording to.
pub(crate) type RecordingHandler<'a> = dyn FnMut(&ListedRecording) + 'a;

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
    handler: &mut RecordingHandler<'_>,
) -> Result<u32, Failure> {
    let client = table().with(archive, |entry| entry.client)?;
    match client {
        Some(client) => clients().with(client, |client_entry| {
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
    handler: &mut RecordingHandler<'_>,
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
    let mut delivered = 0u32;
    for recording in listing.recordings.iter().take(count) {
        handler(recording);
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

/// Closes `archive`: its handles are removed from its client.
///
/// # Errors
///
/// The handles' failures.
pub(crate) fn close(archive: Handle) -> Result<(), Status> {
    match table().read_even_poisoned(archive, |entry| entry.client)? {
        Some(client) => clients().with(client, |entry| {
            let removed = table().remove(archive)?;
            entry.archives.retain(|handle| *handle != archive);
            removed.release(&mut entry.client);
            Ok(())
        })?,
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
        deadline,
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
