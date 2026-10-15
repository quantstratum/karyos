// SPDX-License-Identifier: Apache-2.0

//! A client in another process than its driver (Linux;
//! `quantstratum-docs: karyos/design/ipc-admission.md`, `quantstratum-docs: karyos/design/ipc-admission-server.md`).
//!
//! [`attach`] connects to the driver's admission socket after checking its
//! directory, socket and peer uid, sends `Hello` with a pidfd of this
//! process, and receives `Admitted` and one `Region` per record. It maps
//! each region only after the descriptor checks and the header comparison
//! of [`Region::attach`], and builds the client conductor over the
//! attached command ring and broadcast buffer.
//!
//! The process keeps the one-process contract of the first profile: it
//! does not fork while it holds the socket, a received descriptor or a
//! mapping. Closing a [`RemoteClient`] closes the conductor, unmaps every
//! region and then sends `Leave`; a failed attach does the same with what
//! it had received. The client never hands out an owner of a mapping (the
//! conductor, its ring producer and broadcast receiver, or the counters
//! reader), only calls that borrow them, so no mapping outlives the client
//! and `Leave` is a true release proof. In this step hand-over keys cannot be taken yet: log
//! buffers in regions come with i2.

use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use karyos_protocol::admission::{
    MAX_MESSAGE_LENGTH, Message, Record, RegionKind as WireKind, VERSION, refusal,
};
use karyos_protocol::cnc::{StreamKey, SubscriberRole};
use karyos_sys::broadcast::BroadcastReceiver;
use karyos_sys::command_ring::RingProducer;
use karyos_sys::counters::{CellRead, CountersReader};
use karyos_sys::error::SysError;
use karyos_sys::ipc::{self, PidFd, Recv, Region, RegionKind, RegionRecord, Sent};

use crate::conductor::{ClientConductor, Completion, ConductorError, ConductorPoll};
use crate::link::{ClientLink, Owner};

/// Why an attach failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AttachError {
    /// The driver refused the client with this code
    /// (`karyos_protocol::admission::refusal`).
    #[error("the driver refused the client (code {code})")]
    Refused {
        /// The refusal code.
        code: u64,
    },
    /// The driver runs another protocol version: it refused this one, or
    /// admitted the client at another.
    #[error("the driver does not run protocol version {VERSION}")]
    IncompatibleVersion {
        /// The version the driver announced, when it admitted the client.
        driver: Option<u64>,
    },
    /// The driver sent a message out of order, malformed, or with a
    /// missing or extra descriptor.
    #[error("admission protocol error")]
    Protocol,
    /// The driver did not answer within the timeout.
    #[error("the driver did not answer in time")]
    Timeout,
    /// A system call or a region check failed.
    #[error(transparent)]
    Sys(#[from] SysError),
}

/// A client admitted by a driver in another process.
#[derive(Debug)]
pub struct RemoteClient {
    instance: u128,
    client: u64,
    conductor: Option<ClientConductor>,
    counters: Option<CountersReader>,
    socket: Option<OwnedFd>,
}

/// One received message, with its descriptor.
fn receive(socket: &OwnedFd) -> Result<(Message, Option<OwnedFd>), AttachError> {
    let mut buffer = [0u8; MAX_MESSAGE_LENGTH];
    match ipc::recv(socket.as_fd(), &mut buffer)? {
        Recv::Message(received) => {
            let bytes = buffer.get(..received.len).unwrap_or(&[]);
            let message = Message::decode(bytes).map_err(|_| AttachError::Protocol)?;
            Ok((message, received.fd))
        }
        Recv::WouldBlock => Err(AttachError::Timeout),
        Recv::PeerClosed => Err(AttachError::Protocol),
    }
}

fn send(socket: &OwnedFd, message: &Message, fd: Option<&OwnedFd>) -> Result<(), AttachError> {
    let mut out = [0u8; MAX_MESSAGE_LENGTH];
    let length = message
        .encode(&mut out)
        .map_err(|_| AttachError::Protocol)?;
    let bytes = out.get(..length).ok_or(AttachError::Protocol)?;
    match ipc::send(socket.as_fd(), bytes, fd.map(AsFd::as_fd))? {
        Sent::Sent => Ok(()),
        Sent::WouldBlock => Err(AttachError::Timeout),
    }
}

/// The region header a record describes.
fn expected(instance: u128, record: &Record) -> Result<RegionRecord, AttachError> {
    let kind = match record.kind {
        WireKind::CommandRing => RegionKind::CommandRing,
        WireKind::Broadcast => RegionKind::Broadcast,
        WireKind::Counters => RegionKind::Counters,
        WireKind::LogBuffer => return Err(AttachError::Protocol),
    };
    Ok(RegionRecord {
        instance,
        region: record.region,
        kind,
        generation: record.generation,
        layout: u64::from(record.layout),
        structure_length: usize::try_from(record.structure_length)
            .map_err(|_| AttachError::Protocol)?,
    })
}

/// The CnC regions of a bootstrap, mapped and checked.
#[derive(Default)]
struct Staged {
    ring: Option<Region>,
    broadcast: Option<Region>,
    counters: Option<Region>,
}

/// Receives the bootstrap after `Hello`: `Admitted`, then one `Region`
/// per record, each mapped as soon as it arrives.
fn bootstrap(socket: &OwnedFd) -> Result<(u128, u64, Staged), AttachError> {
    let (instance, client, records) = match receive(socket)? {
        (
            Message::Admitted {
                instance,
                version,
                client,
                records,
            },
            None,
        ) => {
            if version != VERSION {
                return Err(AttachError::IncompatibleVersion {
                    driver: Some(version),
                });
            }
            (instance, client, records)
        }
        (
            Message::Refused {
                code: refusal::INCOMPATIBLE_VERSION,
                ..
            },
            None,
        ) => return Err(AttachError::IncompatibleVersion { driver: None }),
        (Message::Refused { code, .. }, None) => return Err(AttachError::Refused { code }),
        _ => return Err(AttachError::Protocol),
    };
    let mut staged = Staged::default();
    for (index, record) in (0u64..).zip(&records) {
        let (
            Message::Region {
                fetch: 0,
                index: got,
            },
            Some(fd),
        ) = receive(socket)?
        else {
            return Err(AttachError::Protocol);
        };
        if got != index {
            return Err(AttachError::Protocol);
        }
        let region = Region::attach(fd, expected(instance, record)?)?;
        let slot = match record.kind {
            WireKind::CommandRing => &mut staged.ring,
            WireKind::Broadcast => &mut staged.broadcast,
            WireKind::Counters => &mut staged.counters,
            WireKind::LogBuffer => return Err(AttachError::Protocol),
        };
        if slot.replace(region).is_some() {
            return Err(AttachError::Protocol);
        }
    }
    Ok((instance, client, staged))
}

/// Attaches to the driver whose admission socket is in `dir`, waiting at
/// most `timeout` for each of its messages. `max_pending` bounds the
/// conductor's pending requests, as for an in-process client.
///
/// # Errors
///
/// Returns [`AttachError`]. Every region already mapped is unmapped and
/// every received descriptor closed; if the driver had admitted the client,
/// `Leave` is sent so that it releases the client at once.
pub fn attach(
    dir: &Path,
    timeout: Duration,
    max_pending: usize,
) -> Result<RemoteClient, AttachError> {
    let socket = ipc::connect(dir, timeout)?;
    let pidfd = PidFd::of_self()?;
    // `PidFd` keeps its descriptor private; pass a duplicate.
    let pidfd_fd = pidfd.as_fd().try_clone_to_owned().map_err(|error| {
        AttachError::Sys(SysError::Os {
            operation: "dup(pidfd)",
            errno: error.raw_os_error().unwrap_or(0),
        })
    })?;
    send(
        &socket,
        &Message::Hello { version: VERSION },
        Some(&pidfd_fd),
    )?;
    drop(pidfd_fd);
    let built = bootstrap(&socket).and_then(|(instance, client, staged)| {
        let (Some(ring), Some(broadcast), Some(counters)) =
            (staged.ring, staged.broadcast, staged.counters)
        else {
            return Err(AttachError::Protocol);
        };
        let producer = RingProducer::attach(ring)?;
        let receiver = BroadcastReceiver::attach(broadcast)?;
        let counters = CountersReader::attach(counters)?;
        let owner = Owner {
            driver: instance as u64,
            client,
        };
        let conductor = ClientConductor::new(
            owner,
            producer,
            receiver,
            Arc::new(ClientLink::new()),
            max_pending,
        );
        Ok((instance, client, conductor, counters))
    });
    match built {
        Ok((instance, client, conductor, counters)) => Ok(RemoteClient {
            instance,
            client,
            conductor: Some(conductor),
            counters: Some(counters),
            socket: Some(socket),
        }),
        Err(error) => {
            // Everything staged is unmapped by now (dropped); tell the
            // driver, which may have admitted this client.
            let _ = send(&socket, &Message::Leave, None);
            Err(error)
        }
    }
}

impl RemoteClient {
    /// The driver instance id.
    #[must_use]
    pub fn instance(&self) -> u128 {
        self.instance
    }

    /// The client id the driver assigned.
    #[must_use]
    pub fn client(&self) -> u64 {
        self.client
    }

    /// Requests a publication on `stream` (the client conductor's
    /// `add_publication`); returns the request sequence.
    ///
    /// # Errors
    ///
    /// As [`ClientConductor::add_publication`].
    pub fn add_publication(
        &mut self,
        stream: StreamKey,
        allow_unconnected: bool,
    ) -> Result<u64, ConductorError> {
        self.conductor_mut()?
            .add_publication(stream, allow_unconnected)
    }

    /// Requests a concurrent publication handle on `stream`.
    ///
    /// # Errors
    ///
    /// As [`ClientConductor::add_concurrent_publication`].
    pub fn add_concurrent_publication(
        &mut self,
        stream: StreamKey,
        allow_unconnected: bool,
    ) -> Result<u64, ConductorError> {
        self.conductor_mut()?
            .add_concurrent_publication(stream, allow_unconnected)
    }

    /// Requests a subscription to `stream` with `role`.
    ///
    /// # Errors
    ///
    /// As [`ClientConductor::add_subscription`].
    pub fn add_subscription(
        &mut self,
        stream: StreamKey,
        role: SubscriberRole,
    ) -> Result<u64, ConductorError> {
        self.conductor_mut()?.add_subscription(stream, role)
    }

    /// Reports completed requests to `on`, as [`ClientConductor::poll`].
    pub fn poll<F>(&mut self, limit: usize, on: F) -> ConductorPoll
    where
        F: FnMut(Completion),
    {
        self.conductor
            .as_mut()
            .map_or_else(ConductorPoll::default, |conductor| {
                conductor.poll(limit, on)
            })
    }

    /// Requests submitted and not yet reported.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.conductor.as_ref().map_or(0, ClientConductor::pending)
    }

    /// Cells of the driver's counters region.
    #[must_use]
    pub fn counter_capacity(&self) -> usize {
        self.counters.as_ref().map_or(0, CountersReader::capacity)
    }

    /// Reads counter cell `index` of the driver's counters region.
    #[must_use]
    pub fn read_counter(&self, index: usize) -> CellRead {
        self.counters
            .as_ref()
            .map_or(CellRead::Free, |counters| counters.read(index))
    }

    fn conductor_mut(&mut self) -> Result<&mut ClientConductor, ConductorError> {
        self.conductor.as_mut().ok_or(ConductorError::Closed)
    }

    /// Closes the conductor, unmaps every region and sends `Leave`. Same as
    /// dropping the client.
    pub fn close(self) {
        drop(self);
    }
}

impl Drop for RemoteClient {
    fn drop(&mut self) {
        drop(self.conductor.take());
        drop(self.counters.take());
        if let Some(socket) = self.socket.take() {
            let _ = send(&socket, &Message::Leave, None);
        }
    }
}
