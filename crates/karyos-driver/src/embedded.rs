// SPDX-License-Identifier: Apache-2.0

//! The embedded driver: log buffers and their conductors in the
//! application's process, with conductor duty run by the application.
//!
//! The driver never calls application code. Its data path holds no locks;
//! the only lock is each client's hand-over table, on the control path
//! (quantstratum-docs: karyos/design/client-commands.md). Dropping the driver stops conductor
//! duty and closes the broadcast buffer: publications and subscriptions
//! already handed out keep their buffers alive and keep working until the
//! buffers need rotation, cleaning or new limits, which then report back
//! pressure or admin actions: without the driver, progress is bounded by
//! what is already prepared and admitted. Requests clients had submitted
//! become unknown; new requests and hand-over takes fail.
//!
//! Streams are configured on the driver ([`EmbeddedDriver::add_stream`]).
//! Clients admitted with [`EmbeddedDriver::connect`] request publications
//! and subscriptions through their command rings; the direct
//! [`EmbeddedDriver::publication`] and [`EmbeddedDriver::subscribe`] calls
//! remain for single-component use and hold no stream lease.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use karyos_client::link::StreamLeases;
use karyos_client::{ClientPublication, ClientSubscription};
use karyos_protocol::cnc::MAX_RESPONSE_LENGTH;
use karyos_sys::broadcast::{BroadcastTransmitter, HEADER_LENGTH, broadcast};
use karyos_sys::log_buffer::{Conductor, LogBuffer, LogBufferConfig, Role};

use crate::commands::ClientSlot;
use crate::error::DriverError;

/// Limits and sizes of the control channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriverConfig {
    /// Clients admitted at once, including retired clients whose command
    /// ring producer has not yet detached.
    pub max_clients: usize,
    /// Pending requests and held hand-over entries per client.
    pub max_pending_per_client: usize,
    /// Held hand-over entries over all clients.
    pub max_hand_over: usize,
    /// Commands served per duty cycle (`B`).
    pub command_budget: usize,
    /// Duty cycles whose responses may fall between the ends of two
    /// consecutive drains by a client (`m`); the application's promise.
    pub cycles_between_drains: usize,
    /// Bytes of each client's command ring.
    pub ring_capacity: usize,
    /// Bytes of the broadcast buffer; at least `2 * B * R * m`, `R` being
    /// the largest response record.
    pub broadcast_capacity: usize,
}

impl Default for DriverConfig {
    fn default() -> Self {
        Self {
            max_clients: 16,
            max_pending_per_client: 16,
            max_hand_over: 64,
            command_budget: 64,
            cycles_between_drains: 2,
            ring_capacity: 1024,
            broadcast_capacity: 16 * 1024,
        }
    }
}

/// Bytes of the largest response record: header plus payload.
const RESPONSE_EXTENT: usize = HEADER_LENGTH as usize + MAX_RESPONSE_LENGTH;

/// Configuration of one stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamConfig {
    /// The log buffer's configuration.
    pub buffer: LogBufferConfig,
    /// Allow offers while no subscriber is attached (SPEC.md §4).
    pub allow_unconnected: bool,
}

/// Names a stream of one [`EmbeddedDriver`]. It is distinct from the wire
/// `stream_id`: it carries the issuing driver's identity, so a handle from
/// another driver is rejected instead of naming the wrong buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamHandle {
    driver: u64,
    index: usize,
}

/// Source of driver identities within the process.
static NEXT_DRIVER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub(crate) struct Stream {
    pub(crate) buffer: Arc<LogBuffer>,
    pub(crate) conductor: Conductor<Arc<LogBuffer>>,
    pub(crate) leases: Arc<StreamLeases>,
    allow_unconnected: bool,
    pub(crate) stream_id: i32,
    pub(crate) session_id: i32,
}

/// Owns streams and clients and runs conductor duty on demand.
#[derive(Debug)]
pub struct EmbeddedDriver {
    pub(crate) id: u64,
    pub(crate) config: DriverConfig,
    pub(crate) streams: Vec<Stream>,
    pub(crate) broadcast: BroadcastTransmitter,
    pub(crate) clients: Vec<ClientSlot>,
    pub(crate) registrations: Vec<crate::commands::Registration>,
    pub(crate) next_client: u64,
    pub(crate) next_registration: u64,
    pub(crate) scan_cursor: usize,
    pub(crate) terminal: bool,
}

impl EmbeddedDriver {
    /// An empty driver.
    ///
    /// # Errors
    ///
    /// Returns [`DriverError::DriverIdsExhausted`] once the process has
    /// created `u64::MAX - 1` drivers; identities are never reused, so a
    /// stale handle can never name another driver's stream.
    pub fn new() -> Result<Self, DriverError> {
        Self::with_config(DriverConfig::default())
    }

    /// An empty driver with explicit control-channel limits.
    ///
    /// # Errors
    ///
    /// Returns [`DriverError::InvalidConfig`] for a zero limit, a ring or
    /// broadcast size the primitives reject, or a broadcast smaller than
    /// `2 * B * R * m`; and [`DriverError::DriverIdsExhausted`].
    pub fn with_config(config: DriverConfig) -> Result<Self, DriverError> {
        let needed = RESPONSE_EXTENT
            .checked_mul(2)
            .and_then(|n| n.checked_mul(config.command_budget))
            .and_then(|n| n.checked_mul(config.cycles_between_drains))
            .ok_or(DriverError::InvalidConfig)?;
        let valid = config.max_clients > 0
            && config.max_pending_per_client > 0
            && config.max_hand_over > 0
            && config.command_budget > 0
            && config.cycles_between_drains > 0
            && config.broadcast_capacity >= needed;
        if !valid {
            return Err(DriverError::InvalidConfig);
        }
        let broadcast =
            broadcast(config.broadcast_capacity).map_err(|_| DriverError::InvalidConfig)?;
        if !broadcast.has_room(MAX_RESPONSE_LENGTH) {
            return Err(DriverError::InvalidConfig);
        }
        let id = NEXT_DRIVER
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| DriverError::DriverIdsExhausted)?;
        Ok(Self {
            id,
            config,
            streams: Vec::new(),
            broadcast,
            clients: Vec::new(),
            registrations: Vec::new(),
            next_client: 1,
            next_registration: 1,
            scan_cursor: 0,
            terminal: false,
        })
    }

    /// Live capability leases of a stream: capabilities held for hand-over
    /// or owned by handles obtained through a client conductor.
    ///
    /// # Errors
    ///
    /// Returns [`DriverError::UnknownStream`] for a foreign handle.
    pub fn live_leases(&mut self, stream: StreamHandle) -> Result<u64, DriverError> {
        Ok(self.stream(stream)?.leases.live())
    }

    /// Whether the driver is in its terminal state: the broadcast buffer is
    /// closed and no command is served.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.terminal
    }

    /// Creates a stream (control path: allocates its log buffer).
    ///
    /// # Errors
    ///
    /// Returns configuration and allocation errors; no stream is added on
    /// error.
    pub fn add_stream(&mut self, config: StreamConfig) -> Result<StreamHandle, DriverError> {
        let key = (config.buffer.stream_id, config.buffer.session_id);
        if self
            .streams
            .iter()
            .any(|s| (s.stream_id, s.session_id) == key)
        {
            return Err(DriverError::DuplicateStream {
                stream_id: key.0,
                session_id: key.1,
            });
        }
        let buffer = Arc::new(LogBuffer::new(config.buffer)?);
        let conductor = buffer
            .conductor_owned()
            .ok_or(karyos_sys::error::SysError::ResourcesUnavailable)?;
        self.streams.push(Stream {
            buffer,
            conductor,
            leases: Arc::new(StreamLeases::default()),
            allow_unconnected: config.allow_unconnected,
            stream_id: key.0,
            session_id: key.1,
        });
        Ok(StreamHandle {
            driver: self.id,
            index: self.streams.len() - 1,
        })
    }

    /// Takes the stream's only publication.
    ///
    /// # Errors
    ///
    /// Returns [`DriverError::PublicationTaken`] after the first call and
    /// [`DriverError::UnknownStream`] for a foreign handle.
    pub fn publication(&mut self, stream: StreamHandle) -> Result<ClientPublication, DriverError> {
        let stream = self.stream(stream)?;
        let inner = stream
            .buffer
            .publication_owned()?
            .ok_or(DriverError::PublicationTaken)?;
        Ok(ClientPublication::new(inner, stream.allow_unconnected))
    }

    /// Admits a subscriber to the stream (control path: allocates its copy
    /// buffer).
    ///
    /// # Errors
    ///
    /// Returns `ResourcesUnavailable` when the stream's registry or loan
    /// credits are exhausted.
    pub fn subscribe(
        &mut self,
        stream: StreamHandle,
        role: Role,
    ) -> Result<ClientSubscription, DriverError> {
        let stream = self.stream(stream)?;
        let inner = stream.conductor.subscribe(role)?;
        Ok(ClientSubscription::new(inner))
    }

    /// Runs one duty cycle: retires closed clients, serves client commands,
    /// then runs one conductor duty cycle on every stream. Returns commands
    /// served plus slots cleaned plus terms prepared, a rough measure of
    /// work done.
    ///
    /// # Errors
    ///
    /// Returns the first conductor error, which indicates a broken invariant.
    pub fn do_work(&mut self) -> Result<u32, DriverError> {
        self.retire_closed_clients();
        let mut work = self.serve_commands();
        for stream in &mut self.streams {
            let report = stream.conductor.duty_cycle()?;
            work += report.cleaned + u32::from(report.prepared);
        }
        Ok(work)
    }

    fn stream(&mut self, stream: StreamHandle) -> Result<&mut Stream, DriverError> {
        if stream.driver != self.id {
            return Err(DriverError::UnknownStream {
                index: stream.index,
            });
        }
        self.streams
            .get_mut(stream.index)
            .ok_or(DriverError::UnknownStream {
                index: stream.index,
            })
    }
}
