// SPDX-License-Identifier: Apache-2.0

//! The embedded driver: log buffers and their conductors in the
//! application's process, with conductor duty run by the application.
//!
//! The driver never calls application code and holds no locks. Dropping it
//! stops conductor duty: publications and subscriptions already handed out
//! keep their buffers alive and keep working until the buffers need
//! rotation, cleaning or new limits, which then report back pressure or
//! admin actions: without the driver, progress is bounded by what is
//! already prepared and admitted.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use karyos_client::{ClientPublication, ClientSubscription};
use karyos_sys::log_buffer::{Conductor, LogBuffer, LogBufferConfig, Role};

use crate::error::DriverError;

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
struct Stream {
    buffer: Arc<LogBuffer>,
    conductor: Conductor<Arc<LogBuffer>>,
    allow_unconnected: bool,
    stream_id: i32,
    session_id: i32,
}

/// Owns streams and runs their conductor duty on demand.
#[derive(Debug)]
pub struct EmbeddedDriver {
    id: u64,
    streams: Vec<Stream>,
}

impl Default for EmbeddedDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl EmbeddedDriver {
    /// An empty driver.
    #[must_use]
    pub fn new() -> Self {
        Self {
            id: NEXT_DRIVER.fetch_add(1, Ordering::Relaxed),
            streams: Vec::new(),
        }
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
        Ok(ClientPublication::new(
            inner,
            Arc::clone(&stream.buffer),
            stream.allow_unconnected,
        ))
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
        Ok(ClientSubscription::new(
            inner,
            stream.buffer.max_message_length(),
        ))
    }

    /// Runs one conductor duty cycle on every stream. Returns the number of
    /// slots cleaned plus terms prepared, a rough measure of work done.
    ///
    /// # Errors
    ///
    /// Returns the first conductor error, which indicates a broken invariant.
    pub fn do_work(&mut self) -> Result<u32, DriverError> {
        let mut work = 0;
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
