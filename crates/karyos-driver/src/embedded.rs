// SPDX-License-Identifier: Apache-2.0

//! The embedded driver: log buffers and their conductors in the
//! application's process, with conductor duty run by the application.
//!
//! The driver never calls application code and holds no locks. Dropping it
//! stops conductor duty: publications and subscriptions already handed out
//! keep their buffers alive and keep working until the buffers need
//! rotation, cleaning or new limits, which then report back pressure or
//! admin actions.

use std::sync::Arc;

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

/// Names a stream of one [`EmbeddedDriver`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamHandle(usize);

#[derive(Debug)]
struct Stream {
    buffer: Arc<LogBuffer>,
    conductor: Conductor<Arc<LogBuffer>>,
    allow_unconnected: bool,
}

/// Owns streams and runs their conductor duty on demand.
#[derive(Debug, Default)]
pub struct EmbeddedDriver {
    streams: Vec<Stream>,
}

impl EmbeddedDriver {
    /// An empty driver.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a stream (control path: allocates its log buffer).
    ///
    /// # Errors
    ///
    /// Returns configuration and allocation errors; no stream is added on
    /// error.
    pub fn add_stream(&mut self, config: StreamConfig) -> Result<StreamHandle, DriverError> {
        let buffer = Arc::new(LogBuffer::new(config.buffer)?);
        let conductor = buffer
            .conductor_owned()
            .ok_or(karyos_sys::error::SysError::ResourcesUnavailable)?;
        self.streams.push(Stream {
            buffer,
            conductor,
            allow_unconnected: config.allow_unconnected,
        });
        Ok(StreamHandle(self.streams.len() - 1))
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
        self.streams
            .get_mut(stream.0)
            .ok_or(DriverError::UnknownStream { index: stream.0 })
    }
}
