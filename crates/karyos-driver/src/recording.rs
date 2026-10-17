// SPDX-License-Identifier: Apache-2.0

//! The read capability an Archive recording takes from a stream
//! (quantstratum-docs: karyos/design/archive-gap-analysis.md, §4). The
//! driver does not depend on the Archive, nor the Archive on the driver
//! (SPEC.md §14): the host asks the driver for a lane's reader and hands it
//! to the Archive's agent, which reads it through its `FrameSource`.

use std::sync::Arc;

use karyos_client::link::{Lease, LeaseEnd};
use karyos_sys::SysError;
use karyos_sys::log_buffer::{DEFAULT_CORRUPT_RETRIES, Role, SenderRead};
use karyos_sys::term_bytes::HeapTerms;

use crate::agents::data::LaneReader;
use crate::embedded::{EmbeddedDriver, StreamHandle};
use crate::error::DriverError;

/// A recording's reader of a stream, with the lease that keeps the stream:
/// a removed stream is freed only once the lease is dropped, so its
/// conductor positions the seal the reader ends at. Take the parts with
/// [`RecordingReader::into_parts`] and keep the lease for as long as the
/// reader (the Archive's `Guarded` source drops the reader first).
#[derive(Debug)]
pub struct RecordingReader {
    reader: LaneReader,
    lease: Lease,
}

impl RecordingReader {
    /// The reader and the stream's lease.
    #[must_use]
    pub fn into_parts(self) -> (LaneReader, Lease) {
        (self.reader, self.lease)
    }
}

impl EmbeddedDriver<HeapTerms> {
    /// A recording's reader of `stream`'s log, admitted as `role`:
    /// [`Role::Required`], with its spare-slot reservation, bounds the
    /// publisher as the network sender's readers do (a `required`
    /// recording); [`Role::Optional`] never bounds it, and a lapped reader
    /// rejoins at the head ([`SenderRead::rejoin_at_head`], an `async`
    /// recording). Dropping the reader leaves the participant and frees its
    /// cell; the stream stays until the returned lease is dropped too.
    ///
    /// # Errors
    ///
    /// [`DriverError::Sys`] with [`SysError::InvalidPublicationMode`] for
    /// any other role; [`DriverError::ExportIdsExhausted`] when no occupant
    /// id is left; [`DriverError::StreamRetiring`],
    /// [`DriverError::CutoverPending`] and [`DriverError::UnknownStream`]
    /// as [`EmbeddedDriver::subscribe`]; and [`DriverError::Sys`] when the
    /// stream has no free cell or spare-slot credit.
    pub fn recording_reader(
        &mut self,
        stream: StreamHandle,
        role: Role,
    ) -> Result<RecordingReader, DriverError> {
        if !matches!(role, Role::Required | Role::Optional) {
            return Err(SysError::InvalidPublicationMode {
                reason: "a recording reads as a required or an optional participant",
            }
            .into());
        }
        let occupant = self.next_export;
        let next = occupant
            .checked_add(1)
            .ok_or(DriverError::ExportIdsExhausted)?;
        let target = self.active_stream_mut(stream)?;
        target.issuing()?;
        let subscription = target
            .conductor
            .subscribe_as(role, role == Role::Required, occupant)?;
        let reader = SenderRead::for_recording(subscription, DEFAULT_CORRUPT_RETRIES)?;
        let lease = Lease::acquire(&target.leases, &Arc::new(LeaseEnd::default()));
        self.next_export = next;
        Ok(RecordingReader { reader, lease })
    }
}

#[cfg(test)]
mod tests;
