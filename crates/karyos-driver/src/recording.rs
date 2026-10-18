// SPDX-License-Identifier: Apache-2.0

//! The read capability an Archive recording takes from a stream
//! (quantstratum-docs: karyos/design/archive-gap-analysis.md, §4). The
//! driver does not depend on the Archive, nor the Archive on the driver
//! (SPEC.md §14): the host asks the driver for a lane's reader and hands it
//! to the Archive's agent, which reads it through its `FrameSource`.

use std::sync::Arc;

use karyos_client::GenerationLink;
use karyos_client::link::{Lease, LeaseEnd};
use karyos_sys::SysError;
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{DEFAULT_CORRUPT_RETRIES, Role, SenderRead};
use karyos_sys::term_bytes::HeapTerms;

use crate::agents::data::LaneReader;
use crate::embedded::{EmbeddedDriver, StreamHandle};
use crate::error::DriverError;
use crate::generations::MemberKind;

/// A recording's reader of a stream, with the lease that keeps the stream:
/// a removed stream is freed only once the lease is dropped, so its
/// conductor positions the seal the reader ends at. The reader is a member
/// of the stream's cutovers (mapping-generations.md, "Recordings"): its
/// [`GenerationLink`] is offered a successor recording cell when a
/// cutover opens, and the reader's mapping starts at stream position
/// [`RecordingReader::base`]. Take the parts with
/// [`RecordingReader::into_parts`] and keep the lease for as long as the
/// reader (the Archive's `Guarded` source drops the reader first).
#[derive(Debug)]
pub struct RecordingReader {
    reader: LaneReader,
    lease: RecordingLease,
    format: RecordingFormat,
    link: Arc<GenerationLink>,
    base: u64,
}

/// The recorded lane's format: what a host records with the recording, as
/// the Archive's stream format, and gives the replay target. The stream's
/// `initial_term_id` is drawn when it is added, so this is where a host
/// learns it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordingFormat {
    /// The recorded lane.
    pub lane: Lane,
    /// The stream's first term id, as `ReplayTargetConfig` takes it.
    pub initial_term_id: i32,
    /// Bytes of each term.
    pub term_length: u32,
    /// The stream's MTU.
    pub mtu: u32,
}

impl RecordingReader {
    /// The recorded lane's format.
    #[must_use]
    pub fn format(&self) -> RecordingFormat {
        self.format
    }

    /// The reader's generation link: what offers it a successor at a
    /// cutover.
    #[must_use]
    pub fn link(&self) -> &Arc<GenerationLink> {
        &self.link
    }

    /// The stream position where the reader's mapping starts: its local
    /// positions plus this are stream positions.
    #[must_use]
    pub fn base(&self) -> u64 {
        self.base
    }

    /// The reader and the stream's lease.
    #[must_use]
    pub fn into_parts(self) -> (LaneReader, RecordingLease) {
        (self.reader, self.lease)
    }
}

/// A recording's hold on its stream: the stream's lease, released on drop.
#[derive(Debug)]
pub struct RecordingLease {
    _lease: Lease,
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
    /// any other role, checked before anything is admitted, and for a
    /// network image's lane; [`DriverError::ExportIdsExhausted`] when no occupant
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
        let buffer = target.buffer.config();
        let format = RecordingFormat {
            lane: buffer.lane,
            initial_term_id: buffer.initial_term_id.get().cast_signed(),
            term_length: buffer.term_length.get(),
            mtu: buffer.mtu,
        };
        let subscription = target
            .conductor
            .subscribe_as(role, role == Role::Required, occupant)?;
        let cell = subscription.cell();
        let reader = SenderRead::for_recording(subscription, DEFAULT_CORRUPT_RETRIES)?;
        let lease = RecordingLease {
            _lease: Lease::acquire(&target.leases, &Arc::new(LeaseEnd::default())),
        };
        let (link, base) = target.join(MemberKind::Recording {
            role,
            cell,
            occupant,
        });
        self.next_export = next;
        self.update_stream_gauges();
        Ok(RecordingReader {
            reader,
            lease,
            format,
            link,
            base,
        })
    }
}

#[cfg(test)]
mod tests;
