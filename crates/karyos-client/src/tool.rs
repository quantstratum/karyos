// SPDX-License-Identifier: Apache-2.0

//! A tool attached to a driver in another process (Linux;
//! `quantstratum-docs: karyos/design/observability-and-tools.md`, Tool
//! attach and Read-only views).
//!
//! [`attach_tool`] connects to the driver's admission socket after the same
//! directory, socket and peer uid checks as a client, and sends `ToolHello`
//! without a descriptor. The driver answers `ToolAdmitted` with its
//! instance and the records of its five diagnostic regions, then one
//! `Region` per record with a descriptor it reopened read-only (owner
//! decision Q7, A1). The tool validates as a client does:
//!
//! - the version of `ToolAdmitted` is its own;
//! - the records name each of the five diagnostic kinds (driver counters,
//!   client counters, error log, loss report, trace mirror) exactly once
//!   and no other kind;
//! - each `Region` arrives for the next record in order, with fetch id 0
//!   and exactly one descriptor;
//! - each descriptor passes [`ReadOnlyRegion::attach`] against the header
//!   built from the full `ToolAdmitted` instance and its record, under the
//!   seal profile of its kind: driver-only (A2) for the driver counters,
//!   the error log, the loss report and the trace mirror, shared for the
//!   client counters, which clients write.
//!
//! Any failure rolls the attach back: every staged mapping is unmapped,
//! every received descriptor closed, the socket closed, and the error
//! reported. A tool holds nothing the driver must reclaim, so it sends no
//! `Leave`: closing the socket ends its connection.
//!
//! The driver keeps the connection open after the bootstrap and sends
//! nothing more on it; [`RemoteTool::driver_closed`] notices, without
//! blocking, when it closes, which is how a tool learns that the driver
//! exited. The mappings stay readable after that: the readers then show
//! the driver's last state.

use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;
use std::time::Duration;

use karyos_protocol::admission::{Message, Record, RegionKind as WireKind, VERSION, refusal};
use karyos_sys::counters::CountersReader;
use karyos_sys::diag::{ErrorLogReader, LossReportReader};
use karyos_sys::ipc::{self, ReadOnlyRegion, Recv, RegionRecord, SealProfile};
use karyos_sys::trace_mirror::TraceMirrorReader;

use crate::ipc::{AttachError, receive, send};

/// The diagnostic kinds a tool receives, each exactly once.
const TOOL_KINDS: [WireKind; 5] = [
    WireKind::Counters,
    WireKind::ClientCounters,
    WireKind::ErrorLog,
    WireKind::LossReport,
    WireKind::TraceMirror,
];

/// A tool attached to a driver: read-only views of its five diagnostic
/// regions, and the admission socket, whose close tells the driver's exit.
#[derive(Debug)]
pub struct RemoteTool {
    instance: u128,
    counters: CountersReader,
    client_counters: CountersReader,
    errors: ErrorLogReader,
    losses: LossReportReader,
    mirror: TraceMirrorReader,
    socket: Option<OwnedFd>,
}

/// The diagnostic regions of a tool's bootstrap, mapped read-only and
/// checked. Dropping it unmaps what it holds.
#[derive(Default)]
struct Staged {
    counters: Option<ReadOnlyRegion>,
    client_counters: Option<ReadOnlyRegion>,
    errors: Option<ReadOnlyRegion>,
    losses: Option<ReadOnlyRegion>,
    mirror: Option<ReadOnlyRegion>,
}

impl Staged {
    /// The slot of `kind` and the seal profile its region carries.
    fn slot(&mut self, kind: WireKind) -> Option<(&mut Option<ReadOnlyRegion>, SealProfile)> {
        match kind {
            WireKind::Counters => Some((&mut self.counters, SealProfile::DriverOnly)),
            WireKind::ClientCounters => Some((&mut self.client_counters, SealProfile::Shared)),
            WireKind::ErrorLog => Some((&mut self.errors, SealProfile::DriverOnly)),
            WireKind::LossReport => Some((&mut self.losses, SealProfile::DriverOnly)),
            WireKind::TraceMirror => Some((&mut self.mirror, SealProfile::DriverOnly)),
            WireKind::CommandRing
            | WireKind::Broadcast
            | WireKind::LogBuffer
            | WireKind::Journal => None,
        }
    }
}

/// The region header a tool's record describes, under the full instance
/// of `ToolAdmitted`: the wire record carries no instance.
fn expected(instance: u128, record: &Record) -> Result<RegionRecord, AttachError> {
    if !TOOL_KINDS.contains(&record.kind) {
        return Err(AttachError::Protocol);
    }
    Ok(RegionRecord {
        instance,
        region: record.region,
        kind: record.kind.to_sys(),
        generation: record.generation,
        layout: u64::from(record.layout),
        structure_length: usize::try_from(record.structure_length)
            .map_err(|_| AttachError::Protocol)?,
    })
}

/// Checks the record set before any descriptor is taken: each diagnostic
/// kind exactly once and no other kind.
fn check_kinds(records: &[Record]) -> Result<(), AttachError> {
    let complete = records.len() == TOOL_KINDS.len()
        && TOOL_KINDS
            .iter()
            .all(|kind| records.iter().filter(|record| record.kind == *kind).count() == 1);
    if complete {
        Ok(())
    } else {
        Err(AttachError::Protocol)
    }
}

/// Receives the bootstrap after `ToolHello`: `ToolAdmitted`, then one
/// `Region` per record in order, each attached read-only as it arrives.
fn bootstrap(socket: &OwnedFd) -> Result<(u128, Staged), AttachError> {
    let (instance, records) = match receive(socket)? {
        (
            Message::ToolAdmitted {
                instance,
                version,
                records,
            },
            None,
        ) => {
            if version != VERSION {
                return Err(AttachError::IncompatibleVersion {
                    driver: Some(version),
                });
            }
            (instance, records)
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
    check_kinds(&records)?;
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
        let expected = expected(instance, record)?;
        let (slot, profile) = staged.slot(record.kind).ok_or(AttachError::Protocol)?;
        if slot.is_some() {
            return Err(AttachError::Protocol);
        }
        *slot = Some(ReadOnlyRegion::attach(fd, expected, profile)?);
    }
    Ok((instance, staged))
}

/// Attaches a tool to the driver whose admission socket is in `dir`,
/// waiting at most `timeout` for each of its messages.
///
/// # Errors
///
/// Returns [`AttachError::Refused`] when the driver refuses the tool (for
/// example at its tool limit), [`AttachError::IncompatibleVersion`],
/// [`AttachError::Protocol`] for a bootstrap that breaks the rules of the
/// module documentation, [`AttachError::Timeout`], and
/// [`AttachError::Sys`] when a check or a system call fails. Every region
/// already mapped is unmapped and every received descriptor closed.
pub fn attach_tool(dir: &Path, timeout: Duration) -> Result<RemoteTool, AttachError> {
    let socket = ipc::connect(dir, timeout)?;
    send(&socket, &Message::ToolHello { version: VERSION }, None)?;
    // On any error, `staged` (and with it every mapping) and the socket are
    // dropped here; each descriptor was closed by its attach.
    let (instance, staged) = bootstrap(&socket)?;
    let (Some(counters), Some(client_counters), Some(errors), Some(losses), Some(mirror)) = (
        staged.counters,
        staged.client_counters,
        staged.errors,
        staged.losses,
        staged.mirror,
    ) else {
        return Err(AttachError::Protocol);
    };
    Ok(RemoteTool {
        instance,
        counters: CountersReader::attach_read_only(counters)?,
        client_counters: CountersReader::attach_read_only(client_counters)?,
        errors: ErrorLogReader::attach_read_only(errors)?,
        losses: LossReportReader::attach_read_only(losses)?,
        mirror: TraceMirrorReader::attach_read_only(mirror)?,
        socket: Some(socket),
    })
}

impl RemoteTool {
    /// The driver instance id of `ToolAdmitted`.
    #[must_use]
    pub fn instance(&self) -> u128 {
        self.instance
    }

    /// The driver counters, read-only.
    #[must_use]
    pub fn counters(&self) -> &CountersReader {
        &self.counters
    }

    /// The client counters, read-only.
    #[must_use]
    pub fn client_counters(&self) -> &CountersReader {
        &self.client_counters
    }

    /// The error log, read-only.
    #[must_use]
    pub fn error_log(&self) -> &ErrorLogReader {
        &self.errors
    }

    /// The loss report, read-only.
    #[must_use]
    pub fn loss_report(&self) -> &LossReportReader {
        &self.losses
    }

    /// The trace mirror, read-only: the journal table and the records the
    /// driver drained from the client trace journals.
    #[must_use]
    pub fn trace_mirror(&self) -> &TraceMirrorReader {
        &self.mirror
    }

    /// Whether the driver closed the connection, checked without blocking.
    /// A driver that exits closes it; once closed, it stays closed. The
    /// driver sends nothing after the bootstrap, so a message here is a
    /// protocol error, and the connection is closed on this side too.
    ///
    /// # Errors
    ///
    /// Returns [`AttachError::Protocol`] for an unexpected message (its
    /// descriptor, if any, is closed), and [`AttachError::Sys`] when a
    /// system call fails.
    pub fn driver_closed(&mut self) -> Result<bool, AttachError> {
        let Some(socket) = self.socket.as_ref() else {
            return Ok(true);
        };
        if !ipc::readable(socket.as_fd())? {
            return Ok(false);
        }
        let mut buffer = [0u8; karyos_protocol::admission::MAX_MESSAGE_LENGTH];
        // Readable: the receive does not block (a spurious wake up reports
        // `WouldBlock` through the receive timeout at worst).
        let received = ipc::recv(socket.as_fd(), &mut buffer);
        if matches!(received, Ok(Recv::WouldBlock)) {
            return Ok(false);
        }
        self.socket = None;
        match received? {
            Recv::PeerClosed => Ok(true),
            Recv::WouldBlock | Recv::Message(_) => Err(AttachError::Protocol),
        }
    }
}
