// SPDX-License-Identifier: Apache-2.0

//! The audit of grants on chosen streams (`quantstratum-docs:
//! karyos/design/archive-host.md`, H3): a host marks a stream audited, and
//! each handle the control path grants on it, to a client of the
//! in-process command ring or to a remote one, is recorded with its
//! client, process, uid and role for the host to drain and log. `karyosd`
//! audits its Archive's control streams this way.
//!
//! Under same-uid admission every admitted client runs as the driver's own
//! uid, so the record names who held the stream, not who was allowed to:
//! the trust boundary is the driver's uid, until per-client authorization
//! (owner item 43).

/// What a granted handle may do on its stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantRole {
    /// An exclusive publication.
    Publication,
    /// A concurrent publication handle.
    ConcurrentPublication,
    /// A subscription.
    Subscription,
}

/// One grant on an audited stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrantAudit {
    /// The client's id in this driver.
    pub client: u64,
    /// The client's process id: proven by its pidfd for a remote client,
    /// this process for one of the in-process command ring; `None` when
    /// the driver could not tell.
    pub pid: Option<u32>,
    /// The uid admission proved the client's (the driver's own); `None` off
    /// Linux.
    pub uid: Option<u32>,
    /// The stream's wire id.
    pub stream_id: i32,
    /// The stream's session.
    pub session_id: i32,
    /// The handle's role.
    pub role: GrantRole,
    /// The registration the grant answered with.
    pub registration: u64,
}

/// The audited streams and the grants not drained yet: at most
/// `CAPACITY`; one more is dropped and counted.
#[derive(Debug, Default)]
pub(crate) struct GrantAudits {
    /// The audited streams' internal ids.
    streams: Vec<u64>,
    /// The grants not drained yet.
    pending: Vec<GrantAudit>,
    /// Grants dropped while `pending` was full.
    dropped: u64,
}

impl GrantAudits {
    /// Grants held between two drains at most.
    pub(crate) const CAPACITY: usize = 64;

    /// Audits the stream `stream` from now on (control path: allocates).
    pub(crate) fn watch(&mut self, stream: u64) {
        if self.pending.capacity() == 0 {
            self.pending.reserve_exact(Self::CAPACITY);
        }
        if !self.streams.contains(&stream) {
            self.streams.push(stream);
        }
    }

    /// Whether the stream `stream` is audited.
    pub(crate) fn watches(&self, stream: u64) -> bool {
        self.streams.contains(&stream)
    }

    /// Records `audit`, or counts it dropped while full.
    pub(crate) fn record(&mut self, audit: GrantAudit) {
        if self.pending.len() < Self::CAPACITY {
            self.pending.push(audit);
        } else if let Some(count) = self.dropped.checked_add(1) {
            self.dropped = count;
        }
    }

    /// Hands every pending grant to `each`, oldest first.
    pub(crate) fn drain(&mut self, each: impl FnMut(GrantAudit)) {
        self.pending.drain(..).for_each(each);
    }

    /// Grants dropped while full.
    pub(crate) fn dropped(&self) -> u64 {
        self.dropped
    }
}
