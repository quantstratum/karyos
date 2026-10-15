// SPDX-License-Identifier: Apache-2.0

//! The export ledger of a remote client (`quantstratum-docs:
//! karyos/design/ipc-data-path.md`, Grants and the export ledger): one entry
//! per grant, from the command that reserves its participant until its
//! registration ends.

use karyos_sys::log_buffer::Role;

/// The state of a grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GrantState {
    /// Reserved and answered; not fetched yet. `Fetch` (d2c) adds the
    /// exporting, exported and failed states.
    Held,
}

/// The participant a grant reserves in its stream's log buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Participant {
    /// The exclusive publication.
    Exclusive,
    /// A concurrent publisher slot.
    Concurrent { slot: usize },
    /// A subscriber cell.
    Subscriber { cell: usize, role: Role },
}

/// One grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Grant {
    /// Its export id, stored in the participant's registration word.
    pub(crate) export: u64,
    /// The registration it answers.
    pub(crate) registration: u64,
    /// The hand-over key of its response, which a fetch names.
    pub(crate) key: u64,
    /// The driver's id of its stream.
    pub(crate) stream: u64,
    pub(crate) participant: Participant,
    pub(crate) state: GrantState,
    /// Whether a descriptor of it has left the outbound queue: from then on
    /// it stays charged until its `Detach` or the client's exit proof.
    pub(crate) sent: bool,
}

/// The grants of one remote client.
#[derive(Debug)]
pub(crate) struct Ledger {
    grants: Vec<Grant>,
    /// `max_exports_per_client`: grants in any state.
    limit: usize,
}

impl Ledger {
    /// An empty ledger that holds at most `limit` grants.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "remote clients are admitted only on Linux")
    )]
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            grants: Vec::new(),
            limit,
        }
    }

    /// Whether a new grant would exceed the client's bound.
    pub(crate) fn full(&self) -> bool {
        self.grants.len() >= self.limit
    }

    /// Records a new grant.
    pub(crate) fn push(&mut self, grant: Grant) {
        self.grants.push(grant);
    }

    /// The grant answering `registration`.
    pub(crate) fn by_registration(&self, registration: u64) -> Option<&Grant> {
        self.grants
            .iter()
            .find(|grant| grant.registration == registration)
    }

    /// Removes and returns the grant answering `registration`.
    pub(crate) fn remove_registration(&mut self, registration: u64) -> Option<Grant> {
        let index = self
            .grants
            .iter()
            .position(|grant| grant.registration == registration)?;
        Some(self.grants.swap_remove(index))
    }

    /// Whether any grant names the stream `stream`.
    pub(crate) fn names_stream(&self, stream: u64) -> bool {
        self.grants.iter().any(|grant| grant.stream == stream)
    }

    /// Records that a descriptor of the grant answering `registration` has
    /// left the outbound queue.
    #[cfg(test)]
    pub(crate) fn mark_sent(&mut self, registration: u64) {
        if let Some(grant) = self
            .grants
            .iter_mut()
            .find(|grant| grant.registration == registration)
        {
            grant.sent = true;
        }
    }

    /// The grants, for inspection.
    #[cfg(test)]
    pub(crate) fn grants(&self) -> &[Grant] {
        &self.grants
    }
}
