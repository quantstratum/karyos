// SPDX-License-Identifier: Apache-2.0

//! The export ledger of a remote client (`quantstratum-docs:
//! karyos/design/ipc-data-path.md`, Grants and the export ledger): one entry
//! per grant, from the command that reserves its participant until its
//! registration ends.

use karyos_sys::log_buffer::Role;

/// The state of a grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "fetches are served only on Linux")
)]
pub(crate) enum GrantState {
    /// Reserved and answered; not fetched yet.
    Held,
    /// Its fetch is being sent.
    Exporting,
    /// Every message of its fetch was sent.
    Exported,
    /// A send of its fetch failed; it is never fetched again.
    Failed,
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
    /// `max_regions_per_fetch` and `max_fetch_bytes`: a grant beyond them
    /// could never be fetched, so its command is refused.
    max_regions: usize,
    max_bytes: u64,
}

impl Ledger {
    /// An empty ledger that holds at most `limit` grants.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "remote clients are admitted only on Linux")
    )]
    pub(crate) fn new(limit: usize, max_regions: usize, max_bytes: u64) -> Self {
        Self {
            grants: Vec::new(),
            limit,
            max_regions,
            max_bytes,
        }
    }

    /// Whether a grant of `regions` regions of `bytes` bytes in all fits
    /// one fetch.
    pub(crate) fn fetchable(&self, regions: usize, bytes: u64) -> bool {
        regions <= self.max_regions && bytes <= self.max_bytes
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

    /// Removes and returns every grant whose descriptor never left.
    pub(crate) fn take_unsent(&mut self) -> Vec<Grant> {
        let (unsent, sent) = core::mem::take(&mut self.grants)
            .into_iter()
            .partition(|grant| !grant.sent);
        self.grants = sent;
        unsent
    }

    /// Every grant, ending the ledger.
    pub(crate) fn into_grants(self) -> Vec<Grant> {
        self.grants
    }

    /// Whether any grant names the stream `stream`.
    pub(crate) fn names_stream(&self, stream: u64) -> bool {
        self.grants.iter().any(|grant| grant.stream == stream)
    }

    /// The `Held` grant whose response carried `key`.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "remote clients are admitted only on Linux")
    )]
    pub(crate) fn held(&self, key: u64) -> Option<&Grant> {
        self.grants
            .iter()
            .find(|grant| grant.key == key && grant.state == GrantState::Held)
    }

    /// Moves the grant answering `registration` to `state`.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "remote clients are admitted only on Linux")
    )]
    pub(crate) fn set_state(&mut self, registration: u64, state: GrantState) {
        if let Some(grant) = self
            .grants
            .iter_mut()
            .find(|grant| grant.registration == registration)
        {
            grant.state = state;
        }
    }

    /// Records that a descriptor of the grant answering `registration` has
    /// left the outbound queue.
    #[cfg_attr(
        all(not(target_os = "linux"), not(test)),
        allow(dead_code, reason = "remote clients are admitted only on Linux")
    )]
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
