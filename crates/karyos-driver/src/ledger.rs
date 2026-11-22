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
    /// No stream participant: a client trace journal (`quantstratum-docs:
    /// karyos/design/trace-journal-region.md`), whose grant has stream 0.
    Journal { journal: u64 },
    /// No log buffer participant: a read-only view of the stream's
    /// conflation table (`quantstratum-docs:
    /// karyos/design/conflation-end-to-end.md`, Cross-process views). The
    /// table outlives mapping generations, so a cutover neither moves nor
    /// fences the grant, and it charges no generation.
    Conflation,
    /// No log buffer participant: one region of a guarded publication's
    /// binding (`quantstratum-docs: karyos/design/guards-and-abort.md`,
    /// "The binding across processes"), granted with the publication's log
    /// buffer under the same key. Its region outlives mapping generations,
    /// so a cutover neither moves nor fences it. A concurrent handle's
    /// consumed cell names its `slot` of the incarnation's shared outcome
    /// ring (ADR-0092); every other binding region has none.
    Binding {
        region: BindingRegion,
        slot: Option<usize>,
    },
}

/// Which region of a guarded publication's binding a grant carries, in
/// the order its manifest lists them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum BindingRegion {
    /// The handle's outcome ring, read-only.
    Outcomes,
    /// The handle's consumed cell, writable by its client alone.
    Consumed,
    /// The driver's guard words, read-only.
    Guards,
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
    /// The driver's id of its stream; 0 (no stream) for a journal grant.
    pub(crate) stream: u64,
    pub(crate) participant: Participant,
    pub(crate) state: GrantState,
    /// Whether a descriptor of it has left the outbound queue: from then on
    /// it stays charged until its `Detach` or the client's exit proof.
    pub(crate) sent: bool,
    /// The mapping generation of its participant.
    pub(crate) generation: u32,
    /// The publication incarnation of its stream when it was granted
    /// (`quantstratum-docs: karyos/design/guards-and-abort.md`, The fresh
    /// incarnation); 0 for a journal grant, which names no stream.
    pub(crate) incarnation: u64,
    /// For a successor grant reserved at a cutover: when the driver fences
    /// it if its participant has not adopted it (`quantstratum-docs:
    /// karyos/design/ipc-data-path.md`, Generations across processes).
    pub(crate) fence_at: Option<u64>,
    /// Whether the driver fenced it before its participant adopted it: its
    /// participant never reached this generation, so a later cutover does
    /// not move it, yet a sent one stays charged until its `Detach` or the
    /// client's exit proof.
    pub(crate) fenced: bool,
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
        !self.has_room(1)
    }

    /// Whether `grants` more grants fit the client's bound.
    pub(crate) fn has_room(&self, grants: usize) -> bool {
        self.grants
            .len()
            .checked_add(grants)
            .is_some_and(|total| total <= self.limit)
    }

    /// The most grants it holds at once, `max_exports_per_client`.
    pub(crate) fn limit(&self) -> usize {
        self.limit
    }

    /// Records a new grant.
    pub(crate) fn push(&mut self, grant: Grant) {
        self.grants.push(grant);
    }

    /// Removes and returns every grant of `registration`, of any
    /// generation, whose descriptor never left.
    pub(crate) fn take_unsent_of(&mut self, registration: u64) -> Vec<Grant> {
        let (unsent, kept) = core::mem::take(&mut self.grants)
            .into_iter()
            .partition(|grant| grant.registration == registration && !grant.sent);
        self.grants = kept;
        unsent
    }

    /// Every grant, to change.
    pub(crate) fn grants_mut(&mut self) -> &mut Vec<Grant> {
        &mut self.grants
    }

    /// Whether a successor grant of stream `stream` is still waiting for
    /// its adoption or its fence.
    pub(crate) fn unsettled_successor(&self, stream: u64) -> bool {
        self.grants
            .iter()
            .any(|grant| grant.stream == stream && grant.fence_at.is_some())
    }

    /// Removes and returns the grant of `export` if its fetch is over
    /// (`Exported` or `Failed`): the only grants a `Detach` may end.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "remote clients are admitted only on Linux")
    )]
    pub(crate) fn detach(&mut self, export: u64) -> Option<Grant> {
        let index = self.grants.iter().position(|grant| {
            grant.export == export
                && matches!(grant.state, GrantState::Exported | GrantState::Failed)
        })?;
        Some(self.grants.swap_remove(index))
    }

    /// Whether no grant was sent: the client may `Leave`, which ends every
    /// grant like the exit proof.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "remote clients are admitted only on Linux")
    )]
    pub(crate) fn only_held(&self) -> bool {
        self.grants
            .iter()
            .all(|grant| grant.state == GrantState::Held && !grant.sent)
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

    /// The `Held` grant whose response carried `key`; for a guarded
    /// publication, its log buffer's ([`Ledger::held_binding`] has the
    /// rest).
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "remote clients are admitted only on Linux")
    )]
    pub(crate) fn held(&self, key: u64) -> Option<&Grant> {
        self.grants.iter().find(|grant| {
            grant.key == key
                && grant.state == GrantState::Held
                && !matches!(grant.participant, Participant::Binding { .. })
        })
    }

    /// The `Held` binding grants that share `key` with a guarded
    /// publication's grant, in manifest order: the outcome ring, the
    /// consumed cell and the guard region. Sorted, because removals
    /// reorder the ledger.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "remote clients are admitted only on Linux")
    )]
    pub(crate) fn held_binding(&self, key: u64) -> Vec<Grant> {
        let mut held = self
            .grants
            .iter()
            .filter(|grant| {
                grant.key == key
                    && grant.state == GrantState::Held
                    && matches!(grant.participant, Participant::Binding { .. })
            })
            .copied()
            .collect::<Vec<_>>();
        held.sort_by_key(|grant| match grant.participant {
            Participant::Binding { region, .. } => Some(region),
            _ => None,
        });
        held
    }

    /// Moves the grant of `export` to `state`.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "remote clients are admitted only on Linux")
    )]
    pub(crate) fn set_state(&mut self, export: u64, state: GrantState) {
        if let Some(grant) = self.grants.iter_mut().find(|grant| grant.export == export) {
            grant.state = state;
        }
    }

    /// Records that a descriptor of the grant of `export` has left the
    /// outbound queue.
    #[cfg_attr(
        all(not(target_os = "linux"), not(test)),
        allow(dead_code, reason = "remote clients are admitted only on Linux")
    )]
    pub(crate) fn mark_sent(&mut self, export: u64) {
        if let Some(grant) = self.grants.iter_mut().find(|grant| grant.export == export) {
            grant.sent = true;
        }
    }

    /// The grants.
    pub(crate) fn grants(&self) -> &[Grant] {
        &self.grants
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(registration: u64) -> Grant {
        Grant {
            incarnation: crate::embedded::FIRST_INCARNATION,
            export: registration + 100,
            registration,
            key: registration,
            stream: 1,
            participant: Participant::Exclusive,
            state: GrantState::Held,
            sent: false,
            generation: 0,
            fence_at: None,
            fenced: false,
        }
    }

    #[test]
    fn leave_is_allowed_only_while_nothing_was_sent() {
        let mut ledger = Ledger::new(4, 4, 1 << 30);
        assert!(ledger.only_held());
        ledger.push(grant(1));
        ledger.push(grant(2));
        assert!(ledger.only_held());
        ledger.mark_sent(102);
        assert!(!ledger.only_held());
        // A retirement ends the unsent one and keeps the sent one.
        let unsent = ledger.take_unsent();
        assert_eq!(unsent.len(), 1);
        assert_eq!(unsent[0].registration, 1);
        assert_eq!(ledger.grants().len(), 1);
    }
}
