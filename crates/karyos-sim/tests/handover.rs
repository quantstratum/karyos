// SPDX-License-Identifier: Apache-2.0

//! W5's leader handover (karyos#687 P3, karyos#905 review): what the
//! generic pass requires of a handover, and the reference fixture's
//! handover safety when `TimeoutNow` arrives late or its sender crashes.
//! The `Reference` runs are harness validation, not C5 evidence.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::cell::Cell;

use karyos_sim::harness::core::{
    ConsensusCore, Limits, LogView, NotLeader, Persisted, Ready, Refused, TransferRefused,
    Unsupported,
};
use karyos_sim::harness::reference::{Message, Reference};
use karyos_sim::harness::workloads::{Action, Case, Failed, Progress, W5, pass, run};
use karyos_sim::net::NodeId;

thread_local! {
    /// The tick `Late` releases the TimeoutNow messages it holds.
    static RELEASE: Cell<u64> = const { Cell::new(0) };
}

macro_rules! delegate {
    () => {
        fn recover_with(
            id: NodeId,
            peers: &[NodeId],
            limits: &Limits,
            log: &mut LogView<'_>,
        ) -> Result<Self, Unsupported> {
            Reference::recover_with(id, peers, limits, log).map(|core| Self::wrap(core))
        }

        fn propose(&mut self, command: Vec<u8>, log: &mut LogView<'_>) -> Result<(), Refused> {
            self.inner().propose(command, log)
        }

        fn step(&mut self, from: NodeId, message: Message, log: &mut LogView<'_>) {
            self.inner().step(from, message, log);
        }

        fn advance(&mut self, persisted: Persisted, log: &mut LogView<'_>) {
            self.inner().advance(persisted, log);
        }

        fn term(&self) -> u64 {
            self.inner_ref().term()
        }

        fn leads(&self) -> bool {
            self.inner_ref().leads()
        }

        fn received(&self) -> Option<u64> {
            self.inner_ref().received()
        }

        fn committed(&self) -> Option<u64> {
            self.inner_ref().committed()
        }
    };
}

/// A core that answers every handover Ok and never hands over.
#[derive(Debug)]
struct Faker(Reference);

impl Faker {
    fn wrap(core: Reference) -> Self {
        Self(core)
    }
    fn inner(&mut self) -> &mut Reference {
        &mut self.0
    }
    fn inner_ref(&self) -> &Reference {
        &self.0
    }
}

impl ConsensusCore for Faker {
    type Message = Message;

    fn recover(id: NodeId, peers: &[NodeId], log: &mut LogView<'_>) -> Self {
        Self(Reference::recover(id, peers, log))
    }

    fn ready(&mut self, log: &mut LogView<'_>) -> Option<Ready<Message>> {
        self.0.ready(log)
    }

    fn tick(&mut self, now: u64, log: &mut LogView<'_>) {
        self.0.tick(now, log);
    }

    fn transfer_leadership(
        &mut self,
        _to: NodeId,
        _log: &mut LogView<'_>,
    ) -> Result<(), TransferRefused> {
        Ok(())
    }

    delegate!();
}

/// `Reference` holding every TimeoutNow it sends until [`RELEASE`].
#[derive(Debug)]
struct Late {
    core: Reference,
    held: Vec<(NodeId, Message)>,
    now: u64,
}

impl Late {
    fn wrap(core: Reference) -> Self {
        Self {
            core,
            held: Vec::new(),
            now: 0,
        }
    }
    fn inner(&mut self) -> &mut Reference {
        &mut self.core
    }
    fn inner_ref(&self) -> &Reference {
        &self.core
    }
}

impl ConsensusCore for Late {
    type Message = Message;

    fn recover(id: NodeId, peers: &[NodeId], log: &mut LogView<'_>) -> Self {
        Self::wrap(Reference::recover(id, peers, log))
    }

    fn tick(&mut self, now: u64, log: &mut LogView<'_>) {
        self.now = now;
        self.core.tick(now, log);
    }

    fn ready(&mut self, log: &mut LogView<'_>) -> Option<Ready<Message>> {
        let mut ready = self.core.ready(log);
        if let Some(ready) = ready.as_mut() {
            let (late, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut ready.after_persist)
                .into_iter()
                .partition(|(_, message)| matches!(message, Message::TimeoutNow { .. }));
            ready.after_persist = kept;
            self.held.extend(late);
            let (late, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut ready.messages)
                .into_iter()
                .partition(|(_, message)| matches!(message, Message::TimeoutNow { .. }));
            ready.messages = kept;
            self.held.extend(late);
            if self.now >= RELEASE.with(Cell::get) {
                ready.after_persist.append(&mut self.held);
            }
        }
        ready
    }

    fn transfer_leadership(
        &mut self,
        to: NodeId,
        log: &mut LogView<'_>,
    ) -> Result<(), TransferRefused> {
        self.core.transfer_leadership(to, log)
    }

    delegate!();
}

fn retry_case() -> Case {
    W5::skeleton().cases().unwrap().pop().unwrap()
}

/// The generic pass requires the declared handover (karyos#905 review,
/// codex): a core that answers it Ok and never hands over fails the case,
/// whatever else it shows.
#[test]
fn a_handover_answered_but_not_made_fails_the_case() {
    let case = retry_case();
    assert_eq!(case.handover, Some(1));
    let outcome = run::<Faker>(&case, 1).unwrap();
    assert_eq!(pass(&case, &outcome), Err(Failed::NotShown("handover")));
    let mut lax = case;
    lax.handover = None;
    assert_ne!(pass(&lax, &outcome), Err(Failed::NotShown("handover")));
}

/// A TimeoutNow that arrives long after the handover began (karyos#905
/// review: one delivered at step 200 made a leader lacking the old
/// leader's later commits): the old leader never resumes its term, so
/// nothing committed is lost, and the target still takes over.
#[test]
fn a_late_timeout_now_loses_nothing() {
    let mut case = retry_case();
    case.operations = 200;
    case.steps = 10_000;
    RELEASE.with(|release| release.set(200));
    let outcome = run::<Late>(&case, 1).unwrap();
    RELEASE.with(|release| release.set(0));
    assert_eq!(pass(&case, &outcome), Ok(None));
}

/// The old leader crashes right after it began the handover, and restarts
/// later: it follows the target, never its own term again, and no
/// committed entry is lost (progress may stop: there is no election).
#[test]
fn an_old_leader_crashing_mid_handover_stays_safe() {
    for crash_after in [0, 1, 2, 5] {
        let mut case = Case::healthy("handover crash", 3, 2, 40);
        let at = 20;
        case.schedule = vec![
            (at, Action::TransferLeadership(1)),
            (at + crash_after, Action::Crash(0)),
            (at + crash_after + 60, Action::Restart(0)),
        ];
        case.progress = Progress::MayStop;
        case.steps = 2_000;
        let outcome = run::<Reference>(&case, 1).unwrap();
        assert!(
            outcome.safety.is_ok(),
            "crash {crash_after} after: {:?}",
            outcome.safety
        );
        assert!(!matches!(pass(&case, &outcome), Err(Failed::Safety(_))));
    }
}

/// `Reference` that answers a handover Ok at once and makes it only at
/// tick 1,000, after every request has finished (karyos#905 review,
/// codex's artifact 264).
#[derive(Debug)]
struct Deferred {
    core: Reference,
    pending: Option<NodeId>,
}

impl Deferred {
    fn wrap(core: Reference) -> Self {
        Self {
            core,
            pending: None,
        }
    }
    fn inner(&mut self) -> &mut Reference {
        &mut self.core
    }
    fn inner_ref(&self) -> &Reference {
        &self.core
    }
}

impl ConsensusCore for Deferred {
    type Message = Message;

    fn recover(id: NodeId, peers: &[NodeId], log: &mut LogView<'_>) -> Self {
        Self::wrap(Reference::recover(id, peers, log))
    }

    fn tick(&mut self, now: u64, log: &mut LogView<'_>) {
        if now >= 1_000
            && let Some(to) = self.pending.take()
        {
            let _ = self.core.transfer_leadership(to, log);
        }
        self.core.tick(now, log);
    }

    fn ready(&mut self, log: &mut LogView<'_>) -> Option<Ready<Message>> {
        self.core.ready(log)
    }

    fn transfer_leadership(
        &mut self,
        to: NodeId,
        _log: &mut LogView<'_>,
    ) -> Result<(), TransferRefused> {
        if !self.core.leads() {
            return Err(TransferRefused::Invalid);
        }
        self.pending = Some(to);
        Ok(())
    }

    delegate!();
}

/// The retry must cross the handover, in order (karyos#905 review): a
/// handover made only after every request finished, with retries
/// deduplicated before it, does not show the case.
#[test]
fn a_handover_after_the_retries_does_not_show_them() {
    let case = retry_case();
    let outcome = run::<Deferred>(&case, 1).unwrap();
    assert!(
        outcome.observations.iter().any(|o| matches!(
            o,
            karyos_sim::harness::node::Observation::Commit {
                node: 1,
                leader: true,
                ..
            }
        )),
        "the deferred handover still happened"
    );
    assert_eq!(pass(&case, &outcome), Err(Failed::NotShown("retry")));
}

thread_local! {
    /// The tick `Held` releases the target's held applications.
    static APPLY: Cell<u64> = const { Cell::new(0) };
}

/// `Deferred` that also redirects one request to node 1 at tick 7 and holds
/// node 1's applications until [`APPLY`] (karyos#905 review, codex's
/// artifact 267): node 1 then applies the retried request as a replica
/// after it leads, without ever serving that client.
#[derive(Debug)]
struct Held {
    id: NodeId,
    deferred: Deferred,
    redirected: bool,
    held: Vec<karyos_cluster::Entry>,
    now: u64,
}

impl Held {
    fn wrap(id: NodeId, core: Reference) -> Self {
        Self {
            id,
            deferred: Deferred::wrap(core),
            redirected: false,
            held: Vec::new(),
            now: 0,
        }
    }
    fn inner(&mut self) -> &mut Reference {
        &mut self.deferred.core
    }
    fn inner_ref(&self) -> &Reference {
        &self.deferred.core
    }
}

impl ConsensusCore for Held {
    type Message = Message;

    fn recover(id: NodeId, peers: &[NodeId], log: &mut LogView<'_>) -> Self {
        Self::wrap(id, Reference::recover(id, peers, log))
    }

    fn recover_with(
        id: NodeId,
        peers: &[NodeId],
        limits: &Limits,
        log: &mut LogView<'_>,
    ) -> Result<Self, Unsupported> {
        Reference::recover_with(id, peers, limits, log).map(|core| Self::wrap(id, core))
    }

    fn propose(&mut self, command: Vec<u8>, log: &mut LogView<'_>) -> Result<(), Refused> {
        if self.now >= 7 && !self.redirected && self.id != 1 && self.inner_ref().leads() {
            self.redirected = true;
            return Err(Refused::NotLeader(NotLeader { leader: Some(1) }));
        }
        self.inner().propose(command, log)
    }

    fn step(&mut self, from: NodeId, message: Message, log: &mut LogView<'_>) {
        self.inner().step(from, message, log);
    }

    fn advance(&mut self, persisted: Persisted, log: &mut LogView<'_>) {
        self.inner().advance(persisted, log);
    }

    fn tick(&mut self, now: u64, log: &mut LogView<'_>) {
        self.now = now;
        self.deferred.tick(now, log);
    }

    fn ready(&mut self, log: &mut LogView<'_>) -> Option<Ready<Message>> {
        let mut ready = self.deferred.ready(log);
        if self.id != 1 {
            return ready;
        }
        if let Some(ready) = ready.as_mut() {
            self.held.append(&mut ready.committed);
        }
        if self.now < APPLY.with(Cell::get) || self.held.is_empty() {
            return ready;
        }
        let mut ready = ready.unwrap_or_default();
        ready.committed = std::mem::take(&mut self.held);
        Some(ready)
    }

    fn transfer_leadership(
        &mut self,
        to: NodeId,
        log: &mut LogView<'_>,
    ) -> Result<(), TransferRefused> {
        self.deferred.transfer_leadership(to, log)
    }

    fn term(&self) -> u64 {
        self.inner_ref().term()
    }

    fn leads(&self) -> bool {
        self.inner_ref().leads()
    }

    fn received(&self) -> Option<u64> {
        self.inner_ref().received()
    }

    fn committed(&self) -> Option<u64> {
        self.inner_ref().committed()
    }
}

/// A retry is shown only by a retained answer the target actually sends
/// (karyos#905 review, codex's artifact 267): the target applying the
/// retried request as a replica, after it leads, serves no client, and
/// fails the case whenever its applications are released.
#[test]
fn a_replica_applying_the_retry_does_not_show_it() {
    for release in [1_000, 1_100] {
        let case = retry_case();
        APPLY.with(|apply| apply.set(release));
        let outcome = run::<Held>(&case, 1).unwrap();
        APPLY.with(|apply| apply.set(0));
        assert!(
            outcome.safety.is_ok(),
            "release {release}: {:?}",
            outcome.safety
        );
        assert!(
            outcome.observations.iter().any(|o| matches!(
                o,
                karyos_sim::harness::node::Observation::Redirected { to: 1, .. }
            )),
            "release {release}: the redirect happened"
        );
        assert_eq!(
            pass(&case, &outcome),
            Err(Failed::NotShown("retry")),
            "release {release}"
        );
    }
}

/// Two handovers asked back to back (karyos#905 review, codex): the
/// second, to another target, is refused while the first is under way, so
/// two nodes never both lead the next term.
#[test]
fn a_second_handover_mid_handover_never_makes_two_leaders() {
    for gap in [0, 1, 2, 5] {
        let mut case = Case::healthy("overlapping handovers", 3, 2, 40);
        let at = 1_000;
        case.schedule = vec![
            (at, Action::TransferLeadership(1)),
            (at + gap, Action::TransferLeadership(2)),
        ];
        case.steps = 2_000;
        let outcome = run::<Reference>(&case, 1).unwrap();
        assert!(outcome.safety.is_ok(), "gap {gap}: {:?}", outcome.safety);
        let refused = outcome.observations.iter().any(|o| {
            matches!(
                o,
                karyos_sim::harness::node::Observation::Transfer {
                    node: 0,
                    to: 2,
                    result: Err(TransferRefused::NotLeader(_)),
                }
            )
        });
        let transfers: Vec<_> = outcome
            .observations
            .iter()
            .filter(|o| matches!(o, karyos_sim::harness::node::Observation::Transfer { .. }))
            .collect();
        assert!(
            transfers.iter().any(|o| matches!(
                o,
                karyos_sim::harness::node::Observation::Transfer {
                    node: 0,
                    to: 1,
                    result: Ok(()),
                }
            )),
            "gap {gap}: the first handover began: {transfers:?}"
        );
        assert!(refused, "gap {gap}: the second was refused: {transfers:?}");
    }
}
