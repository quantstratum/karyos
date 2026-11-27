// SPDX-License-Identifier: Apache-2.0

//! H8 round 4 (karyos#648): invariants whose evidence the review found
//! insufficient, raised to proofs through both network agents, their rings
//! and the receiver's real intake; and the missing properties it named.
//! Each test names its `INV-` id in the invariant list.

use std::sync::{Arc, Mutex};

use super::*;

/// H8 round 5 evidence (R5-07 to R5-09) on the helpers of this module.
mod r6;

/// Durable marks shared across a restart and observable by the test: the
/// epochs, the latched guards, and whether a persist fails.
#[derive(Debug, Clone, Default)]
struct SharedMarks(Arc<Mutex<Held>>);

/// What [`SharedMarks`] holds: `.0` the epochs, `.1` the latched guards,
/// `.2` whether a persist fails.
#[derive(Debug, Default)]
struct Held(std::collections::HashMap<u64, u64>, Vec<u64>, bool);

impl crate::remote_guard::MarkStore for SharedMarks {
    fn load(&self, guard_id: u64) -> Result<u64, crate::remote_guard::MarkError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .0
            .get(&guard_id)
            .copied()
            .unwrap_or(0))
    }

    fn latched(&self, guard_id: u64) -> Result<bool, crate::remote_guard::MarkError> {
        Ok(self.0.lock().unwrap().1.contains(&guard_id))
    }

    fn persist(&mut self, guard_id: u64, epoch: u64) -> Result<(), crate::remote_guard::MarkError> {
        let mut held = self.0.lock().unwrap();
        if held.2 {
            return Err(crate::remote_guard::MarkError::Commit);
        }
        let mark = held.0.entry(guard_id).or_insert(0);
        *mark = (*mark).max(epoch);
        Ok(())
    }

    fn latch(&mut self, guard_id: u64) -> Result<(), crate::remote_guard::MarkError> {
        let mut held = self.0.lock().unwrap();
        if !held.1.contains(&guard_id) {
            held.1.push(guard_id);
        }
        Ok(())
    }
}

impl SharedMarks {
    fn with(guard_id: u64, epoch: u64) -> Self {
        let marks = Self::default();
        marks.0.lock().unwrap().0.insert(guard_id, epoch);
        marks
    }

    fn fail_writes(&self, fail: bool) {
        self.0.lock().unwrap().2 = fail;
    }

    fn is_latched(&self, guard_id: u64) -> bool {
        self.0.lock().unwrap().1.contains(&guard_id)
    }
}

/// [`remotely_guarded_rig`] over `marks`, which the test keeps.
fn guarded_over(
    marks: &SharedMarks,
    authority: Option<Arc<karyos_client::HeapWords>>,
) -> (Rig, SocketAddr, crate::authority::Ed25519Signer) {
    use karyos_sys::applied_epoch::AppliedEpoch;

    use crate::authority::Ed25519Signer;
    use crate::guard_authority::{AuthorityGuard, GuardAuthority};
    use crate::remote_guard::RemoteGuard;
    use crate::signed_control::Authority;

    let mirror = guard_word(1, false);
    let (mut rig, b) = Rig::new(Setup {
        remote_guard: Some(crate::agents::data::GuardSpec {
            word: Arc::clone(&mirror) as Arc<dyn karyos_client::SharedWords>,
            cell: Arc::new(AppliedEpoch::new()),
            epoch: 0,
            empty_since: None,
            rate: None,
            reserve: None,
            policy: None,
            frontier: Default::default(),
        }),
        ..Setup::default()
    });
    let a = rig.publisher;
    let a_at = rig.endpoints.local_address(a).unwrap();
    let b_at = rig.endpoints.local_address(b).unwrap();
    let signer = Ed25519Signer::from_seed(&[9; 32]);
    let receiver = &mut rig.agents.receiver.role;
    receiver.trust_authorities(
        vec![Authority::of(10, signer.verifier(), 10, &[11], false)],
        0,
    );
    let guard = RemoteGuard::load(10, 11, marks);
    receiver.follow_guard(guard, 66, a, b_at, Box::new(marks.clone()), Some(mirror));
    if let Some(word) = authority {
        let guards = vec![AuthorityGuard {
            guard_id: 11,
            word: word as Arc<dyn karyos_client::SharedWords>,
            lifetime_ms: 5_000,
            receivers: vec![(66, a_at)],
        }];
        receiver.set_guard_authority(
            Some(
                GuardAuthority::new(
                    10,
                    10,
                    Ed25519Signer::from_seed(&[9; 32]),
                    guards,
                    Box::new(MemoryMarks::default()),
                    0,
                )
                .unwrap(),
            ),
            &[b],
        );
    }
    (rig, b_at, signer)
}

/// The follower's next STATUS_CHALLENGE to `authority`, taken off the
/// sender's queue unsent (the sender stays stopped).
fn next_challenge(
    rig: &mut Rig,
    authority: SocketAddr,
) -> karyos_protocol::network::authenticated::StatusChallenge {
    use crate::agents::control::ControlItem;

    rig.sender_stopped = true;
    for _ in 0..3000 {
        rig.round(true);
        while let Some(item) = rig.agents.sender.role.take_control() {
            if let ControlItem::Raw {
                destination, bytes, ..
            } = item
                && destination == authority
                && let Ok(challenge) =
                    karyos_protocol::network::authenticated::decode_bare_status_challenge(
                        bytes.get(),
                    )
            {
                return challenge;
            }
        }
    }
    panic!("no challenge");
}

/// A STATUS of guard 11 answering `nonce` for `receiver`, at `epoch`.
fn signed_status(
    signer: &crate::authority::Ed25519Signer,
    receiver: karyos_protocol::network::Receiver,
    nonce: [u64; 2],
    epoch: u64,
    seq: u64,
) -> Vec<u8> {
    use karyos_protocol::network::authenticated::{AuthControl, GuardStatus, GuardWord};
    use karyos_protocol::protection::signed::{SignedBinding, SignedDomain, seal_signed};

    let mut bytes = vec![0u8; 256];
    let body = AuthControl::Status(GuardStatus {
        authority_id: 10,
        guard_id: 11,
        receiver,
        nonce,
        word: GuardWord::from_epoch(epoch).unwrap(),
    })
    .encode(&mut bytes)
    .unwrap();
    let binding = SignedBinding {
        domain: SignedDomain::Guard,
        party_epoch: 0,
        session_id: 0,
        stream_id: 0,
        key_id: 10,
    };
    let length = seal_signed(&mut bytes, body, &binding, seq, signer).unwrap();
    bytes.truncate(length);
    bytes
}

fn pending(rig: &Rig) -> bool {
    rig.agents
        .sender
        .role
        .outbound(0)
        .unwrap()
        .admission_pending()
}

/// INV-GRD-2 (ADR-0107 d2), through the receiver's intake and the
/// publication's admission: a STATUS for another nonce or another boot id
/// is refused and admits nothing; the genuine answer admits the
/// publication, and its replay is refused (the nonce is consumed).
#[test]
fn inv_r4_stale_or_misdirected_statuses_never_admit_the_publication() {
    use crate::remote_guard::Phase;

    let (mut rig, b_at, signer) = guarded_over(&SharedMarks::default(), None);
    // ADM-14: while pending it registers no SETUP session, so it never
    // establishes before the genuine STATUS.
    for _ in 0..300 {
        rig.round(true);
    }
    assert_eq!(rig.agents.sender.role.registered_sessions(), (0, 1));
    let challenge = next_challenge(&mut rig, b_at);
    let other_boot = karyos_protocol::network::Receiver {
        receiver_boot_id: [challenge.receiver.receiver_boot_id[0] ^ 1, 1],
        ..challenge.receiver
    };
    let refused = rig.agents.receiver.counters().guard_refused;
    for (receiver, nonce) in [
        (
            challenge.receiver,
            [challenge.nonce[0] ^ 1, challenge.nonce[1]],
        ),
        (other_boot, challenge.nonce),
    ] {
        inject_at_a(
            &mut rig,
            b_at,
            &signed_status(&signer, receiver, nonce, 2, 0),
        );
    }
    assert_eq!(rig.agents.receiver.counters().guard_refused, refused + 2);
    assert!(pending(&rig), "nothing admitted");
    // ADM-14: still pending, it registers no SETUP session.
    assert_eq!(rig.agents.sender.role.registered_sessions(), (0, 1));
    rig.sender_stopped = false;
    assert_eq!(send_one(&mut rig, 50), 0);
    let genuine = signed_status(&signer, challenge.receiver, challenge.nonce, 2, 1);
    // The nonce may have been replaced by a newer round meanwhile: answer
    // the current one.
    let challenge = next_challenge(&mut rig, b_at);
    let genuine_now = signed_status(&signer, challenge.receiver, challenge.nonce, 2, 2);
    inject_at_a(&mut rig, b_at, &genuine_now);
    assert!(matches!(
        rig.agents.receiver.role.guard_phase(11, rig.now),
        Some(Phase::Open { epoch: 2, .. })
    ));
    rig.sender_stopped = false;
    assert!(send_one(&mut rig, 100) >= 1, "admitted and sending");
    let refused = rig.agents.receiver.counters().guard_refused;
    inject_at_a(&mut rig, b_at, &genuine_now);
    inject_at_a(&mut rig, b_at, &genuine);
    assert_eq!(
        rig.agents.receiver.counters().guard_refused,
        refused + 2,
        "a consumed or replaced nonce is refused"
    );
}

/// INV-GRD-3 (ADR-0107 d2), the at-mark arm end to end: with a durable
/// mark of 2, the authority's STATUS at 2 completes recovery and admits
/// the publication (the below-mark arm is
/// `a_restart_with_the_stored_mark_refuses_an_old_open`).
#[test]
fn inv_r4_a_status_at_the_mark_admits_the_publication() {
    use crate::remote_guard::Phase;

    let (mut rig, _b_at, _signer) =
        guarded_over(&SharedMarks::with(11, 2), Some(guard_word(2, true)));
    let _slot = established(&mut rig);
    rig.until(true, |rig| {
        matches!(
            rig.agents.receiver.role.guard_phase(11, rig.now),
            Some(Phase::Open { epoch: 2, .. })
        )
    });
    assert!(send_one(&mut rig, 100) >= 1);
    assert!(!pending(&rig));
}

/// INV-GRD-4 (ADR-0107 d3 and d5), end to end: after recovery a STATE at
/// the floor is refused and changes nothing (the publication keeps
/// sending); after a Closed STATE above it, a later Open STATE alone does
/// not reopen the guard, with the authority still closed.
#[test]
fn inv_r4_after_recovery_states_need_an_epoch_above_the_floor_and_an_open_state_alone_never_opens()
{
    use crate::remote_guard::Phase;

    let authority = guard_word(2, true);
    let (mut rig, b_at, signer) =
        guarded_over(&SharedMarks::default(), Some(Arc::clone(&authority)));
    let _slot = established(&mut rig);
    rig.until(true, |rig| {
        matches!(
            rig.agents.receiver.role.guard_phase(11, rig.now),
            Some(Phase::Open { epoch: 2, .. })
        )
    });
    let refused = rig.agents.receiver.counters().guard_refused;
    inject_at_a(&mut rig, b_at, &signed_state(&signer, 1, 0));
    assert_eq!(rig.agents.receiver.counters().guard_refused, refused + 1);
    assert!(send_one(&mut rig, 100) >= 1, "still open and sending");
    set_word(&authority, 3, false);
    inject_at_a(&mut rig, b_at, &signed_state(&signer, 3, 1));
    assert_eq!(
        rig.agents.receiver.role.guard_phase(11, rig.now),
        Some(Phase::Closed)
    );
    // An Open STATE at 4 while the authority stays closed at 3.
    inject_at_a(&mut rig, b_at, &signed_state(&signer, 4, 2));
    for _ in 0..300 {
        rig.round(true);
    }
    assert!(
        !matches!(
            rig.agents.receiver.role.guard_phase(11, rig.now),
            Some(Phase::Open { .. })
        ),
        "{:?}",
        rig.agents.receiver.role.guard_phase(11, rig.now)
    );
    assert_eq!(send_one(&mut rig, 100), 0);
}

/// INV-GRD-7 (H8 R1 #3), end to end: a verified close whose mark cannot
/// be persisted still closes and raises the in-memory floor: a STATUS at
/// the old floor, answering the follower's own fresh challenge, does not
/// reopen it, and the publication sends nothing more.
#[test]
fn inv_r4_an_unpersisted_close_never_lets_the_old_floor_reopen() {
    use crate::remote_guard::Phase;

    let marks = SharedMarks::default();
    let authority = guard_word(2, true);
    let (mut rig, b_at, signer) = guarded_over(&marks, Some(Arc::clone(&authority)));
    let _slot = established(&mut rig);
    rig.until(true, |rig| {
        matches!(
            rig.agents.receiver.role.guard_phase(11, rig.now),
            Some(Phase::Open { epoch: 2, .. })
        )
    });
    assert!(send_one(&mut rig, 100) >= 1);
    marks.fail_writes(true);
    set_word(&authority, 3, false);
    inject_at_a(&mut rig, b_at, &signed_state(&signer, 3, 0));
    assert_eq!(
        rig.agents.receiver.role.guard_phase(11, rig.now),
        Some(Phase::Closed)
    );
    // The authority goes. An Open STATE above the raised floor asks for a
    // confirmation round, whose challenge is answered at the old floor.
    rig.agents.receiver.role.set_guard_authority(None, &[]);
    inject_at_a(&mut rig, b_at, &signed_state(&signer, 4, 1));
    let challenge = next_challenge(&mut rig, b_at);
    inject_at_a(
        &mut rig,
        b_at,
        &signed_status(&signer, challenge.receiver, challenge.nonce, 2, 9),
    );
    assert!(
        !matches!(
            rig.agents.receiver.role.guard_phase(11, rig.now),
            Some(Phase::Open { .. })
        ),
        "{:?}",
        rig.agents.receiver.role.guard_phase(11, rig.now)
    );
    rig.sender_stopped = false;
    assert_eq!(send_one(&mut rig, 100), 0);
}

/// INV-GRD-8 (ADR-0107 d6; ADR-0118 (c)), end to end across a restart: a
/// recovery STATUS below the durable mark latches the guard, the latch is
/// stored with the mark, and a restarted follower over the same marks
/// stays latched and never admits the publication, even when the
/// authority answers above the mark.
#[test]
fn inv_r4_a_rollback_latch_survives_a_restart() {
    use crate::remote_guard::Phase;

    let marks = SharedMarks::with(11, 4);
    {
        let (mut rig, _b_at, _signer) = guarded_over(&marks, Some(guard_word(2, true)));
        // ADM-14: pending, it registers no SETUP session.
        rig.until(true, |rig| {
            rig.agents.receiver.role.guard_phase(11, rig.now) == Some(Phase::Latched)
        });
    }
    assert!(marks.is_latched(11), "the latch is durable");
    let (mut rig, _b_at, _signer) = guarded_over(&marks, Some(guard_word(6, true)));
    for _ in 0..1500 {
        rig.round(true);
    }
    // Latched, it never registers a SETUP session either (ADM-14).
    assert_eq!(rig.agents.sender.role.registered_sessions(), (0, 1));
    assert_eq!(
        rig.agents.receiver.role.guard_phase(11, rig.now),
        Some(Phase::Latched)
    );
    assert_eq!(send_one(&mut rig, 100), 0);
    assert!(pending(&rig));
}

/// INV-RST-6 (ADR-0086 section 7, domains 2 and 3), end to end: after the
/// authority's Closed STATE applies, a restarted authority that reuses
/// `envelope_seq` 0 and signs an Open STATE at the old epoch reopens
/// nothing: the epoch decides, not the sequence.
#[test]
fn inv_r4_an_authority_restart_reusing_sequences_opens_nothing() {
    use crate::remote_guard::Phase;

    let authority = guard_word(2, true);
    let (mut rig, b_at, signer) =
        guarded_over(&SharedMarks::default(), Some(Arc::clone(&authority)));
    let _slot = established(&mut rig);
    rig.until(true, |rig| {
        matches!(
            rig.agents.receiver.role.guard_phase(11, rig.now),
            Some(Phase::Open { .. })
        )
    });
    set_word(&authority, 3, false);
    inject_at_a(&mut rig, b_at, &signed_state(&signer, 3, 0));
    let refused = rig.agents.receiver.counters().guard_refused;
    inject_at_a(&mut rig, b_at, &signed_state(&signer, 2, 0));
    assert_eq!(rig.agents.receiver.counters().guard_refused, refused + 1);
    assert_eq!(
        rig.agents.receiver.role.guard_phase(11, rig.now),
        Some(Phase::Closed)
    );
    assert_eq!(send_one(&mut rig, 100), 0);
}

/// INV-GRD-13 (guards-and-abort.md, the sender gate), on the two-path
/// rig: a local guard close stops submission on both routes; nothing more
/// is committed from either path.
#[test]
fn inv_r4_a_close_stops_submission_on_every_route() {
    use karyos_sys::applied_epoch::AppliedEpoch;

    let word = Arc::new(karyos_client::HeapWords::zeroed(1));
    word.words()[0].store(
        karyos_sys::guard::created(),
        karyos_sys::sync::Ordering::Release,
    );
    assert_eq!(karyos_sys::guard::reopen(&word.words()[0], 1), Ok(2));
    let (mut rig, _a, _b) = Rig::routed(Setup {
        reliable: true,
        guard: Some(crate::agents::data::GuardSpec {
            word: Arc::clone(&word) as Arc<dyn karyos_client::SharedWords>,
            cell: Arc::new(AppliedEpoch::new()),
            epoch: 2,
            empty_since: None,
            rate: None,
            reserve: None,
            policy: None,
            frontier: Default::default(),
        }),
        ..Setup::default()
    });
    assert!(
        send_one(&mut rig, 1000) >= 1,
        "the routes are up and sending"
    );
    let _ = karyos_sys::guard::close(&word.words()[0]).unwrap();
    for _ in 0..20 {
        rig.round(true);
    }
    assert_eq!(send_one(&mut rig, 300), 0, "nothing on either route");
}

/// INV-VM-4 (ADR-0086 section 7; H8 R4), old queued controls after the
/// fence releases: an SM queued sealed under an image's domain 4 key
/// before a VM generation change is not sent after the class has
/// re-established under the fresh boot id.
#[test]
fn inv_r4_a_control_queued_before_a_generation_change_is_not_sent_after_release() {
    use crate::agents::control::ControlItem;
    use crate::wire_enc::VmGenerationWatch;
    use crate::wire_enc::vm_generation::InjectedSignal;
    use karyos_protocol::network::Control;

    let (mut rig, _b, _channel) = authenticated_rig();
    let (signal, injector) = InjectedSignal::new();
    rig.agents
        .receiver
        .role
        .enc_watch(VmGenerationWatch::new(Box::new(signal)));
    let (quiet, _quiet) = InjectedSignal::new();
    rig.agents
        .sender
        .role
        .auth_watch(VmGenerationWatch::new(Box::new(quiet)));
    let _slot = established(&mut rig);
    let old_party = rig
        .agents
        .sender
        .role
        .outbound(0)
        .unwrap()
        .sealer_party()
        .unwrap();
    let item = queued(&mut rig, |item| {
        matches!(
            item,
            ControlItem::Outgoing {
                control: Control::Status(_),
                seal: Some(_),
                ..
            }
        )
    });
    injector.change();
    rig.until(true, |rig| {
        rig.agents
            .sender
            .role
            .outbound(0)
            .and_then(|outbound| outbound.sealer_party())
            .is_some_and(|party| party != old_party)
    });
    assert!(!crate::wire_enc::vm_generation::quiesced(), "released");
    let before = rig.agents.sender.role.counters();
    rig.agents.receiver.role.post_to_sender(item);
    rig.round(true);
    let after = rig.agents.sender.role.counters();
    assert_eq!(after.sent, before.sent, "{after:?}");
    assert!(after.seal_failures > before.seal_failures, "{after:?}");
}

/// INV-VM-5 (ADR-0086 section 7), the authenticated class: when the
/// successor table refuses the sender's redraw, no authenticated identity
/// is drawn or used: no session sealer is installed, nothing is bound
/// again, and no CHALLENGE is posted, over many duties. The staged-DATA
/// and repair handoff is closed by the same withdrawn sealer (see
/// `a_held_fence_submits_nothing_authenticated`).
#[test]
fn inv_r4_a_refused_successor_draws_no_authenticated_identity() {
    use crate::wire_enc::VmGenerationWatch;
    use crate::wire_enc::vm_generation::{self, InjectedSignal, MAX_SUCCESSORS};

    let (mut rig, _b, _channel) = authenticated_rig();
    let _slot = established(&mut rig);
    let established_before = rig.agents.sender.role.session_counters().established;
    let challenges = rig.agents.receiver.role.posted_challenges().len();
    let (signal, injector) = InjectedSignal::new();
    let mut watch = VmGenerationWatch::new(Box::new(signal));
    injector.change();
    assert_eq!(watch.poll(0), 1);
    let generation = vm_generation::generation();
    for id in 1..=u64::try_from(MAX_SUCCESSORS).unwrap() {
        assert!(vm_generation::successor([id, 0xFEED], generation).is_some());
    }
    for _ in 0..1000 {
        rig.round(true);
    }
    assert!(vm_generation::quiesced());
    assert_eq!(
        rig.agents.sender.role.auth_state().1,
        0,
        "no live session sealer"
    );
    assert_eq!(
        rig.agents.sender.role.outbound(0).unwrap().sealer_party(),
        None
    );
    assert_eq!(
        rig.agents.sender.role.session_counters().established,
        established_before
    );
    assert_eq!(
        rig.agents.receiver.role.posted_challenges().len(),
        challenges
    );
}

/// INV-VM-4, the bare STATUS_CHALLENGE path while the fence is held: the
/// guard authority's answer is signed output under a key of the process,
/// so nothing it signs leaves while held.
#[test]
fn inv_r4_a_held_fence_sends_no_guard_status() {
    use crate::wire_enc::VmGenerationWatch;
    use crate::wire_enc::vm_generation::{self, InjectedSignal, MAX_SUCCESSORS};
    use karyos_protocol::network::Receiver;
    use karyos_protocol::network::authenticated::{AuthControl, StatusChallenge};

    let (mut rig, b_at, _signer) = guarded_over(&SharedMarks::default(), Some(guard_word(2, true)));
    rig.sender_stopped = true;
    rig.round(true);
    vm_generation::register();
    let (signal, injector) = InjectedSignal::new();
    let mut watch = VmGenerationWatch::new(Box::new(signal));
    injector.change();
    assert_eq!(watch.poll(0), 1);
    let generation = vm_generation::generation();
    for id in 1..=u64::try_from(MAX_SUCCESSORS).unwrap() {
        assert!(vm_generation::successor([id, 0xFEED], generation).is_some());
    }
    rig.round(true);
    let a_at = rig.endpoints.local_address(rig.publisher).unwrap();
    let mut bytes = vec![0u8; 256];
    let length = AuthControl::Challenge(StatusChallenge {
        authority_id: 10,
        guard_id: 11,
        receiver: Receiver {
            receiver_boot_id: [1, 2],
            receiver_id: 66,
        },
        nonce: [7, 8],
    })
    .encode(&mut bytes)
    .unwrap();
    bytes.truncate(length);
    let _ = b_at;
    let b = {
        // B is the authority's control endpoint in `guarded_over`.
        let mut found = None;
        for id in 0..8u32 {
            if rig.endpoints.local_address(EndpointId(id)) == Some(b_at) {
                found = Some(EndpointId(id));
            }
        }
        found.unwrap()
    };
    let raw_before = rig.agents.sender.role.counters().raw_sent;
    let receiver = &mut rig.agents.receiver;
    receiver
        .role
        .inject_datagram(&receiver.sessions, b, a_at, &bytes, rig.now);
    rig.sender_stopped = false;
    for _ in 0..20 {
        rig.round(true);
    }
    assert_eq!(
        rig.agents.sender.role.counters().raw_sent,
        raw_before,
        "no STATUS left while the fence is held: {:?}",
        rig.agents.receiver.counters()
    );
}

/// BUD-1 (ADR-0086 section 6), at the receiver's intake: a forged
/// SESSION_ABORT is charged to its source's verify budget before its
/// signature is checked, so the genuine abort that follows in the same
/// budget window is refused unverified; once the budget refills it
/// applies.
#[test]
fn inv_r4_signed_intake_charges_the_budget_before_verifying() {
    use karyos_protocol::network::authenticated::GUARD_CLOSED;

    let scope = crate::agents::roles::AbortScope {
        authority_id: 10,
        guard_id: 11,
    };
    let (mut rig, b, _slot) = abort_rig(Some(scope));
    let genuine = signed_abort(10, 11, GUARD_CLOSED);
    let mut forged = genuine.clone();
    let last = forged.len() - 1;
    forged[last] ^= 1;
    let source = rig.endpoints.local_address(rig.publisher).unwrap();
    rig.now += 300 * MS;
    rig.round(true);
    let before = rig.agents.receiver.counters();
    for bytes in [&forged, &forged, &forged, &forged, &genuine] {
        let receiver = &mut rig.agents.receiver;
        receiver
            .role
            .inject_datagram(&receiver.sessions, b, source, bytes, rig.now);
    }
    let after = rig.agents.receiver.counters();
    assert_eq!(after.abort_acks_sent, before.abort_acks_sent, "{after:?}");
    assert_eq!(after.signed_refused, before.signed_refused + 5, "{after:?}");
    let after = inject_abort(&mut rig, b, &genuine);
    assert_eq!(
        after.abort_acks_sent,
        before.abort_acks_sent + 1,
        "{after:?}"
    );
}

/// BUD-3 (ADR-0107 d1), at the authority's intake: a flood of valid bare
/// challenges is answered within the authority's budgets, never once per
/// challenge, and the rest are refused and counted.
#[test]
fn inv_r4_a_challenge_flood_is_answered_within_the_budget() {
    use karyos_protocol::network::Receiver;
    use karyos_protocol::network::authenticated::{AuthControl, StatusChallenge};

    let (mut rig, b_at, _signer) = guarded_over(&SharedMarks::default(), Some(guard_word(2, true)));
    rig.sender_stopped = true;
    rig.round(true);
    let a_at = rig.endpoints.local_address(rig.publisher).unwrap();
    let b = (0..8u32)
        .map(EndpointId)
        .find(|id| rig.endpoints.local_address(*id) == Some(b_at))
        .unwrap();
    let before = rig.agents.receiver.counters();
    for i in 0..200u64 {
        let mut bytes = vec![0u8; 256];
        let length = AuthControl::Challenge(StatusChallenge {
            authority_id: 10,
            guard_id: 11,
            receiver: Receiver {
                receiver_boot_id: [1, 2],
                receiver_id: 66,
            },
            nonce: [i, 8],
        })
        .encode(&mut bytes)
        .unwrap();
        bytes.truncate(length);
        let receiver = &mut rig.agents.receiver;
        receiver
            .role
            .inject_datagram(&receiver.sessions, b, a_at, &bytes, rig.now);
    }
    let after = rig.agents.receiver.counters();
    let sent = after.guard_statuses_sent - before.guard_statuses_sent;
    let refused = after.guard_challenges_refused - before.guard_challenges_refused;
    assert!((1..20).contains(&sent), "{after:?}");
    assert_eq!(sent + refused, 200, "{after:?}");
}

/// BUD-7 (ADR-0086 section 7), at the publisher's real RSP_SETUP intake:
/// a stream of verified CHALLENGEs naming ever new boot ids binds at most
/// the boot table's capacity, then is refused; nothing grows without
/// bound.
#[test]
fn inv_r4_new_boot_ids_are_bounded_by_the_boot_table() {
    use crate::wire_auth::{ENVELOPE_LEN, Proof, ProofKind};
    use karyos_protocol::network::{ChallengeBlock, Control, RspChallenge};

    let (mut rig, _b, _channel) = authenticated_rig();
    let (_, pairwise) = auth_keys(77);
    let _slot = established(&mut rig);
    rig.sender_stopped = true;
    let proof = Proof::new(
        ProofKind::RspSetup { receiver_id: 77 },
        alias(),
        Some(&pairwise),
        [&pairwise],
        pairwise.file_epoch,
    )
    .unwrap();
    let a = rig.publisher;
    let mut bound = 0;
    for i in 1..=1000u64 {
        let control = Control::Challenge(RspChallenge {
            alias: alias(),
            identity: identity(),
            challenge: ChallengeBlock {
                receiver_boot_id: [0xB00, i],
                nonce: [i, i],
            },
        });
        let mut bytes = vec![0u8; karyos_protocol::network::MAX_CONTROL_LENGTH + ENVELOPE_LEN];
        let length = control.encode(&mut bytes).unwrap();
        let length = proof.seal(&mut bytes, length).unwrap();
        bytes.truncate(length);
        if rig.agents.sender.role.open_sealed_for(a, &bytes).is_some() {
            bound += 1;
        }
    }
    assert!((1..1000).contains(&bound), "bound {bound} of 1000");
}

/// BUD-10 (ADR-0086 section 2), at the receiver's intake: a truncated
/// envelope and an oversized datagram for an authenticated image are
/// refused before any key work, counted, and move nothing.
#[test]
fn inv_r4_short_and_oversized_datagrams_are_refused_at_the_intake() {
    let (mut rig, b, _channel) = authenticated_rig();
    let _slot = established(&mut rig);
    rig.sender_stopped = true;
    let source = rig.endpoints.local_address(rig.publisher).unwrap();
    let mut short = vec![0u8; 24];
    short[6..8]
        .copy_from_slice(&karyos_protocol::protection::hmac_sha256::FRAME_TYPE.to_le_bytes());
    short[12..16].copy_from_slice(&alias().session_id.to_le_bytes());
    short[16..20].copy_from_slice(&alias().stream_id.to_le_bytes());
    let mut oversized = vec![0u8; 9000];
    oversized[..24].copy_from_slice(&short);
    let before = rig.agents.receiver.counters();
    for bytes in [&short, &oversized] {
        let receiver = &mut rig.agents.receiver;
        receiver
            .role
            .inject_datagram(&receiver.sessions, b, source, bytes, rig.now);
    }
    let after = rig.agents.receiver.counters();
    assert_eq!(after.data_committed, before.data_committed);
    assert_eq!(
        (after.auth_rejected + after.auth_unbound + after.decode_errors)
            - (before.auth_rejected + before.auth_unbound + before.decode_errors),
        2,
        "{after:?}"
    );
}

/// MP-1 (ADR-0035; H8 R4 missing property): a valid stale SETUP ANSWER
/// cannot regress an established image's join point: an ANSWER sealed
/// under the channel's SETUP proof, naming joins at 0 and a nonce the
/// receiver no longer holds, after DATA was delivered past 0, installs no
/// image and moves nothing; delivery goes on.
#[test]
fn inv_r4_a_stale_answer_cannot_regress_a_join_point() {
    use crate::wire_auth::{ENVELOPE_LEN, Proof, ProofKind};
    use karyos_protocol::network::{ChallengeBlock, Control, SetupAnswer};
    use karyos_sys::log_buffer::Role;

    let (mut rig, b, channel) = authenticated_rig();
    let slot = established(&mut rig);
    let (_conductor, mut subscriber) = image_subscriber(&rig, slot, 0, Role::Optional);
    assert!(send_one(&mut rig, 200) >= 1);
    while poll_message(&mut subscriber).is_some() {}
    let boot = rig.agents.receiver.role.boot_id();
    let answer = Control::SetupAnswer(SetupAnswer {
        alias: alias(),
        identity: identity(),
        term: term(65_536),
        challenge: ChallengeBlock {
            receiver_boot_id: boot,
            nonce: [0xDEAD, 0xBEEF],
        },
        joins: Lanes::new(&[0, 0]).unwrap(),
    });
    let proof = Proof::new(
        ProofKind::Setup,
        alias(),
        Some(&channel),
        [&channel],
        channel.file_epoch,
    )
    .unwrap();
    let mut bytes = vec![0u8; karyos_protocol::network::MAX_CONTROL_LENGTH + ENVELOPE_LEN];
    let length = answer.encode(&mut bytes).unwrap();
    let length = proof.seal(&mut bytes, length).unwrap();
    bytes.truncate(length);
    let source = rig.endpoints.local_address(rig.publisher).unwrap();
    let events = rig.events.len();
    let before = rig.agents.receiver.counters();
    let receiver = &mut rig.agents.receiver;
    receiver
        .role
        .inject_datagram(&receiver.sessions, b, source, &bytes, rig.now);
    assert!(send_one(&mut rig, 200) >= 1, "delivery goes on");
    let after = rig.agents.receiver.counters();
    assert_eq!(after.paths_bound, before.paths_bound);
    assert!(
        rig.events[events..]
            .iter()
            .all(|event| !matches!(event, ImageEvent::Installed { .. })),
        "no image reinstalled at the old join"
    );
    assert!(
        rig.agents.receiver.role.auth_rejections(slot).is_some(),
        "the same image"
    );
    assert_eq!(
        poll_message(&mut subscriber).map(|m| m.len()),
        Some(100),
        "nothing replayed from 0"
    );
}

/// MP-3 (ADR-0076; H8 R4 missing property), receiver-only restart: after
/// the receive side restarts (fresh boot id, images and caches lost, the
/// sender untouched), an old SETUP ANSWER for the previous boot id and
/// forward DATA sealed under the previous establishment are refused and
/// install nothing.
#[test]
fn inv_r4_after_a_receiver_only_restart_old_answers_and_forward_data_are_refused() {
    use crate::wire_auth::{ENVELOPE_LEN, Proof, ProofKind, Sealer};
    use karyos_protocol::network::{ChallengeBlock, Control, SetupAnswer};

    let (mut rig, b, channel) = authenticated_rig();
    let slot = established(&mut rig);
    let old_boot = rig.agents.receiver.role.receiver_of(slot).receiver_boot_id;
    let old_party = rig
        .agents
        .sender
        .role
        .outbound(0)
        .unwrap()
        .sealer_party()
        .unwrap();
    let crate::wire_auth::Party::Sender { nonce, .. } = old_party else {
        panic!("a sender party");
    };
    rig.sender_stopped = true;
    let now = rig.now;
    let receiver = &mut rig.agents.receiver;
    receiver.role.restart_receive_side(&receiver.sessions, now);
    assert_ne!(rig.agents.receiver.role.boot_id(), old_boot);
    rig.round(true);
    let source = rig.endpoints.local_address(rig.publisher).unwrap();
    let answer = Control::SetupAnswer(SetupAnswer {
        alias: alias(),
        identity: identity(),
        term: term(65_536),
        challenge: ChallengeBlock {
            receiver_boot_id: old_boot,
            nonce,
        },
        joins: Lanes::new(&[0, 0]).unwrap(),
    });
    let proof = Proof::new(
        ProofKind::Setup,
        alias(),
        Some(&channel),
        [&channel],
        channel.file_epoch,
    )
    .unwrap();
    let mut bytes = vec![0u8; karyos_protocol::network::MAX_CONTROL_LENGTH + ENVELOPE_LEN];
    let length = answer.encode(&mut bytes).unwrap();
    let length = proof.seal(&mut bytes, length).unwrap();
    bytes.truncate(length);
    let mut forward = Sealer::new(&channel, old_party, alias()).unwrap();
    let data = sealed(&mut forward, &stale_frame(9, 64, 32));
    let events = rig.events.len();
    let before = rig.agents.receiver.counters();
    for datagram in [&bytes, &data] {
        let receiver = &mut rig.agents.receiver;
        receiver
            .role
            .inject_datagram(&receiver.sessions, b, source, datagram, rig.now);
    }
    for _ in 0..50 {
        rig.round(true);
    }
    let after = rig.agents.receiver.counters();
    assert_eq!(after.data_committed, before.data_committed, "{after:?}");
    assert_eq!(rig.agents.receiver.role.auth_state().1, 0, "no image");
    assert!(
        rig.events[events..]
            .iter()
            .all(|event| !matches!(event, ImageEvent::Installed { .. }))
    );
}

/// RCV-1 (ADR-0086 section 7, domain 4), corrected statement: once the
/// publisher binds the restarted receiver's new boot id, an SM sealed
/// under the old boot id's domain 4 key fails at the publisher.
#[test]
fn inv_r4_old_sms_fail_once_the_publisher_binds_the_new_boot() {
    use crate::wire_auth::{ENVELOPE_LEN, Party, Sealer};
    use karyos_protocol::network::{Control, LaneStatus, Receiver, StatusMessage};

    let (mut rig, _b, _channel) = authenticated_rig();
    let (_, pairwise) = auth_keys(77);
    let slot = established(&mut rig);
    let old_boot = rig.agents.receiver.role.receiver_of(slot).receiver_boot_id;
    let old_party = rig
        .agents
        .sender
        .role
        .outbound(0)
        .unwrap()
        .sealer_party()
        .unwrap();
    let now = rig.now;
    let receiver = &mut rig.agents.receiver;
    receiver.role.restart_receive_side(&receiver.sessions, now);
    let rebound = (0..20_000).any(|_| {
        rig.round(true);
        rig.agents
            .sender
            .role
            .outbound(0)
            .and_then(|outbound| outbound.sealer_party())
            .is_some_and(|party| party != old_party)
    });
    assert!(rebound, "the publisher binds the new boot id");
    let status = Control::Status(StatusMessage {
        alias: alias(),
        identity: identity(),
        receiver: Receiver {
            receiver_boot_id: old_boot,
            receiver_id: 77,
        },
        group_tag: 0,
        lanes: Lanes::new(
            &[LaneStatus {
                consumption: 0,
                window: 65_536,
            }; 2],
        )
        .unwrap(),
    });
    let mut old = Sealer::new(
        &pairwise,
        Party::Receiver {
            identity: identity(),
            receiver_boot_id: old_boot,
            receiver_id: 77,
        },
        alias(),
    )
    .unwrap();
    let mut bytes = vec![0u8; karyos_protocol::network::MAX_CONTROL_LENGTH + ENVELOPE_LEN];
    let length = status.encode(&mut bytes).unwrap();
    let length = old.seal(&mut bytes, length).unwrap();
    bytes.truncate(length);
    let a = rig.publisher;
    assert!(rig.agents.sender.role.open_sealed_for(a, &bytes).is_none());
}

// ---------------------------------------------------------------------
// H8 round 5: the rows the round 4 review found evidence-insufficient,
// raised to proofs through both agents and their real intakes.
// ---------------------------------------------------------------------

/// A pairwise key file of receiver `receiver_id` (key `key_id`, publisher
/// 5) at file `epoch`, its secret `fill` repeated.
fn pairwise_file(
    key_id: u32,
    epoch: u32,
    receiver_id: u64,
    fill: char,
) -> crate::wire_keys::KeyFile {
    let secret: String = core::iter::repeat_n(fill, 64).collect();
    let text = format!(
        "format=karyos-wire-key-v1\nkey_id={key_id}\nfile_epoch={epoch}\npurpose=pairwise\nprofile_id=1\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-01-30T00:00:00Z\nsecret={secret}\nreceiver_id={receiver_id}\npublisher_id=5\n"
    );
    crate::wire_keys::parse(&format!("{key_id}-{epoch}.key"), text.as_bytes()).unwrap()
}

/// A CHALLENGE of receiver `receiver_id` naming `boot` and `nonce`,
/// sealed under `file`'s RSP_SETUP proof (domain 6).
fn rsp_challenge(
    file: &crate::wire_keys::KeyFile,
    receiver_id: u64,
    boot: [u64; 2],
    nonce: [u64; 2],
) -> Vec<u8> {
    use crate::wire_auth::{ENVELOPE_LEN, Proof, ProofKind};
    use karyos_protocol::network::{ChallengeBlock, Control, RspChallenge};

    let proof = Proof::new(
        ProofKind::RspSetup { receiver_id },
        alias(),
        Some(file),
        [file],
        file.file_epoch,
    )
    .unwrap();
    let control = Control::Challenge(RspChallenge {
        alias: alias(),
        identity: identity(),
        challenge: ChallengeBlock {
            receiver_boot_id: boot,
            nonce,
        },
    });
    let mut bytes = vec![0u8; karyos_protocol::network::MAX_CONTROL_LENGTH + ENVELOPE_LEN];
    let length = control.encode(&mut bytes).unwrap();
    let length = proof.seal(&mut bytes, length).unwrap();
    bytes.truncate(length);
    bytes
}

/// [`authenticated_rig`] whose publication verifies receiver 77's pairwise
/// file epochs 1 and 2 (2 current) and whose subscription holds epoch 2:
/// the rig, B, the channel key and both pairwise files.
fn lifecycle_rig() -> (
    Rig,
    EndpointId,
    crate::wire_keys::KeyFile,
    crate::wire_keys::KeyFile,
    crate::wire_keys::KeyFile,
) {
    use crate::agents::roles::publish_auth::PublicationAuth;
    use crate::agents::roles::receive_auth::SubscriptionAuth;

    let (mut rig, b) = Rig::new(Setup {
        auth: true,
        reliable: true,
        identity: Some(identity_77(0)),
        ..Setup::default()
    });
    let (channel, previous) = auth_keys(77);
    let current = pairwise_file(9, 2, 77, '4');
    let a = rig.publisher;
    rig.agents.receiver.role.authenticate_published(a, alias());
    rig.agents.receiver.role.authenticate_subscription(
        SubscriptionAuth::new(b, alias(), &channel, &current, 77).unwrap(),
    );
    rig.agents.sender.role.authenticate_publication(
        PublicationAuth::new(a, alias(), identity(), 2, &channel, &[&previous, &current]).unwrap(),
    );
    (rig, b, channel, previous, current)
}

/// The publication's installed sealer's party.
fn bound_party(rig: &Rig) -> Option<crate::wire_auth::Party> {
    rig.agents.sender.role.outbound(0).unwrap().sealer_party()
}

/// The publication's refusals of `reason`.
fn refused_for(rig: &Rig, reason: crate::agents::roles::receive_auth::AuthReason) -> u64 {
    let a = rig.publisher;
    rig.agents
        .sender
        .role
        .publication_rejections(a, alias())
        .unwrap()
        .get(reason)
}

/// The installed key and the establishment, as the sender holds them:
/// what no refused input may change.
fn key_state(rig: &Rig) -> (Option<crate::wire_auth::Party>, u64, u64) {
    (
        bound_party(rig),
        rig.agents.sender.role.counters().auth_sealers_installed,
        rig.agents.sender.role.session_counters().established,
    )
}

/// The image's replay refusals (duplicates and too old).
fn replays(rig: &Rig, slot: SlotRef) -> u64 {
    use crate::agents::roles::receive_auth::AuthReason;

    let rejections = rig.agents.receiver.role.auth_rejections(slot).unwrap();
    rejections.get(AuthReason::Duplicate) + rejections.get(AuthReason::TooOld)
}

/// Injects `bytes` at A from B, then runs `rounds` rounds (an RSP_SETUP
/// spaced past the per-destination rate).
fn challenge_a(rig: &mut Rig, from: SocketAddr, bytes: &[u8], rounds: usize) {
    rig.now += 300 * MS;
    inject_at_a(rig, from, bytes);
    for _ in 0..rounds {
        rig.round(true);
    }
}

/// Restarts the receive side and runs until the publisher binds a party
/// other than `old` or a boot table refusal is counted; returns whether
/// it bound.
fn restart_and_rebind(rig: &mut Rig, old: Option<crate::wire_auth::Party>) -> bool {
    use crate::agents::roles::receive_auth::AuthReason;

    let full = refused_for(rig, AuthReason::Full);
    let now = rig.now;
    let receiver = &mut rig.agents.receiver;
    receiver.role.restart_receive_side(&receiver.sessions, now);
    for _ in 0..20_000 {
        rig.round(true);
        if bound_party(rig).is_some() && bound_party(rig) != old {
            return true;
        }
        if refused_for(rig, AuthReason::Full) > full {
            return false;
        }
    }
    panic!(
        "neither bound nor refused: {:?}",
        rig.agents.sender.role.counters()
    );
}

/// INV-EST-6, EST-7, EST-8, EST-9, EST-10, RCV-2 and RCV-3 (ADR-0086
/// section 7; ADR-0118 (d)), one authenticated lifecycle through both
/// agents and the publisher's real RSP_SETUP intake:
///
/// - lost ANSWER: the receiver's CHALLENGE again, same boot id and nonce,
///   is answered again and re-derives nothing (no new sealer, the same
///   establishment);
/// - the bound boot id under another nonce (`Rebind`), a CHALLENGE that
///   verifies only under the previous pairwise file epoch
///   (`PreviousEpoch`) and another receiver's (`OtherReceiver`) are
///   refused; none moves the installed key, the establishment or the
///   image's replay state, and delivery goes on;
/// - receiver replacement: a restarted receiver binds only through its
///   fresh challenge, and the publisher retires the old boot id: the old
///   CHALLENGE replayed is refused (`Retired`);
/// - over capacity: restarts past the retired-boot table are refused
///   (`Full`, fail closed), and the last binding stays.
#[test]
fn inv_r5_an_authenticated_lifecycle_refuses_every_stale_or_foreign_response() {
    use crate::agents::roles::receive_auth::AuthReason;
    use crate::wire_auth::{MAX_RETIRED_BOOTS, Party};

    let (mut rig, b, _channel, previous, current) = lifecycle_rig();
    let slot = established(&mut rig);
    let b_at = rig.endpoints.local_address(b).unwrap();
    assert!(send_one(&mut rig, 200) >= 1);
    let Some(Party::Sender {
        receiver_boot_id: boot,
        nonce,
        ..
    }) = bound_party(&rig)
    else {
        panic!("bound");
    };
    let installed = |rig: &Rig| {
        rig.events
            .iter()
            .filter(|event| matches!(event, ImageEvent::Installed { .. }))
            .count()
    };
    let (state, images, replayed) = (key_state(&rig), installed(&rig), replays(&rig, slot));

    // Lost ANSWER: the same CHALLENGE again is answered, nothing derived.
    let answers = rig.agents.sender.role.session_counters().answers;
    let original = rsp_challenge(&current, 77, boot, nonce);
    challenge_a(&mut rig, b_at, &original, 50);
    assert!(
        rig.agents.sender.role.session_counters().answers > answers,
        "the ANSWER is sent again: {:?}",
        rig.agents.sender.role.session_counters()
    );
    assert_eq!(key_state(&rig), state, "the same key and establishment");

    // Refused inputs move nothing.
    let rejected = rig.agents.sender.role.counters().auth_rejected;
    let other = pairwise_file(8, 1, 78, '5');
    for (bytes, reason) in [
        (
            rsp_challenge(&current, 77, boot, [nonce[0] ^ 1, nonce[1]]),
            AuthReason::Rebind,
        ),
        (
            rsp_challenge(&previous, 77, [0xE0, 1], [1, 1]),
            AuthReason::PreviousEpoch,
        ),
        (
            rsp_challenge(&other, 78, [0xE1, 1], [2, 2]),
            AuthReason::OtherReceiver,
        ),
    ] {
        let before = refused_for(&rig, reason);
        challenge_a(&mut rig, b_at, &bytes, 20);
        assert_eq!(
            refused_for(&rig, reason),
            before + 1,
            "{reason:?}: {:?}",
            rig.agents
                .sender
                .role
                .publication_rejections(rig.publisher, alias())
        );
        assert_eq!(key_state(&rig), state, "{reason:?} moved the key");
    }
    assert_eq!(
        rig.agents.sender.role.counters().auth_rejected,
        rejected + 3
    );
    assert_eq!(
        rig.agents.sender.role.counters().auth_other_receiver,
        1,
        "counted by its own reason"
    );
    assert!(send_one(&mut rig, 200) >= 1, "delivery goes on");
    assert_eq!(key_state(&rig), state);
    assert_eq!(installed(&rig), images, "no image installed again");
    assert_eq!(replays(&rig, slot), replayed, "the replay window kept");

    // Receiver replacement: a fresh challenge binds the new boot id; the
    // old one is retired.
    let old = bound_party(&rig);
    assert!(restart_and_rebind(&mut rig, old));
    let Some(Party::Sender {
        receiver_boot_id: new_boot,
        ..
    }) = bound_party(&rig)
    else {
        panic!("rebound");
    };
    assert_eq!(new_boot, rig.agents.receiver.role.boot_id());
    assert_ne!(new_boot, boot);
    // The new establishment completes (its first SM) before the replay.
    for _ in 0..200 {
        rig.round(true);
    }
    let state = key_state(&rig);
    let retired = refused_for(&rig, AuthReason::Retired);
    challenge_a(&mut rig, b_at, &original, 20);
    assert_eq!(
        refused_for(&rig, AuthReason::Retired),
        retired + 1,
        "{:?} {:?}",
        rig.agents
            .sender
            .role
            .publication_rejections(rig.publisher, alias()),
        rig.agents.receiver.counters()
    );
    assert_eq!(key_state(&rig), state, "the retired boot id binds nothing");

    // Over capacity: the retired-boot table holds MAX_RETIRED_BOOTS; the
    // restart after that is refused and the last binding stays.
    let mut rebinds = 1;
    loop {
        let last = bound_party(&rig);
        if !restart_and_rebind(&mut rig, last) {
            assert_eq!(bound_party(&rig), last, "the last binding stays");
            break;
        }
        rebinds += 1;
        assert!(rebinds <= MAX_RETIRED_BOOTS, "never refused");
    }
    assert_eq!(rebinds, MAX_RETIRED_BOOTS, "refused exactly when full");
    assert!(refused_for(&rig, AuthReason::Full) >= 1);
}

/// The key files of the store rollover tests: the rig's epoch 1 channel
/// and pairwise files, their epoch 2 successors, and the authority's
/// signing file and its successor.
const C1: &str = "format=karyos-wire-key-v1\nkey_id=3\nfile_epoch=1\npurpose=channel\nprofile_id=1\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-01-30T00:00:00Z\nsecret=1111111111111111111111111111111111111111111111111111111111111111\nchannel_id=7\nstream_id=6\n";
const C2: &str = "format=karyos-wire-key-v1\nkey_id=3\nfile_epoch=2\npurpose=channel\nprofile_id=1\nnot_before=2026-11-20T00:00:00Z\nnot_after=2027-02-17T00:00:00Z\nsecret=5555555555555555555555555555555555555555555555555555555555555555\nchannel_id=7\nstream_id=6\n";
const P1: &str = "format=karyos-wire-key-v1\nkey_id=9\nfile_epoch=1\npurpose=pairwise\nprofile_id=1\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-01-30T00:00:00Z\nsecret=2222222222222222222222222222222222222222222222222222222222222222\nreceiver_id=77\npublisher_id=5\n";
const P2: &str = "format=karyos-wire-key-v1\nkey_id=9\nfile_epoch=2\npurpose=pairwise\nprofile_id=1\nnot_before=2026-11-20T00:00:00Z\nnot_after=2027-02-17T00:00:00Z\nsecret=4444444444444444444444444444444444444444444444444444444444444444\nreceiver_id=77\npublisher_id=5\n";
const A1: &str = "format=karyos-wire-key-v1\nkey_id=10\nfile_epoch=1\npurpose=authority-signing\nprofile_id=4\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-04-30T00:00:00Z\nsecret=0909090909090909090909090909090909090909090909090909090909090909\nauthority_id=10\nguards=11,12\nabort=true\n";
const A2: &str = "format=karyos-wire-key-v1\nkey_id=10\nfile_epoch=2\npurpose=authority-signing\nprofile_id=4\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-04-30T00:00:00Z\nsecret=0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a\nauthority_id=10\nguards=11,12\nabort=true\n";

/// The driver's one key store over `files`, its key directory kept.
fn store_of(files: &[(&str, &str)]) -> (crate::net::wire::WireKeys, MemDir) {
    use crate::wire_keys::store::{Files as _, KeyStore};

    let (keys_dir, state_dir) = (MemDir::default(), MemDir::default());
    for (name, text) in files {
        keys_dir.put(name, text);
    }
    KeyStore::<MemDir, MemDir>::initialise(&state_dir, zeroize::Zeroizing::new([7; 32])).unwrap();
    let _ = state_dir.names().unwrap();
    let (wire, _) = crate::net::wire::WireKeys::start(
        Box::new(keys_dir.clone()),
        Box::new(state_dir),
        Some(rotation_wall),
    )
    .unwrap();
    (wire, keys_dir)
}

/// INV-RLD-2 and ROT-3 (ADR-0086 section 7), a real store rollover across
/// both roles: the driver's key store admits epoch 2 of the channel and
/// pairwise keys and its view is applied to both agents, as the conductor
/// does. The establishment is unchanged (the same party, no new sealer,
/// no new image); the publication's domain 1 sealer and the image's
/// domain 4 sealer are retagged to epoch 2 and DATA and SMs keep flowing
/// in both directions with nothing refused; a duplicate under the
/// retained epoch 1 is still refused after the rollover (its window was
/// kept, not reset).
#[test]
fn inv_r5_a_store_rollover_keeps_the_establishment_and_its_replay_windows() {
    use crate::wire_auth::{KeySet as _, Sealer};

    let (mut wire, keys_dir) = store_of(&[("3-1.key", C1), ("9-1.key", P1)]);
    let (mut rig, b, channel) = authenticated_rig();
    let slot = established(&mut rig);
    reload_and_apply(&mut rig, &mut wire, 0);
    assert!(send_one(&mut rig, 200) >= 1);
    let party = bound_party(&rig).unwrap();
    let source = rig.endpoints.local_address(rig.publisher).unwrap();
    let duplicate = || {
        let mut replay = Sealer::new(&channel, party, alias()).unwrap();
        sealed(&mut replay, &stale_frame(9, 0, 32))
    };
    let inject = |rig: &mut Rig, bytes: &[u8]| {
        let receiver = &mut rig.agents.receiver;
        receiver
            .role
            .inject_datagram(&receiver.sessions, b, source, bytes, rig.now);
    };
    let replayed = replays(&rig, slot);
    inject(&mut rig, &duplicate());
    assert_eq!(
        replays(&rig, slot),
        replayed + 1,
        "a duplicate under epoch 1"
    );
    assert_eq!(
        rig.agents.receiver.role.image_sealer_key(slot),
        Some((9, 1))
    );
    let state = key_state(&rig);
    let images = rig.events.len();
    let refused = (
        rig.agents.sender.role.counters().auth_rejected,
        rig.agents.receiver.counters().auth_rejected,
    );

    keys_dir.put("3-2.key", C2);
    keys_dir.put("9-2.key", P2);
    let reload_s = u64::try_from(crate::wire_keys::store::RELOAD_INTERVAL_S).unwrap();
    reload_and_apply(&mut rig, &mut wire, reload_s);
    {
        let view = wire.view();
        assert_eq!(view.current_epoch(3), Some(2), "the store admitted epoch 2");
        assert_eq!(view.current_epoch(9), Some(2));
        assert_eq!(view.signing(3).map(|file| file.file_epoch), Some(2));
    }
    let sms = rig.agents.receiver.counters().sm_sent;
    for _ in 0..3 {
        assert!(
            send_one(&mut rig, 200) >= 1,
            "forward DATA under epoch 2: {:?} {:?} {:?} {:?} {:?}",
            rig.agents.sender.role.counters(),
            rig.agents.receiver.counters(),
            rig.agents.receiver.role.auth_rejections(slot),
            rig.agents
                .sender
                .role
                .publication_rejections(rig.publisher, alias()),
            rig.agents.sender.role.outbound(0).unwrap().sealer_keys()
        );
    }
    assert!(
        rig.agents.receiver.counters().sm_sent > sms,
        "SMs flow back"
    );
    assert_eq!(
        rig.agents
            .sender
            .role
            .outbound(0)
            .unwrap()
            .sealer_keys()
            .map(|keys| keys.1),
        Some((3, 2)),
        "DATA retagged to epoch 2"
    );
    assert_eq!(
        rig.agents.receiver.role.image_sealer_key(slot),
        Some((9, 2)),
        "controls retagged to epoch 2"
    );
    assert_eq!(key_state(&rig), state, "the same establishment");
    assert!(
        rig.events[images..]
            .iter()
            .all(|event| !matches!(event, ImageEvent::Installed { .. }))
    );
    assert_eq!(
        (
            rig.agents.sender.role.counters().auth_rejected,
            rig.agents.receiver.counters().auth_rejected,
        ),
        refused,
        "nothing refused either way"
    );
    let replayed = replays(&rig, slot);
    inject(&mut rig, &duplicate());
    assert_eq!(
        replays(&rig, slot),
        replayed + 1,
        "the retained epoch's window was kept"
    );
}

/// INV-REV-4 (ADR-0118 (a)), the outbound side end to end: the
/// publication's abort signer is pinned to the authority file epoch it
/// was admitted under. The store revokes that epoch while its successor
/// of the same `key_id` signs, and the view is applied to both agents.
/// A guard close then sends no SESSION_ABORT at all (the receiver applies
/// and refuses none), and ends as a terminal interruption, reported once.
#[test]
fn inv_r5_a_revoked_abort_epoch_sends_no_abort_though_a_successor_signs() {
    use crate::agents::roles::publish_auth::AbortAuthority;
    use crate::authority::Ed25519Signer;

    let (mut wire, keys_dir) = store_of(&[("3-1.key", C1), ("9-1.key", P1), ("10-1.key", A1)]);
    let (mut rig, word) = guarded_abort_rig(true, false);
    let a = rig.publisher;
    let mut abort = AbortAuthority::new(Ed25519Signer::from_seed(&[9; 32]), 10, 10);
    abort.file_epoch = Some(1);
    rig.agents
        .sender
        .role
        .set_abort_authority(a, alias(), abort);
    reload_and_apply(&mut rig, &mut wire, 0);
    assert!(send_one(&mut rig, 200) >= 1);
    keys_dir.put("10-2.key", A2);
    keys_dir.put("revoked", "10-1\n");
    let reload_s = u64::try_from(crate::wire_keys::store::RELOAD_INTERVAL_S).unwrap();
    reload_and_apply(&mut rig, &mut wire, reload_s);
    {
        use crate::wire_auth::KeySet as _;
        assert_eq!(wire.view().signing(10).map(|file| file.file_epoch), Some(2));
    }
    let signed_refused = rig.agents.receiver.counters().signed_refused;
    close_guard(&mut rig, &word);
    for _ in 0..100 {
        rig.round(true);
    }
    let sender = rig.agents.sender.role.counters();
    assert_eq!(
        (sender.aborts_sent, sender.aborts_interrupted),
        (0, 1),
        "{sender:?}"
    );
    let receiver = rig.agents.receiver.counters();
    assert_eq!(receiver.images_closed_aborted, 0, "{receiver:?}");
    assert_eq!(receiver.signed_refused, signed_refused, "none sent at all");
    assert_eq!(abort_ends(&rig), vec![true]);
}

/// INV-SS-7 (ADR-0086 section 6; manifest 4.3), at the role boundary: the
/// publication's domain 1 sealer and the image's domain 4 sealer are
/// moved to just below 75% of the sequence space (2^47 seals are not run;
/// the sealers are the agents' own). Both cross into in-band epoch 1
/// under the same establishment while DATA and SMs keep flowing, nothing
/// refused by either intake. At the usage limit with no in-band epoch
/// left, the publication seals nothing more: nothing is delivered, and
/// nothing goes bare.
#[test]
fn inv_r5_both_roles_move_epoch_at_75_percent_and_stop_at_the_limit() {
    use crate::wire_auth::{ROTATE_AT, TAG_CAP};

    let (mut rig, _b, _channel) = authenticated_rig();
    let slot = established(&mut rig);
    assert!(send_one(&mut rig, 200) >= 1);
    let state = key_state(&rig);
    rig.agents
        .sender
        .role
        .outbound_mut(0)
        .unwrap()
        .jump_sealer(0, ROTATE_AT - 2);
    let image = rig.agents.receiver.role.image_sealer(slot).unwrap();
    image.jump_to(0, ROTATE_AT - 2);
    let refused = (
        rig.agents.sender.role.counters().auth_rejected,
        rig.agents.receiver.counters().auth_rejected,
    );
    let sms = rig.agents.receiver.counters().sm_sent;
    for _ in 0..5 {
        assert!(send_one(&mut rig, 100) >= 1, "DATA across the move");
    }
    assert!(rig.agents.receiver.counters().sm_sent > sms + 2);
    assert_eq!(
        rig.agents
            .sender
            .role
            .outbound(0)
            .unwrap()
            .sealer_keys()
            .map(|keys| keys.0),
        Some(1),
        "the sender moved epoch"
    );
    assert_eq!(image.party_epoch_now(), Some(1), "the receiver moved epoch");
    assert_eq!(
        (
            rig.agents.sender.role.counters().auth_rejected,
            rig.agents.receiver.counters().auth_rejected,
        ),
        refused,
        "every datagram across the move verified"
    );
    assert_eq!(key_state(&rig), state, "the same establishment");
    // The limit: no in-band epoch left.
    rig.agents
        .sender
        .role
        .outbound_mut(0)
        .unwrap()
        .jump_sealer(u8::MAX, TAG_CAP);
    let bare = rig.agents.receiver.counters().auth_bare;
    assert_eq!(send_one(&mut rig, 200), 0, "nothing sealed at the limit");
    assert_eq!(rig.agents.receiver.counters().auth_bare, bare);
}

/// One rig round, as [`Rig::round`], with the agents' duties and the
/// endpoints' I/O counted for allocations; the conductors and the image
/// table, which the test harness drives, are not.
fn counted_round(rig: &mut Rig) -> [u64; 3] {
    rig.now += MS;
    VIRTUAL_NOW.with(|now| now.set(rig.now));
    for log in [&mut rig.log, &mut rig.second].into_iter().flatten() {
        for conductor in &mut log.conductors {
            let _ = conductor.duty_cycle().unwrap();
        }
    }
    let now = rig.now;
    let (_, sender) = karyos_sys::alloc_count::count(|| rig.agents.sender.do_work(now).unwrap());
    let (_, receiver) =
        karyos_sys::alloc_count::count(|| rig.agents.receiver.do_work(now).unwrap());
    let ((), io) =
        karyos_sys::alloc_count::count(|| rig.endpoints.poll(&rig.links, now, |_| {}, |_| {}));
    let events = &mut rig.events;
    rig.images
        .poll(&rig.links.sessions, &mut LaneSource::heap(), |image| {
            events.push(image);
        });
    std::thread::sleep(Duration::from_micros(200));
    [sender, receiver, io]
}

/// INV-SS-10 and BUD-9 (ADR-0086 sections 5 and 6), around the agents'
/// established staging and intake: with an authenticated session in
/// steady state, the duties that read, seal and send DATA, receive, verify
/// and commit it, and seal and verify the SMs back, allocate nothing; nor
/// does the receiver's signed intake under a burst of signed controls
/// (its digest cache and budgets are preallocated).
#[test]
fn inv_r5_established_staging_and_intake_allocate_nothing() {
    use karyos_protocol::network::authenticated::GUARD_CLOSED;
    use karyos_sys::log_buffer::AppendOptions;

    let scope = crate::agents::roles::AbortScope {
        authority_id: 10,
        guard_id: 12,
    };
    let (mut rig, b, _slot) = abort_rig(Some(scope));
    for _ in 0..3 {
        assert!(send_one(&mut rig, 200) >= 1);
    }
    // The role's test-only logs grow as DATA arrives: reserved here, so
    // only the production path is counted.
    rig.agents.receiver.role.reserve_test_logs();
    let committed = rig.agents.receiver.counters().data_committed;
    let mut allocations = [0; 3];
    let mut first = None;
    for i in 0..200u32 {
        if i % 10 == 0 {
            let _ = rig.log.as_mut().unwrap().publications[0]
                .append(&[4; 300], AppendOptions::default())
                .unwrap();
        }
        let counted = counted_round(&mut rig);
        if first.is_none() && counted.iter().any(|n| *n > 0) {
            first = Some((i, counted));
        }
        for (total, n) in allocations.iter_mut().zip(counted) {
            *total += n;
        }
    }
    assert!(
        rig.agents.receiver.counters().data_committed > committed,
        "DATA flowed while counted"
    );
    assert_eq!(
        allocations, [0; 3],
        "sender, receiver, I/O allocated; first at {first:?}"
    );
    // A burst of signed controls at the receiver's intake: verified,
    // refused or cached, without allocating.
    let source = rig.endpoints.local_address(rig.publisher).unwrap();
    let genuine = signed_abort(10, 11, GUARD_CLOSED);
    let mut forged = genuine.clone();
    let last = forged.len() - 1;
    forged[last] ^= 1;
    let before = rig.agents.receiver.counters().signed_refused;
    let ((), allocations) = karyos_sys::alloc_count::count(|| {
        for i in 0..64u16 {
            let receiver = &mut rig.agents.receiver;
            let from = SocketAddr::new(source.ip(), 20_000 + i);
            let bytes = if i % 2 == 0 { &forged } else { &genuine };
            receiver
                .role
                .inject_datagram(&receiver.sessions, b, from, bytes, rig.now);
        }
    });
    assert!(rig.agents.receiver.counters().signed_refused > before);
    assert_eq!(allocations, 0, "the signed intake allocated");
}

/// INV-SS-11 (ADR-0086 section 5), through both agents on loopback: the
/// largest DATA batches (many small messages packed into one datagram,
/// and messages fragmented at the full frame budget) and every control
/// the receiver sends back are sealed within the channel MTU; the batches
/// do reach it, envelope included. The largest control of the profile
/// sealed fits the smallest MTU.
#[test]
fn inv_r5_full_batches_and_the_largest_controls_fit_the_mtu() {
    use crate::wire_auth::ENVELOPE_LEN;
    use karyos_sys::log_buffer::AppendOptions;

    let mtu = usize::try_from(term(65_536).mtu).unwrap();
    let (mut rig, b, _channel) = authenticated_rig();
    let _slot = established(&mut rig);
    let a = rig.publisher;
    rig.agents.receiver.role.drop_data(&[3, 7]);
    for size in [40, 24, 200] {
        for _ in 0..60 {
            let _ = rig.log.as_mut().unwrap().publications[0]
                .append(&vec![1; size], AppendOptions::default())
                .unwrap();
        }
        for _ in 0..200 {
            rig.round(true);
        }
    }
    for _ in 0..4 {
        let _ = rig.log.as_mut().unwrap().publications[0]
            .append(&[2; 6000], AppendOptions::default())
            .unwrap();
        for _ in 0..200 {
            rig.round(true);
        }
    }
    let data = rig.agents.receiver.role.largest_in(b);
    let controls = rig.agents.receiver.role.largest_in(a);
    assert!(data <= mtu, "DATA {data} over the MTU {mtu}");
    assert!(data + 2 * 32 > mtu, "a full batch reaches the MTU: {data}");
    assert!(controls <= mtu, "a control {controls} over the MTU {mtu}");
    assert!(controls > ENVELOPE_LEN, "controls were sealed and sent");
    let smallest = usize::try_from(karyos_protocol::network::MIN_MTU).unwrap();
    assert!(karyos_protocol::network::MAX_CONTROL_LENGTH + ENVELOPE_LEN <= smallest);
}

/// The missing property (ADR-0035; H8 R4), after a sender restart, and
/// INV-BUD-6 at the receiver's real intake: the publisher's driver stops
/// and its image retires at the liveness timeout. DATA sealed under the
/// prior identity's session key, at a sequence the image never saw, is
/// then refused as unbound: no commit, no image, no SOLICIT or CHALLENGE,
/// and nothing else moves but its counter (no MAC work for no binding).
#[test]
fn inv_r5_stale_data_after_a_sender_restart_is_refused_and_costs_nothing() {
    use crate::wire_auth::Sealer;

    let (mut rig, b, channel) = authenticated_rig();
    let slot = established(&mut rig);
    assert!(send_one(&mut rig, 200) >= 1);
    let party = bound_party(&rig).unwrap();
    rig.sender_stopped = true;
    for _ in 0..30 {
        rig.now += 1_000 * MS;
        rig.round(true);
        if !rig.agents.receiver.role.has_image(slot) {
            break;
        }
    }
    assert!(!rig.agents.receiver.role.has_image(slot), "retired");
    for _ in 0..50 {
        rig.round(true);
    }
    let mut old = Sealer::new(&channel, party, alias()).unwrap();
    old.jump_to(0, 1 << 20);
    let stale = sealed(&mut old, &stale_frame(9, 64, 32));
    let source = rig.endpoints.local_address(rig.publisher).unwrap();
    let images = rig.events.len();
    let challenges = rig.agents.receiver.role.posted_challenges().len();
    let before = rig.agents.receiver.counters();
    let receiver = &mut rig.agents.receiver;
    receiver
        .role
        .inject_datagram(&receiver.sessions, b, source, &stale, rig.now);
    only_changed(
        before,
        rig.agents.receiver.counters(),
        |c| &mut c.auth_unbound,
        1,
    );
    for _ in 0..50 {
        rig.round(true);
    }
    assert_eq!(
        rig.agents.receiver.role.posted_challenges().len(),
        challenges,
        "no CHALLENGE or SOLICIT"
    );
    assert!(
        rig.events[images..]
            .iter()
            .all(|event| !matches!(event, ImageEvent::Installed { .. }))
    );
}

/// INV-BUD-2 (H8 R1 #6), at the receiver's signed intake: a flood of
/// forged SESSION_ABORTs from ever new unknown sources, every duty cycle,
/// spends only the shared unknown budget. The configured peer's genuine
/// abort, arriving behind the flood in the same cycle, is still verified
/// from its reserved bucket and applies.
#[test]
fn inv_r5_a_flood_of_unknown_sources_does_not_starve_the_configured_peer() {
    use karyos_protocol::network::authenticated::GUARD_CLOSED;

    let scope = crate::agents::roles::AbortScope {
        authority_id: 10,
        guard_id: 11,
    };
    let (mut rig, b, _slot) = abort_rig(Some(scope));
    let genuine = signed_abort(10, 11, GUARD_CLOSED);
    let mut forged = genuine.clone();
    let last = forged.len() - 1;
    forged[last] ^= 1;
    let source = rig.endpoints.local_address(rig.publisher).unwrap();
    rig.now += 300 * MS;
    rig.round(true);
    let before = rig.agents.receiver.counters();
    let flood = |rig: &mut Rig, round: u16| {
        for i in 0..20u16 {
            let host = round * 20 + i;
            let from = SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    10,
                    1,
                    u8::try_from(host / 200).unwrap(),
                    u8::try_from(host % 200).unwrap(),
                )),
                30_000 + host,
            );
            let receiver = &mut rig.agents.receiver;
            receiver
                .role
                .inject_datagram(&receiver.sessions, b, from, &forged, rig.now);
        }
    };
    // A sustained flood, every duty cycle, from ever new sources.
    for round in 0..40u16 {
        rig.round(true);
        flood(&mut rig, round);
    }
    let flooded = rig.agents.receiver.counters();
    assert_eq!(flooded.abort_acks_sent, before.abort_acks_sent);
    assert_eq!(flooded.signed_refused, before.signed_refused + 800);
    // The flood goes on, ahead of the genuine abort in each cycle: the
    // abort is served within a few cycles (a cycle verifies at most
    // `VERIFY_PER_CYCLE`), never starved.
    let mut served = None;
    for cycle in 0..5u16 {
        rig.round(true);
        flood(&mut rig, 41 + cycle);
        let receiver = &mut rig.agents.receiver;
        receiver
            .role
            .inject_datagram(&receiver.sessions, b, source, &genuine, rig.now);
        let now = rig.agents.receiver.counters();
        if now.abort_acks_sent > before.abort_acks_sent {
            served = Some(cycle);
            break;
        }
    }
    let after = rig.agents.receiver.counters();
    assert!(served.is_some(), "starved under load: {after:?}");
}

/// INV-VM-4 (ADR-0086 section 7; R3-6), the final backend handoff: a lost
/// DATA datagram's NAK is queued for the sender, and more DATA is
/// appended, before a VM generation change whose successor is refused.
/// With the fence held, neither the repair nor the staged DATA is sealed
/// and handed to the TX backend: nothing more leaves the publication and
/// nothing more is committed.
#[test]
fn inv_r5_a_held_fence_hands_no_repair_or_staged_data_to_the_backend() {
    use karyos_sys::log_buffer::AppendOptions;

    use crate::wire_enc::VmGenerationWatch;
    use crate::wire_enc::vm_generation::{self, InjectedSignal, MAX_SUCCESSORS};

    let (mut rig, _b, _channel) = authenticated_rig();
    let _slot = established(&mut rig);
    assert!(send_one(&mut rig, 200) >= 1);
    rig.agents.receiver.role.drop_data(&[1]);
    for i in 0..4u8 {
        let _ = rig.log.as_mut().unwrap().publications[0]
            .append(&[i; 900], AppendOptions::default())
            .unwrap();
    }
    for _ in 0..3 {
        rig.round(true);
    }
    // The sender stops before the repair: the receiver's NAKs queue for it.
    rig.sender_stopped = true;
    let naks = rig.agents.receiver.counters().naks;
    for _ in 0..100 {
        rig.round(true);
    }
    assert!(
        rig.agents.receiver.counters().naks > naks,
        "a repair is asked"
    );
    for i in 0..4u8 {
        let _ = rig.log.as_mut().unwrap().publications[0]
            .append(&[i; 300], AppendOptions::default())
            .unwrap();
    }
    let (signal, injector) = InjectedSignal::new();
    let mut watch = VmGenerationWatch::new(Box::new(signal));
    injector.change();
    assert_eq!(watch.poll(0), 1);
    let generation = vm_generation::generation();
    for id in 1..=u64::try_from(MAX_SUCCESSORS).unwrap() {
        assert!(vm_generation::successor([id, 0xFEED], generation).is_some());
    }
    let before = rig.agents.sender.role.counters();
    let committed = rig.agents.receiver.counters().data_committed;
    rig.sender_stopped = false;
    for _ in 0..500 {
        rig.round(true);
    }
    assert!(vm_generation::quiesced(), "the fence stays held");
    let after = rig.agents.sender.role.counters();
    assert_eq!(
        (after.sent, after.raw_sent),
        (before.sent, before.raw_sent),
        "{after:?}"
    );
    assert_eq!(rig.agents.receiver.counters().data_committed, committed);
}

/// karyos#649, ADR-0076 clause 1 (SPEC §13 "Receiver restart freshness"),
/// the authenticated unicast case: after a receiver-only restart that
/// rebinds through its fresh challenge, old DATA with a valid MAC under the
/// previous establishment fails authentication at the new binding: it is
/// refused, commits nothing and the new image stays.
#[test]
fn inv_649_old_data_after_a_receiver_restart_fails_its_mac_at_the_new_binding() {
    use crate::wire_auth::Sealer;

    let (mut rig, b, channel) = authenticated_rig();
    let _slot = established(&mut rig);
    assert!(send_one(&mut rig, 100) >= 1);
    let old = bound_party(&rig);
    let old_party = old.unwrap();
    assert!(restart_and_rebind(&mut rig, old), "rebound");
    assert!(
        send_one(&mut rig, 100) >= 1,
        "the new establishment delivers"
    );
    assert_ne!(bound_party(&rig), old, "a new establishment");
    let source = rig.endpoints.local_address(rig.publisher).unwrap();
    // DATA sealed under the old establishment, its MAC valid there.
    let mut old_sealer = Sealer::new(&channel, old_party, alias()).unwrap();
    old_sealer.jump_to(0, 1 << 20);
    let data = sealed(&mut old_sealer, &stale_frame(9, 64, 32));
    let before = rig.agents.receiver.counters();
    let receiver = &mut rig.agents.receiver;
    receiver
        .role
        .inject_datagram(&receiver.sessions, b, source, &data, rig.now);
    for _ in 0..20 {
        rig.round(true);
    }
    let after = rig.agents.receiver.counters();
    assert_eq!(after.auth_rejected, before.auth_rejected + 1, "{after:?}");
    assert_eq!(after.data_committed, before.data_committed);
    assert!(send_one(&mut rig, 100) >= 1, "the new image stays");
}
