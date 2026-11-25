// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::net::SocketAddr;

use karyos_protocol::network::authenticated::{AuthControl, GuardState, GuardWord, SessionAbort};
use karyos_protocol::network::{Alias, Identity};
use karyos_protocol::protection::signed::{SignedBinding, SignedDomain, seal_signed};

use super::*;
use crate::authority::Ed25519Signer;

const ALIAS: Alias = Alias {
    session_id: 5,
    stream_id: 6,
};

const SECOND: u64 = 1_000_000_000;

fn signer(fill: u8) -> Ed25519Signer {
    Ed25519Signer::from_seed(&[fill; 32])
}

fn authority(abort: bool) -> Authority {
    Authority::of(10, signer(9).verifier(), 10, &[11, 12], abort)
}

fn source() -> SocketAddr {
    "10.0.0.1:4000".parse().unwrap()
}

/// `control` signed in its domain under `key_id` by `by`.
fn signed(control: &AuthControl, key_id: u32, seq: u64, by: &Ed25519Signer) -> Vec<u8> {
    let (domain, session_id, stream_id) = match control {
        AuthControl::Abort(abort) => (
            SignedDomain::SessionAbort,
            abort.alias.session_id,
            abort.alias.stream_id,
        ),
        _ => (SignedDomain::Guard, 0, 0),
    };
    let mut bytes = vec![0u8; 256];
    let body = control.encode(&mut bytes).unwrap();
    let binding = SignedBinding {
        domain,
        party_epoch: 0,
        session_id,
        stream_id,
        key_id,
    };
    let length = seal_signed(&mut bytes, body, &binding, seq, by).unwrap();
    bytes.truncate(length);
    bytes
}

fn state(authority_id: u64, guard_id: u64, epoch: u64) -> AuthControl {
    AuthControl::State(GuardState {
        authority_id,
        guard_id,
        word: GuardWord::from_epoch(epoch).unwrap(),
        lifetime_ms: 5_000,
    })
}

fn abort(authority_id: u64, guard_id: u64) -> AuthControl {
    AuthControl::Abort(SessionAbort {
        alias: ALIAS,
        identity: Identity {
            driver_id: [1, 2],
            registration_id: 3,
            incarnation: 1,
        },
        authority_id,
        guard_id,
        guard_epoch: 3,
        reason: if guard_id == 0 { 2 } else { 1 },
    })
}

/// Each refused datagram in its own cycle, so only its own reason applies.
fn refused(intake: &mut SignedIntake<u8>, bytes: &[u8], at: u64) -> SignedRefusal {
    intake.new_cycle();
    intake.receive(source(), bytes, at).unwrap_err()
}

/// ADR-0086 sections 2 and 8: a bad signature, an unknown key, another
/// authority, a guard the key does not serve, and an abort under a key
/// without the permission are each refused by their reason; a good one
/// verifies.
#[test]
fn signatures_and_authority_scope_are_checked() {
    let mut intake = SignedIntake::<u8>::new(vec![authority(false)], 0);
    let good = signer(9);
    let mut at = 0;
    let mut next = || {
        at += SECOND;
        at
    };
    assert_eq!(
        refused(
            &mut intake,
            &signed(&state(10, 11, 2), 10, 0, &signer(8)),
            next()
        ),
        SignedRefusal::Envelope
    );
    assert_eq!(
        refused(
            &mut intake,
            &signed(&state(10, 11, 2), 99, 0, &good),
            next()
        ),
        SignedRefusal::UnknownKey
    );
    assert_eq!(
        refused(
            &mut intake,
            &signed(&state(77, 11, 2), 10, 0, &good),
            next()
        ),
        SignedRefusal::WrongAuthority
    );
    assert_eq!(
        refused(
            &mut intake,
            &signed(&state(10, 13, 2), 10, 0, &good),
            next()
        ),
        SignedRefusal::WrongGuard
    );
    assert_eq!(
        refused(&mut intake, &signed(&abort(10, 0), 10, 0, &good), next()),
        SignedRefusal::NoAbortPermission
    );
    intake.new_cycle();
    assert!(matches!(
        intake.receive(source(), &signed(&state(10, 11, 2), 10, 0, &good), next()),
        Ok(Received::Fresh(_))
    ));
    assert_eq!(intake.verified, 1);
    // With the permission, an abort naming a guard it does not serve is
    // refused too.
    let mut aborting = SignedIntake::<u8>::new(vec![authority(true)], 0);
    assert_eq!(
        refused(&mut aborting, &signed(&abort(10, 13), 10, 0, &good), SECOND),
        SignedRefusal::WrongGuard
    );
    aborting.new_cycle();
    assert!(matches!(
        aborting.receive(source(), &signed(&abort(10, 0), 10, 0, &good), 2 * SECOND),
        Ok(Received::Fresh(Verified {
            control: AuthControl::Abort(_),
            ..
        }))
    ));
}

/// ADR-0086 section 2: past the budget a datagram is dropped and counted
/// before anything verifies it, a forged one included: one per duty cycle,
/// and per source.
#[test]
fn the_budget_drops_before_verifying() {
    let mut intake = SignedIntake::<u8>::new(vec![authority(false)], 0);
    let good = signer(9);
    let forged = signed(&state(10, 11, 2), 10, 0, &signer(8));
    assert!(
        intake
            .receive(source(), &signed(&state(10, 11, 2), 10, 0, &good), 0)
            .is_ok()
    );
    // Same cycle: refused by the budget, not by its signature.
    assert_eq!(
        intake.receive(source(), &forged, 0).unwrap_err(),
        SignedRefusal::BudgetCycle
    );
    assert_eq!(intake.refusals(SignedRefusal::Envelope), 0);
    // Per source: 4 per second with a burst of 4.
    for _ in 0..3 {
        intake.new_cycle();
        assert_eq!(
            intake.receive(source(), &forged, 0).unwrap_err(),
            SignedRefusal::Envelope
        );
    }
    intake.new_cycle();
    assert_eq!(
        intake.receive(source(), &forged, 0).unwrap_err(),
        SignedRefusal::BudgetSource
    );
    assert_eq!(intake.refusals(SignedRefusal::Envelope), 3);
    // Another source still has its own.
    intake.new_cycle();
    assert_eq!(
        intake
            .receive("10.0.0.2:4000".parse().unwrap(), &forged, 0)
            .unwrap_err(),
        SignedRefusal::Envelope
    );
    // A second later the source's bucket refilled.
    intake.new_cycle();
    assert_eq!(
        intake.receive(source(), &forged, SECOND).unwrap_err(),
        SignedRefusal::Envelope
    );
}

/// ADR-0086 sections 2 and 6: an applied datagram's identical resend hits
/// the digest cache and returns what to resend, without verifying again;
/// a datagram not yet applied is verified again.
#[test]
fn a_cache_hit_resends_without_a_second_verification() {
    let mut intake = SignedIntake::<u8>::new(vec![authority(true)], 0);
    let bytes = signed(&abort(10, 0), 10, 0, &signer(9));
    let Ok(Received::Fresh(verified)) = intake.receive(source(), &bytes, 0) else {
        panic!("verified");
    };
    // Not applied yet: verified again.
    intake.new_cycle();
    assert!(matches!(
        intake.receive(source(), &bytes, SECOND),
        Ok(Received::Fresh(_))
    ));
    intake.applied(verified.digest, 7);
    intake.new_cycle();
    assert_eq!(
        intake.receive(source(), &bytes, 2 * SECOND).unwrap(),
        Received::Resend(7)
    );
    assert_eq!((intake.verified, intake.resends), (2, 1));
}

/// A bare GUARD, SESSION_ABORT or SESSION_ABORT_ACK stays gated: the
/// trusted decoder refuses it after its common word.
#[test]
fn bare_signed_bodies_stay_gated() {
    let mut bytes = vec![0u8; 256];
    let length = abort(10, 0).encode(&mut bytes).unwrap();
    bytes.truncate(length);
    assert!(is_gated(&bytes));
    assert!(matches!(
        karyos_protocol::network::classify(&bytes),
        Err(karyos_protocol::network::ControlError::GatedType { .. })
    ));
}

/// An authority public key file gives the authority its scope names.
#[test]
fn an_authority_key_file_names_its_scope() {
    let public = crate::wire_keys::parse(
        "10-1.key",
        b"format=karyos-wire-key-v1\nkey_id=10\nfile_epoch=1\npurpose=authority-public\nprofile_id=4\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-04-30T00:00:00Z\npublic=fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618\nauthority_id=10\nguards=11,12\nabort=true\n",
    )
    .unwrap();
    let authority = Authority::from_file(&public).unwrap();
    assert_eq!(authority.authority_id(), 10);
    let mut intake = SignedIntake::<u8>::new(vec![authority], 0);
    // Signed by the matching seed of the key tests.
    assert!(matches!(
        intake.receive(source(), &signed(&abort(10, 12), 10, 0, &signer(9)), 0),
        Ok(Received::Fresh(_))
    ));
}
