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
    intake.applied(0, source(), verified.digest, 7, SECOND);
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

/// H8 finding 6: unverified datagrams from many unknown sources can
/// neither hold the source table for good nor take a configured peer's
/// budget. Before the fix the first 64 sources kept their slots for the
/// life of the intake and any later source was refused.
#[test]
fn unknown_sources_cannot_starve_a_configured_peer() {
    let mut intake = SignedIntake::<u8>::new(vec![authority(true)], 0);
    let peer: SocketAddr = "10.0.9.9:4000".parse().unwrap();
    assert!(intake.reserve(peer, 0));
    let forged = {
        let mut bytes = signed(&state(10, 11, 2), 10, 0, &signer(9));
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        bytes
    };
    let unknown = |host: usize| SocketAddr::from(([10, 1, 0, u8::try_from(host).unwrap()], 4000));
    // Every unknown slot taken.
    let mut at = 0;
    for host in 0..SOURCE_SLOTS {
        at += SECOND / 16;
        intake.new_cycle();
        assert_eq!(
            intake.receive(unknown(host), &forged, at).unwrap_err(),
            SignedRefusal::Envelope
        );
    }
    // A later source takes an idle slot instead of being refused for good.
    let late: SocketAddr = "10.2.0.1:4000".parse().unwrap();
    intake.new_cycle();
    assert_eq!(
        intake.receive(late, &forged, at).unwrap_err(),
        SignedRefusal::Envelope
    );
    // A burst of unknown sources spends only the shared unknown rate.
    let mut spent = false;
    for host in 100..140 {
        intake.new_cycle();
        if intake.receive(unknown(host), &forged, at).unwrap_err() == SignedRefusal::BudgetSource {
            spent = true;
        }
    }
    assert!(spent, "the unknown sources' shared rate is spent");
    // The peer's reserved bucket still verifies.
    intake.new_cycle();
    assert!(matches!(
        intake.receive(peer, &signed(&state(10, 11, 2), 10, 1, &signer(9)), at),
        Ok(Received::Fresh(_))
    ));
    // Released, the peer is an unknown source again.
    intake.release(peer);
    intake.new_cycle();
    assert_eq!(
        intake.receive(peer, &forged, at).unwrap_err(),
        SignedRefusal::BudgetSource
    );
}

/// H8 finding 8: a digest cache entry answers only its own ingress and
/// source, only until its retention passes, and is dropped by `forget`.
#[test]
fn the_digest_cache_is_scoped_and_bounded() {
    let mut intake = SignedIntake::<u8>::new(vec![authority(true)], 0);
    intake.set_retention(5 * SECOND);
    let bytes = signed(&abort(10, 0), 10, 0, &signer(9));
    let Ok(Received::Fresh(verified)) = intake.receive_on(1, source(), &bytes, 0) else {
        panic!("verified");
    };
    intake.applied(1, source(), verified.digest, 7, 0);
    intake.new_cycle();
    // Another ingress: no hit, verified again.
    assert!(matches!(
        intake.receive_on(2, source(), &bytes, SECOND),
        Ok(Received::Fresh(_))
    ));
    // Another source: no hit.
    intake.new_cycle();
    assert!(matches!(
        intake.receive_on(1, "10.0.0.2:4000".parse().unwrap(), &bytes, SECOND),
        Ok(Received::Fresh(_))
    ));
    // Its own: a hit.
    intake.new_cycle();
    assert_eq!(
        intake.receive_on(1, source(), &bytes, 2 * SECOND).unwrap(),
        Received::Resend(7)
    );
    // Past the retention: verified again.
    intake.new_cycle();
    assert!(matches!(
        intake.receive_on(1, source(), &bytes, 6 * SECOND),
        Ok(Received::Fresh(_))
    ));
    // Forgotten: gone.
    intake.applied(1, source(), verified.digest, 8, 6 * SECOND);
    assert_eq!(intake.cached(), 1);
    intake.forget(|resend| *resend == 8);
    assert_eq!(intake.cached(), 0);
    intake.new_cycle();
    assert!(matches!(
        intake.receive_on(1, source(), &bytes, 7 * SECOND),
        Ok(Received::Fresh(_))
    ));
}

/// H8 finding 8: key application reaches every cached resend, a terminal
/// one included, and an entry past its deadline is pruned with its
/// resend (and so its sealer).
#[test]
fn the_cache_follows_key_application_and_prunes_expired_entries() {
    let mut intake = SignedIntake::<u8>::new(vec![authority(true)], 0);
    intake.applied(1, source(), [1; 32], 7, 0);
    let mut seen = 0;
    intake.for_each_cached(|resend| {
        seen += 1;
        *resend = 0;
    });
    assert_eq!((seen, intake.cached()), (1, 1));
    intake.prune(1);
    assert_eq!(intake.cached(), 1, "within its retention");
    intake.prune(u64::MAX);
    assert_eq!(intake.cached(), 0, "pruned past its deadline");
}

/// H8 review 6, R5-08: replacement in the digest cache, under allocation
/// counting. The cache is filled to its capacity with applied digests;
/// then a new applied digest replaces an expired entry (the others still
/// live), and, with none expired, one replaces the oldest at capacity.
/// Each held digest hits until it is replaced, the cache never grows past
/// its capacity, and no insertion or lookup allocates.
#[test]
fn the_digest_cache_replaces_an_expired_entry_and_the_oldest_at_capacity_without_allocating() {
    use super::{CACHE_ENTRIES, CACHE_RETENTION_NS};
    let mut intake = SignedIntake::<u8>::new(vec![authority(true)], 0);
    let digest = |n: usize| {
        let mut digest = [0u8; 32];
        digest[..8].copy_from_slice(&(n as u64).to_le_bytes());
        digest
    };
    // Entry 0 first, the rest a second later: entry 0 expires first.
    intake.applied(1, source(), digest(0), 0, 0);
    for n in 1..CACHE_ENTRIES {
        intake.applied(1, source(), digest(n), 1, SECOND);
    }
    assert_eq!(intake.cached(), CACHE_ENTRIES);
    // Past entry 0's retention only: a new applied digest takes its slot.
    let now = CACHE_RETENTION_NS;
    let ((), allocations) = karyos_sys::alloc_count::count(|| {
        intake.applied(1, source(), digest(1000), 2, now);
    });
    assert_eq!(allocations, 0, "replacing an expired entry");
    assert_eq!(intake.cached(), CACHE_ENTRIES);
    assert_eq!(intake.cache.find(&digest(1000), 1, source(), now), Some(2));
    assert_eq!(intake.cache.find(&digest(0), 1, source(), now), None);
    assert_eq!(intake.cache.find(&digest(5), 1, source(), now), Some(1));
    // At capacity with none expired: the oldest slot is replaced.
    let ((), allocations) = karyos_sys::alloc_count::count(|| {
        intake.applied(1, source(), digest(2000), 3, now);
    });
    assert_eq!(allocations, 0, "replacing at capacity");
    assert_eq!(intake.cached(), CACHE_ENTRIES);
    assert_eq!(intake.cache.find(&digest(2000), 1, source(), now), Some(3));
    let held = (0..CACHE_ENTRIES)
        .chain([1000])
        .filter(|&n| intake.cache.find(&digest(n), 1, source(), now).is_some())
        .count();
    assert_eq!(
        held,
        CACHE_ENTRIES - 1,
        "exactly one earlier entry replaced"
    );
    // The oldest went: entry 1 (applied at one second, the earliest left),
    // not the entry just put in the expired slot.
    assert_eq!(intake.cache.find(&digest(1000), 1, source(), now), Some(2));
    assert_eq!(intake.cache.find(&digest(1), 1, source(), now), None);
}
