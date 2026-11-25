// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;

use karyos_client::{HeapWords, SharedWords};
use karyos_protocol::network::Receiver;
use karyos_protocol::network::authenticated::{AuthControl, StatusChallenge};

use super::*;
use crate::authority::Ed25519Signer;
use crate::remote_guard::tests::Marks;
use crate::remote_guard::{MarkError, MarkStore};
use crate::signed_control::{Authority, Received, SignedIntake};

const SECOND: u64 = 1_000_000_000;

fn at(port: u16) -> SocketAddr {
    SocketAddr::from(([10, 0, 0, 9], port))
}

/// A guard word open at epoch 2.
fn open_word() -> Arc<dyn SharedWords> {
    let word = Arc::new(HeapWords::zeroed(1));
    word.words()[0].store(
        karyos_sys::guard::encode(karyos_sys::guard::GuardState {
            epoch: 2,
            open: true,
        })
        .unwrap(),
        karyos_sys::sync::Ordering::Release,
    );
    word
}

fn guard(guard_id: u64, receivers: &[(u64, SocketAddr)]) -> AuthorityGuard {
    AuthorityGuard {
        guard_id,
        word: open_word(),
        lifetime_ms: 5_000,
        receivers: receivers.to_vec(),
    }
}

fn authority(guards: Vec<AuthorityGuard>) -> GuardAuthority {
    GuardAuthority::new(
        10,
        10,
        Ed25519Signer::from_seed(&[9; 32]),
        guards,
        Box::new(Marks::default()),
        0,
    )
    .unwrap()
}

fn challenge(guard_id: u64, receiver_id: u64, nonce: u64) -> Vec<u8> {
    let mut bytes = vec![0u8; 128];
    let length = AuthControl::Challenge(StatusChallenge {
        authority_id: 10,
        guard_id,
        receiver: Receiver {
            receiver_boot_id: [7, 8],
            receiver_id,
        },
        nonce: [nonce, 1],
    })
    .encode(&mut bytes)
    .unwrap();
    bytes.truncate(length);
    bytes
}

/// Design 4.2 and 4.3: a challenge from a configured receiver's own
/// address is answered with a STATUS signed in domain 2 over the guard's
/// current word, the receiver's boot id and id and the nonce, sent to the
/// receiver's configured endpoint; it verifies under the authority key.
#[test]
fn a_challenge_is_answered_with_a_signed_status_to_the_configured_endpoint() {
    let mut authority = authority(vec![guard(11, &[(66, at(1))])]);
    let answer = authority.answer(&challenge(11, 66, 5), at(1), 0).unwrap();
    assert_eq!(answer.destination, at(1));
    let mut intake = SignedIntake::<u8>::new(
        vec![Authority::of(
            10,
            Ed25519Signer::from_seed(&[9; 32]).verifier(),
            10,
            &[11],
            false,
        )],
        0,
    );
    let Ok(Received::Fresh(verified)) = intake.receive(at(2), answer.datagram(), 0) else {
        panic!("the STATUS verifies");
    };
    let AuthControl::Status(status) = verified.control else {
        panic!("a STATUS");
    };
    assert_eq!((status.guard_id, status.nonce), (11, [5, 1]));
    assert_eq!(status.receiver.receiver_boot_id, [7, 8]);
    assert_eq!((status.word.epoch(), status.word.is_open()), (2, true));
}

/// Design 4.2: an unknown guard or receiver, another authority, a spoofed
/// source and a malformed datagram are refused before any signature, by
/// their reasons; nothing is answered.
#[test]
fn spoofed_or_unconfigured_challenges_get_no_answer() {
    let mut authority = authority(vec![guard(11, &[(66, at(1))])]);
    let refuse = |authority: &mut GuardAuthority, bytes: &[u8], from| {
        authority.answer(bytes, from, 0).unwrap_err()
    };
    assert_eq!(
        refuse(&mut authority, &challenge(12, 66, 1), at(1)),
        ChallengeRefusal::UnknownGuard
    );
    assert_eq!(
        refuse(&mut authority, &challenge(11, 67, 1), at(1)),
        ChallengeRefusal::UnknownReceiver
    );
    assert_eq!(
        refuse(&mut authority, &challenge(11, 66, 1), at(3)),
        ChallengeRefusal::SourceMismatch
    );
    let mut other = challenge(11, 66, 1);
    other[24] = 77;
    assert_eq!(
        refuse(&mut authority, &other, at(1)),
        ChallengeRefusal::WrongAuthority
    );
    assert_eq!(
        refuse(&mut authority, &[0u8; 8], at(1)),
        ChallengeRefusal::Malformed
    );
    assert_eq!(authority.answered, 0);
}

/// Design 4.2: a flood saturates the per-destination budget (4, refilled
/// at 4 per second) and the per-cycle one (4), each counted by reason;
/// two guards naming one endpoint share its bucket.
#[test]
fn a_challenge_flood_is_held_to_its_budgets() {
    let mut authority = authority(vec![
        guard(11, &[(66, at(1))]),
        guard(12, &[(66, at(1)), (67, at(2))]),
    ]);
    for nonce in 0..4 {
        let guard_id = if nonce % 2 == 0 { 11 } else { 12 };
        assert!(
            authority
                .answer(&challenge(guard_id, 66, nonce), at(1), 0)
                .is_ok()
        );
    }
    // The shared endpoint's bucket is empty, in a new cycle too.
    authority.new_cycle();
    assert_eq!(
        authority
            .answer(&challenge(12, 66, 9), at(1), 0)
            .unwrap_err(),
        ChallengeRefusal::DestinationBudget
    );
    // The cycle's four are spent, whoever asks.
    for nonce in 0..4 {
        assert!(
            authority
                .answer(&challenge(12, 67, nonce), at(2), 0)
                .is_ok()
        );
    }
    assert_eq!(
        authority
            .answer(&challenge(12, 67, 9), at(2), 0)
            .unwrap_err(),
        ChallengeRefusal::DriverBudget
    );
    // A second later the endpoint has its budget again.
    authority.new_cycle();
    assert!(
        authority
            .answer(&challenge(11, 66, 10), at(1), SECOND)
            .is_ok()
    );
    assert_eq!(authority.refusals(ChallengeRefusal::DestinationBudget), 1);
    assert_eq!(authority.refusals(ChallengeRefusal::DriverBudget), 1);
}

/// Design 4.2: a configuration beyond the authority's or an endpoint's
/// capacity, or an invalid one, is refused at load.
#[test]
fn configurations_over_capacity_are_refused_at_load() {
    let signer = || Ed25519Signer::from_seed(&[9; 32]);
    let make = |guards| {
        GuardAuthority::new(10, 10, signer(), guards, Box::new(Marks::default()), 0).map(|_| ())
    };
    // 321 receivers at 5 s: above 64 × 5.
    let many: Vec<(u64, SocketAddr)> = (1..=321)
        .map(|id| (id, at(u16::try_from(id).unwrap())))
        .collect();
    assert_eq!(
        make(vec![guard(11, &many)]),
        Err(AuthorityConfigError::AuthorityCapacity)
    );
    assert_eq!(make(vec![guard(11, &many[..320])]), Ok(()));
    // Six guards at 5 s on one endpoint: 2.4 per second, above 2.
    let shared: Vec<AuthorityGuard> = (11..=16).map(|id| guard(id, &[(66, at(1))])).collect();
    assert_eq!(
        make(shared.clone()),
        Err(AuthorityConfigError::EndpointCapacity)
    );
    assert_eq!(make(shared[..5].to_vec()), Ok(()));
    let mut zero = guard(11, &[(66, at(1))]);
    zero.lifetime_ms = 0;
    assert_eq!(make(vec![zero]), Err(AuthorityConfigError::Invalid));
    assert_eq!(
        make(vec![guard(11, &[(66, at(1))]), guard(11, &[(67, at(2))])]),
        Err(AuthorityConfigError::Invalid)
    );
}

/// Committed epochs shared with the test after the authority takes them.
#[derive(Debug, Clone, Default)]
struct Shared(Arc<std::sync::Mutex<Marks>>);

impl MarkStore for Shared {
    fn load(&self, guard_id: u64) -> Result<u64, MarkError> {
        self.0.lock().unwrap().load(guard_id)
    }

    fn latched(&self, guard_id: u64) -> Result<bool, MarkError> {
        self.0.lock().unwrap().latched(guard_id)
    }

    fn persist(&mut self, guard_id: u64, epoch: u64) -> Result<(), MarkError> {
        self.0.lock().unwrap().persist(guard_id, epoch)
    }

    fn latch(&mut self, guard_id: u64) -> Result<(), MarkError> {
        self.0.lock().unwrap().latch(guard_id)
    }
}

fn set_word(word: &HeapWords, epoch: u64, open: bool) {
    word.words()[0].store(
        karyos_sys::guard::encode(karyos_sys::guard::GuardState { epoch, open }).unwrap(),
        karyos_sys::sync::Ordering::Release,
    );
}

/// Finding 9 of the H8 review (design 4.4, ADR-0086 section 7): the
/// authority signs only a committed word: a word above the committed epoch
/// is committed before it is signed, one below it is never signed, and a
/// failed commit disables signing for good, counted.
#[test]
fn only_a_committed_word_is_signed() {
    let word = Arc::new(HeapWords::zeroed(1));
    set_word(&word, 2, true);
    let store = Shared::default();
    let mut authority = GuardAuthority::new(
        10,
        10,
        Ed25519Signer::from_seed(&[9; 32]),
        vec![AuthorityGuard {
            guard_id: 11,
            word: Arc::clone(&word) as Arc<dyn SharedWords>,
            lifetime_ms: 5_000,
            receivers: vec![(66, at(1))],
        }],
        Box::new(store.clone()),
        0,
    )
    .unwrap();
    assert!(authority.answer(&challenge(11, 66, 1), at(1), 0).is_ok());
    assert_eq!(store.0.lock().unwrap().held[&11], 2, "committed first");
    // The authority's own word rolled back below its committed epoch.
    set_word(&word, 5, false);
    authority.new_cycle();
    assert!(authority.answer(&challenge(11, 66, 2), at(1), 0).is_ok());
    set_word(&word, 2, true);
    authority.new_cycle();
    assert_eq!(
        authority
            .answer(&challenge(11, 66, 3), at(1), 0)
            .unwrap_err(),
        ChallengeRefusal::BelowCommitted
    );
    // A commit that fails disables signing.
    set_word(&word, 6, true);
    store.0.lock().unwrap().fail = true;
    assert_eq!(
        authority
            .answer(&challenge(11, 66, 4), at(1), SECOND)
            .unwrap_err(),
        ChallengeRefusal::Uncommitted
    );
    assert!(!authority.signing());
    store.0.lock().unwrap().fail = false;
    assert_eq!(
        authority
            .answer(&challenge(11, 66, 5), at(1), 2 * SECOND)
            .unwrap_err(),
        ChallengeRefusal::Uncommitted
    );
    assert_eq!(authority.refusals(ChallengeRefusal::Uncommitted), 2);
    assert_eq!(store.0.lock().unwrap().held[&11], 5);
    assert_eq!(authority.answered, 2);
}

/// Finding 9: unreadable committed state at load disables signing.
#[test]
fn unreadable_committed_state_disables_signing() {
    let mut authority = GuardAuthority::new(
        10,
        10,
        Ed25519Signer::from_seed(&[9; 32]),
        vec![guard(11, &[(66, at(1))])],
        Box::new(Marks {
            unreadable: true,
            ..Marks::default()
        }),
        0,
    )
    .unwrap();
    assert!(!authority.signing());
    assert_eq!(
        authority
            .answer(&challenge(11, 66, 1), at(1), 0)
            .unwrap_err(),
        ChallengeRefusal::Uncommitted
    );
    assert_eq!(authority.answered, 0);
}
