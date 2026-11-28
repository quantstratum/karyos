// SPDX-License-Identifier: Apache-2.0

//! ADR-0126 on a receiver role (`quantstratum-docs:
//! karyos/adr/0126-encrypted-verification-on-worker-threads.md`): jobs in
//! flight across a key change, a withdrawal, a binding removal and a VM
//! generation change commit nothing and keep their keys until their
//! leases return; and a representative subset of the encrypted suite
//! passes with a verifier pool, on threads and run by the role alone.

use karyos_protocol::protection::aes_gcm_siv::EncRejection;
use karyos_sys::log_buffer::{AppendOptions, Role};

use super::*;
use crate::agents::roles::receive_enc::with_enc_verifiers;
use crate::wire_enc::EncVerifyConfig;

/// The pool of these tests: two verifiers, 64 slots.
const POOL: EncVerifyConfig = EncVerifyConfig {
    verifiers: 2,
    slots: 64,
};

/// A rig with jobs in flight: see [`in_flight`].
struct InFlight {
    rig: Rig,
    b: EndpointId,
    slot: SlotRef,
    /// The committed count before the held jobs.
    committed: u64,
    _conductor: karyos_sys::log_buffer::Conductor<std::sync::Arc<LogBuffer>>,
    _subscriber: karyos_sys::log_buffer::Subscription<std::sync::Arc<LogBuffer>>,
}

/// An established encrypted rig whose receiver verifies through a pool
/// run by the role alone, four messages delivered, then one more sent
/// while results are held: its jobs are in flight.
fn in_flight() -> InFlight {
    let (mut rig, b) = with_enc_verifiers(POOL, false, encrypted_rig);
    let slot = established(&mut rig);
    let (conductor, mut subscriber) = image_subscriber(&rig, slot, 0, Role::Optional);
    let first: Vec<Vec<u8>> = (0..4u8).map(|i| vec![i; 100]).collect();
    assert_eq!(enc_deliver(&mut rig, &mut subscriber, &first), first);
    assert_eq!(rig.agents.receiver.role.enc_in_flight(), 0);
    rig.agents.receiver.role.enc_hold(true);
    let committed = rig.agents.receiver.counters().data_committed;
    let _ = rig.log.as_mut().unwrap().publications[0]
        .append(&[9; 100], AppendOptions::default())
        .unwrap();
    for _ in 0..50 {
        rig.round(true);
        if rig.agents.receiver.role.enc_in_flight() > 0 {
            break;
        }
    }
    assert!(
        rig.agents.receiver.role.enc_in_flight() > 0,
        "a job in flight"
    );
    assert_eq!(rig.agents.receiver.counters().data_committed, committed);
    InFlight {
        rig,
        b,
        slot,
        committed,
        _conductor: conductor,
        _subscriber: subscriber,
    }
}

fn withdrawn(rig: &Rig, b: EndpointId) -> u64 {
    rig.agents
        .receiver
        .role
        .enc_rejections(b, alias().stream_id)
        .unwrap()
        .get(EncRejection::Withdrawn)
}

/// The control: released, the held jobs commit.
#[test]
fn held_jobs_commit_once_released() {
    let InFlight {
        mut rig,
        slot,
        committed,
        _conductor: _keep_conductor,
        _subscriber: _keep_subscriber,
        ..
    } = in_flight();
    rig.agents.receiver.role.enc_hold(false);
    rig.round(true);
    assert_eq!(rig.agents.receiver.role.enc_in_flight(), 0);
    assert!(rig.agents.receiver.counters().data_committed > committed);
    assert_eq!(rig.agents.receiver.role.enc_leases(slot).unwrap().0, 0);
}

/// Decision 5: a key change with a job verified and one queued withdraws
/// both before the set applies: nothing is committed, every lease is back
/// when it returns, and the session keeps its keys.
#[test]
fn a_key_change_with_a_job_in_flight_commits_nothing() {
    let InFlight {
        mut rig,
        b,
        slot,
        committed,
        _conductor: _keep_conductor,
        _subscriber: _keep_subscriber,
        ..
    } = in_flight();
    assert!(rig.agents.receiver.role.enc_verify_one(), "one verified");
    let held = u64::try_from(rig.agents.receiver.role.enc_in_flight()).unwrap();
    let before = withdrawn(&rig, b);
    let (channel, pairwise) = enc_keys(77);
    rig.agents
        .receiver
        .role
        .apply_keys(&crate::wire_auth::FixedKeys {
            files: vec![channel, pairwise],
        });
    assert_eq!(rig.agents.receiver.role.enc_in_flight(), 0);
    assert_eq!(withdrawn(&rig, b), before + held);
    let (leases, key) = rig.agents.receiver.role.enc_leases(slot).unwrap();
    assert_eq!(leases, 0);
    assert!(key.upgrade().is_some(), "the opener keeps its key");
    rig.agents.receiver.role.enc_hold(false);
    rig.round(true);
    assert_eq!(rig.agents.receiver.counters().data_committed, committed);
}

/// Decision 5: a withdrawal (every key revoked) with jobs in flight: all
/// refused, nothing committed, and the key erased once no lease holds it.
#[test]
fn a_withdrawal_with_a_job_in_flight_commits_nothing() {
    let InFlight {
        mut rig,
        b,
        slot,
        committed,
        _conductor: _keep_conductor,
        _subscriber: _keep_subscriber,
        ..
    } = in_flight();
    assert!(rig.agents.receiver.role.enc_verify_one());
    let (_, key) = rig.agents.receiver.role.enc_leases(slot).unwrap();
    let before = withdrawn(&rig, b);
    let held = u64::try_from(rig.agents.receiver.role.enc_in_flight()).unwrap();
    rig.agents
        .receiver
        .role
        .apply_keys(&crate::wire_auth::FixedKeys::default());
    assert_eq!(rig.agents.receiver.role.enc_in_flight(), 0);
    assert_eq!(withdrawn(&rig, b), before + held);
    assert!(key.upgrade().is_none(), "erased, every lease back");
    rig.agents.receiver.role.enc_hold(false);
    rig.round(true);
    assert_eq!(rig.agents.receiver.counters().data_committed, committed);
}

/// Decision 5: the binding removed while one job is verified and the
/// others queued: the queued ones are cancelled, the verified one is
/// refused at its re-check, and the key the leases hold is not erased
/// before the last returns.
#[test]
fn a_binding_removal_with_a_job_in_flight_commits_nothing() {
    let InFlight {
        mut rig,
        b,
        slot,
        committed,
        _conductor: _keep_conductor,
        _subscriber: _keep_subscriber,
        ..
    } = in_flight();
    assert!(rig.agents.receiver.role.enc_verify_one());
    let (leases, key) = rig.agents.receiver.role.enc_leases(slot).unwrap();
    assert!(leases > 0);
    rig.agents.receiver.role.enc_remove_binding(slot);
    let alive = key.upgrade().expect("held by the leases out");
    assert!(
        alive.context().key_epoch > 0
            && alive.context().domain == karyos_protocol::protection::aes_gcm_siv::Domain::Sender,
        "not erased early"
    );
    drop(alive);
    let refused = rig
        .agents
        .receiver
        .role
        .enc_rejections(b, alias().stream_id)
        .unwrap()
        .total();
    rig.agents.receiver.role.enc_hold(false);
    let now = rig.now;
    let receiver = &mut rig.agents.receiver;
    receiver.role.enc_settle(&receiver.sessions, now);
    assert_eq!(rig.agents.receiver.role.enc_in_flight(), 0);
    assert!(
        key.upgrade().is_none(),
        "erased once the last lease returned"
    );
    assert_eq!(rig.agents.receiver.counters().data_committed, committed);
    let after = rig
        .agents
        .receiver
        .role
        .enc_rejections(b, alias().stream_id)
        .unwrap()
        .total();
    assert!(after > refused, "each job refused and counted");
}

/// Decision 5 and ADR-0114 section 10: a VM generation change with jobs
/// in flight withdraws them all before anything closes; the role redraws
/// only with every lease back, and nothing is committed.
#[test]
fn a_vm_generation_change_with_a_job_in_flight_commits_nothing() {
    use crate::wire_enc::VmGenerationWatch;
    use crate::wire_enc::vm_generation::InjectedSignal;

    let (signal, injector) = InjectedSignal::new();
    let InFlight {
        mut rig,
        b,
        slot,
        committed,
        _conductor: _keep_conductor,
        _subscriber: _keep_subscriber,
        ..
    } = in_flight();
    rig.agents
        .receiver
        .role
        .enc_watch(VmGenerationWatch::new(Box::new(signal)));
    assert!(rig.agents.receiver.role.enc_verify_one());
    let (_, key) = rig.agents.receiver.role.enc_leases(slot).unwrap();
    let generation = rig.agents.receiver.role.enc_generation();
    let before = withdrawn(&rig, b);
    let held = u64::try_from(rig.agents.receiver.role.enc_in_flight()).unwrap();
    injector.change();
    rig.round(true);
    assert_ne!(
        rig.agents.receiver.role.enc_generation(),
        generation,
        "redrawn"
    );
    assert_eq!(rig.agents.receiver.role.enc_in_flight(), 0);
    assert!(withdrawn(&rig, b) >= before + held);
    assert!(key.upgrade().is_none(), "erased, every lease back");
    assert_eq!(rig.agents.receiver.counters().data_committed, committed);
}

/// The receiver's verifier threads start with the pool, at the first
/// encrypted subscription, and none without one.
#[test]
fn the_pool_starts_with_the_first_encrypted_subscription() {
    let (rig, _b) = with_enc_verifiers(POOL, true, encrypted_rig);
    assert_eq!(rig.agents.receiver.role.enc_verifiers(), Some(2));
    let (rig, _b) = encrypted_rig();
    assert_eq!(rig.agents.receiver.role.enc_verifiers(), None, "default 0");
}

/// A representative subset of the encrypted suite, run with a verifier
/// pool on threads (`threads`) and run by the role alone (`inline`).
macro_rules! with_pool {
    ($($threads:ident, $inline:ident => $case:ident;)*) => {
        $(
            #[test]
            fn $threads() {
                with_enc_verifiers(POOL, true, $case);
            }

            #[test]
            fn $inline() {
                with_enc_verifiers(POOL, false, $case);
            }
        )*
    };
}

with_pool! {
    pool_threads_establish_deliver_resync, pool_inline_establish_deliver_resync
        => an_encrypted_publisher_and_receiver_establish_deliver_and_resynchronise;
    pool_threads_revoked_key, pool_inline_revoked_key
        => a_revoked_key_stops_an_encrypted_images_controls;
    pool_threads_rotation, pool_inline_rotation
        => a_key_rotation_keeps_an_encrypted_session_flowing;
    pool_threads_vm_generation, pool_inline_vm_generation
        => a_vm_generation_change_re_establishes_an_encrypted_session;
    pool_threads_invalid_tag_flood, pool_inline_invalid_tag_flood
        => an_invalid_tag_flood_on_an_encrypted_image_allocates_nothing;
    pool_threads_refused_batch, pool_inline_refused_batch
        => a_tagged_batch_its_image_would_refuse_marks_no_sequence;
    pool_threads_next_epoch_control, pool_inline_next_epoch_control
        => a_next_epoch_sender_control_its_handler_would_refuse_marks_nothing;
    pool_threads_replayed_data, pool_inline_replayed_data
        => replayed_encrypted_data_and_heartbeats_do_not_keep_the_image_alive;
    pool_threads_retirement, pool_inline_retirement
        => an_ordinary_retirement_erases_a_queued_domain_4_sealer;
}
