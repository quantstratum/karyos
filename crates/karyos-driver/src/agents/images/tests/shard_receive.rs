// SPDX-License-Identifier: Apache-2.0

//! ADR-0127 on a receiver role (`quantstratum-docs:
//! karyos/adr/0127-encrypted-sharded-receive-per-endpoint.md`): receive
//! shards start with the first encrypted subscription of an endpoint and
//! receive it instead of the role; a key change and a VM generation change
//! while they dispatch commit nothing and keep every key until its leases
//! return; and a representative subset of the encrypted suite passes with
//! shards on (the suite itself runs with them off).

use karyos_protocol::protection::aes_gcm_siv::EncRejection;
use karyos_sys::log_buffer::{AppendOptions, Role};

use super::*;
use crate::agents::roles::receive_enc::with_enc_shards;
use crate::wire_enc::{EncShardConfig, EncVerifyConfig};

/// The shards of these tests: two per endpoint, small rings.
const SHARDS: EncShardConfig = EncShardConfig {
    shards: 2,
    ring: 64,
};

/// Their verifiers: two, 64 slots per lane.
const VERIFY: EncVerifyConfig = EncVerifyConfig {
    verifiers: 2,
    slots: 64,
};

/// A sharded rig with jobs in flight: see [`in_flight`].
struct InFlight {
    rig: Rig,
    b: EndpointId,
    slot: SlotRef,
    committed: u64,
    _conductor: karyos_sys::log_buffer::Conductor<std::sync::Arc<LogBuffer>>,
    _subscriber: karyos_sys::log_buffer::Subscription<std::sync::Arc<LogBuffer>>,
}

/// An established encrypted rig received by shards, four messages
/// delivered, then one more sent while the role holds results: its jobs
/// are in a shard lane, dispatched under the image's key.
fn in_flight() -> InFlight {
    let (mut rig, b) = with_enc_shards(SHARDS, VERIFY, encrypted_rig);
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
        "a job in a shard lane"
    );
    assert!(rig.agents.receiver.role.enc_leases(slot).unwrap().0 > 0);
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

/// Decision 1: the shards start at the first encrypted subscription of the
/// endpoint and receive it, the role serving their lanes; none without the
/// configuration.
#[test]
fn shards_start_with_the_first_encrypted_subscription_and_receive_its_endpoint() {
    let (mut rig, b) = with_enc_shards(SHARDS, VERIFY, encrypted_rig);
    let slot = established(&mut rig);
    let (_conductor, mut subscriber) = image_subscriber(&rig, slot, 0, Role::Optional);
    let messages: Vec<Vec<u8>> = (0..16u8).map(|i| vec![i; 100]).collect();
    assert_eq!(enc_deliver(&mut rig, &mut subscriber, &messages), messages);
    let stats = rig.agents.receiver.role.enc_shard_stats(b).unwrap();
    assert_eq!((stats.shards, stats.verifiers), (2, 2));
    assert!(
        stats.received > stats.forwarded,
        "the shards dispatched the bound traffic: {stats:?}"
    );
    assert_eq!(stats.ring_full, 0);
    assert_eq!(rig.agents.receiver.role.enc_leases(slot).unwrap().0, 0);
    let (rig, b) = encrypted_rig();
    assert!(
        rig.agents.receiver.role.enc_shard_stats(b).is_none(),
        "default 0"
    );
}

/// Decision 2, step 4: with shards on, the domain 5 SETUP that establishes
/// the session is derived on a shard (a scratch derivation under a lease
/// on its subscription), verified, and decided by the role, and every
/// lease is back.
#[test]
fn shards_derive_the_establishing_setup_and_the_role_decides_it() {
    let (mut rig, b) = with_enc_shards(SHARDS, VERIFY, encrypted_rig);
    let slot = established(&mut rig);
    let stats = rig.agents.receiver.role.enc_shard_stats(b).unwrap();
    assert!(stats.scratch >= 1, "derived on a shard: {stats:?}");
    assert!(rig.agents.receiver.role.enc_leases(slot).is_some());
}

/// The control: released, the held jobs commit.
#[test]
fn held_shard_jobs_commit_once_released() {
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

/// Decision 7: a key change while the shards dispatch takes their snapshot
/// back and withdraws every job in their lanes before the set applies:
/// nothing is committed, every lease is back when it returns, and the
/// session keeps its keys.
#[test]
fn a_key_change_while_shards_dispatch_commits_nothing() {
    let InFlight {
        mut rig,
        b,
        slot,
        committed,
        _conductor: _keep_conductor,
        _subscriber: _keep_subscriber,
    } = in_flight();
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

/// Decision 7: a withdrawal (every key revoked) while the shards dispatch:
/// all refused, nothing committed, the key erased once no lease and no
/// snapshot holds it.
#[test]
fn a_withdrawal_while_shards_dispatch_commits_nothing() {
    let InFlight {
        mut rig,
        b,
        slot,
        committed,
        _conductor: _keep_conductor,
        _subscriber: _keep_subscriber,
    } = in_flight();
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

/// Decision 7 and ADR-0114 section 10: a VM generation change while the
/// shards dispatch withdraws their jobs before anything closes; the role
/// redraws only with every lease back, and nothing is committed.
#[test]
fn a_vm_generation_change_while_shards_dispatch_commits_nothing() {
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
    } = in_flight();
    rig.agents
        .receiver
        .role
        .enc_watch(VmGenerationWatch::new(Box::new(signal)));
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
    // What is in flight now is the new generation's: the publisher's
    // SETUPs re-establishing, derived on the shards from the snapshot
    // published after the redraw. Every job of the old one was withdrawn.
    assert!(withdrawn(&rig, b) >= before + held);
    assert!(key.upgrade().is_none(), "erased, every lease back");
    assert_eq!(rig.agents.receiver.counters().data_committed, committed);
}

/// A representative subset of the encrypted suite, run with receive
/// shards on.
macro_rules! with_shards {
    ($($name:ident => $case:ident;)*) => {
        $(
            #[test]
            fn $name() {
                with_enc_shards(SHARDS, VERIFY, $case);
            }
        )*
    };
}

with_shards! {
    shards_establish_deliver_resync
        => an_encrypted_publisher_and_receiver_establish_deliver_and_resynchronise;
    shards_revoked_key => a_revoked_key_stops_an_encrypted_images_controls;
    shards_rotation => a_key_rotation_keeps_an_encrypted_session_flowing;
    shards_vm_generation => a_vm_generation_change_re_establishes_an_encrypted_session;
    shards_invalid_tag_flood => an_invalid_tag_flood_on_an_encrypted_image_allocates_nothing;
    shards_refused_batch => a_tagged_batch_its_image_would_refuse_marks_no_sequence;
    shards_next_epoch_control => a_next_epoch_sender_control_its_handler_would_refuse_marks_nothing;
    shards_replayed_data => replayed_encrypted_data_and_heartbeats_do_not_keep_the_image_alive;
    shards_retirement => an_ordinary_retirement_erases_a_queued_domain_4_sealer;
}

/// Decision 7 for a promotion: a datagram the role re-checked as
/// promotable always commits. Two sender controls promote the next party
/// epochs in turn; before the second, a shard snapshot holds the previous
/// key. A shard racing the second commit, leasing that previous key
/// between the role's last check and the commit, finds the snapshot
/// already taken back: it takes nothing, and the promotion commits.
#[test]
fn a_promotion_rechecked_by_the_role_always_commits() {
    use karyos_protocol::network::{Control, PathHeartbeat};
    use karyos_protocol::protection::aes_gcm_siv::Domain;

    let (mut rig, b) = with_enc_shards(SHARDS, VERIFY, encrypted_rig);
    crate::wire_enc::record_seals();
    let slot = established(&mut rig);
    let (_conductor, mut subscriber) = image_subscriber(&rig, slot, 0, Role::Optional);
    let first: Vec<Vec<u8>> = (0..3u8).map(|i| vec![i; 100]).collect();
    assert_eq!(enc_deliver(&mut rig, &mut subscriber, &first), first);
    rig.sender_stopped = true;
    let data = crate::wire_enc::take_seals()
        .iter()
        .rfind(|record| record.context.domain == Domain::Sender)
        .unwrap()
        .clone();
    let heartbeat = Control::PathHeartbeat(PathHeartbeat {
        alias: alias(),
        identity: identity(),
    });
    let source = rig.endpoints.local_address(rig.publisher).unwrap();
    let mut context = data.context;
    for promotion in 0..2 {
        context.party_epoch += 1;
        let mut record = data.clone();
        let mut frames = vec![0_u8; 512];
        let length = heartbeat.encode(&mut frames).unwrap();
        frames.truncate(length);
        record.context = context;
        record.seq = 0;
        record.frames = frames;
        if promotion == 1 {
            assert!(
                rig.agents.receiver.role.enc_shards_hold_previous(),
                "a shard snapshot holds the previous key"
            );
            rig.agents.receiver.role.enc_race_promotions(true);
        }
        let receiver = &mut rig.agents.receiver;
        receiver
            .role
            .inject_datagram(&receiver.sessions, b, source, &replayed(&record), rig.now);
        assert_eq!(
            rig.agents.receiver.role.enc_epochs(slot),
            Some((context.key_epoch, context.party_epoch)),
            "promotion {promotion} committed"
        );
    }
    assert_eq!(
        rig.agents.receiver.role.enc_raced(),
        (1, 0),
        "the commit was raced once and no lease was taken"
    );
    assert_eq!(rig.agents.receiver.role.enc_leases(slot).unwrap().0, 0);
}

/// Decision 7 at the agent: stopping the receiver through its runner
/// withdraws, cancels, drains and joins its shards before it reports
/// stopped. The agent handed back, still held, has no shard set (its
/// shards and verifiers joined), nothing in flight and no lease out.
#[test]
fn stopping_the_receiver_joins_its_shards_before_it_is_handed_back() {
    use crate::agents::{AgentRunner, ThreadingMode, YieldThenSleep};

    let InFlight {
        rig,
        b,
        slot,
        _conductor: _keep_conductor,
        _subscriber: _keep_subscriber,
        ..
    } = in_flight();
    assert!(rig.agents.receiver.role.enc_shard_stats(b).is_some());
    let Rig {
        agents,
        links: _links,
        endpoints: _endpoints,
        ..
    } = rig;
    let runner = AgentRunner::start(
        ThreadingMode::Dedicated,
        agents,
        AgentConfig::default(),
        YieldThenSleep::default,
    )
    .unwrap();
    let stopped = runner.stop();
    assert!(stopped.failures.is_empty() && stopped.late.is_empty());
    let receiver = stopped.receiver.expect("the receiver is handed back");
    assert!(
        receiver.role.enc_shard_stats(b).is_none(),
        "its shards were joined before it reported stopped"
    );
    assert_eq!(receiver.role.enc_in_flight(), 0);
    assert_eq!(
        receiver.role.enc_leases(slot).unwrap().0,
        0,
        "every lease back"
    );
    drop(receiver);
}
