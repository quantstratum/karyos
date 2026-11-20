// SPDX-License-Identifier: Apache-2.0

//! The sender's side of dynamic registration (karyos#644 step 2;
//! `quantstratum-docs: karyos/design/multi-destination-unicast.md` 3.2,
//! 9.2): the receiver hands a REGISTER over only for a stream published on
//! its endpoint; the sender admits it only for a `control-mode=dynamic`
//! publication, through the driver's registrations; a pending registrant's
//! CHALLENGE is answered at its source; its first valid SM takes an
//! optional slot or, with the slots taken meanwhile, gets one ERR
//! REGISTRATION.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::net::{IpAddr, SocketAddr};

use karyos_io::sockets::OsSocket;
use karyos_protocol::network::{
    ChallengeBlock, Control, Receiver, Registration, RegistrationReason, RspChallenge, RspRegister,
};

use super::super::super::{AgentCommand, AgentConfig, AgentEvent, EndpointId};
use super::{alias, event_ring, identity, intake, publication, receiver_with, sm_status};
use crate::agents::data::RemovalReason;
use crate::sessions::register::{AddressRange, RegistrationAllowlist, RegistrationPolicy};

/// Far from zero, so ages never saturate.
const T0: u64 = 1_000_000_000_000;

fn lan() -> RegistrationPolicy {
    let range = AddressRange::new(IpAddr::from([10, 0, 0, 0]), 8).unwrap();
    RegistrationPolicy::new(RegistrationAllowlist::new(&[range]).unwrap(), true)
}

/// A sender with one dynamic publication on endpoint 1 admitting
/// `10.0.0.0/8`, at most `max` destinations; whether it was added.
fn dynamic_sender(max: usize) -> super::super::SenderRole {
    let (mut sender, _receiver) = super::super::roles(&AgentConfig::default()).unwrap();
    assert!(add_dynamic(&mut sender, max, publication(EndpointId(1))));
    sender
}

fn add_dynamic(
    sender: &mut super::super::SenderRole,
    max: usize,
    publication: crate::sessions::send::Publication,
) -> bool {
    let (replies, _keep) = super::super::super::ring::ring::<AgentEvent<OsSocket>>(
        std::num::NonZeroUsize::new(4).unwrap(),
    );
    let (mut outbound, _log) = super::super::super::data::testing::outbound(
        publication.endpoint,
        publication.alias,
        "10.0.0.2:4000".parse().unwrap(),
        publication.term,
        1,
        false,
    );
    outbound.set_registration(max, lan()).unwrap();
    match sender.command(AgentCommand::<OsSocket>::AddPublication {
        reply: replies.reserve().unwrap(),
        publication,
        outbound,
        guard: None,
        roles: None,
    }) {
        Some((_, AgentEvent::PublicationAdded { .. })) => true,
        Some((_, AgentEvent::PublicationRefused { .. })) => false,
        other => panic!("{other:?}"),
    }
}

fn register_of(boot: u64) -> RspRegister {
    RspRegister {
        stream_id: alias().stream_id,
        receiver: Receiver {
            receiver_boot_id: [boot, boot],
            receiver_id: 1,
        },
    }
}

fn challenge_of(boot: u64) -> Control {
    Control::Challenge(RspChallenge {
        alias: alias(),
        identity: identity(),
        challenge: ChallengeBlock {
            receiver_boot_id: [boot, boot],
            nonce: [9, 9],
        },
    })
}

fn full_err() -> Control {
    Control::Registration(Registration {
        stream_id: alias().stream_id,
        reason: RegistrationReason::DestinationsFull,
    })
}

/// The registration exchange: REGISTER, one ANNOUNCE to its source;
/// CHALLENGE from that source, the ANSWER to it; first SM, a slot.
fn join(sender: &mut super::super::SenderRole, from: SocketAddr, boot: u64, now: u64) {
    let announced = sender.register(EndpointId(1), from, &register_of(boot), now);
    assert!(
        matches!(announced, Some((to, Control::SetupAnnounce(_))) if to == from),
        "{announced:?}"
    );
    let answered = sender.answer_for(EndpointId(1), from, now, challenge_of(boot));
    assert!(
        matches!(answered, Some((to, Control::SetupAnswer(_))) if to == from),
        "{answered:?}"
    );
    let reply = sender.status(EndpointId(1), from, &sm_status([boot, boot], 0), now + 1);
    assert_eq!(reply, None);
}

#[test]
fn a_registrant_is_announced_answered_and_joins_at_its_first_sm() {
    let mut sender = dynamic_sender(4);
    let from: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    assert!(!sender.sends_to(EndpointId(1), alias(), from));
    join(&mut sender, from, 7, T0);
    assert!(sender.sends_to(EndpointId(1), alias(), from));
    let counters = sender.counters();
    assert_eq!(counters.registrants_joined, 1);
    assert_eq!(counters.sm_accepted, 1);
    let registrations = sender.registration_counters();
    assert_eq!(registrations.registered, 1);
    assert_eq!(registrations.challenged, 1);
    assert!(sender.registrations.pending().is_empty());
}

/// Mutation target of design 10: a CHALLENGE answered without a pending
/// registration would reflect an ANSWER to any allowed address.
#[test]
fn only_a_pending_registrants_challenge_is_answered() {
    let mut sender = dynamic_sender(4);
    let from: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    // Never registered: refused.
    assert_eq!(
        sender.answer_for(EndpointId(1), from, T0, challenge_of(7)),
        None
    );
    let _ = sender.register(EndpointId(1), from, &register_of(7), T0);
    // Another boot id, or another port of the same address: refused.
    assert_eq!(
        sender.answer_for(EndpointId(1), from, T0, challenge_of(8)),
        None
    );
    let other_port: SocketAddr = "10.0.0.9:5001".parse().unwrap();
    assert_eq!(
        sender.answer_for(EndpointId(1), other_port, T0, challenge_of(7)),
        None
    );
    // Another incarnation leaves the entry in place.
    let mut stale = challenge_of(7);
    if let Control::Challenge(challenge) = &mut stale {
        challenge.identity.incarnation += 1;
    }
    assert_eq!(sender.answer_for(EndpointId(1), from, T0, stale), None);
    assert_eq!(sender.registrations.pending().len(), 1);
    // A SOLICIT from the registrant is not a CHALLENGE: refused.
    let solicit = Control::Solicit(karyos_protocol::network::RspSolicit {
        alias: alias(),
        challenge: ChallengeBlock {
            receiver_boot_id: [7, 7],
            nonce: [1, 1],
        },
    });
    assert_eq!(sender.answer_for(EndpointId(1), from, T0, solicit), None);
    // The registrant's own CHALLENGE takes the entry, once.
    assert!(
        sender
            .answer_for(EndpointId(1), from, T0, challenge_of(7))
            .is_some()
    );
    assert_eq!(
        sender.answer_for(EndpointId(1), from, T0, challenge_of(7)),
        None
    );
    assert_eq!(sender.counters().refused, 6);
}

/// An SM from an address that registered but was never answered, or from
/// another source than the one answered, takes no slot.
#[test]
fn an_sm_without_an_answered_registration_takes_no_slot() {
    let mut sender = dynamic_sender(4);
    let from: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    let _ = sender.register(EndpointId(1), from, &register_of(7), T0);
    assert_eq!(
        sender.status(EndpointId(1), from, &sm_status([7, 7], 0), T0),
        None
    );
    assert!(
        sender
            .answer_for(EndpointId(1), from, T0, challenge_of(7))
            .is_some()
    );
    let elsewhere: SocketAddr = "10.0.0.10:5000".parse().unwrap();
    assert_eq!(
        sender.status(EndpointId(1), elsewhere, &sm_status([7, 7], 0), T0),
        None
    );
    assert!(!sender.sends_to(EndpointId(1), alias(), elsewhere));
    assert!(!sender.sends_to(EndpointId(1), alias(), from));
    let counters = sender.counters();
    assert_eq!(counters.registrants_joined, 0);
    assert_eq!(counters.sm_unbound, 2);
}

/// Design 3.2 step 6 and the slot at the first SM: a REGISTER with the
/// table full gets one ERR; two registrants answered for the last slot,
/// the second SM gets one ERR and its binding goes; the joined destination
/// is unaffected (SPEC.md §6).
#[test]
fn a_full_table_answers_one_err_at_register_and_at_the_first_sm() {
    let mut sender = dynamic_sender(1);
    let first: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    let second: SocketAddr = "10.0.0.10:5000".parse().unwrap();
    for (from, boot) in [(first, 7), (second, 8)] {
        assert!(
            sender
                .register(EndpointId(1), from, &register_as(boot, boot), T0)
                .is_some()
        );
        assert!(
            sender
                .answer_for(EndpointId(1), from, T0, challenge_of(boot))
                .is_some()
        );
    }
    assert_eq!(
        sender.status(EndpointId(1), first, &sm_as(7, 7), T0 + 1),
        None
    );
    assert_eq!(
        sender.status(EndpointId(1), second, &sm_as(8, 8), T0 + 1),
        Some((second, full_err()))
    );
    assert!(sender.sends_to(EndpointId(1), alias(), first));
    assert!(!sender.sends_to(EndpointId(1), alias(), second));
    let counters = sender.counters();
    assert_eq!(
        (counters.registrants_joined, counters.registrants_full),
        (1, 1)
    );
    // Its binding went: its next SM is unbound, and answers nothing.
    assert_eq!(
        sender.status(EndpointId(1), second, &sm_as(8, 8), T0 + 2),
        None
    );
    assert_eq!(sender.counters().sm_unbound, 1);
    // A new REGISTER with the table full: one ERR, then none within
    // `registration_refusal_interval`.
    let third: SocketAddr = "10.0.0.11:5000".parse().unwrap();
    assert_eq!(
        sender.register(EndpointId(1), third, &register_of(9), T0 + 3),
        Some((third, full_err()))
    );
    assert_eq!(
        sender.register(EndpointId(1), third, &register_of(9), T0 + 4),
        None
    );
    assert_eq!(sender.registration_counters().refused_full, 1);
}

/// A REGISTER for a publication that is not dynamic, for another stream,
/// or for a publication being removed causes nothing.
#[test]
fn a_register_for_no_dynamic_publication_causes_nothing() {
    let from: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    // A unicast publication of the stream.
    let mut unicast = super::sm_sender();
    assert_eq!(
        unicast.register(EndpointId(1), from, &register_of(7), T0),
        None
    );
    assert_eq!(unicast.counters().registers_unknown, 1);
    // Another stream, another endpoint.
    let mut sender = dynamic_sender(4);
    let mut other = register_of(7);
    other.stream_id += 1;
    assert_eq!(sender.register(EndpointId(1), from, &other, T0), None);
    assert_eq!(
        sender.register(EndpointId(2), from, &register_of(7), T0),
        None
    );
    assert_eq!(sender.counters().registers_unknown, 2);
    assert_eq!(sender.registration_counters().registered, 0);
    // Outside the allowlist: the driver's drop counters say why.
    let outside: SocketAddr = "192.168.0.9:5000".parse().unwrap();
    assert_eq!(
        sender.register(EndpointId(1), outside, &register_of(7), T0),
        None
    );
    assert_eq!(sender.registration_counters().dropped_not_allowed, 1);
    // Being removed: no new registrant (driver-network-agents.md §7).
    let _ = sender.begin_remove::<OsSocket>(EndpointId(1), alias(), 3, 0);
    assert_eq!(
        sender.register(EndpointId(1), from, &register_of(7), T0),
        None
    );
    assert_eq!(sender.counters().registers_unknown, 3);
}

/// A REGISTER names only its stream (design 2.5, 3.2 step 1): a second
/// dynamic publication of one stream on one endpoint is refused; another
/// stream, or the same stream on another endpoint, is not.
#[test]
fn a_second_dynamic_publication_of_a_stream_on_an_endpoint_is_refused() {
    let mut sender = dynamic_sender(4);
    let mut again = publication(EndpointId(1));
    again.alias.session_id += 1;
    assert!(!add_dynamic(&mut sender, 4, again));
    let mut other_stream = again;
    other_stream.alias.stream_id += 1;
    assert!(add_dynamic(&mut sender, 4, other_stream));
    assert!(add_dynamic(&mut sender, 4, publication(EndpointId(2))));
}

/// karyos#940 item 4: a REGISTER is charged to a per-address bucket of
/// the registrations, not to the sender's `setup_answer_rate` table: 64
/// REGISTERs from one address on as many ports leave another address's
/// REGISTER and every source's CHALLENGE their rates.
#[test]
fn registers_from_many_ports_of_one_address_leave_others_their_rates() {
    let mut sender = dynamic_sender(4);
    for port in 1..=64u16 {
        let from = SocketAddr::from(([10, 0, 0, 77], port));
        let _ = sender.register(EndpointId(1), from, &register_as(1, 1), T0);
    }
    assert_eq!(sender.registration_counters().dropped_source_rate, 44);
    let legit: SocketAddr = "10.0.0.50:5000".parse().unwrap();
    assert_eq!(join_as(&mut sender, legit, 5, 50, T0 + 1), None);
    assert!(sender.sends_to(EndpointId(1), alias(), legit));
    assert_eq!(sender.registration_counters().dropped_source_rate, 44);
    assert_eq!(sender.session_counters().rate_limited, 0);
}

/// karyos#945 review: registrants' CHALLENGEs are charged to their
/// address's bucket of the registrations, not to the shared
/// `setup_answer_rate` table keyed on address and port. REGISTER and
/// CHALLENGE pairs from 128 address and port pairs (8 addresses, 16
/// ports each), twice that table's 64 entries, leave it free: a new
/// registrant's CHALLENGE and a joined destination's own CHALLENGE are
/// still answered.
#[test]
fn register_and_challenge_pairs_leave_the_answer_rate_table_free() {
    let mut sender = dynamic_sender(8);
    let joined: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    assert_eq!(join_as(&mut sender, joined, 5, 7, T0), None);
    let now = T0 + 2_000_000_000;
    let mut answered = 0;
    for host in 1..=8u8 {
        for port in 1..=16u16 {
            let from = SocketAddr::from(([10, 0, 3, host], port));
            let boot = u64::from(host) * 100 + u64::from(port);
            let _ = sender.register(EndpointId(1), from, &register_as(1000 + boot, boot), now);
            if sender
                .answer_for(EndpointId(1), from, now, challenge_of(boot))
                .is_some()
            {
                answered += 1;
            }
        }
    }
    // Each address has a bucket of 20 for its REGISTERs and another for
    // its CHALLENGEs (karyos#941 item 1): all 16 pairs of each pass.
    assert_eq!(answered, 8 * 16);
    let fresh: SocketAddr = "10.0.0.50:5000".parse().unwrap();
    assert!(
        sender
            .register(EndpointId(1), fresh, &register_as(6, 50), now + 1)
            .is_some()
    );
    assert!(
        sender
            .answer_for(EndpointId(1), fresh, now + 2, challenge_of(50))
            .is_some()
    );
    assert!(
        sender
            .answer_for(EndpointId(1), joined, now + 3, challenge_of(7))
            .is_some()
    );
    assert_eq!(sender.session_counters().rate_sources_full, 0);
    assert_eq!(sender.session_counters().rate_limited, 0);
}

/// karyos#945 review: with the registrations' per-address table full, a
/// registrant's CHALLENGE from an address it cannot track is answered:
/// its ANSWER takes the pending entry an admitted REGISTER made.
#[test]
fn a_registrant_challenge_with_the_rate_table_full_is_answered() {
    let mut config = AgentConfig::default();
    config.registration.sources = 1;
    let mut sender = dynamic_sender_config(&config, 4, &[]);
    let (tracked, untracked): (SocketAddr, SocketAddr) = (
        "10.0.0.9:5000".parse().unwrap(),
        "10.0.0.10:5000".parse().unwrap(),
    );
    // The tracked address takes the one entry of both tables, its
    // REGISTERs' and its CHALLENGEs' (karyos#941 item 1).
    assert_eq!(join_as(&mut sender, tracked, 5, 7, T0), None);
    assert_eq!(join_as(&mut sender, untracked, 6, 8, T0), None);
    assert!(sender.sends_to(EndpointId(1), alias(), untracked));
    assert_eq!(sender.registration_counters().source_rates_full, 2);
}

/// karyos#940 item 7: a registrant's CHALLENGE whose ANSWER its rate
/// refuses takes no pending entry: the next CHALLENGE, once the bucket
/// refills, finds it and is answered. Its rate is its address's CHALLENGE
/// bucket of the registrations, not `setup_answer_rate` (karyos#945
/// review) and not its REGISTERs' bucket (karyos#941 item 1): two
/// REGISTERs a second apart, at a rate of one a second, leave the
/// CHALLENGE bucket one token for two CHALLENGEs.
#[test]
fn a_challenge_refused_for_its_rate_keeps_its_pending_entry() {
    let mut config = AgentConfig::default();
    config.registration.source_rate = 1;
    let mut sender = dynamic_sender_config(&config, 4, &[]);
    let from: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    let second: SocketAddr = "10.0.0.9:5001".parse().unwrap();
    let later = T0 + 1_000_000_000;
    assert!(
        sender
            .register(EndpointId(1), from, &register_as(5, 7), T0)
            .is_some()
    );
    assert!(
        sender
            .register(EndpointId(1), second, &register_as(6, 8), later)
            .is_some()
    );
    assert!(
        sender
            .answer_for(EndpointId(1), from, later, challenge_of(7))
            .is_some()
    );
    assert_eq!(
        sender.answer_for(EndpointId(1), second, later, challenge_of(8)),
        None
    );
    assert_eq!(sender.registration_counters().dropped_challenge_rate, 1);
    assert_eq!(sender.session_counters().rate_limited, 0);
    assert_eq!(sender.registrations.pending().len(), 1);
    assert_eq!(sender.registration_counters().challenged, 1);
    let refilled = later + 1_000_000_000;
    assert!(matches!(
        sender.answer_for(EndpointId(1), second, refilled, challenge_of(8)),
        Some((to, Control::SetupAnswer(_))) if to == second
    ));
    assert!(sender.registrations.pending().is_empty());
    assert_eq!(sender.registration_counters().challenged, 2);
}

/// karyos#941 item 1: REGISTERs from one address cannot spend the
/// CHALLENGE that completes a registration from it. Three subscriptions
/// of one receiving driver share its address; their REGISTERs empty the
/// address's REGISTER bucket, and the CHALLENGE that answers one of them
/// is still answered, from a bucket of its own.
#[test]
fn registers_from_an_address_leave_its_challenge_its_own_bucket() {
    let mut sender = dynamic_sender(4);
    let from: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    assert!(
        sender
            .register(EndpointId(1), from, &register_as(5, 7), T0)
            .is_some()
    );
    // Retries of the same REGISTER spend the address's bucket of 20.
    for _ in 0..40 {
        let _ = sender.register(EndpointId(1), from, &register_as(5, 7), T0);
    }
    assert_eq!(sender.registration_counters().dropped_source_rate, 21);
    assert!(matches!(
        sender.answer_for(EndpointId(1), from, T0, challenge_of(7)),
        Some((to, Control::SetupAnswer(_))) if to == from
    ));
    assert_eq!(sender.registration_counters().dropped_challenge_rate, 0);
}

/// The receiver hands a REGISTER to the sender only for a stream published
/// on its endpoint; an ERR REGISTRATION stays unhandled until the
/// receiver's REGISTER loop (step 3 of karyos#644).
#[test]
fn the_receiver_forwards_a_register_only_for_a_published_stream() {
    use super::super::super::control::ControlItem;

    let (sender, mut role) = receiver_with(AgentConfig::default());
    let (events, _link) = event_ring();
    let source: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    let register = Control::Register(register_of(7));
    intake(&mut role, &events, 1).control(source, register);
    assert_eq!(role.counters().not_published, 1);
    assert!(matches!(sender.from_receiver.try_take(), Ok(None)));
    // Published on endpoint 1 (any session of the stream).
    let (replies, _keep) = super::super::super::ring::ring::<AgentEvent<OsSocket>>(
        std::num::NonZeroUsize::new(4).unwrap(),
    );
    let _ = role.command(AgentCommand::<OsSocket>::AddPublishedAlias {
        reply: replies.reserve().unwrap(),
        endpoint: EndpointId(1),
        alias: alias(),
    });
    intake(&mut role, &events, 2).control(source, register);
    assert!(matches!(
        sender.from_receiver.try_take(),
        Ok(Some(ControlItem::Incoming {
            control: Control::Register(_),
            ..
        }))
    ));
    let before = role.counters();
    intake(&mut role, &events, 3).control(source, full_err());
    assert_eq!(role.counters().unhandled, before.unhandled + 1);
    assert!(matches!(sender.from_receiver.try_take(), Ok(None)));
}

/// A `control-mode=dynamic` subscription key on endpoint 1, registering
/// at `control` (step 3b) as `identity`.
fn subscribe_dynamic(
    role: &mut super::super::ReceiverRole,
    control: SocketAddr,
    identity: Option<crate::membership::ReceiverIdentity>,
) -> std::sync::Arc<crate::sessions::register::RegistrationStatus> {
    subscribe_dynamic_stream(role, alias().stream_id, control, identity)
}

/// [`subscribe_dynamic`] of `stream_id`, returning the registration state
/// its receiver writes.
fn subscribe_dynamic_stream(
    role: &mut super::super::ReceiverRole,
    stream_id: i32,
    control: SocketAddr,
    identity: Option<crate::membership::ReceiverIdentity>,
) -> std::sync::Arc<crate::sessions::register::RegistrationStatus> {
    let (replies, _keep) = super::super::super::ring::ring::<AgentEvent<OsSocket>>(
        std::num::NonZeroUsize::new(4).unwrap(),
    );
    let status = std::sync::Arc::<crate::sessions::register::RegistrationStatus>::default();
    let _ = role.command(AgentCommand::<OsSocket>::AddSubscription {
        reply: replies.reserve().unwrap(),
        endpoint: EndpointId(1),
        stream_id,
        max_term_length: 1 << 20,
        reliable: true,
        multicast: false,
        control_group: None,
        identity,
        conflated: None,
        solicit_from: None,
        register_at: Some((control, status.clone())),
    });
    status
}

/// A SETUP ANNOUNCE of the test stream.
fn announce_of_stream() -> Control {
    Control::SetupAnnounce(karyos_protocol::network::SetupAnnounce {
        alias: alias(),
        identity: identity(),
        term: karyos_protocol::network::TermParams {
            term_length: 65_536,
            initial_term_id: 9,
            mtu: 1408,
        },
        lane_count: 1,
    })
}

/// The CHALLENGEs the receiver posted, drained.
fn challenges_posted(role: &mut super::super::ReceiverRole) -> usize {
    let count = role
        .posted_challenges
        .iter()
        .filter(|(_, control)| matches!(control, Control::Challenge(_)))
        .count();
    role.posted_challenges.clear();
    count
}

/// karyos#941 item 1 and karyos#947: an unanswered dynamic subscription
/// backs off, its interval doubling from `setup_interval` to sixteen times
/// it (1.6 s), and stays at that cap. An ANNOUNCE from its `control`
/// address whose CHALLENGE is never answered is no progress: it leaves the
/// backoff at the cap, so an optional receiver the sender cannot bind does
/// not register at the base cadence for ever.
#[test]
fn an_unanswered_registration_backs_off_to_the_cap_and_an_announce_leaves_it_there() {
    let config = AgentConfig::default();
    let interval = config.setup_interval;
    let (sender, mut role) = receiver_with(config);
    let (events, _link) = event_ring();
    let control: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    let _status = subscribe_dynamic(&mut role, control, receiver_42());
    // Sent at 0, 1, 3, 7, 15, 31 and 47 intervals: the gaps double up to
    // sixteen intervals, then stay there.
    let mut sent_at = Vec::new();
    for step in 0..=48u64 {
        if role.send_registers(&events, T0 + step * interval) == 1 {
            sent_at.push(step);
        }
    }
    assert_eq!(sent_at, [0, 1, 3, 7, 15, 31, 47]);
    let _ = registers_posted(&sender);
    assert_eq!(16 * interval, 1_600_000_000);
    // An ANNOUNCE from `control` at 48, and again before each REGISTER,
    // none of them answered: the REGISTERs stay sixteen intervals apart.
    let mut again = Vec::new();
    for step in 48..=96u64 {
        intake(&mut role, &events, T0 + step * interval).control(control, announce_of_stream());
        if role.send_registers(&events, T0 + step * interval) == 1 {
            again.push(step);
        }
    }
    assert_eq!(again, [63, 79, 95]);
}

/// karyos#941 item 1: keys registering at one `control` address are
/// spread within an interval: after their first REGISTERs, sent
/// together, the second key's next one is due an eighth of an interval
/// after the first's.
#[test]
fn keys_registering_at_one_control_are_staggered() {
    let config = AgentConfig::default();
    let interval = config.setup_interval;
    let (_sender, mut role) = receiver_with(config);
    let (events, _link) = event_ring();
    let control: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    let _first = subscribe_dynamic_stream(&mut role, alias().stream_id, control, receiver_42());
    let _second =
        subscribe_dynamic_stream(&mut role, alias().stream_id + 1, control, receiver_42());
    assert_eq!(role.send_registers(&events, T0), 2);
    assert_eq!(role.send_registers(&events, T0 + interval), 1);
    assert_eq!(
        role.send_registers(&events, T0 + interval + interval / 8 - 1),
        0
    );
    assert_eq!(
        role.send_registers(&events, T0 + interval + interval / 8),
        1
    );
}

/// karyos#941 item 1: REGISTERs draw on their own bucket per `control`
/// address, not on the RSP_SETUP limits: 21 keys due at once send 20 and
/// count one rate limited, and the CHALLENGE answering `control`'s
/// ANNOUNCE still goes.
#[test]
fn registers_leave_the_challenge_its_rsp_setup_bucket() {
    let config = AgentConfig::default();
    let (_sender, mut role) = receiver_with(config);
    let (events, _link) = event_ring();
    let control: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    let _status = subscribe_dynamic(&mut role, control, receiver_42());
    for stream in 1..=20 {
        let _ = subscribe_dynamic_stream(
            &mut role,
            alias().stream_id + stream,
            control,
            receiver_42(),
        );
    }
    assert_eq!(role.send_registers(&events, T0), 20);
    assert_eq!(role.counters().registers_rate_limited, 1);
    assert_eq!(role.counters().registers_unsent, 1);
    role.posted_challenges.clear();
    intake(&mut role, &events, T0 + 1).control(control, announce_of_stream());
    assert_eq!(challenges_posted(&mut role), 1);
    assert_eq!(role.counters().rsp_setup_rate_limited, 0);
}

/// karyos#941 item 5: on a registering key a SETUP ANNOUNCE or ANSWER is
/// taken only from its `control` address, port included: one from any
/// other source is counted and challenges nothing, so no host that
/// reaches the key's port can set up an image of its stream.
#[test]
fn a_registering_key_takes_setup_only_from_its_control_address() {
    use karyos_protocol::network::{ChallengeBlock, Lanes, SetupAnswer};

    let (_sender, mut role) = receiver_with(AgentConfig::default());
    let (events, _link) = event_ring();
    let control: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    let _status = subscribe_dynamic(&mut role, control, receiver_42());
    for stranger in ["10.0.0.10:5000", "10.0.0.9:5001"] {
        let stranger: SocketAddr = stranger.parse().unwrap();
        intake(&mut role, &events, T0).control(stranger, announce_of_stream());
        let answer = Control::SetupAnswer(SetupAnswer {
            alias: alias(),
            identity: identity(),
            term: karyos_protocol::network::TermParams {
                term_length: 65_536,
                initial_term_id: 9,
                mtu: 1408,
            },
            challenge: ChallengeBlock {
                receiver_boot_id: role.sessions.boot_id(),
                nonce: [9, 9],
            },
            joins: Lanes::new(&[0]).unwrap(),
        });
        intake(&mut role, &events, T0).control(stranger, answer);
    }
    assert_eq!(challenges_posted(&mut role), 0);
    assert_eq!(role.counters().setup_not_from_control, 4);
    intake(&mut role, &events, T0 + 1).control(control, announce_of_stream());
    assert_eq!(challenges_posted(&mut role), 1);
    assert_eq!(role.counters().setup_not_from_control, 4);
}

/// karyos#941 item 3: a dynamic subscription's state, which the
/// application reads, follows its registration: `Registering` until its
/// `control` address answers, `Announced` on an ANNOUNCE from there,
/// `Refused` on an ERR REGISTRATION, `Bound` once its image is installed
/// and `Registering` again once the image is gone.
#[test]
fn a_dynamic_subscriptions_state_follows_its_registration() {
    use crate::sessions::register::RegistrationState;

    let config = AgentConfig::default();
    let interval = config.setup_interval;
    let (_sender, mut role) = receiver_with(config);
    let (events, _link) = event_ring();
    let control: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    let status = subscribe_dynamic(&mut role, control, receiver_42());
    assert_eq!(role.send_registers(&events, T0), 1);
    assert_eq!(status.get(), RegistrationState::Registering);
    intake(&mut role, &events, T0 + 1).control(control, full_err());
    assert_eq!(status.get(), RegistrationState::Refused);
    intake(&mut role, &events, T0 + 2).control(control, announce_of_stream());
    assert_eq!(status.get(), RegistrationState::Announced);
    let (image, _) = super::installed_image();
    role.images.push(image);
    let _ = role.send_registers(&events, T0 + interval);
    assert_eq!(status.get(), RegistrationState::Bound);
    role.images.clear();
    let _ = role.send_registers(&events, T0 + 2 * interval);
    assert_eq!(status.get(), RegistrationState::Registering);
}

/// The configured identity of receiver 42.
fn receiver_42() -> Option<crate::membership::ReceiverIdentity> {
    Some(crate::membership::ReceiverIdentity {
        receiver_id: std::num::NonZeroU64::new(42).unwrap(),
        group_tag: 0,
    })
}

/// The REGISTERs `sender` holds from the receiver, each with where it goes.
fn registers_posted(sender: &super::super::SenderRole) -> Vec<(SocketAddr, RspRegister)> {
    use super::super::super::control::ControlItem;

    let mut out = Vec::new();
    while let Ok(Some(item)) = sender.from_receiver.try_take() {
        if let ControlItem::Outgoing {
            endpoint,
            destination,
            control: Control::Register(register),
            ..
        } = item
        {
            assert_eq!(endpoint, EndpointId(1));
            out.push((destination, register));
        }
    }
    out
}

/// A dynamic subscription sends REGISTER to its `control` address at once,
/// then every `setup_interval`, never in between, with this boot's receiver
/// block; it stops once an image of its stream from `control` is bound,
/// and its removal stops it too (design 3.2, step 3b).
#[test]
fn a_dynamic_subscription_registers_every_interval_until_bound() {
    let config = AgentConfig::default();
    let interval = config.setup_interval;
    let (sender, mut role) = receiver_with(config);
    let (events, _link) = event_ring();
    let control: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    // Nothing is due before a dynamic key exists.
    assert_eq!(role.send_registers(&events, T0), 0);
    let _status = subscribe_dynamic(&mut role, control, receiver_42());
    assert_eq!(role.send_registers(&events, T0), 1);
    let posted = registers_posted(&sender);
    assert_eq!(posted.len(), 1);
    let (to, register) = posted[0];
    assert_eq!(to, control);
    assert_eq!(register.stream_id, alias().stream_id);
    assert_eq!(register.receiver.receiver_boot_id, role.sessions.boot_id());
    assert_eq!(register.receiver.receiver_id, 42);
    // Not again within the interval; again at it.
    assert_eq!(role.send_registers(&events, T0 + interval - 1), 0);
    assert_eq!(role.send_registers(&events, T0 + interval), 1);
    assert_eq!(registers_posted(&sender).len(), 1);
    assert_eq!(role.counters().registers_sent, 2);
    // Bound: an image of the stream from `control` stops it.
    let (image, _) = super::installed_image();
    assert_eq!(image.key.source, control);
    role.images.push(image);
    assert_eq!(role.send_registers(&events, T0 + 4 * interval), 0);
    assert!(registers_posted(&sender).is_empty());
    // Gone again: it registers again.
    role.images.clear();
    assert_eq!(role.send_registers(&events, T0 + 5 * interval), 1);
    let _ = registers_posted(&sender);
    // Removed: never again.
    let (replies, _keep) = super::super::super::ring::ring::<AgentEvent<OsSocket>>(
        std::num::NonZeroUsize::new(4).unwrap(),
    );
    let _ = role.command(AgentCommand::<OsSocket>::RemoveSubscription {
        reply: replies.reserve().unwrap(),
        endpoint: EndpointId(1),
        stream_id: alias().stream_id,
    });
    assert_eq!(role.send_registers(&events, T0 + 10 * interval), 0);
}

/// An ERR REGISTRATION from the address a dynamic subscription of its
/// stream registers at is counted, and the subscription keeps registering
/// at its interval; one from anywhere else, or for another stream, is
/// unhandled.
#[test]
fn an_err_registration_is_read_only_from_the_control_address() {
    let config = AgentConfig::default();
    let interval = config.setup_interval;
    let (sender, mut role) = receiver_with(config);
    let (events, _link) = event_ring();
    let control: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    let _status = subscribe_dynamic(&mut role, control, receiver_42());
    assert_eq!(role.send_registers(&events, T0), 1);
    intake(&mut role, &events, T0 + 1).control(control, full_err());
    assert_eq!(role.counters().registration_refusals, 1);
    let other: SocketAddr = "10.0.0.9:5001".parse().unwrap();
    let unhandled = role.counters().unhandled;
    intake(&mut role, &events, T0 + 2).control(other, full_err());
    let other_stream = Control::Registration(Registration {
        stream_id: alias().stream_id + 1,
        reason: RegistrationReason::DestinationsFull,
    });
    intake(&mut role, &events, T0 + 3).control(control, other_stream);
    assert_eq!(role.counters().unhandled, unhandled + 2);
    assert_eq!(role.counters().registration_refusals, 1);
    // Still registering at its interval.
    assert_eq!(role.send_registers(&events, T0 + interval), 1);
    assert_eq!(registers_posted(&sender).len(), 2);
}

/// A sender with one dynamic publication on endpoint 1 admitting
/// `10.0.0.0/8`, at most `max` destinations, `required` its required
/// receiver ids (MD-17).
fn dynamic_sender_with(max: usize, required: &[u64]) -> super::super::SenderRole {
    dynamic_sender_config(&AgentConfig::default(), max, required)
}

/// The destinations removed and not reported yet, with their reasons,
/// each reported at `now` as the duty does: its slot is then free.
fn removals(sender: &mut super::super::SenderRole, now: u64) -> Vec<(SocketAddr, RemovalReason)> {
    let mut removed = Vec::new();
    let outbound = &mut sender.publications[0];
    while let Some(removal) = outbound.removal_unreported() {
        removed.push((removal.destination, removal.reason));
        outbound.removal_reported(removal.destination, now);
    }
    removed
}

/// [`dynamic_sender_with`] under `config`.
fn dynamic_sender_config(
    config: &AgentConfig,
    max: usize,
    required: &[u64],
) -> super::super::SenderRole {
    let (mut sender, _receiver) = super::super::roles(config).unwrap();
    let (replies, _keep) = super::super::super::ring::ring::<AgentEvent<OsSocket>>(
        std::num::NonZeroUsize::new(4).unwrap(),
    );
    let publication = publication(EndpointId(1));
    let (mut outbound, _log) = super::super::super::data::testing::outbound(
        publication.endpoint,
        publication.alias,
        "10.0.0.2:4000".parse().unwrap(),
        publication.term,
        1,
        false,
    );
    outbound
        .set_registration(max, lan().with_required(required).unwrap())
        .unwrap();
    // The publication's roles name the same required receiver ids as its
    // registration policy, as `net/publish.rs` wires both: `AddPublication`
    // builds the publication's `Membership` from them.
    let added = sender.command(AgentCommand::<OsSocket>::AddPublication {
        reply: replies.reserve().unwrap(),
        publication,
        outbound,
        guard: None,
        roles: Some(Box::new(crate::membership::PublicationRoles {
            strategy: crate::membership::Strategy::Min,
            required: required.to_vec(),
            tags: Vec::new(),
        })),
    });
    assert!(matches!(
        added,
        Some((_, AgentEvent::PublicationAdded { .. }))
    ));
    sender
}

fn register_as(receiver_id: u64, boot: u64) -> RspRegister {
    let mut register = register_of(boot);
    register.receiver.receiver_id = receiver_id;
    register
}

fn sm_as(receiver_id: u64, boot: u64) -> karyos_protocol::network::StatusMessage {
    let mut status = sm_status([boot, boot], 0);
    status.receiver.receiver_id = receiver_id;
    status
}

/// REGISTER, CHALLENGE and first SM of `receiver_id` with boot `boot` from
/// `from` at `now`; what the SM answered.
fn join_as(
    sender: &mut super::super::SenderRole,
    from: SocketAddr,
    receiver_id: u64,
    boot: u64,
    now: u64,
) -> Option<(SocketAddr, Control)> {
    let announced = sender.register(EndpointId(1), from, &register_as(receiver_id, boot), now);
    assert!(
        matches!(announced, Some((to, Control::SetupAnnounce(_))) if to == from),
        "{announced:?}"
    );
    let answered = sender.answer_for(EndpointId(1), from, now, challenge_of(boot));
    assert!(
        matches!(answered, Some((_, Control::SetupAnswer(_)))),
        "{answered:?}"
    );
    sender.status(EndpointId(1), from, &sm_as(receiver_id, boot), now + 1)
}

/// MD-17: optional registrants fill only the optional quota; a required
/// receiver id still joins, in its reserved slot.
#[test]
fn a_required_id_joins_its_reserved_slot_after_optional_registrants_fill_their_quota() {
    let mut sender = dynamic_sender_with(2, &[42]);
    let (a, b, c): (SocketAddr, SocketAddr, SocketAddr) = (
        "10.0.0.9:5000".parse().unwrap(),
        "10.0.0.10:5000".parse().unwrap(),
        "10.0.0.11:5000".parse().unwrap(),
    );
    assert_eq!(join_as(&mut sender, a, 1, 7, T0), None);
    // The optional quota (2 minus 1 required) is taken: one ERR.
    assert_eq!(
        sender.register(EndpointId(1), b, &register_as(2, 8), T0 + 10),
        Some((b, full_err()))
    );
    assert_eq!(join_as(&mut sender, c, 42, 9, T0 + 20), None);
    assert!(sender.sends_to(EndpointId(1), alias(), a));
    assert!(sender.sends_to(EndpointId(1), alias(), c));
    assert_eq!(sender.counters().registrants_joined, 2);
    assert_eq!(sender.registration_counters().refused_full, 1);
}

/// More required receiver ids than `max_destinations` is refused at
/// creation (design 3.5).
#[test]
fn more_required_ids_than_destinations_is_refused() {
    let publication = publication(EndpointId(1));
    let (mut outbound, _log) = super::super::super::data::testing::outbound(
        publication.endpoint,
        publication.alias,
        "10.0.0.2:4000".parse().unwrap(),
        publication.term,
        1,
        false,
    );
    assert_eq!(
        outbound.set_registration(1, lan().with_required(&[1, 2]).unwrap()),
        Err(super::super::super::data::OutboundError::Routes)
    );
}

/// Design 3.2 step 4: an optional `receiver_id` back with a new boot id at
/// another endpoint replaces its old membership at its first SM, and the
/// old destination is removed (reason `restarted`).
#[test]
fn a_restarted_optional_receiver_replaces_its_old_destination() {
    let mut sender = dynamic_sender(4);
    let (a, b): (SocketAddr, SocketAddr) = (
        "10.0.0.9:5000".parse().unwrap(),
        "10.0.0.10:5000".parse().unwrap(),
    );
    let quiet = sender.registrations.config().move_quiet;
    assert_eq!(join_as(&mut sender, a, 5, 7, T0), None);
    // Its last SM was at T0 + 1: quiet from T0 + 1 + quiet.
    let restart = T0 + 1 + quiet;
    assert_eq!(join_as(&mut sender, b, 5, 8, restart), None);
    assert!(!sender.sends_to(EndpointId(1), alias(), a));
    assert!(sender.sends_to(EndpointId(1), alias(), b));
    assert_eq!(
        removals(&mut sender, restart),
        [(a, RemovalReason::Restarted)]
    );
    let counters = sender.counters();
    assert_eq!(counters.registrants_restarted, 1);
    assert_eq!(counters.registrants_joined, 2);
    // At the same endpoint the destination stays, with the new receiver.
    let again = restart + 2 + quiet;
    assert!(
        sender
            .register(EndpointId(1), b, &register_as(5, 9), again)
            .is_some()
    );
    assert!(
        sender
            .answer_for(EndpointId(1), b, again, challenge_of(9))
            .is_some()
    );
    assert_eq!(
        sender.status(EndpointId(1), b, &sm_as(5, 9), again + 1),
        None
    );
    assert!(sender.sends_to(EndpointId(1), alias(), b));
    assert!(removals(&mut sender, again).is_empty());
    assert_eq!(sender.counters().registrants_restarted, 2);
}

/// MD-19: the same receiver block at another endpoint is a
/// `duplicate_receiver` while its old destination took an SM within
/// `destination_move_quiet`, and a move after it.
#[test]
fn an_optional_receiver_moves_only_after_destination_move_quiet() {
    let mut sender = dynamic_sender(4);
    let quiet = sender.registrations.config().move_quiet;
    let (a, b): (SocketAddr, SocketAddr) = (
        "10.0.0.9:5000".parse().unwrap(),
        "10.0.0.10:5000".parse().unwrap(),
    );
    assert_eq!(join_as(&mut sender, a, 5, 7, T0), None);
    // Its last SM was at T0 + 1.
    assert_eq!(
        sender.register(EndpointId(1), b, &register_as(5, 7), T0 + quiet),
        None
    );
    assert_eq!(sender.registration_counters().duplicate_receiver, 1);
    assert_eq!(join_as(&mut sender, b, 5, 7, T0 + 1 + quiet), None);
    assert!(!sender.sends_to(EndpointId(1), alias(), a));
    assert!(sender.sends_to(EndpointId(1), alias(), b));
    assert_eq!(
        removals(&mut sender, T0 + 1 + quiet),
        [(a, RemovalReason::Moved)]
    );
    assert_eq!(sender.counters().registrants_moved, 1);
    // The membership moved: its next SM from the new endpoint is taken.
    let before = sender.counters().sm_accepted;
    assert_eq!(
        sender.status(EndpointId(1), b, &sm_as(5, 7), T0 + 2 + quiet),
        None
    );
    assert_eq!(sender.counters().sm_accepted, before + 1);
}

/// A required receiver id is never restarted nor moved (owner decision
/// M4, MD-19): its REGISTER with a new boot id, or at a new port, is
/// dropped; and a destination at the source with the same receiver block
/// drops its REGISTER too.
#[test]
fn a_required_receiver_never_restarts_nor_moves() {
    let mut sender = dynamic_sender_with(4, &[42]);
    let quiet = sender.registrations.config().move_quiet;
    let (a, b): (SocketAddr, SocketAddr) = (
        "10.0.0.9:5000".parse().unwrap(),
        "10.0.0.10:5000".parse().unwrap(),
    );
    assert_eq!(join_as(&mut sender, a, 42, 7, T0), None);
    let late = T0 + 10 * quiet;
    assert_eq!(
        sender.register(EndpointId(1), b, &register_as(42, 8), late),
        None
    );
    assert_eq!(
        sender.register(EndpointId(1), b, &register_as(42, 7), late),
        None
    );
    assert_eq!(
        sender.register(EndpointId(1), a, &register_as(42, 7), late),
        None
    );
    let counters = sender.registration_counters();
    assert_eq!(counters.dropped_boot_changed, 1);
    assert_eq!(counters.duplicate_receiver, 1);
    assert_eq!(counters.dropped_bound, 1);
    assert!(sender.sends_to(EndpointId(1), alias(), a));
    assert!(!sender.sends_to(EndpointId(1), alias(), b));
}

/// Design 3.7, 8: a registrant whose receiver sends no SM for
/// `image_liveness_timeout` loses its slot.
#[test]
fn a_silent_registrant_is_removed() {
    let mut sender = dynamic_sender(4);
    let a: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    assert_eq!(join_as(&mut sender, a, 5, 7, T0), None);
    let late = T0 + 1 + sender.confirmed_timeout;
    let stranger: SocketAddr = "10.0.0.20:5000".parse().unwrap();
    let _ = sender.status(EndpointId(1), stranger, &sm_as(6, 6), late);
    assert!(!sender.sends_to(EndpointId(1), alias(), a));
    assert_eq!(removals(&mut sender, late), [(a, RemovalReason::Timeout)]);
    assert_eq!(sender.counters().registrants_timed_out, 1);
}

/// A receiver id is configured and stable across restarts (design 2.3;
/// multicast-flow-control.md M1): a dynamic key with no identity sends no
/// REGISTER, never one naming an id of its own making, and counts each
/// due one unsent.
#[test]
fn a_dynamic_key_without_an_identity_sends_no_register() {
    let config = AgentConfig::default();
    let interval = config.setup_interval;
    let (sender, mut role) = receiver_with(config);
    let (events, _link) = event_ring();
    let control: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    let _status = subscribe_dynamic(&mut role, control, None);
    assert_eq!(role.send_registers(&events, T0), 0);
    assert_eq!(role.send_registers(&events, T0 + interval - 1), 0);
    assert_eq!(role.send_registers(&events, T0 + interval), 0);
    assert!(registers_posted(&sender).is_empty());
    assert_eq!(role.counters().registers_unsent, 2);
    assert_eq!(role.counters().registers_sent, 0);
}

/// Design 3.6, 9.2: a dynamic publication never announces periodically to
/// its destinations, live or not; a manual one keeps announcing to one
/// with no live member.
#[test]
fn a_dynamic_destination_gets_no_periodic_announce() {
    use crate::agents::data::DestinationChange;

    let publication = publication(EndpointId(1));
    let make = || {
        super::super::super::data::testing::outbound(
            publication.endpoint,
            publication.alias,
            "10.0.0.2:4000".parse().unwrap(),
            publication.term,
            1,
            false,
        )
    };
    let (mut dynamic, _log) = make();
    dynamic.set_registration(4, lan()).unwrap();
    let joined = dynamic.join_registrant("10.0.0.9:5000".parse().unwrap(), (5, false), T0, 0);
    assert_eq!(joined, DestinationChange::Added);
    assert!(!dynamic.every_destination_live());
    assert!(!dynamic.announces_destinations());
    let (mut manual, _log) = make();
    manual
        .set_destinations(4, &["10.0.0.9:5000".parse().unwrap()], &[], Some(true))
        .unwrap();
    assert!(manual.announces_destinations());
}

/// MD-17 at the table: optional registrants get `max_destinations` minus
/// the required ids; a required id joins past them.
#[test]
fn the_optional_quota_leaves_the_reserved_slots_free() {
    use crate::agents::data::DestinationChange;
    use crate::sessions::register::Capacity;

    let publication = publication(EndpointId(1));
    let (mut outbound, _log) = super::super::super::data::testing::outbound(
        publication.endpoint,
        publication.alias,
        "10.0.0.2:4000".parse().unwrap(),
        publication.term,
        1,
        false,
    );
    outbound
        .set_registration(3, lan().with_required(&[42, 43]).unwrap())
        .unwrap();
    let at = |last: u8| SocketAddr::from(([10, 0, 0, last], 5000));
    assert_eq!(outbound.registration_capacity(), Capacity::Free);
    assert_eq!(
        outbound.join_registrant(at(1), (1, false), T0, 0),
        DestinationChange::Added
    );
    assert_eq!(outbound.registration_capacity(), Capacity::Full);
    assert_eq!(
        outbound.join_registrant(at(2), (2, false), T0, 0),
        DestinationChange::Full
    );
    for last in [3, 4] {
        assert_eq!(
            outbound.join_registrant(at(last), (u64::from(last) + 39, true), T0, 0),
            DestinationChange::Added
        );
    }
    // A required destination is never retired as a registrant.
    assert!(!outbound.retire_registrant(at(3), crate::agents::data::RemovalReason::Moved, T0));
    assert!(outbound.retire_registrant(at(1), crate::agents::data::RemovalReason::Moved, T0));
}

fn required_targets(sender: &super::super::SenderRole) -> Vec<SocketAddr> {
    sender.publications[0].required_destinations().collect()
}

/// karyos#940 item 1, at the role: two spoofed REGISTERs from a required
/// receiver's own address, on other ports, do not keep its REGISTER out
/// at any of its retries.
#[test]
fn spoofed_registers_from_a_required_receivers_address_do_not_lock_it_out() {
    let mut sender = dynamic_sender_with(4, &[42]);
    let real: SocketAddr = "10.0.0.42:5000".parse().unwrap();
    let interval = AgentConfig::default().setup_interval;
    let join_timeout = sender.registrations.config().join_timeout;
    // The spoofer re-arms its two entries at each `join_timeout`; the
    // receiver retries every `setup_interval` for two of them.
    for retry in 0..2 * join_timeout / interval {
        let now = T0 + retry * interval;
        if (retry * interval) % join_timeout == 0 {
            for port in [1u16, 2] {
                let spoofed = SocketAddr::from(([10, 0, 0, 42], port));
                assert!(
                    sender
                        .register(
                            EndpointId(1),
                            spoofed,
                            &register_as(900 + u64::from(port), retry + 1),
                            now,
                        )
                        .is_some()
                );
            }
        }
        assert!(matches!(
            sender.register(EndpointId(1), real, &register_as(42, 4242), now + 1),
            Some((to, Control::SetupAnnounce(_))) if to == real
        ));
    }
    assert_eq!(
        sender.registration_counters().dropped_source_pending_full,
        0
    );
    // Its CHALLENGE finds its entry, and it joins its reserved slot.
    let late = T0 + 2 * join_timeout;
    assert!(
        sender
            .answer_for(EndpointId(1), real, late, challenge_of(4242))
            .is_some()
    );
    assert_eq!(
        sender.status(EndpointId(1), real, &sm_as(42, 4242), late + 1),
        None
    );
    assert_eq!(required_targets(&sender), [real]);
}

/// karyos#940 item 2: the first SM must name the receiver block of the
/// REGISTER whose entry its CHALLENGE took. An optional REGISTER followed
/// by an SM naming a required id, or another optional id, takes no slot.
#[test]
fn a_first_sm_naming_another_receiver_than_its_register_takes_no_slot() {
    let mut sender = dynamic_sender_with(4, &[42]);
    let a: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    for (n, claimed) in [42u64, 2].into_iter().enumerate() {
        let now = T0 + 10 * n as u64;
        assert!(
            sender
                .register(EndpointId(1), a, &register_as(1, 7 + n as u64), now)
                .is_some()
        );
        assert!(
            sender
                .answer_for(EndpointId(1), a, now, challenge_of(7 + n as u64))
                .is_some()
        );
        assert_eq!(
            sender.status(EndpointId(1), a, &sm_as(claimed, 7 + n as u64), now + 1),
            None
        );
        assert!(!sender.sends_to(EndpointId(1), alias(), a));
    }
    assert!(required_targets(&sender).is_empty());
    let counters = sender.counters();
    assert_eq!(counters.registrants_refused, 2);
    assert_eq!(counters.registrants_joined, 0);
    // The real required receiver then joins its reserved slot.
    let real: SocketAddr = "10.0.0.42:5000".parse().unwrap();
    assert_eq!(join_as(&mut sender, real, 42, 4242, T0 + 100), None);
    assert_eq!(required_targets(&sender), [real]);
}

/// REGISTER, CHALLENGE and first SM of `receiver_id` with boot `boot` from
/// `from` at `now`, each step only if the one before went through; what
/// the SM answered, `None` also when an earlier step was refused.
fn try_join(
    sender: &mut super::super::SenderRole,
    from: SocketAddr,
    receiver_id: u64,
    boot: u64,
    now: u64,
) -> Option<(SocketAddr, Control)> {
    sender.register(EndpointId(1), from, &register_as(receiver_id, boot), now)?;
    sender.answer_for(EndpointId(1), from, now, challenge_of(boot))?;
    sender.status(EndpointId(1), from, &sm_as(receiver_id, boot), now + 1)
}

/// The admission of the publication's `Membership` at `now`.
fn admission(sender: &super::super::SenderRole, now: u64) -> crate::membership::Admission {
    sender.publications[0].membership().unwrap().admission(now)
}

/// karyos#940 item 2: one allowlisted host cannot turn the table into
/// required targets. Joining as required id 42 from port after port, and
/// renaming each slot by a REGISTER at its endpoint as an optional id,
/// leaves one required target, and the optional quota free.
#[test]
fn a_required_id_holds_at_most_one_slot() {
    let mut sender = dynamic_sender_with(4, &[42]);
    let at = |port: u16| SocketAddr::from(([10, 0, 0, 9], port));
    let mut now = T0;
    for port in 1..=4u16 {
        let boot = u64::from(port);
        let _ = try_join(&mut sender, at(port), 42, boot, now);
        now += 10;
        // A REGISTER at the required slot's endpoint as another id: its
        // first SM is refused, the slot stays 42's.
        let other = 1000 + u64::from(port);
        let _ = try_join(&mut sender, at(1), other, 1, now);
        now += 10;
        assert_eq!(required_targets(&sender), [at(1)], "port {port}");
    }
    assert!(removals(&mut sender, now).is_empty());
    // The three optional slots are free for registrants.
    for last in 50..53u8 {
        let legit = SocketAddr::from(([10, 0, 0, last], 5000));
        assert_eq!(
            join_as(&mut sender, legit, u64::from(last), u64::from(last), now),
            None
        );
        assert!(sender.sends_to(EndpointId(1), alias(), legit));
    }
}

/// karyos#945 review: a required receiver id holds one slot for the
/// publication's incarnation (design 3.2 step 4, 4.6, M5). Back on a new
/// port after its binding expired, with a new boot id or the same one, it
/// is refused: its old slot stays, nothing is removed, and its
/// `Membership`, which holds it `LostRequired`, and the destination table
/// agree. Whether such a return may replace its slot is open in
/// quantstratum-docs#829.
#[test]
fn a_required_receiver_back_on_another_port_is_refused_while_its_membership_holds_it_lost() {
    use crate::membership::Admission;

    for boot in [8, 7] {
        let mut sender = dynamic_sender_with(4, &[42]);
        let (a, b): (SocketAddr, SocketAddr) = (
            "10.0.0.9:5000".parse().unwrap(),
            "10.0.0.9:5001".parse().unwrap(),
        );
        assert_eq!(join_as(&mut sender, a, 42, 7, T0), None);
        assert_eq!(admission(&sender, T0 + 2), Admission::Open);
        let late = T0 + 2 * sender.confirmed_timeout;
        sender.expire_bindings(late);
        assert_eq!(sender.counters().registrants_timed_out, 0);
        assert_eq!(admission(&sender, late), Admission::LostRequired);
        let joined = sender.counters().registrants_joined;
        assert_eq!(try_join(&mut sender, b, 42, boot, late), None);
        assert_eq!(sender.counters().registrants_joined, joined, "boot {boot}");
        assert_eq!(required_targets(&sender), [a]);
        assert!(!sender.sends_to(EndpointId(1), alias(), b));
        assert!(removals(&mut sender, late).is_empty());
        assert_eq!(admission(&sender, late + 2), Admission::LostRequired);
    }
}

/// karyos#945 review: a required id never takes a second slot, so it
/// takes no slot of the optional quota either, even with the table full.
#[test]
fn a_required_id_never_takes_a_second_slot() {
    use crate::agents::data::DestinationChange;
    use crate::sessions::register::Capacity;

    let publication = publication(EndpointId(1));
    let (mut outbound, _log) = super::super::super::data::testing::outbound(
        publication.endpoint,
        publication.alias,
        "10.0.0.2:4000".parse().unwrap(),
        publication.term,
        1,
        false,
    );
    outbound
        .set_registration(2, lan().with_required(&[42]).unwrap())
        .unwrap();
    let at = |last: u8| SocketAddr::from(([10, 0, 0, last], 5000));
    assert_eq!(
        outbound.join_registrant(at(1), (1, false), T0, 0),
        DestinationChange::Added
    );
    assert_eq!(
        outbound.join_registrant(at(2), (42, true), T0, 0),
        DestinationChange::Added
    );
    assert_eq!(
        outbound.join_registrant(at(3), (42, true), T0, 0),
        DestinationChange::Required
    );
    assert!(outbound.removal_unreported().is_none());
    assert_eq!(outbound.registration_capacity(), Capacity::Full);
    assert_eq!(
        outbound.required_destinations().collect::<Vec<_>>(),
        [at(2)]
    );
}

/// karyos#945 review: an SM refused at a slot already held (a bare
/// CHALLENGE at the slot's own endpoint, then an SM naming another
/// receiver id, or a REGISTER as another id there) leaves the binding
/// that holds the slot unconfirmed, so the slot retires at its timeout
/// (reason `timeout`) and the optional quota is free again.
#[test]
fn a_refused_sm_at_a_held_slot_retires_the_slot_at_its_timeout() {
    let mut sender = dynamic_sender(4);
    let at = |port: u16| SocketAddr::from(([10, 0, 0, 9], port));
    let mut now = T0;
    for port in 1..=4u16 {
        let boot = u64::from(port);
        assert_eq!(join_as(&mut sender, at(port), 100 + boot, boot, now), None);
        now += 10;
        if port % 2 == 0 {
            assert!(
                sender
                    .answer_for(EndpointId(1), at(port), now, challenge_of(boot))
                    .is_some()
            );
        } else {
            assert!(
                sender
                    .register(EndpointId(1), at(port), &register_as(7777, boot), now)
                    .is_some()
            );
            assert!(
                sender
                    .answer_for(EndpointId(1), at(port), now, challenge_of(boot))
                    .is_some()
            );
        }
        assert_eq!(
            sender.status(EndpointId(1), at(port), &sm_as(7777, boot), now + 1),
            None
        );
        now += 10;
    }
    assert_eq!(sender.counters().registrants_refused, 4);
    let late = now + sender.unconfirmed_timeout;
    sender.expire_bindings(late);
    let mut removed = removals(&mut sender, late);
    removed.sort_by_key(|(address, _)| *address);
    assert_eq!(
        removed,
        (1..=4u16)
            .map(|port| (at(port), RemovalReason::Timeout))
            .collect::<Vec<_>>()
    );
    assert_eq!(sender.counters().registrants_timed_out, 4);
    let legit: SocketAddr = "10.0.0.50:5000".parse().unwrap();
    assert_eq!(join_as(&mut sender, legit, 5, 50, late + 10), None);
}

/// karyos#945 review: the slot's own receiver confirms its binding again
/// after a refused SM at its slot, and keeps the slot.
#[test]
fn a_refused_sm_at_a_held_slot_leaves_its_own_receiver_the_slot() {
    let mut sender = dynamic_sender(4);
    let a: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    assert_eq!(join_as(&mut sender, a, 5, 7, T0), None);
    assert!(
        sender
            .answer_for(EndpointId(1), a, T0 + 10, challenge_of(7))
            .is_some()
    );
    assert_eq!(sender.status(EndpointId(1), a, &sm_as(6, 7), T0 + 11), None);
    assert_eq!(sender.counters().registrants_refused, 1);
    assert_eq!(sender.status(EndpointId(1), a, &sm_as(5, 7), T0 + 12), None);
    let late = T0 + 12 + sender.unconfirmed_timeout;
    sender.expire_bindings(late);
    assert!(removals(&mut sender, late).is_empty());
    assert!(sender.sends_to(EndpointId(1), alias(), a));
}

/// karyos#945 review: a binding answered again keeps its receiver id
/// until its next SM. A REGISTER naming that live required id from
/// another host, after a CHALLENGE from the live receiver's endpoint
/// with its boot id, still meets that id's binding (`boot_changed`): the
/// required slot stays where it is.
#[test]
fn a_reset_binding_still_holds_its_receiver_id() {
    let mut sender = dynamic_sender_with(4, &[42]);
    let real: SocketAddr = "10.0.0.42:5000".parse().unwrap();
    let other: SocketAddr = "10.0.0.66:1".parse().unwrap();
    assert_eq!(join_as(&mut sender, real, 42, 4242, T0), None);
    let now = T0 + 5_000_000;
    assert_eq!(
        sender.status(EndpointId(1), real, &sm_as(42, 4242), now),
        None
    );
    assert!(
        sender
            .answer_for(EndpointId(1), real, now + 2, challenge_of(4242))
            .is_some()
    );
    assert_eq!(
        sender.register(EndpointId(1), other, &register_as(42, 666), now + 3),
        None
    );
    assert_eq!(sender.registration_counters().dropped_boot_changed, 1);
    assert_eq!(required_targets(&sender), [real]);
    assert!(removals(&mut sender, now + 4).is_empty());
}

/// karyos#945 review: a binding answered again keeps its optional
/// receiver id until its next SM. A registrant that registered that id
/// before, from another endpoint, is refused at its first SM: the id
/// takes no second slot.
#[test]
fn a_reset_binding_keeps_its_optional_id_from_a_second_slot() {
    let mut sender = dynamic_sender(4);
    let (a, b): (SocketAddr, SocketAddr) = (
        "10.0.0.9:5000".parse().unwrap(),
        "10.0.0.10:5000".parse().unwrap(),
    );
    assert!(
        sender
            .register(EndpointId(1), b, &register_as(5, 8), T0)
            .is_some()
    );
    assert_eq!(join_as(&mut sender, a, 5, 7, T0), None);
    assert!(
        sender
            .answer_for(EndpointId(1), a, T0 + 2, challenge_of(7))
            .is_some()
    );
    assert!(
        sender
            .answer_for(EndpointId(1), b, T0 + 3, challenge_of(8))
            .is_some()
    );
    assert_eq!(sender.status(EndpointId(1), b, &sm_as(5, 8), T0 + 4), None);
    assert!(!sender.sends_to(EndpointId(1), alias(), b));
    assert!(sender.sends_to(EndpointId(1), alias(), a));
    assert_eq!(sender.counters().registrants_refused, 1);
}

/// Owner decision M4, MD-19: a required receiver id is never restarted,
/// even at its own slot's endpoint with its old binding quiet. A REGISTER
/// with a new boot id that was pending before the id joined is refused at
/// its first SM.
#[test]
fn a_required_id_is_never_restarted_at_its_slot() {
    let mut sender = dynamic_sender_with(4, &[42]);
    let a: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    assert!(
        sender
            .register(EndpointId(1), a, &register_as(42, 8), T0)
            .is_some()
    );
    assert_eq!(join_as(&mut sender, a, 42, 7, T0), None);
    let later = T0 + 100_000_000;
    assert!(
        sender
            .answer_for(EndpointId(1), a, later, challenge_of(8))
            .is_some()
    );
    assert_eq!(
        sender.status(EndpointId(1), a, &sm_as(42, 8), later + 1),
        None
    );
    assert_eq!(sender.counters().registrants_refused, 1);
    assert_eq!(sender.counters().registrants_restarted, 0);
    assert_eq!(required_targets(&sender), [a]);
}

/// karyos#945 review: a host with an optional slot at `y` that registers
/// and is answered at another port `x` cannot send that binding's first
/// SM from `y` naming a required id: it is unbound, the binding learns no
/// receiver id, and the real required receiver still registers and joins.
#[test]
fn a_first_sm_from_another_source_than_its_answer_is_unbound() {
    let mut sender = dynamic_sender_with(4, &[42]);
    let (y, x, real): (SocketAddr, SocketAddr, SocketAddr) = (
        "10.0.0.9:5000".parse().unwrap(),
        "10.0.0.9:5001".parse().unwrap(),
        "10.0.0.42:5000".parse().unwrap(),
    );
    assert_eq!(join_as(&mut sender, y, 1, 7, T0), None);
    assert!(
        sender
            .register(EndpointId(1), x, &register_as(2, 8), T0 + 10)
            .is_some()
    );
    assert!(
        sender
            .answer_for(EndpointId(1), x, T0 + 10, challenge_of(8))
            .is_some()
    );
    let unbound = sender.counters().sm_unbound;
    assert_eq!(
        sender.status(EndpointId(1), y, &sm_as(42, 8), T0 + 11),
        None
    );
    assert_eq!(sender.counters().sm_unbound, unbound + 1);
    assert!(
        sender
            .bindings
            .iter()
            .all(|binding| binding.receiver_id != Some(42))
    );
    assert_eq!(join_as(&mut sender, real, 42, 4242, T0 + 20), None);
    assert_eq!(required_targets(&sender), [real]);
}

/// karyos#945 review: two required ids each hold their own slot. The
/// second's join, and the first's refused return on a new port, leave the
/// other's slot in place.
#[test]
fn a_required_id_leaves_another_required_ids_slot_in_place() {
    let mut sender = dynamic_sender_with(4, &[42, 43]);
    let (a, b, c): (SocketAddr, SocketAddr, SocketAddr) = (
        "10.0.0.42:5000".parse().unwrap(),
        "10.0.0.43:5000".parse().unwrap(),
        "10.0.0.42:5001".parse().unwrap(),
    );
    assert_eq!(join_as(&mut sender, a, 42, 1, T0), None);
    assert_eq!(join_as(&mut sender, b, 43, 2, T0 + 10), None);
    let late = T0 + 2 * sender.confirmed_timeout;
    sender.expire_bindings(late);
    let _ = try_join(&mut sender, c, 42, 3, late);
    assert!(removals(&mut sender, late).is_empty());
    let mut held = required_targets(&sender);
    held.sort();
    assert_eq!(held, [a, b]);
}

/// karyos#940 item 3: a REGISTER naming a bound optional `receiver_id`
/// with a new boot id while its binding took an SM within
/// `destination_move_quiet` is a `duplicate_receiver`, and the live
/// receiver keeps its slot and its address stays out of quarantine.
#[test]
fn a_live_optional_receiver_is_not_evicted_by_its_id() {
    let mut sender = dynamic_sender(4);
    let quiet = sender.registrations.config().move_quiet;
    let victim: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    let attacker: SocketAddr = "10.0.0.66:1".parse().unwrap();
    assert_eq!(join_as(&mut sender, victim, 5, 7, T0), None);
    // Its last SM was at T0 + 1: one before the quiet time ends.
    let now = T0 + quiet;
    assert_eq!(
        sender.register(EndpointId(1), attacker, &register_as(5, 666), now),
        None
    );
    assert_eq!(sender.registration_counters().duplicate_receiver, 1);
    assert!(sender.sends_to(EndpointId(1), alias(), victim));
    assert!(removals(&mut sender, now).is_empty());
    // Its next SM is still taken.
    let before = sender.counters().sm_accepted;
    assert_eq!(
        sender.status(EndpointId(1), victim, &sm_as(5, 7), now),
        None
    );
    assert_eq!(sender.counters().sm_accepted, before + 1);
}

/// karyos#940 item 3, at the first SM: a registrant admitted while the
/// old binding was quiet is refused if that binding took an SM since,
/// within `destination_move_quiet`.
#[test]
fn a_restart_is_refused_at_its_first_sm_while_the_old_binding_is_live() {
    let mut sender = dynamic_sender(4);
    let quiet = sender.registrations.config().move_quiet;
    let victim: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    let attacker: SocketAddr = "10.0.0.66:1".parse().unwrap();
    assert_eq!(join_as(&mut sender, victim, 5, 7, T0), None);
    let now = T0 + 1 + quiet;
    assert!(
        sender
            .register(EndpointId(1), attacker, &register_as(5, 666), now)
            .is_some()
    );
    assert!(
        sender
            .answer_for(EndpointId(1), attacker, now, challenge_of(666))
            .is_some()
    );
    assert_eq!(
        sender.status(EndpointId(1), victim, &sm_as(5, 7), now + 1),
        None
    );
    assert_eq!(
        sender.status(EndpointId(1), attacker, &sm_as(5, 666), now + 2),
        None
    );
    assert!(sender.sends_to(EndpointId(1), alias(), victim));
    assert!(!sender.sends_to(EndpointId(1), alias(), attacker));
    assert_eq!(sender.counters().registrants_refused, 1);
    assert_eq!(sender.counters().registrants_restarted, 0);
}

/// A required id is refused at its first SM while another binding holds
/// it, however quiet that binding is (owner decision M4): a REGISTER
/// admitted before the real receiver bound cannot restart it later.
#[test]
fn a_required_id_is_refused_at_its_first_sm_while_another_binding_holds_it() {
    let mut sender = dynamic_sender_with(4, &[42]);
    let quiet = sender.registrations.config().move_quiet;
    let real: SocketAddr = "10.0.0.42:5000".parse().unwrap();
    let other: SocketAddr = "10.0.0.66:1".parse().unwrap();
    assert!(
        sender
            .register(EndpointId(1), other, &register_as(42, 666), T0)
            .is_some()
    );
    assert_eq!(join_as(&mut sender, real, 42, 4242, T0), None);
    let later = T0 + 10 * quiet;
    assert!(
        sender
            .answer_for(EndpointId(1), other, later, challenge_of(666))
            .is_some()
    );
    assert_eq!(
        sender.status(EndpointId(1), other, &sm_as(42, 666), later + 1),
        None
    );
    assert_eq!(required_targets(&sender), [real]);
    assert!(removals(&mut sender, later).is_empty());
    assert_eq!(sender.counters().registrants_refused, 1);
}

/// karyos#940 item 6 (design 3.7): a registrant removed at its timeout
/// gets no ANNOUNCE while its address is in quarantine; after it, it
/// registers and joins again.
#[test]
fn a_registrant_in_its_quarantine_gets_no_announce() {
    let mut sender = dynamic_sender(4);
    let a: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    assert_eq!(join_as(&mut sender, a, 5, 7, T0), None);
    let late = T0 + 1 + sender.confirmed_timeout;
    sender.expire_bindings(late);
    // Removed and not reported yet, its address is in quarantine already.
    assert_eq!(
        sender.register(EndpointId(1), a, &register_as(5, 8), late + 1),
        None
    );
    assert_eq!(sender.registration_counters().dropped_quarantined, 1);
    assert_eq!(removals(&mut sender, late), [(a, RemovalReason::Timeout)]);
    let quarantine = sender.membership.receiver_timeout;
    assert_eq!(
        sender.register(EndpointId(1), a, &register_as(5, 8), late + 10),
        None
    );
    assert_eq!(
        sender.register(EndpointId(1), a, &register_as(5, 8), late + quarantine - 1),
        None
    );
    assert_eq!(sender.registration_counters().dropped_quarantined, 3);
    assert_eq!(sender.registration_counters().registered, 1);
    // The quarantine ends at removal + quarantine: it rejoins.
    assert_eq!(join_as(&mut sender, a, 5, 8, late + quarantine), None);
    assert!(sender.sends_to(EndpointId(1), alias(), a));
}

/// karyos#940 item 6 (design 3.2 step 4): a receiver restarting at the
/// endpoint of its own optional slot needs no new slot, so a full quota
/// does not refuse it; it reuses its slot.
#[test]
fn a_restart_at_its_own_endpoint_is_not_refused_for_a_full_quota() {
    let mut sender = dynamic_sender(1);
    let quiet = sender.registrations.config().move_quiet;
    let a: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    assert_eq!(join_as(&mut sender, a, 5, 7, T0), None);
    // Another receiver is refused for the full quota.
    let b: SocketAddr = "10.0.0.10:5000".parse().unwrap();
    assert_eq!(
        sender.register(EndpointId(1), b, &register_as(6, 9), T0 + 2),
        Some((b, full_err()))
    );
    let restart = T0 + 1 + quiet;
    assert_eq!(join_as(&mut sender, a, 5, 8, restart), None);
    assert!(sender.sends_to(EndpointId(1), alias(), a));
    assert!(removals(&mut sender, restart).is_empty());
    assert_eq!(sender.counters().registrants_restarted, 1);
}

/// Design 2.4, MD-16 (karyos#945 review): on a dynamic publication an SM
/// from another slot's address adopts nothing. Receiver 6 sends from both
/// slots of one host: its SMs from `a` count `sm_unbound`, and `a`'s own
/// slot expires with its binding once its receiver goes quiet.
#[test]
fn an_sm_from_another_slots_address_adopts_nothing_on_a_dynamic_publication() {
    let mut sender = dynamic_sender(4);
    let (a, b): (SocketAddr, SocketAddr) = (
        "10.0.0.9:5000".parse().unwrap(),
        "10.0.0.10:5000".parse().unwrap(),
    );
    assert_eq!(join_as(&mut sender, a, 5, 7, T0), None);
    assert_eq!(join_as(&mut sender, b, 6, 8, T0), None);
    let timeout = sender.confirmed_timeout;
    let step = timeout / 4;
    let unbound = sender.counters().sm_unbound;
    let mut now = T0 + 1;
    let mut sent = 0;
    while now < T0 + 1 + timeout + step {
        now += step;
        assert_eq!(sender.status(EndpointId(1), b, &sm_as(6, 8), now), None);
        assert_eq!(sender.status(EndpointId(1), a, &sm_as(6, 8), now), None);
        sent += 1;
    }
    assert_eq!(sender.counters().sm_unbound, unbound + sent);
    assert_eq!(sender.counters().bindings_adopted, 0);
    sender.expire_bindings(now);
    assert!(!sender.sends_to(EndpointId(1), alias(), a));
    assert!(sender.sends_to(EndpointId(1), alias(), b));
    assert_eq!(
        removals(&mut sender, now),
        vec![(a, RemovalReason::Timeout)]
    );
    assert_eq!(sender.counters().registrants_timed_out, 1);
}

/// MD-19: a move carries the receiver's membership to its new endpoint:
/// the membership is live there, and no longer at the old one.
#[test]
fn a_moved_receiver_keeps_its_membership() {
    let mut sender = dynamic_sender_with(4, &[]);
    let quiet = sender.registrations.config().move_quiet;
    let (a, b): (SocketAddr, SocketAddr) = (
        "10.0.0.9:5000".parse().unwrap(),
        "10.0.0.10:5000".parse().unwrap(),
    );
    assert_eq!(join_as(&mut sender, a, 5, 7, T0), None);
    let membership = |sender: &super::super::SenderRole, at: SocketAddr, now: u64| {
        sender.publications[0]
            .membership()
            .unwrap()
            .live_at(at, now)
    };
    assert!(membership(&sender, a, T0 + 1));
    let moved = T0 + 1 + quiet;
    assert_eq!(join_as(&mut sender, b, 5, 7, moved), None);
    assert_eq!(sender.counters().registrants_moved, 1);
    assert!(membership(&sender, b, moved + 1));
    assert!(!membership(&sender, a, moved + 1));
    // One membership throughout: joined once, never ended.
    let mut events = Vec::new();
    sender.publications[0]
        .membership_mut()
        .unwrap()
        .drain_events(|event| events.push(event));
    assert_eq!(events.len(), 1, "{events:?}");
    assert!(matches!(
        events[0],
        crate::membership::MemberEvent::Joined { .. }
    ));
}

/// Every live optional registrant slot of the publication: a destination
/// a registrant's first SM took, not removed, other than the required
/// ones.
fn optional_slots(sender: &super::super::SenderRole) -> Vec<SocketAddr> {
    let required = required_targets(sender);
    let outbound = &sender.publications[0];
    outbound
        .destinations()
        .unwrap()
        .filter(|address| !required.contains(address) && outbound.registrant_at(*address).is_some())
        .collect()
}

/// The optional slots no binding covers: none may exist (the invariant
/// `retire_uncovered_registrants` keeps).
fn uncovered_slots(sender: &super::super::SenderRole) -> Vec<SocketAddr> {
    optional_slots(sender)
        .into_iter()
        .filter(|address| !sender.bindings.iter().any(|held| held.source() == *address))
        .collect()
}

/// karyos#945 review: an SM of one slot's receiver sent from another
/// slot's address (`y` holds boot 7, `x` boot 8) cannot claim required id
/// 42 through an adoption: it is unbound, no binding names 42, admission
/// keeps its required target missing, and the real 42 joins.
#[test]
fn an_sm_from_another_slot_cannot_claim_a_required_id() {
    let mut sender = dynamic_sender_with(4, &[42]);
    let y: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    let x: SocketAddr = "10.0.0.9:5001".parse().unwrap();
    assert_eq!(join_as(&mut sender, y, 1, 7, T0), None);
    assert_eq!(join_as(&mut sender, x, 2, 8, T0 + 10), None);
    let before = sender.counters();
    assert_eq!(
        sender.status(EndpointId(1), y, &sm_as(42, 8), T0 + 20),
        None
    );
    let after = sender.counters();
    assert_eq!(after.sm_unbound, before.sm_unbound + 1);
    assert_eq!(after.sm_accepted, before.sm_accepted);
    assert_eq!(after.bindings_adopted, 0);
    assert!(
        sender
            .bindings
            .iter()
            .all(|held| held.receiver_id != Some(42))
    );
    assert!(required_targets(&sender).is_empty());
    let real: SocketAddr = "10.0.0.42:5000".parse().unwrap();
    assert_eq!(join_as(&mut sender, real, 42, 4242, T0 + 30), None);
    assert_eq!(required_targets(&sender), vec![real]);
    assert_eq!(
        admission(&sender, T0 + 31),
        crate::membership::Admission::Open
    );
}

/// karyos#945 review: `make_room` evicting a reset binding that holds a
/// slot leaves the slot to the bindings still at its address, and retires
/// it with the last of them (on `main` it stayed for good). Three slot owners reset their
/// bindings with a bare CHALLENGE, then CHALLENGEs with new boot ids
/// within `setup_answer_rate` fill the table.
#[test]
fn an_evicted_binding_retires_the_slot_it_held() {
    let mut sender = dynamic_sender(4);
    let at = |port: u16| SocketAddr::from(([10, 0, 0, 9], port));
    for port in 1..=3u16 {
        let id = u64::from(port);
        assert_eq!(join_as(&mut sender, at(port), id, id, T0), None);
    }
    let now = T0 + 5_000_000_000;
    for port in 1..=3u16 {
        let id = u64::from(port);
        assert_eq!(
            sender.status(EndpointId(1), at(port), &sm_as(id, id), now),
            None
        );
        assert!(
            sender
                .answer_for(EndpointId(1), at(port), now + 1, challenge_of(id))
                .is_some()
        );
    }
    for (offset, count) in [(2u64, 19u64), (500_000_000, 9)] {
        for boot in 0..count {
            for port in 1..=3u16 {
                let boot = 1000 + offset % 7 * 1000 + boot * 10 + u64::from(port);
                let _ =
                    sender.answer_for(EndpointId(1), at(port), now + offset, challenge_of(boot));
                assert_eq!(uncovered_slots(&sender), Vec::<SocketAddr>::new());
            }
        }
    }
    // The bindings that held the slots are evicted; the slots stay only
    // while the new bindings at their addresses can still expire them.
    assert!(sender.counters().bindings_evicted > 0);
    assert!(sender.bindings.iter().all(|held| held.last_sm.is_none()));
    let late = now + 500_000_000 + sender.unconfirmed_timeout;
    sender.expire_bindings(late);
    assert!(optional_slots(&sender).is_empty());
    let mut removed = removals(&mut sender, late);
    removed.sort_by_key(|(address, _)| *address);
    let expected: Vec<_> = (1..=3u16)
        .map(|port| (at(port), RemovalReason::Timeout))
        .collect();
    assert_eq!(removed, expected);
    assert_eq!(sender.counters().registrants_timed_out, 3);
}

/// karyos#945 review: with the table at three bindings, five datagrams
/// evict the binding that holds a slot; the slot goes with the last
/// binding at its address.
#[test]
fn an_evicted_binding_retires_its_slot_with_a_small_table() {
    let config = AgentConfig {
        receiver_bindings: 3,
        ..AgentConfig::default()
    };
    let mut sender = dynamic_sender_config(&config, 4, &[]);
    let a: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    assert_eq!(join_as(&mut sender, a, 1, 7, T0), None);
    // A bare CHALLENGE resets the binding, then three new boot ids.
    for (offset, boot) in [(10u64, 7u64), (20, 8), (30, 9), (40, 10)] {
        assert!(
            sender
                .answer_for(EndpointId(1), a, T0 + offset, challenge_of(boot))
                .is_some()
        );
        assert_eq!(uncovered_slots(&sender), Vec::<SocketAddr>::new());
    }
    assert_eq!(sender.counters().bindings_evicted, 1);
    let late = T0 + 40 + sender.unconfirmed_timeout;
    sender.expire_bindings(late);
    assert!(optional_slots(&sender).is_empty());
    assert_eq!(
        removals(&mut sender, late),
        vec![(a, RemovalReason::Timeout)]
    );
}

/// karyos#945 review: two slots of one host, `y`'s receiver silent and
/// `x`'s receiver sending from `y` too, leave no slot behind: no adoption
/// shares `y`'s address, so each slot expires with its own binding, and
/// four honest registrants take the four slots afterwards.
#[test]
fn a_slot_another_receiver_sends_at_still_expires() {
    let mut sender = dynamic_sender(4);
    let y: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    let x: SocketAddr = "10.0.0.9:5001".parse().unwrap();
    assert_eq!(join_as(&mut sender, y, 1, 7, T0), None);
    assert_eq!(join_as(&mut sender, x, 2, 8, T0 + 10), None);
    let live = sender.confirmed_timeout;
    let mut at = T0 + 20;
    while at < T0 + 20 + live / 2 {
        let _ = sender.status(EndpointId(1), y, &sm_as(2, 8), at);
        at += live / 20;
    }
    assert_eq!(sender.counters().bindings_adopted, 0);
    let mut removed = Vec::new();
    for step in 1..=12u64 {
        let now = at + step * live / 4;
        sender.expire_bindings(now);
        removed.extend(removals(&mut sender, now));
    }
    removed.sort_by_key(|(address, _)| *address);
    assert_eq!(
        removed,
        vec![(y, RemovalReason::Timeout), (x, RemovalReason::Timeout)]
    );
    let late = at + 100 * live;
    for last in 50..54u8 {
        let honest = SocketAddr::from(([10, 0, 0, last], 5000));
        assert_eq!(
            join_as(&mut sender, honest, u64::from(last), u64::from(last), late),
            None
        );
        assert!(sender.sends_to(EndpointId(1), alias(), honest));
    }
}

/// Design 4.6, M5 (karyos#945 review): a required id back at its own
/// endpoint after its binding expired, with its boot id or a new one, is
/// dropped at its REGISTER (`dropped_required_lost`), as `Membership`
/// refuses it: nothing is announced, answered or accepted.
#[test]
fn a_required_id_back_with_no_binding_is_dropped_at_its_register() {
    for boot in [7u64, 8] {
        let mut sender = dynamic_sender_with(4, &[42]);
        let a: SocketAddr = "10.0.0.9:5000".parse().unwrap();
        assert_eq!(join_as(&mut sender, a, 42, 7, T0), None);
        let late = T0 + 2 * sender.confirmed_timeout;
        sender.expire_bindings(late);
        assert!(sender.bindings.is_empty());
        let accepted = sender.counters().sm_accepted;
        assert_eq!(
            sender.register(EndpointId(1), a, &register_as(42, boot), late),
            None
        );
        assert_eq!(sender.registration_counters().dropped_required_lost, 1);
        assert_eq!(try_join(&mut sender, a, 42, boot, late + 10), None);
        assert_eq!(sender.counters().sm_accepted, accepted);
        assert_eq!(
            admission(&sender, late + 20),
            crate::membership::Admission::LostRequired
        );
        // At another endpoint too, before any ANNOUNCE.
        let b: SocketAddr = "10.0.0.10:5000".parse().unwrap();
        assert_eq!(
            sender.register(EndpointId(1), b, &register_as(42, boot), late + 30),
            None
        );
        assert_eq!(sender.registration_counters().dropped_required_lost, 3);
    }
}

/// One step of [`every_optional_slot_keeps_a_binding_able_to_expire_it`].
#[derive(Debug, Clone, Copy)]
enum Step {
    /// REGISTER, CHALLENGE and SM, each only if the one before went.
    Join(usize, u64, u64),
    Register(usize, u64, u64),
    Challenge(usize, u64),
    Sm(usize, u64, u64),
    Wait(u64),
    Report,
}

/// The invariant `retire_uncovered_registrants` keeps (karyos#945
/// review): every optional registrant slot always has a binding able to
/// expire it, after every datagram and every wait, and silence leaves no
/// slot nor binding. Random sequences of REGISTER, CHALLENGE, SM, waits and
/// removal reports over four endpoints of two hosts, three receiver ids
/// and one required id, from fixed seeds (xorshift), under the default
/// table and a three-binding one: they reach every path that removes a
/// binding (expiry, `make_room` eviction, a full or refused join, a
/// restart, a move), each asserted reached. A failure names its seed, the
/// step and the sequence so far. It also checks that the binding kept for
/// required id 42 until it joins is never taken (karyos#941 item 2), with
/// the refusals that keep it asserted reached.
#[test]
fn every_optional_slot_keeps_a_binding_able_to_expire_it() {
    const SEEDS: u64 = 12_000;
    let addresses: [SocketAddr; 4] = [
        "10.0.0.9:5000".parse().unwrap(),
        "10.0.0.9:5001".parse().unwrap(),
        "10.0.0.10:5000".parse().unwrap(),
        "10.0.0.42:5000".parse().unwrap(),
    ];
    let ids = [1u64, 2, 3, 42];
    let boots = [7u64, 8, 9];
    let mut reached = super::super::SenderCounters::default();
    for bindings in [64usize, 3] {
        for seed in 1..=SEEDS {
            let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
            let mut next = |n: u64| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                usize::try_from(state % n).unwrap()
            };
            let config = AgentConfig {
                receiver_bindings: bindings,
                ..AgentConfig::default()
            };
            let mut sender = dynamic_sender_config(&config, 4, &[42]);
            let live = sender.confirmed_timeout;
            let waits = [
                1_000_000u64,
                20_000_000,
                60_000_000,
                300_000_000,
                1_100_000_000,
                live / 2,
                live + 1,
            ];
            let mut now = T0;
            let mut steps = Vec::new();
            let length = 6 + next(30);
            for _ in 0..length {
                let step = match next(13) {
                    0..=2 => Step::Register(next(4), ids[next(4)], boots[next(3)]),
                    3..=4 => Step::Challenge(next(4), boots[next(3)]),
                    5..=7 => Step::Sm(next(4), ids[next(4)], boots[next(3)]),
                    8 => Step::Wait(waits[next(7)]),
                    9 => Step::Report,
                    _ => Step::Join(next(4), ids[next(4)], boots[next(3)]),
                };
                steps.push(step);
                now += 1000;
                match step {
                    Step::Join(at, id, boot) => {
                        let _ = try_join(&mut sender, addresses[at], id, boot, now);
                        now += 1;
                    }
                    Step::Register(at, id, boot) => {
                        let _ = sender.register(
                            EndpointId(1),
                            addresses[at],
                            &register_as(id, boot),
                            now,
                        );
                    }
                    Step::Challenge(at, boot) => {
                        let _ = sender.answer_for(
                            EndpointId(1),
                            addresses[at],
                            now,
                            challenge_of(boot),
                        );
                    }
                    Step::Sm(at, id, boot) => {
                        let _ = sender.status(EndpointId(1), addresses[at], &sm_as(id, boot), now);
                    }
                    Step::Wait(by) => {
                        now += by;
                        sender.expire_bindings(now);
                    }
                    Step::Report => {
                        let _ = removals(&mut sender, now);
                    }
                }
                let uncovered = uncovered_slots(&sender);
                assert!(
                    uncovered.is_empty(),
                    "receiver_bindings {bindings}, seed {seed}: {uncovered:?} uncovered after {steps:#?}"
                );
                // karyos#941 item 2: the binding kept for required id 42
                // until it joins is never taken by another receiver.
                let kept = sender.unjoined_required_count();
                assert!(
                    sender.bindings.len() + kept <= bindings,
                    "receiver_bindings {bindings}, seed {seed}: {} bindings and {kept} kept for 42 after {steps:#?}",
                    sender.bindings.len()
                );
            }
            for step in 1..=24u64 {
                let at = now + step * live / 4;
                sender.expire_bindings(at);
                let _ = removals(&mut sender, at);
            }
            let left = optional_slots(&sender);
            assert!(
                left.is_empty() && sender.bindings.is_empty(),
                "receiver_bindings {bindings}, seed {seed}: {left:?} and {} bindings left after silence, from {steps:#?}",
                sender.bindings.len()
            );
            let counters = sender.counters();
            reached.bindings_expired += counters.bindings_expired;
            reached.bindings_evicted += counters.bindings_evicted;
            reached.registrants_full += counters.registrants_full;
            reached.registrants_refused += counters.registrants_refused;
            reached.registrants_restarted += counters.registrants_restarted;
            reached.registrants_moved += counters.registrants_moved;
            reached.registrants_timed_out += counters.registrants_timed_out;
            reached.bindings_reserved += counters.bindings_reserved;
            reached.challenges_unbound += counters.challenges_unbound;
        }
    }
    for (path, count) in [
        ("expiry", reached.bindings_expired),
        ("make_room eviction", reached.bindings_evicted),
        ("full join", reached.registrants_full),
        ("refused join", reached.registrants_refused),
        ("restart", reached.registrants_restarted),
        ("move", reached.registrants_moved),
        ("slot retired", reached.registrants_timed_out),
        ("binding kept for a required id", reached.bindings_reserved),
        (
            "challenge with no room unanswered",
            reached.challenges_unbound,
        ),
    ] {
        assert!(count > 0, "the sequences never reach {path}");
    }
}

/// karyos#940 item 2: a binding no REGISTER created (a bare CHALLENGE at a
/// destination's address) gives no slot to its SM once that destination
/// is removed: the stranger's first SM must name a registered receiver
/// block. It takes a `setup_challenge_timeout` longer than the quarantine
/// for the binding to outlive it.
#[test]
fn an_unregistered_binding_at_a_removed_destination_takes_no_slot() {
    let mut config = AgentConfig::default();
    config.sessions.setup_challenge_timeout = 4 * config.image_liveness_timeout;
    let mut sender = dynamic_sender_config(&config, 4, &[]);
    let a: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    assert_eq!(join_as(&mut sender, a, 5, 7, T0), None);
    // A bare CHALLENGE resets the binding: it holds no registered block.
    assert!(
        sender
            .answer_for(EndpointId(1), a, T0 + 10, challenge_of(7))
            .is_some()
    );
    let quarantine = sender.membership.receiver_timeout;
    assert_eq!(
        sender.publications[0].change_destination(a, false, T0 + 20, quarantine),
        crate::agents::data::DestinationChange::Removed
    );
    assert_eq!(
        removals(&mut sender, T0 + 20),
        vec![(a, RemovalReason::Command)]
    );
    let later = T0 + 30 + quarantine;
    assert_eq!(sender.bindings.len(), 1);
    let refused = sender.counters().registrants_refused;
    assert_eq!(sender.status(EndpointId(1), a, &sm_as(5, 7), later), None);
    assert_eq!(sender.counters().registrants_refused, refused + 1);
    assert!(!sender.sends_to(EndpointId(1), alias(), a));
}

/// A destination added by command to a dynamic publication took no
/// registrant's SM and holds no receiver id: a binding's removal never
/// retires it, as no binding was ever meant to expire it (karyos#945
/// review).
#[test]
fn a_binding_removal_leaves_a_commanded_destination_in_place() {
    let mut sender = dynamic_sender(4);
    let quarantine = sender.membership.receiver_timeout;
    let commanded: SocketAddr = "10.0.0.77:5000".parse().unwrap();
    assert_eq!(
        sender.publications[0].change_destination(commanded, true, T0, quarantine),
        crate::agents::data::DestinationChange::Added
    );
    let a: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    assert_eq!(join_as(&mut sender, a, 5, 7, T0), None);
    let late = T0 + 2 * sender.confirmed_timeout;
    sender.expire_bindings(late);
    assert_eq!(
        removals(&mut sender, late),
        vec![(a, RemovalReason::Timeout)]
    );
    assert!(sender.sends_to(EndpointId(1), alias(), commanded));
}

/// A second dynamic publication, stream 8, on endpoint 1 of `sender`.
fn add_second_dynamic_publication(
    sender: &mut super::super::SenderRole,
) -> karyos_protocol::network::Alias {
    let (replies, _keep) = super::super::super::ring::ring::<AgentEvent<OsSocket>>(
        std::num::NonZeroUsize::new(4).unwrap(),
    );
    let mut publication = publication(EndpointId(1));
    publication.alias.session_id = 7;
    publication.alias.stream_id = 8;
    let (mut outbound, _log) = super::super::super::data::testing::outbound(
        publication.endpoint,
        publication.alias,
        "10.0.0.2:4000".parse().unwrap(),
        publication.term,
        1,
        false,
    );
    outbound.set_registration(4, lan()).unwrap();
    let added = sender.command(AgentCommand::<OsSocket>::AddPublication {
        reply: replies.reserve().unwrap(),
        publication,
        outbound,
        guard: None,
        roles: Some(Box::new(crate::membership::PublicationRoles {
            strategy: crate::membership::Strategy::Min,
            required: Vec::new(),
            tags: Vec::new(),
        })),
    });
    assert!(matches!(
        added,
        Some((_, AgentEvent::PublicationAdded { .. }))
    ));
    publication.alias
}

/// A slot is covered only by a binding of its own publication: a binding
/// of another publication at the same address keeps it no longer than its
/// own, and the slot retires when its own binding expires (karyos#945
/// review).
#[test]
fn only_a_binding_of_its_own_publication_covers_a_slot() {
    let mut sender = dynamic_sender(4);
    let other = add_second_dynamic_publication(&mut sender);
    let a: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    assert_eq!(join_as(&mut sender, a, 5, 7, T0), None);
    // The same receiver joins the second publication from `a` later.
    let later = T0 + sender.confirmed_timeout / 2;
    let mut register = register_as(6, 8);
    register.stream_id = other.stream_id;
    assert!(
        sender
            .register(EndpointId(1), a, &register, later)
            .is_some()
    );
    let Control::Challenge(mut challenge) = challenge_of(8) else {
        unreachable!()
    };
    challenge.alias = other;
    assert!(
        sender
            .answer_for(EndpointId(1), a, later, Control::Challenge(challenge))
            .is_some()
    );
    let mut status = sm_as(6, 8);
    status.alias = other;
    assert_eq!(sender.status(EndpointId(1), a, &status, later + 1), None);
    assert!(sender.publications[1].registrant_at(a).is_some());
    // The first publication's binding expires; the second's still lives.
    let expired = T0 + 1 + sender.confirmed_timeout;
    sender.expire_bindings(expired);
    assert!(sender.publications[0].registrant_at(a).is_none());
    assert!(sender.publications[1].registrant_at(a).is_some());
}

/// karyos#941 item 2, found by the property test (seed 49): a required
/// id's binding, answered again at its own tuple for another receiver
/// block, would hand on the binding kept for that id. With the table full
/// but for it, that CHALLENGE gets no ANSWER and the binding still names
/// 42. Optional receivers evict no required id's binding either.
#[test]
fn a_required_ids_binding_is_not_handed_to_another_receiver() {
    let config = AgentConfig {
        receiver_bindings: 3,
        ..AgentConfig::default()
    };
    let mut sender = dynamic_sender_config(&config, 4, &[42]);
    let (a, b, c, d): (SocketAddr, SocketAddr, SocketAddr, SocketAddr) = (
        "10.0.0.9:5000".parse().unwrap(),
        "10.0.0.10:5000".parse().unwrap(),
        "10.0.0.11:5000".parse().unwrap(),
        "10.0.0.12:5000".parse().unwrap(),
    );
    assert_eq!(join_as(&mut sender, a, 1, 7, T0), None);
    assert_eq!(join_as(&mut sender, b, 2, 8, T0), None);
    // The third binding is kept for 42: optional receiver 3 is not
    // answered.
    let refused = |sender: &mut super::super::SenderRole, now| {
        assert!(
            sender
                .register(EndpointId(1), d, &register_as(3, 6), now)
                .is_some()
        );
        assert_eq!(
            sender.answer_for(EndpointId(1), d, now, challenge_of(6)),
            None
        );
    };
    refused(&mut sender, T0 + 1);
    assert_eq!(sender.counters().bindings_reserved, 1);
    assert_eq!(sender.counters().challenges_unbound, 1);
    // 42 is answered and takes it, unconfirmed.
    assert!(
        sender
            .register(EndpointId(1), c, &register_as(42, 9), T0 + 2)
            .is_some()
    );
    assert!(
        sender
            .answer_for(EndpointId(1), c, T0 + 2, challenge_of(9))
            .is_some()
    );
    // Receiver 3 again: no eviction of 42's unconfirmed binding makes
    // room for it.
    refused(&mut sender, T0 + 3);
    assert_eq!(sender.counters().bindings_evicted, 0);
    assert_eq!(sender.counters().bindings_full, 1);
    // Another receiver block at 42's tuple is not answered either.
    assert!(
        sender
            .register(EndpointId(1), c, &register_as(3, 9), T0 + 4)
            .is_some()
    );
    assert_eq!(
        sender.answer_for(EndpointId(1), c, T0 + 4, challenge_of(9)),
        None
    );
    assert_eq!(sender.counters().bindings_reserved, 2);
    assert!(sender.bindings.iter().any(|held| {
        held.registered
            .is_some_and(|receiver| receiver.receiver_id == 42)
    }));
    // 42's first SM joins its reserved slot.
    assert_eq!(sender.status(EndpointId(1), c, &sm_as(42, 9), T0 + 5), None);
    assert_eq!(sender.counters().registrants_joined, 3);
}

/// karyos#941 item 2: with no dynamic publication nothing is kept, and a
/// static publication's receivers use the whole table as before; a full
/// table evicts its oldest unconfirmed binding.
#[test]
fn without_a_dynamic_publication_no_binding_is_kept() {
    let config = AgentConfig {
        receiver_bindings: 2,
        max_destinations: 2,
        ..AgentConfig::default()
    };
    let (mut sender, _receiver) = super::super::roles(&config).unwrap();
    let endpoint = EndpointId(1);
    let (path, _log) = super::super::super::data::testing::outbound(
        endpoint,
        alias(),
        "10.0.0.2:4000".parse().unwrap(),
        publication(endpoint).term,
        1,
        false,
    );
    sender.publications.push(path);
    let answer = |boot| karyos_protocol::network::SetupAnswer {
        alias: alias(),
        identity: identity(),
        term: publication(endpoint).term,
        challenge: karyos_protocol::network::ChallengeBlock {
            receiver_boot_id: [boot, boot],
            nonce: [9, 9],
        },
        joins: karyos_protocol::network::Lanes::new(&[0]).unwrap(),
    };
    let source: SocketAddr = "10.0.0.2:4000".parse().unwrap();
    for boot in 1..=3 {
        sender.bind(endpoint, source, &answer(boot), None, T0 + boot);
    }
    assert_eq!(sender.unjoined_required_count(), 0);
    assert_eq!(sender.bindings.len(), 2);
    assert_eq!(sender.counters().bindings_evicted, 1);
    assert_eq!(sender.counters().bindings_reserved, 0);
}

/// karyos#941 item 1: once its image goes, a key registers again at once
/// and from `setup_interval`, not from the backoff it had reached.
#[test]
fn a_key_whose_image_goes_registers_again_from_the_first_interval() {
    let config = AgentConfig::default();
    let interval = config.setup_interval;
    let (_sender, mut role) = receiver_with(config);
    let (events, _link) = event_ring();
    let control: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    let _status = subscribe_dynamic(&mut role, control, receiver_42());
    for step in 0..=31u64 {
        let _ = role.send_registers(&events, T0 + step * interval);
    }
    let (image, _) = super::installed_image();
    role.images.push(image);
    assert_eq!(role.send_registers(&events, T0 + 40 * interval), 0);
    role.images.clear();
    assert_eq!(role.send_registers(&events, T0 + 41 * interval), 1);
    assert_eq!(role.send_registers(&events, T0 + 42 * interval - 1), 0);
    assert_eq!(role.send_registers(&events, T0 + 42 * interval), 1);
}

/// karyos#941 item 2: a required id that joined keeps no binding free
/// once its own binding expires (its slot is held lost, and its REGISTER
/// is dropped): optional receivers use the whole table again.
#[test]
fn a_joined_required_id_keeps_no_binding_once_its_own_expires() {
    let config = AgentConfig {
        receiver_bindings: 2,
        ..AgentConfig::default()
    };
    let mut sender = dynamic_sender_config(&config, 4, &[42]);
    let (a, b, c): (SocketAddr, SocketAddr, SocketAddr) = (
        "10.0.0.9:5000".parse().unwrap(),
        "10.0.0.10:5000".parse().unwrap(),
        "10.0.0.11:5000".parse().unwrap(),
    );
    assert_eq!(join_as(&mut sender, c, 42, 9, T0), None);
    let later = T0 + 2 * sender.confirmed_timeout;
    sender.expire_bindings(later);
    assert!(sender.bindings.is_empty());
    assert_eq!(sender.unjoined_required_count(), 0);
    assert_eq!(join_as(&mut sender, a, 1, 7, later), None);
    assert_eq!(join_as(&mut sender, b, 2, 8, later + 10), None);
    assert_eq!(sender.counters().bindings_reserved, 0);
}

/// Counters once per event (karyos#943 item 4): each REGISTER from a
/// source schemas 7.3 refuses (port 0) counts `dropped_source` exactly
/// once, each from outside the allowlist `dropped_not_allowed` exactly
/// once, neither gets a reply, and an admitted one counts `registered`
/// exactly once.
#[test]
fn each_dropped_register_counts_its_reason_once() {
    let mut sender = dynamic_sender(4);
    let portless: SocketAddr = "10.0.0.9:0".parse().unwrap();
    let outside: SocketAddr = "192.168.0.9:5000".parse().unwrap();
    for sent in 1..=3u64 {
        let now = T0 + sent;
        assert_eq!(
            sender.register(EndpointId(1), portless, &register_as(5, 7), now),
            None
        );
        // Each call's increment, read right after it.
        let counters = sender.registration_counters();
        assert_eq!(counters.dropped_source, sent);
        assert_eq!(counters.dropped_not_allowed, sent - 1);
        assert_eq!(
            sender.register(EndpointId(1), outside, &register_as(6, 7), now),
            None
        );
        let counters = sender.registration_counters();
        assert_eq!(counters.dropped_source, sent);
        assert_eq!(counters.dropped_not_allowed, sent);
    }
    assert_eq!(sender.registration_counters().registered, 0);
    let inside: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    assert!(
        sender
            .register(EndpointId(1), inside, &register_as(5, 7), T0 + 4)
            .is_some()
    );
    let counters = sender.registration_counters();
    assert_eq!(counters.registered, 1);
    assert_eq!(counters.dropped_source, 3);
    assert_eq!(counters.dropped_not_allowed, 3);
}
