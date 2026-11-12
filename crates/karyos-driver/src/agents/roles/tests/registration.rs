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
                .register(EndpointId(1), from, &register_of(boot), T0)
                .is_some()
        );
        assert!(
            sender
                .answer_for(EndpointId(1), from, T0, challenge_of(boot))
                .is_some()
        );
    }
    assert_eq!(
        sender.status(EndpointId(1), first, &sm_status([7, 7], 0), T0 + 1),
        None
    );
    assert_eq!(
        sender.status(EndpointId(1), second, &sm_status([8, 8], 0), T0 + 1),
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
        sender.status(EndpointId(1), second, &sm_status([8, 8], 0), T0 + 2),
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

/// Design 3.2 step 3: a REGISTER is charged to the sender's
/// `setup_answer_rate` bucket of its source, which a CHALLENGE's ANSWER
/// draws from too, so registering cannot multiply what one source gets.
#[test]
fn a_register_draws_on_the_sources_setup_answer_rate() {
    let mut sender = dynamic_sender(4);
    let from: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    // The default bucket holds 20: the first REGISTER and its 19 retries.
    for _ in 0..20 {
        assert!(
            sender
                .register(EndpointId(1), from, &register_of(7), T0)
                .is_some()
        );
    }
    // The CHALLENGE takes the entry, but its ANSWER finds the bucket empty.
    assert_eq!(
        sender.answer_for(EndpointId(1), from, T0, challenge_of(7)),
        None
    );
    assert_eq!(sender.session_counters().rate_limited, 1);
    assert_eq!(
        sender.register(EndpointId(1), from, &register_of(7), T0),
        None
    );
    assert_eq!(sender.registration_counters().dropped_source_rate, 1);
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
) {
    let (replies, _keep) = super::super::super::ring::ring::<AgentEvent<OsSocket>>(
        std::num::NonZeroUsize::new(4).unwrap(),
    );
    let _ = role.command(AgentCommand::<OsSocket>::AddSubscription {
        reply: replies.reserve().unwrap(),
        endpoint: EndpointId(1),
        stream_id: alias().stream_id,
        max_term_length: 1 << 20,
        reliable: true,
        multicast: false,
        control_group: None,
        identity,
        conflated: None,
        solicit_from: None,
        register_at: Some(control),
    });
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
    subscribe_dynamic(&mut role, control, receiver_42());
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
    subscribe_dynamic(&mut role, control, receiver_42());
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
    let (mut sender, _receiver) = super::super::roles(&AgentConfig::default()).unwrap();
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
    let added = sender.command(AgentCommand::<OsSocket>::AddPublication {
        reply: replies.reserve().unwrap(),
        publication,
        outbound,
        guard: None,
        roles: None,
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
    assert_eq!(join_as(&mut sender, a, 5, 7, T0), None);
    assert_eq!(join_as(&mut sender, b, 5, 8, T0 + 10), None);
    assert!(!sender.sends_to(EndpointId(1), alias(), a));
    assert!(sender.sends_to(EndpointId(1), alias(), b));
    let counters = sender.counters();
    assert_eq!(counters.registrants_restarted, 1);
    assert_eq!(counters.registrants_joined, 2);
    // At the same endpoint the destination stays, with the new receiver.
    assert!(
        sender
            .register(EndpointId(1), b, &register_as(5, 9), T0 + 20)
            .is_some()
    );
    assert!(
        sender
            .answer_for(EndpointId(1), b, T0 + 20, challenge_of(9))
            .is_some()
    );
    assert_eq!(sender.status(EndpointId(1), b, &sm_as(5, 9), T0 + 21), None);
    assert!(sender.sends_to(EndpointId(1), alias(), b));
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
    subscribe_dynamic(&mut role, control, None);
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
    let joined = dynamic.join_registrant("10.0.0.9:5000".parse().unwrap(), false, T0, 0);
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
        outbound.join_registrant(at(1), false, T0, 0),
        DestinationChange::Added
    );
    assert_eq!(outbound.registration_capacity(), Capacity::Full);
    assert_eq!(
        outbound.join_registrant(at(2), false, T0, 0),
        DestinationChange::Full
    );
    for last in [3, 4] {
        assert_eq!(
            outbound.join_registrant(at(last), true, T0, 0),
            DestinationChange::Added
        );
    }
    // A required destination is never retired as a registrant.
    assert!(!outbound.retire_registrant(at(3), crate::agents::data::RemovalReason::Moved, T0));
    assert!(outbound.retire_registrant(at(1), crate::agents::data::RemovalReason::Moved, T0));
}
