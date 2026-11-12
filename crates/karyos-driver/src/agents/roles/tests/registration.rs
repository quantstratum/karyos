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
