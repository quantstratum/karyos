// SPDX-License-Identifier: Apache-2.0

//! H8 round 6 (karyos#648): the round 5 review's evidence rows R5-06,
//! R5-10 and R5-11, raised to proofs through both network agents and their
//! real intakes. Each test names its row and its `INV-` ids.

use super::*;

/// The sender's binding: its sealer's party, the sealers it installed and
/// the establishments it made.
fn key_state(rig: &Rig) -> (Option<crate::wire_auth::Party>, u64, u64) {
    (
        rig.agents
            .sender
            .role
            .outbound(0)
            .and_then(|outbound| outbound.sealer_party()),
        rig.agents.sender.role.counters().auth_sealers_installed,
        rig.agents.sender.role.session_counters().established,
    )
}

/// The image's joins, by lane, as its installed lanes were configured.
fn image_joins(rig: &Rig, slot: SlotRef) -> Vec<u64> {
    rig.images
        .installed(slot)
        .unwrap_or_else(|| panic!("slot {slot:?} not installed; events {:?}", rig.events))
        .iter()
        .map(|lane| match lane.config().publication {
            PublicationMode::Image { join, .. } => join,
            _ => panic!("an image lane"),
        })
        .collect()
}

/// The slot of the last image installed.
fn last_installed(rig: &Rig) -> SlotRef {
    rig.events
        .iter()
        .rev()
        .find_map(|event| match event {
            ImageEvent::Installed { slot, .. } => Some(*slot),
            _ => None,
        })
        .expect("an image installed")
}

/// Appends `count` messages of `size` bytes to the publication.
fn append(rig: &mut Rig, count: u8, size: usize) {
    for i in 0..count {
        let _ = rig.log.as_mut().unwrap().publications[0]
            .append(
                &vec![i; size],
                karyos_sys::log_buffer::AppendOptions::default(),
            )
            .unwrap();
    }
}

/// R5-06 (INV-SS-7, ABT-10; ADR-0086 section 6): the receiver's own hard
/// stop. The image's domain 4 sealer, the agents' own, is moved to its
/// usage limit with no in-band epoch left (2^48 seals are not run). From
/// then on every control of the image the sender agent goes to send fails
/// to seal: none leaves, sealed or bare, while the publication's DATA side
/// is untouched; its key is the same establishment's.
#[test]
fn inv_r6_the_images_sealer_stops_its_controls_at_the_limit() {
    use crate::wire_auth::TAG_CAP;

    let (mut rig, _b, _channel) = authenticated_rig();
    let slot = established(&mut rig);
    assert!(send_one(&mut rig, 200) >= 1);
    let state = key_state(&rig);
    let image = rig.agents.receiver.role.image_sealer(slot).unwrap();
    // Controls do flow below the limit.
    let before = rig.agents.sender.role.counters();
    for _ in 0..100 {
        rig.round(true);
    }
    let flowing = rig.agents.sender.role.counters();
    assert!(flowing.sent > before.sent, "SMs sent below the limit");
    image.jump_to(u8::MAX, TAG_CAP);
    let at_limit = rig.agents.sender.role.counters();
    let bare = (
        rig.agents.sender.role.counters().auth_bare,
        rig.agents.receiver.counters().auth_bare,
    );
    let sms = rig.agents.receiver.counters().sm_sent;
    for _ in 0..3 {
        let _ = send_one(&mut rig, 100);
    }
    let after = rig.agents.sender.role.counters();
    assert!(
        rig.agents.receiver.counters().sm_sent > sms,
        "the image keeps asking to send its SMs"
    );
    assert!(
        after.seal_failures > at_limit.seal_failures,
        "each is refused at its seal: {after:?}"
    );
    assert_eq!(after.sent, at_limit.sent, "no control left: {after:?}");
    assert_eq!(
        (
            rig.agents.sender.role.counters().auth_bare,
            rig.agents.receiver.counters().auth_bare,
        ),
        bare,
        "nothing went bare"
    );
    assert_eq!(image.party_epoch_now(), Some(u8::MAX), "no epoch left");
    assert_eq!(key_state(&rig), state, "the same establishment");
}

/// R5-06 (INV-ABT-10; ADR-0118): an ACK completes a pending abort only with
/// each lane's range in `[join, high]`, the joins being the real ones of
/// the receiver's establishment and the ACK arriving sealed in domain 4
/// through the publisher's own intake. The image's establishment is the
/// one after a receive-side restart, so its joins are the sender's read
/// cursors then: different on the two lanes, lane 0 above 0. One aligned
/// frame below a join or above a submitted high-water mark: refused and
/// counted, nothing
/// completed; the exact ranges complete it once, a second counts as a
/// duplicate.
#[test]
fn inv_r6_a_wire_ack_is_bounded_by_the_real_joins_and_highs() {
    use crate::agents::control::ControlSeal;
    use crate::wire_auth::ENVELOPE_LEN;
    use karyos_protocol::network::Receiver;
    use karyos_protocol::network::authenticated::{AbortAck, AckLane, AuthControl};

    let (mut rig, word, b) = guarded_abort_rig_tuned(false, true, None);
    // Lane 0 moves before the receiver joins again.
    append(&mut rig, 4, 600);
    for _ in 0..200 {
        rig.round(true);
    }
    let old_party = rig
        .agents
        .sender
        .role
        .outbound(0)
        .and_then(|outbound| outbound.sealer_party())
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
    // The restarted receive side installs its new image.
    rig.until(true, |rig| {
        rig.events
            .iter()
            .filter(|event| matches!(event, ImageEvent::Installed { .. }))
            .count()
            == 2
    });
    let slot = last_installed(&rig);
    let joins = image_joins(&rig, slot);
    assert_eq!(joins.len(), 2);
    assert!(joins[0] > 0, "lane 0 joins above 0: {joins:?}");
    assert_ne!(joins[0], joins[1], "the lanes join apart: {joins:?}");
    append(&mut rig, 4, 600);
    for _ in 0..100 {
        rig.round(true);
    }
    close_guard(&mut rig, &word);
    for _ in 0..20 {
        rig.round(true);
    }
    let (epoch, _, _) = rig.agents.sender.role.pending_abort().expect("pending");
    let outbound = rig.agents.sender.role.outbound(0).unwrap();
    let highs = [
        outbound.submitted_high(0).unwrap(),
        outbound.submitted_high(1).unwrap(),
    ];
    assert!(highs[0] > joins[0], "{highs:?} {joins:?}");
    let boot = rig.agents.receiver.role.boot_id();
    let mut seal = rig.agents.receiver.role.image_sealer(slot).unwrap();
    let source = rig.endpoints.local_address(b).unwrap();
    let mut send = |rig: &mut Rig, lanes: [(u64, u64); 2]| {
        let ack = AuthControl::Ack(AbortAck {
            alias: alias(),
            identity: identity(),
            receiver: Receiver {
                receiver_boot_id: boot,
                receiver_id: 77,
            },
            guard_epoch: epoch,
            lanes: karyos_protocol::network::Lanes::new(&lanes.map(
                |(delivered, unresolved_end)| AckLane {
                    delivered,
                    unresolved_end,
                },
            ))
            .unwrap(),
        });
        let mut bytes = vec![0u8; karyos_protocol::network::MAX_CONTROL_LENGTH + ENVELOPE_LEN];
        let frames = ack.encode(&mut bytes).unwrap();
        let length = seal.seal_control(&mut bytes, frames).expect("sealed");
        bytes.truncate(length);
        // The publisher's verify budget for the receiver refills between
        // them.
        rig.now += 300 * MS;
        let opened = rig.agents.sender.role.counters().abort_acks;
        inject_at_a(rig, source, &bytes);
        // The receiver's intake hands it to the sender, which opens it in
        // its next duty.
        rig.round(true);
        let after = rig.agents.sender.role.counters();
        assert_eq!(after.abort_acks, opened + 1, "{lanes:?} opened: {after:?}");
    };
    let exact = [(joins[0], highs[0]), (joins[1], highs[1])];
    let acks = rig.agents.sender.role.counters().abort_acks;
    let mut invalid = 0;
    for lane in 0..2 {
        if joins[lane] > 0 {
            let mut below = exact;
            below[lane].0 = joins[lane] - 32;
            send(&mut rig, below);
            invalid += 1;
        }
        let mut above = exact;
        above[lane].1 = highs[lane] + 32;
        send(&mut rig, above);
        invalid += 1;
    }
    let sender = rig.agents.sender.role.counters();
    assert_eq!(sender.abort_acks, acks + invalid, "each opened: {sender:?}");
    assert_eq!(sender.abort_acks_invalid, invalid, "{sender:?}");
    assert_eq!(sender.aborts_completed, 0, "{sender:?}");
    assert!(
        rig.agents.sender.role.pending_abort().is_some(),
        "still pending"
    );
    send(&mut rig, exact);
    send(&mut rig, exact);
    let sender = rig.agents.sender.role.counters();
    assert_eq!(
        (sender.aborts_completed, sender.abort_acks_duplicate),
        (1, 1),
        "{sender:?}"
    );
}
