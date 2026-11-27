// SPDX-License-Identifier: Apache-2.0

//! H8 invariants once proven only at unit level, raised to proofs through
//! both network agents on loopback, their rings and the conductor's
//! `ApplyKeys` command (karyos#648). Each test names its `INV-` id in the
//! round 4 invariant list.

use super::*;

/// INV-ABT-7 (H8 R1 #8, R2 #8), two agents: once the coordinated view
/// withdraws the keys, the identical SESSION_ABORT no longer gets its
/// cached ACK resent: the cache's sealer and the authority follow the key
/// application, and the publisher sees no further ACK.
#[test]
fn inv_e2e_a_withdrawn_view_stops_the_cached_abort_ack() {
    use crate::agents::roles::publish_auth::AbortAuthority;
    use crate::authority::Ed25519Signer;
    use crate::signed_control::Authority;
    use karyos_protocol::network::authenticated::GUARD_CLOSED;

    let (mut rig, b, _channel) = authenticated_rig();
    let signer = Ed25519Signer::from_seed(&[9; 32]);
    let verifier = signer.verifier();
    let a = rig.publisher;
    rig.agents
        .sender
        .role
        .set_abort_authority(a, alias(), AbortAuthority::new(signer, 10, 10));
    rig.agents
        .receiver
        .role
        .trust_authorities(vec![Authority::of(10, verifier, 10, &[11], true)], rig.now);
    rig.agents.receiver.role.permit_abort(
        b,
        alias().stream_id,
        crate::agents::roles::AbortScope {
            authority_id: 10,
            guard_id: 11,
        },
    );
    let _slot = established(&mut rig);
    assert!(
        rig.agents
            .sender
            .role
            .request_abort(a, alias(), GUARD_CLOSED, 11, 3, rig.now)
    );
    rig.until(true, |rig| {
        rig.agents.sender.role.counters().abort_acks == 1
    });
    let bytes = rig.agents.sender.role.last_abort_bytes().unwrap();
    let keys = std::sync::Arc::new(crate::net::wire::KeyView::withdrawn());
    rig.links
        .receiver
        .post(|reply| AgentCommand::ApplyKeys { reply, keys })
        .unwrap();
    rig.round(true);
    let before = rig.agents.receiver.counters();
    let source = rig.endpoints.local_address(a).unwrap();
    let receiver = &mut rig.agents.receiver;
    receiver
        .role
        .inject_datagram(&receiver.sessions, b, source, &bytes, rig.now);
    for _ in 0..50 {
        rig.round(true);
    }
    let after = rig.agents.receiver.counters();
    assert_eq!(
        after.abort_acks_resent, before.abort_acks_resent,
        "{after:?}"
    );
    assert_eq!(rig.agents.sender.role.counters().abort_acks, 1);
}

/// INV-SS-8 (ADR-0086 sections 4 and 7a), two agents on an established
/// session: a datagram sealed with the receiver's own domain 4 key is
/// refused as DATA at the receiver, and one sealed with the session's
/// domain 1 key is refused as a receiver control at the publisher: no key
/// verifies outside its domain and direction.
#[test]
fn inv_e2e_no_key_verifies_outside_its_domain_and_direction() {
    use crate::wire_auth::{ENVELOPE_LEN, Party, Sealer};
    use karyos_protocol::network::{Control, LaneStatus, Receiver, StatusMessage};

    let (mut rig, b, channel) = authenticated_rig();
    let (_, pairwise) = auth_keys(77);
    let slot = established(&mut rig);
    rig.sender_stopped = true;
    let boot = rig.agents.receiver.role.receiver_of(slot).receiver_boot_id;
    let sender_party = rig
        .agents
        .sender
        .role
        .outbound(0)
        .unwrap()
        .sealer_party()
        .unwrap();
    let receiver_party = Party::Receiver {
        identity: identity(),
        receiver_boot_id: boot,
        receiver_id: 77,
    };
    // DATA under the receiver's domain 4 key, to the receiver.
    let mut reverse = Sealer::new(&pairwise, receiver_party, alias()).unwrap();
    let bytes = sealed(&mut reverse, &stale_frame(9, 0, 32));
    let source = rig.endpoints.local_address(rig.publisher).unwrap();
    let before = rig.agents.receiver.counters();
    let receiver = &mut rig.agents.receiver;
    receiver
        .role
        .inject_datagram(&receiver.sessions, b, source, &bytes, rig.now);
    let after = rig.agents.receiver.counters();
    assert_eq!(after.data_committed, before.data_committed, "{after:?}");
    assert!(after.auth_rejected > before.auth_rejected, "{after:?}");
    // An SM under the session's domain 1 key, to the publisher.
    let status = Control::Status(StatusMessage {
        alias: alias(),
        identity: identity(),
        receiver: Receiver {
            receiver_boot_id: boot,
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
    let mut forward = Sealer::new(&channel, sender_party, alias()).unwrap();
    let mut sm = vec![0u8; karyos_protocol::network::MAX_CONTROL_LENGTH + ENVELOPE_LEN];
    let length = status.encode(&mut sm).unwrap();
    let length = forward.seal(&mut sm, length).unwrap();
    sm.truncate(length);
    let a = rig.publisher;
    assert!(rig.agents.sender.role.open_sealed_for(a, &sm).is_none());
}
