// SPDX-License-Identifier: Apache-2.0

//! H8 invariants of the authenticated class (karyos#648) at the receiver
//! role's intake: each test names the invariant it proves (the `INV-` id
//! of the round 4 invariant list).

use super::*;

/// INV-EST-4 (ADR-0086 section 7a, open point 11): an RSP_SETUP for a
/// local authenticated publication is accepted only sealed in domain 6. A
/// bare CHALLENGE and a bare SOLICIT naming it are dropped at the intake,
/// counted, and never reach the sender, so no binding or ANSWER can come
/// of them.
#[test]
fn inv_a_bare_rsp_setup_for_an_authenticated_publication_never_reaches_the_sender() {
    use karyos_protocol::network::{ChallengeBlock, RspChallenge, RspSolicit};

    let (mut sender, mut role) = receiver_with(AgentConfig::default());
    role.authenticate_published(EndpointId(1), alias());
    let (events, _keep) = event_ring();
    let source: SocketAddr = "10.0.0.9:5000".parse().unwrap();
    let block = ChallengeBlock {
        receiver_boot_id: [7, 8],
        nonce: [1, 2],
    };
    let challenge = Control::Challenge(RspChallenge {
        alias: alias(),
        identity: identity(),
        challenge: block,
    });
    let solicit = Control::Solicit(RspSolicit {
        alias: alias(),
        challenge: block,
    });
    {
        let mut intake = intake(&mut role, &events, 1);
        intake.bytes_in(source, &encoded(&challenge));
        intake.bytes_in(source, &encoded(&solicit));
    }
    let counters = role.counters();
    assert_eq!(counters.auth_bare, 2, "{counters:?}");
    assert_eq!(counters.forwarded, 0);
    assert!(
        sender.take_control().is_none(),
        "nothing reaches the sender"
    );
}
