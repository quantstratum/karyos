// SPDX-License-Identifier: Apache-2.0

//! The data path over the scripted `SocketOps`: what it emits.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use karyos_io::backend::InstanceId;
use karyos_io::sockets::endpoint::{SocketsConfig, SocketsEndpoint};
use karyos_io::sockets::ops::SendResult;
use karyos_io::sockets::scripted::ScriptedSocket;
use karyos_protocol::lanes::drr::Budget;
use karyos_protocol::network::{Alias, Datagram, TermParams, classify};
use karyos_sys::log_buffer::{AppendOptions, ClaimOutcome};

use super::EndpointId;
use super::testing::{outbound, outbound_joined};

/// Everything the data path flushes is a DATA datagram of its alias and
/// lane (a batch of DATA, PAD or ABORTED records): no control can take the
/// data gate, whose only caller reads the log. An aborted claim goes out
/// as its canonical record, never as payload.
#[test]
fn the_data_path_emits_only_data() {
    let socket = ScriptedSocket::new();
    let observer = socket.observer();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = Arc::clone(&seen);
    observer.set_send_hook(Box::new(move |_, datagrams| {
        for datagram in datagrams {
            record.lock().unwrap().push(datagram.to_vec());
        }
    }));
    for _ in 0..64 {
        observer.push_send(SendResult::Sent {
            sent: 1,
            error: None,
        });
    }
    let local = SocketsConfig::new(SocketAddr::from(([127, 0, 0, 1], 0)));
    let endpoint = SocketsEndpoint::open(&local, InstanceId::FIRST, socket).unwrap();
    let (mut tx, _rx) = endpoint.split().unwrap();
    let alias = Alias {
        session_id: 5,
        stream_id: 6,
    };
    let term = TermParams {
        term_length: 65_536,
        initial_term_id: 9,
        mtu: 1408,
    };
    let destination = SocketAddr::from(([127, 0, 0, 1], 41_000));
    let (mut path, mut log) = outbound(EndpointId(1), alias, destination, term, 1, false);
    let publication = &mut log.publications[0];
    let _ = publication
        .append(&[1u8; 3000], AppendOptions::default())
        .unwrap();
    let ClaimOutcome::Claimed(claim) = publication
        .try_claim(100, AppendOptions::default())
        .unwrap()
    else {
        panic!("not claimed");
    };
    claim.abort();
    let _ = publication
        .append(&[2u8; 200], AppendOptions::default())
        .unwrap();
    let budget = Budget {
        work: 64,
        bytes: 1 << 20,
    };
    for _ in 0..4 {
        let _ = path.serve(&mut tx, budget, None, 0).unwrap();
    }
    let seen = seen.lock().unwrap();
    assert!(seen.len() >= 4, "{} datagrams", seen.len());
    for bytes in seen.iter() {
        let Ok(Datagram::DataBatch(data)) = classify(bytes) else {
            panic!("not a DATA datagram: {:?}", classify(bytes));
        };
        assert_eq!(data.alias(), alias);
    }
    assert_eq!(path.counters().records, 1);
    assert!(path.readers()[0].sent_position() > 0);
}

/// A scripted endpoint with `max_queues` queues and two routes, the
/// observer, and a one-lane outbound path with three messages committed.
fn scripted(
    max_queues: u16,
    lanes: u8,
) -> (
    karyos_io::sockets::endpoint::SocketsTx<ScriptedSocket>,
    ScriptedSocket,
    Box<super::Outbound>,
    super::testing::TestLog,
) {
    let (tx, _rx, observer, path, log) = scripted_halves(max_queues, lanes);
    (tx, observer, path, log)
}

/// [`scripted`], keeping the RX half, so a test can join and retire an
/// endpoint left with pending items.
fn scripted_halves(
    max_queues: u16,
    lanes: u8,
) -> (
    karyos_io::sockets::endpoint::SocketsTx<ScriptedSocket>,
    karyos_io::sockets::endpoint::SocketsRx<ScriptedSocket>,
    ScriptedSocket,
    Box<super::Outbound>,
    super::testing::TestLog,
) {
    use std::num::NonZeroU16;

    let socket = ScriptedSocket::new();
    let observer = socket.observer();
    let mut local = SocketsConfig::new(SocketAddr::from(([127, 0, 0, 1], 0)));
    local.max_queues = NonZeroU16::new(max_queues).unwrap();
    local.max_routes = NonZeroU16::new(2).unwrap();
    let endpoint = SocketsEndpoint::open(&local, InstanceId::FIRST, socket).unwrap();
    let (tx, rx) = endpoint.split().unwrap();
    let alias = Alias {
        session_id: 5,
        stream_id: 6,
    };
    let term = TermParams {
        term_length: 65_536,
        initial_term_id: 9,
        mtu: 1408,
    };
    let destination = SocketAddr::from(([127, 0, 0, 1], 41_000));
    let (path, mut log) = outbound(EndpointId(1), alias, destination, term, lanes, false);
    for i in 0..3u8 {
        let _ = log.publications[0]
            .append(&[i; 300], AppendOptions::default())
            .unwrap();
    }
    (tx, rx, observer, path, log)
}

/// P2-4: a send fault is retried on its queue, which keeps its items; the
/// lane is not wedged and nothing needs a reset.
#[test]
fn a_send_fault_is_retried() {
    use karyos_io::sockets::ops::Errno;

    let (mut tx, observer, mut path, _log) = scripted(4, 1);
    observer.push_send(SendResult::Error(Errno::NETUNREACH));
    for _ in 0..16 {
        observer.push_send(SendResult::Sent {
            sent: 1,
            error: None,
        });
    }
    let budget = Budget {
        work: 64,
        bytes: 1 << 20,
    };
    for _ in 0..6 {
        let _ = path.serve(&mut tx, budget, None, 0).unwrap();
    }
    let counters = path.counters();
    assert_eq!(counters.send_faults, 1);
    assert!(counters.submitted >= 1, "{counters:?}");
    assert!(!path.needs_reset());
    let reader = &path.readers()[0];
    assert_eq!(reader.sent_position(), reader.position());
}

/// A backend failure (EBADF stops the half) is no send fault: the
/// publication needs an endpoint reset, the failure is counted once, and
/// later serves do not retry it.
#[test]
fn a_backend_failure_needs_a_reset() {
    use karyos_io::backend::TxReport;
    use karyos_io::sockets::endpoint::Retired;
    use karyos_io::sockets::ops::Errno;

    let (mut tx, rx, observer, mut path, _log) = scripted_halves(4, 1);
    observer.push_send(SendResult::Error(Errno::BADF));
    for _ in 0..16 {
        observer.push_send(SendResult::Sent {
            sent: 1,
            error: None,
        });
    }
    let budget = Budget {
        work: 64,
        bytes: 1 << 20,
    };
    let _ = path.serve(&mut tx, budget, None, 0).unwrap();
    let first = path.counters();
    assert!(path.needs_reset());
    assert_eq!((first.send_failures, first.send_faults), (1, 0));
    for _ in 0..5 {
        let _ = path.serve(&mut tx, budget, None, 0).unwrap();
    }
    let counters = path.counters();
    assert!(path.needs_reset());
    assert_eq!(counters.send_faults, 0);
    assert_eq!(counters.submitted, first.submitted, "{counters:?}");
    // The endpoint table's part: retire the endpoint, returning its items.
    let mut endpoint = SocketsEndpoint::join(tx, rx).ok().unwrap();
    let mut report = TxReport::new();
    while !matches!(endpoint.retire(&mut report), Retired::Complete { .. }) {
        while report.pop_front().is_some() {}
    }
}

/// P2-5: an open that fails part way closes what it opened, so retrying
/// every cycle never exhausts the endpoint's routes.
#[test]
fn a_failed_open_leaks_nothing() {
    // Two lanes, one queue allowed: the second queue always fails.
    let (mut tx, _observer, mut path, _log) = scripted(1, 2);
    let budget = Budget {
        work: 64,
        bytes: 1 << 20,
    };
    for _ in 0..5 {
        assert_eq!(path.serve(&mut tx, budget, None, 0).unwrap(), 0);
    }
    let counters = path.counters();
    assert_eq!((counters.queue_failures, counters.route_failures), (5, 0));
}

/// Flow control (multicast-flow-control.md; ACS 15707): with membership
/// attached, nothing is sent without a receiver window; sends stay within a
/// joined member's edge (a whole maximum frame from the cursor must fit);
/// an advancing SM moves the edge; a lost required member holds every lane.
#[test]
fn first_sends_follow_the_receivers_limits() {
    use karyos_protocol::frame::Lane;
    use karyos_protocol::network::{Identity, LaneStatus, Lanes, Receiver, StatusMessage};

    use crate::membership::{Membership, MembershipConfig, Roles, SmKey};

    let socket = ScriptedSocket::new();
    let observer = socket.observer();
    for _ in 0..256 {
        observer.push_send(SendResult::Sent {
            sent: 1,
            error: None,
        });
    }
    let local = SocketsConfig::new(SocketAddr::from(([127, 0, 0, 1], 0)));
    let endpoint = SocketsEndpoint::open(&local, InstanceId::FIRST, socket).unwrap();
    let (mut tx, _rx) = endpoint.split().unwrap();
    let alias = Alias {
        session_id: 5,
        stream_id: 6,
    };
    let identity = Identity {
        driver_id: [1, 2],
        registration_id: 1,
        incarnation: 1,
    };
    let term = TermParams {
        term_length: 65_536,
        initial_term_id: 9,
        mtu: 1408,
    };
    let destination = SocketAddr::from(([127, 0, 0, 1], 41_000));
    let (mut path, mut log) = outbound(EndpointId(1), alias, destination, term, 1, false);
    let receiver = Receiver {
        receiver_boot_id: [7, 8],
        receiver_id: 1,
    };
    let membership = Membership::new(
        MembershipConfig::new(1, 1408, 32_768),
        identity,
        alias,
        &Roles {
            required: &[1],
            tags: &[],
        },
        0,
    )
    .unwrap();
    path.attach_membership(Box::new(membership));
    for i in 0..20u8 {
        let _ = log.publications[0]
            .append(&[i; 1000], AppendOptions::default())
            .unwrap();
    }
    let budget = Budget {
        work: 64,
        bytes: 1 << 20,
    };
    let key = SmKey {
        endpoint: EndpointId(1),
        alias,
        source: SocketAddr::from(([10, 0, 0, 1], 5000)),
        identity,
        receiver,
    };
    let sm = |consumption: u64| StatusMessage {
        alias,
        identity,
        receiver,
        group_tag: 0,
        lanes: Lanes::new(&[LaneStatus {
            consumption,
            window: 4096,
        }])
        .unwrap(),
    };
    // No receiver window: nothing goes out.
    let _ = path.serve(&mut tx, budget, None, 0).unwrap();
    assert_eq!(path.readers()[0].position(), 0);
    assert!(path.counters().window_waits > 0);
    // A member joins at 0 with a 4096-byte window: the edge is 4096.
    let membership = path.membership_mut().unwrap();
    let _ = membership.status(&key, &sm(0), 1);
    let _ = path.serve(&mut tx, budget, None, 2).unwrap();
    let first = path.readers()[0].position();
    assert!(
        first > 0 && first + 1408 > 4096 && first <= 4096,
        "cursor {first}"
    );
    // It consumes what was sent: the edge moves on.
    let sent = path.readers()[0].position();
    let membership = path.membership_mut().unwrap();
    let _ = membership.status(&key, &sm(sent), 3);
    let _ = path.serve(&mut tx, budget, None, 4).unwrap();
    let second = path.readers()[0].position();
    assert!(second > first && second <= sent + 4096, "cursor {second}");
    // The required member falls silent: past its timeout every lane holds.
    let membership = path.membership_mut().unwrap();
    assert_eq!(
        membership.limit(Lane::ZERO, 5_000_000_004),
        crate::membership::Limit::Held
    );
    let _ = path.serve(&mut tx, budget, None, 5_000_000_004).unwrap();
    assert_eq!(path.readers()[0].position(), second, "held: no first sends");
    assert!(path.counters().held > 0);
}

#[test]
fn a_held_publication_keeps_its_staged_heads_queued() {
    use karyos_protocol::network::{Identity, LaneStatus, Lanes, Receiver, StatusMessage};

    use karyos_io::backend::TxReport;
    use karyos_io::sockets::endpoint::Retired;

    use crate::membership::{Membership, MembershipConfig, Roles, SmKey};

    // Unscripted sends would block: staged heads stay queued.
    let socket = ScriptedSocket::new();
    let observer = socket.observer();
    let local = SocketsConfig::new(SocketAddr::from(([127, 0, 0, 1], 0)));
    let endpoint = SocketsEndpoint::open(&local, InstanceId::FIRST, socket).unwrap();
    let (mut tx, rx) = endpoint.split().unwrap();
    let alias = Alias {
        session_id: 5,
        stream_id: 6,
    };
    let identity = Identity {
        driver_id: [1, 2],
        registration_id: 1,
        incarnation: 1,
    };
    let term = TermParams {
        term_length: 65_536,
        initial_term_id: 9,
        mtu: 1408,
    };
    let destination = SocketAddr::from(([127, 0, 0, 1], 41_000));
    let (mut path, mut log) = outbound(EndpointId(1), alias, destination, term, 1, false);
    let receiver = Receiver {
        receiver_boot_id: [7, 8],
        receiver_id: 1,
    };
    let membership = Membership::new(
        MembershipConfig::new(1, 1408, 32_768),
        identity,
        alias,
        &Roles {
            required: &[1],
            tags: &[],
        },
        0,
    )
    .unwrap();
    path.attach_membership(Box::new(membership));
    for i in 0..20u8 {
        let _ = log.publications[0]
            .append(&[i; 1000], AppendOptions::default())
            .unwrap();
    }
    let budget = Budget {
        work: 64,
        bytes: 1 << 20,
    };
    let key = SmKey {
        endpoint: EndpointId(1),
        alias,
        source: SocketAddr::from(([10, 0, 0, 1], 5000)),
        identity,
        receiver,
    };
    let sm = StatusMessage {
        alias,
        identity,
        receiver,
        group_tag: 0,
        lanes: Lanes::new(&[LaneStatus {
            consumption: 0,
            window: 4096,
        }])
        .unwrap(),
    };
    let _ = path.membership_mut().unwrap().status(&key, &sm, 1);
    let _ = path.serve(&mut tx, budget, None, 2).unwrap();
    assert!(path.readers()[0].position() > 0, "heads were staged");
    // The receiver falls silent with heads still queued: none goes out.
    for _ in 0..16 {
        observer.push_send(SendResult::Sent {
            sent: 1,
            error: None,
        });
    }
    let offered = observer.datagrams_offered();
    let _ = path.serve(&mut tx, budget, None, 5_000_000_004).unwrap();
    assert!(path.counters().held > 0);
    assert_eq!(
        observer.datagrams_offered(),
        offered,
        "held: queued heads wait"
    );
    assert_eq!(observer.remaining_sends(), 16);
    // The endpoint table's part: retire the endpoint, returning its items.
    let mut endpoint = SocketsEndpoint::join(tx, rx).ok().unwrap();
    let mut report = TxReport::new();
    while !matches!(endpoint.retire(&mut report), Retired::Complete { .. }) {
        while report.pop_front().is_some() {}
    }
}

/// P2-6, mutant M7 of the #270 review: a reliable lane rewinds to its
/// registered position on a new endpoint epoch. With no bound receiver its
/// registered position holds at the join, so after the reset every frame
/// it had submitted goes out again.
#[test]
fn a_reliable_lane_resends_from_its_registered_position_after_a_reset() {
    use karyos_io::backend::TxReport;

    let socket = ScriptedSocket::new();
    let observer = socket.observer();
    let seen = Arc::new(Mutex::new(0usize));
    let record = Arc::clone(&seen);
    observer.set_send_hook(Box::new(move |_, datagrams| {
        *record.lock().unwrap() += datagrams.len();
    }));
    let local = SocketsConfig::new(SocketAddr::from(([127, 0, 0, 1], 0)));
    let endpoint = SocketsEndpoint::open(&local, InstanceId::FIRST, socket).unwrap();
    let (mut tx, rx) = endpoint.split().unwrap();
    let alias = Alias {
        session_id: 5,
        stream_id: 6,
    };
    let term = TermParams {
        term_length: 65_536,
        initial_term_id: 9,
        mtu: 1408,
    };
    let destination = SocketAddr::from(([127, 0, 0, 1], 41_000));
    let (mut path, mut log) = outbound(EndpointId(1), alias, destination, term, 1, true);
    for i in 0..3u8 {
        let _ = log.publications[0]
            .append(&[i; 300], AppendOptions::default())
            .unwrap();
    }
    let budget = Budget {
        work: 64,
        bytes: 1 << 20,
    };
    for _ in 0..4 {
        let _ = path.serve(&mut tx, budget, None, 0).unwrap();
    }
    let first = *seen.lock().unwrap();
    assert!(first >= 1, "nothing sent");
    assert_eq!(path.readers()[0].sent_position(), 0, "held: no receiver");
    // The endpoint is reset and reopened at its next epoch.
    let mut endpoint = SocketsEndpoint::join(tx, rx).ok().unwrap();
    let mut report = TxReport::new();
    while endpoint.reset(&mut report).more {
        while report.pop_front().is_some() {}
    }
    while report.pop_front().is_some() {}
    let _ = endpoint.reopen(&local).unwrap();
    let (mut tx, rx) = endpoint.split().unwrap();
    for _ in 0..4 {
        let _ = path.serve(&mut tx, budget, None, 0).unwrap();
    }
    assert_eq!(*seen.lock().unwrap(), 2 * first, "the lane did not resend");
    let mut endpoint = SocketsEndpoint::join(tx, rx).ok().unwrap();
    while !matches!(
        endpoint.retire(&mut report),
        karyos_io::sockets::endpoint::Retired::Complete { .. }
    ) {
        while report.pop_front().is_some() {}
    }
}

/// One lane of 1000-byte messages (1056-byte frames) with its receivers'
/// membership, over a socket that sends everything.
struct Flow {
    tx: karyos_io::sockets::endpoint::SocketsTx<ScriptedSocket>,
    rx: karyos_io::sockets::endpoint::SocketsRx<ScriptedSocket>,
    path: Box<super::Outbound>,
    log: super::testing::TestLog,
    key: crate::membership::SmKey,
}

/// The aligned length of one 1000-byte message's frame.
const FRAME: u64 = 1056;

const FLOW_BUDGET: Budget = Budget {
    work: 64,
    bytes: 1 << 20,
};

impl Flow {
    /// `required` receivers; `before` messages are appended before the
    /// reader subscribes, so it joins above 0.
    fn new(required: &[u64], before: u8) -> Self {
        use karyos_protocol::network::{Identity, Receiver};

        use crate::membership::{Membership, MembershipConfig, Roles, SmKey};

        let socket = ScriptedSocket::new();
        for _ in 0..256 {
            socket.push_send(SendResult::Sent {
                sent: 1,
                error: None,
            });
        }
        let local = SocketsConfig::new(SocketAddr::from(([127, 0, 0, 1], 0)));
        let endpoint = SocketsEndpoint::open(&local, InstanceId::FIRST, socket).unwrap();
        let (tx, rx) = endpoint.split().unwrap();
        let alias = Alias {
            session_id: 5,
            stream_id: 6,
        };
        let identity = Identity {
            driver_id: [1, 2],
            registration_id: 1,
            incarnation: 1,
        };
        let term = TermParams {
            term_length: 65_536,
            initial_term_id: 9,
            mtu: 1408,
        };
        let destination = SocketAddr::from(([127, 0, 0, 1], 41_000));
        let (mut path, mut log) =
            outbound_joined(EndpointId(1), alias, destination, term, 1, false, before);
        assert_eq!(path.readers()[0].position(), u64::from(before) * FRAME);
        let membership = Membership::new(
            MembershipConfig::new(1, 1408, 32_768),
            identity,
            alias,
            &Roles {
                required,
                tags: &[],
            },
            0,
        )
        .unwrap();
        path.attach_membership(Box::new(membership));
        for i in 0..20u8 {
            let _ = log.publications[0]
                .append(&[i; 1000], AppendOptions::default())
                .unwrap();
        }
        let key = SmKey {
            endpoint: EndpointId(1),
            alias,
            source: SocketAddr::from(([10, 0, 0, 1], 5000)),
            identity,
            receiver: Receiver {
                receiver_boot_id: [7, 8],
                receiver_id: 1,
            },
        };
        Self {
            tx,
            rx,
            path,
            log,
            key,
        }
    }

    /// An SM of the receiver at `consumption` with `window`, at `now`.
    fn sm(&mut self, consumption: u64, window: u32, now: u64) -> crate::membership::StatusOutcome {
        self.sm_of(1, consumption, window, now)
    }

    /// An SM of receiver `id` (from the same source and boot).
    fn sm_of(
        &mut self,
        id: u64,
        consumption: u64,
        window: u32,
        now: u64,
    ) -> crate::membership::StatusOutcome {
        use karyos_protocol::network::{LaneStatus, Lanes, StatusMessage};

        self.key.receiver.receiver_id = id;
        let sm = StatusMessage {
            alias: self.key.alias,
            identity: self.key.identity,
            receiver: self.key.receiver,
            group_tag: 0,
            lanes: Lanes::new(&[LaneStatus {
                consumption,
                window,
            }])
            .unwrap(),
        };
        let key = self.key;
        self.path.membership_mut().unwrap().status(&key, &sm, now)
    }

    fn serve(&mut self, now: u64) {
        let _ = self
            .path
            .serve(&mut self.tx, FLOW_BUDGET, None, now)
            .unwrap();
    }

    fn cursor(&self) -> u64 {
        self.path.readers()[0].position()
    }

    /// Retires the endpoint, returning what it still holds.
    fn finish(self) {
        use karyos_io::backend::TxReport;
        use karyos_io::sockets::endpoint::Retired;

        drop(self.log);
        let mut endpoint = SocketsEndpoint::join(self.tx, self.rx).ok().unwrap();
        let mut report = TxReport::new();
        while !matches!(endpoint.retire(&mut report), Retired::Complete { .. }) {
            while report.pop_front().is_some() {}
        }
    }
}

/// A frame that ends exactly on the receivers' edge is sent; one more is
/// not.
#[test]
fn a_frame_ending_on_the_edge_is_sent() {
    let mut flow = Flow::new(&[1], 0);
    // Edge 3520: 2112 + 1408 (the largest frame) ends on it.
    assert!(matches!(
        flow.sm(0, 3520, 1),
        crate::membership::StatusOutcome::Accepted { .. }
    ));
    flow.serve(2);
    assert_eq!(flow.cursor(), 3 * FRAME);
    // Waiting at the edge counts once, not once per cycle.
    for now in 3..6 {
        flow.serve(now);
    }
    assert_eq!(flow.path.counters().window_waits, 1);
    // The edge moves, the lane stages again, and its next wait counts.
    let _ = flow.sm(3 * FRAME, 3520, 6);
    flow.serve(7);
    assert_eq!(flow.cursor(), 6 * FRAME);
    assert_eq!(flow.path.counters().window_waits, 2);
    flow.finish();
}

/// Until the required receiver joins nothing is staged; then a lane's
/// registered position follows what the required members consumed, never
/// what was only submitted.
#[test]
fn registration_follows_the_required_consumption() {
    let mut flow = Flow::new(&[1], 0);
    // An optional receiver's window does not open the gate.
    assert!(matches!(
        flow.sm_of(2, 0, 4096, 1),
        crate::membership::StatusOutcome::Accepted { .. }
    ));
    flow.serve(1);
    assert_eq!(flow.cursor(), 0);
    assert!(flow.path.counters().not_joined > 0);
    let _ = flow.sm(0, 4096, 2);
    flow.serve(3);
    assert_eq!(flow.cursor(), 3 * FRAME);
    assert_eq!(
        flow.path.readers()[0].sent_position(),
        0,
        "nothing consumed"
    );
    let _ = flow.sm(2 * FRAME, 4096, 4);
    flow.serve(5);
    assert_eq!(flow.path.readers()[0].sent_position(), 2 * FRAME);
    flow.finish();
}

/// A reader that joined above 0 starts the membership's `sent_high` at
/// its join, so its receiver's first SM there is accepted.
#[test]
fn a_reader_joined_above_zero_accepts_its_join() {
    let mut flow = Flow::new(&[1], 3);
    assert!(matches!(
        flow.sm(3 * FRAME, 4096, 1),
        crate::membership::StatusOutcome::Accepted { joined: true, .. }
    ));
    flow.serve(2);
    assert_eq!(flow.cursor(), 6 * FRAME);
    assert_eq!(
        flow.path
            .membership_mut()
            .unwrap()
            .counters()
            .sent_regressed,
        0
    );
    flow.finish();
}

/// The membership's timers run in each cycle: a silent optional member
/// expires.
#[test]
fn a_silent_optional_member_expires_in_the_cycle() {
    let mut flow = Flow::new(&[], 0);
    let _ = flow.sm(0, 4096, 1);
    flow.serve(2);
    let config = crate::membership::MembershipConfig::new(1, 1408, 32_768);
    // 16 entries per cycle: four cycles sweep the 64-entry table.
    for cycle in 0..u64::from(config.max_receivers / 16) {
        flow.serve(2 + config.receiver_timeout + cycle);
    }
    assert_eq!(flow.path.membership_mut().unwrap().counters().expired, 1);
    flow.finish();
}

/// A removal's drain needs the lane's submitted high at its seal
/// (`high >= seal`), not only its reader there: an unreliable lane whose
/// staged tail an endpoint reset dropped has read past what it submitted,
/// so it is not drained early and sends no EOS; at the drain bound it is
/// given up.
#[test]
fn a_tail_dropped_by_a_reset_is_not_drained() {
    use karyos_io::backend::TxReport;
    use karyos_io::sockets::endpoint::Retired;

    // Unscripted sends would block: the tail stays staged.
    let (mut tx, rx, observer, mut path, mut log) = scripted_halves(4, 1);
    let budget = Budget {
        work: 64,
        bytes: 1 << 20,
    };
    let _ = path.serve(&mut tx, budget, None, 0).unwrap();
    let read = path.readers()[0].position();
    assert!(read > 0, "the tail was staged");
    assert_eq!(path.counters().submitted, 0, "and never submitted");
    // The endpoint is reset: the staged tail is dropped, and an unreliable
    // lane does not read it again.
    let mut endpoint = SocketsEndpoint::join(tx, rx).ok().unwrap();
    let mut report = TxReport::new();
    while endpoint.reset(&mut report).more {
        while report.pop_front().is_some() {}
    }
    while report.pop_front().is_some() {}
    // As `scripted_halves` opened it.
    let mut local = SocketsConfig::new(SocketAddr::from(([127, 0, 0, 1], 0)));
    local.max_queues = std::num::NonZeroU16::new(4).unwrap();
    local.max_routes = std::num::NonZeroU16::new(2).unwrap();
    let _ = endpoint.reopen(&local).unwrap();
    let (mut tx, rx) = endpoint.split().unwrap();
    for _ in 0..16 {
        observer.push_send(SendResult::Sent {
            sent: 1,
            error: None,
        });
    }
    let _ = path.serve(&mut tx, budget, None, 0).unwrap();
    assert_eq!(path.readers()[0].position(), read, "no rewind");
    // The publisher releases and the seal is positioned at the tail's end.
    log.publications.clear();
    log.conductors[0].seal().unwrap();
    let _ = log.conductors[0].duty_cycle().unwrap();
    assert_eq!(path.readers()[0].seal_position(), Some(read));
    let (linger, interval) = (1_000, 100);
    path.begin_removal(1, linger, interval);
    for now in [0, 10, 50] {
        let step = path.serve_removal(Some(&mut tx), now);
        assert_eq!((step.sent, step.drained, step.gave_up), (0, false, false));
    }
    let step = path.serve_removal(Some(&mut tx), linger);
    assert_eq!((step.sent, step.gave_up), (0, true));
    let mut endpoint = SocketsEndpoint::join(tx, rx).ok().unwrap();
    while !matches!(endpoint.retire(&mut report), Retired::Complete { .. }) {
        while report.pop_front().is_some() {}
    }
}

/// T-x1 (timed-tx.md section 11, TT-6): an entry whose time is past the
/// sender's clock plus its own horizon is the publisher's violation. The
/// sender counts it once in `schedule_faults` and stages nothing more of
/// the lane (interim, until T-x2 seals it with `ScheduleViolation`).
#[test]
fn a_schedule_violation_stops_the_lane_counted_once() {
    use karyos_sys::log_buffer::ScheduledOutcome;

    use super::testing::outbound_timed;
    use crate::timed_gate::LatePolicy;

    let socket = ScriptedSocket::new();
    let local = SocketsConfig::new(SocketAddr::from(([127, 0, 0, 1], 0)));
    let endpoint = SocketsEndpoint::open(&local, InstanceId::FIRST, socket).unwrap();
    let (mut tx, rx) = endpoint.split().unwrap();
    let alias = Alias {
        session_id: 5,
        stream_id: 6,
    };
    let term = TermParams {
        term_length: 65_536,
        initial_term_id: 9,
        mtu: 1408,
    };
    let destination = SocketAddr::from(([127, 0, 0, 1], 41_000));
    let (mut path, mut log) = outbound_timed(EndpointId(1), alias, destination, term, 4);
    let policy = LatePolicy {
        max_horizon: 10,
        ..LatePolicy::default()
    };
    path.set_timed(&[policy], vec![None], 0).unwrap();
    // The append path does not check the horizon: the sender must.
    for time in [5, 100, 100] {
        assert!(matches!(
            log.publications[0]
                .append_scheduled(&[1; 100], AppendOptions::default(), time)
                .unwrap(),
            ScheduledOutcome::Append(karyos_sys::log_buffer::AppendOutcome::Appended { .. })
        ));
    }
    let budget = Budget {
        work: 64,
        bytes: 1 << 20,
    };
    for now in 1..5 {
        let _ = path.serve(&mut tx, budget, None, now).unwrap();
    }
    assert_eq!(path.counters().staged, 1, "only the entry in reach");
    assert_eq!(path.counters().schedule_faults, 1, "counted once");
    let mut endpoint = SocketsEndpoint::join(tx, rx).ok().unwrap();
    let mut report = karyos_io::backend::TxReport::new();
    while !matches!(
        endpoint.retire(&mut report),
        karyos_io::sockets::endpoint::Retired::Complete { .. }
    ) {
        while report.pop_front().is_some() {}
    }
}

/// T-x1 review P2 (timed-tx.md section 11, TT-6): an entry's position is
/// checked against its frame, and a forged one is the publisher's breach
/// like a ring violation: counted once in `schedule_faults`, and the lane
/// stages nothing more, on every later duty.
#[test]
fn a_forged_entry_position_stops_the_lane_counted_once() {
    use karyos_sys::log_buffer::ScheduledOutcome;
    use karyos_sys::schedule_ring::HEADER_WORDS;
    use karyos_sys::sync::Ordering;

    use super::testing::outbound_timed;
    use crate::timed_gate::LatePolicy;

    let socket = ScriptedSocket::new();
    let local = SocketsConfig::new(SocketAddr::from(([127, 0, 0, 1], 0)));
    let endpoint = SocketsEndpoint::open(&local, InstanceId::FIRST, socket).unwrap();
    let (mut tx, rx) = endpoint.split().unwrap();
    let alias = Alias {
        session_id: 5,
        stream_id: 6,
    };
    let term = TermParams {
        term_length: 65_536,
        initial_term_id: 9,
        mtu: 1408,
    };
    let destination = SocketAddr::from(([127, 0, 0, 1], 41_000));
    let (mut path, mut log) = outbound_timed(EndpointId(1), alias, destination, term, 4);
    path.set_timed(&[LatePolicy::default()], vec![None], 0)
        .unwrap();
    for _ in 0..3 {
        assert!(matches!(
            log.publications[0]
                .append_scheduled(&[1; 100], AppendOptions::default(), 0)
                .unwrap(),
            ScheduledOutcome::Append(karyos_sys::log_buffer::AppendOutcome::Appended { .. })
        ));
    }
    // The first entry's position, forged: no frame lies there.
    let ring = log.lanes[0].schedule_ring().unwrap();
    ring[HEADER_WORDS].store(999, Ordering::Relaxed);
    let budget = Budget {
        work: 64,
        bytes: 1 << 20,
    };
    for now in 1..5 {
        let _ = path.serve(&mut tx, budget, None, now).unwrap();
    }
    assert_eq!(path.counters().staged, 0);
    assert_eq!(path.counters().schedule_faults, 1, "counted once");
    let mut endpoint = SocketsEndpoint::join(tx, rx).ok().unwrap();
    let mut report = karyos_io::backend::TxReport::new();
    while !matches!(
        endpoint.retire(&mut report),
        karyos_io::sockets::endpoint::Retired::Complete { .. }
    ) {
        while report.pop_front().is_some() {}
    }
}

/// #404 re-check P3: a timed message whose last fragment never reached its
/// queue frees its own schedule entry, the newest read: an older message
/// still staged keeps its slot, so the publisher's ring stays full until
/// that one leaves.
#[test]
fn a_lost_timed_message_frees_its_own_entry() {
    use karyos_sys::log_buffer::ScheduledOutcome;
    use karyos_sys::schedule_ring::SchedulePublisher;

    use super::testing::outbound_timed;
    use crate::timed_gate::LatePolicy;

    // Unscripted sends block: staged heads stay queued.
    let socket = ScriptedSocket::new();
    let local = SocketsConfig::new(SocketAddr::from(([127, 0, 0, 1], 0)));
    let endpoint = SocketsEndpoint::open(&local, InstanceId::FIRST, socket).unwrap();
    let (mut tx, rx) = endpoint.split().unwrap();
    let alias = Alias {
        session_id: 5,
        stream_id: 6,
    };
    let term = TermParams {
        term_length: 65_536,
        initial_term_id: 9,
        mtu: 1408,
    };
    let destination = SocketAddr::from(([127, 0, 0, 1], 41_000));
    let (mut path, mut log) = outbound_timed(EndpointId(1), alias, destination, term, 2);
    path.set_timed(&[LatePolicy::default()], vec![None], 0)
        .unwrap();
    for i in 0..2u8 {
        assert!(matches!(
            log.publications[0]
                .append_scheduled(&[i; 100], AppendOptions::default(), 0)
                .unwrap(),
            ScheduledOutcome::Append(karyos_sys::log_buffer::AppendOutcome::Appended { .. })
        ));
    }
    let budget = Budget {
        work: 64,
        bytes: 1 << 20,
    };
    for now in 1..4 {
        let _ = path.serve(&mut tx, budget, None, now).unwrap();
    }
    assert_eq!(path.counters().staged, 2);
    let ring = log.lanes[0].schedule_ring().unwrap();
    let mut publisher = SchedulePublisher::attach(ring).unwrap();
    assert_eq!(publisher.has_room(ring), Ok(false));
    // The newest is lost: the older, still staged, keeps its entry.
    path.timed_message_lost(0);
    assert_eq!(publisher.has_room(ring), Ok(false), "the older one's slot");
    assert_eq!(path.counters().schedule_faults, 0);
    // The endpoint table's part: retire the endpoint, returning its items.
    let mut endpoint = SocketsEndpoint::join(tx, rx).ok().unwrap();
    let mut report = karyos_io::backend::TxReport::new();
    while !matches!(
        endpoint.retire(&mut report),
        karyos_io::sockets::endpoint::Retired::Complete { .. }
    ) {
        while report.pop_front().is_some() {}
    }
}

/// #412 review P3: a reliable timed message reset after its first
/// fragment was submitted and before its last counts as sent: the reset
/// resends it at once, outside the late policy, counted rewound, never
/// late, though its time is long past.
#[test]
fn a_partly_sent_timed_message_is_replayed_after_a_reset() {
    use karyos_io::backend::TxReport;
    use karyos_sys::log_buffer::ScheduledOutcome;

    use super::testing::outbound_timed_reliable;
    use crate::timed_gate::LatePolicy;

    // One send taken, the rest block: the first fragment leaves, the
    // others stay staged.
    let socket = ScriptedSocket::new();
    let observer = socket.observer();
    observer.push_send(SendResult::Sent {
        sent: 1,
        error: None,
    });
    let local = SocketsConfig::new(SocketAddr::from(([127, 0, 0, 1], 0)));
    let endpoint = SocketsEndpoint::open(&local, InstanceId::FIRST, socket).unwrap();
    let (mut tx, rx) = endpoint.split().unwrap();
    let alias = Alias {
        session_id: 5,
        stream_id: 6,
    };
    let term = TermParams {
        term_length: 65_536,
        initial_term_id: 9,
        mtu: 1408,
    };
    let destination = SocketAddr::from(([127, 0, 0, 1], 41_000));
    let (mut path, mut log) = outbound_timed_reliable(EndpointId(1), alias, destination, term, 2);
    path.set_timed(&[LatePolicy::default()], vec![None], 0)
        .unwrap();
    assert!(matches!(
        log.publications[0]
            .append_scheduled(&[7; 3000], AppendOptions::default(), 0)
            .unwrap(),
        ScheduledOutcome::Append(karyos_sys::log_buffer::AppendOutcome::Appended { .. })
    ));
    let budget = Budget {
        work: 64,
        bytes: 1 << 20,
    };
    for now in 1..4 {
        let _ = path.serve(&mut tx, budget, None, now).unwrap();
    }
    let counts = path.timed_counts().unwrap();
    assert_eq!((counts.sent, counts.rewound), (0, 0), "{counts:?}");
    // The endpoint is reset and reopened; everything is sent now, 10 s
    // past the message's time.
    let mut endpoint = SocketsEndpoint::join(tx, rx).ok().unwrap();
    let mut report = TxReport::new();
    while endpoint.reset(&mut report).more {
        while report.pop_front().is_some() {}
    }
    while report.pop_front().is_some() {}
    let _ = endpoint.reopen(&local).unwrap();
    let (mut tx, rx) = endpoint.split().unwrap();
    for _ in 0..8 {
        observer.push_send(SendResult::Sent {
            sent: 1,
            error: None,
        });
    }
    let late = 10_000_000_000;
    for now in late..late + 4 {
        let _ = path.serve(&mut tx, budget, None, now).unwrap();
    }
    let counts = path.timed_counts().unwrap();
    assert_eq!(counts.rewound, 1, "{counts:?}");
    assert_eq!(counts.late_sends, 0, "a replay is not late: {counts:?}");
    assert_eq!(path.counters().schedule_faults, 0);
    let mut endpoint = SocketsEndpoint::join(tx, rx).ok().unwrap();
    while !matches!(
        endpoint.retire(&mut report),
        karyos_io::sockets::endpoint::Retired::Complete { .. }
    ) {
        while report.pop_front().is_some() {}
    }
}

/// MD-20 (karyos#802): two destinations at different positions when the
/// endpoint resets. The second's member window holds it at four frames
/// while the first takes all twenty; after the reset, the first is resent
/// nothing, and the second is caught up by its own repair path over
/// exactly the sixteen frames it lacked.
#[test]
fn a_reset_resends_only_what_each_destination_lacks() {
    reset_with_a_held_window(0);
}

/// karyos#890 review (codex): the same with the second destination's
/// window ending 32 bytes into a frame. The catch-up never takes a job
/// that ends inside a frame as its last word: it waits until a whole
/// frame fits, and a job that stopped inside one resumes from its last
/// whole frame, so every frame still arrives once and in order.
#[test]
fn a_catch_up_held_at_an_unaligned_edge_still_arrives_whole() {
    reset_with_a_held_window(32);
}

/// The reset scenario, the second destination's window `4 x FRAME +
/// extra` bytes.
fn reset_with_a_held_window(extra: u64) {
    use karyos_io::backend::TxReport;
    use karyos_protocol::network::{Identity, LaneStatus, Lanes, Receiver, StatusMessage};

    use crate::agents::repair::RepairConfig;
    use crate::membership::{Membership, MembershipConfig, Roles, SmKey};

    let first = SocketAddr::from(([127, 0, 0, 1], 41_001));
    let second = SocketAddr::from(([127, 0, 0, 1], 41_002));
    let socket = ScriptedSocket::new();
    for _ in 0..1024 {
        socket.push_send(SendResult::Sent {
            sent: 1,
            error: None,
        });
    }
    let observer = socket.observer();
    // Each DATA datagram sent, by destination and position: one 1056-byte
    // frame per datagram at this MTU, message `i` carrying `[i; 1000]`.
    let sent: Arc<Mutex<Vec<(SocketAddr, u64)>>> = Arc::new(Mutex::new(Vec::new()));
    let record = Arc::clone(&sent);
    observer.set_send_hook(Box::new(move |route, datagrams| {
        let mut sent = record.lock().unwrap();
        for datagram in datagrams {
            if let Ok(Datagram::DataBatch(_)) = classify(datagram)
                && let Some(index) = datagram.get(karyos_sys::frame::HEADER_LENGTH as usize)
            {
                sent.push((route.address(), u64::from(*index) * FRAME));
            }
        }
    }));
    let local = SocketsConfig::new(SocketAddr::from(([127, 0, 0, 1], 0)));
    let endpoint = SocketsEndpoint::open(&local, InstanceId::FIRST, socket).unwrap();
    let (mut tx, rx) = endpoint.split().unwrap();
    let alias = Alias {
        session_id: 5,
        stream_id: 6,
    };
    let identity = Identity {
        driver_id: [1, 2],
        registration_id: 1,
        incarnation: 1,
    };
    let term = TermParams {
        term_length: 65_536,
        initial_term_id: 9,
        mtu: 1408,
    };
    let (mut path, mut log) = outbound(EndpointId(1), alias, first, term, 1, true);
    // The second is required: held at its own edge, it is never removed
    // as slow (MD-7).
    path.set_destinations(
        crate::agents::data::DEFAULT_MAX_DESTINATIONS,
        &[first, second],
        &[second],
        Some(true),
    )
    .unwrap();
    path.enable_repair(&RepairConfig::default(), term.term_length, identity)
        .unwrap();
    // `max`: each destination waits at its own edge only.
    let mut config = MembershipConfig::new(1, 1408, 32_768);
    config.strategy = crate::membership::Strategy::Max;
    let membership = Membership::new(
        config,
        identity,
        alias,
        &Roles {
            required: &[],
            tags: &[],
        },
        0,
    )
    .unwrap();
    path.attach_membership(Box::new(membership));
    for i in 0..20u8 {
        let _ = log.publications[0]
            .append(&[i; 1000], AppendOptions::default())
            .unwrap();
    }
    // Each destination's receiver: its own source, id and window.
    let status = |path: &mut Box<super::Outbound>, source, id, (consumption, window), now| {
        let key = SmKey {
            endpoint: EndpointId(1),
            alias,
            source,
            identity,
            receiver: Receiver {
                receiver_boot_id: [7, 8],
                receiver_id: id,
            },
        };
        let sm = StatusMessage {
            alias,
            identity,
            receiver: key.receiver,
            group_tag: 0,
            lanes: Lanes::new(&[LaneStatus {
                consumption,
                window,
            }])
            .unwrap(),
        };
        let _ = path.membership_mut().unwrap().status(&key, &sm, now);
    };
    let held = u32::try_from(4 * FRAME + extra).unwrap();
    for now in 0..8 {
        status(&mut path, first, 1, (0, 32_768), now);
        status(&mut path, second, 2, (0, held), now);
        let _ = path.serve(&mut tx, FLOW_BUDGET, None, now).unwrap();
    }
    // Where each stands when the endpoint resets: the readers at `r`,
    // each destination at its own submitted `high`.
    let before = path.destination_catch_ups();
    let r = path.readers()[0].position();
    let high = |to| {
        before
            .iter()
            .find(|(at, ..)| *at == to)
            .map(|(_, _, high, _)| *high)
            .unwrap()
    };
    let (first_high, second_high) = (high(first), high(second));
    // Frames sent to `to` below `r` (resent or caught up) and from it (new).
    let count = |sent: &[(SocketAddr, u64)], to, below: u64| {
        sent.iter()
            .filter(|(at, position)| *at == to && *position < below)
            .count()
    };
    {
        let sent = sent.lock().unwrap();
        assert_eq!(
            u64::try_from(count(&sent, second, u64::MAX)).unwrap() * FRAME,
            second_high
        );
        assert_eq!(second_high, 4 * FRAME, "held at its window");
        assert!(first_high > second_high, "{first_high} {second_high}");
    }
    sent.lock().unwrap().clear();
    // The reset: the endpoint reopens in its next epoch.
    let mut endpoint = SocketsEndpoint::join(tx, rx).ok().unwrap();
    let mut report = TxReport::new();
    while endpoint.reset(&mut report).more {
        while report.pop_front().is_some() {}
    }
    while report.pop_front().is_some() {}
    let _ = endpoint.reopen(&local).unwrap();
    let (mut tx, rx) = endpoint.split().unwrap();
    let mut budget = crate::repair::scheduler::RepairBudget::default();
    // karyos#890 review (codex): still held at its window, the second gets
    // no catch-up past its own edge, as no new DATA would pass it (4.2).
    for now in 8..16 {
        status(&mut path, first, 1, (0, 32_768), now);
        status(&mut path, second, 2, (0, held), now);
        let _ = path.serve(&mut tx, FLOW_BUDGET, None, now).unwrap();
        let _ = path.serve_repair(&mut tx, &mut budget, now);
        budget = crate::repair::scheduler::RepairBudget::default();
    }
    {
        let sent = sent.lock().unwrap();
        assert_eq!(
            count(&sent, second, u64::MAX),
            0,
            "nothing past the second's edge while its window is shut: {sent:?}"
        );
    }
    // It consumes what it has, so its window opens (a window never
    // changes size, design 4.2): the rest arrives, once and in order
    // (below).
    for now in 16..32 {
        let consumed = sent
            .lock()
            .unwrap()
            .iter()
            .filter(|(at, _)| *at == second)
            .map(|(_, position)| position + FRAME)
            .max()
            .unwrap_or(second_high)
            .min(r);
        status(&mut path, first, 1, (0, 32_768), now);
        status(&mut path, second, 2, (consumed, held), now);
        let _ = path.serve(&mut tx, FLOW_BUDGET, None, now).unwrap();
        let _ = path.serve_repair(&mut tx, &mut budget, now);
        budget = crate::repair::scheduler::RepairBudget::default();
    }
    let sent = sent.lock().unwrap();
    let lacked = |high: u64| usize::try_from((r - high) / FRAME).unwrap();
    // Below `r`: what each lacked, nothing more; the first lacked nothing
    // it was sent. What is sent from `r` on is new, not resent.
    assert_eq!(
        count(&sent, first, r),
        lacked(first_high),
        "the first gets only what it lacked: {sent:?}"
    );
    assert_eq!(
        count(&sent, second, r),
        lacked(second_high),
        "the second gets exactly [high, r): {sent:?}"
    );
    let caught_up: Vec<u64> = sent
        .iter()
        .filter(|(at, position)| *at == second && *position < r)
        .map(|(_, position)| *position)
        .collect();
    assert_eq!(
        caught_up,
        (second_high / FRAME..r / FRAME)
            .map(|i| i * FRAME)
            .collect::<Vec<_>>(),
        "in order, once each"
    );
    // karyos#890 review (codex): the catch-up's submissions are the
    // destination's, so its frontier reaches `r`, and a NAK below `r` is a
    // valid repair request, not RangeInvalid.
    let after = path.destination_catch_ups();
    let high_of = |to| {
        after
            .iter()
            .find(|(at, ..)| *at == to)
            .map(|(_, _, high, _)| *high)
            .unwrap()
    };
    // Its window open, new DATA follows the catch-up, so the frontier is
    // at least `r`.
    assert!(high_of(second) >= r, "the frontier follows the catch-up");
    let nak = karyos_protocol::network::Nak {
        alias,
        identity,
        receiver: Receiver {
            receiver_boot_id: [7, 8],
            receiver_id: 2,
        },
        range: karyos_protocol::network::NakRange {
            lane: karyos_sys::frame::Lane::ZERO,
            length: u32::try_from(FRAME).unwrap(),
            start: r - FRAME,
        },
    };
    let outcome = path.nak_from(
        second,
        &nak,
        crate::repair::admission::Requester::Member {
            join: 0,
            consumption: 0,
            window: 32_768,
        },
        40,
    );
    assert!(
        !matches!(outcome, crate::agents::repair::NakOutcome::Reply(_)),
        "{outcome:?}"
    );
    let counters = path.destination_counters();
    let repairs = |to| {
        counters
            .iter()
            .find(|(at, _)| *at == to)
            .map(|(_, counters)| counters.repairs)
    };
    assert_eq!(
        (repairs(first), repairs(second)),
        (
            Some(u64::try_from(lacked(first_high)).unwrap()),
            Some(u64::try_from(lacked(second_high)).unwrap())
        )
    );
    drop(sent);
    let mut endpoint = SocketsEndpoint::join(tx, rx).ok().unwrap();
    while !matches!(
        endpoint.retire(&mut report),
        karyos_io::sockets::endpoint::Retired::Complete { .. }
    ) {
        while report.pop_front().is_some() {}
    }
}

/// A channel key file and the unicast sender party of one establishment.
fn sender_key() -> (crate::wire_keys::KeyFile, crate::wire_auth::Party) {
    let text = "format=karyos-wire-key-v1\nkey_id=3\nfile_epoch=1\npurpose=channel\nprofile_id=1\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-01-30T00:00:00Z\nsecret=1111111111111111111111111111111111111111111111111111111111111111\nchannel_id=7\nstream_id=6\n";
    let file = crate::wire_keys::parse("3-1.key", text.as_bytes()).unwrap();
    let party = crate::wire_auth::Party::Sender {
        identity: karyos_protocol::network::Identity {
            driver_id: [1, 2],
            registration_id: 1,
            incarnation: 1,
        },
        lane_count: 1,
        receiver_boot_id: [3, 4],
        nonce: [5, 6],
    };
    (file, party)
}

type Recorded = Arc<Mutex<Vec<Vec<u8>>>>;

/// A scripted endpoint recording what it sends, and a one-lane outbound
/// path with 3000 bytes, an aborted claim and 200 bytes committed.
fn recorded_path() -> (
    karyos_io::sockets::endpoint::SocketsTx<ScriptedSocket>,
    Recorded,
    Box<super::Outbound>,
    super::testing::TestLog,
) {
    let socket = ScriptedSocket::new();
    let observer = socket.observer();
    let seen: Recorded = Arc::new(Mutex::new(Vec::new()));
    let record = Arc::clone(&seen);
    observer.set_send_hook(Box::new(move |_, datagrams| {
        for datagram in datagrams {
            record.lock().unwrap().push(datagram.to_vec());
        }
    }));
    for _ in 0..64 {
        observer.push_send(SendResult::Sent {
            sent: 1,
            error: None,
        });
    }
    let local = SocketsConfig::new(SocketAddr::from(([127, 0, 0, 1], 0)));
    let endpoint = SocketsEndpoint::open(&local, InstanceId::FIRST, socket).unwrap();
    let (tx, _rx) = endpoint.split().unwrap();
    // The log is sized for the inner budget, the channel's 1408 less the
    // envelope; the path sends datagrams up to the whole 1408.
    let term = TermParams {
        term_length: 65_536,
        initial_term_id: 9,
        mtu: 1360,
    };
    let destination = SocketAddr::from(([127, 0, 0, 1], 41_000));
    let (path, mut log) =
        super::testing::outbound_wire(EndpointId(1), AUTH_ALIAS, destination, term, 1408);
    let publication = &mut log.publications[0];
    let _ = publication
        .append(&[1u8; 3000], AppendOptions::default())
        .unwrap();
    let ClaimOutcome::Claimed(claim) = publication
        .try_claim(100, AppendOptions::default())
        .unwrap()
    else {
        panic!("not claimed");
    };
    claim.abort();
    let _ = publication
        .append(&[2u8; 200], AppendOptions::default())
        .unwrap();
    (tx, seen, path, log)
}

const AUTH_ALIAS: Alias = Alias {
    session_id: 5,
    stream_id: 6,
};

const AUTH_BUDGET: Budget = Budget {
    work: 64,
    bytes: 1 << 20,
};

/// An authenticated publication seals every DATA datagram and record: each
/// opens under the session's key, once, and holds exactly the trusted
/// path's inner frames, at most the inner MTU, in a datagram at most the
/// envelope larger (ADR-0086 sections 2, 5 and 6).
#[test]
fn an_authenticated_publication_seals_every_datagram() {
    use crate::wire_auth::{ENVELOPE_LEN, Sealer, Verifier};
    let (mut tx, seen, mut path, _log) = recorded_path();
    let (file, party) = sender_key();
    path.require_auth().unwrap();
    path.install_sealer(Sealer::new(&file, party, AUTH_ALIAS).unwrap())
        .unwrap();
    for _ in 0..4 {
        let _ = path.serve(&mut tx, AUTH_BUDGET, None, 0).unwrap();
    }
    let mut verifier = Verifier::new([&file], party, AUTH_ALIAS).unwrap();
    let seen = seen.lock().unwrap();
    assert!(seen.len() >= 4, "{} datagrams", seen.len());
    let mut seqs = Vec::new();
    for bytes in seen.iter() {
        assert!(bytes.len() <= 1408);
        // Never bare on the wire.
        assert!(!matches!(classify(bytes), Ok(Datagram::DataBatch(_))));
        let opened = verifier.open(bytes, 0).unwrap();
        seqs.push(opened.seq);
        let inner = &bytes[opened.start..opened.start + opened.frames];
        assert!(inner.len() <= 1408 - ENVELOPE_LEN);
        let Ok(Datagram::DataBatch(data)) = classify(inner) else {
            panic!("not a DATA datagram inside: {:?}", classify(inner));
        };
        assert_eq!(data.alias(), AUTH_ALIAS);
        assert!(verifier.open(bytes, 0).is_err(), "a replay opened");
    }
    // One fresh sequence per transmission, in order.
    assert!(
        seqs.windows(2).all(|pair| pair[1] == pair[0] + 1),
        "{seqs:?}"
    );
    assert_eq!(path.counters().records, 1);
    assert_eq!(path.counters().seal_failures, 0);
}

/// Until the establishment installs its key an authenticated publication
/// sends nothing, not even a heartbeat, and reads nothing it would drop;
/// once keyed it sends from where it stopped.
#[test]
fn an_authenticated_publication_sends_nothing_without_its_key() {
    use crate::wire_auth::{Sealer, Verifier};
    let (mut tx, seen, mut path, _log) = recorded_path();
    path.require_auth().unwrap();
    for _ in 0..4 {
        let _ = path.serve(&mut tx, AUTH_BUDGET, None, 0).unwrap();
    }
    assert_eq!(path.serve_heartbeats(&mut tx, 1_000, 10), Some(0));
    assert_eq!(path.serve_heartbeats(&mut tx, 2_000, 10), Some(0));
    assert!(seen.lock().unwrap().is_empty());
    assert!(path.counters().seal_waits > 0);
    assert_eq!(path.readers()[0].sent_position(), 0);
    let (file, party) = sender_key();
    path.install_sealer(Sealer::new(&file, party, AUTH_ALIAS).unwrap())
        .unwrap();
    for _ in 0..4 {
        let _ = path.serve(&mut tx, AUTH_BUDGET, None, 0).unwrap();
    }
    let mut verifier = Verifier::new([&file], party, AUTH_ALIAS).unwrap();
    let seen = seen.lock().unwrap();
    assert!(seen.len() >= 4);
    // The first datagram starts at the log's first frame.
    let opened = verifier.open(&seen[0], 0).unwrap();
    let Ok(Datagram::DataBatch(data)) = classify(&seen[0][opened.start..][..opened.frames]) else {
        panic!("not DATA");
    };
    assert_eq!(data.alias(), AUTH_ALIAS);
    assert!(path.readers()[0].sent_position() > 0);
}

/// An idle authenticated lane's heartbeat is sealed like its DATA.
#[test]
fn an_authenticated_heartbeat_is_sealed() {
    use crate::wire_auth::{Sealer, Verifier};
    let (mut tx, seen, mut path, _log) = recorded_path();
    let (file, party) = sender_key();
    path.require_auth().unwrap();
    path.install_sealer(Sealer::new(&file, party, AUTH_ALIAS).unwrap())
        .unwrap();
    for _ in 0..4 {
        let _ = path.serve(&mut tx, AUTH_BUDGET, None, 0).unwrap();
    }
    // Idle since 0: one heartbeat at each idle interval.
    assert_eq!(path.serve_heartbeats(&mut tx, 1_000, 10), Some(1));
    assert_eq!(path.serve_heartbeats(&mut tx, 2_000, 10), Some(1));
    let seen = seen.lock().unwrap();
    // Every datagram opens in sequence order, and the
    // heartbeats are the two header-only DATA frames behind the envelope.
    let mut verifier = Verifier::new([&file], party, AUTH_ALIAS).unwrap();
    let mut heartbeats = 0;
    for bytes in seen.iter() {
        let opened = verifier.open(bytes, 0).unwrap();
        if let Ok(Datagram::Heartbeat(_)) = classify(&bytes[opened.start..][..opened.frames]) {
            assert_eq!(opened.frames, 32);
            heartbeats += 1;
        }
    }
    assert_eq!(heartbeats, 2);
}

/// Authentication is unicast single-path only: a publication that has
/// several destinations refuses it, and an authenticated one refuses
/// destinations; a sealer needs an authenticated publication.
#[test]
fn only_a_unicast_publication_is_authenticated() {
    use crate::wire_auth::Sealer;
    let (_tx, _seen, mut path, _log) = recorded_path();
    let (file, party) = sender_key();
    assert_eq!(
        path.install_sealer(Sealer::new(&file, party, AUTH_ALIAS).unwrap()),
        Err(super::AuthUnsupported::NotAuthenticated)
    );
    path.require_auth().unwrap();
    let destinations = [
        SocketAddr::from(([127, 0, 0, 1], 41_001)),
        SocketAddr::from(([127, 0, 0, 1], 41_002)),
    ];
    assert!(
        path.set_destinations(4, &destinations, &[], Some(true))
            .is_err()
    );
    let (_tx, _seen, mut fanned, _log) = recorded_path();
    fanned
        .set_destinations(4, &destinations, &[], Some(true))
        .unwrap();
    assert_eq!(
        fanned.require_auth(),
        Err(super::AuthUnsupported::NotUnicast)
    );
}
