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
