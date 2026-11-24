// SPDX-License-Identifier: Apache-2.0

//! Section 12 rows on a real socket over loopback (section 9, "Loopback,
//! Linux and macOS"): RX oversize, split halves on two threads, the round
//! trip, the buffer and path MTU probes, an unanswered port and loopback
//! multicast. Unprivileged; the endpoint runs over [`OsSocket`], `rustix`
//! on Linux and `std::net` on macOS, so every row runs on both platforms.
//! Where the platforms differ by design (the oversize length, the buffer
//! read back, the route MTU), the expected result is selected by platform
//! and both are asserted, never skipped.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::*;
use crate::backend::{
    Capability, CapabilityState, ClaimError, FlushStop, PendingCause, Reason, ReturnReason,
    RxDropReason, RxStop, TxItemOutcome,
};
use crate::sockets::OsSocket;

#[cfg(target_os = "linux")]
mod privileged;

/// How long a test waits for loopback traffic that should already be there.
const PATIENCE: Duration = Duration::from_secs(10);

/// Records a skipped case with its reason (section 9).
#[expect(
    clippy::print_stderr,
    reason = "section 9 records every skip with its reason in the test log"
)]
fn skip(reason: &str) {
    eprintln!("skip: {reason}");
}

fn loopback_any_port() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

/// [`config`] bound to `local`, without buffer requests.
fn os_config(local: SocketAddr) -> SocketsConfig {
    let mut config = config();
    config.local = local;
    config.send_buffer = None;
    config.recv_buffer = None;
    config
}

/// An endpoint over a real socket.
struct Node {
    tx: SocketsTx<OsSocket>,
    rx: SocketsRx<OsSocket>,
    local: SocketAddr,
}

impl Node {
    fn open(config: &SocketsConfig) -> Self {
        let endpoint = SocketsEndpoint::open(config, InstanceId::FIRST, OsSocket::new()).unwrap();
        let local = endpoint.capabilities().local;
        let (tx, rx) = endpoint.split().unwrap();
        Self { tx, rx, local }
    }

    fn loopback() -> Self {
        Self::open(&os_config(loopback_any_port()))
    }

    /// A route and a queue of 8 towards `peer`.
    fn queue_to(&mut self, peer: SocketAddr) -> TxQueueId {
        let route = self.tx.add_route(peer).unwrap();
        self.tx
            .open_queue(TxQueueConfig {
                authority: Authority::FIRST,
                route,
                max_pending: nz(8),
                etf: None,
            })
            .unwrap()
    }

    /// Commits and flushes `datagrams` on `queue`; returns the report.
    fn send(&mut self, queue: TxQueueId, datagrams: &[&[u8]]) -> (FlushOutcome, Vec<TxEntry>) {
        for (token, bytes) in (0_u64..).zip(datagrams) {
            let mut frame = self.tx.claim_tx(queue, bytes.len()).unwrap();
            frame.bytes_mut().copy_from_slice(bytes);
            frame
                .commit(Commit {
                    len: bytes.len(),
                    token: SenderToken::new(token),
                    options: TxOptions::none(),
                })
                .unwrap();
        }
        let mut report = TxReport::new();
        let outcome = self.tx.flush(
            FlushRequest {
                queue,
                max_datagrams: nz(64),
                max_bytes: u32::MAX,
            },
            &mut Gate::default(),
            &mut report,
        );
        (outcome, drain(&mut report))
    }

    /// Joins and retires the endpoint, returning the items still pending.
    fn retire(self) -> Vec<TxEntry> {
        let mut endpoint = SocketsEndpoint::join(self.tx, self.rx).unwrap();
        retire_all(&mut endpoint)
    }

    /// Joins and retires the endpoint, which must hold no pending item.
    fn shutdown(self) {
        assert!(self.retire().is_empty());
    }
}

/// Retires `nodes` after a case that may skip: a case that ran asserts no
/// item is left pending, while a skip, such as a send refused with no
/// route, may leave one, and its retirement returns it (karyos#880).
fn finish(nodes: impl IntoIterator<Item = Node>, skipped: Option<String>) {
    match skipped {
        None => nodes.into_iter().for_each(Node::shutdown),
        Some(reason) => {
            for node in nodes {
                node.retire();
            }
            skip(&reason);
        }
    }
}

/// Polls `rx` until `handler` holds `datagrams` datagrams and drops, or
/// [`PATIENCE`] runs out.
fn receive(rx: &mut SocketsRx<OsSocket>, handler: &mut Recorder, datagrams: usize) {
    let budget = config().rx_budget().unwrap();
    let start = Instant::now();
    while handler.datagrams.len() + handler.drops.len() < datagrams && start.elapsed() < PATIENCE {
        let outcome = rx.poll_rx(budget, handler);
        match outcome.stop {
            RxStop::WouldBlock => std::thread::yield_now(),
            RxStop::Budget => {}
            other => panic!("unexpected stop {other:?}"),
        }
    }
}

fn all_submitted(entries: &[TxEntry]) -> bool {
    entries
        .iter()
        .all(|entry| matches!(entry.outcome, TxItemOutcome::Submitted { .. }))
}

/// The length an oversize drop reports (4.4): the true length on Linux
/// (`MSG_TRUNC`), none on macOS, where a read that fills the
/// `max_datagram + 1` buffer is all that is known.
fn reported_length(received: usize) -> Option<usize> {
    if cfg!(target_os = "linux") {
        Some(received)
    } else {
        None
    }
}

/// Section 12, RX oversize: `max_datagram + 1` and 9,000 bytes are dropped
/// as `Oversize`, never delivered short, with the length Linux reports and
/// none on macOS; a datagram of exactly `max_datagram` is delivered whole.
/// 9,000 bytes stays below the macOS default `net.inet.udp.maxdgram` of
/// 9,216.
#[test]
fn rx_oversize_on_loopback() {
    let mut node = Node::loopback();
    let sender = UdpSocket::bind(loopback_any_port()).unwrap();
    let source = sender.local_addr().unwrap();
    for len in [257, 9000, 256] {
        sender.send_to(&payload(9, len), node.local).unwrap();
    }
    let mut handler = Recorder::default();
    receive(&mut node.rx, &mut handler, 3);
    let oversize = |received| RxDrop {
        reason: RxDropReason::Oversize {
            limit: 256,
            received: reported_length(received),
        },
        source: Some(source),
    };
    assert_eq!(handler.drops, vec![oversize(257), oversize(9000)]);
    assert_eq!(handler.datagrams, vec![(payload(9, 256), source)]);
    node.shutdown();
}

/// Section 12, loopback round trip: unicast both ways; bytes equal and the
/// source endpoint is the peer's bound address.
#[test]
fn loopback_round_trip() {
    let mut a = Node::loopback();
    let mut b = Node::loopback();
    let to_b = a.queue_to(b.local);
    let to_a = b.queue_to(a.local);

    let (outcome, entries) = a.send(to_b, &[b"ping", b"ping again"]);
    assert_eq!((outcome.submitted, outcome.stop), (2, FlushStop::Exposed));
    assert!(all_submitted(&entries));
    let mut at_b = Recorder::default();
    receive(&mut b.rx, &mut at_b, 2);
    assert_eq!(
        at_b.datagrams,
        vec![
            (b"ping".to_vec(), a.local),
            (b"ping again".to_vec(), a.local)
        ]
    );

    let (outcome, _) = b.send(to_a, &[b"pong"]);
    assert_eq!(outcome.submitted, 1);
    let mut at_a = Recorder::default();
    receive(&mut a.rx, &mut at_a, 1);
    assert_eq!(at_a.datagrams, vec![(b"pong".to_vec(), b.local)]);
    a.shutdown();
    b.shutdown();
}

/// Section 12, split halves: each half on its own thread exchanges traffic
/// over loopback, and dropping one half leaves the other working.
///
/// The sender keeps at most [`WINDOW`] datagrams ahead of what the receiver
/// has taken, so the receive buffer (the OS default; no request) never
/// overflows on a loaded host, where the receiving thread may not run for
/// a while.
#[test]
fn split_halves_on_two_threads() {
    const COUNT: usize = 200;
    /// Datagrams in flight at most: far below what any default receive
    /// buffer holds.
    const WINDOW: usize = 16;
    let mut a = Node::loopback();
    let b = Node::loopback();
    let to_b = a.queue_to(b.local);
    let a_local = a.local;
    let Node {
        tx: b_tx,
        rx: mut b_rx,
        local: _,
    } = b;

    let taken = Arc::new(AtomicUsize::new(0));
    let progress = Arc::clone(&taken);
    let receiver = std::thread::spawn(move || {
        let mut handler = Recorder::default();
        let budget = config().rx_budget().unwrap();
        let start = Instant::now();
        while handler.datagrams.len() < COUNT && start.elapsed() < PATIENCE {
            let outcome = b_rx.poll_rx(budget, &mut handler);
            progress.store(handler.datagrams.len(), Ordering::Release);
            match outcome.stop {
                RxStop::WouldBlock => std::thread::yield_now(),
                RxStop::Budget => {}
                other => panic!("unexpected stop {other:?}"),
            }
        }
        (b_rx, handler)
    });
    let Node {
        tx: mut a_tx,
        rx: a_rx,
        local: _,
    } = a;
    let sender = std::thread::spawn(move || {
        let start = Instant::now();
        for index in 0..COUNT {
            while index >= taken.load(Ordering::Acquire) + WINDOW && start.elapsed() < PATIENCE {
                std::thread::yield_now();
            }
            let mut frame = a_tx.claim_tx(to_b, 4).unwrap();
            frame
                .bytes_mut()
                .copy_from_slice(&u32::try_from(index).unwrap().to_be_bytes());
            frame
                .commit(Commit {
                    len: 4,
                    token: SenderToken::new(u64::try_from(index).unwrap()),
                    options: TxOptions::none(),
                })
                .unwrap();
            let mut report = TxReport::new();
            let outcome = a_tx.flush(
                FlushRequest {
                    queue: to_b,
                    max_datagrams: nz(64),
                    max_bytes: u32::MAX,
                },
                &mut Gate::default(),
                &mut report,
            );
            assert_eq!(outcome.submitted, 1, "{outcome:?}");
            drain(&mut report);
        }
        a_tx
    });
    let mut a_tx = sender.join().unwrap();
    let (b_rx, handler) = receiver.join().unwrap();
    // Loopback keeps order and loses nothing below the receive buffer.
    let expected: Vec<(Vec<u8>, SocketAddr)> = (0..COUNT)
        .map(|index| {
            (
                u32::try_from(index).unwrap().to_be_bytes().to_vec(),
                a_local,
            )
        })
        .collect();
    assert_eq!(handler.datagrams, expected);

    // Dropping A's receive half closes only its duplicate: A still sends.
    drop(a_rx);
    let mut report = TxReport::new();
    let mut frame = a_tx.claim_tx(to_b, 5).unwrap();
    frame.bytes_mut().copy_from_slice(b"after");
    frame
        .commit(Commit {
            len: 5,
            token: SenderToken::new(0),
            options: TxOptions::none(),
        })
        .unwrap();
    let outcome = a_tx.flush(
        FlushRequest {
            queue: to_b,
            max_datagrams: nz(64),
            max_bytes: u32::MAX,
        },
        &mut Gate::default(),
        &mut report,
    );
    assert_eq!(outcome.submitted, 1);
    drain(&mut report);
    let mut b_rx = b_rx;
    let mut handler = Recorder::default();
    receive(&mut b_rx, &mut handler, 1);
    assert_eq!(handler.datagrams, vec![(b"after".to_vec(), a_local)]);

    // Dropping B's send half leaves its receive half working.
    drop(b_tx);
    let sender = UdpSocket::bind(loopback_any_port()).unwrap();
    let b_local = b_rx.capabilities().local;
    sender.send_to(b"still", b_local).unwrap();
    let mut handler = Recorder::default();
    receive(&mut b_rx, &mut handler, 1);
    assert_eq!(handler.datagrams.len(), 1);
    drop(a_tx);
}

/// Section 12, reset, on a real socket (section 9, "Loopback, Linux and
/// macOS"):
/// pending items return with `Reset`; the finished reset closes the
/// socket, which `reopen` proves by binding the same address again (an
/// open descriptor would fail it with `EADDRINUSE`); `reopen` probes again
/// and publishes the snapshot of the next epoch; old queue handles and
/// tickets are inert; traffic flows in the new epoch. Only the few
/// statements between the reset and the rebind leave the port free for a
/// parallel test's `bind(0)`, a race of negligible likelihood.
#[test]
fn reset_on_loopback() {
    let mut a = Node::loopback();
    let mut b = Node::loopback();
    let local = a.local;
    let queue = a.queue_to(b.local);
    let tickets: Vec<TxTicket> = (0_u64..3)
        .map(|token| {
            let mut frame = a.tx.claim_tx(queue, 4).unwrap();
            frame.bytes_mut().copy_from_slice(b"held");
            frame
                .commit(Commit {
                    len: 4,
                    token: SenderToken::new(token),
                    options: TxOptions::none(),
                })
                .unwrap()
        })
        .collect();
    let first = *a.tx.capabilities();
    let mut endpoint = SocketsEndpoint::join(a.tx, a.rx).unwrap();
    let entries = reset_all(&mut endpoint);
    assert_eq!(entries.len(), 3);
    assert!(entries.iter().all(|entry| entry.outcome
        == TxItemOutcome::Returned {
            reason: ReturnReason::Reset
        }));

    let snapshot = *endpoint.reopen(&os_config(local)).unwrap();
    assert_eq!(snapshot.local, local, "the closed socket freed its port");
    assert_eq!(snapshot.epoch.get().get(), 2);
    assert_eq!(
        (snapshot.dont_fragment, snapshot.tx_batch),
        (first.dont_fragment, first.tx_batch),
        "probed again with the same results"
    );
    let (mut tx, rx) = endpoint.split().unwrap();
    assert!(tickets.iter().all(|ticket| !tx.is_pending(*ticket)));
    assert_eq!(tx.claim_tx(queue, 4).err(), Some(ClaimError::UnknownQueue));
    let mut a = Node { tx, rx, local };
    let queue = a.queue_to(b.local);
    let (outcome, entries) = a.send(queue, &[b"after reset"]);
    assert_eq!(outcome.submitted, 1);
    assert!(all_submitted(&entries));
    let mut at_b = Recorder::default();
    receive(&mut b.rx, &mut at_b, 1);
    assert_eq!(at_b.datagrams, vec![(b"after reset".to_vec(), local)]);
    a.shutdown();
    b.shutdown();
}

/// The snapshot of a real socket: the probed rows, the `LibraryApi` rows of
/// decision O-3 and the buffer read backs (section 12, buffer sizes).
#[cfg(target_os = "linux")]
#[test]
fn snapshot_of_a_linux_socket() {
    let mut wanted = os_config(loopback_any_port());
    wanted.send_buffer = SocketsConfig::new(loopback_any_port()).send_buffer;
    wanted.recv_buffer = SocketsConfig::new(loopback_any_port()).recv_buffer;
    let endpoint = SocketsEndpoint::open(&wanted, InstanceId::FIRST, OsSocket::new()).unwrap();
    let snapshot = *endpoint.capabilities();
    assert_eq!(snapshot.platform, Platform::Linux);
    assert_ne!(snapshot.local.port(), 0);
    assert_eq!(snapshot.dont_fragment, CapabilityState::Active);
    assert_eq!(snapshot.tx_batch, CapabilityState::Active);
    let library = CapabilityState::Unavailable(Reason::LibraryApi);
    for state in [
        snapshot.rx_batch,
        snapshot.gso,
        snapshot.gro,
        snapshot.kernel_stamps,
        snapshot.hardware_stamps,
        snapshot.busy_poll,
    ] {
        assert_eq!(state, library);
    }
    assert!(!snapshot.enobufs_reported);
    for (buffer, requested) in [
        (snapshot.send_buffer, wanted.send_buffer),
        (snapshot.recv_buffer, wanted.recv_buffer),
    ] {
        let requested = requested.unwrap();
        let effective = buffer.effective.unwrap();
        assert_eq!(buffer.requested, Some(requested));
        let expected = if effective >= requested.get() {
            CapabilityState::Active
        } else {
            CapabilityState::Fallback(Reason::BelowRequest { effective })
        };
        assert_eq!(buffer.state, expected);
    }
    // A required buffer below the request fails to open (8.3).
    let below = [
        (Capability::SendBuffer, snapshot.send_buffer.state),
        (Capability::RecvBuffer, snapshot.recv_buffer.state),
    ];
    for (capability, state) in below {
        if state == CapabilityState::Active {
            continue;
        }
        let mut required = wanted;
        required.require = CapabilitySet::EMPTY.with(capability);
        assert_eq!(
            SocketsEndpoint::open(&required, InstanceId::FIRST, OsSocket::new()).err(),
            Some(OpenError::RequiredCapability { capability, state })
        );
    }
    let (tx, rx) = endpoint.split().unwrap();
    let mut endpoint = SocketsEndpoint::join(tx, rx).unwrap();
    assert!(retire_all(&mut endpoint).is_empty());
}

/// The snapshot of a real macOS socket (4.1, 8.1, decision O-2): what
/// `std` cannot do is recorded, never made up. Batching is the
/// `Fallback(Platform)` of single sends; don't fragment and the buffer
/// requests are `Fallback(LibraryApi)` with no effective size; the
/// decision O-3 rows are `LibraryApi` as on Linux. A required buffer or
/// batching fails to open (8.3).
#[cfg(target_os = "macos")]
#[test]
fn snapshot_of_a_macos_socket() {
    let mut wanted = os_config(loopback_any_port());
    wanted.send_buffer = SocketsConfig::new(loopback_any_port()).send_buffer;
    wanted.recv_buffer = SocketsConfig::new(loopback_any_port()).recv_buffer;
    let endpoint = SocketsEndpoint::open(&wanted, InstanceId::FIRST, OsSocket::new()).unwrap();
    let snapshot = *endpoint.capabilities();
    assert_eq!(snapshot.platform, Platform::MacOs);
    assert_ne!(snapshot.local.port(), 0);
    let library = CapabilityState::Unavailable(Reason::LibraryApi);
    for state in [
        snapshot.rx_batch,
        snapshot.gso,
        snapshot.gro,
        snapshot.kernel_stamps,
        snapshot.hardware_stamps,
        snapshot.busy_poll,
    ] {
        assert_eq!(state, library);
    }
    let fallback = CapabilityState::Fallback(Reason::LibraryApi);
    assert_eq!(snapshot.dont_fragment, fallback);
    assert_eq!(
        snapshot.tx_batch,
        CapabilityState::Fallback(Reason::Platform)
    );
    assert_eq!(snapshot.user_observations, CapabilityState::Active);
    assert!(!snapshot.enobufs_reported);
    for (buffer, requested) in [
        (snapshot.send_buffer, wanted.send_buffer),
        (snapshot.recv_buffer, wanted.recv_buffer),
    ] {
        assert_eq!(
            buffer,
            BufferSize {
                requested,
                effective: None,
                state: fallback,
            }
        );
    }
    let missing = [
        (Capability::DontFragment, fallback),
        (Capability::TxBatch, snapshot.tx_batch),
        (Capability::SendBuffer, fallback),
        (Capability::RecvBuffer, fallback),
    ];
    for (capability, state) in missing {
        let mut required = wanted;
        required.require = CapabilitySet::EMPTY.with(capability);
        assert_eq!(
            SocketsEndpoint::open(&required, InstanceId::FIRST, OsSocket::new()).err(),
            Some(OpenError::RequiredCapability { capability, state })
        );
    }
    let (tx, rx) = endpoint.split().unwrap();
    let mut endpoint = SocketsEndpoint::join(tx, rx).unwrap();
    assert!(retire_all(&mut endpoint).is_empty());
}

/// Section 12, path MTU on loopback: the loopback route is measured and
/// `Active`; a route whose measurement fails (the broadcast address, which
/// the temporary socket cannot connect to without `SO_BROADCAST`) is
/// `Fallback(Unverified)`, or `PathUnverified` when the path MTU is
/// required.
#[cfg(target_os = "linux")]
#[test]
fn path_mtu_on_loopback() {
    let mut node = Node::loopback();
    let peer = Node::loopback();
    let route = node.tx.add_route(peer.local).unwrap();
    let info = node.tx.route_info(route).unwrap();
    assert_eq!(info.path_mtu, CapabilityState::Active);
    assert!(info.route_mtu.unwrap() >= 256 + 8 + 20);

    let broadcast = SocketAddr::from((Ipv4Addr::BROADCAST, 9));
    let route = node.tx.add_route(broadcast).unwrap();
    assert_eq!(
        node.tx.route_info(route).unwrap(),
        RouteInfo {
            route_mtu: None,
            path_mtu: CapabilityState::Fallback(Reason::Unverified),
        }
    );
    node.shutdown();

    let mut required = os_config(loopback_any_port());
    required.require = CapabilitySet::EMPTY.with(Capability::PathMtu);
    let mut node = Node::open(&required);
    assert_eq!(
        node.tx.add_route(broadcast),
        Err(RouteError::PathUnverified)
    );
    assert!(node.tx.add_route(peer.local).is_ok());
    node.shutdown();
    peer.shutdown();
}

/// Section 12, path MTU on macOS: no route MTU is measured (4.5), so every
/// route, loopback included, takes the declared fallback,
/// `Fallback(Unverified)` with no route MTU, and fails with
/// `PathUnverified` when the path MTU is required.
#[cfg(target_os = "macos")]
#[test]
fn path_mtu_on_loopback() {
    let mut node = Node::loopback();
    let peer = Node::loopback();
    let route = node.tx.add_route(peer.local).unwrap();
    assert_eq!(
        node.tx.route_info(route).unwrap(),
        RouteInfo {
            route_mtu: None,
            path_mtu: CapabilityState::Fallback(Reason::Unverified),
        }
    );
    node.shutdown();

    let mut required = os_config(loopback_any_port());
    required.require = CapabilitySet::EMPTY.with(Capability::PathMtu);
    let mut node = Node::open(&required);
    assert_eq!(
        node.tx.add_route(peer.local),
        Err(RouteError::PathUnverified)
    );
    node.shutdown();
    peer.shutdown();
}

/// Section 12, `ECONNREFUSED` on send, on a real socket: an unconnected
/// socket gets no ICMP error (on Linux without `IP_RECVERR`, S-9; on macOS
/// as on every BSD), so datagrams to a port nobody listens on are
/// `Submitted` and neither half counts a peer error. The `PeerError` path of a reported `ECONNREFUSED` is the scripted
/// test `econnrefused_on_send`.
#[test]
fn an_unanswered_port_on_loopback() {
    let closed = UdpSocket::bind(loopback_any_port())
        .unwrap()
        .local_addr()
        .unwrap();
    let mut node = Node::loopback();
    let queue = node.queue_to(closed);
    for _ in 0..3 {
        let (outcome, entries) = node.send(queue, &[b"anyone?"]);
        assert_eq!(outcome.submitted, 1);
        assert!(all_submitted(&entries));
        assert!(!entries.iter().any(|entry| entry.outcome
            == TxItemOutcome::Pending {
                cause: PendingCause::PeerError
            }));
    }
    let outcome = node
        .rx
        .poll_rx(config().rx_budget().unwrap(), &mut Recorder::default());
    assert_eq!(outcome.stop, RxStop::WouldBlock);
    assert_eq!((node.tx.peer_errors(), node.rx.peer_errors()), (0, 0));
    node.shutdown();
}

/// A multicast endpoint on `local` joined to `group` on the default
/// interface, or `None` when the host cannot join (a recorded skip).
fn multicast_node(local: SocketAddr, group: Ipv4Addr, loopback: bool) -> Option<Node> {
    let mut wanted = os_config(local);
    let mut multicast = MulticastConfig::new(IpAddr::V4(group), InterfaceSel::Index(0));
    multicast.loopback = loopback;
    wanted.multicast = Some(multicast);
    match SocketsEndpoint::open(&wanted, InstanceId::FIRST, OsSocket::new()) {
        Ok(endpoint) => {
            let local = endpoint.capabilities().local;
            let (tx, rx) = endpoint.split().unwrap();
            Some(Node { tx, rx, local })
        }
        Err(error) => {
            skip(&format!("multicast join on the default interface: {error}"));
            None
        }
    }
}

/// Section 12, multicast, as far as one network namespace allows: a group
/// joined on the default interface, the sender's own datagrams looped back
/// (`IP_MULTICAST_LOOP`), the receiver bound to the group address so a
/// second group on the same port is not delivered, and loop off honored.
/// Needs an interface with a multicast route: a container's `eth0` on
/// Linux, where `lo` has no multicast flag, or the macOS default route
/// interface, through which `std` also sends (no `IP_MULTICAST_IF`). A host
/// without one records a skip. Delivery between namespaces and an explicit
/// interface run in the privileged gate (`privileged`, karyos#179).
#[test]
fn multicast_loopback_on_the_default_interface() {
    let group_a = Ipv4Addr::new(239, 255, 77, 1);
    let group_b = Ipv4Addr::new(239, 255, 77, 2);
    let any = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
    let Some(mut receiver_a) = multicast_node(SocketAddr::from((group_a, 0)), group_a, true) else {
        return;
    };
    let port = receiver_a.local.port();
    let destination = SocketAddr::from((group_a, port));
    let mut receiver_b = multicast_node(SocketAddr::from((group_b, port)), group_b, true).unwrap();
    let mut looped = multicast_node(any, group_a, true).unwrap();
    let mut quiet = multicast_node(any, group_a, false).unwrap();
    let skipped = multicast_loopback(
        &mut receiver_a,
        &mut receiver_b,
        &mut looped,
        &mut quiet,
        destination,
    );
    // Every node retires, on a skip too: a TX half dropped with an item
    // queued discards it (karyos#880).
    finish([receiver_a, receiver_b, looped, quiet], skipped);
}

/// A skip that leaves an item pending retires it rather than failing the
/// shutdown check, as a multicast send refused with no route does
/// (karyos#880).
#[test]
fn a_skip_retires_a_pending_item() {
    let mut node = Node::loopback();
    let queue = node.queue_to(node.local);
    let mut frame = node.tx.claim_tx(queue, 4).unwrap();
    frame.bytes_mut().copy_from_slice(b"left");
    frame
        .commit(Commit {
            len: 4,
            token: SenderToken::new(0),
            options: TxOptions::none(),
        })
        .unwrap();
    finish(
        [node],
        Some("a forced skip with an item pending".to_owned()),
    );
}

/// The checks of [`multicast_loopback_on_the_default_interface`], returning
/// why the host skips them, if it does.
fn multicast_loopback(
    receiver_a: &mut Node,
    receiver_b: &mut Node,
    looped: &mut Node,
    quiet: &mut Node,
    destination: SocketAddr,
) -> Option<String> {
    let looped_queue = looped.queue_to(destination);
    let quiet_queue = quiet.queue_to(destination);

    let (outcome, _) = looped.send(looped_queue, &[b"to group a"]);
    if outcome.submitted != 1 {
        return Some(format!(
            "multicast send on the default interface: {outcome:?}"
        ));
    }
    let mut at_a = Recorder::default();
    receive(&mut receiver_a.rx, &mut at_a, 1);
    if at_a.datagrams.is_empty() {
        return Some("multicast loop delivered nothing on this host".to_owned());
    }
    assert_eq!(at_a.datagrams.len(), 1);
    let (bytes, source) = at_a.datagrams.remove(0);
    assert_eq!(bytes, b"to group a");
    assert_eq!(source.port(), looped.local.port());
    // The group bind of B keeps group A's datagram out.
    let outcome = receiver_b
        .rx
        .poll_rx(config().rx_budget().unwrap(), &mut Recorder::default());
    assert_eq!((outcome.delivered, outcome.stop), (0, RxStop::WouldBlock));

    // Loop off: the quiet sender's datagram is not delivered on this host.
    // Loopback delivery is synchronous, so the marker sent after it is the
    // first and only datagram the receiver sees.
    let (outcome, _) = quiet.send(quiet_queue, &[b"not looped"]);
    assert_eq!(outcome.submitted, 1);
    let (outcome, _) = looped.send(looped_queue, &[b"marker"]);
    assert_eq!(outcome.submitted, 1);
    let mut after = Recorder::default();
    receive(&mut receiver_a.rx, &mut after, 1);
    let outcome = receiver_a
        .rx
        .poll_rx(config().rx_budget().unwrap(), &mut after);
    assert_eq!(outcome.stop, RxStop::WouldBlock);
    assert_eq!(after.datagrams.len(), 1);
    assert_eq!(after.datagrams[0].0, b"marker");
    None
}
