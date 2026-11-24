// SPDX-License-Identifier: Apache-2.0

//! The section 12 rows the standard Linux container cannot run (karyos#179,
//! decision O-7): multicast between interfaces, the `sendmmsg` probes under
//! seccomp, the path MTU of a 1280 byte link and an MTU shrink, and a real
//! `EAGAIN` from a small `SO_SNDBUF`. Each test is `#[ignore]`d, so the
//! standard gate lists it as ignored rather than passing it, and fails when
//! run outside `scripts/privileged-test.sh`, which builds the links below
//! in a container with `NET_ADMIN` and `SYS_ADMIN` and sets the variable
//! each test checks once its environment is in place.
//!
//! The links, all built by the script:
//! - `m0` 10.78.0.1/24 and `m1` 10.78.0.2/24: a veth pair, both ends in the
//!   test's namespace (`accept_local` on, `rp_filter` off), for multicast
//!   between interfaces.
//! - `v0` 10.77.0.1/24 to `v1` 10.77.0.2/24 in the namespace `peer`: the
//!   IPv4 link whose MTU the shrink test lowers.
//! - `p0` fd78::1/64 to `p1` fd78::2/64 in `peer`, MTU 1280.
//! - `s0` 10.79.0.1/24 to `s1` 10.79.0.2/24 in `peer`, behind a `tbf`
//!   qdisc of 100 kbit/s, so a burst outruns the link.

use std::num::NonZeroU32;

use super::*;
use crate::backend::SendError;

/// The variable `scripts/privileged-test.sh` sets once the links exist.
const NET_GATE: &str = "KARYOS_PRIVILEGED_NET";
/// The variable naming the seccomp profile the script ran the test under.
const SECCOMP_GATE: &str = "KARYOS_PRIVILEGED_SECCOMP";

/// `ENOSYS` and `EPERM` as the seccomp profiles return them.
const ENOSYS: i32 = 38;
const EPERM: i32 = 1;

/// Fails a run outside the privileged gate's network setup.
fn require_net() {
    assert_eq!(
        std::env::var(NET_GATE).as_deref(),
        Ok("1"),
        "run through scripts/privileged-test.sh (the namespace links)"
    );
}

/// Fails a run outside the privileged gate's seccomp profile `profile`.
fn require_seccomp(profile: &str) {
    assert_eq!(
        std::env::var(SECCOMP_GATE).as_deref(),
        Ok(profile),
        "run through scripts/privileged-test.sh (the {profile} seccomp profile)"
    );
}

/// The index of the interface `name`.
fn ifindex(name: &str) -> u32 {
    std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

/// Runs `ip` with `args`, which must succeed.
fn ip(args: &[&str]) {
    let status = std::process::Command::new("ip")
        .args(args)
        .status()
        .unwrap();
    assert!(status.success(), "ip {args:?}: {status}");
}

/// [`os_config`] for datagrams of 1,408 bytes and batches of 64.
fn large_config(local: SocketAddr) -> SocketsConfig {
    let mut config = os_config(local);
    config.max_datagram = nz(1408);
    config.tx_slots = nz(64);
    config.max_batch = nz(64);
    config
}

/// A multicast endpoint on `local`, joined to `group` on the interface
/// `index`, which also carries what it sends (`IP_MULTICAST_IF`).
fn joined(local: SocketAddr, group: Ipv4Addr, index: u32, loopback: bool) -> Node {
    let mut config = os_config(local);
    let mut multicast = MulticastConfig::new(IpAddr::V4(group), InterfaceSel::Index(index));
    multicast.loopback = loopback;
    config.multicast = Some(multicast);
    Node::open(&config)
}

/// Section 12, multicast between interfaces: a datagram to group A sent out
/// of `m0` arrives through the wire at `m1`. It reaches the receiver joined
/// to A on `m1`, not the receiver joined to A on `m0` (the sender's loop is
/// off and the kernel delivers to a membership on the arriving interface
/// only), and not the receiver bound to group B on `m1`.
#[test]
#[ignore = "privileged Linux gate: scripts/privileged-test.sh"]
fn privileged_multicast_between_interfaces() {
    require_net();
    let group_a = Ipv4Addr::new(239, 255, 78, 1);
    let group_b = Ipv4Addr::new(239, 255, 78, 2);
    let (m0, m1) = (ifindex("m0"), ifindex("m1"));
    let mut on_m1 = joined(SocketAddr::from((group_a, 0)), group_a, m1, false);
    let port = on_m1.local.port();
    let mut on_m0 = joined(SocketAddr::from((group_a, port)), group_a, m0, false);
    let mut other_group = joined(SocketAddr::from((group_b, port)), group_b, m1, false);
    let mut sender = joined(
        SocketAddr::from((Ipv4Addr::new(10, 78, 0, 1), 0)),
        group_a,
        m0,
        false,
    );
    let queue = sender.queue_to(SocketAddr::from((group_a, port)));
    let (outcome, entries) = sender.send(queue, &[b"across", b"marker"]);
    assert_eq!(outcome.submitted, 2);
    assert!(all_submitted(&entries));

    let mut at_m1 = Recorder::default();
    receive(&mut on_m1.rx, &mut at_m1, 2);
    let received: Vec<&[u8]> = at_m1
        .datagrams
        .iter()
        .map(|(bytes, _)| bytes.as_slice())
        .collect();
    assert_eq!(received, [b"across".as_slice(), b"marker".as_slice()]);
    assert!(at_m1.drops.is_empty());
    assert_eq!(
        at_m1.datagrams[0].1,
        SocketAddr::from((Ipv4Addr::new(10, 78, 0, 1), sender.local.port()))
    );
    // Both datagrams were delivered at m1 before these polls, so nothing
    // still in flight could reach the other two receivers.
    for node in [&mut on_m0, &mut other_group] {
        let outcome = node
            .rx
            .poll_rx(config().rx_budget().unwrap(), &mut Recorder::default());
        assert_eq!((outcome.delivered, outcome.stop), (0, RxStop::WouldBlock));
    }
    finish([on_m1, on_m0, other_group, sender], None);
}

/// Section 12, path MTU: over the 1280 byte link `p0`, a route for
/// datagrams of 1,408 bytes is `PathTooSmall` (1,408 + 48 > 1,280), and a
/// route for 1,232 byte datagrams, which fit exactly, is `Active` with the
/// link's MTU.
#[test]
#[ignore = "privileged Linux gate: scripts/privileged-test.sh"]
fn privileged_path_mtu_of_a_1280_byte_link() {
    require_net();
    let local = SocketAddr::from((std::net::Ipv6Addr::new(0xfd78, 0, 0, 0, 0, 0, 0, 1), 0));
    let peer = SocketAddr::from((std::net::Ipv6Addr::new(0xfd78, 0, 0, 0, 0, 0, 0, 2), 9));
    let mut node = Node::open(&large_config(local));
    assert_eq!(
        node.tx.add_route(peer),
        Err(RouteError::PathTooSmall {
            datagram: 1408,
            overhead: 48,
            route_mtu: 1280,
        })
    );
    node.shutdown();
    let mut fitting = large_config(local);
    fitting.max_datagram = nz(1232);
    let mut node = Node::open(&fitting);
    let route = node.tx.add_route(peer).unwrap();
    assert_eq!(
        node.tx.route_info(route).unwrap(),
        RouteInfo {
            route_mtu: Some(1280),
            path_mtu: CapabilityState::Active,
        }
    );
    node.shutdown();
}

/// Section 12, MTU shrink: a route measured at `v0`'s 1,500 bytes sends a
/// 1,400 byte datagram; once the link shrinks to 1,280 the same send
/// faults the queue with `MessageTooLarge` (don't fragment is set), and
/// nothing later is exposed until the queue is retried.
#[test]
#[ignore = "privileged Linux gate: scripts/privileged-test.sh"]
fn privileged_an_mtu_shrink_faults_the_queue() {
    require_net();
    ip(&["link", "set", "v0", "mtu", "1500"]);
    let mut node = Node::open(&large_config(SocketAddr::from((
        Ipv4Addr::new(10, 77, 0, 1),
        0,
    ))));
    let peer = SocketAddr::from((Ipv4Addr::new(10, 77, 0, 2), 9));
    let route = node.tx.add_route(peer).unwrap();
    assert_eq!(node.tx.route_info(route).unwrap().route_mtu, Some(1500));
    let queue = node
        .tx
        .open_queue(TxQueueConfig {
            authority: Authority::FIRST,
            route,
            max_pending: nz(8),
        })
        .unwrap();
    let datagram = [7_u8; 1400];
    let (outcome, entries) = node.send(queue, &[&datagram]);
    assert_eq!(outcome.submitted, 1);
    assert!(all_submitted(&entries));

    ip(&["link", "set", "v0", "mtu", "1280"]);
    let (outcome, entries) = node.send(queue, &[&datagram]);
    ip(&["link", "set", "v0", "mtu", "1500"]);
    let faulted = SendError::MessageTooLarge;
    assert_eq!(outcome.stop, FlushStop::Faulted(faulted));
    assert_eq!(outcome.submitted, 0);
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry.outcome)
            .collect::<Vec<_>>(),
        [TxItemOutcome::Pending {
            cause: PendingCause::Faulted(faulted)
        }]
    );
    let returned = node.retire();
    assert_eq!(returned.len(), 1);
}

/// Section 12 (section 9 environment), a small `SO_SNDBUF`: behind `s0`'s
/// 100 kbit/s qdisc each queued datagram keeps its send buffer charge, so
/// at the minimum buffer the kernel soon refuses with a real `EAGAIN`. A
/// `sendmmsg` that accepted some datagrams first loses that errno
/// (`ErrorLost`, 4.3); the next flush starts at the refused item, so its
/// `EAGAIN` is reported: the flush stops with `WouldBlock`, the item stays
/// pending as `WouldBlock`, and the queue is not faulted.
#[test]
#[ignore = "privileged Linux gate: scripts/privileged-test.sh"]
fn privileged_a_small_send_buffer_gives_eagain() {
    require_net();
    let mut config = large_config(SocketAddr::from((Ipv4Addr::new(10, 79, 0, 1), 0)));
    config.send_buffer = NonZeroU32::new(4096);
    let mut node = Node::open(&config);
    let queue = node.queue_to(SocketAddr::from((Ipv4Addr::new(10, 79, 0, 2), 9)));
    let datagram = [3_u8; 1400];
    let burst: [&[u8]; 8] = [&datagram; 8];
    let (mut outcome, mut entries) = node.send(queue, &burst);
    // At 100 kbit/s one datagram leaves every 112 ms; ten flushes in a
    // row cannot drain the buffer between them.
    for _ in 0..10 {
        if outcome.stop == FlushStop::WouldBlock {
            break;
        }
        assert!(
            matches!(outcome.stop, FlushStop::Exposed | FlushStop::ErrorLost),
            "{outcome:?}"
        );
        let mut report = TxReport::new();
        outcome = node.tx.flush(
            FlushRequest {
                queue,
                max_datagrams: nz(64),
                max_bytes: u32::MAX,
            },
            &mut Gate::default(),
            &mut report,
        );
        entries = drain(&mut report);
    }
    assert_eq!(outcome.stop, FlushStop::WouldBlock, "{outcome:?}");
    assert_eq!(outcome.submitted, 0);
    assert_eq!(
        entries.first().map(|entry| entry.outcome),
        Some(TxItemOutcome::Pending {
            cause: PendingCause::WouldBlock
        })
    );
    assert!(!entries.iter().any(|entry| matches!(
        entry.outcome,
        TxItemOutcome::Pending {
            cause: PendingCause::Faulted(_)
        }
    )));
    assert!(!node.retire().is_empty(), "the refused items are returned");
}

/// The probe rows under a seccomp profile that answers `sendmmsg` with
/// `errno`: TX batching is `Fallback(reason)`, sends still go out one
/// `sendmsg` each, and an endpoint that requires TX batching does not open.
fn probes_under_seccomp(errno: i32, reason: Reason) {
    let fallback = CapabilityState::Fallback(reason);
    let config = os_config(loopback_any_port());
    let endpoint = SocketsEndpoint::open(&config, InstanceId::FIRST, OsSocket::new()).unwrap();
    assert_eq!(endpoint.capabilities().tx_batch, fallback, "errno {errno}");
    let local = endpoint.capabilities().local;
    let (tx, rx) = endpoint.split().unwrap();
    let mut node = Node { tx, rx, local };
    let queue = node.queue_to(node.local);
    let (outcome, entries) = node.send(queue, &[b"one", b"two", b"three"]);
    assert_eq!(outcome.submitted, 3);
    assert_eq!(outcome.spent.ops, 3, "one sendmsg per datagram");
    assert!(all_submitted(&entries));
    let mut received = Recorder::default();
    receive(&mut node.rx, &mut received, 3);
    assert_eq!(received.datagrams.len(), 3);
    node.shutdown();

    let mut required = config;
    required.require = CapabilitySet::EMPTY.with(Capability::TxBatch);
    assert_eq!(
        SocketsEndpoint::open(&required, InstanceId::FIRST, OsSocket::new()).err(),
        Some(OpenError::RequiredCapability {
            capability: Capability::TxBatch,
            state: fallback,
        })
    );
}

/// Section 12, probes: `sendmmsg` answered `ENOSYS` is `Unsupported`.
#[test]
#[ignore = "privileged Linux gate: scripts/privileged-test.sh"]
fn privileged_probes_sendmmsg_enosys() {
    require_seccomp("enosys");
    probes_under_seccomp(ENOSYS, Reason::Unsupported { errno: ENOSYS });
}

/// Section 12, probes: `sendmmsg` answered `EPERM` is `Denied`.
#[test]
#[ignore = "privileged Linux gate: scripts/privileged-test.sh"]
fn privileged_probes_sendmmsg_eperm() {
    require_seccomp("eperm");
    probes_under_seccomp(EPERM, Reason::Denied { errno: EPERM });
}
