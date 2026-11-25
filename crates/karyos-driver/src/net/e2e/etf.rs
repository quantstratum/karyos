// SPDX-License-Identifier: Apache-2.0

//! The `etf` route end to end over a veth pair with an `etf` qdisc
//! (ADR-0109 points 7 and 8; karyos#625): the privileged gate
//! (`scripts/privileged-test.sh`) builds `e0` (10.80.0.1) here and `e1`
//! (10.80.0.2) in the `peer` namespace, a root `prio` qdisc on `e0` that
//! maps priority 3 to band 0 and an `etf` leaf there (`CLOCK_TAI`, delta
//! 300 ms), and sets `KARYOS_PRIVILEGED_NET=1`. The receiver runs in
//! `peer`: this test binary again, under `ip netns exec`.
//!
//! A drop is forced as the qdisc makes one: lane 0's message for
//! `start + 1 s` is dequeued 300 ms early, at `start + 700 ms`; lane 1's
//! message for `start + 850 ms`, offered at `start + 750 ms`, is then
//! timed before the leaf's last dequeue, so the leaf drops it and reports
//! it with its time. Both lanes share the publication's one leaf.

use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use karyos_client::OfferOutcome;
use karyos_client::schedule::{ScheduleOptions, TimedRoute};
use karyos_protocol::channel::{Destination, EtfDeclaration, Interface, Security, UdpConfig};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::Role;

use super::{BUDGET, aggregate, driver, shared};
use crate::agents::ThreadingMode;

const SENDER: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 80, 0, 1));
const RECEIVER: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 80, 0, 2));
const MS: u64 = 1_000_000;
const DELTA: u64 = 300 * MS;
/// The longest the receiver listens, if its parent never stops it.
const LISTEN: Duration = Duration::from_secs(120);
/// How long the sender serves after its last offer, for catch-ups,
/// repairs and the receiver's gap handling.
const SETTLE: Duration = Duration::from_secs(4);

/// A line to the parent, flushed at once.
fn say(line: &str) {
    use std::io::Write;

    let mut out = std::io::stdout().lock();
    writeln!(out, "{line}").unwrap();
    out.flush().unwrap();
}

fn privileged() -> bool {
    std::env::var_os("KARYOS_PRIVILEGED_NET").is_some()
}

fn channel(interface: IpAddr, port: u16, reliable: bool, etf: bool) -> UdpConfig {
    UdpConfig {
        destination: Destination::Unicast(SocketAddr::new(RECEIVER, port)),
        interface: Some(Interface::Address(interface)),
        paths: Vec::new(),
        reliable,
        flow_control: None,
        security: Security::Trusted,
        retransmit_window: None,
        nak_control: Vec::new(),
        linger: None,
        path_skew: None,
        etf: etf.then_some(EtfDeclaration {
            priority: 3,
            delta: Duration::from_nanos(DELTA),
        }),
    }
}

/// The receiver, run in `peer` by [`privileged_etf_drops_are_caught_up_or_gapped`]
/// with `KARYOS_ETF_RECEIVER` set to `<reliable> <port>`: it prints
/// `ready`, then `got <lane> <index>` for each message, until its parent
/// closes its stdin, then `end`.
#[test]
#[ignore = "run in the peer namespace by the privileged etf test"]
fn privileged_etf_receiver() {
    let Some(args) = std::env::var_os("KARYOS_ETF_RECEIVER") else {
        return;
    };
    let args = args.into_string().unwrap();
    let (reliable, port) = args.split_once(' ').unwrap();
    let (reliable, port): (bool, u16) = (reliable.parse().unwrap(), port.parse().unwrap());
    let mut b = driver(ThreadingMode::Shared);
    let _ = b
        .add_network_subscription(10, &channel(RECEIVER, port, reliable, false))
        .unwrap();
    say("ready");
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stopped = std::sync::Arc::clone(&stop);
    let _ = std::thread::spawn(move || {
        let mut sink = Vec::new();
        let _ = std::io::Read::read_to_end(&mut std::io::stdin(), &mut sink);
        stopped.store(true, std::sync::atomic::Ordering::Release);
    });
    let deadline = Instant::now() + LISTEN;
    let mut reader = None;
    while Instant::now() < deadline && !stop.load(std::sync::atomic::Ordering::Acquire) {
        let _ = b.do_work().unwrap();
        if reader.is_none()
            && let Some(image) = b.network_image(10, 3)
        {
            reader = Some(b.subscribe_aggregate(&image, Role::Required).unwrap());
            say("image");
        }
        if let Some(reader) = reader.as_mut() {
            let _ = reader.poll(
                |bytes, lane, _| {
                    let index = u32::from_le_bytes(bytes[..4].try_into().unwrap());
                    say(&format!("got {} {index}", lane.get()));
                },
                BUDGET,
            );
        }
        std::thread::sleep(Duration::from_micros(200));
    }
    say("end");
}

/// ADR-0109 point 8: over a real `etf` leaf, a reliable publication's
/// dropped datagram is caught up on the immediate route and every message
/// is delivered; an unreliable one's is a gap at the receiver, and the
/// rest is delivered.
#[test]
#[ignore = "needs the privileged gate's veth pair, etf qdisc and peer namespace"]
fn privileged_etf_drops_are_caught_up_or_gapped() {
    if !privileged() {
        return;
    }
    for (reliable, port) in [(true, 47_300u16), (false, 47_301)] {
        let (got, counts) = run(reliable, port);
        // One drop, matched by its report; the margin keeps late reports
        // at zero (ADR-0109 point 7).
        assert_eq!(
            (counts.dropped, counts.late_drop_reports),
            (1, 0),
            "{counts:?}, got {got:?}"
        );
        if reliable {
            assert_eq!((counts.caught_up, counts.gaps), (1, 0), "{counts:?}");
            assert_eq!(got, [(0, 0), (0, 1), (1, 0), (1, 1)], "delivered complete");
        } else {
            assert_eq!((counts.gaps, counts.caught_up), (1, 0), "{counts:?}");
            assert_eq!(got, [(0, 0), (0, 1), (1, 1)], "a gap where the drop was");
        }
    }
}

/// One run: the receiver in `peer`, the publication here; what the
/// receiver got, sorted, and what the etf drop ledger counted.
fn run(reliable: bool, port: u16) -> (Vec<(u8, u32)>, crate::agents::data::etf::EtfCounts) {
    let exe = std::env::current_exe().unwrap();
    let mut child = Command::new("ip")
        .args(["netns", "exec", "peer"])
        .arg(&exe)
        .args([
            "--exact",
            "net::e2e::etf::privileged_etf_receiver",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("KARYOS_ETF_RECEIVER", format!("{reliable} {port}"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    for line in lines.by_ref() {
        // libtest may print the test's name before it on the same line.
        if line.unwrap().ends_with("ready") {
            break;
        }
    }
    // The receiver's lines, from now until its `end`.
    let reader = std::thread::spawn(move || {
        let mut got = Vec::new();
        for line in lines {
            let line = line.unwrap();
            if let Some(rest) = line.split_once("got ").map(|(_, rest)| rest) {
                let (lane, index) = rest.split_once(' ').unwrap();
                got.push((lane.parse().unwrap(), index.parse().unwrap()));
            }
            // Read to the end, so the receiver's summary has a reader.
        }
        got
    });
    let mut a = driver(ThreadingMode::Shared);
    let mut config = aggregate(10, 3, 2);
    config.stream.buffer.schedule_capacity = 8;
    let options = ScheduleOptions::default()
        .with_route(TimedRoute::Etf { advance: DELTA })
        .with_max_horizon(2_000 * MS);
    let publication = a
        .add_timed_network_publication(
            config,
            &channel(SENDER, port, reliable, true),
            None,
            options,
        )
        .unwrap();
    let mut lanes = [
        a.publication(publication.lane(Lane::ZERO).unwrap())
            .unwrap(),
        a.publication(publication.lane(Lane::try_new(1).unwrap()).unwrap())
            .unwrap(),
    ];
    // The receiver's status messages connect the publication first.
    let start = karyos_sys::host_clock::host_monotonic_ns() + 1_000 * MS;
    // (lane, index, offered at, requested time), from `start`.
    let plan = [
        (0usize, 0u32, 0u64, 1_000 * MS),
        (1, 0, 750 * MS, 850 * MS),
        (1, 1, 900 * MS, 1_100 * MS),
        (0, 1, 950 * MS, 1_200 * MS),
    ];
    let mut next = 0;
    let mut settled = None;
    let stdin = child.stdin.take();
    // Serve until the last offer has settled, then stop the receiver and
    // serve until it ends: heartbeats, catch-ups and repairs go on.
    let mut stdin = stdin;
    while !reader.is_finished() {
        if next == plan.len() {
            let at = *settled.get_or_insert_with(|| Instant::now() + SETTLE);
            if Instant::now() >= at {
                drop(stdin.take());
            }
        }
        let _ = a.do_work().unwrap();
        let now = karyos_sys::host_clock::host_monotonic_ns();
        while let Some(&(lane, index, at, time)) = plan.get(next) {
            if now < start + at {
                break;
            }
            let outcome = lanes[lane]
                .offer_at(&index.to_le_bytes(), start + time)
                .unwrap();
            assert!(
                matches!(outcome, OfferOutcome::Accepted { .. }),
                "{outcome:?}"
            );
            next += 1;
        }
        std::thread::sleep(Duration::from_micros(200));
    }
    assert_eq!(next, plan.len(), "every message was offered");
    let mut got = reader.join().unwrap();
    let _ = child.wait().unwrap();
    got.sort_unstable();
    let counts = shared(&mut a).sender.etf_counts(0).unwrap();
    (got, counts)
}
