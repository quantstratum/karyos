// SPDX-License-Identifier: Apache-2.0

//! Whether an idle publication keeps its subscriber's paths (karyos#859,
//! plan 168): a measurement, not a pass or fail test. A later path is
//! live while PATH_HB or DATA reaches it (RP-3); a DATA heartbeat is
//! evidence of the image, not of a path. A publication sends PATH_HB only
//! when it is routed, so an idle one on one route leaves its subscriber's
//! paths without evidence. Each second of `KARYOS_IDLE_SECS` (default 60)
//! idle seconds prints the paths the subscriber rebound since it went
//! idle (each one lost first), PATH_HB sent and seen, the subscriber's SOLICITs and retries,
//! and the publisher's answers and rate drops, for a routed publication
//! (two paths) and one on one route, each to a two path subscription.
//!
//! ```text
//! KARYOS_IDLE_SECS=60 cargo test -p karyos-driver --lib --locked idle_paths -- --ignored --nocapture
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::print_stdout,
    reason = "a measurement printed to the job's log (ADR-0007 allows these in tests)"
)]

use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use karyos_client::OfferOutcome;
use karyos_protocol::channel::{Destination, Interface, Security, UdpConfig};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::Role;

use super::{BUDGET, aggregate, driver, free_port, multicast_probe, pump, shared};
use crate::agents::ThreadingMode;

/// The idle seconds: `KARYOS_IDLE_SECS`, or 60.
fn idle_secs() -> u64 {
    std::env::var("KARYOS_IDLE_SECS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(60)
}

fn channel(group: SocketAddr, paths: Vec<Interface>) -> UdpConfig {
    UdpConfig {
        retransmit_window: None,
        nak_control: Vec::new(),
        linger: None,
        destination: Destination::Multicast { group, ttl: None },
        interface: None,
        paths,
        reliable: true,
        flow_control: None,
        security: Security::Trusted,
    }
}

fn measure(label: &str, routed: bool) {
    if let Err(why) = multicast_probe() {
        let _ = writeln!(std::io::stderr(), "SKIPPED idle_paths {label}: {why}");
        return;
    }
    let two = vec![
        Interface::Address(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        Interface::Address(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    ];
    let port = free_port();
    let group = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 255, 0, 5)), port);
    let publishing = if routed {
        channel(group, two.clone())
    } else {
        channel(group, Vec::new())
    };
    let subscribing = channel(group, two);
    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    for side in [&mut a, &mut b] {
        side.net.as_mut().unwrap().assume_isolated_paths();
    }
    let _ = b.add_network_subscription(10, &subscribing).unwrap();
    let publication = a
        .add_network_publication(aggregate(10, 4, 1), &publishing)
        .unwrap();
    let mut image = None;
    pump(&mut [&mut a, &mut b], |drivers| {
        image = drivers[1].network_image(10, 4);
        image.is_some()
    });
    let Some(image) = image else {
        unreachable!("pumped until it exists");
    };
    let mut reader = b.subscribe_aggregate(&image, Role::Required).unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    let (mut sent, mut seen) = (0u32, 0u32);
    pump(&mut [&mut a, &mut b], |_| {
        while sent < 16 {
            match lane.offer(&[0u8; 100]).unwrap() {
                OfferOutcome::Accepted { .. } => sent += 1,
                _ => break,
            }
        }
        let _ = reader.poll(|_, _, _| seen += 1, BUDGET);
        seen == 16
    });
    // Idle from here: no offer; the reader keeps polling.
    let start = Instant::now();
    let mut next = Duration::from_secs(1);
    let total = Duration::from_secs(idle_secs());
    let bound_at_idle = b
        .net
        .as_ref()
        .unwrap()
        .receiver_counters()
        .unwrap()
        .paths_bound;
    while start.elapsed() < total {
        let _ = a.do_work().unwrap();
        let _ = b.do_work().unwrap();
        let _ = reader.poll(|_, _, _| seen += 1, BUDGET);
        if start.elapsed() >= next {
            next += Duration::from_secs(1);
            let receiver = b.net.as_ref().unwrap().receiver_counters().unwrap();
            let sessions = shared(&mut b).receiver.session_counters();
            let sender = a.net.as_ref().unwrap().sender_counters().unwrap();
            let answers = shared(&mut a).sender.session_counters();
            println!(
                "idle_paths {label} {:>3} s: rebound {} (bound {}) | path_hb sent {} seen {} unbound {} | data_unbound {} | solicits {} retries {} answered {} | publisher answers {} rate_limited {}",
                start.elapsed().as_secs(),
                receiver.paths_bound - bound_at_idle,
                receiver.paths_bound,
                sender.path_heartbeats_sent,
                receiver.path_heartbeats,
                receiver.path_heartbeats_unbound,
                receiver.data_unbound,
                sessions.solicits,
                sessions.solicit_retries,
                sessions.solicits_answered,
                answers.answers,
                answers.rate_limited,
            );
        }
        std::thread::sleep(Duration::from_micros(100));
    }
    let bound = b
        .net
        .as_ref()
        .unwrap()
        .receiver_counters()
        .unwrap()
        .paths_bound;
    println!(
        "idle_paths {label}: {} paths rebound in {} s idle",
        bound - bound_at_idle,
        total.as_secs()
    );
}

/// An idle routed publication (two paths) to a two path subscription.
#[test]
#[ignore = "a measurement: KARYOS_IDLE_SECS idle seconds"]
fn m859_an_idle_routed_publication_keeps_its_paths() {
    measure("routed", true);
}

/// An idle publication on one route to a two path subscription.
#[test]
#[ignore = "a measurement: KARYOS_IDLE_SECS idle seconds"]
fn m859_an_idle_single_route_publication_keeps_its_paths() {
    measure("single", false);
}
