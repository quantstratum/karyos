// SPDX-License-Identifier: Apache-2.0

use std::net::SocketAddr;

use karyos_protocol::network::Alias;

use super::{PathIntake, Queue};
use crate::agents::EndpointId;
use crate::paths::PathConfig;

const ALIAS: Alias = Alias {
    session_id: 5,
    stream_id: 6,
};

fn intake(paths: u8, queue: u16) -> PathIntake {
    PathIntake::new(&PathConfig {
        max_paths: paths,
        path_queue_datagrams: queue,
        ..PathConfig::default()
    })
    .unwrap()
}

fn from(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// Pops every datagram: its endpoint, first byte and poll time.
fn drain(intake: &mut PathIntake) -> Vec<(EndpointId, u8, u64)> {
    let mut out = Vec::new();
    let slab = intake.take_slab();
    while let Some((endpoint, entry)) = intake.pop() {
        let first = PathIntake::bytes(&entry, &slab)[0];
        out.push((endpoint, first, entry.now));
        intake.release(entry);
    }
    intake.put_slab(slab);
    out
}

/// Within one path the order is the order of arrival, DATA and heartbeats
/// alike, and each datagram keeps its poll's time however late it is
/// drained.
#[test]
fn one_paths_datagrams_keep_their_order_and_poll_time() {
    let mut intake = intake(2, 8);
    let a = EndpointId(1);
    for (byte, now) in [(1u8, 100u64), (2, 100), (3, 250)] {
        assert_eq!(
            intake.push(a, (from(1), ALIAS, now), &[byte; 32]),
            Queue::Queued
        );
    }
    assert!(intake.holds(a));
    // Drained "a turn later": the stamps are the polls'.
    assert_eq!(drain(&mut intake), [(a, 1, 100), (a, 2, 100), (a, 3, 250)]);
    assert!(!intake.holds(a));
}

/// A slow path is served once per turn: a burst on A does not hold B's
/// datagram behind it.
#[test]
fn round_robin_serves_a_slow_path() {
    let mut intake = intake(2, 8);
    let (a, b) = (EndpointId(1), EndpointId(2));
    for byte in 1..=4u8 {
        let _ = intake.push(a, (from(1), ALIAS, 10), &[byte; 16]);
    }
    let _ = intake.push(b, (from(2), ALIAS, 10), &[9; 16]);
    let order: Vec<(EndpointId, u8)> = drain(&mut intake)
        .into_iter()
        .map(|(endpoint, byte, _)| (endpoint, byte))
        .collect();
    assert_eq!(order, [(a, 1), (b, 9), (a, 2), (a, 3), (a, 4)]);
}

/// A full queue drops only its own path's datagram; the other path's queue
/// takes its own.
#[test]
fn a_full_queue_drops_only_its_paths_datagram() {
    let mut intake = intake(2, 2);
    let (a, b) = (EndpointId(1), EndpointId(2));
    assert_eq!(intake.push(a, (from(1), ALIAS, 0), &[1; 8]), Queue::Queued);
    assert_eq!(intake.push(a, (from(1), ALIAS, 0), &[2; 8]), Queue::Queued);
    assert_eq!(intake.push(a, (from(1), ALIAS, 0), &[3; 8]), Queue::Dropped);
    assert_eq!(intake.push(b, (from(2), ALIAS, 0), &[4; 8]), Queue::Queued);
    assert_eq!(intake.waiting(), Some(3));
    let firsts: Vec<u8> = drain(&mut intake).into_iter().map(|(_, b, _)| b).collect();
    assert_eq!(firsts, [1, 4, 2]);
}

/// With every queue taken, a third endpoint is not queued (the caller
/// delivers it at once); an idle queue is freed for it.
#[test]
fn a_third_endpoint_waits_for_a_free_queue() {
    let mut intake = intake(2, 4);
    let (a, b, c) = (EndpointId(1), EndpointId(2), EndpointId(3));
    let _ = intake.push(a, (from(1), ALIAS, 0), &[1; 8]);
    let _ = intake.push(b, (from(2), ALIAS, 0), &[2; 8]);
    assert_eq!(intake.push(c, (from(3), ALIAS, 0), &[3; 8]), Queue::Bypass);
    let _ = drain(&mut intake);
    intake.release_idle();
    assert_eq!(intake.push(c, (from(3), ALIAS, 0), &[3; 8]), Queue::Queued);
    let _ = drain(&mut intake);
}

/// A datagram of the largest size an endpoint delivers is queued whole.
#[test]
fn the_largest_datagram_is_queued_whole() {
    use karyos_io::sockets::endpoint::MAX_DATAGRAM;

    let mut intake = intake(1, 1);
    let bytes = vec![7u8; usize::from(MAX_DATAGRAM)];
    assert_eq!(
        intake.push(EndpointId(1), (from(1), ALIAS, 0), &bytes),
        Queue::Queued
    );
    let slab = intake.take_slab();
    let (_, entry) = intake.pop().unwrap();
    assert_eq!(PathIntake::bytes(&entry, &slab), bytes.as_slice());
    intake.release(entry);
    intake.put_slab(slab);
    // One byte more is dropped, never queued nor bypassed.
    let longer = vec![7u8; usize::from(MAX_DATAGRAM) + 1];
    assert_eq!(
        intake.push(EndpointId(1), (from(1), ALIAS, 0), &longer),
        Queue::Dropped
    );
}

/// A path whose queue holds datagrams is never bypassed: with every queue
/// taken, its later datagrams still join its own queue, behind the earlier
/// ones; only an endpoint with no queue is bypassed.
#[test]
fn a_waiting_path_is_never_bypassed() {
    let mut intake = intake(2, 4);
    let (a, b, c) = (EndpointId(1), EndpointId(2), EndpointId(3));
    let _ = intake.push(a, (from(1), ALIAS, 0), &[1; 8]);
    let _ = intake.push(b, (from(2), ALIAS, 0), &[2; 8]);
    assert_eq!(intake.push(c, (from(3), ALIAS, 0), &[9; 8]), Queue::Bypass);
    assert_eq!(intake.push(a, (from(1), ALIAS, 1), &[3; 8]), Queue::Queued);
    let order: Vec<(EndpointId, u8)> = drain(&mut intake)
        .into_iter()
        .map(|(endpoint, byte, _)| (endpoint, byte))
        .collect();
    assert_eq!(order, [(a, 1), (b, 2), (a, 3)]);
}

/// A path that stops being multi-path while its queue holds datagrams
/// still goes through its queue until the queue drains; then it bypasses.
#[test]
fn a_path_keeps_its_queue_until_it_drains() {
    let mut intake = intake(2, 4);
    let a = EndpointId(1);
    assert!(intake.takes(a, true));
    assert!(!intake.takes(a, false), "nothing waiting: bypass");
    let _ = intake.push(a, (from(1), ALIAS, 0), &[1; 8]);
    assert!(intake.takes(a, false), "waiting: queued behind");
    let _ = drain(&mut intake);
    assert!(!intake.takes(a, false));
}

/// A control on an endpoint first takes that path's queued datagrams, out
/// of turn and in order; the other paths keep theirs.
#[test]
fn one_paths_datagrams_are_taken_out_of_turn() {
    let mut intake = intake(2, 4);
    let (a, b) = (EndpointId(1), EndpointId(2));
    let _ = intake.push(b, (from(2), ALIAS, 0), &[9; 8]);
    let _ = intake.push(a, (from(1), ALIAS, 0), &[1; 8]);
    let _ = intake.push(a, (from(1), ALIAS, 0), &[2; 8]);
    let slab = intake.take_slab();
    let mut firsts = Vec::new();
    while let Some(entry) = intake.pop_from(a) {
        firsts.push(PathIntake::bytes(&entry, &slab)[0]);
        intake.release(entry);
    }
    intake.put_slab(slab);
    assert_eq!(firsts, [1, 2]);
    assert!(!intake.holds(a));
    assert!(intake.holds(b), "B keeps its datagram");
    let _ = drain(&mut intake);
}
