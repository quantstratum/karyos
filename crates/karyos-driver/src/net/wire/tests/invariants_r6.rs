// SPDX-License-Identifier: Apache-2.0

//! H8 round 6 (karyos#648): the round 5 review's evidence rows R5-10 and
//! R5-11 through production admission and both drivers' real agents.

use super::*;

use std::net::UdpSocket;

use karyos_client::OfferOutcome;
use karyos_protocol::lanes::drr::Budget;
use karyos_protocol::protection::hmac_sha256::Domain;
use karyos_sys::log_buffer::Role;

const BUDGET: Budget = Budget {
    work: 256,
    bytes: 1 << 22,
};

/// A UDP relay between a publisher and the subscriber: the publisher
/// sends to it, and the subscriber sees every datagram from the relay's
/// address, so the source stays the same across a publisher restart.
/// Holding, it keeps the publisher's DATA (domain 1) instead of passing
/// it on: datagrams sent and never seen by the subscriber.
struct Relay {
    socket: UdpSocket,
    subscriber: SocketAddr,
    publisher: Option<SocketAddr>,
    hold: bool,
    held: Vec<Vec<u8>>,
}

impl Relay {
    fn new(subscriber: SocketAddr) -> Self {
        let socket = UdpSocket::bind(SocketAddr::new(LOOPBACK, 0)).unwrap();
        socket.set_nonblocking(true).unwrap();
        Self {
            socket,
            subscriber,
            publisher: None,
            hold: false,
            held: Vec::new(),
        }
    }

    fn address(&self) -> SocketAddr {
        self.socket.local_addr().unwrap()
    }

    /// Passes on what arrived: the subscriber's datagrams to the current
    /// publisher, the publisher's to the subscriber unless held.
    fn step(&mut self) {
        let mut buffer = [0u8; 9000];
        while let Ok((length, from)) = self.socket.recv_from(&mut buffer) {
            let bytes = &buffer[..length];
            if from == self.subscriber {
                if let Some(publisher) = self.publisher {
                    let _ = self.socket.send_to(bytes, publisher);
                }
            } else {
                self.publisher = Some(from);
                // The envelope's domain byte (ADR-0086 section 2).
                if self.hold && bytes.get(10) == Some(&(Domain::Data as u8)) {
                    self.held.push(bytes.to_vec());
                } else {
                    let _ = self.socket.send_to(bytes, self.subscriber);
                }
            }
        }
    }
}

/// Runs `drivers` and `relay` until `done`, at most 60 seconds of host
/// time: an image's liveness runs on the host's clock.
fn relay_until(
    drivers: &mut [&mut EmbeddedDriver],
    relay: &mut Relay,
    mut done: impl FnMut(&mut [&mut EmbeddedDriver], &mut Relay) -> bool,
) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while std::time::Instant::now() < deadline {
        for driver in drivers.iter_mut() {
            let _ = driver.do_work().unwrap();
        }
        relay.step();
        if done(drivers, relay) {
            return true;
        }
        std::thread::sleep(Duration::from_micros(500));
    }
    false
}

/// An authenticated publisher of `STREAM` sending to `to`.
fn publisher_to(to: SocketAddr) -> (EmbeddedDriver, crate::embedded::AggregateHandle) {
    let (mut publisher, _keys) = keyed(&borrowed(&publisher_files()));
    let security = Security::Authenticated(auth(Some(authority(control()))));
    let handle = publisher
        .add_network_publication(aggregate(STREAM), &udp(Destination::Unicast(to), security))
        .unwrap();
    (publisher, handle)
}

/// R5-10, MP-4 (INV-RST-7; ADR-0035, ADR-0086 section 7): after a real
/// publisher restart, its replacement establishes a new identity from the
/// same source address. DATA the old publisher sealed and sent at
/// sequences the receiver never saw (held on the way) then arrives under
/// the replacement's binding: each is refused at authentication, nothing
/// is delivered or committed, no heartbeat is counted, and the image
/// stays the replacement's, live and not aborted.
#[test]
fn inv_r6_old_data_after_a_publisher_restart_never_reaches_the_replacement() {
    let (mut subscriber, _sub_keys) = keyed(&borrowed(&subscriber_files()));
    let security = Security::Authenticated(auth(Some(authority(control()))));
    subscriber
        .add_network_subscription_as(
            STREAM,
            &udp(Destination::Unicast(ANY_PORT), security),
            identity(RECEIVER),
        )
        .unwrap();
    let mut relay = Relay::new(subscriber.network_subscription_address(STREAM).unwrap());
    let (mut publisher, handle) = publisher_to(relay.address());
    let image_of = |driver: &EmbeddedDriver| driver.net.as_ref().unwrap().auth_image();
    let up = relay_until(
        &mut [&mut publisher, &mut subscriber],
        &mut relay,
        |d, _| image_of(d[1]).is_some() && !d[1].network_images(STREAM).is_empty(),
    );
    assert!(up, "the first publisher establishes");
    let (_, old, _) = image_of(&subscriber).unwrap();
    let (image, _) = subscriber.network_images(STREAM)[0];
    let mut reader = subscriber
        .subscribe_aggregate(&image, Role::Required)
        .unwrap();
    let mut lane = publisher
        .publication(handle.lane(Lane::ZERO).unwrap())
        .unwrap();
    let mut seen = 0u32;
    for i in 0..4u32 {
        assert!(matches!(
            lane.offer(&i.to_le_bytes()).unwrap(),
            OfferOutcome::Accepted { .. }
        ));
    }
    let delivered = relay_until(
        &mut [&mut publisher, &mut subscriber],
        &mut relay,
        |_, _| {
            let _ = reader.poll(|_, _, _| seen += 1, BUDGET);
            seen == 4
        },
    );
    assert!(delivered, "seen {seen} of 4 before the restart");
    // DATA sent and never seen: held on the way.
    relay.hold = true;
    for i in 4..8u32 {
        assert!(matches!(
            lane.offer(&i.to_le_bytes()).unwrap(),
            OfferOutcome::Accepted { .. }
        ));
    }
    let held = relay_until(&mut [&mut publisher], &mut relay, |_, relay| {
        relay.held.iter().filter(|bytes| bytes.len() > 96).count() >= 4
    });
    assert!(held, "the old DATA was sent: {} held", relay.held.len());
    let stale = std::mem::take(&mut relay.held);
    relay.hold = false;
    // The publisher restarts: a new driver, the same keys, a new identity.
    drop(lane);
    drop(publisher);
    relay.publisher = None;
    let (mut publisher, _handle) = publisher_to(relay.address());
    let replaced = relay_until(
        &mut [&mut publisher, &mut subscriber],
        &mut relay,
        |d, _| image_of(d[1]).is_some_and(|(_, identity, _)| identity != old),
    );
    assert!(
        replaced,
        "the replacement establishes: {:?}",
        image_of(&subscriber)
    );
    let (key, replacement, _) = image_of(&subscriber).unwrap();
    // The replacement's own traffic is paused; only the stale DATA flows.
    let counters =
        |driver: &EmbeddedDriver| driver.net.as_ref().unwrap().receiver_counters().unwrap();
    let before = counters(&subscriber);
    for bytes in &stale {
        relay.socket.send_to(bytes, relay.subscriber).unwrap();
    }
    let arrived = pump(&mut [&mut subscriber], |d| {
        counters(d[0]).datagrams >= before.datagrams + stale.len() as u64
    });
    assert!(arrived, "the stale DATA reached the receiver");
    for _ in 0..200 {
        let _ = subscriber.do_work().unwrap();
    }
    let after = counters(&subscriber);
    assert_eq!(after.data_committed, before.data_committed, "{after:?}");
    assert_eq!(
        after.heartbeats, before.heartbeats,
        "no liveness: {after:?}"
    );
    assert_eq!(
        after.auth_rejected,
        before.auth_rejected + stale.len() as u64,
        "each refused at authentication: {after:?}"
    );
    let _ = reader.poll(|_, _, _| seen += 1, BUDGET);
    assert_eq!(seen, 4, "nothing delivered");
    assert_eq!(
        image_of(&subscriber),
        Some((key, replacement, false)),
        "still the replacement's image"
    );
}
