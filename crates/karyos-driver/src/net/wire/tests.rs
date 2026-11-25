// SPDX-License-Identifier: Apache-2.0

//! The driver's wire key store and the admission of authenticated
//! channels, through the real admission paths: `post_sender`,
//! `subscribe_network`, the agents' bindings and the conductor duty
//! (karyos#648).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use std::cell::Cell;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use karyos_protocol::channel::{
    AuthenticatedChannel, ChannelAuthority, Destination, Interface, Security, UdpConfig,
};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, LossPolicy, PublicationMode};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;
use zeroize::Zeroizing;

use super::Dir;
use crate::agents::ThreadingMode;
use crate::embedded::{AggregateConfig, DriverConfig, EmbeddedDriver, StreamConfig};
use crate::error::{AuthRefusal, DriverError};
use crate::membership::ReceiverIdentity;
use crate::net::NetworkConfig;
use crate::wire_keys::store::{FileError, Files, KeyStore, RELOAD_INTERVAL_S};

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
/// 2026-11-18, inside every test key's validity.
const START: i64 = 1_795_000_000;
const STREAM: i32 = 6;
const RECEIVER: u64 = 77;

thread_local! {
    /// The wall clock of this test's drivers, in seconds.
    static WALL: Cell<i64> = const { Cell::new(START) };
}

fn wall() -> i64 {
    WALL.with(Cell::get)
}

fn advance(seconds: i64) {
    WALL.with(|wall| wall.set(wall.get() + seconds));
    // The reload cadence is monotonic (H8 R3-1): it moves too.
    super::MONO_SKEW.with(|skew| {
        skew.set(skew.get() + seconds.unsigned_abs() * 1_000_000_000);
    });
}

/// An in-memory directory shared with the test, which can fail to list.
#[derive(Clone, Default)]
struct Mem {
    files: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    fail_list: Arc<Mutex<bool>>,
    fail_writes: Arc<Mutex<bool>>,
}

impl Mem {
    fn put(&self, name: &str, bytes: &str) {
        self.files
            .lock()
            .unwrap()
            .insert(name.to_owned(), bytes.as_bytes().to_vec());
    }
}

impl Files for Mem {
    fn names(&self) -> Result<Vec<String>, FileError> {
        if *self.fail_list.lock().unwrap() {
            return Err(FileError::Refused);
        }
        Ok(self.files.lock().unwrap().keys().cloned().collect())
    }

    fn read(&self, name: &str, buf: &mut [u8]) -> Result<usize, FileError> {
        let files = self.files.lock().unwrap();
        let bytes = files.get(name).ok_or(FileError::NotFound)?;
        if bytes.len() >= buf.len() {
            return Err(FileError::Refused);
        }
        buf[..bytes.len()].copy_from_slice(bytes);
        Ok(bytes.len())
    }

    fn write_atomic(&self, name: &str, bytes: &[u8]) -> Result<(), FileError> {
        if *self.fail_writes.lock().unwrap() {
            return Err(FileError::Refused);
        }
        self.files
            .lock()
            .unwrap()
            .insert(name.to_owned(), bytes.to_vec());
        Ok(())
    }

    fn lock(&self) -> Result<(), FileError> {
        Ok(())
    }
}

fn channel_key(key_id: u32, stream_id: i32) -> String {
    format!(
        "format=karyos-wire-key-v1\nkey_id={key_id}\nfile_epoch=1\npurpose=channel\nprofile_id=1\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-01-30T00:00:00Z\nsecret={:02x}{}\nchannel_id=7\nstream_id={stream_id}\n",
        key_id % 256,
        "11".repeat(31)
    )
}

const PAIRWISE: &str = "format=karyos-wire-key-v1\nkey_id=9\nfile_epoch=1\npurpose=pairwise\nprofile_id=1\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-01-30T00:00:00Z\nsecret=2222222222222222222222222222222222222222222222222222222222222222\nreceiver_id=77\npublisher_id=5\n";
const SIGNING: &str = "format=karyos-wire-key-v1\nkey_id=10\nfile_epoch=1\npurpose=authority-signing\nprofile_id=4\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-04-30T00:00:00Z\nsecret=0909090909090909090909090909090909090909090909090909090909090909\nauthority_id=10\nguards=11,12\nabort=true\n";
const PUBLIC: &str = "format=karyos-wire-key-v1\nkey_id=10\nfile_epoch=1\npurpose=authority-public\nprofile_id=4\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-04-30T00:00:00Z\npublic=fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618\nauthority_id=10\nguards=11,12\nabort=true\n";

/// A key directory holding `files`, and an initialised state directory.
fn dirs(files: &[(&str, &str)]) -> (Mem, Mem) {
    let (keys, state) = (Mem::default(), Mem::default());
    for (name, text) in files {
        keys.put(name, text);
    }
    KeyStore::<Mem, Mem>::initialise(&state, Zeroizing::new([7; 32])).unwrap();
    (keys, state)
}

fn driver_with(subscriptions: usize) -> EmbeddedDriver {
    let mut network = NetworkConfig {
        threading: ThreadingMode::Shared,
        ..NetworkConfig::default()
    };
    network.agents.subscriptions = subscriptions;
    EmbeddedDriver::with_config(DriverConfig {
        network: Some(network),
        ..DriverConfig::default()
    })
    .unwrap()
}

/// A driver whose store holds `files`, and its key directory.
fn keyed(files: &[(&str, &str)]) -> (EmbeddedDriver, Mem) {
    let mut driver = driver_with(64);
    let (keys, state) = dirs(files);
    let report = driver
        .start_wire_keys_at(Box::new(keys.clone()) as Dir, Box::new(state) as Dir, wall)
        .unwrap();
    assert!(!report.alarm(), "{report:?}");
    (driver, keys)
}

fn publisher_files() -> Vec<(&'static str, String)> {
    vec![
        ("3-1.key", channel_key(3, STREAM)),
        ("9-1.key", PAIRWISE.to_owned()),
        ("10-1.key", SIGNING.to_owned()),
    ]
}

fn subscriber_files() -> Vec<(&'static str, String)> {
    vec![
        ("3-1.key", channel_key(3, STREAM)),
        ("9-1.key", PAIRWISE.to_owned()),
        ("10-1.key", PUBLIC.to_owned()),
    ]
}

fn borrowed<'a>(files: &'a [(&'static str, String)]) -> Vec<(&'static str, &'a str)> {
    files
        .iter()
        .map(|(name, text)| (*name, text.as_str()))
        .collect()
}

fn authority(control: SocketAddr) -> ChannelAuthority {
    ChannelAuthority {
        key_id: 10,
        authority_id: 10,
        guard_id: 11,
        control,
        follower_id: 0,
    }
}

fn auth(authority: Option<ChannelAuthority>) -> AuthenticatedChannel {
    AuthenticatedChannel {
        channel_key_id: 3,
        pairwise_key_id: 9,
        receiver_id: RECEIVER,
        authority,
    }
}

fn control() -> SocketAddr {
    SocketAddr::new(LOOPBACK, 7)
}

fn udp(destination: Destination, security: Security) -> UdpConfig {
    UdpConfig {
        retransmit_window: None,
        nak_control: Vec::new(),
        linger: None,
        path_skew: None,
        destination,
        interface: Some(Interface::Address(LOOPBACK)),
        paths: Vec::new(),
        reliable: true,
        flow_control: None,
        security,
        etf: None,
    }
}

fn aggregate(stream_id: i32) -> AggregateConfig {
    AggregateConfig {
        stream: StreamConfig {
            buffer: LogBufferConfig {
                term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
                spare_slots: 3,
                max_subscribers: 4,
                mtu: DEFAULT_MTU,
                max_reserved: MIN_TERM_LENGTH / 8,
                initial_term_id: TermId::new(7),
                lane: Lane::ZERO,
                session_id: 1,
                stream_id,
                claim_deadline: 100,
                publication: PublicationMode::Exclusive,
                schedule_capacity: 0,
            },
            allow_unconnected: true,
            on_required_loss: LossPolicy::Hold,
            conflation: None,
        },
        quanta: vec![u64::from(DEFAULT_MTU) * 4; 1],
    }
}

fn identity(receiver_id: u64) -> ReceiverIdentity {
    ReceiverIdentity {
        receiver_id: NonZeroU64::new(receiver_id).unwrap(),
        group_tag: 0,
    }
}

const ANY_PORT: SocketAddr = SocketAddr::new(LOOPBACK, 0);

fn refused(reason: AuthRefusal) -> DriverError {
    DriverError::AuthenticatedRefused { reason }
}

/// The authenticated state of `driver`'s roles.
fn roles(driver: &EmbeddedDriver) -> ((usize, usize, usize), (usize, usize, usize)) {
    driver.net.as_ref().unwrap().auth_state().unwrap()
}

/// Runs both drivers until `done`, at most 60 seconds of host time.
fn pump(
    drivers: &mut [&mut EmbeddedDriver],
    mut done: impl FnMut(&mut [&mut EmbeddedDriver]) -> bool,
) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while std::time::Instant::now() < deadline {
        for driver in drivers.iter_mut() {
            let _ = driver.do_work().unwrap();
        }
        if done(drivers) {
            return true;
        }
        std::thread::sleep(Duration::from_micros(200));
    }
    false
}

/// Item 1: an authenticated channel is refused, typed, by both roles of a
/// driver with no key store; nothing is created.
#[test]
fn authenticated_admission_needs_a_key_store() {
    let mut driver = driver_with(64);
    let to = SocketAddr::new(LOOPBACK, 9);
    let security = Security::Authenticated(auth(None));
    assert_eq!(
        driver
            .add_network_publication(aggregate(STREAM), &udp(Destination::Unicast(to), security))
            .unwrap_err(),
        refused(AuthRefusal::NoKeyStore)
    );
    assert_eq!(
        driver
            .add_network_subscription_as(
                STREAM,
                &udp(Destination::Unicast(ANY_PORT), security),
                identity(RECEIVER),
            )
            .unwrap_err(),
        refused(AuthRefusal::NoKeyStore)
    );
    let net = driver.net.as_ref().unwrap();
    assert_eq!((net.publication_count(), net.subscription_count()), (0, 0));
}

/// Item 1: a key id with no valid key of its purpose and scope refuses
/// admission, typed, on each role, before anything is posted.
#[test]
fn authenticated_admission_refuses_a_missing_key_typed() {
    let to = Destination::Unicast(SocketAddr::new(LOOPBACK, 9));
    let sub = Destination::Unicast(ANY_PORT);
    // The publisher holds no pairwise key, the subscriber no channel key
    // of this stream.
    let channel = channel_key(3, STREAM);
    let (mut publisher, _) = keyed(&[("3-1.key", &channel), ("10-1.key", SIGNING)]);
    let other = channel_key(3, STREAM + 1);
    let (mut subscriber, _) = keyed(&[
        ("3-1.key", &other),
        ("9-1.key", PAIRWISE),
        ("10-1.key", PUBLIC),
    ]);
    let cases = [
        (auth(None), AuthRefusal::PairwiseKey),
        (
            AuthenticatedChannel {
                channel_key_id: 4,
                ..auth(None)
            },
            AuthRefusal::ChannelKey,
        ),
    ];
    for (channel, reason) in cases {
        let security = Security::Authenticated(channel);
        assert_eq!(
            publisher
                .add_network_publication(aggregate(STREAM), &udp(to.clone(), security))
                .unwrap_err(),
            refused(reason)
        );
    }
    // The pairwise key of another receiver is no key for this one.
    let security = Security::Authenticated(AuthenticatedChannel {
        receiver_id: 78,
        ..auth(None)
    });
    let (mut paired, _) = keyed(&borrowed(&publisher_files()));
    assert_eq!(
        paired
            .add_network_publication(aggregate(STREAM), &udp(to.clone(), security))
            .unwrap_err(),
        refused(AuthRefusal::PairwiseKey)
    );
    // A guard the authority key does not list.
    let security = Security::Authenticated(auth(Some(ChannelAuthority {
        guard_id: 13,
        ..authority(control())
    })));
    assert_eq!(
        paired
            .add_network_publication(aggregate(STREAM), &udp(to, security))
            .unwrap_err(),
        refused(AuthRefusal::AuthorityKey)
    );
    let security = Security::Authenticated(auth(Some(authority(control()))));
    assert_eq!(
        subscriber
            .add_network_subscription_as(STREAM, &udp(sub.clone(), security), identity(RECEIVER))
            .unwrap_err(),
        refused(AuthRefusal::ChannelKey)
    );
    // The subscriber's authority must be a public authority key.
    let channel = channel_key(3, STREAM);
    let (mut unkeyed, _) = keyed(&[("3-1.key", &channel), ("9-1.key", PAIRWISE)]);
    assert_eq!(
        unkeyed
            .add_network_subscription_as(STREAM, &udp(sub, security), identity(RECEIVER))
            .unwrap_err(),
        refused(AuthRefusal::AuthorityKey)
    );
    for driver in [&publisher, &paired, &subscriber, &unkeyed] {
        let net = driver.net.as_ref().unwrap();
        assert_eq!((net.publication_count(), net.subscription_count()), (0, 0));
    }
}

/// Item 1: several receivers, fan-out, multicast, a dynamic or routed
/// channel, another receiver identity, or a second handle of the key with
/// other keys is ambiguous and refused, typed.
#[test]
fn authenticated_admission_refuses_ambiguous_configurations() {
    let (mut driver, _) = keyed(&borrowed(&publisher_files()));
    let security = Security::Authenticated(auth(None));
    let destinations = Destination::MultiDestination {
        destinations: vec![SocketAddr::new(LOOPBACK, 9), SocketAddr::new(LOOPBACK, 10)],
        control: None,
        mode: karyos_protocol::channel::ControlMode::Manual,
    };
    let multicast = Destination::Multicast {
        group: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 1, 1, 1)), 4000),
        ttl: None,
    };
    for destination in [destinations, multicast] {
        assert_eq!(
            driver
                .add_network_publication(aggregate(STREAM), &udp(destination, security))
                .unwrap_err(),
            refused(AuthRefusal::Ambiguous)
        );
    }
    let (mut subscriber, _) = keyed(&borrowed(&subscriber_files()));
    let channel = udp(Destination::Unicast(ANY_PORT), security);
    assert_eq!(
        subscriber
            .add_network_subscription_as(STREAM, &channel, identity(78))
            .unwrap_err(),
        refused(AuthRefusal::Ambiguous)
    );
    let mut routed = channel.clone();
    routed.interface = None;
    routed.paths = vec![Interface::Address(LOOPBACK), Interface::Address(LOOPBACK)];
    assert!(
        subscriber
            .add_network_subscription_as(STREAM, &routed, identity(RECEIVER))
            .is_err()
    );
    // A second handle of the key under no keys at all.
    let bind = SocketAddr::new(LOOPBACK, crate::test_ports::test_port());
    let first = udp(Destination::Unicast(bind), security);
    subscriber
        .add_network_subscription_as(STREAM, &first, identity(RECEIVER))
        .unwrap();
    assert_eq!(
        subscriber
            .add_network_subscription_as(
                STREAM,
                &udp(Destination::Unicast(bind), Security::Trusted),
                identity(RECEIVER),
            )
            .unwrap_err(),
        refused(AuthRefusal::Ambiguous)
    );
}

/// Item 1: the signed control budget is reserved at admission; once the
/// receiver's peer table is full, an authority at a new control endpoint
/// is refused, typed, and a removal frees its peer.
#[test]
fn a_full_control_budget_refuses_admission() {
    let peers = crate::signed_control::PEER_SLOTS;
    let channels: Vec<(String, String)> = (0..=peers)
        .map(|at| {
            let key_id = 100 + u32::try_from(at).unwrap();
            let stream = 100 + i32::try_from(at).unwrap();
            (format!("{key_id}-1.key"), channel_key(key_id, stream))
        })
        .collect();
    let mut files: Vec<(&str, &str)> = channels
        .iter()
        .map(|(name, text)| (name.as_str(), text.as_str()))
        .collect();
    files.push(("9-1.key", PAIRWISE));
    files.push(("10-1.key", PUBLIC));
    let mut driver = driver_with(128);
    let (keys, state) = dirs(&files);
    driver
        .start_wire_keys_at(Box::new(keys) as Dir, Box::new(state) as Dir, wall)
        .unwrap();
    let subscribe = |driver: &mut EmbeddedDriver, at: usize| {
        let key_id = 100 + u32::try_from(at).unwrap();
        let stream = 100 + i32::try_from(at).unwrap();
        let control = SocketAddr::new(LOOPBACK, 20_000 + u16::try_from(at).unwrap());
        let security = Security::Authenticated(AuthenticatedChannel {
            channel_key_id: key_id,
            ..auth(Some(authority(control)))
        });
        driver.add_network_subscription_as(
            stream,
            &udp(Destination::Unicast(ANY_PORT), security),
            identity(RECEIVER),
        )
    };
    let mut held = Vec::new();
    for at in 0..peers {
        held.push(subscribe(&mut driver, at).unwrap());
        // The receiver drains its ring as it would between admissions.
        let _ = driver.do_work().unwrap();
    }
    assert_eq!(
        subscribe(&mut driver, peers).unwrap_err(),
        refused(AuthRefusal::ControlBudget)
    );
    driver
        .remove_network_subscription(held.pop().unwrap())
        .unwrap();
    subscribe(&mut driver, peers).unwrap();
    let _ = driver.do_work().unwrap();
    // The receiver bound every admitted subscription.
    assert_eq!(roles(&driver).1.0, peers);
}

/// Two drivers on loopback whose authenticated publication and
/// subscription of [`STREAM`] are admitted through the real paths, and
/// pumped until established: both roles hold their bindings and the
/// session sealer is installed.
fn established() -> (EmbeddedDriver, Mem, EmbeddedDriver, Mem) {
    let (publisher, pub_keys, subscriber, sub_keys, _) = established_publication();
    (publisher, pub_keys, subscriber, sub_keys)
}

/// [`established`], with the publication's handle.
fn established_publication() -> (
    EmbeddedDriver,
    Mem,
    EmbeddedDriver,
    Mem,
    crate::embedded::AggregateHandle,
) {
    let (mut subscriber, sub_keys) = keyed(&borrowed(&subscriber_files()));
    let security = Security::Authenticated(auth(Some(authority(control()))));
    subscriber
        .add_network_subscription_as(
            STREAM,
            &udp(Destination::Unicast(ANY_PORT), security),
            identity(RECEIVER),
        )
        .unwrap();
    let to = subscriber.network_subscription_address(STREAM).unwrap();
    let (mut publisher, pub_keys) = keyed(&borrowed(&publisher_files()));
    let handle = publisher
        .add_network_publication(aggregate(STREAM), &udp(Destination::Unicast(to), security))
        .unwrap();
    let registration = handle.registration();
    let up = pump(&mut [&mut publisher, &mut subscriber], |drivers| {
        let net = drivers[0].net.as_ref().unwrap();
        net.publication_established(registration)
            && roles(drivers[0]).0 == (1, 1, 0)
            && roles(drivers[1]).1.1 == 1
            && !drivers[1].network_images(STREAM).is_empty()
    });
    assert!(
        up,
        "never established: {:?} {:?}",
        roles(&publisher),
        roles(&subscriber)
    );
    (publisher, pub_keys, subscriber, sub_keys, handle)
}

/// An authenticated publisher on port 0 whose port another socket takes
/// while a reset has it closed does not move, unlike a trusted one: a
/// receiver's challenge from a new source would rebind its boot id under a
/// new nonce, which the publisher rule refuses (ADR-0086 section 7). The
/// endpoint fails closed, as a fixed port publisher's does, and what the
/// socket now holding the old port sends to the receiver is not accepted:
/// it is not sealed with the session's keys.
#[test]
fn an_authenticated_publisher_whose_port_is_taken_across_a_reset_fails_closed() {
    use karyos_client::OfferOutcome;
    use karyos_protocol::lanes::drr::Budget;
    use karyos_sys::log_buffer::Role;

    const BUDGET: Budget = Budget {
        work: 256,
        bytes: 1 << 22,
    };
    let (mut publisher, _pub_keys, mut subscriber, _sub_keys, handle) = established_publication();
    let (image, _) = subscriber.network_images(STREAM)[0];
    let mut reader = subscriber
        .subscribe_aggregate(&image, Role::Required)
        .unwrap();
    let mut lane = publisher
        .publication(handle.lane(Lane::ZERO).unwrap())
        .unwrap();
    let (mut sent, mut seen) = (0u32, 0u32);
    let delivered = pump(&mut [&mut publisher, &mut subscriber], |_| {
        while sent < 8 {
            match lane.offer(&sent.to_le_bytes()).unwrap() {
                OfferOutcome::Accepted { .. } => sent += 1,
                _ => break,
            }
        }
        let _ = reader.poll(
            |bytes, _, _| {
                assert_eq!(u32::from_le_bytes(bytes[..4].try_into().unwrap()), seen);
                seen += 1;
            },
            BUDGET,
        );
        seen >= 8
    });
    assert!(delivered, "seen {seen} of 8 before the reset");
    let (endpoint, alias) = publisher
        .net
        .as_ref()
        .unwrap()
        .publication_route(handle.registration())
        .unwrap();
    let before = publisher
        .net
        .as_ref()
        .unwrap()
        .endpoint_address(endpoint)
        .unwrap();
    publisher.net.as_mut().unwrap().occupy_ports_on_reset();
    publisher
        .net
        .as_ref()
        .unwrap()
        .links()
        .sender
        .post(|_reply| crate::agents::AgentCommand::ForceReset { endpoint, alias })
        .unwrap();
    let failed = pump(&mut [&mut publisher, &mut subscriber], |drivers| {
        drivers[0].net.as_ref().unwrap().endpoints_failed() >= 1
    });
    assert!(failed, "the endpoint failed closed");
    let net = publisher.net.as_mut().unwrap();
    assert_eq!(
        net.ports_moved(),
        0,
        "an authenticated publisher never moves"
    );
    assert_eq!(net.endpoint_address(endpoint), None);
    // What the old port's holder sends from there is not accepted.
    let occupied = net.take_occupied();
    let old = occupied.first().unwrap();
    assert_eq!(old.local_addr().unwrap(), before);
    let to = subscriber.network_subscription_address(STREAM).unwrap();
    let counters =
        |driver: &EmbeddedDriver| driver.net.as_ref().unwrap().receiver_counters().unwrap();
    let (received, committed) = {
        let now = counters(&subscriber);
        (now.datagrams, now.data_committed)
    };
    for bytes in [&[0u8; 64][..], &[0xffu8; 128][..], &[1u8; 32][..]] {
        old.send_to(bytes, to).unwrap();
    }
    let arrived = pump(&mut [&mut subscriber], |drivers| {
        counters(drivers[0]).datagrams >= received + 3
    });
    assert!(arrived, "the old port's datagrams reached the receiver");
    let _ = reader.poll(|_, _, _| seen += 1, BUDGET);
    assert_eq!(seen, 8, "nothing more delivered");
    assert_eq!(counters(&subscriber).data_committed, committed);
}

/// Item 1, end to end: the admitted keys establish the session through
/// the real admission and agent paths (the publication's sealer is
/// installed, the image is authenticated); a trusted publisher of the
/// stream never gets an image at that subscription.
#[test]
fn an_admitted_authenticated_channel_establishes_and_a_trusted_one_does_not() {
    let (publisher, _, subscriber, _) = established();
    assert_eq!(roles(&publisher).0, (1, 1, 0));
    assert_eq!(roles(&subscriber).1, (1, 1, 0));

    let (mut subscriber, _) = keyed(&borrowed(&subscriber_files()));
    let security = Security::Authenticated(auth(None));
    subscriber
        .add_network_subscription_as(
            STREAM,
            &udp(Destination::Unicast(ANY_PORT), security),
            identity(RECEIVER),
        )
        .unwrap();
    let to = subscriber.network_subscription_address(STREAM).unwrap();
    let mut trusted = driver_with(64);
    let handle = trusted
        .add_network_publication(
            aggregate(STREAM),
            &udp(Destination::Unicast(to), Security::Trusted),
        )
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        let _ = trusted.do_work().unwrap();
        let _ = subscriber.do_work().unwrap();
        std::thread::sleep(Duration::from_micros(200));
    }
    assert!(subscriber.network_images(STREAM).is_empty());
    assert!(
        !trusted
            .net
            .as_ref()
            .unwrap()
            .publication_established(handle.registration())
    );
}

/// Item 2: a revocation reaches both roles of both drivers within one
/// reload interval: the publication's session sealer is withdrawn and the
/// image's sealer too, through the coordinated key view.
#[test]
fn a_revocation_reaches_both_roles_within_one_reload_interval() {
    let (mut publisher, pub_keys, mut subscriber, sub_keys) = established();
    let applied = |driver: &EmbeddedDriver| driver.wire_key_counters().unwrap().applied;
    let before = (applied(&publisher), applied(&subscriber));
    for keys in [&pub_keys, &sub_keys] {
        keys.put("revoked", "3-1\n9-1\n");
    }
    advance(RELOAD_INTERVAL_S);
    let reached = pump(&mut [&mut publisher, &mut subscriber], |drivers| {
        roles(drivers[0]).0.1 == 0 && {
            let (_, images, withdrawn) = roles(drivers[1]).1;
            images == withdrawn
        }
    });
    assert!(
        reached,
        "not withdrawn: {:?} {:?}",
        roles(&publisher),
        roles(&subscriber)
    );
    assert!(applied(&publisher) > before.0 && applied(&subscriber) > before.1);
    // No new authenticated admission under the revoked keys.
    let security = Security::Authenticated(auth(None));
    assert_eq!(
        publisher
            .add_network_publication(
                aggregate(STREAM + 1),
                &udp(Destination::Unicast(SocketAddr::new(LOOPBACK, 9)), security),
            )
            .unwrap_err(),
        refused(AuthRefusal::ChannelKey)
    );
}

/// Item 2: a store that fails (its key directory cannot be listed)
/// disables every authenticated path on both roles at the next reload,
/// raises the alarm and refuses every new authenticated admission.
#[test]
fn a_store_failure_disables_every_authenticated_path() {
    let (mut publisher, pub_keys, mut subscriber, sub_keys) = established();
    for keys in [&pub_keys, &sub_keys] {
        *keys.fail_list.lock().unwrap() = true;
    }
    advance(RELOAD_INTERVAL_S);
    let reached = pump(&mut [&mut publisher, &mut subscriber], |drivers| {
        roles(drivers[0]).0.1 == 0 && {
            let (_, images, withdrawn) = roles(drivers[1]).1;
            images == withdrawn
        }
    });
    assert!(
        reached,
        "not disabled: {:?} {:?}",
        roles(&publisher),
        roles(&subscriber)
    );
    for driver in [&publisher, &subscriber] {
        assert!(driver.wire_key_counters().unwrap().failures >= 1);
        assert!(!driver.wire_key_events().is_empty());
    }
    let security = Security::Authenticated(auth(None));
    assert_eq!(
        publisher
            .add_network_publication(
                aggregate(STREAM + 1),
                &udp(Destination::Unicast(SocketAddr::new(LOOPBACK, 9)), security),
            )
            .unwrap_err(),
        refused(AuthRefusal::KeyStoreDisabled)
    );
}

/// Item 2: the store starts once per driver.
#[test]
fn the_key_store_starts_once() {
    let (mut driver, _) = keyed(&borrowed(&publisher_files()));
    let (keys, state) = dirs(&[]);
    assert_eq!(
        driver
            .start_wire_keys(Box::new(keys) as Dir, Box::new(state) as Dir)
            .unwrap_err(),
        DriverError::InvalidConfig
    );
}

/// The authority driver's files: its signing key.
fn authority_files() -> Vec<(&'static str, String)> {
    vec![("10-1.key", SIGNING.to_owned())]
}

/// A publisher's files for a remotely guarded publication: the
/// authority's public key, not its signing key.
fn guarded_files() -> Vec<(&'static str, String)> {
    vec![
        ("3-1.key", channel_key(3, STREAM)),
        ("9-1.key", PAIRWISE.to_owned()),
        ("10-1.key", PUBLIC.to_owned()),
    ]
}

fn open_word(epoch: u64) -> Arc<karyos_client::HeapWords> {
    let word = Arc::new(karyos_client::HeapWords::zeroed(1));
    word.words()[0].store(
        karyos_sys::guard::encode(karyos_sys::guard::GuardState { epoch, open: true }).unwrap(),
        karyos_sys::sync::Ordering::Release,
    );
    word
}

/// Item 3: a remotely guarded publication needs the durable guard state;
/// without it admission is refused, typed.
#[test]
fn a_remotely_guarded_publication_needs_durable_guard_state() {
    let (mut publisher, _) = keyed(&borrowed(&guarded_files()));
    let security = Security::Authenticated(auth(Some(ChannelAuthority {
        follower_id: 66,
        ..authority(control())
    })));
    assert_eq!(
        publisher
            .add_network_publication(
                aggregate(STREAM),
                &udp(Destination::Unicast(SocketAddr::new(LOOPBACK, 9)), security),
            )
            .unwrap_err(),
        refused(AuthRefusal::GuardState)
    );
    // And an authority with none refuses too.
    let (mut authority_driver, _) = keyed(&borrowed(&authority_files()));
    assert_eq!(
        authority_driver
            .start_guard_authority(10, Vec::new(), &[SocketAddr::new(LOOPBACK, 0)])
            .unwrap_err(),
        refused(AuthRefusal::GuardState)
    );
}

/// A remotely guarded authenticated publication on loopback: its
/// publisher (durable marks in `marks`), its subscriber, and the guard
/// authority (committed epochs in `commits`) of guard 11, open at epoch 2,
/// answering only on its configured control endpoint. Returns the
/// drivers, publisher first, and the publication's registration.
fn remotely_guarded(
    marks: &Mem,
    commits: &Mem,
) -> ([EmbeddedDriver; 3], crate::embedded::AggregateHandle) {
    let control = SocketAddr::new(LOOPBACK, crate::test_ports::test_port());
    let guard = ChannelAuthority {
        follower_id: 66,
        ..authority(control)
    };
    let (mut authority_driver, _) = keyed(&borrowed(&authority_files()));
    authority_driver
        .start_guard_state(
            Box::new(Mem::default()) as Dir,
            Box::new(commits.clone()) as Dir,
        )
        .unwrap();
    let (mut subscriber, _) = keyed(&borrowed(&subscriber_files()));
    let security = Security::Authenticated(auth(Some(guard)));
    subscriber
        .add_network_subscription_as(
            STREAM,
            &udp(Destination::Unicast(ANY_PORT), security),
            identity(RECEIVER),
        )
        .unwrap();
    let to = subscriber.network_subscription_address(STREAM).unwrap();
    let (mut publisher, _) = keyed(&borrowed(&guarded_files()));
    publisher
        .start_guard_state(
            Box::new(marks.clone()) as Dir,
            Box::new(Mem::default()) as Dir,
        )
        .unwrap();
    let handle = publisher
        .add_network_publication(aggregate(STREAM), &udp(Destination::Unicast(to), security))
        .unwrap();
    let registration = handle.registration();
    let net = publisher.net.as_ref().unwrap();
    let path = net.publication_paths(registration)[0];
    let from = net.endpoint_address(path).unwrap();
    authority_driver
        .start_guard_authority(
            10,
            vec![crate::guard_authority::AuthorityGuard {
                guard_id: 11,
                word: open_word(2) as Arc<dyn karyos_client::SharedWords>,
                lifetime_ms: 5_000,
                receivers: vec![(66, from)],
            }],
            &[control],
        )
        .unwrap();
    ([publisher, subscriber, authority_driver], handle)
}

/// Item 3, end to end: the publisher follows the authority's guard from
/// its configured state, is admission-pending until the authority's
/// signed STATUS opens it, persists the guard's mark durably before
/// acting on it, and only then establishes and delivers; the authority
/// commits the epoch it signs.
#[test]
fn a_remote_guard_opens_the_publication_through_its_authority() {
    let (marks, commits) = (Mem::default(), Mem::default());
    let ([mut publisher, mut subscriber, mut authority_driver], handle) =
        remotely_guarded(&marks, &commits);
    let registration = handle.registration();
    let opened = pump(
        &mut [&mut publisher, &mut subscriber, &mut authority_driver],
        |drivers| {
            let net = drivers[0].net.as_ref().unwrap();
            net.publication_established(registration)
                && roles(drivers[0]).0 == (1, 1, 0)
                && !drivers[1].network_images(STREAM).is_empty()
        },
    );
    assert!(
        opened,
        "never opened: {:?} {:?} {:?}",
        roles(&publisher),
        publisher.net.as_ref().unwrap().receiver_counters(),
        authority_driver.net.as_ref().unwrap().receiver_counters()
    );
    let mark = marks
        .files
        .lock()
        .unwrap()
        .get("guard-11")
        .cloned()
        .unwrap();
    assert!(String::from_utf8(mark).unwrap().contains("epoch=2"));
    assert!(
        commits
            .files
            .lock()
            .unwrap()
            .contains_key("authority-guard-11")
    );
}

/// Item 3: a mark the follower cannot persist opens nothing: the
/// publication stays admission-pending and the failure is counted as an
/// alarm.
#[test]
fn an_unpersisted_guard_mark_keeps_the_publication_pending_and_alarms() {
    let (marks, commits) = (Mem::default(), Mem::default());
    *marks.fail_writes.lock().unwrap() = true;
    let ([mut publisher, mut subscriber, mut authority_driver], _) =
        remotely_guarded(&marks, &commits);
    let alarmed = pump(
        &mut [&mut publisher, &mut subscriber, &mut authority_driver],
        |drivers| {
            let counters = drivers[0]
                .net
                .as_ref()
                .unwrap()
                .receiver_counters()
                .unwrap();
            counters.guard_persist_failures > 0
        },
    );
    assert!(
        alarmed,
        "{:?}",
        publisher.net.as_ref().unwrap().receiver_counters()
    );
    assert_eq!(roles(&publisher).0.2, 1, "still admission-pending");
    assert!(!marks.files.lock().unwrap().contains_key("guard-11"));
}

/// Item 3: an authority whose committed state cannot be written signs
/// nothing: the failure is counted as an alarm and the publication stays
/// admission-pending.
#[test]
fn an_uncommitted_authority_answers_nothing_and_alarms() {
    let (marks, commits) = (Mem::default(), Mem::default());
    *commits.fail_writes.lock().unwrap() = true;
    let ([mut publisher, mut subscriber, mut authority_driver], _) =
        remotely_guarded(&marks, &commits);
    let alarmed = pump(
        &mut [&mut publisher, &mut subscriber, &mut authority_driver],
        |drivers| {
            let counters = drivers[2]
                .net
                .as_ref()
                .unwrap()
                .receiver_counters()
                .unwrap();
            counters.authority_commit_failures > 0
        },
    );
    assert!(
        alarmed,
        "{:?}",
        authority_driver.net.as_ref().unwrap().receiver_counters()
    );
    assert_eq!(roles(&publisher).0.2, 1, "still admission-pending");
}

/// Follow-up (a) and (c): removing the last publication a remote guard
/// guards unfollows it, and an unfollow a full receiver ring refuses is
/// deferred, counted, and posted at a later duty, never lost.
#[test]
fn removing_a_remotely_guarded_publication_unfollows_its_guard_even_past_a_full_ring() {
    let (marks, commits) = (Mem::default(), Mem::default());
    let ([mut publisher, mut subscriber, mut authority_driver], handle) =
        remotely_guarded(&marks, &commits);
    let registration = handle.registration();
    let opened = pump(
        &mut [&mut publisher, &mut subscriber, &mut authority_driver],
        |drivers| {
            drivers[0]
                .net
                .as_ref()
                .unwrap()
                .publication_established(registration)
        },
    );
    assert!(opened);
    assert_eq!(publisher.net.as_ref().unwrap().followed_guards(), Some(1));
    assert!(publisher.net.as_ref().unwrap().fill_receiver_ring() > 0);
    publisher.remove_aggregate(&handle).unwrap();
    assert_eq!(publisher.wire_key_counters().unwrap().bindings_deferred, 1);
    let unfollowed = pump(&mut [&mut publisher], |drivers| {
        drivers[0].net.as_ref().unwrap().followed_guards() == Some(0)
    });
    assert!(
        unfollowed,
        "the deferred unfollow never reached the receiver"
    );
}

/// Follow-up (c): an authenticated admission whose binding finds the
/// receiver's ring full is refused, typed (`NetworkBusy`), and counted;
/// nothing of it is kept.
#[test]
fn a_full_ring_at_admission_refuses_and_counts() {
    let (mut subscriber, _) = keyed(&borrowed(&subscriber_files()));
    // The endpoint is open first, through a trusted subscription of
    // another stream on the same address: only the binding meets the
    // full ring.
    let bind = SocketAddr::new(LOOPBACK, crate::test_ports::test_port());
    subscriber
        .add_network_subscription_as(
            STREAM + 1,
            &udp(Destination::Unicast(bind), Security::Trusted),
            identity(RECEIVER),
        )
        .unwrap();
    assert!(pump(&mut [&mut subscriber], |_| true));
    assert!(subscriber.net.as_ref().unwrap().fill_receiver_ring() > 0);
    let security = Security::Authenticated(auth(Some(authority(control()))));
    let channel = udp(Destination::Unicast(bind), security);
    assert_eq!(
        subscriber
            .add_network_subscription_as(STREAM, &channel, identity(RECEIVER))
            .unwrap_err(),
        DriverError::NetworkBusy
    );
    assert_eq!(subscriber.wire_key_counters().unwrap().admissions_busy, 1);
    assert_eq!(subscriber.net.as_ref().unwrap().subscription_count(), 1);
    // Its control peer was released: once the ring drains, the admission
    // reserves it again and succeeds.
    let _ = subscriber.do_work().unwrap();
    subscriber
        .add_network_subscription_as(STREAM, &channel, identity(RECEIVER))
        .unwrap();
}

/// An etf declaration (ADR-0109) on an authenticated channel is refused,
/// typed and counted, on both roles, until that combination is designed;
/// nothing is created.
#[test]
fn an_etf_declaration_is_refused_on_an_authenticated_channel() {
    use karyos_protocol::channel::EtfDeclaration;

    let declared = |destination, security| UdpConfig {
        etf: Some(EtfDeclaration {
            priority: 3,
            delta: Duration::from_nanos(100_000),
        }),
        ..udp(destination, security)
    };
    let security = Security::Authenticated(auth(None));
    let (mut publisher, _) = keyed(&borrowed(&publisher_files()));
    let to = Destination::Unicast(SocketAddr::new(LOOPBACK, 9));
    assert_eq!(
        publisher
            .add_network_publication(aggregate(STREAM), &declared(to, security))
            .unwrap_err(),
        refused(AuthRefusal::Etf)
    );
    let (mut subscriber, _) = keyed(&borrowed(&subscriber_files()));
    assert_eq!(
        subscriber
            .add_network_subscription_as(
                STREAM,
                &declared(Destination::Unicast(ANY_PORT), security),
                identity(RECEIVER),
            )
            .unwrap_err(),
        refused(AuthRefusal::Etf)
    );
    for driver in [&publisher, &subscriber] {
        assert_eq!(driver.wire_key_counters().unwrap().etf_refused, 1);
        let net = driver.net.as_ref().unwrap();
        assert_eq!((net.publication_count(), net.subscription_count()), (0, 0));
    }
}

/// karyos#648, a refused successor: while a VM generation change is not
/// released (a role of the process never redraws), every authenticated
/// path stops and stays stopped, a new authenticated admission is
/// refused, typed and counted, and a trusted channel keeps running.
#[test]
fn a_held_generation_fence_stops_the_authenticated_class_and_trusted_keeps_running() {
    use crate::wire_enc::VmGenerationWatch;
    use crate::wire_enc::vm_generation::{self, InjectedSignal};

    let (mut publisher, _, mut subscriber, _) = established();
    // A role of the process that never redraws holds the fence.
    vm_generation::register();
    let (signal, injector) = InjectedSignal::new();
    let mut watch = VmGenerationWatch::new(Box::new(signal));
    injector.change();
    assert_eq!(watch.poll(0), 1);
    assert!(vm_generation::quiesced());
    let stopped = pump(&mut [&mut publisher, &mut subscriber], |drivers| {
        roles(drivers[0]).0.1 == 0 && roles(drivers[1]).1.1 == 0
    });
    assert!(
        stopped,
        "not stopped: {:?} {:?}",
        roles(&publisher),
        roles(&subscriber)
    );
    // A trusted channel is established and delivers meanwhile.
    let mut trusted = driver_with(64);
    trusted
        .add_network_subscription_as(
            STREAM + 2,
            &udp(Destination::Unicast(ANY_PORT), Security::Trusted),
            identity(RECEIVER),
        )
        .unwrap();
    let to = trusted.network_subscription_address(STREAM + 2).unwrap();
    let mut sender = driver_with(64);
    let handle = sender
        .add_network_publication(
            aggregate(STREAM + 2),
            &udp(Destination::Unicast(to), Security::Trusted),
        )
        .unwrap();
    let running = pump(
        &mut [&mut sender, &mut trusted, &mut publisher, &mut subscriber],
        |drivers| {
            drivers[0]
                .net
                .as_ref()
                .unwrap()
                .publication_established(handle.registration())
                && !drivers[1].network_images(STREAM + 2).is_empty()
        },
    );
    assert!(running, "the trusted channel runs");
    assert!(vm_generation::quiesced(), "still held");
    // The authenticated class stays stopped.
    assert_eq!(roles(&publisher).0.1, 0);
    assert_eq!(roles(&subscriber).1.1, 0);
    // And no authenticated admission is taken.
    let security = Security::Authenticated(auth(None));
    assert_eq!(
        publisher
            .add_network_publication(
                aggregate(STREAM + 1),
                &udp(Destination::Unicast(SocketAddr::new(LOOPBACK, 9)), security),
            )
            .unwrap_err(),
        refused(AuthRefusal::GenerationChange)
    );
    assert_eq!(
        subscriber
            .add_network_subscription_as(
                STREAM + 1,
                &udp(Destination::Unicast(ANY_PORT), security),
                identity(RECEIVER),
            )
            .unwrap_err(),
        refused(AuthRefusal::GenerationChange)
    );
    for driver in [&publisher, &subscriber] {
        assert_eq!(driver.wire_key_counters().unwrap().generation_refused, 1);
    }
}

/// H8 R3-1: the reload cadence runs on the monotonic clock. A wall clock
/// stepped back an hour does not delay a revocation: the next reload
/// comes one interval of monotonic time later and reaches both roles.
#[test]
fn a_backward_wall_step_does_not_delay_a_revocation() {
    let (mut publisher, pub_keys, mut subscriber, sub_keys) = established();
    for keys in [&pub_keys, &sub_keys] {
        keys.put("revoked", "3-1\n9-1\n");
    }
    WALL.with(|wall| wall.set(wall.get() - 3600));
    super::MONO_SKEW.with(|skew| {
        skew.set(skew.get() + RELOAD_INTERVAL_S.unsigned_abs() * 1_000_000_000);
    });
    let reached = pump(&mut [&mut publisher, &mut subscriber], |drivers| {
        roles(drivers[0]).0.1 == 0 && {
            let (_, images, withdrawn) = roles(drivers[1]).1;
            images == withdrawn
        }
    });
    assert!(
        reached,
        "not withdrawn: {:?} {:?}",
        roles(&publisher),
        roles(&subscriber)
    );
}

/// Leaves exactly one free slot in `driver`'s receiver command ring
/// (tests): fills it, lets the receiver drain it, and fills it again
/// but for one.
fn one_receiver_slot(driver: &mut EmbeddedDriver) {
    for _ in 0..10 {
        let _ = driver.do_work().unwrap();
    }
    let capacity = driver.net.as_ref().unwrap().fill_receiver_ring();
    assert!(capacity > 1);
    for _ in 0..10 {
        let _ = driver.do_work().unwrap();
    }
    // The ring and its reply slots are free again: as many as before
    // fit, so all but one are taken now.
    driver.net.as_ref().unwrap().ping_receiver(capacity - 1);
}

/// H8 R3-5: an authenticated subscription is one receiver command, so it
/// is admitted with exactly one ring slot and bound once; with none it is
/// refused, typed, and nothing of it is bound.
#[test]
fn an_authenticated_admission_needs_one_ring_slot_and_leaves_nothing_when_refused() {
    let (mut subscriber, _) = keyed(&borrowed(&subscriber_files()));
    let bind = SocketAddr::new(LOOPBACK, crate::test_ports::test_port());
    subscriber
        .add_network_subscription_as(
            STREAM + 1,
            &udp(Destination::Unicast(bind), Security::Trusted),
            identity(RECEIVER),
        )
        .unwrap();
    assert!(pump(&mut [&mut subscriber], |_| true));
    let security = Security::Authenticated(auth(Some(authority(control()))));
    let channel = udp(Destination::Unicast(bind), security);
    // No slot: refused, and nothing reaches the receiver.
    assert!(subscriber.net.as_ref().unwrap().fill_receiver_ring() > 0);
    assert_eq!(
        subscriber
            .add_network_subscription_as(STREAM, &channel, identity(RECEIVER))
            .unwrap_err(),
        DriverError::NetworkBusy
    );
    let _ = subscriber.do_work().unwrap();
    let _ = subscriber.do_work().unwrap();
    assert_eq!(roles(&subscriber).1.0, 0, "nothing bound");
    // Exactly one slot: the binding and the subscription go together.
    one_receiver_slot(&mut subscriber);
    subscriber
        .add_network_subscription_as(STREAM, &channel, identity(RECEIVER))
        .unwrap();
    assert_eq!(
        subscriber.net.as_ref().unwrap().fill_receiver_ring(),
        0,
        "it took the one slot there was"
    );
    let bound = pump(&mut [&mut subscriber], |drivers| roles(drivers[0]).1.0 == 1);
    assert!(bound, "{:?}", roles(&subscriber));
    assert_eq!(subscriber.net.as_ref().unwrap().subscription_count(), 2);
}

/// H8 R3-5: a cleanup names the installation it removes: once a
/// subscription is removed and admitted again, its old Unbind, arriving
/// late, leaves the replacement bound.
#[test]
fn a_late_unbind_never_removes_a_replacement_binding() {
    let (mut subscriber, _) = keyed(&borrowed(&subscriber_files()));
    let security = Security::Authenticated(auth(Some(authority(control()))));
    let channel = udp(Destination::Unicast(ANY_PORT), security);
    let first = subscriber
        .add_network_subscription_as(STREAM, &channel, identity(RECEIVER))
        .unwrap();
    let (endpoint, old) = subscriber
        .net
        .as_ref()
        .unwrap()
        .auth_installation(STREAM)
        .unwrap();
    assert!(pump(&mut [&mut subscriber], |drivers| roles(drivers[0])
        .1
        .0
        == 1));
    subscriber.remove_network_subscription(first).unwrap();
    let _ = subscriber.do_work().unwrap();
    subscriber
        .add_network_subscription_as(STREAM, &channel, identity(RECEIVER))
        .unwrap();
    let (_, new) = subscriber
        .net
        .as_ref()
        .unwrap()
        .auth_installation(STREAM)
        .unwrap();
    assert_ne!(old, new);
    assert!(pump(&mut [&mut subscriber], |drivers| roles(drivers[0])
        .1
        .0
        == 1));
    // The old installation's cleanup, late.
    assert!(
        subscriber
            .net
            .as_ref()
            .unwrap()
            .post_binding(crate::agents::roles::Binding::Unbind {
                endpoint,
                stream_id: STREAM,
                installation: old,
            })
    );
    for _ in 0..10 {
        let _ = subscriber.do_work().unwrap();
    }
    assert_eq!(roles(&subscriber).1.0, 1, "the replacement stays bound");
}

/// H8 R3-5: an Unfollow a full ring deferred names the follow it
/// undoes: a publication of the same guard admitted before it is posted
/// keeps the guard followed.
#[test]
fn a_deferred_unfollow_never_undoes_a_later_follow() {
    let (marks, commits) = (Mem::default(), Mem::default());
    let ([mut publisher, mut subscriber, mut authority_driver], handle) =
        remotely_guarded(&marks, &commits);
    let registration = handle.registration();
    assert!(pump(
        &mut [&mut publisher, &mut subscriber, &mut authority_driver],
        |drivers| drivers[0]
            .net
            .as_ref()
            .unwrap()
            .publication_established(registration),
    ));
    assert_eq!(publisher.net.as_ref().unwrap().followed_guards(), Some(1));
    // The removal's unfollow meets a full ring and is deferred.
    assert!(publisher.net.as_ref().unwrap().fill_receiver_ring() > 0);
    publisher.remove_aggregate(&handle).unwrap();
    assert_eq!(publisher.wire_key_counters().unwrap().bindings_deferred, 1);
    // One duty: the ring drains, the deferred unfollow is still held.
    let _ = publisher.do_work().unwrap();
    // A replacement guarded by the same guard, admitted now, posts its
    // follow ahead of the deferred unfollow.
    let security = Security::Authenticated(auth(Some(ChannelAuthority {
        follower_id: 66,
        ..authority(control())
    })));
    let to = subscriber.network_subscription_address(STREAM).unwrap();
    publisher
        .add_network_publication(
            aggregate(STREAM + 1),
            &udp(Destination::Unicast(to), security),
        )
        .unwrap();
    for _ in 0..50 {
        let _ = publisher.do_work().unwrap();
    }
    assert!(publisher.wire_key_counters().unwrap().bindings_deferred >= 1);
    assert_eq!(
        publisher.net.as_ref().unwrap().followed_guards(),
        Some(1),
        "the replacement's follow stays"
    );
}

/// The H8 invariants of the authenticated class (karyos#648).
mod invariants;

/// H8 unit-level invariants raised to end-to-end proofs (karyos#648).
mod invariants_e2e;
