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
use crate::error::{AuthRefusal, AuthUnsupported, DriverError};
use crate::membership::ReceiverIdentity;
use crate::net::NetworkConfig;
use crate::wire_keys::store::{FileError, Files, KeyStore, RELOAD_INTERVAL_S};

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
/// 2026-11-18, inside every test key's validity.
const START: i64 = 1_795_000_000;
const STREAM: i32 = 6;
const RECEIVER: u64 = 77;

thread_local! {
    /// Whether [`dirs`] fills the durable state to its capacity.
    static NEAR_FULL: Cell<bool> = const { Cell::new(false) };
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
    if NEAR_FULL.with(Cell::get) {
        // Admit `files` once, then fill the durable state to exactly its
        // capacity: the next admission overflows it (KSF-4).
        let (store, _) = KeyStore::start(keys.clone(), state.clone(), wall()).unwrap();
        let used = store.state().entries();
        let mut full = store.state().clone();
        drop(store);
        for epoch in 1..=u32::try_from(crate::wire_keys::state::MAX_ENTRIES - used).unwrap() {
            full.tombstones.insert((9999, epoch));
        }
        state.put(crate::wire_keys::store::STATE, &full.encode().unwrap());
    }
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
        channel_id: 7,
        publisher_id: 5,
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
        refused(AuthRefusal::PairwiseScope)
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
        refused(AuthRefusal::ChannelScope)
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
    for (destination, operation) in [
        (destinations, AuthUnsupported::MultiDestination),
        (multicast, AuthUnsupported::Multicast),
    ] {
        assert_eq!(
            driver
                .add_network_publication(aggregate(STREAM), &udp(destination, security))
                .unwrap_err(),
            refused(AuthRefusal::Unsupported { operation })
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

/// Item 1 (ADM-5): the signed control budget is reserved at admission;
/// once the receiver's peer table is full, an authority at a new control
/// endpoint is refused, typed, and a removal frees its peer for reuse.
#[test]
fn a_full_control_budget_refuses_admission_and_a_removal_frees_a_peer() {
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
        // A second channel, of another stream, for a replacement.
        ("4-1.key", channel_key(4, STREAM + 1)),
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
    let (drivers, handle, _) = remotely_guarded_keys(marks, commits);
    (drivers, handle)
}

/// [`remotely_guarded`], with the publisher's and the authority's key
/// directories.
fn remotely_guarded_keys(
    marks: &Mem,
    commits: &Mem,
) -> (
    [EmbeddedDriver; 3],
    crate::embedded::AggregateHandle,
    (Mem, Mem),
) {
    remotely_guarded_by(marks, commits, open_word(2), 5_000)
}

/// [`remotely_guarded_keys`], the authority's guard word `word` (which
/// the test may keep, to close the guard) and its `lifetime_ms`.
fn remotely_guarded_by(
    marks: &Mem,
    commits: &Mem,
    word: Arc<karyos_client::HeapWords>,
    lifetime_ms: u32,
) -> (
    [EmbeddedDriver; 3],
    crate::embedded::AggregateHandle,
    (Mem, Mem),
) {
    let control = SocketAddr::new(LOOPBACK, crate::test_ports::test_port());
    let guard = ChannelAuthority {
        follower_id: 66,
        ..authority(control)
    };
    let (mut authority_driver, authority_keys) = keyed(&borrowed(&authority_files()));
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
    let (mut publisher, publisher_keys) = keyed(&borrowed(&guarded_files()));
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
                word: word as Arc<dyn karyos_client::SharedWords>,
                lifetime_ms,
                receivers: vec![(66, from)],
            }],
            &[control],
        )
        .unwrap();
    (
        [publisher, subscriber, authority_driver],
        handle,
        (publisher_keys, authority_keys),
    )
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
    // ADM-14: admitted but pending, the sender holds no live SETUP
    // session incarnation, only a deferred one, until the first persisted
    // OPEN.
    let _ = publisher.do_work().unwrap();
    assert_eq!(roles(&publisher).0.2, 1, "admission-pending");
    assert!(!marks.files.lock().unwrap().contains_key("guard-11"));
    assert_eq!(
        publisher.net.as_ref().unwrap().registered_sessions(),
        Some((0, 1))
    );
    let opened = pump(
        &mut [&mut publisher, &mut subscriber, &mut authority_driver],
        |drivers| {
            let net = drivers[0].net.as_ref().unwrap();
            net.publication_established(registration)
                && roles(drivers[0]).0 == (1, 1, 0)
                && !drivers[1].network_images(STREAM).is_empty()
        },
    );
    assert_eq!(
        publisher.net.as_ref().unwrap().registered_sessions(),
        Some((1, 0)),
        "registered at the open"
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

/// Two remotely guarded publications of one guard (PR #1286 review): the
/// first opens and delivers, then a second of the same guard, on another
/// stream, is admitted on the guard's current open while the first runs.
/// Returns the drivers, publisher first, both handles and the authority's
/// guard word.
fn two_publications_on_one_guard(
    marks: &Mem,
    commits: &Mem,
    lifetime_ms: u32,
) -> (
    [EmbeddedDriver; 3],
    [crate::embedded::AggregateHandle; 2],
    Arc<karyos_client::HeapWords>,
) {
    let word = open_word(2);
    let ([mut publisher, mut subscriber, mut authority_driver], first, _) =
        remotely_guarded_by(marks, commits, Arc::clone(&word), lifetime_ms);
    let registration = first.registration();
    assert!(pump(
        &mut [&mut publisher, &mut subscriber, &mut authority_driver],
        |drivers| drivers[0]
            .net
            .as_ref()
            .unwrap()
            .publication_established(registration),
    ));
    let security = Security::Authenticated(AuthenticatedChannel {
        channel_key_id: 4,
        ..auth(Some(ChannelAuthority {
            follower_id: 66,
            ..authority(control())
        }))
    });
    let to = subscriber.network_subscription_address(STREAM).unwrap();
    let second = publisher
        .add_network_publication(
            aggregate(STREAM + 1),
            &udp(Destination::Unicast(to), security),
        )
        .unwrap();
    assert!(
        pump(
            &mut [&mut publisher, &mut subscriber, &mut authority_driver],
            |drivers| roles(drivers[0]).0.2 == 0,
        ),
        "the second is admitted on the open: {:?}",
        roles(&publisher)
    );
    assert_eq!(publisher.net.as_ref().unwrap().followed_guards(), Some(1));
    (
        [publisher, subscriber, authority_driver],
        [first, second],
        word,
    )
}

/// How many incarnations the guard gate of the Shared sender's
/// `index`-th publication aborted; `None` before it was admitted.
fn guard_aborts(driver: &EmbeddedDriver, index: usize) -> Option<u64> {
    match &driver.net.as_ref().unwrap().agents {
        crate::net::Agents::Shared(agents) => agents.sender.guard_aborts(index),
        _ => panic!("not shared"),
    }
}

/// Runs `drivers` until the guard gates of both publications of
/// `drivers[0]` aborted their incarnation, each offering a message
/// whenever it may; returns each gate's aborts.
fn both_abort(
    drivers: &mut [&mut EmbeddedDriver],
    handles: &[crate::embedded::AggregateHandle; 2],
) -> [Option<u64>; 2] {
    let mut lanes = handles.each_ref().map(|handle| {
        drivers[0]
            .publication(handle.lane(Lane::ZERO).unwrap())
            .unwrap()
    });
    let _ = pump(drivers, |drivers| {
        for lane in &mut lanes {
            let _ = lane.offer(&[7u8; 64]);
            let _ = lane.poll_outcomes(64, |_, _| {}).unwrap();
        }
        (0..2).all(|index| guard_aborts(drivers[0], index).is_some_and(|aborted| aborted >= 1))
    });
    [guard_aborts(drivers[0], 0), guard_aborts(drivers[0], 1)]
}

/// PR #1286 review (P1): every publication a remote guard guards stops
/// when its authority closes the guard, the one admitted first as well as
/// the one admitted while it ran: both incarnations end.
#[test]
fn a_remote_guard_close_stops_every_publication_it_guards() {
    let (marks, commits) = (Mem::default(), Mem::default());
    let ([mut publisher, mut subscriber, mut authority_driver], [first, second], word) =
        two_publications_on_one_guard(&marks, &commits, 5_000);
    // Both were admitted behind their gate, nothing aborted yet.
    assert_eq!(
        [guard_aborts(&publisher, 0), guard_aborts(&publisher, 1)],
        [Some(0); 2]
    );
    word.words()[0].store(
        karyos_sys::guard::encode(karyos_sys::guard::GuardState {
            epoch: 3,
            open: false,
        })
        .unwrap(),
        karyos_sys::sync::Ordering::Release,
    );
    assert_eq!(
        both_abort(
            &mut [&mut publisher, &mut subscriber, &mut authority_driver],
            &[first, second],
        ),
        [Some(1); 2],
        "the first publication kept its open mirror"
    );
}

/// PR #1286 review (P1): every publication a remote guard guards stops
/// when its confirmation expires (the authority silent), the one admitted
/// first as well as the one admitted while it ran.
#[test]
fn a_lapsed_remote_guard_stops_every_publication_it_guards() {
    let (marks, commits) = (Mem::default(), Mem::default());
    let ([mut publisher, mut subscriber, _authority], [first, second], _word) =
        two_publications_on_one_guard(&marks, &commits, 1_000);
    assert_eq!(
        [guard_aborts(&publisher, 0), guard_aborts(&publisher, 1)],
        [Some(0); 2]
    );
    // The authority answers no more: the open lapses.
    assert_eq!(
        both_abort(&mut [&mut publisher, &mut subscriber], &[first, second]),
        [Some(1); 2],
        "the first publication kept its open mirror"
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
    // ADM-14: no SETUP session incarnation without a persisted OPEN.
    assert_eq!(
        publisher.net.as_ref().unwrap().registered_sessions(),
        Some((0, 1))
    );
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
        refused(AuthRefusal::Unsupported {
            operation: AuthUnsupported::Etf
        })
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
        refused(AuthRefusal::Unsupported {
            operation: AuthUnsupported::Etf
        })
    );
    for driver in [&publisher, &subscriber] {
        assert_eq!(driver.wire_key_counters().unwrap().etf_refused, 1);
        let net = driver.net.as_ref().unwrap();
        assert_eq!((net.publication_count(), net.subscription_count()), (0, 0));
    }
    // ADM-4: the refusal does not depend on a key store. Without one it is
    // the same typed refusal, ahead of `NoKeyStore`; the count lives in the
    // store's counters, so it is kept only once a store is started.
    let mut unkeyed = driver_with(64);
    let to = Destination::Unicast(SocketAddr::new(LOOPBACK, 9));
    assert_eq!(
        unkeyed
            .add_network_publication(aggregate(STREAM), &declared(to, security))
            .unwrap_err(),
        refused(AuthRefusal::Unsupported {
            operation: AuthUnsupported::Etf
        })
    );
    assert_eq!(
        unkeyed
            .add_network_subscription_as(
                STREAM,
                &declared(Destination::Unicast(ANY_PORT), security),
                identity(RECEIVER),
            )
            .unwrap_err(),
        refused(AuthRefusal::Unsupported {
            operation: AuthUnsupported::Etf
        })
    );
    assert_eq!(unkeyed.wire_key_counters(), None);
    let net = unkeyed.net.as_ref().unwrap();
    assert_eq!((net.publication_count(), net.subscription_count()), (0, 0));
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
    let security = Security::Authenticated(AuthenticatedChannel {
        channel_key_id: 4,
        ..auth(Some(ChannelAuthority {
            follower_id: 66,
            ..authority(control())
        }))
    });
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

/// The admission of encrypted channels and their delivery end to end
/// (ADR-0114).
mod encrypted;

/// The inner budget of authenticated publications (ADR-0086 section 5).
mod auth_mtu;

/// The authenticated profile challenge-table ceilings at admission
/// (ADR-0086 section 6; H8 R5-04).
mod challenge_ceilings;

/// H8 RLD-4: freshness is granted only once a reload has completed and
/// both roles have applied its view, and it runs the revocation bound
/// from the start of that reload's read. A conductor that stalls, or a
/// view the roles do not apply, stops every authenticated use within the
/// bound of the file change; applying the view grants it again.
#[test]
fn a_stalled_reload_or_unapplied_view_lapses_within_the_bound() {
    use crate::wire_auth::{KeyGeneration, KeySet, Side};

    let (keys, state) = dirs(&borrowed(&publisher_files()));
    let (mut wire, _) = super::WireKeys::start(
        Box::new(keys.clone()) as Dir,
        Box::new(state) as Dir,
        Some(wall),
    )
    .unwrap();
    let fence = Arc::new(KeyGeneration::default());
    assert!(wire.duty(&fence).is_none(), "the start view, unchanged");
    let granted = super::mono_now();
    assert!(fence.admits(Side::Sender, granted));
    assert!(
        !fence.admits(Side::Sender, granted + super::FRESH_NS),
        "never past the bound from the read"
    );
    // A file revoked now, with the conductor stalled: refused within the
    // bound of the change, whatever happens next.
    keys.put("revoked", "3-1\n");
    let changed = super::mono_now();
    assert!(!fence.admits(Side::Sender, changed + super::FRESH_NS));
    assert!(!fence.admits(Side::Receiver, changed + super::FRESH_NS));
    // The next reload runs and publishes the new view, which no role has
    // applied (a full ring): both roles stop at once, and no freshness is
    // granted.
    super::MONO_SKEW.with(|skew| skew.set(skew.get() + super::REFRESH_NS));
    let view = wire.duty(&fence).expect("a new view");
    assert!(!fence.admits(Side::Sender, super::mono_now()));
    assert!(!fence.admits(Side::Receiver, super::mono_now()));
    // Both roles apply it: the next duty grants freshness from its read.
    fence.applied(Side::Sender, view.view_generation());
    fence.applied(Side::Receiver, view.view_generation());
    let _ = wire.duty(&fence);
    let now = super::mono_now();
    assert!(fence.admits(Side::Sender, now) && fence.admits(Side::Receiver, now));
    assert!(!fence.admits(Side::Sender, now + super::FRESH_NS));
}

/// H8 RLD-4: admission reads a fresh view only: past the bound with no
/// granted reload, an authenticated channel is refused.
#[test]
fn admission_refuses_a_stale_view() {
    let (mut publisher, _) = keyed(&borrowed(&publisher_files()));
    super::MONO_SKEW.with(|skew| skew.set(skew.get() + super::FRESH_NS));
    let security = Security::Authenticated(auth(None));
    assert_eq!(
        publisher
            .add_network_publication(
                aggregate(STREAM),
                &udp(Destination::Unicast(SocketAddr::new(LOOPBACK, 9)), security),
            )
            .unwrap_err(),
        refused(AuthRefusal::KeyStoreDisabled)
    );
}

/// An authority signing file of epoch 2, seed `0a..`, and its public file.
fn successor_files() -> (String, String) {
    let public: String = crate::authority::Ed25519Signer::from_seed(&[0x0a; 32])
        .verifier()
        .to_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    (
        SIGNING
            .replace("file_epoch=1", "file_epoch=2")
            .replace(&"09".repeat(32), &"0a".repeat(32)),
        PUBLIC.replace("file_epoch=1", "file_epoch=2").replace(
            "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618",
            &public,
        ),
    )
}

/// H8 REV-5, end to end on the production path: the guard authority's
/// original signing epoch is revoked while its successor is present. The
/// authority signs every later STATUS under the successor, never the
/// withdrawn seed: the follower, which now trusts only the successor,
/// keeps verifying them, and the publication stays admitted past the
/// guard's lifetime.
#[test]
fn a_revoked_authority_epoch_with_a_successor_keeps_signing_under_the_successor() {
    let (marks, commits) = (Mem::default(), Mem::default());
    let (
        [mut publisher, mut subscriber, mut authority_driver],
        handle,
        (publisher_keys, authority_keys),
    ) = remotely_guarded_keys(&marks, &commits);
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
    let (signing, public) = successor_files();
    authority_keys.put("10-2.key", &signing);
    authority_keys.put("revoked", "10-1\n");
    publisher_keys.put("10-2.key", &public);
    publisher_keys.put("revoked", "10-1\n");
    advance(RELOAD_INTERVAL_S);
    let refused = |driver: &EmbeddedDriver| {
        driver
            .net
            .as_ref()
            .unwrap()
            .receiver_counters()
            .unwrap()
            .signed_refused
    };
    let sent = |driver: &EmbeddedDriver| {
        driver
            .net
            .as_ref()
            .unwrap()
            .receiver_counters()
            .unwrap()
            .guard_statuses_sent
    };
    let (refused_before, sent_before) = (refused(&publisher), sent(&authority_driver));
    // Past the guard's 5 s lifetime: only verifying STATUS keeps it open.
    let deadline = std::time::Instant::now() + Duration::from_secs(8);
    while std::time::Instant::now() < deadline {
        for driver in [&mut publisher, &mut subscriber, &mut authority_driver] {
            let _ = driver.do_work().unwrap();
        }
        std::thread::sleep(Duration::from_micros(200));
    }
    assert!(
        sent(&authority_driver) > sent_before,
        "statuses were signed"
    );
    assert_eq!(refused(&publisher), refused_before, "and all verified");
    assert!(
        publisher
            .net
            .as_ref()
            .unwrap()
            .publication_established(registration),
        "the guard stayed open"
    );
}

/// H8 KSF-4, end to end: a durable state that would exceed its capacity
/// disables the store, and both roles of both drivers stop every
/// authenticated path at the next reload.
#[test]
fn a_full_durable_state_stops_both_roles() {
    NEAR_FULL.with(|full| full.set(true));
    let (mut publisher, pub_keys, mut subscriber, sub_keys) = established();
    // One more key to admit: its admission would exceed the capacity.
    for keys in [&pub_keys, &sub_keys] {
        keys.put("4-1.key", &channel_key(4, STREAM + 1));
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
    }
}

/// ADM-2 (wire-key-files.md section 2.2): admission checks the complete
/// scope of each key file against the channel, one field at a time: the
/// channel key's `channel_id` on both roles and its `stream_id` on both,
/// the pairwise key's `receiver_id` and `publisher_id` on both. A
/// mismatch is refused, typed, and nothing is created.
#[test]
fn admission_refuses_a_key_of_another_scope_for_each_field() {
    let to = Destination::Unicast(SocketAddr::new(LOOPBACK, 9));
    let sub = Destination::Unicast(ANY_PORT);
    let (mut publisher, _) = keyed(&borrowed(&publisher_files()));
    let (mut subscriber, _) = keyed(&borrowed(&subscriber_files()));
    let base = auth(None);
    let cases = [
        (
            "channel_id",
            AuthenticatedChannel {
                channel_id: 8,
                ..base
            },
            STREAM,
            AuthRefusal::ChannelScope,
        ),
        ("stream_id", base, STREAM + 1, AuthRefusal::ChannelScope),
        (
            "publisher_id",
            AuthenticatedChannel {
                publisher_id: 6,
                ..base
            },
            STREAM,
            AuthRefusal::PairwiseScope,
        ),
        (
            "receiver_id",
            AuthenticatedChannel {
                receiver_id: 78,
                ..base
            },
            STREAM,
            AuthRefusal::PairwiseScope,
        ),
    ];
    for (field, channel, stream, reason) in cases {
        let security = Security::Authenticated(channel);
        assert_eq!(
            publisher
                .add_network_publication(aggregate(stream), &udp(to.clone(), security))
                .unwrap_err(),
            refused(reason),
            "publisher, {field}"
        );
        assert_eq!(
            subscriber
                .add_network_subscription_as(
                    stream,
                    &udp(sub.clone(), security),
                    identity(channel.receiver_id),
                )
                .unwrap_err(),
            refused(reason),
            "subscriber, {field}"
        );
    }
    for driver in [&publisher, &subscriber] {
        let net = driver.net.as_ref().unwrap();
        assert_eq!((net.publication_count(), net.subscription_count()), (0, 0));
    }
}

/// ADM-2: a replacement epoch of an admitted key under another scope is
/// never used: once it is the key's newest, the channel's sessions stop
/// (fail closed) rather than moving to it.
#[test]
fn a_replacement_epoch_of_another_scope_is_never_used() {
    let (mut publisher, pub_keys, mut subscriber, sub_keys) = established();
    let other = channel_key(3, STREAM + 1)
        .replacen("file_epoch=1", "file_epoch=2", 1)
        .replacen("secret=03", "secret=f3", 1);
    for keys in [&pub_keys, &sub_keys] {
        keys.put("3-2.key", &other);
    }
    advance(RELOAD_INTERVAL_S);
    super::MONO_SKEW.with(|skew| {
        skew.set(skew.get() + RELOAD_INTERVAL_S.unsigned_abs() * 1_000_000_000);
    });
    let stopped = pump(&mut [&mut publisher, &mut subscriber], |drivers| {
        roles(drivers[0]).0.1 == 0
    });
    assert!(
        stopped,
        "it moved to the other scope: {:?}",
        roles(&publisher)
    );
}

/// Capability enablement fails closed (ADR-0035, ADR-0076): every
/// operation the authenticated class does not support is refused at
/// admission, typed, on each role that can ask for it, and nothing is
/// created.
#[test]
fn every_unsupported_authenticated_operation_is_refused_typed() {
    use karyos_protocol::channel::{ControlMode, EtfDeclaration};

    use crate::sessions::register::{AddressRange, RegistrationAllowlist};

    let security = Security::Authenticated(auth(None));
    let unicast = SocketAddr::new(LOOPBACK, 9);
    let group = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 1, 1, 1)), 4000);
    let control = SocketAddr::new(LOOPBACK, 4001);
    let multicast = || udp(Destination::Multicast { group, ttl: None }, security);
    let manual = || {
        udp(
            Destination::MultiDestination {
                destinations: vec![unicast, SocketAddr::new(LOOPBACK, 10)],
                control: None,
                mode: ControlMode::Manual,
            },
            security,
        )
    };
    let dynamic = || {
        udp(
            Destination::MultiDestination {
                destinations: Vec::new(),
                control: Some(control),
                mode: ControlMode::Dynamic,
            },
            security,
        )
    };
    let routed = |to| UdpConfig {
        interface: None,
        paths: vec![Interface::Address(LOOPBACK), Interface::Address(LOOPBACK)],
        ..udp(Destination::Unicast(to), security)
    };
    let paired = || UdpConfig {
        interface: None,
        paths: vec![Interface::Address(LOOPBACK), Interface::Address(LOOPBACK)],
        ..udp(
            Destination::PairedPaths {
                endpoints: vec![unicast, SocketAddr::new(LOOPBACK, 10)],
            },
            security,
        )
    };
    let etf = |to| UdpConfig {
        etf: Some(EtfDeclaration {
            priority: 3,
            delta: Duration::from_nanos(100_000),
        }),
        ..udp(Destination::Unicast(to), security)
    };
    let allowlist = RegistrationAllowlist::new(&[AddressRange::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
        8,
    )
    .unwrap()])
    .unwrap();
    let roles = crate::membership::PublicationRoles {
        strategy: karyos_protocol::roles::Strategy::Min,
        required: Vec::new(),
        tags: Vec::new(),
    };
    let (mut publisher, _) = keyed(&borrowed(&publisher_files()));
    let publications = [
        (
            "multicast",
            publisher.add_network_publication(aggregate(STREAM), &multicast()),
            AuthUnsupported::Multicast,
        ),
        (
            "multi-destination",
            publisher.add_network_publication(aggregate(STREAM), &manual()),
            AuthUnsupported::MultiDestination,
        ),
        (
            "required destinations",
            publisher.add_network_publication_with_destinations(
                aggregate(STREAM),
                &udp(Destination::Unicast(unicast), security),
                None,
                &[unicast],
            ),
            AuthUnsupported::MultiDestination,
        ),
        (
            "dynamic registration",
            publisher.add_dynamic_network_publication(
                aggregate(STREAM),
                &dynamic(),
                allowlist,
                None,
            ),
            AuthUnsupported::Dynamic,
        ),
        (
            "routed",
            publisher.add_network_publication(aggregate(STREAM), &routed(unicast)),
            AuthUnsupported::Routed,
        ),
        (
            "paired paths",
            publisher.add_network_publication(aggregate(STREAM), &paired()),
            AuthUnsupported::PairedPaths,
        ),
        (
            "etf",
            publisher.add_network_publication(aggregate(STREAM), &etf(unicast)),
            AuthUnsupported::Etf,
        ),
        (
            "receiver roles",
            publisher.add_network_publication_with_roles(
                aggregate(STREAM),
                &udp(Destination::Unicast(unicast), security),
                roles,
            ),
            AuthUnsupported::Roles,
        ),
    ];
    for (name, result, operation) in publications {
        assert_eq!(
            result.map(drop),
            Err(refused(AuthRefusal::Unsupported { operation })),
            "publication, {name}"
        );
    }
    let (mut subscriber, _) = keyed(&borrowed(&subscriber_files()));
    let subscriptions = [
        (
            "multicast",
            subscriber.add_network_subscription_as(STREAM, &multicast(), identity(RECEIVER)),
            AuthUnsupported::Multicast,
        ),
        (
            "multi-destination",
            subscriber.add_network_subscription_as(STREAM, &manual(), identity(RECEIVER)),
            AuthUnsupported::MultiDestination,
        ),
        (
            "dynamic registration",
            subscriber.add_dynamic_network_subscription(STREAM, &dynamic(), identity(RECEIVER)),
            AuthUnsupported::Dynamic,
        ),
        (
            "routed",
            subscriber.add_network_subscription_as(STREAM, &routed(ANY_PORT), identity(RECEIVER)),
            AuthUnsupported::Routed,
        ),
        (
            "paired paths",
            subscriber.add_network_subscription_as(STREAM, &paired(), identity(RECEIVER)),
            AuthUnsupported::PairedPaths,
        ),
        (
            "etf",
            subscriber.add_network_subscription_as(STREAM, &etf(ANY_PORT), identity(RECEIVER)),
            AuthUnsupported::Etf,
        ),
    ];
    for (name, result, operation) in subscriptions {
        assert_eq!(
            result.map(drop),
            Err(refused(AuthRefusal::Unsupported { operation })),
            "subscription, {name}"
        );
    }
    for driver in [&publisher, &subscriber] {
        let net = driver.net.as_ref().unwrap();
        assert_eq!((net.publication_count(), net.subscription_count()), (0, 0));
    }
}

/// Leaves exactly `free` slots in `driver`'s receiver command ring.
fn receiver_slots(driver: &mut EmbeddedDriver, free: usize) {
    for _ in 0..10 {
        let _ = driver.do_work().unwrap();
    }
    let capacity = driver.net.as_ref().unwrap().fill_receiver_ring();
    assert!(capacity > free);
    for _ in 0..10 {
        let _ = driver.do_work().unwrap();
    }
    driver.net.as_ref().unwrap().ping_receiver(capacity - free);
}

/// H8 R3-5, cross-role rollback: a remotely guarded admission whose
/// alias binding and follow reach the receiver (its last two free slots)
/// while its `AddPublication` is refused by the sender's full ring leaves
/// nothing behind on either role: the alias is unbound, the follow undone
/// by its own installation (deferred past the full receiver ring, never
/// lost), and the sender holds no binding.
#[test]
fn a_refused_remotely_guarded_admission_leaves_nothing_on_either_role() {
    let (mut publisher, _) = keyed(&borrowed(&guarded_files()));
    publisher
        .start_guard_state(
            Box::new(Mem::default()) as Dir,
            Box::new(Mem::default()) as Dir,
        )
        .unwrap();
    // The send endpoint is open first, through a trusted publication of
    // another stream on the same interface.
    let silent = std::net::UdpSocket::bind(SocketAddr::new(LOOPBACK, 0)).unwrap();
    publisher
        .add_network_publication(
            aggregate(STREAM + 2),
            &udp(
                Destination::Unicast(silent.local_addr().unwrap()),
                Security::Trusted,
            ),
        )
        .unwrap();
    assert!(pump(&mut [&mut publisher], |_| true));
    receiver_slots(&mut publisher, 2);
    assert!(publisher.net.as_ref().unwrap().fill_sender_ring() > 0);
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
            .map(drop),
        Err(DriverError::NetworkBusy)
    );
    assert_eq!(
        publisher.net.as_ref().unwrap().fill_receiver_ring(),
        0,
        "the alias and the follow took the receiver's two slots"
    );
    let counters = publisher.wire_key_counters().unwrap();
    assert_eq!(
        (counters.admissions_busy, counters.bindings_deferred),
        (1, 1)
    );
    let clean = pump(&mut [&mut publisher], |drivers| {
        let net = drivers[0].net.as_ref().unwrap();
        net.followed_guards() == Some(0) && net.published_bound() == Some(0)
    });
    assert!(
        clean,
        "left behind: {:?} {:?} {:?}",
        publisher.net.as_ref().unwrap().followed_guards(),
        publisher.net.as_ref().unwrap().published_bound(),
        roles(&publisher)
    );
    assert_eq!(roles(&publisher).0.0, 0, "the sender holds no binding");
    assert_eq!(publisher.net.as_ref().unwrap().publication_count(), 1);
}

/// ADM-8 (ADR-0118 (a)), through the production path: the subscription's
/// admitted authority and guard reach its image through the receiver's
/// own `Binding::Subscription` (no scope hook). A validly signed abort
/// from another trusted abort-capable authority (20, trusted on this
/// receiver through a second channel), or from the guarding authority
/// under another of its guards, is refused before any state changes and
/// counted; the guarding authority's abort under its guard applies.
#[test]
fn the_subscription_hands_its_abort_scope_to_the_image() {
    use crate::agents::roles::publish_auth::AbortAuthority;
    use crate::authority::Ed25519Signer;
    use karyos_protocol::network::authenticated::{GUARD_CLOSED, SessionAbort};

    let public: String = Ed25519Signer::from_seed(&[8; 32])
        .verifier()
        .to_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let other = format!(
        "format=karyos-wire-key-v1\nkey_id=20\nfile_epoch=1\npurpose=authority-public\nprofile_id=4\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-04-30T00:00:00Z\npublic={public}\nauthority_id=20\nguards=21\nabort=true\n"
    );
    let mut files = subscriber_files();
    files.push(("4-1.key", channel_key(4, STREAM + 1)));
    files.push(("20-1.key", other));
    let (mut subscriber, _) = keyed(&borrowed(&files));
    let guarded = Security::Authenticated(auth(Some(authority(control()))));
    subscriber
        .add_network_subscription_as(
            STREAM,
            &udp(Destination::Unicast(ANY_PORT), guarded),
            identity(RECEIVER),
        )
        .unwrap();
    let second = Security::Authenticated(AuthenticatedChannel {
        channel_key_id: 4,
        ..auth(Some(ChannelAuthority {
            key_id: 20,
            authority_id: 20,
            guard_id: 21,
            control: SocketAddr::new(LOOPBACK, 8),
            follower_id: 0,
        }))
    });
    subscriber
        .add_network_subscription_as(
            STREAM + 1,
            &udp(Destination::Unicast(ANY_PORT), second),
            identity(RECEIVER),
        )
        .unwrap();
    let to = subscriber.network_subscription_address(STREAM).unwrap();
    let (mut publisher, _) = keyed(&borrowed(&publisher_files()));
    publisher
        .add_network_publication(aggregate(STREAM), &udp(Destination::Unicast(to), guarded))
        .unwrap();
    let up = pump(&mut [&mut publisher, &mut subscriber], |drivers| {
        drivers[1].net.as_ref().unwrap().auth_image().is_some()
    });
    assert!(up, "never established: {:?}", roles(&subscriber));
    let (key, incarnation, _) = subscriber.net.as_ref().unwrap().auth_image().unwrap();
    let abort = |authority_id: u64, guard_id: u64, reason: u16| {
        let seed = if authority_id == 10 { 9 } else { 8 };
        let mut signer = AbortAuthority::new(
            Ed25519Signer::from_seed(&[seed; 32]),
            u32::try_from(authority_id).unwrap(),
            authority_id,
        );
        let mut bytes = vec![0u8; 256];
        let length = signer
            .sign(
                &SessionAbort {
                    alias: key.alias,
                    identity: incarnation,
                    authority_id,
                    guard_id,
                    guard_epoch: 3,
                    reason,
                },
                &mut bytes,
            )
            .unwrap();
        bytes.truncate(length);
        bytes
    };
    let counters =
        |driver: &EmbeddedDriver| driver.net.as_ref().unwrap().receiver_counters().unwrap();
    for (authority_id, guard_id, reason) in [
        (20, 21, GUARD_CLOSED),
        (20, 0, 2),
        (10, 12, GUARD_CLOSED),
        (10, 12, 2),
    ] {
        // The publisher's reserved verify budget refills between aborts.
        std::thread::sleep(Duration::from_millis(300));
        // One verify per receiver cycle.
        let _ = subscriber.do_work().unwrap();
        let before = counters(&subscriber);
        subscriber
            .net
            .as_mut()
            .unwrap()
            .inject_received(key, &abort(authority_id, guard_id, reason));
        let after = counters(&subscriber);
        assert_eq!(
            (after.aborts_out_of_scope, after.abort_acks_sent),
            (before.aborts_out_of_scope + 1, before.abort_acks_sent),
            "{authority_id} {guard_id} {reason}: {after:?}"
        );
        assert!(
            !subscriber.net.as_ref().unwrap().auth_image().unwrap().2,
            "not aborted"
        );
    }
    std::thread::sleep(Duration::from_millis(300));
    let _ = subscriber.do_work().unwrap();
    let before = counters(&subscriber);
    subscriber
        .net
        .as_mut()
        .unwrap()
        .inject_received(key, &abort(10, 11, GUARD_CLOSED));
    let after = counters(&subscriber);
    assert_eq!(
        after.abort_acks_sent,
        before.abort_acks_sent + 1,
        "{after:?}"
    );
    assert!(subscriber.net.as_ref().unwrap().auth_image().unwrap().2);
}

/// ADM-6, ADM-13, RNG-1, RNG-5 (cross-role rollback, delivery order
/// reversed): a remotely guarded admission whose alias and follow reach
/// the receiver while the sender refuses it leaves cleanups behind (its
/// alias queued stale, its unfollow deferred past the full receiver
/// ring). A replacement of the same stream and guard admitted before those
/// cleanups are delivered posts its alias and follow ahead of them; the
/// late cleanups, named by alias key and installation id, leave the
/// replacement bound and its guard followed.
#[test]
fn a_late_cleanup_of_a_refused_admission_never_touches_its_replacement() {
    let (mut publisher, _) = keyed(&borrowed(&guarded_files()));
    publisher
        .start_guard_state(
            Box::new(Mem::default()) as Dir,
            Box::new(Mem::default()) as Dir,
        )
        .unwrap();
    let silent = std::net::UdpSocket::bind(SocketAddr::new(LOOPBACK, 0)).unwrap();
    publisher
        .add_network_publication(
            aggregate(STREAM + 2),
            &udp(
                Destination::Unicast(silent.local_addr().unwrap()),
                Security::Trusted,
            ),
        )
        .unwrap();
    assert!(pump(&mut [&mut publisher], |_| true));
    receiver_slots(&mut publisher, 2);
    assert!(publisher.net.as_ref().unwrap().fill_sender_ring() > 0);
    let security = Security::Authenticated(auth(Some(ChannelAuthority {
        follower_id: 66,
        ..authority(control())
    })));
    let to = Destination::Unicast(SocketAddr::new(LOOPBACK, 9));
    assert_eq!(
        publisher
            .add_network_publication(aggregate(STREAM), &udp(to.clone(), security))
            .map(drop),
        Err(DriverError::NetworkBusy)
    );
    // One duty: both rings drain; the unfollow, met by the still full
    // receiver ring at the duty's start, stays deferred.
    let _ = publisher.do_work().unwrap();
    assert_eq!(
        publisher
            .net
            .as_ref()
            .unwrap()
            .wire_keys()
            .unwrap()
            .deferred_bindings(),
        1,
        "the cleanup is still held"
    );
    // The replacement, admitted now, is delivered ahead of the cleanup.
    publisher
        .add_network_publication(aggregate(STREAM), &udp(to, security))
        .unwrap();
    for _ in 0..50 {
        let _ = publisher.do_work().unwrap();
    }
    let net = publisher.net.as_ref().unwrap();
    assert_eq!(net.wire_keys().unwrap().deferred_bindings(), 0, "delivered");
    assert_eq!(
        net.followed_guards(),
        Some(1),
        "the replacement's follow stays"
    );
    assert_eq!(
        net.published_bound(),
        Some(1),
        "the replacement's alias stays"
    );
    assert_eq!(roles(&publisher).0.0, 1, "the sender binds the replacement");
    assert_eq!(net.publication_count(), 2);
}
/// H8 round 4: proofs through the authority restart (karyos#648).
mod invariants_r4;

/// H8 round 6: the round 5 review's rows R5-10 and R5-11 end to end (karyos#648).
mod invariants_r6;
