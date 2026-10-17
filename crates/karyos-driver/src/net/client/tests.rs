// SPDX-License-Identifier: Apache-2.0

//! Clients naming network channels by URI (W5b): two embedded drivers over
//! loopback, each driven only through a client conductor.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use karyos_client::{ClientConductor, MessageLimit, OfferOutcome, Outcome};
use karyos_protocol::cnc::{ErrorCode, Event, StreamKey, SubscriberRole};

use crate::agents::ThreadingMode;
use crate::embedded::{DriverConfig, EmbeddedDriver};
use crate::net::NetworkConfig;

fn driver() -> EmbeddedDriver {
    let mut network = NetworkConfig {
        threading: ThreadingMode::Shared,
        ..NetworkConfig::default()
    };
    network.stream_defaults.term_length = 64 * 1024;
    EmbeddedDriver::with_config(DriverConfig {
        network: Some(network),
        ..DriverConfig::default()
    })
    .unwrap()
}

fn port() -> u16 {
    UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Runs the drivers until `done`, polling every client into `outcomes`.
fn run(
    drivers: &mut [&mut EmbeddedDriver],
    clients: &mut [&mut ClientConductor],
    outcomes: &mut Vec<(usize, u64, Outcome)>,
    mut done: impl FnMut(&[(usize, u64, Outcome)], &mut [&mut ClientConductor]) -> bool,
) {
    for _ in 0..20_000 {
        for driver in drivers.iter_mut() {
            let _ = driver.do_work().unwrap();
        }
        for (index, client) in clients.iter_mut().enumerate() {
            let _ = client.poll(usize::MAX, |completion| {
                outcomes.push((index, completion.sequence, completion.outcome));
            });
        }
        if done(outcomes, clients) {
            return;
        }
        std::thread::sleep(Duration::from_micros(100));
    }
    panic!("not reached: {outcomes:?}");
}

/// The outcome of request `sequence` of client `client`.
fn take_of(outcomes: &mut Vec<(usize, u64, Outcome)>, client: usize, sequence: u64) -> Outcome {
    let index = outcomes
        .iter()
        .position(|(of, found, _)| (*of, *found) == (client, sequence))
        .unwrap();
    outcomes.remove(index).2
}

/// The outcome of request `sequence` of the only client.
fn take(outcomes: &mut Vec<(usize, u64, Outcome)>, sequence: u64) -> Outcome {
    take_of(outcomes, 0, sequence)
}

/// W5b end to end: a client of A publishes by URI, a client of B
/// subscribes by URI, learns the image from `ImageAvailable`, attaches
/// with `AddSubscription` naming its alias, and reads every message.
#[test]
fn clients_exchange_messages_by_channel_uri() {
    let (mut a, mut b) = (driver(), driver());
    let mut publisher = a.connect().unwrap();
    let mut subscriber = b.connect().unwrap();
    let port = port();
    let receive = format!("karyos:udp?endpoint=127.0.0.1:{port}");
    let send = format!("karyos:udp?endpoint=127.0.0.1:{port}|interface=127.0.0.1");
    let mut outcomes = Vec::new();
    let subscribed = subscriber
        .add_network_subscription(&receive, 10, SubscriberRole::Required)
        .unwrap();
    let published = publisher.add_network_publication(&send, 10, true).unwrap();
    let mut image = None;
    run(
        &mut [&mut a, &mut b],
        &mut [&mut publisher, &mut subscriber],
        &mut outcomes,
        |_, clients| {
            for event in clients[1].take_events() {
                if let Event::ImageAvailable { stream, .. } = event {
                    image = Some(stream);
                }
            }
            image.is_some()
        },
    );
    let Outcome::NetworkSubscription { registration } = take_of(&mut outcomes, 1, subscribed)
    else {
        panic!("not a network subscription");
    };
    assert!(registration > 0);
    let Outcome::Publication(mut publication) = take_of(&mut outcomes, 0, published) else {
        panic!("not a publication");
    };
    let image: StreamKey = image.unwrap();
    assert_eq!(image.stream_id, 10);
    assert_ne!(image.session_id, 0, "the driver drew the alias");
    let attach = subscriber
        .add_subscription(image, SubscriberRole::Required)
        .unwrap();
    run(
        &mut [&mut a, &mut b],
        &mut [&mut publisher, &mut subscriber],
        &mut outcomes,
        |outcomes, _| {
            outcomes
                .iter()
                .any(|(client, sequence, _)| (*client, *sequence) == (1, attach))
        },
    );
    let Outcome::Subscription(mut reading) = take_of(&mut outcomes, 1, attach) else {
        panic!("not a subscription");
    };
    let (mut sent, mut seen) = (0u32, 0u32);
    run(
        &mut [&mut a, &mut b],
        &mut [&mut publisher, &mut subscriber],
        &mut outcomes,
        |_, _| {
            while sent < 64 {
                match publication.offer(&sent.to_le_bytes()).unwrap() {
                    OfferOutcome::Accepted { .. } => sent += 1,
                    _ => break,
                }
            }
            let _ = reading.poll(
                |bytes, _| {
                    assert_eq!(u32::from_le_bytes(bytes[..4].try_into().unwrap()), seen);
                    seen += 1;
                },
                MessageLimit::new(64),
            );
            seen == 64
        },
    );
}

/// `karyos:ipc` resolves the configured stream by id; an id with two
/// sessions is ambiguous, an unparsable URI is `InvalidChannel` with the
/// parse error's code, and an IPC subscription is `AddSubscription`'s.
#[test]
fn ipc_uris_and_refusals() {
    let mut driver = driver();
    let config = |stream_id, session_id| {
        let mut stream = crate::net::e2e_config(stream_id);
        stream.buffer.session_id = session_id;
        stream
    };
    let _ = driver.add_stream(config(20, 1)).unwrap();
    let _ = driver.add_stream(config(21, 1)).unwrap();
    let _ = driver.add_stream(config(21, 2)).unwrap();
    let mut client = driver.connect().unwrap();
    let mut outcomes = Vec::new();
    let resolved = client
        .add_network_publication("karyos:ipc", 20, true)
        .unwrap();
    let ambiguous = client
        .add_network_publication("karyos:ipc", 21, true)
        .unwrap();
    // A URI that does not parse is refused on the client side (W5a).
    let code = karyos_protocol::channel::ChannelConfig::parse("karyos:tcp")
        .unwrap_err()
        .code();
    assert_eq!(
        client.add_network_publication("karyos:tcp", 20, true),
        Err(karyos_client::ConductorError::InvalidChannel { code })
    );
    let ipc_subscription = client
        .add_network_subscription("karyos:ipc", 20, SubscriberRole::Optional)
        .unwrap();
    let sequences = [resolved, ambiguous, ipc_subscription];
    run(
        &mut [&mut driver],
        &mut [&mut client],
        &mut outcomes,
        |outcomes, _| {
            sequences
                .iter()
                .all(|sequence| outcomes.iter().any(|(_, found, _)| found == sequence))
        },
    );
    assert!(matches!(
        take(&mut outcomes, resolved),
        Outcome::Publication(_)
    ));
    assert!(matches!(
        take(&mut outcomes, ambiguous),
        Outcome::Refused {
            code: ErrorCode::UnknownStream,
            ..
        }
    ));
    assert!(matches!(
        take(&mut outcomes, ipc_subscription),
        Outcome::Refused {
            code: ErrorCode::UnsupportedChannel,
            ..
        }
    ));
}

/// W5b B3: what a client created goes with it: its network publication
/// and its network subscription are removed once its conductor is gone.
#[test]
fn a_lost_client_takes_its_network_resources_with_it() {
    let mut driver = driver();
    let mut client = driver.connect().unwrap();
    let port = port();
    let mut outcomes = Vec::new();
    let published = client
        .add_network_publication(
            &format!("karyos:udp?endpoint=127.0.0.1:{port}|interface=127.0.0.1"),
            10,
            true,
        )
        .unwrap();
    let subscribed = client
        .add_network_subscription(
            &format!("karyos:udp?endpoint=127.0.0.1:{}", port + 1),
            11,
            SubscriberRole::Optional,
        )
        .unwrap();
    run(
        &mut [&mut driver],
        &mut [&mut client],
        &mut outcomes,
        |outcomes, _| {
            [published, subscribed]
                .iter()
                .all(|sequence| outcomes.iter().any(|(_, found, _)| found == sequence))
        },
    );
    let net = driver.net.as_ref().unwrap();
    assert_eq!((net.publication_count(), net.subscription_count()), (1, 1));
    // The client goes, with its handles.
    drop(outcomes);
    drop(client);
    for _ in 0..200 {
        let _ = driver.do_work().unwrap();
        let net = driver.net.as_ref().unwrap();
        if (net.publication_count(), net.subscription_count()) == (0, 0) {
            assert!(driver.net_owned.is_empty());
            return;
        }
    }
    panic!("the client's network resources outlived it");
}

/// W5b B5: a full receiver table refuses a client's network subscription
/// at once, with `ResourcesUnavailable`.
#[test]
fn a_full_subscription_table_refuses_at_once() {
    let mut network = NetworkConfig {
        threading: ThreadingMode::Shared,
        ..NetworkConfig::default()
    };
    network.agents.subscriptions = 1;
    let mut driver = EmbeddedDriver::with_config(DriverConfig {
        network: Some(network),
        ..DriverConfig::default()
    })
    .unwrap();
    let mut client = driver.connect().unwrap();
    let port = port();
    let mut outcomes = Vec::new();
    let first = client
        .add_network_subscription(
            &format!("karyos:udp?endpoint=127.0.0.1:{port}"),
            10,
            SubscriberRole::Optional,
        )
        .unwrap();
    let second = client
        .add_network_subscription(
            &format!("karyos:udp?endpoint=127.0.0.1:{port}"),
            11,
            SubscriberRole::Optional,
        )
        .unwrap();
    run(
        &mut [&mut driver],
        &mut [&mut client],
        &mut outcomes,
        |outcomes, _| {
            [first, second]
                .iter()
                .all(|sequence| outcomes.iter().any(|(_, found, _)| found == sequence))
        },
    );
    assert!(matches!(
        take(&mut outcomes, first),
        Outcome::NetworkSubscription { .. }
    ));
    assert!(matches!(
        take(&mut outcomes, second),
        Outcome::Refused {
            code: ErrorCode::ResourcesUnavailable,
            ..
        }
    ));
}

/// A second network subscription of one endpoint and stream with another
/// reliability is refused with `ReliabilityMismatch`, not given the
/// first's.
#[test]
fn a_subscription_with_another_reliability_is_refused() {
    let mut driver = driver();
    let mut client = driver.connect().unwrap();
    let port = port();
    let mut outcomes = Vec::new();
    let first = client
        .add_network_subscription(
            &format!("karyos:udp?endpoint=127.0.0.1:{port}"),
            10,
            SubscriberRole::Optional,
        )
        .unwrap();
    let second = client
        .add_network_subscription(
            &format!("karyos:udp?endpoint=127.0.0.1:{port}|reliable=false"),
            10,
            SubscriberRole::Optional,
        )
        .unwrap();
    run(
        &mut [&mut driver],
        &mut [&mut client],
        &mut outcomes,
        |outcomes, _| {
            [first, second]
                .iter()
                .all(|sequence| outcomes.iter().any(|(_, found, _)| found == sequence))
        },
    );
    assert!(matches!(
        take(&mut outcomes, first),
        Outcome::NetworkSubscription { .. }
    ));
    assert!(matches!(
        take(&mut outcomes, second),
        Outcome::Refused {
            code: ErrorCode::ReliabilityMismatch,
            ..
        }
    ));
}
