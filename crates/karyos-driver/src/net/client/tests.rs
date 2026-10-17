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
    let ambiguous_subscription = client
        .add_network_subscription("karyos:ipc", 21, SubscriberRole::Optional)
        .unwrap();
    let sequences = [
        resolved,
        ambiguous,
        ipc_subscription,
        ambiguous_subscription,
    ];
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
    // W7: an IPC URI subscribes the only stream of the id.
    assert!(matches!(
        take(&mut outcomes, ipc_subscription),
        Outcome::Subscription(_)
    ));
    assert!(matches!(
        take(&mut outcomes, ambiguous_subscription),
        Outcome::Refused {
            code: ErrorCode::UnknownStream,
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
    // The client goes, with its handles. The sender's answer to the
    // removal takes a few cycles of the agents: bounded by time, not by a
    // cycle count, which a loaded machine runs through first.
    drop(outcomes);
    drop(client);
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(10) {
        let _ = driver.do_work().unwrap();
        let net = driver.net.as_ref().unwrap();
        if (net.publication_count(), net.subscription_count()) == (0, 0) {
            assert!(driver.net_owned.is_empty());
            return;
        }
        std::thread::sleep(Duration::from_micros(100));
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

/// A driver whose configuration `change` adjusts.
fn driver_with(change: impl FnOnce(&mut DriverConfig)) -> EmbeddedDriver {
    let mut network = NetworkConfig {
        threading: ThreadingMode::Shared,
        ..NetworkConfig::default()
    };
    network.stream_defaults.term_length = 64 * 1024;
    let mut config = DriverConfig {
        network: Some(network),
        ..DriverConfig::default()
    };
    change(&mut config);
    EmbeddedDriver::with_config(config).unwrap()
}

/// Runs `driver` until `done`, for at most 5 s: bounded by time, never
/// by a cycle count, which a loaded machine runs through first.
fn eventually(driver: &mut EmbeddedDriver, mut done: impl FnMut(&EmbeddedDriver) -> bool) {
    let start = std::time::Instant::now();
    while !done(driver) {
        assert!(start.elapsed() < Duration::from_secs(5), "not reached");
        let _ = driver.do_work().unwrap();
        std::thread::sleep(Duration::from_micros(100));
    }
}

/// Runs one driver and its client until request `sequence` completes.
fn complete(driver: &mut EmbeddedDriver, client: &mut ClientConductor, sequence: u64) -> Outcome {
    let mut outcomes = Vec::new();
    run(
        &mut [driver],
        &mut [client],
        &mut outcomes,
        |outcomes, _| outcomes.iter().any(|(_, found, _)| *found == sequence),
    );
    take(&mut outcomes, sequence)
}

/// #294 P2: `karyos:ipc` counts an aggregate once, whatever its lanes, and
/// never the network's aggregates of the same id: a network publication
/// or an image.
#[test]
fn ipc_resolution_counts_aggregates_not_lanes_or_network_streams() {
    let (mut a, mut b) = (driver(), driver());
    let mut aggregate = crate::embedded::AggregateConfig {
        stream: crate::net::e2e_config(30),
        quanta: vec![u64::from(karyos_sys::sizing::DEFAULT_MTU) * 4; 2],
    };
    aggregate.stream.buffer.session_id = 5;
    let _ = b.add_aggregate(aggregate).unwrap();
    let mut ipc = crate::net::e2e_config(10);
    ipc.buffer.session_id = 7;
    let _ = a.add_stream(ipc).unwrap();
    let _ = b.add_stream(ipc).unwrap();
    let mut publisher = a.connect().unwrap();
    let mut subscriber = b.connect().unwrap();
    let port = port();
    let mut outcomes = Vec::new();
    // A network publication of id 10 beside A's IPC stream of id 10, and
    // its image on B beside B's.
    let subscribed = subscriber
        .add_network_subscription(
            &format!("karyos:udp?endpoint=127.0.0.1:{port}"),
            10,
            SubscriberRole::Required,
        )
        .unwrap();
    let published = publisher
        .add_network_publication(
            &format!("karyos:udp?endpoint=127.0.0.1:{port}|interface=127.0.0.1"),
            10,
            true,
        )
        .unwrap();
    let mut image = false;
    run(
        &mut [&mut a, &mut b],
        &mut [&mut publisher, &mut subscriber],
        &mut outcomes,
        |_, clients| {
            image |= clients[1]
                .take_events()
                .any(|event| matches!(event, Event::ImageAvailable { .. }));
            image
        },
    );
    assert!(matches!(
        take_of(&mut outcomes, 1, subscribed),
        Outcome::NetworkSubscription { .. }
    ));
    assert!(matches!(
        take_of(&mut outcomes, 0, published),
        Outcome::Publication(_)
    ));
    let lanes = subscriber
        .add_network_publication("karyos:ipc", 30, true)
        .unwrap();
    let beside_image = subscriber
        .add_network_publication("karyos:ipc", 10, true)
        .unwrap();
    let beside_publication = publisher
        .add_network_publication("karyos:ipc", 10, true)
        .unwrap();
    let sequences = [(1, lanes), (1, beside_image), (0, beside_publication)];
    run(
        &mut [&mut a, &mut b],
        &mut [&mut publisher, &mut subscriber],
        &mut outcomes,
        |outcomes, _| {
            sequences
                .iter()
                .all(|wanted| outcomes.iter().any(|(c, s, _)| (*c, *s) == *wanted))
        },
    );
    for (client, sequence) in sequences {
        assert!(
            matches!(
                take_of(&mut outcomes, client, sequence),
                Outcome::Publication(_)
            ),
            "request {sequence} of client {client}"
        );
    }
}

/// The image events of `registration` seen by `client` so far, as
/// (available, unavailable) counts.
fn image_events(client: &mut ClientConductor, counts: &mut [(u64, u32, u32)]) {
    for event in client.take_events() {
        let (registration, available) = match event {
            Event::ImageAvailable { registration, .. } => (registration, true),
            Event::ImageUnavailable { registration, .. } => (registration, false),
            _ => continue,
        };
        if let Some(entry) = counts.iter_mut().find(|entry| entry.0 == registration) {
            if available {
                entry.1 += 1;
            } else {
                entry.2 += 1;
            }
        }
    }
}

/// #294 P2: a subscription made before an image and one made after it
/// are each told of it once, and of its retirement once.
#[test]
fn each_subscription_learns_of_an_image_once_either_way() {
    // The receiver retires an image half a second after its sender goes.
    let (mut a, mut b) = (
        driver(),
        driver_with(|config| {
            if let Some(network) = &mut config.network {
                network.agents.image_liveness_timeout = 500_000_000;
            }
        }),
    );
    let mut publisher = a.connect().unwrap();
    let mut subscriber = b.connect().unwrap();
    let port = port();
    let uri = format!("karyos:udp?endpoint=127.0.0.1:{port}");
    let mut outcomes = Vec::new();
    let before = subscriber
        .add_network_subscription(&uri, 10, SubscriberRole::Required)
        .unwrap();
    let Outcome::NetworkSubscription {
        registration: first,
    } = complete(&mut b, &mut subscriber, before)
    else {
        panic!("not a network subscription");
    };
    let published = publisher
        .add_network_publication(&format!("{uri}|interface=127.0.0.1"), 10, true)
        .unwrap();
    let mut counts = vec![(first, 0, 0)];
    run(
        &mut [&mut a, &mut b],
        &mut [&mut publisher, &mut subscriber],
        &mut outcomes,
        |_, clients| {
            image_events(clients[1], &mut counts);
            counts[0].1 > 0
        },
    );
    let Outcome::Publication(publication) = take_of(&mut outcomes, 0, published) else {
        panic!("not a publication");
    };
    // The second subscription shares the receiver's entry: it learns of
    // the image already there.
    let after = subscriber
        .add_network_subscription(&uri, 10, SubscriberRole::Required)
        .unwrap();
    let mut second = None;
    run(
        &mut [&mut a, &mut b],
        &mut [&mut publisher, &mut subscriber],
        &mut outcomes,
        |outcomes, clients| {
            if second.is_none()
                && let Some((_, _, Outcome::NetworkSubscription { registration })) =
                    outcomes.iter().find(|(_, s, _)| *s == after)
            {
                let registration = *registration;
                second = Some(registration);
                counts.push((registration, 0, 0));
            }
            image_events(clients[1], &mut counts);
            counts.len() == 2 && counts[1].1 > 0
        },
    );
    // The publication goes: its image retires once the receiver sees the
    // sender gone.
    drop(publication);
    let start = std::time::Instant::now();
    while !counts.iter().all(|entry| entry.2 > 0) {
        assert!(start.elapsed() < Duration::from_secs(30), "{counts:?}");
        let _ = a.do_work().unwrap();
        let _ = b.do_work().unwrap();
        let _ = publisher.poll(usize::MAX, |_| {});
        let _ = subscriber.poll(usize::MAX, |_| {});
        image_events(&mut subscriber, &mut counts);
        std::thread::sleep(Duration::from_micros(100));
    }
    for _ in 0..200 {
        let _ = a.do_work().unwrap();
        let _ = b.do_work().unwrap();
        let _ = subscriber.poll(usize::MAX, |_| {});
    }
    image_events(&mut subscriber, &mut counts);
    assert_eq!(
        counts
            .iter()
            .map(|entry| (entry.1, entry.2))
            .collect::<Vec<_>>(),
        [(1, 1), (1, 1)],
        "{counts:?}"
    );
}

/// #294 P2 (§14): a client owns at most `max_owned_per_client` network
/// resources by URI; another is refused at once and counted.
#[test]
fn a_client_owns_a_bounded_number_of_network_resources() {
    let mut driver = driver_with(|config| {
        if let Some(network) = &mut config.network {
            network.max_owned_per_client = 2;
        }
    });
    let mut client = driver.connect().unwrap();
    let port = port();
    let uri = format!("karyos:udp?endpoint=127.0.0.1:{port}");
    for expected in [true, true, false] {
        let sequence = client
            .add_network_subscription(&uri, 10, SubscriberRole::Required)
            .unwrap();
        let outcome = complete(&mut driver, &mut client, sequence);
        if expected {
            assert!(matches!(outcome, Outcome::NetworkSubscription { .. }));
        } else {
            assert!(matches!(
                outcome,
                Outcome::Refused {
                    code: ErrorCode::ResourcesUnavailable,
                    ..
                }
            ));
        }
    }
    let publication = client
        .add_network_publication(&format!("{uri}|interface=127.0.0.1"), 11, true)
        .unwrap();
    assert!(matches!(
        complete(&mut driver, &mut client, publication),
        Outcome::Refused {
            code: ErrorCode::ResourcesUnavailable,
            ..
        }
    ));
    assert_eq!(driver.network_owned_refusals(), 2);
    assert_eq!(driver.net.as_ref().unwrap().publication_count(), 0);
}

/// #294 tests: `RemoveSubscription` of a network subscription removes it
/// for its client only; another client's request names no registration of
/// its own.
#[test]
fn only_its_client_removes_a_network_subscription() {
    let mut driver = driver();
    let mut owner = driver.connect().unwrap();
    let mut other = driver.connect().unwrap();
    let port = port();
    let sequence = owner
        .add_network_subscription(
            &format!("karyos:udp?endpoint=127.0.0.1:{port}"),
            10,
            SubscriberRole::Required,
        )
        .unwrap();
    let Outcome::NetworkSubscription { registration } = complete(&mut driver, &mut owner, sequence)
    else {
        panic!("not a network subscription");
    };
    let refused = other.remove_network_subscription(registration).unwrap();
    assert!(matches!(
        complete(&mut driver, &mut other, refused),
        Outcome::Refused {
            code: ErrorCode::UnknownRegistration,
            ..
        }
    ));
    assert_eq!(driver.net.as_ref().unwrap().subscription_count(), 1);
    let removed = owner.remove_network_subscription(registration).unwrap();
    assert!(matches!(
        complete(&mut driver, &mut owner, removed),
        Outcome::Succeeded
    ));
    assert!(driver.net_owned.is_empty());
    eventually(&mut driver, |driver| {
        driver.net.as_ref().unwrap().subscription_count() == 0
    });
}

/// #294 tests: a client that stops heartbeating is no longer served, and
/// its network subscription goes with it.
#[test]
fn a_timed_out_client_loses_its_network_subscription() {
    let mut driver = driver_with(|config| {
        config.heartbeat_interval = 1_000_000;
        config.client_liveness_timeout = 20_000_000;
    });
    let mut client = driver.connect().unwrap();
    client.set_liveness(Duration::from_millis(1), Duration::from_secs(10));
    let port = port();
    let sequence = client
        .add_network_subscription(
            &format!("karyos:udp?endpoint=127.0.0.1:{port}"),
            10,
            SubscriberRole::Required,
        )
        .unwrap();
    assert!(matches!(
        complete(&mut driver, &mut client, sequence),
        Outcome::NetworkSubscription { .. }
    ));
    // The client no longer polls, so it sends no heartbeat.
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        let _ = driver.do_work().unwrap();
        if driver.net_owned.is_empty() && driver.net.as_ref().unwrap().subscription_count() == 0 {
            return;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    panic!("the timed-out client's network subscription outlived its service");
}

/// #294 tests: a network publication whose grant is refused leaves
/// nothing behind.
#[test]
fn a_refused_grant_removes_its_network_publication() {
    let mut driver = driver_with(|config| config.max_hand_over = 1);
    let _ = driver.add_stream(crate::net::e2e_config(20)).unwrap();
    let mut client = driver.connect().unwrap();
    let port = port();
    // The first grant stays held, untaken, so the second is refused.
    let held = client
        .add_network_publication("karyos:ipc", 20, true)
        .unwrap();
    let refused = client
        .add_network_publication(
            &format!("karyos:udp?endpoint=127.0.0.1:{port}|interface=127.0.0.1"),
            10,
            true,
        )
        .unwrap();
    // Both commands are served (one per cycle), then the refused grant's
    // publication is removed, once the sender answers.
    for _ in 0..2 {
        let _ = driver.do_work().unwrap();
    }
    assert!(driver.net_owned.is_empty());
    eventually(&mut driver, |driver| {
        driver.net.as_ref().unwrap().publication_count() == 0
    });
    let mut outcomes = Vec::new();
    run(
        &mut [&mut driver],
        &mut [&mut client],
        &mut outcomes,
        |outcomes, _| outcomes.len() == 2,
    );
    assert!(matches!(take(&mut outcomes, held), Outcome::Publication(_)));
    assert!(matches!(
        take(&mut outcomes, refused),
        Outcome::Refused {
            code: ErrorCode::ResourcesUnavailable,
            ..
        }
    ));
}

/// #294 tests: a drawn session id is never 0 nor one of the id's streams;
/// a failed random source and endless collisions are refused distinctly.
#[test]
fn session_draws_skip_zero_and_collisions() {
    let mut driver = driver();
    let mut taken = crate::net::e2e_config(10);
    taken.buffer.session_id = 5;
    let _ = driver.add_stream(taken).unwrap();
    let mut words = [0u64, 5, 6].into_iter();
    assert_eq!(driver.draw_session(10, || words.next()), Ok(6));
    // The low 32 bits are the session id.
    assert_eq!(
        driver.draw_session(10, || Some(5 | 1 << 40)),
        Err(ErrorCode::IdentitiesExhausted)
    );
    assert_eq!(driver.draw_session(11, || Some(5)), Ok(5));
    assert_eq!(
        driver.draw_session(10, || None),
        Err(ErrorCode::ResourcesUnavailable)
    );
}

/// #294 tests: `karyos:udp` on a driver without a network is unsupported.
#[test]
fn udp_without_a_network_is_unsupported() {
    let mut driver = EmbeddedDriver::new().unwrap();
    let mut client = driver.connect().unwrap();
    let uri = "karyos:udp?endpoint=127.0.0.1:40999";
    let publication = client.add_network_publication(uri, 10, true).unwrap();
    let subscription = client
        .add_network_subscription(uri, 10, SubscriberRole::Required)
        .unwrap();
    for sequence in [publication, subscription] {
        assert!(matches!(
            complete(&mut driver, &mut client, sequence),
            Outcome::Refused {
                code: ErrorCode::UnsupportedChannel,
                ..
            }
        ));
    }
}

/// #294 tests: stream defaults that make no valid log are refused at
/// start.
#[test]
fn invalid_stream_defaults_are_refused_at_start() {
    for change in [
        (|network: &mut NetworkConfig| network.stream_defaults.term_length = 1000)
            as fn(&mut NetworkConfig),
        |network| network.stream_defaults.lanes = 0,
        |network| network.stream_defaults.lanes = 5,
        |network| network.stream_defaults.spare_slots = 0,
        |network| network.max_owned_per_client = 0,
        // Beyond the bound, and a product with max_clients that would
        // overflow: refused, never a capacity panic (#300 P2).
        |network| network.max_owned_per_client = 4097,
        |network| network.max_owned_per_client = usize::MAX / 2,
    ] {
        let mut network = NetworkConfig::default();
        change(&mut network);
        assert!(matches!(
            EmbeddedDriver::with_config(DriverConfig {
                network: Some(network),
                ..DriverConfig::default()
            }),
            Err(crate::DriverError::InvalidConfig)
        ));
    }
}

/// #294's race (#300 follow-up): a subscription created in the same cycle
/// as its image's `Installed` is told of the image once. One subscription
/// is created every cycle (one command per client ring and cycle) until
/// well after the image arrives, so one of them is created in the cycle
/// that installs it; every one of them sees exactly one `ImageAvailable`.
#[test]
fn a_subscription_made_in_the_installing_cycle_learns_of_the_image_once() {
    let mut a = driver();
    let mut b = driver_with(|config| {
        if let Some(network) = &mut config.network {
            network.max_owned_per_client = 4096;
        }
    });
    let mut publisher = a.connect().unwrap();
    let mut subscriber = b.connect().unwrap();
    let port = port();
    let uri = format!("karyos:udp?endpoint=127.0.0.1:{port}");
    let mut published = None;
    // The publication's handle is kept: dropping it would end it.
    let mut publication = None;
    let mut counts: Vec<(u64, u32, u32)> = Vec::new();
    let mut after_image = 0u32;
    let start = std::time::Instant::now();
    while after_image < 20 {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "{} subscriptions",
            counts.len()
        );
        let _ = subscriber
            .add_network_subscription(&uri, 10, SubscriberRole::Required)
            .unwrap();
        // The publication follows the first subscription: its receiver
        // is bound when its first setup arrives.
        if published.is_none() && !counts.is_empty() {
            published = Some(
                publisher
                    .add_network_publication(&format!("{uri}|interface=127.0.0.1"), 10, true)
                    .unwrap(),
            );
        }
        let _ = a.do_work().unwrap();
        let _ = b.do_work().unwrap();
        let _ = publisher.poll(usize::MAX, |completion| {
            assert_eq!(Some(completion.sequence), published);
            let Outcome::Publication(handle) = completion.outcome else {
                panic!("not a publication: {:?}", completion.outcome);
            };
            publication = Some(handle);
        });
        let _ = subscriber.poll(usize::MAX, |completion| {
            let Outcome::NetworkSubscription { registration } = completion.outcome else {
                panic!("not a network subscription: {:?}", completion.outcome);
            };
            counts.push((registration, 0, 0));
        });
        image_events(&mut subscriber, &mut counts);
        if counts.iter().any(|entry| entry.1 > 0) {
            after_image += 1;
        }
        std::thread::sleep(Duration::from_micros(100));
    }
    // Late events of the last subscriptions.
    for _ in 0..20 {
        let _ = a.do_work().unwrap();
        let _ = b.do_work().unwrap();
        let _ = subscriber.poll(usize::MAX, |completion| {
            if let Outcome::NetworkSubscription { registration } = completion.outcome {
                counts.push((registration, 0, 0));
            }
        });
        image_events(&mut subscriber, &mut counts);
    }
    assert!(publication.is_some());
    assert!(
        counts.iter().all(|entry| entry.1 == 1),
        "every subscription saw the image exactly once: {:?}",
        counts
            .iter()
            .filter(|entry| entry.1 != 1)
            .collect::<Vec<_>>()
    );
}

/// Publish before subscribe, the usual order (#300 follow-up, ACS
/// 16256): a unicast publication announces to an endpoint nobody is bound
/// to yet; a subscription made later still gets its image, and messages
/// flow. The publication's handle is kept: dropping it would end it.
#[test]
fn a_publication_made_before_its_subscription_reaches_it() {
    let (mut a, mut b) = (driver(), driver());
    let mut publisher = a.connect().unwrap();
    let mut subscriber = b.connect().unwrap();
    let port = port();
    let uri = format!("karyos:udp?endpoint=127.0.0.1:{port}");
    let published = publisher
        .add_network_publication(&format!("{uri}|interface=127.0.0.1"), 10, true)
        .unwrap();
    let Outcome::Publication(mut publication) = complete(&mut a, &mut publisher, published) else {
        panic!("not a publication");
    };
    // Its announcements go unanswered for a while.
    for _ in 0..50 {
        let _ = a.do_work().unwrap();
        let _ = b.do_work().unwrap();
        std::thread::sleep(Duration::from_millis(1));
    }
    let subscribed = subscriber
        .add_network_subscription(&uri, 10, SubscriberRole::Required)
        .unwrap();
    let mut outcomes = Vec::new();
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
    assert!(matches!(
        take_of(&mut outcomes, 1, subscribed),
        Outcome::NetworkSubscription { .. }
    ));
    let attach = subscriber
        .add_subscription(image.unwrap(), SubscriberRole::Required)
        .unwrap();
    let Outcome::Subscription(mut reading) = complete(&mut b, &mut subscriber, attach) else {
        panic!("not a subscription");
    };
    let (mut sent, mut seen) = (0u32, 0u32);
    run(
        &mut [&mut a, &mut b],
        &mut [&mut publisher, &mut subscriber],
        &mut outcomes,
        |_, _| {
            while sent < 32 {
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
                MessageLimit::new(32),
            );
            seen == 32
        },
    );
}

/// #306 review: a network subscription whose request timed out is
/// removed when its late grant arrives, so it holds nothing.
#[test]
fn a_late_network_subscription_grant_is_removed() {
    let mut driver = driver();
    let mut client = karyos_client::Client::with_conductor(
        driver.connect().unwrap(),
        karyos_client::Context::builder()
            .timeout(Duration::from_millis(20))
            .build()
            .unwrap(),
    );
    let port = port();
    // The driver runs on this thread: the request times out.
    assert!(matches!(
        client.add_subscription(
            &format!("karyos:udp?endpoint=127.0.0.1:{port}"),
            karyos_protocol::cnc::StreamId::new(10),
        ),
        Err(karyos_client::ClientError::Timeout)
    ));
    let start = std::time::Instant::now();
    while client.late_grants_released() == 0 {
        assert!(start.elapsed() < Duration::from_secs(5), "not released");
        let _ = driver.do_work().unwrap();
        let _ = client.poll();
    }
    eventually(&mut driver, |driver| {
        driver.net_owned.is_empty() && driver.net.as_ref().unwrap().subscription_count() == 0
    });
}

/// #306 review (P1): a lap of the client's broadcast receiver loses image
/// events, so the facade closes its network subscriptions with
/// `EventsLost` instead of keeping images it can no longer track.
#[test]
fn a_lap_closes_the_network_subscriptions() {
    let mut driver = driver();
    let mut client = karyos_client::Client::with_conductor(
        driver.connect().unwrap(),
        karyos_client::Context::builder().build().unwrap(),
    );
    let port = port();
    let uri = format!("karyos:udp?endpoint=127.0.0.1:{port}");
    let mut reading = std::thread::scope(|scope| {
        let handle =
            scope.spawn(|| client.add_subscription(&uri, karyos_protocol::cnc::StreamId::new(10)));
        while !handle.is_finished() {
            let _ = driver.do_work().unwrap();
        }
        handle.join().unwrap().unwrap()
    });
    assert!(reading.poll(|_, _| {}, MessageLimit::new(1)).is_ok());
    // Another client's answers fill the broadcast many times over while
    // this client does not poll: its receiver is lapped.
    let mut other = driver.connect().unwrap();
    for _ in 0..200 {
        for _ in 0..32 {
            let _ = other.add_subscription(
                StreamKey {
                    stream_id: 99,
                    session_id: 1,
                },
                SubscriberRole::Optional,
            );
        }
        for _ in 0..40 {
            let _ = driver.do_work().unwrap();
        }
        let _ = other.poll(usize::MAX, |_| {});
    }
    let _ = client.poll();
    assert_eq!(
        reading.poll(|_, _| {}, MessageLimit::new(1)).err(),
        Some(karyos_client::SubscriptionError::Closed(
            karyos_client::ClientError::EventsLost
        ))
    );
}
