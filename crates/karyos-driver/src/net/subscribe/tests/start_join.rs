// SPDX-License-Identifier: Apache-2.0

//! ADR-0100 (karyos#844): a network subscription that exists when an image
//! of its key is built gets an awaiting cell at the image's join, and an
//! `AddImageSubscriptionOf` naming it adopts that cell in place.

use std::sync::Arc;

use karyos_client::link::{Capability, ClientLink};
use karyos_protocol::cnc::{ChannelUri, Command, ErrorCode, Event, Response, SubscriberRole};
use karyos_sys::broadcast::{BroadcastReceiver, Received};
use karyos_sys::log_buffer::PollOutcome;

use super::*;

/// An in-process client of `driver`, its command ring and its link.
fn local_client(
    driver: &mut EmbeddedDriver,
) -> (u64, karyos_sys::command_ring::RingProducer, Arc<ClientLink>) {
    let (producer, consumer) = karyos_sys::command_ring::command_ring(1024).unwrap();
    let link = Arc::new(ClientLink::new());
    let client = driver.admit(consumer, Arc::clone(&link), None).unwrap();
    (client, producer, link)
}

/// Responses and events `observer` has not read yet.
fn drain(observer: &mut BroadcastReceiver) -> (Vec<Response>, Vec<Event>) {
    let (mut responses, mut events) = (Vec::new(), Vec::new());
    while let Received::Message {
        type_id, payload, ..
    } = observer.receive()
    {
        if let Ok(response) = Response::decode(type_id, payload) {
            responses.push(response);
        } else if let Ok(event) = Event::decode(type_id, payload) {
            events.push(event);
        }
    }
    (responses, events)
}

/// A publisher `a`, a subscribing driver `b` with an image deadline of
/// `deadline` ns, an in-process client of `b` whose network subscription
/// of `role` exists before the image, and the image once built: the
/// client, its ring, its link, the subscription's registration, the image
/// and the publisher's lane 0 publication.
struct Rig {
    a: EmbeddedDriver,
    b: EmbeddedDriver,
    producer: karyos_sys::command_ring::RingProducer,
    link: Arc<ClientLink>,
    observer: BroadcastReceiver,
    parent: u64,
    image: u64,
    publication: karyos_client::ClientPublication,
}

impl Rig {
    fn new(role: SubscriberRole, deadline: u64) -> Self {
        Self::with_client(role, deadline, false)
    }

    /// As [`Rig::new`]; with `remote`, the client is admitted with an
    /// export ledger, so its attaches are grants (`add_remote`).
    fn with_client(role: SubscriberRole, deadline: u64, remote: bool) -> Self {
        Self::with_ledger(
            role,
            deadline,
            remote.then(|| crate::ledger::Ledger::new(4, 4, 1 << 30)),
        )
    }

    /// As [`Rig::with_client`], the remote client admitted with `ledger`.
    fn with_ledger(
        role: SubscriberRole,
        deadline: u64,
        ledger: Option<crate::ledger::Ledger>,
    ) -> Self {
        let a = driver(ThreadingMode::Shared);
        let mut network = NetworkConfig {
            threading: ThreadingMode::Shared,
            ..NetworkConfig::default()
        };
        network.images.image_join_deadline = deadline;
        let mut b = EmbeddedDriver::with_config(DriverConfig {
            network: Some(network),
            ..DriverConfig::default()
        })
        .unwrap();
        let address = SocketAddr::new(LOOPBACK, free_port());
        let mut observer = b.broadcast.receiver();
        let (_client, mut producer, link) = match ledger {
            Some(ledger) => {
                let (producer, consumer) = karyos_sys::command_ring::command_ring(1024).unwrap();
                let link = Arc::new(ClientLink::new());
                let client = b.admit(consumer, Arc::clone(&link), Some(ledger)).unwrap();
                (client, producer, link)
            }
            None => local_client(&mut b),
        };
        write_command(
            &mut producer,
            Command::AddNetworkSubscription {
                sequence: 1,
                stream_id: 10,
                role,
                uri: ChannelUri::new(&format!("karyos:udp?endpoint={address}")).unwrap(),
            },
        );
        let mut parent = None;
        // Bounded by a deadline, not 200 duty cycles: a loaded host can
        // take longer to answer (karyos#1067).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        while std::time::Instant::now() < deadline {
            let _ = b.do_work().unwrap();
            parent = setup_answer(&drain(&mut observer).0, 1).or(parent);
            if parent.is_some() {
                break;
            }
        }
        let parent = parent.expect("the network subscription is ready");
        let mut a = a;
        let handle = a
            .add_network_publication(aggregate(10, 3, 1), &channel(address))
            .unwrap();
        let publication = a.publication(handle.lane(Lane::ZERO).unwrap()).unwrap();
        pump(&mut a, &mut b, |_, b| b.network_images(10).len() == 1);
        let image = b.network_images(10)[0].0.registration();
        let _ = drain(&mut observer);
        Self {
            a,
            b,
            producer,
            link,
            observer,
            parent,
            image,
            publication,
        }
    }

    /// Offers `payload` until the publication is connected and takes it,
    /// then lets it reach the image.
    fn offer(&mut self, payload: &[u8]) -> u64 {
        let mut position = None;
        pump(&mut self.a, &mut self.b, |_, _| {
            if position.is_none()
                && let Ok(OfferOutcome::Accepted { position: at, .. }) =
                    self.publication.offer(payload)
            {
                position = Some(at);
            }
            position.is_some()
        });
        for _ in 0..50 {
            let _ = (self.a.do_work().unwrap(), self.b.do_work().unwrap());
        }
        position.unwrap()
    }

    /// Sends `command` and serves it: the response and the events.
    fn send(&mut self, command: Command) -> (Vec<Response>, Vec<Event>) {
        write_command(&mut self.producer, command);
        for _ in 0..20 {
            let _ = (self.a.do_work().unwrap(), self.b.do_work().unwrap());
        }
        drain(&mut self.observer)
    }

    /// The subscription handed over for `key`.
    fn take(&self, key: u64) -> karyos_sys::log_buffer::Subscription<Arc<LogBuffer>> {
        match self.link.take(key).unwrap().capability {
            Capability::Subscription(inner) => inner,
            other => panic!("not a subscription: {other:?}"),
        }
    }

    fn attach_of(&self, sequence: u64) -> Command {
        Command::AddImageSubscriptionOf {
            sequence,
            image: self.image,
            parent: self.parent,
            lane: Lane::ZERO,
        }
    }
}

type LogBuffer = karyos_sys::log_buffer::LogBuffer<karyos_sys::term_bytes::HeapTerms>;

/// The registration of the network subscription set up by request
/// `sequence`, once its readiness is among `responses`. A refusal of that
/// request fails at once with its code and detail, rather than waiting out
/// the setup's deadline (karyos#1221 review).
fn setup_answer(responses: &[Response], sequence: u64) -> Option<u64> {
    let mut ready = None;
    for response in responses {
        match response {
            Response::NetworkSubscriptionReady { registration, .. } => ready = Some(*registration),
            Response::Error {
                request,
                code,
                detail,
            } if request.sequence == sequence => {
                panic!("the network subscription was refused: {code:?}, detail {detail}")
            }
            _ => {}
        }
    }
    ready
}

#[test]
#[should_panic(expected = "the network subscription was refused")]
fn a_refused_setup_fails_at_once() {
    let refused = Response::Error {
        request: karyos_protocol::cnc::RequestId {
            client: 1,
            sequence: 1,
        },
        code: ErrorCode::UnknownRegistration,
        detail: 7,
    };
    let _ = setup_answer(&[refused], 1);
}

#[test]
fn another_requests_refusal_is_not_the_setups() {
    let refused = Response::Error {
        request: karyos_protocol::cnc::RequestId {
            client: 1,
            sequence: 2,
        },
        code: ErrorCode::UnknownRegistration,
        detail: 7,
    };
    assert_eq!(setup_answer(&[refused], 1), None);
}

fn key(responses: &[Response]) -> u64 {
    responses
        .iter()
        .find_map(|response| match response {
            Response::SubscriptionReady { key, .. } => Some(*key),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no SubscriptionReady in {responses:?}"))
}

fn first_message(
    subscription: &mut karyos_sys::log_buffer::Subscription<Arc<LogBuffer>>,
) -> Option<u64> {
    let mut out = [0u8; 2048];
    for _ in 0..100 {
        match subscription.poll(&mut out).unwrap() {
            PollOutcome::Message { position, .. } => return Some(position),
            _ => std::thread::sleep(Duration::from_micros(100)),
        }
    }
    None
}

/// An optional subscription that existed before the image reads the
/// message offered before its attach, from the image's join; no loss is
/// reported.
#[test]
fn an_awaiting_optional_subscription_reads_from_the_join() {
    let mut rig = Rig::new(SubscriberRole::Optional, 10_000_000_000);
    let early = rig.offer(b"early");
    let (responses, events) = rig.send(rig.attach_of(2));
    let mut subscription = rig.take(key(&responses));
    assert_eq!(first_message(&mut subscription), Some(early));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, Event::ImageJoinLoss { .. })),
        "{events:?}"
    );
}

/// A legacy attach joins at the head, as before ADR-0100, and withdraws
/// its client's awaiting cell of its role, so nothing is left waiting: the
/// message offered before the attach is not read.
#[test]
fn a_legacy_attach_joins_at_the_head_and_withdraws_its_cell() {
    let mut rig = Rig::new(SubscriberRole::Optional, 10_000_000_000);
    let _early = rig.offer(b"early");
    let (responses, _) = rig.send(Command::AddImageSubscription {
        sequence: 2,
        image: rig.image,
        lane: Lane::ZERO,
        role: SubscriberRole::Optional,
    });
    let mut subscription = rig.take(key(&responses));
    assert_eq!(first_message(&mut subscription), None);
    // The lane admits one optional reader by default: the legacy one leaves
    // first. Its cell is gone, so a later parent-aware attach joins at the
    // head too, and is told what it missed.
    drop(subscription);
    let (responses, events) = rig.send(rig.attach_of(3));
    let _late = rig.take(key(&responses));
    assert!(
        events.iter().any(
            |event| matches!(event, Event::ImageJoinLoss { parent, .. } if *parent == rig.parent)
        ),
        "{events:?}"
    );
}

/// A required awaiting cell ends at `image_join_deadline`: the later
/// attach joins at the head, and its `ImageJoinLoss` names the range from
/// the join to where it started, its committed cursor.
#[test]
fn an_expired_required_cell_joins_at_the_head_with_its_loss() {
    let mut rig = Rig::new(SubscriberRole::Required, 1);
    let early = rig.offer(b"early");
    let (responses, events) = rig.send(rig.attach_of(2));
    let mut subscription = rig.take(key(&responses));
    let started = subscription.position();
    let loss = events.iter().find_map(|event| match event {
        Event::ImageJoinLoss {
            parent, from, to, ..
        } if *parent == rig.parent => Some((*from, *to)),
        _ => None,
    });
    assert_eq!(loss, Some((early, started)), "{events:?}");
    assert!(started > early);
    assert_eq!(first_message(&mut subscription), None);
}

/// A parent that is not a live network subscription of the client, of
/// the image's key, is refused, and no cell is taken.
#[test]
fn an_attach_naming_another_parent_is_refused() {
    let mut rig = Rig::new(SubscriberRole::Optional, 10_000_000_000);
    let early = rig.offer(b"early");
    let (responses, _) = rig.send(Command::AddImageSubscriptionOf {
        sequence: 2,
        image: rig.image,
        parent: rig.parent + 1000,
        lane: Lane::ZERO,
    });
    assert!(
        responses.iter().any(|response| matches!(
            response,
            Response::Error {
                code: ErrorCode::UnknownRegistration,
                ..
            }
        )),
        "{responses:?}"
    );
    // The awaiting cell is still there for its own parent.
    let (responses, _) = rig.send(rig.attach_of(3));
    let mut subscription = rig.take(key(&responses));
    assert_eq!(first_message(&mut subscription), Some(early));
}

/// A required subscription that attaches before its deadline adopts its
/// awaiting cell and reads from the join, with no loss.
#[test]
fn an_awaiting_required_subscription_reads_from_the_join() {
    let mut rig = Rig::new(SubscriberRole::Required, 10_000_000_000);
    let early = rig.offer(b"early");
    let (responses, events) = rig.send(rig.attach_of(2));
    let mut subscription = rig.take(key(&responses));
    assert_eq!(first_message(&mut subscription), Some(early));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, Event::ImageJoinLoss { .. })),
        "{events:?}"
    );
}

/// A remote client's parent-aware attach is granted the awaiting cell
/// itself, under the export the cell was registered with at the build,
/// and the driver's export counter does not move back.
#[test]
fn a_remote_attach_is_granted_the_awaiting_cell() {
    let mut rig = Rig::with_client(SubscriberRole::Optional, 10_000_000_000, true);
    let _early = rig.offer(b"early");
    let before = rig.b.next_export;
    let (responses, _) = rig.send(rig.attach_of(2));
    assert!(
        responses
            .iter()
            .any(|response| matches!(response, Response::SubscriptionReady { .. })),
        "{responses:?}"
    );
    let client = rig
        .b
        .clients
        .iter()
        .find(|slot| slot.ledger.is_some())
        .map(|slot| slot.id())
        .unwrap();
    let grant = *rig.b.ledger(client).unwrap().grants().last().unwrap();
    assert!(grant.export < before, "the cell's export, from the build");
    assert!(rig.b.next_export >= before);
}

/// Review of #1175: a remote attach completes as a local one does. An
/// expired required cell's remote attach is granted at the head, and its
/// `ImageJoinLoss` is sent and counted.
#[test]
fn a_late_remote_attach_reports_its_loss() {
    let mut rig = Rig::with_client(SubscriberRole::Required, 1, true);
    let early = rig.offer(b"early");
    let (responses, events) = rig.send(rig.attach_of(2));
    assert!(
        responses
            .iter()
            .any(|response| matches!(response, Response::SubscriptionReady { .. })),
        "{responses:?}"
    );
    assert!(
        events.iter().any(|event| matches!(
            event,
            Event::ImageJoinLoss { parent, from, .. } if *parent == rig.parent && *from == early
        )),
        "{events:?}"
    );
}

/// Review of #1175: a remote grant refused after the awaiting cell was
/// found (a fetch the ledger's region bound cannot carry) leaves the cell on
/// its stream, still awaiting, for its expiry or its parent's removal.
#[test]
fn a_refused_remote_grant_leaves_the_cell_awaiting() {
    let mut rig = Rig::with_ledger(
        SubscriberRole::Required,
        10_000_000_000,
        Some(crate::ledger::Ledger::new(4, 0, 1 << 30)),
    );
    let _early = rig.offer(b"early");
    let awaiting = |rig: &Rig| {
        rig.b
            .streams
            .iter()
            .map(|stream| stream.awaiting.len())
            .sum::<usize>()
    };
    assert_eq!(awaiting(&rig), 1);
    let (responses, _) = rig.send(rig.attach_of(2));
    assert!(
        responses
            .iter()
            .any(|response| matches!(response, Response::Error { .. })),
        "{responses:?}"
    );
    assert_eq!(awaiting(&rig), 1, "the refused grant left the cell tracked");
}

/// karyos#1067: an in-process network subscription of the embedded API
/// that awaits its images (ADR-0100 decisions 1 to 4) reads an image from
/// its join, position 0, although the image received every message before
/// the attach; a second attach finds no cell and gets the typed error that
/// sends a caller to the head fallback (decision 6).
#[test]
fn an_embedded_awaiting_subscription_reads_from_the_join_what_came_before() {
    let mut a = driver(ThreadingMode::Shared);
    let mut b = EmbeddedDriver::with_config(DriverConfig {
        network: Some(NetworkConfig {
            threading: ThreadingMode::Shared,
            ..NetworkConfig::default()
        }),
        ..DriverConfig::default()
    })
    .unwrap();
    let address = SocketAddr::new(LOOPBACK, free_port());
    let subscription = b.add_network_subscription(10, &channel(address)).unwrap();
    b.await_network_images(subscription, Role::Required)
        .unwrap();
    let handle = a
        .add_network_publication(aggregate(10, 3, 1), &channel(address))
        .unwrap();
    let mut publication = a.publication(handle.lane(Lane::ZERO).unwrap()).unwrap();
    pump(&mut a, &mut b, |_, b| b.network_images(10).len() == 1);
    // Every message reaches the image before anything attaches.
    let payloads: [&[u8]; 3] = [b"first", b"second", b"third"];
    let mut positions = Vec::new();
    for payload in payloads {
        let mut at = None;
        pump(&mut a, &mut b, |_, _| {
            if at.is_none()
                && let Ok(OfferOutcome::Accepted { position, .. }) = publication.offer(payload)
            {
                at = Some(position);
            }
            at.is_some()
        });
        positions.push(at.unwrap());
    }
    for _ in 0..50 {
        let _ = (a.do_work().unwrap(), b.do_work().unwrap());
    }
    assert_eq!(positions[0], 0, "the publication starts at 0");
    let image = b.network_images(10)[0].0;
    let lane = image.lane(Lane::ZERO).unwrap();
    let mut reader = b.subscribe_image_of(subscription, lane).unwrap();
    let mut read = Vec::new();
    let start = std::time::Instant::now();
    while read.len() < payloads.len() {
        assert!(start.elapsed() < Duration::from_secs(30), "read {read:?}");
        let _ = (a.do_work().unwrap(), b.do_work().unwrap());
        let _ = reader.poll(
            |bytes, info| read.push((info.position, bytes.to_vec())),
            karyos_client::MessageLimit::new(8),
        );
    }
    assert_eq!(
        read,
        positions
            .iter()
            .zip(payloads)
            .map(|(position, payload)| (*position, payload.to_vec()))
            .collect::<Vec<_>>(),
        "every message, from the join"
    );
    assert!(matches!(
        b.subscribe_image_of(subscription, lane),
        Err(crate::error::DriverError::NoAwaitingCell)
    ));
    // A subscription that does not await its images has no cell either.
    let other = b
        .add_network_subscription(11, &channel(SocketAddr::new(LOOPBACK, free_port())))
        .unwrap();
    assert!(matches!(
        b.subscribe_image_of(other, lane),
        Err(crate::error::DriverError::NoAwaitingCell)
    ));
}
