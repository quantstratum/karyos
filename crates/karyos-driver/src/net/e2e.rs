// SPDX-License-Identifier: Apache-2.0

//! The end-to-end matrix of the network wiring (W4, ACS 15962): embedded
//! drivers in one process over loopback, one publishing (W2), the others
//! subscribing to its images (W3).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use karyos_client::OfferOutcome;
use karyos_client::aggregate::{AggregateSubscription, LaneEnd};
use karyos_protocol::channel::{Destination, Interface, Security, UdpConfig};
use karyos_protocol::lanes::drr::Budget;
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{LogBufferConfig, LossPolicy, PublicationMode, Role, SealReason};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;
use karyos_sys::term_bytes::HeapTerms;

use crate::agents::{AgentConfig, ThreadingMode};
use crate::embedded::{
    AggregateConfig, AggregateHandle, DriverConfig, EmbeddedDriver, StreamConfig, StreamTerms,
};
use crate::error::DriverError;
use crate::net::NetworkConfig;

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const MS: u64 = 1_000_000;

/// Agent settings that retire a silent image within 100 ms.
fn fast_agents() -> AgentConfig {
    AgentConfig {
        sm_interval: 5 * MS,
        image_liveness_timeout: 100 * MS,
        idle_image_timeout: 100 * MS,
        sender_heartbeat_interval: 20 * MS,
        ..AgentConfig::default()
    }
}

/// A driver with the default liveness: an image held at its window by a
/// stalled subscriber sees only stationary heartbeats, which keep it for
/// `idle_image_timeout`, so the fast settings would retire it under load.
fn driver(threading: ThreadingMode) -> EmbeddedDriver {
    driver_with(threading, AgentConfig::default())
}

/// A driver whose silent images retire within 100 ms.
fn fast_driver(threading: ThreadingMode) -> EmbeddedDriver {
    driver_with(threading, fast_agents())
}

fn driver_with(threading: ThreadingMode, agents: AgentConfig) -> EmbeddedDriver {
    EmbeddedDriver::with_config(DriverConfig {
        network: Some(NetworkConfig {
            threading,
            agents,
            ..NetworkConfig::default()
        }),
        ..DriverConfig::default()
    })
    .unwrap()
}

fn aggregate(stream_id: i32, session_id: i32, lanes: usize) -> AggregateConfig {
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
                session_id,
                stream_id,
                claim_deadline: 100,
                publication: PublicationMode::Exclusive,
                schedule_capacity: 0,
            },
            allow_unconnected: true,
            on_required_loss: LossPolicy::Hold,
            conflation: None,
        },
        quanta: vec![u64::from(DEFAULT_MTU) * 4; lanes],
    }
}

fn channel(address: SocketAddr, reliable: bool) -> UdpConfig {
    UdpConfig {
        destination: Destination::Unicast(address),
        interface: Some(Interface::Address(LOOPBACK)),
        paths: Vec::new(),
        reliable,
        flow_control: None,
        security: Security::Trusted,
    }
}

/// A loopback address for a subscription to bind on any port: the kernel
/// picks it at the bind, and [`bound`] reads it back, so no other process
/// can take it in between.
const ANY_PORT: SocketAddr = SocketAddr::new(LOOPBACK, 0);

/// The address `driver`'s network subscription of `stream_id` is bound
/// to.
fn bound<T: StreamTerms>(driver: &EmbeddedDriver<T>, stream_id: i32) -> SocketAddr {
    driver.network_subscription_address(stream_id).unwrap()
}

/// A loopback socket nobody reads, for a publication with no receiver to
/// send to: held while the test runs, so no other process takes its port.
fn silent() -> UdpSocket {
    UdpSocket::bind(SocketAddr::new(LOOPBACK, 0)).unwrap()
}

/// A port for a multicast group or a destination: it is named before any
/// bind, so it cannot be read back from one. Picked outside the ephemeral
/// range (karyos#520, [`crate::test_ports`]).
fn free_port() -> u16 {
    crate::test_ports::test_port()
}

/// Runs every driver until `done`, at most about four seconds.
fn pump<T: StreamTerms>(
    drivers: &mut [&mut EmbeddedDriver<T>],
    mut done: impl FnMut(&mut [&mut EmbeddedDriver<T>]) -> bool,
) {
    for _ in 0..40_000 {
        for driver in drivers.iter_mut() {
            let _ = driver.do_work().unwrap();
        }
        if done(drivers) {
            return;
        }
        std::thread::sleep(Duration::from_micros(100));
    }
    let counters: Vec<String> = drivers
        .iter()
        .map(|driver| driver.net.as_ref().unwrap().agent_counters())
        .collect();
    panic!("not reached: {counters:?}");
}

const BUDGET: Budget = Budget {
    work: 256,
    bytes: 1 << 22,
};

/// A publication on `a` and B's subscription of it, with B's image found.
fn connected<T: StreamTerms>(
    a: &mut EmbeddedDriver<T>,
    b: &mut EmbeddedDriver<T>,
    reliable: bool,
    stream_id: i32,
) -> (AggregateHandle, AggregateHandle) {
    let _ = b
        .add_network_subscription(stream_id, &channel(ANY_PORT, reliable))
        .unwrap();
    let address = bound(b, stream_id);
    let publication = a
        .add_network_publication(aggregate(stream_id, 3, 1), &channel(address, reliable))
        .unwrap();
    let mut image = None;
    pump(&mut [a, b], |drivers| {
        image = drivers[1].network_image(stream_id, 3);
        image.is_some()
    });
    (publication, image.unwrap())
}

/// [`connected`] over a reliable channel whose receiver, B, is required
/// (receiver 77): its consumption bounds the sender's registered position
/// (SPEC.md §4, "Sender position"), where an optional one no longer does
/// (quantstratum-docs: karyos/design/retention-floor-optional-receivers.md).
fn connected_required<T: StreamTerms>(
    a: &mut EmbeddedDriver<T>,
    b: &mut EmbeddedDriver<T>,
    stream_id: i32,
) -> (AggregateHandle, AggregateHandle) {
    use crate::membership::{PublicationRoles, ReceiverIdentity, Strategy};

    let identity = ReceiverIdentity {
        receiver_id: core::num::NonZeroU64::new(77).unwrap(),
        group_tag: 0,
    };
    let _ = b
        .add_network_subscription_as(stream_id, &channel(ANY_PORT, true), identity)
        .unwrap();
    let address = bound(b, stream_id);
    let publication = a
        .add_network_publication_with_roles(
            aggregate(stream_id, 3, 1),
            &channel(address, true),
            PublicationRoles {
                strategy: Strategy::Min,
                required: vec![77],
                tags: Vec::new(),
            },
        )
        .unwrap();
    let mut image = None;
    pump(&mut [a, b], |drivers| {
        image = drivers[1].network_image(stream_id, 3);
        image.is_some()
    });
    (publication, image.unwrap())
}

/// Offers `count` numbered messages on lane 0 of `publication` while
/// reading `reader` on `b`, until every one arrived in order.
fn exchange<T: StreamTerms>(
    a: &mut EmbeddedDriver<T>,
    b: &mut EmbeddedDriver<T>,
    publication: &AggregateHandle,
    reader: &mut AggregateSubscription<T>,
    count: u32,
) {
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    exchange_on(a, b, &mut lane, reader, 0..count);
}

/// [`exchange`] of the messages numbered `range` on `lane`.
fn exchange_on<T: StreamTerms>(
    a: &mut EmbeddedDriver<T>,
    b: &mut EmbeddedDriver<T>,
    lane: &mut karyos_client::ClientPublication<T>,
    reader: &mut AggregateSubscription<T>,
    range: core::ops::Range<u32>,
) {
    exchange_from(a, b, lane, reader, range.start, range);
}

/// [`exchange_on`] whose messages from `range.start` up to `sent` were
/// already offered.
fn exchange_from<T: StreamTerms>(
    a: &mut EmbeddedDriver<T>,
    b: &mut EmbeddedDriver<T>,
    lane: &mut karyos_client::ClientPublication<T>,
    reader: &mut AggregateSubscription<T>,
    sent: u32,
    range: core::ops::Range<u32>,
) {
    let count = range.end;
    let (mut sent, mut seen) = (sent, range.start);
    pump(&mut [a, b], |_| {
        while sent < count {
            let mut payload = [0u8; 1000];
            payload[..4].copy_from_slice(&sent.to_le_bytes());
            match lane.offer(&payload).unwrap() {
                OfferOutcome::Accepted { .. } => sent += 1,
                _ => break,
            }
        }
        let _ = reader.poll(
            |bytes, _, _| {
                let index = u32::from_le_bytes(bytes[..4].try_into().unwrap());
                assert_eq!(index, seen, "in order, exactly once");
                seen += 1;
            },
            BUDGET,
        );
        seen == count
    });
}

/// E1: reliable and unreliable channels both deliver in order across terms,
/// in every threading mode.
#[test]
fn both_channel_kinds_deliver_across_terms() {
    for mode in [ThreadingMode::Shared, ThreadingMode::Dedicated] {
        for reliable in [true, false] {
            let (mut a, mut b) = (driver(mode), driver(mode));
            let (publication, image) = connected(&mut a, &mut b, reliable, 10);
            let mut reader = b.subscribe_aggregate(&image, Role::Required).unwrap();
            exchange(&mut a, &mut b, &publication, &mut reader, 256);
        }
    }
}

/// E1, SPEC §6 flow control: on either channel kind the sender is bound by
/// the receiver's window, so a stalled required subscriber of the image
/// holds the publisher; once it reads, the publisher goes on. Reliability
/// changes recovery (NAKs), not the window.
#[test]
fn a_stalled_receiver_holds_either_channel_at_its_window() {
    for reliable in [true, false] {
        let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
        let (publication, image) = connected(&mut a, &mut b, reliable, 10);
        let mut reader = b.subscribe_aggregate(&image, Role::Required).unwrap();
        let mut lane = a
            .publication(publication.lane(Lane::ZERO).unwrap())
            .unwrap();
        let offer = |lane: &mut karyos_client::ClientPublication<HeapTerms>| {
            matches!(
                lane.offer(&[7u8; 1000]).unwrap(),
                OfferOutcome::Accepted { .. }
            )
        };
        let mut accepted = 0u32;
        let mut pressed = false;
        for _ in 0..4000 {
            if offer(&mut lane) {
                accepted += 1;
            } else {
                pressed = true;
            }
            let _ = a.do_work().unwrap();
            let _ = b.do_work().unwrap();
        }
        assert!(
            pressed,
            "reliable {reliable}: never held ({accepted} accepted)"
        );
        assert!(
            accepted < 1024,
            "reliable {reliable}: {accepted} accepted while stalled"
        );
        // The subscriber reads: the window reopens and the publisher goes on.
        let held = accepted;
        pump(&mut [&mut a, &mut b], |_| {
            let _ = reader.poll(|_, _, _| {}, BUDGET);
            if offer(&mut lane) {
                accepted += 1;
            }
            accepted > held + 256
        });
    }
}

/// E4: a publication that goes silent retires its image at liveness; the
/// reader sees the image's seal, and the image is reclaimed once it drops.
/// Its driver's network stops, which sends no EOS and lingers for nothing
/// (driver-network-agents.md §7); a removal would end it at its EOS.
#[test]
fn a_silent_publication_retires_its_image_at_liveness() {
    let (mut a, mut b) = (
        fast_driver(ThreadingMode::Shared),
        fast_driver(ThreadingMode::Shared),
    );
    let (_publication, image) = connected(&mut a, &mut b, true, 10);
    let mut reader = b.subscribe_aggregate(&image, Role::Optional).unwrap();
    let _ = a.close_network();
    let mut end = None;
    pump(&mut [&mut a, &mut b], |_| {
        let poll = reader.poll(|_, _, _| {}, BUDGET);
        end = poll.lanes.first().and_then(|lane| lane.end);
        end.is_some()
    });
    assert!(
        matches!(
            end,
            Some(LaneEnd::Closed {
                reason: SealReason::ImageRetired,
                ..
            })
        ),
        "{end:?}"
    );
    drop(reader);
    pump(&mut [&mut a, &mut b], |drivers| {
        drivers[1].net.as_ref().unwrap().image_count() == 0
    });
}

/// E4: closing a subscriber's network with an image installed is clean,
/// and a receiver panic on one driver leaves the other unaffected (DN-9).
#[test]
fn closing_and_failing_one_side_leaves_the_other_clean() {
    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let _ = connected(&mut a, &mut b, true, 10);
    let shutdown = b.close_network().unwrap();
    assert!(shutdown.agents_stopped);
    assert!(shutdown.failures.is_empty() && shutdown.late.is_empty());
    assert!(shutdown.endpoints_retired >= 1);
    for _ in 0..100 {
        let _ = a.do_work().unwrap();
    }
    let mut c = driver(ThreadingMode::Shared);
    let _ = connected(&mut a, &mut c, true, 11);
    c.net
        .as_ref()
        .unwrap()
        .links()
        .receiver
        .post(|_reply| crate::agents::AgentCommand::Panic)
        .unwrap();
    assert!(c.do_work().is_err());
    for _ in 0..100 {
        let _ = a.do_work().unwrap();
    }
    // A still serves: a fresh subscriber of a new publication reads it.
    let mut d = driver(ThreadingMode::Shared);
    let (publication, image) = connected(&mut a, &mut d, true, 12);
    let mut reader = d.subscribe_aggregate(&image, Role::Required).unwrap();
    exchange(&mut a, &mut d, &publication, &mut reader, 32);
}

/// The value of each allocated cell labelled `label`, with its keys.
fn cells<T: StreamTerms>(
    driver: &EmbeddedDriver<T>,
    label: &str,
) -> Vec<(u64, karyos_sys::counters::CounterKeys)> {
    let reader = driver.counters();
    (0..reader.capacity())
        .filter_map(|index| match reader.read(index) {
            karyos_sys::counters::CellRead::Allocated {
                metadata, value, ..
            } if metadata.label() == label.as_bytes() => Some((value, metadata.keys)),
            _ => None,
        })
        .collect()
}

/// M2 (`quantstratum-docs: karyos/design/management-agent-gap-analysis.md`):
/// the agents' system counters reach the CnC in every threading mode, as
/// driver-wide cells (keys zero) that only the agent writes. The
/// publisher's sender counts the receiver's SMs, the receiver counts the
/// datagrams and sends SMs, and a cell only grows. Closing the network
/// frees every cell.
#[test]
fn the_agents_counters_reach_the_cnc_in_every_mode() {
    let labels = crate::agents::SENDER_CELLS
        .iter()
        .chain(&crate::agents::RECEIVER_CELLS);
    for mode in [
        ThreadingMode::Shared,
        ThreadingMode::Dedicated,
        ThreadingMode::SharedNetwork,
    ] {
        let (mut a, mut b) = (driver(mode), driver(mode));
        for label in labels.clone() {
            let found = cells(&a, label);
            assert_eq!(found.len(), 1, "{mode:?}: {label}");
            assert_eq!(found[0].1, karyos_sys::counters::CounterKeys::DRIVER);
        }
        let (publication, image) = connected(&mut a, &mut b, true, 10);
        let mut reader = b.subscribe_aggregate(&image, Role::Required).unwrap();
        let mut lane = a
            .publication(publication.lane(Lane::ZERO).unwrap())
            .unwrap();
        exchange_on(&mut a, &mut b, &mut lane, &mut reader, 0..64);
        let value = |driver: &EmbeddedDriver, label| cells(driver, label)[0].0;
        // Threads publish at the end of their cycle: wait for the counts.
        pump(&mut [&mut a, &mut b], |drivers| {
            value(drivers[1], "datagrams received") >= 64
                && value(drivers[1], "status messages sent") > 0
                && value(drivers[0], "status messages received") > 0
        });
        let received = value(&b, "datagrams received");
        exchange_on(&mut a, &mut b, &mut lane, &mut reader, 64..96);
        pump(&mut [&mut a, &mut b], |drivers| {
            value(drivers[1], "datagrams received") >= received + 32
        });
        assert_eq!(value(&b, "invalid frames received"), 0, "{mode:?}");
        for driver in [&mut a, &mut b] {
            let shutdown = driver.close_network().unwrap();
            assert!(shutdown.late.is_empty(), "{mode:?}");
            for label in labels.clone() {
                assert!(cells(driver, label).is_empty(), "{mode:?}: {label} kept");
            }
        }
    }
}

/// M2b (`quantstratum-docs: karyos/design/management-agent-gap-analysis.md`):
/// a network publication's and an image's counts reach the CnC in every
/// threading mode, as cells keyed by their stream's registration that
/// only their agent writes; the publication's are freed when it is
/// removed, the image's when it retires, and none is left at the close.
#[test]
fn per_stream_network_counters_reach_the_cnc_in_every_mode() {
    use crate::agents::{IMAGE_CELLS, PUBLICATION_CELLS};
    let keyed = |driver: &EmbeddedDriver, label: &str, stream: u64| {
        cells(driver, label)
            .into_iter()
            .filter(|(_, keys)| keys.stream == stream)
            .map(|(value, _)| value)
            .collect::<Vec<_>>()
    };
    for mode in [
        ThreadingMode::Shared,
        ThreadingMode::Dedicated,
        ThreadingMode::SharedNetwork,
    ] {
        // A short linger, so the removal ends soon.
        let quick = || {
            EmbeddedDriver::with_config(DriverConfig {
                network: Some(NetworkConfig {
                    threading: mode,
                    agents: fast_agents(),
                    stream_defaults: crate::net::NetworkStreamDefaults {
                        publication_linger: 20 * MS,
                        ..crate::net::NetworkStreamDefaults::default()
                    },
                    ..NetworkConfig::default()
                }),
                ..DriverConfig::default()
            })
            .unwrap()
        };
        let (mut a, mut b) = (quick(), quick());
        let (publication, image) = connected(&mut a, &mut b, true, 10);
        let (sent, seen) = (publication.registration(), image.registration());
        for label in PUBLICATION_CELLS {
            assert_eq!(keyed(&a, label, sent).len(), 1, "{mode:?}: {label}");
        }
        for label in IMAGE_CELLS {
            assert_eq!(keyed(&b, label, seen).len(), 1, "{mode:?}: {label}");
        }
        let mut reader = b.subscribe_aggregate(&image, Role::Required).unwrap();
        let mut lane = a
            .publication(publication.lane(Lane::ZERO).unwrap())
            .unwrap();
        exchange_on(&mut a, &mut b, &mut lane, &mut reader, 0..64);
        // The sender stores at the end of its cycle: wait for the counts.
        pump(&mut [&mut a, &mut b], |drivers| {
            keyed(drivers[0], "network frames sent", sent)[0] >= 64
                && keyed(drivers[0], "network bytes sent", sent)[0] >= 64 * 4
        });
        // Nothing was lost on the loopback: nothing to repair.
        assert_eq!(keyed(&a, "network retransmits", sent), [0], "{mode:?}");
        // The removal frees the publication's cells, and the image retires
        // with its EOS, freeing its own.
        drop(lane);
        drop(reader);
        a.remove_aggregate(&publication).unwrap();
        pump(&mut [&mut a, &mut b], |drivers| {
            keyed(drivers[0], "network frames sent", sent).is_empty()
                && keyed(drivers[1], "network losses", seen).is_empty()
        });
        for label in PUBLICATION_CELLS.iter().chain(&IMAGE_CELLS) {
            assert!(keyed(&a, label, sent).is_empty(), "{mode:?}: {label}");
            assert!(keyed(&b, label, seen).is_empty(), "{mode:?}: {label}");
        }
        for driver in [&mut a, &mut b] {
            let shutdown = driver.close_network().unwrap();
            assert!(shutdown.late.is_empty(), "{mode:?}");
        }
    }
}

/// M2b: the cells of a publication and an image still held at the close
/// come back with the agents and are freed.
#[test]
fn the_close_frees_the_stream_cells_still_held() {
    use crate::agents::{IMAGE_CELLS, PUBLICATION_CELLS};
    for mode in [ThreadingMode::Shared, ThreadingMode::Dedicated] {
        let (mut a, mut b) = (driver(mode), driver(mode));
        let (publication, image) = connected(&mut a, &mut b, true, 10);
        // Traffic, so the receiver has taken its image's cells.
        let mut reader = b.subscribe_aggregate(&image, Role::Required).unwrap();
        exchange(&mut a, &mut b, &publication, &mut reader, 8);
        drop(reader);
        for driver in [&mut a, &mut b] {
            let shutdown = driver.close_network().unwrap();
            assert!(shutdown.late.is_empty(), "{mode:?}");
            for label in PUBLICATION_CELLS.iter().chain(&IMAGE_CELLS) {
                assert!(cells(driver, label).is_empty(), "{mode:?}: {label} kept");
            }
        }
    }
}

/// M3 (`quantstratum-docs: karyos/design/management-agent-gap-analysis.md`,
/// SPEC §16.8): each network endpoint's effective capabilities reach the
/// CnC as gauges keyed by participant kind endpoint and its instance id,
/// and closing the network frees them.
#[test]
fn endpoint_capabilities_reach_the_cnc() {
    use karyos_sys::counters::{CellRead, KIND_ENDPOINT};
    let endpoint_cells = |driver: &EmbeddedDriver| {
        let reader = driver.counters();
        (0..reader.capacity())
            .filter_map(|index| match reader.read(index) {
                CellRead::Allocated {
                    metadata, value, ..
                } if metadata.keys.kind == KIND_ENDPOINT => Some((
                    metadata.keys.participant,
                    String::from_utf8(metadata.label().to_vec()).unwrap(),
                    value,
                )),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let _ = connected(&mut a, &mut b, true, 10);
    for driver in [&mut a, &mut b] {
        let cells = endpoint_cells(driver);
        assert!(!cells.is_empty());
        let value = |label: &str| {
            cells
                .iter()
                .find(|(_, name, _)| name == label)
                .map(|(_, _, value)| *value)
                .unwrap()
        };
        assert_ne!(cells[0].0, 0, "keyed by the endpoint's instance");
        assert_eq!(value("capability epoch"), 1);
        // Written in one pass: the pass cell is even, one pass done (M6b).
        assert_eq!(value("capability pass"), 2);
        let platform = if cfg!(target_os = "linux") { 1 } else { 2 };
        assert_eq!(value("capability platform"), platform);
        // The baseline observes receives in user space, actively.
        assert_eq!(value("capability user observations"), 1);
        // No UDP segmentation offload in the baseline: unavailable for
        // lack of a library API, reported but not counted as missing.
        assert_eq!(value("capability gso"), 3 | 3 << 8);
        let _ = driver.close_network().unwrap();
        assert!(endpoint_cells(driver).is_empty());
    }
}

/// M5 (`crate::spin`): each agent idle loop has its type-3 spin cell for
/// its threading mode, and the default `YieldThenSleep`, which never
/// spins, reports 0 through traffic. Shared mode's loop is the
/// conductor's, so its agents have none.
#[test]
fn yield_then_sleep_agents_report_no_spin_time() {
    let spin_cells = |driver: &EmbeddedDriver| {
        let reader = driver.counters();
        let mut cells: Vec<(String, u64)> = (0..reader.capacity())
            .filter_map(|index| match reader.read(index) {
                karyos_sys::counters::CellRead::Allocated {
                    metadata, value, ..
                } if metadata.type_id == crate::counters::TYPE_SPIN_TIME => {
                    Some((String::from_utf8(metadata.label().to_vec()).unwrap(), value))
                }
                _ => None,
            })
            .collect();
        cells.sort();
        cells
    };
    for (mode, labels) in [
        (ThreadingMode::Shared, &["conductor spin time"][..]),
        (
            ThreadingMode::Dedicated,
            &[
                "conductor spin time",
                "receiver spin time",
                "sender spin time",
            ][..],
        ),
        (
            ThreadingMode::SharedNetwork,
            &["conductor spin time", "network spin time"][..],
        ),
    ] {
        let (mut a, mut b) = (driver(mode), driver(mode));
        let (publication, image) = connected(&mut a, &mut b, true, 10);
        let mut reader = b.subscribe_aggregate(&image, Role::Required).unwrap();
        exchange(&mut a, &mut b, &publication, &mut reader, 64);
        for driver in [&a, &b] {
            let cells = spin_cells(driver);
            let names: Vec<&str> = cells.iter().map(|(name, _)| name.as_str()).collect();
            assert_eq!(names, labels, "{mode:?}");
            assert!(
                cells.iter().all(|(_, value)| *value == 0),
                "{mode:?}: {cells:?}"
            );
        }
    }
}

/// E5: in steady state, a network cycle on either side allocates nothing.
#[test]
fn a_steady_network_cycle_allocates_nothing() {
    use karyos_sys::alloc_count::count;

    let ((), made) = count(|| drop(std::hint::black_box(vec![0_u8; 8])));
    assert!(made > 0, "the counting allocator counts in this binary");
    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let (publication, image) = connected(&mut a, &mut b, true, 10);
    let mut reader = b.subscribe_aggregate(&image, Role::Required).unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    // Warm up: every buffer the path keeps is sized by real traffic.
    exchange_on(&mut a, &mut b, &mut lane, &mut reader, 0..128);
    // Then traffic keeps flowing while only the network cycles are counted:
    // the client's offers and polls, and the streams' duty, stay outside.
    let (mut sent, mut seen, mut work) = (128u32, 128u32, [0u64; 2]);
    for _ in 0..2_000 {
        while sent < 384 {
            let mut payload = [0u8; 1000];
            payload[..4].copy_from_slice(&sent.to_le_bytes());
            match lane.offer(&payload).unwrap() {
                OfferOutcome::Accepted { .. } => sent += 1,
                _ => break,
            }
        }
        for (side, driver) in [&mut a, &mut b].into_iter().enumerate() {
            let ((units, error), made) = count(|| driver.serve_network());
            assert!(error.is_none());
            assert_eq!(made, 0, "side {side}: {units} units allocated");
            work[side] += u64::from(units);
        }
        let _ = (a.do_work().unwrap(), b.do_work().unwrap());
        let _ = reader.poll(|_, _, _| seen += 1, BUDGET);
        if seen == 384 {
            break;
        }
        std::thread::sleep(Duration::from_micros(50));
    }
    assert_eq!(seen, 384);
    assert!(
        work[0] > 0 && work[1] > 0,
        "counted cycles did work: {work:?}"
    );
}

/// E2: a send fault that needs an endpoint reset, end to end: the sender
/// requests it (#270), the endpoint table resets and reopens the endpoint,
/// the reliable lane resends from its registered position, and the
/// subscriber gets every message exactly once, in order.
#[test]
fn an_endpoint_reset_loses_nothing_on_a_reliable_channel() {
    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let (publication, image) = connected(&mut a, &mut b, true, 10);
    let mut reader = b.subscribe_aggregate(&image, Role::Required).unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    exchange_on(&mut a, &mut b, &mut lane, &mut reader, 0..64);
    // The subscriber holds: its consumption, and so the sender's
    // registered position, stays at 64 while 16 more are sent and
    // committed.
    let committed =
        |driver: &EmbeddedDriver| driver.net.as_ref().unwrap().receiver_counters().unwrap();
    let before = committed(&b).data_committed;
    let mut sent = 64u32;
    pump(&mut [&mut a, &mut b], |drivers| {
        while sent < 80 {
            let mut payload = [0u8; 1000];
            payload[..4].copy_from_slice(&sent.to_le_bytes());
            match lane.offer(&payload).unwrap() {
                OfferOutcome::Accepted { .. } => sent += 1,
                _ => break,
            }
        }
        committed(drivers[1]).data_committed >= before + 16
    });
    let dropped = committed(&b).data_dropped;
    let (endpoint, alias) = a
        .net
        .as_ref()
        .unwrap()
        .publication_route(publication.registration())
        .unwrap();
    a.net
        .as_ref()
        .unwrap()
        .links()
        .sender
        .post(|_reply| crate::agents::AgentCommand::ForceReset { endpoint, alias })
        .unwrap();
    // The reset reopens the endpoint and the reliable lane rewinds to its
    // registered position: what it already sent arrives again, and the
    // receiver drops those copies as duplicates.
    pump(&mut [&mut a, &mut b], |drivers| {
        drivers[0].net.as_ref().unwrap().reopened() >= 1
            && committed(drivers[1]).data_dropped > dropped
    });
    // The subscriber still reads every message exactly once, in order, and
    // traffic after the reset flows.
    exchange_from(&mut a, &mut b, &mut lane, &mut reader, sent, 64..320);
}

/// E2: a send fault that needs an endpoint reset, end to end: the sender
/// requests it (#270), the endpoint table resets and reopens the endpoint,
/// the reliable lane resends from its registered position, and the
/// subscriber gets every message exactly once, in order, with the
/// receiver required: its consumption also holds the registered position
/// (SPEC.md §4, "Sender position").
#[test]
fn an_endpoint_reset_loses_nothing_with_a_required_receiver() {
    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let (publication, image) = connected_required(&mut a, &mut b, 10);
    let mut reader = b.subscribe_aggregate(&image, Role::Required).unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    exchange_on(&mut a, &mut b, &mut lane, &mut reader, 0..64);
    // The subscriber holds: its consumption, and so the required
    // receiver's retention and the sender's registered position, stays at
    // 64 while 16 more are sent and committed.
    let committed =
        |driver: &EmbeddedDriver| driver.net.as_ref().unwrap().receiver_counters().unwrap();
    let before = committed(&b).data_committed;
    let mut sent = 64u32;
    pump(&mut [&mut a, &mut b], |drivers| {
        while sent < 80 {
            let mut payload = [0u8; 1000];
            payload[..4].copy_from_slice(&sent.to_le_bytes());
            match lane.offer(&payload).unwrap() {
                OfferOutcome::Accepted { .. } => sent += 1,
                _ => break,
            }
        }
        committed(drivers[1]).data_committed >= before + 16
    });
    let dropped = committed(&b).data_dropped;
    let (endpoint, alias) = a
        .net
        .as_ref()
        .unwrap()
        .publication_route(publication.registration())
        .unwrap();
    a.net
        .as_ref()
        .unwrap()
        .links()
        .sender
        .post(|_reply| crate::agents::AgentCommand::ForceReset { endpoint, alias })
        .unwrap();
    // The reset reopens the endpoint and the reliable lane rewinds to its
    // registered position: what it already sent arrives again, and the
    // receiver drops those copies as duplicates.
    pump(&mut [&mut a, &mut b], |drivers| {
        drivers[0].net.as_ref().unwrap().reopened() >= 1
            && committed(drivers[1]).data_dropped > dropped
    });
    // The subscriber still reads every message exactly once, in order, and
    // traffic after the reset flows.
    exchange_from(&mut a, &mut b, &mut lane, &mut reader, sent, 64..320);
}

/// E3, Linux: one multicast publication reaches two subscribing drivers
/// on one group, each through its own image. Both sides use the default
/// interface, so the group's route decides; where the host has no
/// multicast route or cannot join (a minimal container network), the test
/// is skipped, and says so on the process's stderr, which the harness does
/// not capture, so the gate output shows it.
#[cfg(target_os = "linux")]
#[test]
fn a_multicast_publication_reaches_every_subscriber() {
    use std::io::Write as _;

    let skip = |why: &str| {
        let _ = writeln!(
            std::io::stderr(),
            "SKIPPED a_multicast_publication_reaches_every_subscriber: {why}"
        );
    };
    // Probe the host with plain sockets first: only a host that cannot
    // carry loopback multicast skips; after a good probe, any driver
    // failure fails the test.
    if let Err(why) = multicast_probe() {
        skip(&why);
        return;
    }
    let port = free_port();
    let group = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 255, 0, 1)), port);
    let channel = UdpConfig {
        destination: Destination::Multicast { group, ttl: None },
        interface: None,
        paths: Vec::new(),
        reliable: true,
        flow_control: None,
        security: Security::Trusted,
    };
    let (mut a, mut b, mut c) = (
        driver(ThreadingMode::Shared),
        driver(ThreadingMode::Shared),
        driver(ThreadingMode::Shared),
    );
    for subscriber in [&mut b, &mut c] {
        let _ = subscriber.add_network_subscription(10, &channel).unwrap();
    }
    let publication = a
        .add_network_publication(aggregate(10, 3, 1), &channel)
        .unwrap();
    let mut images = (None, None);
    pump(&mut [&mut a, &mut b, &mut c], |drivers| {
        images = (
            drivers[1].network_image(10, 3),
            drivers[2].network_image(10, 3),
        );
        images.0.is_some() && images.1.is_some()
    });
    let (Some(first), Some(second)) = images else {
        unreachable!("pumped until both exist");
    };
    let mut readers = [
        b.subscribe_aggregate(&first, Role::Required).unwrap(),
        c.subscribe_aggregate(&second, Role::Required).unwrap(),
    ];
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    let (mut sent, mut seen) = (0u32, [0u32; 2]);
    pump(&mut [&mut a, &mut b, &mut c], |_| {
        while sent < 128 {
            let mut payload = [0u8; 1000];
            payload[..4].copy_from_slice(&sent.to_le_bytes());
            match lane.offer(&payload).unwrap() {
                OfferOutcome::Accepted { .. } => sent += 1,
                _ => break,
            }
        }
        for (reader, seen) in readers.iter_mut().zip(seen.iter_mut()) {
            let _ = reader.poll(
                |bytes, _, _| {
                    let index = u32::from_le_bytes(bytes[..4].try_into().unwrap());
                    assert_eq!(index, *seen, "in order, exactly once");
                    *seen += 1;
                },
                BUDGET,
            );
        }
        seen == [128, 128]
    });
}

/// SPEC §13 phase 2, alias collision, on one multicast group: two
/// publisher drivers use the same `session_id` and stream on one group.
/// The subscribing driver's receiver keeps two images, keyed by source
/// endpoint, and commits each source's frames into its own image: every
/// frame of both publishers commits and none is refused. Both images are
/// exposed, each with its own source (`quantstratum-docs:
/// karyos/design/per-source-images.md`, D2-1), and each delivers only its
/// own publisher's messages, every one, in order: nothing of the other
/// publisher crosses into it. Linux, after the loopback multicast probe,
/// like `a_multicast_publication_reaches_every_subscriber`.
#[cfg(target_os = "linux")]
#[test]
fn colliding_aliases_on_one_multicast_group_keep_two_images_apart() {
    use std::io::Write as _;

    if let Err(why) = multicast_probe() {
        let _ = writeln!(
            std::io::stderr(),
            "SKIPPED colliding_aliases_on_one_multicast_group_keep_two_images_apart: {why}"
        );
        return;
    }
    let group = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 255, 0, 5)), free_port());
    let channel = UdpConfig {
        destination: Destination::Multicast { group, ttl: None },
        interface: None,
        paths: Vec::new(),
        reliable: true,
        flow_control: None,
        security: Security::Trusted,
    };
    let (mut a1, mut a2, mut b) = (
        driver(ThreadingMode::Shared),
        driver(ThreadingMode::Shared),
        driver(ThreadingMode::Shared),
    );
    let _ = b.add_network_subscription(10, &channel).unwrap();
    // The same stream and session on both: one alias, two sources.
    let publications = [
        a1.add_network_publication(aggregate(10, 3, 1), &channel)
            .unwrap(),
        a2.add_network_publication(aggregate(10, 3, 1), &channel)
            .unwrap(),
    ];
    // Two images installed, both exposed, from two sources.
    pump(&mut [&mut a1, &mut a2, &mut b], |drivers| {
        drivers[2].network_images(10).len() == 2
    });
    assert_eq!(b.network_images_unexposed(), 0);
    let images = b.network_images(10);
    assert_ne!(images[0].1, images[1].1, "two sources");
    let mut readers = [images[0].0, images[1].0]
        .map(|image| b.subscribe_aggregate(&image, Role::Required).unwrap());
    let mut lanes = [
        a1.publication(publications[0].lane(Lane::ZERO).unwrap())
            .unwrap(),
        a2.publication(publications[1].lane(Lane::ZERO).unwrap())
            .unwrap(),
    ];
    // Publisher p's message i is tagged (p, i).
    let count = 64u32;
    let mut sent = [0u32; 2];
    let mut seen: [Vec<(u8, u32)>; 2] = [Vec::new(), Vec::new()];
    let mut offer = |lanes: &mut [karyos_client::ClientPublication<HeapTerms>; 2]| {
        for (publisher, lane) in lanes.iter_mut().enumerate() {
            while sent[publisher] < count {
                let mut payload = [0u8; 1000];
                payload[0] = u8::try_from(publisher + 1).unwrap();
                payload[1..5].copy_from_slice(&sent[publisher].to_le_bytes());
                match lane.offer(&payload).unwrap() {
                    OfferOutcome::Accepted { .. } => sent[publisher] += 1,
                    _ => break,
                }
            }
        }
        sent
    };
    let read = |readers: &mut [AggregateSubscription<HeapTerms>; 2],
                seen: &mut [Vec<(u8, u32)>; 2]| {
        for (image, reader) in readers.iter_mut().enumerate() {
            let _ = reader.poll(
                |bytes, _, _| {
                    let index = u32::from_le_bytes(bytes[1..5].try_into().unwrap());
                    seen[image].push((bytes[0], index));
                },
                BUDGET,
            );
        }
    };
    pump(&mut [&mut a1, &mut a2, &mut b], |drivers| {
        let sent = offer(&mut lanes);
        read(&mut readers, &mut seen);
        // Every frame of both publishers is committed, each into its own
        // image (1000-byte messages are one frame each).
        let committed = drivers[2]
            .net
            .as_ref()
            .unwrap()
            .receiver_counters()
            .unwrap()
            .data_committed;
        sent == [count, count]
            && seen.iter().all(|seen| seen.len() >= 64)
            && committed >= 2 * u64::from(count)
    });
    // A while more: nothing else reaches either image.
    for _ in 0..200 {
        let _ = a1.do_work().unwrap();
        let _ = a2.do_work().unwrap();
        let _ = b.do_work().unwrap();
        read(&mut readers, &mut seen);
    }
    let owners = [seen[0][0].0, seen[1][0].0];
    assert_ne!(owners[0], owners[1], "one publisher per image");
    for (image, seen) in seen.iter().enumerate() {
        let expected: Vec<(u8, u32)> = (0..count).map(|i| (owners[image], i)).collect();
        assert_eq!(
            seen, &expected,
            "image {image}: a frame of the other publisher crossed, or one was lost"
        );
    }
    let counters = b.net.as_ref().unwrap().receiver_counters().unwrap();
    assert_eq!(counters.create_image, 2, "{counters:?}");
    assert_eq!(counters.data_refused, 0, "{counters:?}");
}

/// MC-1, the "required receiver precedence" row: a live required
/// receiver bounds the sender under every strategy. On one multicast group
/// B (receiver 77) stalls its subscriber and C reads everything. Under
/// `max` with no required receiver, the sender follows C and is not held;
/// with B required it is held at B's window, under `max` and under a
/// `tagged` group that C alone is in: in every cycle its sent frontier
/// (`sent_high`) is at most B's position plus the window B advertises
/// (SPEC §13), and it is held only where one more maximum frame would
/// pass it. B's position is its image's join, since its subscriber never
/// reads. Two mechanisms hold the sender at that one point: the strategy
/// limit with B's precedence, and, on this unreliable channel too, the
/// retention of a joined required member, which keeps the log's registered
/// position at B's consumption so the publisher meets back pressure half
/// a term past it. B's window is also half a term, so this test cannot
/// tell them apart; `membership/tests.rs`
/// (`edges_are_checked_sums_and_required_members_bound_every_strategy`)
/// checks the limit alone. Every call is public since karyos#637, and the
/// strategy comes from the channel's URI (`fc=`). Linux, after the
/// multicast probe.
#[cfg(target_os = "linux")]
#[test]
fn a_required_receiver_bounds_every_strategy() {
    use std::io::Write as _;

    use crate::membership::{PublicationRoles, ReceiverIdentity, Strategy};

    if let Err(why) = multicast_probe() {
        let _ = writeln!(
            std::io::stderr(),
            "SKIPPED a_required_receiver_bounds_every_strategy: {why}"
        );
        return;
    }
    let identity = |id: u64, group_tag: u64| ReceiverIdentity {
        receiver_id: core::num::NonZeroU64::new(id).unwrap(),
        group_tag,
    };
    let cases = [
        ("max", Strategy::Max, Vec::new(), Vec::new(), None, false),
        (
            "max, B required",
            Strategy::Max,
            vec![77],
            Vec::new(),
            None,
            true,
        ),
        (
            "tagged C, B required",
            Strategy::Tagged(9),
            vec![77],
            vec![(88, 9)],
            Some(identity(88, 9)),
            true,
        ),
    ];
    for (name, strategy, required, tags, c_identity, held) in cases {
        let port = free_port();
        // The strategy comes from the channel's URI, its one source
        // (karyos#637): the public path, not a driver-internal one.
        let fc = match strategy {
            Strategy::Max => "max".to_owned(),
            Strategy::Tagged(group) => format!("tagged:{group}"),
            Strategy::Min => "min".to_owned(),
        };
        let uri = format!("karyos:udp?group=239.255.0.3:{port}|reliable=false|fc={fc}");
        let karyos_protocol::channel::Media::Udp(channel) =
            karyos_protocol::channel::ChannelConfig::parse(&uri)
                .unwrap()
                .media
        else {
            panic!("{name}: not udp");
        };
        let (mut a, mut b, mut c) = (
            driver(ThreadingMode::Shared),
            driver(ThreadingMode::Shared),
            driver(ThreadingMode::Shared),
        );
        let _ = b
            .add_network_subscription_as(10, &channel, identity(77, 0))
            .unwrap();
        let _ = match c_identity {
            Some(identity) => c.add_network_subscription_as(10, &channel, identity),
            None => c.add_network_subscription(10, &channel),
        }
        .unwrap();
        let publication = a
            .add_network_publication_with_roles(
                aggregate(10, 3, 1),
                &channel,
                PublicationRoles {
                    strategy,
                    required,
                    tags,
                },
            )
            .unwrap();
        let mut images = (None, None);
        pump(&mut [&mut a, &mut b, &mut c], |drivers| {
            images = (
                drivers[1].network_image(10, 3),
                drivers[2].network_image(10, 3),
            );
            images.0.is_some() && images.1.is_some()
        });
        let (Some(stalled), Some(fast)) = images else {
            unreachable!("pumped until both exist");
        };
        // B's subscriber never reads; C's reads everything.
        let _stalled = b.subscribe_aggregate(&stalled, Role::Required).unwrap();
        let mut reader = c.subscribe_aggregate(&fast, Role::Required).unwrap();
        let mut lane = a
            .publication(publication.lane(Lane::ZERO).unwrap())
            .unwrap();
        // B's position plus its window: the stalled subscriber stays at
        // the image's join, and B advertises half a term (the receiver's
        // window rule, `agents/roles.rs`).
        let image_lane = b.stream_ref(stalled.lane(Lane::ZERO).unwrap()).unwrap();
        let config = image_lane.buffer.config();
        let PublicationMode::Image { join, .. } = config.publication else {
            panic!("{name}: not an image");
        };
        let window = (config.term_length.get() / 2).min(karyos_protocol::network::MAX_WINDOW)
            & !(karyos_sys::frame::FRAME_ALIGNMENT - 1);
        let bound = join + u64::from(window);
        let (mut accepted, mut delivered, mut sent) = (0u32, 0u32, 0u64);
        for _ in 0..4000 {
            if matches!(
                lane.offer(&[7u8; 1000]).unwrap(),
                OfferOutcome::Accepted { .. }
            ) {
                accepted += 1;
            }
            let _ = a.do_work().unwrap();
            let _ = b.do_work().unwrap();
            let _ = c.do_work().unwrap();
            let _ = reader.poll(|_, _, _| delivered += 1, BUDGET);
            sent = shared(&mut a).sender.sent_high(0, 0).unwrap();
            if held {
                assert!(
                    sent <= bound,
                    "{name}: sent {sent} past B's position {join} plus its window {window}"
                );
            }
        }
        if held {
            assert!(
                accepted < 1024,
                "{name}: {accepted} accepted while B stalls"
            );
            // Held at B's window, not before it: a first send needs a whole
            // maximum frame to fit below the edge, and one more would pass
            // it.
            assert!(
                sent + u64::from(DEFAULT_MTU) > bound,
                "{name}: held at {sent}, short of B's bound {bound}"
            );
            assert!(delivered > 0, "{name}: nothing sent");
        } else {
            assert!(
                accepted >= 1024,
                "{name}: held at {accepted} with no required receiver"
            );
        }
    }
}

/// Whether this host carries IPv4 multicast on its default route back to
/// itself: a group joined on one plain socket receives what another sends.
#[cfg(target_os = "linux")]
fn multicast_probe() -> Result<(), String> {
    let group = Ipv4Addr::new(239, 255, 0, 2);
    let receiver = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        .map_err(|error| format!("probe bind: {error}"))?;
    receiver
        .join_multicast_v4(&group, &Ipv4Addr::UNSPECIFIED)
        .map_err(|error| format!("probe join: {error}"))?;
    receiver
        .set_read_timeout(Some(Duration::from_millis(500)))
        .map_err(|error| format!("probe timeout: {error}"))?;
    let port = receiver
        .local_addr()
        .map_err(|error| format!("probe address: {error}"))?
        .port();
    let sender = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        .map_err(|error| format!("probe sender: {error}"))?;
    sender
        .send_to(b"probe", SocketAddr::new(IpAddr::V4(group), port))
        .map_err(|error| format!("probe send: {error}"))?;
    let mut buffer = [0u8; 8];
    match receiver.recv(&mut buffer) {
        Ok(5) if &buffer[..5] == b"probe" => Ok(()),
        Ok(_) => Err("probe received something else".into()),
        Err(error) => Err(format!("no loopback multicast: {error}")),
    }
}

/// E1 on two lanes: each lane delivers its own messages in order, on both
/// channel kinds.
#[test]
fn two_lanes_deliver_in_order_on_either_kind() {
    for reliable in [true, false] {
        let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
        let _ = b
            .add_network_subscription(10, &channel(ANY_PORT, reliable))
            .unwrap();
        let address = bound(&b, 10);
        let publication = a
            .add_network_publication(aggregate(10, 3, 2), &channel(address, reliable))
            .unwrap();
        let mut image = None;
        pump(&mut [&mut a, &mut b], |drivers| {
            image = drivers[1].network_image(10, 3);
            image.is_some()
        });
        let mut reader = b
            .subscribe_aggregate(&image.unwrap(), Role::Required)
            .unwrap();
        let mut lanes = [
            a.publication(publication.lane(Lane::ZERO).unwrap())
                .unwrap(),
            a.publication(publication.lane(Lane::try_new(1).unwrap()).unwrap())
                .unwrap(),
        ];
        let (mut sent, mut seen) = ([0u32; 2], [0u32; 2]);
        pump(&mut [&mut a, &mut b], |_| {
            for (lane, publication) in lanes.iter_mut().enumerate() {
                while sent[lane] < 96 {
                    let mut payload = [0u8; 1000];
                    payload[..4].copy_from_slice(&sent[lane].to_le_bytes());
                    match publication.offer(&payload).unwrap() {
                        OfferOutcome::Accepted { .. } => sent[lane] += 1,
                        _ => break,
                    }
                }
            }
            let _ = reader.poll(
                |bytes, lane, _| {
                    let lane = usize::from(lane.get());
                    let index = u32::from_le_bytes(bytes[..4].try_into().unwrap());
                    assert_eq!(index, seen[lane], "lane {lane} in order");
                    seen[lane] += 1;
                },
                BUDGET,
            );
            seen == [96, 96]
        });
    }
}

/// The shared agents of `driver`.
fn shared(
    driver: &mut EmbeddedDriver,
) -> &mut crate::agents::NetworkAgents<karyos_io::sockets::OsSocket> {
    match &mut driver.net.as_mut().unwrap().agents {
        super::Agents::Shared(agents) => agents,
        _ => panic!("not shared"),
    }
}

/// A driver clock that never moves.
#[derive(Debug)]
struct Frozen;

impl crate::clock::MonotonicClock for Frozen {
    fn now(&mut self) -> u64 {
        0
    }
}

/// The network keeps its own time base (`host_monotonic_ns`) in the
/// shared mode, whatever the driver's injectable clock says (here frozen
/// at 0). A NAK left unanswered is asked again one RTT after its
/// submission, which compares the NAK's start (the role clock) with the
/// cycle's `now`; an RTTM round trip yields a sample, which needs the
/// probe's issue, its start and the reply's arrival on one clock.
#[test]
fn the_network_keeps_its_own_clock() {
    let frozen = || {
        EmbeddedDriver::with_clock(
            DriverConfig {
                network: Some(NetworkConfig {
                    threading: ThreadingMode::Shared,
                    ..NetworkConfig::default()
                }),
                ..DriverConfig::default()
            },
            Box::new(Frozen),
        )
        .unwrap()
    };
    let (mut a, mut b) = (frozen(), frozen());
    let (publication, image) = connected(&mut a, &mut b, true, 10);
    let mut reader = b.subscribe_aggregate(&image, Role::Required).unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    // The second DATA datagram is lost, and the sender never repairs.
    shared(&mut b).receiver.drop_data(&[1]);
    shared(&mut a).sender.ignore_naks();
    let mut sent = 0u32;
    pump(&mut [&mut a, &mut b], |drivers| {
        while sent < 8
            && matches!(
                lane.offer(&[7u8; 1000]).unwrap(),
                OfferOutcome::Accepted { .. }
            )
        {
            sent += 1;
        }
        let _ = reader.poll(|_, _, _| {}, BUDGET);
        drivers[1]
            .net
            .as_ref()
            .unwrap()
            .receiver_counters()
            .is_some_and(|counters| counters.nak_retries >= 1 && counters.rttm_samples >= 1)
    });
}

/// mc-w2 in the shared mode with a frozen driver clock (ACS 16142): a
/// multicast image's cycles run on the network's own time base, so a hole
/// the sender never repairs is asked again cycle after cycle; each NAK's
/// copy reaches the other subscriber's control group, where it passes
/// validation. Linux only, after the loopback multicast probe, like
/// `a_multicast_publication_reaches_every_subscriber`.
#[cfg(target_os = "linux")]
#[test]
fn multicast_cycles_run_on_the_network_clock() {
    use std::io::Write as _;

    use crate::net::{ControlGroup, MAX_CONTROL_GROUPS};

    if let Err(why) = multicast_probe() {
        let _ = writeln!(
            std::io::stderr(),
            "SKIPPED multicast_cycles_run_on_the_network_clock: {why}"
        );
        return;
    }
    let group = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 255, 0, 3)), free_port());
    let control = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 255, 0, 4)), free_port());
    let mut table = [None; MAX_CONTROL_GROUPS];
    table[0] = Some(ControlGroup {
        data_group: group,
        interface: None,
        control_group: control,
    });
    let frozen = || {
        EmbeddedDriver::with_clock(
            DriverConfig {
                network: Some(NetworkConfig {
                    threading: ThreadingMode::Shared,
                    nak_control_groups: table,
                    ..NetworkConfig::default()
                }),
                ..DriverConfig::default()
            },
            Box::new(Frozen),
        )
        .unwrap()
    };
    let channel = UdpConfig {
        destination: Destination::Multicast { group, ttl: None },
        interface: None,
        paths: Vec::new(),
        reliable: true,
        flow_control: None,
        security: Security::Trusted,
    };
    let (mut a, mut b, mut c) = (frozen(), frozen(), frozen());
    for subscriber in [&mut b, &mut c] {
        let _ = subscriber.add_network_subscription(10, &channel).unwrap();
    }
    assert_eq!(b.network_control_join_failures(), 0);
    let publication = a
        .add_network_publication(aggregate(10, 3, 1), &channel)
        .unwrap();
    let mut image = None;
    pump(&mut [&mut a, &mut b, &mut c], |drivers| {
        image = drivers[1].network_image(10, 3);
        image.is_some() && drivers[2].network_image(10, 3).is_some()
    });
    let mut reader = b
        .subscribe_aggregate(&image.unwrap(), Role::Required)
        .unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    // B loses the second DATA datagram; the sender never repairs.
    shared(&mut b).receiver.drop_data(&[1]);
    shared(&mut a).sender.ignore_naks();
    let mut sent = 0u32;
    let counters =
        |driver: &EmbeddedDriver| driver.net.as_ref().unwrap().receiver_counters().unwrap();
    pump(&mut [&mut a, &mut b, &mut c], |drivers| {
        while sent < 8
            && matches!(
                lane.offer(&[7u8; 1000]).unwrap(),
                OfferOutcome::Accepted { .. }
            )
        {
            sent += 1;
        }
        let _ = reader.poll(|_, _, _| {}, BUDGET);
        let (b, c) = (counters(&*drivers[1]), counters(&*drivers[2]));
        b.nak_cycles >= 2 && b.naks >= 2 && c.group_naks >= 1
    });
    let b = counters(&b);
    assert!(b.group_nak_copies >= 2, "{b:?}");
}

mod linger;

mod netem;

mod bind_time;

mod trace;

mod timed;

/// The table of the conflated views below: four keys of 16 bytes.
const VIEW: karyos_sys::conflation::ConflationConfig = karyos_sys::conflation::ConflationConfig {
    keys: 4,
    value_capacity: 16,
    journal_capacity: 1024,
    refresh: false,
};

/// Offers `value` under `key` on `lane`, pumping both drivers until it is
/// accepted.
fn offer_keyed(
    a: &mut EmbeddedDriver,
    b: &mut EmbeddedDriver,
    lane: &mut karyos_client::ClientPublication<HeapTerms>,
    key: i64,
    value: u8,
) {
    let options = karyos_sys::log_buffer::AppendOptions {
        reserved_value: key,
        ..karyos_sys::log_buffer::AppendOptions::default()
    };
    pump(&mut [a, b], |_| {
        matches!(
            lane.offer_with(&[value; 16], options).unwrap(),
            OfferOutcome::Accepted { .. }
        )
    });
}

/// Polls `reader` while pumping both drivers until `done` holds for the
/// latest `(value, freshness)` of each key.
fn view_until(
    a: &mut EmbeddedDriver,
    b: &mut EmbeddedDriver,
    reader: &mut karyos_sys::conflation::ConflationReader,
    latest: &mut [Option<(u8, karyos_sys::freshness::Freshness)>; 4],
    mut done: impl FnMut(&[Option<(u8, karyos_sys::freshness::Freshness)>; 4]) -> bool,
) {
    let budget = karyos_sys::conflation::Budget {
        keys: 16,
        retries: 4,
    };
    pump(&mut [a, b], |_| {
        let _ = reader.poll_changed(budget, |key, _, value, freshness| {
            latest[key as usize] = Some((value[0], freshness));
        });
        done(latest)
    });
}

/// C4 (conflated-network-images.md (a)): a conflated subscription's image
/// gets a view fed from its lane; its values read Fresh.
#[test]
fn a_conflated_network_view_reads_its_values_fresh() {
    use karyos_sys::freshness::Freshness;

    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let _subscription = b
        .add_network_subscription_conflated(10, &channel(ANY_PORT, false), Lane::ZERO, VIEW)
        .unwrap();
    let address = bound(&b, 10);
    let publication = a
        .add_network_publication(aggregate(10, 3, 1), &channel(address, false))
        .unwrap();
    let mut image = None;
    pump(&mut [&mut a, &mut b], |drivers| {
        image = drivers[1].network_image(10, 3);
        image.is_some()
    });
    let image = image.unwrap();
    assert_eq!(b.network_view_counters().built, 1);
    let mut reader = b.network_view_reader(&image, Lane::ZERO).unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    for key in 0..4 {
        offer_keyed(&mut a, &mut b, &mut lane, key, 10 + key as u8);
    }
    let mut latest = [None; 4];
    view_until(&mut a, &mut b, &mut reader, &mut latest, |latest| {
        (0..4).all(|key| latest[key] == Some((10 + key as u8, Freshness::Fresh)))
    });
}

/// Per-source images (`quantstratum-docs:
/// karyos/design/per-source-images.md`, D2-6): two images of one alias
/// get two views, each fed only by its own image.
#[test]
fn two_images_of_one_alias_get_a_view_each() {
    use karyos_sys::freshness::Freshness;

    let (mut a1, mut a2, mut b) = (
        driver(ThreadingMode::Shared),
        driver(ThreadingMode::Shared),
        driver(ThreadingMode::Shared),
    );
    let _subscription = b
        .add_network_subscription_conflated(10, &channel(ANY_PORT, false), Lane::ZERO, VIEW)
        .unwrap();
    let address = bound(&b, 10);
    let publications = [
        a1.add_network_publication(aggregate(10, 3, 1), &channel(address, false))
            .unwrap(),
        a2.add_network_publication(aggregate(10, 3, 1), &channel(address, false))
            .unwrap(),
    ];
    pump(&mut [&mut a1, &mut a2, &mut b], |drivers| {
        drivers[2].network_images(10).len() == 2
    });
    let views = b.network_view_counters();
    assert_eq!((views.built, views.unbuilt_unexposed), (2, 0), "{views:?}");
    let images = b.network_images(10);
    let mut readers =
        [images[0].0, images[1].0].map(|image| b.network_view_reader(&image, Lane::ZERO).unwrap());
    let mut lanes = [
        a1.publication(publications[0].lane(Lane::ZERO).unwrap())
            .unwrap(),
        a2.publication(publications[1].lane(Lane::ZERO).unwrap())
            .unwrap(),
    ];
    // Publisher p offers 10 * (p + 1) + key under each key.
    let mut offered = [0i64; 2];
    let mut latest = [[None; 4]; 2];
    let budget = karyos_sys::conflation::Budget {
        keys: 16,
        retries: 4,
    };
    pump(&mut [&mut a1, &mut a2, &mut b], |_| {
        for (publisher, lane) in lanes.iter_mut().enumerate() {
            let key = offered[publisher];
            if key < 4 {
                let options = karyos_sys::log_buffer::AppendOptions {
                    reserved_value: key,
                    ..karyos_sys::log_buffer::AppendOptions::default()
                };
                let value = u8::try_from(10 * (publisher + 1)).unwrap() + key as u8;
                if matches!(
                    lane.offer_with(&[value; 16], options).unwrap(),
                    OfferOutcome::Accepted { .. }
                ) {
                    offered[publisher] += 1;
                }
            }
        }
        for (view, reader) in readers.iter_mut().enumerate() {
            let _ = reader.poll_changed(budget, |key, _, value, freshness| {
                latest[view][key as usize] = Some((value[0], freshness));
            });
        }
        latest.iter().all(|view| view.iter().all(Option::is_some))
    });
    // Each view holds one publisher's values, all of them, Fresh.
    let owners = latest.map(|view| view[0].map(|(value, _)| value / 10));
    assert_ne!(owners[0], owners[1], "one publisher per view");
    for (view, owner) in latest.iter().zip(owners) {
        for (key, entry) in view.iter().enumerate() {
            let expected = owner.unwrap() * 10 + key as u8;
            assert_eq!(*entry, Some((expected, Freshness::Fresh)), "{latest:?}");
        }
    }
}

/// C4, GU-9 end to end: on an unreliable channel a lost update makes every
/// key Stale since the gap's start once the receiver seals it, through the
/// view's mailbox (the feeder acknowledges after recording the loss); an
/// update past the gap restores its own key, Fresh.
#[test]
fn a_lost_update_stales_the_view_until_replaced() {
    use karyos_sys::freshness::Freshness;

    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let _subscription = b
        .add_network_subscription_conflated(10, &channel(ANY_PORT, false), Lane::ZERO, VIEW)
        .unwrap();
    let address = bound(&b, 10);
    let publication = a
        .add_network_publication(aggregate(10, 3, 1), &channel(address, false))
        .unwrap();
    let mut image = None;
    pump(&mut [&mut a, &mut b], |drivers| {
        image = drivers[1].network_image(10, 3);
        image.is_some()
    });
    let image = image.unwrap();
    let mut reader = b.network_view_reader(&image, Lane::ZERO).unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    for key in 0..4 {
        offer_keyed(&mut a, &mut b, &mut lane, key, 10 + key as u8);
    }
    let mut latest = [None; 4];
    view_until(&mut a, &mut b, &mut reader, &mut latest, |latest| {
        latest.iter().all(Option::is_some)
    });
    // The next DATA datagram, key 1's update, is lost; key 2's arrives.
    b.net.as_mut().unwrap().drop_receiver_data(&[0]);
    offer_keyed(&mut a, &mut b, &mut lane, 1, 21);
    offer_keyed(&mut a, &mut b, &mut lane, 2, 22);
    view_until(&mut a, &mut b, &mut reader, &mut latest, |latest| {
        latest[0].is_some_and(|(_, freshness)| freshness != Freshness::Fresh)
            && latest[2] == Some((22, Freshness::Fresh))
    });
    let since = match latest[0] {
        Some((10, Freshness::Stale { since })) => since,
        other => panic!("{other:?}"),
    };
    assert_eq!(latest[1], Some((11, Freshness::Stale { since })));
    assert_eq!(latest[3], Some((13, Freshness::Stale { since })));
    // A replacement of key 1 past the gap is Fresh; key 0 stays Stale.
    offer_keyed(&mut a, &mut b, &mut lane, 1, 31);
    view_until(&mut a, &mut b, &mut reader, &mut latest, |latest| {
        latest[1] == Some((31, Freshness::Fresh))
    });
    assert_eq!(latest[0], Some((10, Freshness::Stale { since })));
    let views = b.network_view_counters();
    assert!(views.acked >= 1, "{views:?}");
    let counters = b.net.as_ref().unwrap().receiver_counters().unwrap();
    assert!(
        counters.barrier_acks >= 1 && counters.gaps_sealed >= 1,
        "{counters:?}"
    );
    assert_eq!(counters.barrier_timeouts, 0);
}

/// Runs one step of a refresh cycle on `lane`, pumping both drivers until
/// it is accepted (ADR-0080).
fn cycle_step(
    a: &mut EmbeddedDriver,
    b: &mut EmbeddedDriver,
    lane: &mut karyos_client::ClientPublication<HeapTerms>,
    mut step: impl FnMut(
        &mut karyos_client::ClientPublication<HeapTerms>,
    ) -> Result<OfferOutcome, karyos_client::CycleError>,
) {
    pump(&mut [a, b], |_| {
        matches!(step(lane).unwrap(), OfferOutcome::Accepted { .. })
    });
}

/// SPEC §13 "Conflation refresh" (ADR-0080, karyos#634), end to end over
/// an unreliable channel. A lost update leaves every key Stale. Then a
/// complete refresh cycle that carries key 0 turns it Fresh, while key 3,
/// which it does not carry, stays Stale. Separately, a cycle cut by a lost
/// datagram before its end marker restores no key, not even key 3, whose
/// refresh value arrived.
#[test]
fn a_refresh_cycle_restores_what_it_carried_and_a_cut_one_nothing() {
    use karyos_client::refresh::{CycleId, RefreshCycle, Scope};
    use karyos_sys::freshness::Freshness;

    let view = karyos_sys::conflation::ConflationConfig {
        refresh: true,
        ..VIEW
    };
    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let _subscription = b
        .add_network_subscription_conflated(10, &channel(ANY_PORT, false), Lane::ZERO, view)
        .unwrap();
    let address = bound(&b, 10);
    let publication = a
        .add_network_publication(aggregate(10, 3, 1), &channel(address, false))
        .unwrap();
    let mut image = None;
    pump(&mut [&mut a, &mut b], |drivers| {
        image = drivers[1].network_image(10, 3);
        image.is_some()
    });
    let image = image.unwrap();
    let mut reader = b.network_view_reader(&image, Lane::ZERO).unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    for key in 0..4 {
        offer_keyed(&mut a, &mut b, &mut lane, key, 10 + key as u8);
    }
    let mut latest = [None; 4];
    view_until(&mut a, &mut b, &mut reader, &mut latest, |latest| {
        latest.iter().all(Option::is_some)
    });
    // Key 1's update is lost: every key turns Stale.
    b.net.as_mut().unwrap().drop_receiver_data(&[0]);
    offer_keyed(&mut a, &mut b, &mut lane, 1, 21);
    offer_keyed(&mut a, &mut b, &mut lane, 2, 22);
    view_until(&mut a, &mut b, &mut reader, &mut latest, |latest| {
        latest[0].is_some_and(|(_, freshness)| freshness != Freshness::Fresh)
    });
    let Some((10, Freshness::Stale { since })) = latest[0] else {
        panic!("{latest:?}");
    };
    // A complete cycle carrying key 0: key 0 turns Fresh, key 3 does not.
    let first = CycleId::default();
    let mut cycle = RefreshCycle::new(first, Scope::Refresh);
    cycle_step(&mut a, &mut b, &mut lane, |lane| cycle.begin(lane));
    cycle_step(&mut a, &mut b, &mut lane, |lane| {
        cycle.offer(lane, 0, &[40; 16])
    });
    // Before the end marker, the refresh value reads Stale.
    view_until(&mut a, &mut b, &mut reader, &mut latest, |latest| {
        latest[0].is_some_and(|(value, _)| value == 40)
    });
    assert_eq!(latest[0], Some((40, Freshness::Stale { since })));
    cycle_step(&mut a, &mut b, &mut lane, |lane| cycle.end(lane));
    view_until(&mut a, &mut b, &mut reader, &mut latest, |latest| {
        latest[0] == Some((40, Freshness::Fresh))
    });
    assert_eq!(latest[3], Some((13, Freshness::Stale { since })));
    let views = b.network_view_counters();
    assert_eq!(
        (
            views.cycles_completed,
            views.keys_restored,
            views.cycles_aborted
        ),
        (1, 1, 0),
        "{views:?}"
    );
    // A cycle cut by a lost datagram: key 3's refresh value arrives, key
    // 2's is lost, and the end marker restores nothing.
    let mut cut = RefreshCycle::new(first.next(), Scope::Refresh);
    cycle_step(&mut a, &mut b, &mut lane, |lane| cut.begin(lane));
    cycle_step(&mut a, &mut b, &mut lane, |lane| {
        cut.offer(lane, 3, &[50; 16])
    });
    // Key 3's refresh value reaches the view, Stale, before the loss.
    view_until(&mut a, &mut b, &mut reader, &mut latest, |latest| {
        latest[3].is_some_and(|(value, _)| value == 50)
    });
    b.net.as_mut().unwrap().drop_receiver_data(&[0]);
    cycle_step(&mut a, &mut b, &mut lane, |lane| {
        cut.offer(lane, 2, &[60; 16])
    });
    cycle_step(&mut a, &mut b, &mut lane, |lane| cut.end(lane));
    pump(&mut [&mut a, &mut b], |drivers| {
        drivers[1].network_view_counters().cycles_aborted == 1
    });
    view_until(&mut a, &mut b, &mut reader, &mut latest, |_| true);
    assert!(
        matches!(latest[3], Some((50, Freshness::Stale { .. }))),
        "{latest:?}"
    );
    assert!(
        matches!(latest[2], Some((22, Freshness::Stale { .. }))),
        "{latest:?}"
    );
    let views = b.network_view_counters();
    assert_eq!(
        (views.cycles_completed, views.keys_restored),
        (1, 1),
        "{views:?}"
    );
}

/// C4, design (c): once the view's terminal cell is published (here by the
/// receive owner's side of the link), the conductor closes the feeder on
/// its next duty, and the reader delivers nothing more and reports it.
#[test]
fn a_published_terminal_cell_closes_the_network_view() {
    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let _subscription = b
        .add_network_subscription_conflated(10, &channel(ANY_PORT, false), Lane::ZERO, VIEW)
        .unwrap();
    let address = bound(&b, 10);
    let publication = a
        .add_network_publication(aggregate(10, 3, 1), &channel(address, false))
        .unwrap();
    let mut image = None;
    pump(&mut [&mut a, &mut b], |drivers| {
        image = drivers[1].network_image(10, 3);
        image.is_some()
    });
    let image = image.unwrap();
    let mut reader = b.network_view_reader(&image, Lane::ZERO).unwrap();
    let link = b.network_view_link(&image, Lane::ZERO).unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    offer_keyed(&mut a, &mut b, &mut lane, 0, 10);
    let terminal = karyos_sys::freshness::Terminal {
        start: 0,
        end: 64,
        reason: karyos_sys::freshness::TERMINAL_BARRIER_TIMEOUT,
    };
    assert!(link.terminal().unwrap().publish(terminal));
    pump(&mut [&mut a, &mut b], |drivers| {
        drivers[1].network_view_counters().closed_terminal == 1
    });
    let budget = karyos_sys::conflation::Budget {
        keys: 16,
        retries: 4,
    };
    let mut delivered = 0;
    let report = reader.poll_changed(budget, |_, _, _, _| delivered += 1);
    assert_eq!((delivered, report.terminal), (0, Some(terminal)));
    assert!(
        b.network_view_link(&image, Lane::ZERO).is_none(),
        "feeder closed"
    );
}

/// Subscribes B to a conflated view of `config` and connects A's one-lane
/// publication, pumping until B has its image.
fn conflated_pair(
    a: &mut EmbeddedDriver,
    b: &mut EmbeddedDriver,
    config: karyos_sys::conflation::ConflationConfig,
) -> (
    crate::embedded::AggregateHandle,
    crate::embedded::AggregateHandle,
    crate::net::NetworkSubscription,
) {
    let subscription = b
        .add_network_subscription_conflated(10, &channel(ANY_PORT, false), Lane::ZERO, config)
        .unwrap();
    let address = bound(b, 10);
    let publication = a
        .add_network_publication(aggregate(10, 3, 1), &channel(address, false))
        .unwrap();
    let mut image = None;
    pump(&mut [a, b], |drivers| {
        image = drivers[1].network_image(10, 3);
        image.is_some()
    });
    (publication, image.unwrap(), subscription)
}

/// C4 follow-up: a view whose table cannot be built is counted with its
/// cause; the image is served without one.
#[test]
fn an_unbuildable_view_is_counted_with_its_cause() {
    use crate::net::ViewBuildFailure;
    use karyos_sys::conflation::ConflationError;

    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let config = karyos_sys::conflation::ConflationConfig { keys: 0, ..VIEW };
    let (_publication, image, _subscription) = conflated_pair(&mut a, &mut b, config);
    let views = b.network_view_counters();
    assert_eq!(
        (views.built, views.unbuilt_failed, views.unbuilt_unexposed),
        (0, 1, 0),
        "{views:?}"
    );
    assert_eq!(
        views.last_build_failure,
        Some(ViewBuildFailure::Table(ConflationError::InvalidConfig))
    );
    assert!(b.network_view_reader(&image, Lane::ZERO).is_none());
}

/// C4 follow-up: a gap the receiver seals before the view attaches (the
/// gate then seals as without a feeder) is met in the poll and recorded
/// there, so every key read so far is Stale since its start.
#[test]
fn a_gap_sealed_before_the_attach_stales_the_view() {
    use karyos_sys::freshness::Freshness;

    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    b.net.as_mut().unwrap().defer_view_attach();
    let (publication, image, _subscription) = conflated_pair(&mut a, &mut b, VIEW);
    let mut reader = b.network_view_reader(&image, Lane::ZERO).unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    offer_keyed(&mut a, &mut b, &mut lane, 0, 10);
    let mut latest = [None; 4];
    view_until(&mut a, &mut b, &mut reader, &mut latest, |latest| {
        latest[0] == Some((10, Freshness::Fresh))
    });
    b.net.as_mut().unwrap().drop_receiver_data(&[0]);
    offer_keyed(&mut a, &mut b, &mut lane, 1, 21);
    offer_keyed(&mut a, &mut b, &mut lane, 2, 22);
    view_until(&mut a, &mut b, &mut reader, &mut latest, |latest| {
        latest[2] == Some((22, Freshness::Fresh))
    });
    assert!(
        matches!(latest[0], Some((10, Freshness::Stale { .. }))),
        "{latest:?}"
    );
    b.attach_network_views();
    let views = b.network_view_counters();
    assert!(views.caught_up >= 1, "{views:?}");
    assert_eq!(views.acked, 0, "{views:?}");
}

/// C4 follow-up, driver-level BehindFrontier: a seal request below the
/// feeder's frontier publishes the terminal cell (reason below frontier)
/// and is never acknowledged.
#[test]
fn a_seal_request_below_the_frontier_closes_the_view() {
    use karyos_sys::freshness::{Freshness, TERMINAL_BELOW_FRONTIER};

    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let (publication, image, _subscription) = conflated_pair(&mut a, &mut b, VIEW);
    let mut reader = b.network_view_reader(&image, Lane::ZERO).unwrap();
    let link = b.network_view_link(&image, Lane::ZERO).unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    offer_keyed(&mut a, &mut b, &mut lane, 0, 10);
    offer_keyed(&mut a, &mut b, &mut lane, 1, 11);
    let mut latest = [None; 4];
    view_until(&mut a, &mut b, &mut reader, &mut latest, |latest| {
        latest[1] == Some((11, Freshness::Fresh))
    });
    let request = link.mailbox().unwrap().post(0, 1).unwrap();
    pump(&mut [&mut a, &mut b], |drivers| {
        drivers[1].network_view_counters().closed_terminal == 1
    });
    assert!(!link.mailbox().unwrap().is_acknowledged(request));
    let terminal = karyos_sys::freshness::TerminalCell::read(&link.terminal_words()).unwrap();
    assert_eq!(terminal.reason, TERMINAL_BELOW_FRONTIER);
}

/// Reads `reader` while pumping both drivers until it delivered `count`
/// messages in all, checking that its lane stays open.
fn read_until(
    a: &mut EmbeddedDriver,
    b: &mut EmbeddedDriver,
    reader: &mut AggregateSubscription<HeapTerms>,
    read: &mut u32,
    count: u32,
) {
    pump(&mut [a, b], |_| {
        let poll = reader.poll(|_, _, _| *read += 1, BUDGET);
        assert!(
            poll.lanes.iter().all(|lane| lane.end.is_none()),
            "the image lane closed: {:?}",
            poll.lanes.first().and_then(|lane| lane.end)
        );
        *read >= count
    });
}

/// #330 review: exhausted versions close only the network view, with
/// reason 2 over every position; the image lane stays open, and another
/// subscriber of it still receives.
#[test]
fn an_exhausted_network_view_closes_alone() {
    use karyos_sys::freshness::{Freshness, TERMINAL_FRESHNESS_EXHAUSTED, TerminalCell};

    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let (publication, image, _subscription) = conflated_pair(&mut a, &mut b, VIEW);
    let mut other = b.subscribe_aggregate(&image, Role::Optional).unwrap();
    let mut reader = b.network_view_reader(&image, Lane::ZERO).unwrap();
    let link = b.network_view_link(&image, Lane::ZERO).unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    offer_keyed(&mut a, &mut b, &mut lane, 0, 10);
    let mut latest = [None; 4];
    view_until(&mut a, &mut b, &mut reader, &mut latest, |latest| {
        latest[0] == Some((10, Freshness::Fresh))
    });
    // Key 1's next write exhausts its versions.
    b.seed_network_view_version(&image, Lane::ZERO, 1, u64::MAX - 1);
    offer_keyed(&mut a, &mut b, &mut lane, 1, 21);
    pump(&mut [&mut a, &mut b], |drivers| {
        drivers[1].network_view_counters().closed_terminal == 1
    });
    let terminal = TerminalCell::read(&link.terminal_words()).unwrap();
    assert_eq!(
        (terminal.start, terminal.end, terminal.reason),
        (0, u64::MAX, TERMINAL_FRESHNESS_EXHAUSTED)
    );
    assert_eq!(
        b.seal_state(image.lane(Lane::ZERO).unwrap()).unwrap(),
        karyos_sys::log_buffer::SealState::Active,
        "the image lane is not sealed"
    );
    assert_eq!(b.network_view_counters().feeders_lost, 0);
    // The image lane goes on: a later message reaches the other reader.
    offer_keyed(&mut a, &mut b, &mut lane, 2, 22);
    let mut read = 0;
    read_until(&mut a, &mut b, &mut other, &mut read, 3);
}

/// #330 review: a feeder that cannot read on closes only its network view,
/// with reason 5 over every position, and is counted; the image lane stays
/// open, and another subscriber of it still receives.
#[test]
fn a_lost_feeder_closes_only_its_view() {
    use karyos_sys::freshness::{TERMINAL_FEEDER_LOST, TerminalCell};

    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let (publication, image, _subscription) = conflated_pair(&mut a, &mut b, VIEW);
    let mut other = b.subscribe_aggregate(&image, Role::Optional).unwrap();
    let link = b.network_view_link(&image, Lane::ZERO).unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    offer_keyed(&mut a, &mut b, &mut lane, 0, 10);
    b.fail_network_view_polls(&image, Lane::ZERO);
    pump(&mut [&mut a, &mut b], |drivers| {
        let views = drivers[1].network_view_counters();
        views.feeders_lost == 1 && views.closed_terminal == 1
    });
    let terminal = TerminalCell::read(&link.terminal_words()).unwrap();
    assert_eq!(
        (terminal.start, terminal.end, terminal.reason),
        (0, u64::MAX, TERMINAL_FEEDER_LOST)
    );
    assert_eq!(
        b.seal_state(image.lane(Lane::ZERO).unwrap()).unwrap(),
        karyos_sys::log_buffer::SealState::Active,
        "the image lane is not sealed"
    );
    offer_keyed(&mut a, &mut b, &mut lane, 1, 21);
    let mut read = 0;
    read_until(&mut a, &mut b, &mut other, &mut read, 2);
}

/// C4 follow-up, docs#119 (a): a retiring image closes its view with the
/// image-retired terminal reason, which the reader reports.
#[test]
fn a_retired_image_closes_its_view_as_retired() {
    use karyos_sys::freshness::TERMINAL_IMAGE_RETIRED;

    let (mut a, mut b) = (
        fast_driver(ThreadingMode::Shared),
        fast_driver(ThreadingMode::Shared),
    );
    let (publication, image, _subscription) = conflated_pair(&mut a, &mut b, VIEW);
    let mut reader = b.network_view_reader(&image, Lane::ZERO).unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    offer_keyed(&mut a, &mut b, &mut lane, 0, 10);
    drop(lane);
    a.remove_aggregate(&publication).unwrap();
    let budget = karyos_sys::conflation::Budget {
        keys: 16,
        retries: 4,
    };
    let mut terminal = None;
    pump(&mut [&mut a, &mut b], |_| {
        terminal = reader.poll_changed(budget, |_, _, _, _| {}).terminal;
        terminal.is_some()
    });
    assert_eq!(terminal.map(|t| t.reason), Some(TERMINAL_IMAGE_RETIRED));
    let views = b.network_view_counters();
    assert_eq!(
        (views.closed_retired, views.closed_terminal),
        (1, 0),
        "{views:?}"
    );
}

/// A multicast channel on its own group for the admission tests, `fc=min`
/// from its URI (karyos#637).
#[cfg(target_os = "linux")]
fn admission_channel(last: u8) -> UdpConfig {
    let uri = format!(
        "karyos:udp?group=239.255.0.{last}:{}|reliable=false|fc=min",
        free_port()
    );
    let karyos_protocol::channel::Media::Udp(channel) =
        karyos_protocol::channel::ChannelConfig::parse(&uri)
            .unwrap()
            .media
    else {
        panic!("not udp");
    };
    channel
}

/// Offers 1000-byte messages on `lane` while serving `drivers`, until
/// `limit` offers; returns the outcomes' kinds in order of first sight
/// and whether any was terminal (`Closed`, `Gated`).
#[cfg(target_os = "linux")]
fn offer_outcomes(
    drivers: &mut [&mut EmbeddedDriver],
    lane: &mut karyos_client::ClientPublication<HeapTerms>,
    limit: u32,
) -> (u32, u32, bool) {
    let (mut accepted, mut back_pressured, mut terminal) = (0, 0, false);
    for _ in 0..limit {
        match lane.offer(&[7u8; 1000]).unwrap() {
            OfferOutcome::Accepted { .. } => accepted += 1,
            OfferOutcome::BackPressured => back_pressured += 1,
            OfferOutcome::Closed | OfferOutcome::Gated => terminal = true,
            _ => {}
        }
        for driver in drivers.iter_mut() {
            let _ = driver.do_work().unwrap();
        }
    }
    (accepted, back_pressured, terminal)
}

/// Owner item 7, karyos#637: while a configured required receiver has not
/// joined, the publication's admission state is `NotJoined` and offers
/// keep the existing outcome mapping: the sender stages nothing, so the
/// publication fills its window and offers answer `BackPressured`, never a
/// terminal outcome. Linux, after the multicast probe.
#[cfg(target_os = "linux")]
#[test]
fn not_joined_maps_to_back_pressured() {
    use std::io::Write as _;

    use crate::membership::{PublicationRoles, Strategy};
    use karyos_protocol::cnc::NetworkAdmission;

    if let Err(why) = multicast_probe() {
        let _ = writeln!(
            std::io::stderr(),
            "SKIPPED not_joined_maps_to_back_pressured: {why}"
        );
        return;
    }
    let channel = admission_channel(31);
    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    // B subscribes without the required identity: receiver 77 never joins.
    let _ = b.add_network_subscription(10, &channel).unwrap();
    let publication = a
        .add_network_publication_with_roles(
            aggregate(10, 3, 1),
            &channel,
            PublicationRoles {
                strategy: Strategy::Min,
                required: vec![77],
                tags: Vec::new(),
            },
        )
        .unwrap();
    pump(&mut [&mut a, &mut b], |drivers| {
        drivers[0].network_publication_admission(&publication) == Some(NetworkAdmission::NotJoined)
    });
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    let (_, back_pressured, terminal) = offer_outcomes(&mut [&mut a, &mut b], &mut lane, 4000);
    assert!(back_pressured > 0, "never back pressured");
    assert!(!terminal, "a terminal outcome under NotJoined");
    assert_eq!(
        a.network_publication_admission(&publication),
        Some(NetworkAdmission::NotJoined)
    );
}

/// Owner item 7, karyos#637: once a joined required receiver is lost (its
/// SMs stop past `receiver_timeout`), the admission state is
/// `LostRequired` and offers answer `BackPressured` (stop admission, MC-7),
/// never a terminal outcome. Linux, after the multicast probe.
#[cfg(target_os = "linux")]
#[test]
fn lost_required_maps_to_back_pressured() {
    use std::io::Write as _;

    use crate::membership::{PublicationRoles, ReceiverIdentity, Strategy};
    use karyos_protocol::cnc::NetworkAdmission;

    if let Err(why) = multicast_probe() {
        let _ = writeln!(
            std::io::stderr(),
            "SKIPPED lost_required_maps_to_back_pressured: {why}"
        );
        return;
    }
    let channel = admission_channel(32);
    let (mut a, mut b) = (
        fast_driver(ThreadingMode::Shared),
        fast_driver(ThreadingMode::Shared),
    );
    let subscription = b
        .add_network_subscription_as(
            10,
            &channel,
            ReceiverIdentity {
                receiver_id: core::num::NonZeroU64::new(77).unwrap(),
                group_tag: 0,
            },
        )
        .unwrap();
    let publication = a
        .add_network_publication_with_roles(
            aggregate(10, 3, 1),
            &channel,
            PublicationRoles {
                strategy: Strategy::Min,
                required: vec![77],
                tags: Vec::new(),
            },
        )
        .unwrap();
    pump(&mut [&mut a, &mut b], |drivers| {
        drivers[0].network_publication_admission(&publication) == Some(NetworkAdmission::Open)
    });
    // B goes: its SMs stop, and past the receiver timeout 77 is lost.
    assert!(b.remove_network_subscription(subscription).unwrap());
    pump(&mut [&mut a, &mut b], |drivers| {
        drivers[0].network_publication_admission(&publication)
            == Some(NetworkAdmission::LostRequired)
    });
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    let (_, back_pressured, terminal) = offer_outcomes(&mut [&mut a, &mut b], &mut lane, 4000);
    assert!(back_pressured > 0, "never back pressured");
    assert!(!terminal, "a terminal outcome under LostRequired");
    assert_eq!(
        a.network_publication_admission(&publication),
        Some(NetworkAdmission::LostRequired)
    );
}

/// Owner item 7, karyos#637: a client sees its network publication's
/// admission state change by event: `NotJoined` while receiver 77 has not
/// joined, then `Open` once it joins. Linux, after the multicast probe.
#[cfg(target_os = "linux")]
#[test]
fn a_client_sees_the_admission_change_by_event() {
    use std::io::Write as _;

    use crate::membership::{PublicationRoles, ReceiverIdentity, Strategy};
    use karyos_protocol::cnc::NetworkAdmission;

    if let Err(why) = multicast_probe() {
        let _ = writeln!(
            std::io::stderr(),
            "SKIPPED a_client_sees_the_admission_change_by_event: {why}"
        );
        return;
    }
    let port = free_port();
    let uri = format!("karyos:udp?group=239.255.0.33:{port}|reliable=false|fc=min");
    let karyos_protocol::channel::Media::Udp(channel) =
        karyos_protocol::channel::ChannelConfig::parse(&uri)
            .unwrap()
            .media
    else {
        panic!("not udp");
    };
    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let mut client = a.connect().unwrap();
    let roles = PublicationRoles {
        strategy: Strategy::Min,
        required: vec![77],
        tags: Vec::new(),
    };
    let sequence = client
        .add_network_publication_with_roles(&uri, 10, true, &roles)
        .unwrap();
    // The publication is held for the test: dropping it releases its
    // registration, and the driver removes the network publication.
    let mut held = None;
    pump(&mut [&mut a, &mut b], |_| {
        let _ = client.poll(usize::MAX, |completion| {
            if completion.sequence == sequence
                && let karyos_client::Outcome::Publication(publication) = completion.outcome
            {
                held = Some(publication);
            }
        });
        held.as_ref()
            .and_then(|publication| publication.origin())
            .is_some_and(|origin| {
                client.network_admission(origin.registration()) == Some(NetworkAdmission::NotJoined)
            })
    });
    let registration = held.as_ref().unwrap().origin().unwrap().registration();
    let _ = b
        .add_network_subscription_as(
            10,
            &channel,
            ReceiverIdentity {
                receiver_id: core::num::NonZeroU64::new(77).unwrap(),
                group_tag: 0,
            },
        )
        .unwrap();
    pump(&mut [&mut a, &mut b], |_| {
        let _ = client.poll(usize::MAX, |_| {});
        client.network_admission(registration) == Some(NetworkAdmission::Open)
    });
    drop(held);
}

/// karyos#658 (SPEC.md §7.1 and the "Conflation freshness" row of §13):
/// a view closed at `barrier_ack_timeout` is recreated with every key
/// `Stale` since the terminal's start, its last value kept; a key turns
/// `Fresh` only with its own update, and the receiver's gate moves to the
/// new view.
#[test]
fn a_timed_out_view_is_recreated_with_every_key_stale() {
    use karyos_sys::freshness::{Freshness, TERMINAL_BARRIER_TIMEOUT, Terminal};

    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let (publication, image, _subscription) = conflated_pair(&mut a, &mut b, VIEW);
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    offer_keyed(&mut a, &mut b, &mut lane, 0, 10);
    offer_keyed(&mut a, &mut b, &mut lane, 1, 11);
    let mut reader = b.network_view_reader(&image, Lane::ZERO).unwrap();
    let mut latest = [None; 4];
    view_until(&mut a, &mut b, &mut reader, &mut latest, |latest| {
        latest[0].is_some() && latest[1].is_some()
    });
    // An open view is not recreated.
    assert_eq!(
        b.recreate_network_view(&image, Lane::ZERO),
        Err(DriverError::ViewNotClosed)
    );
    // The cell the gate's fail-safe publishes at the timeout, on the link
    // the gate holds.
    let terminal = Terminal {
        start: 32,
        end: 64,
        reason: TERMINAL_BARRIER_TIMEOUT,
    };
    let link = b.network_view_link(&image, Lane::ZERO).unwrap();
    assert!(link.terminal().unwrap().publish(terminal));
    pump(&mut [&mut a, &mut b], |drivers| {
        drivers[1].network_view_counters().closed_terminal == 1
    });
    assert!(b.holds_closed_network_view(&image, Lane::ZERO));
    b.recreate_network_view(&image, Lane::ZERO).unwrap();
    assert!(!b.holds_closed_network_view(&image, Lane::ZERO));
    assert_eq!(b.network_view_counters().recreated, 1);
    let mut reader = b.network_view_reader(&image, Lane::ZERO).unwrap();
    let mut latest = [None; 4];
    view_until(&mut a, &mut b, &mut reader, &mut latest, |latest| {
        latest[0].is_some() && latest[1].is_some()
    });
    let stale = Freshness::Stale { since: 32 };
    assert_eq!(latest, [Some((10, stale)), Some((11, stale)), None, None]);
    // Key 1's own update restores it, and only it.
    offer_keyed(&mut a, &mut b, &mut lane, 1, 21);
    view_until(&mut a, &mut b, &mut reader, &mut latest, |latest| {
        latest[1] == Some((21, Freshness::Fresh))
    });
    assert_eq!(latest[0], Some((10, stale)));
    // The receiver took the relink: its gate holds the new view's link.
    let counters = b.net.as_ref().unwrap().receiver_counters().unwrap();
    assert_eq!((counters.views_relinked, counters.relinks_refused), (1, 0));
    // The recreated view is open: a second recreation is refused.
    assert_eq!(
        b.recreate_network_view(&image, Lane::ZERO),
        Err(DriverError::ViewNotClosed)
    );
}

/// ADR-0080 with karyos#658: a recreated view starts with no open cycle.
/// A cycle open when the view closed is gone, so its end marker read by
/// the recreated view restores nothing, and key 0, whose refresh value the
/// closed view took, stays `Stale` since the terminal's start.
#[test]
fn a_recreated_view_starts_with_no_open_cycle() {
    use karyos_client::refresh::{CycleId, RefreshCycle, Scope};
    use karyos_sys::freshness::{Freshness, TERMINAL_BARRIER_TIMEOUT, Terminal};

    let view = karyos_sys::conflation::ConflationConfig {
        refresh: true,
        ..VIEW
    };
    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let (publication, image, _subscription) = conflated_pair(&mut a, &mut b, view);
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    offer_keyed(&mut a, &mut b, &mut lane, 0, 10);
    offer_keyed(&mut a, &mut b, &mut lane, 1, 11);
    let mut cycle = RefreshCycle::new(CycleId::default(), Scope::Refresh);
    cycle_step(&mut a, &mut b, &mut lane, |lane| cycle.begin(lane));
    cycle_step(&mut a, &mut b, &mut lane, |lane| {
        cycle.offer(lane, 0, &[40; 16])
    });
    let mut reader = b.network_view_reader(&image, Lane::ZERO).unwrap();
    let mut latest = [None; 4];
    view_until(&mut a, &mut b, &mut reader, &mut latest, |latest| {
        latest[0].is_some_and(|(value, _)| value == 40) && latest[1].is_some()
    });
    let terminal = Terminal {
        start: 32,
        end: 64,
        reason: TERMINAL_BARRIER_TIMEOUT,
    };
    let link = b.network_view_link(&image, Lane::ZERO).unwrap();
    assert!(link.terminal().unwrap().publish(terminal));
    pump(&mut [&mut a, &mut b], |drivers| {
        drivers[1].network_view_counters().closed_terminal == 1
    });
    b.recreate_network_view(&image, Lane::ZERO).unwrap();
    // The cycle's end, then a live update of key 1 past it: once key 1 is
    // Fresh, the end marker was read, and it restored nothing.
    cycle_step(&mut a, &mut b, &mut lane, |lane| cycle.end(lane));
    offer_keyed(&mut a, &mut b, &mut lane, 1, 21);
    let mut reader = b.network_view_reader(&image, Lane::ZERO).unwrap();
    let mut latest = [None; 4];
    view_until(&mut a, &mut b, &mut reader, &mut latest, |latest| {
        latest[1] == Some((21, Freshness::Fresh)) && latest[0].is_some()
    });
    assert_eq!(latest[0], Some((40, Freshness::Stale { since: 32 })));
    let views = b.network_view_counters();
    assert_eq!(
        (views.recreated, views.cycles_completed),
        (1, 0),
        "{views:?}"
    );
}

/// ADR-0080: a marker whose payload does not decode aborts the open cycle
/// and is counted; the cycle's own end marker then finds no open cycle and
/// restores nothing.
#[test]
fn a_malformed_marker_aborts_the_open_cycle() {
    use karyos_client::refresh::{CycleId, RefreshCycle, Scope};

    let view = karyos_sys::conflation::ConflationConfig {
        refresh: true,
        ..VIEW
    };
    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let (publication, _image, _subscription) = conflated_pair(&mut a, &mut b, view);
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    let id = CycleId::default();
    let mut cycle = RefreshCycle::new(id, Scope::Refresh);
    cycle_step(&mut a, &mut b, &mut lane, |lane| cycle.begin(lane));
    cycle_step(&mut a, &mut b, &mut lane, |lane| {
        cycle.offer(lane, 0, &[40; 16])
    });
    let junk = karyos_sys::log_buffer::AppendOptions {
        reserved_value: karyos_sys::conflation::cycle::marker(id),
        ..karyos_sys::log_buffer::AppendOptions::default()
    };
    pump(&mut [&mut a, &mut b], |_| {
        matches!(
            lane.offer_with(&[0xFF; 24], junk).unwrap(),
            OfferOutcome::Accepted { .. }
        )
    });
    cycle_step(&mut a, &mut b, &mut lane, |lane| cycle.end(lane));
    // A live value after the end, so the feeder has read past it.
    offer_keyed(&mut a, &mut b, &mut lane, 1, 11);
    pump(&mut [&mut a, &mut b], |drivers| {
        drivers[1].network_view_counters().markers_malformed == 1
    });
    pump(&mut [&mut a, &mut b], |drivers| {
        let views = drivers[1].network_view_counters();
        views.cycles_aborted == 1
    });
    let views = b.network_view_counters();
    assert_eq!(
        (views.cycles_completed, views.keys_restored),
        (0, 0),
        "{views:?}"
    );
}

/// karyos#658: a closed view's table is released when its image retires,
/// and a retired image's view is not recreated.
#[test]
fn a_retired_image_releases_its_closed_view() {
    use karyos_sys::freshness::{TERMINAL_BARRIER_TIMEOUT, Terminal};

    let (mut a, mut b) = (
        fast_driver(ThreadingMode::Shared),
        fast_driver(ThreadingMode::Shared),
    );
    let (publication, image, _subscription) = conflated_pair(&mut a, &mut b, VIEW);
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    offer_keyed(&mut a, &mut b, &mut lane, 0, 10);
    let link = b.network_view_link(&image, Lane::ZERO).unwrap();
    assert!(link.terminal().unwrap().publish(Terminal {
        start: 0,
        end: 64,
        reason: TERMINAL_BARRIER_TIMEOUT,
    }));
    pump(&mut [&mut a, &mut b], |drivers| {
        drivers[1].holds_closed_network_view(&image, Lane::ZERO)
    });
    drop(lane);
    a.remove_aggregate(&publication).unwrap();
    pump(&mut [&mut a, &mut b], |drivers| {
        !drivers[1].holds_closed_network_view(&image, Lane::ZERO)
    });
    assert!(matches!(
        b.recreate_network_view(&image, Lane::ZERO),
        Err(DriverError::StreamRetiring { .. } | DriverError::UnknownStream { .. })
    ));
}

/// karyos#658: a conflated view of an unreliable channel needs the seal
/// deadline plus `barrier_ack_timeout` below the far-window timeout, so
/// its fail-safe closes the view before the far-window close ends the
/// image. A reliable channel never closes by that timer and is not held
/// to it.
#[test]
fn an_unreliable_view_needs_its_timeout_below_the_far_window() {
    use crate::agents::BarrierAckBound;

    let skip = crate::agents::roles::image_skip_config(
        &crate::agents::roles::receiver_path_config(&AgentConfig::default()),
        false,
    );
    let at_bound = skip.far_window_timeout_ns - skip.deadline_ns();
    let mut b = driver_with(
        ThreadingMode::Shared,
        AgentConfig {
            barrier_ack_timeout: at_bound,
            ..AgentConfig::default()
        },
    );
    assert_eq!(
        b.add_network_subscription_conflated(10, &channel(ANY_PORT, false), Lane::ZERO, VIEW)
            .err(),
        Some(DriverError::BarrierAckTimeout(BarrierAckBound::FarWindow))
    );
    // The same timeout on a reliable channel, and an unconflated
    // unreliable subscription, are accepted.
    assert!(
        b.add_network_subscription_conflated(11, &channel(ANY_PORT, true), Lane::ZERO, VIEW)
            .is_ok()
    );
    assert!(
        b.add_network_subscription(12, &channel(ANY_PORT, false))
            .is_ok()
    );
    let mut c = driver_with(
        ThreadingMode::Shared,
        AgentConfig {
            barrier_ack_timeout: at_bound - 1,
            ..AgentConfig::default()
        },
    );
    assert!(
        c.add_network_subscription_conflated(10, &channel(ANY_PORT, false), Lane::ZERO, VIEW)
            .is_ok()
    );
}

/// karyos#658: a driver refuses a `barrier_ack_timeout` below its floor or
/// below ten conductor duty periods, each with its own typed refusal; the
/// default passes both.
#[test]
fn the_barrier_timeout_bounds_refuse_a_driver() {
    use crate::agents::BarrierAckBound;

    let start = |barrier_ack_timeout, conductor_duty_period| {
        EmbeddedDriver::with_config(DriverConfig {
            network: Some(NetworkConfig {
                threading: ThreadingMode::Shared,
                agents: AgentConfig {
                    barrier_ack_timeout,
                    conductor_duty_period,
                    ..AgentConfig::default()
                },
                ..NetworkConfig::default()
            }),
            ..DriverConfig::default()
        })
        .err()
    };
    const MS: u64 = 1_000_000;
    assert_eq!(
        start(10 * MS - 1, MS),
        Some(DriverError::BarrierAckTimeout(BarrierAckBound::Floor))
    );
    assert_eq!(
        start(15 * MS, 2 * MS),
        Some(DriverError::BarrierAckTimeout(BarrierAckBound::DutyPeriods))
    );
    assert_eq!(start(20 * MS, 2 * MS), None);
    assert_eq!(start(100 * MS, MS), None);
    assert_eq!(start(100 * MS, 0), Some(DriverError::InvalidConfig));
}

/// Offers numbered messages on `lane` up to `until`, runs A and B once and
/// reads B's `reader`, checking order (T9).
fn offer_and_read(
    [a, b]: [&mut EmbeddedDriver; 2],
    lane: &mut karyos_client::ClientPublication<HeapTerms>,
    reader: &mut AggregateSubscription<HeapTerms>,
    (sent, seen): (&mut u32, &mut u32),
    until: u32,
) {
    while *sent < until {
        let mut payload = [0u8; 1000];
        payload[..4].copy_from_slice(&sent.to_le_bytes());
        match lane.offer(&payload).unwrap() {
            OfferOutcome::Accepted { .. } => *sent += 1,
            _ => break,
        }
    }
    let _ = a.do_work().unwrap();
    let _ = b.do_work().unwrap();
    let _ = reader.poll(
        |bytes, _, _| {
            let index = u32::from_le_bytes(bytes[..4].try_into().unwrap());
            assert_eq!(index, *seen, "B in order, exactly once");
            *seen += 1;
        },
        BUDGET,
    );
}

/// The span of A's lane 0 log that is live: from the retention floor to
/// the head. SPEC.md §4 keeps it within two terms (T9, plan item 6).
fn live_range(a: &EmbeddedDriver) -> u64 {
    let conductor = &a.streams[0].conductor;
    conductor.head().unwrap() - conductor.floor()
}

/// T9 (contract-traceability-phase-2.md, "Retention floor"), end to end on
/// a reliable multicast publication with C optional and B, with
/// `b_required`, required (receiver 77): the sender is then bound by B
/// alone. Without it no receiver is required, and the sender follows the
/// fastest member (`Strategy::Max`), B: the floor of optional readers with
/// no required participant (plan item 6, SPEC.md §6 "Retention"). While the
/// sender holds NAKs back, C loses a datagram and the sender sends `total`
/// messages, B reading them all; then NAKs flow. The live range stays
/// within two terms throughout. Returns C's closes `(unrecoverable,
/// cannot_resume)`, and with `repair_b`, checks that B's own hole above the
/// floor is repaired. `None` without multicast on this host.
#[cfg(target_os = "linux")]
fn optional_receiver_closes(
    total: u32,
    repair_b: bool,
    b_required: bool,
    reset: bool,
) -> Option<(u64, u64)> {
    use std::io::Write as _;

    use crate::membership::{PublicationRoles, ReceiverIdentity, Strategy};

    if let Err(why) = multicast_probe() {
        let _ = writeln!(std::io::stderr(), "SKIPPED T9 retention floor: {why}");
        return None;
    }
    let port = free_port();
    let group = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 255, 0, 4)), port);
    let channel = UdpConfig {
        destination: Destination::Multicast { group, ttl: None },
        interface: None,
        paths: Vec::new(),
        reliable: true,
        // `max`, as the roles below: the channel's `fc` is the strategy.
        flow_control: Some(karyos_protocol::channel::FlowControl::Max),
        security: Security::Trusted,
    };
    let (mut a, mut b, mut c) = (
        driver(ThreadingMode::Shared),
        driver(ThreadingMode::Shared),
        driver(ThreadingMode::Shared),
    );
    let required = ReceiverIdentity {
        receiver_id: core::num::NonZeroU64::new(77).unwrap(),
        group_tag: 0,
    };
    let _ = if b_required {
        b.add_network_subscription_as(10, &channel, required)
    } else {
        b.add_network_subscription(10, &channel)
    }
    .unwrap();
    let _ = c.add_network_subscription(10, &channel).unwrap();
    let publication = a
        .add_network_publication_with_roles(
            aggregate(10, 3, 1),
            &channel,
            PublicationRoles {
                strategy: Strategy::Max,
                required: if b_required { vec![77] } else { Vec::new() },
                tags: Vec::new(),
            },
        )
        .unwrap();
    let mut images = (None, None);
    pump(&mut [&mut a, &mut b, &mut c], |drivers| {
        images = (
            drivers[1].network_image(10, 3),
            drivers[2].network_image(10, 3),
        );
        images.0.is_some() && images.1.is_some()
    });
    let (Some(on_b), Some(_on_c)) = images else {
        unreachable!("pumped until both exist");
    };
    let mut reader = b.subscribe_aggregate(&on_b, Role::Required).unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    // The sender holds NAKs back; C loses its third DATA datagram.
    a.net.as_mut().unwrap().sender_ignores_naks(true);
    c.net.as_mut().unwrap().drop_receiver_data(&[2]);
    let (mut sent, mut seen) = (0u32, 0u32);
    for _ in 0..40_000 {
        offer_and_read(
            [&mut a, &mut b],
            &mut lane,
            &mut reader,
            (&mut sent, &mut seen),
            total,
        );
        let _ = c.do_work().unwrap();
        let live = live_range(&a);
        assert!(
            live <= 2 * u64::from(MIN_TERM_LENGTH),
            "a live range of {live} bytes"
        );
        if seen == total {
            break;
        }
        std::thread::sleep(Duration::from_micros(100));
    }
    assert_eq!(seen, total, "B reads everything");
    if reset {
        // An endpoint reset while C lags below the hold: the lane reads
        // again from its restart position, at the hold, and B drops the
        // copies; C's loss stays a reported one.
        force_reset(&a, &publication);
        for _ in 0..40_000 {
            offer_and_read(
                [&mut a, &mut b],
                &mut lane,
                &mut reader,
                (&mut sent, &mut seen),
                total,
            );
            let _ = c.do_work().unwrap();
            if a.net.as_ref().unwrap().reopened() >= 1 {
                break;
            }
            std::thread::sleep(Duration::from_micros(100));
        }
        assert!(a.net.as_ref().unwrap().reopened() >= 1, "reset");
        // The reset resends up to `retransmit_window` at once. Let it
        // drain before going on: a datagram B is later told to lose must
        // be new data, not one of these copies, which B drops as
        // duplicates (karyos#603). Drained once B's DATA frames, committed
        // or dropped, stop arriving (heartbeats are counted apart).
        let data_frames = |b: &EmbeddedDriver| {
            let receiver = b.net.as_ref().unwrap().receiver_counters().unwrap();
            receiver
                .data_committed
                .checked_add(receiver.data_dropped)
                .unwrap()
        };
        let (mut last, mut quiet) = (data_frames(&b), 0u32);
        for _ in 0..40_000 {
            offer_and_read(
                [&mut a, &mut b],
                &mut lane,
                &mut reader,
                (&mut sent, &mut seen),
                total,
            );
            let _ = c.do_work().unwrap();
            let now = data_frames(&b);
            quiet = if now == last {
                quiet.checked_add(1).unwrap()
            } else {
                0
            };
            last = now;
            if quiet >= 200 {
                break;
            }
            std::thread::sleep(Duration::from_micros(100));
        }
        assert!(quiet >= 200, "the reset's resend never drained");
    }
    // NAKs flow again: C's hole is below the floor.
    a.net.as_mut().unwrap().sender_ignores_naks(false);
    let closes = |c: &EmbeddedDriver| {
        c.net.as_ref().unwrap().receiver_counters().map(|counters| {
            (
                counters.images_closed_unrecoverable,
                counters.images_closed_cannot_resume,
            )
        })
    };
    for _ in 0..40_000 {
        offer_and_read(
            [&mut a, &mut b],
            &mut lane,
            &mut reader,
            (&mut sent, &mut seen),
            total,
        );
        let _ = c.do_work().unwrap();
        let live = live_range(&a);
        assert!(
            live <= 2 * u64::from(MIN_TERM_LENGTH),
            "a live range of {live} bytes"
        );
        if closes(&c).is_some_and(|(unrecoverable, cannot)| unrecoverable + cannot >= 1) {
            break;
        }
        std::thread::sleep(Duration::from_micros(100));
    }
    let on_c = c.net.as_ref().unwrap().receiver_counters().unwrap();
    assert!(on_c.naks >= 1, "{on_c:?}");
    if repair_b {
        // The sender answered C's NAK below its floor (RANGE_UNAVAILABLE).
        let sender = a.net.as_ref().unwrap().sender_counters().unwrap();
        assert!(sender.naks >= 1 && sender.nak_replies >= 1, "{sender:?}");
        // A hole above the floor, B's, is repaired.
        b.net.as_mut().unwrap().drop_receiver_data(&[1]);
        let more = total + 8;
        for _ in 0..40_000 {
            offer_and_read(
                [&mut a, &mut b],
                &mut lane,
                &mut reader,
                (&mut sent, &mut seen),
                more,
            );
            let live = live_range(&a);
            assert!(
                live <= 2 * u64::from(MIN_TERM_LENGTH),
                "a live range of {live} bytes"
            );
            if seen == more {
                break;
            }
            std::thread::sleep(Duration::from_micros(100));
        }
        assert_eq!(seen, more, "B's lost datagram was repaired");
        let receiver = b.net.as_ref().unwrap().receiver_counters().unwrap();
        assert!(receiver.naks >= 1, "{receiver:?}");
        assert_eq!(receiver.images_closed_unrecoverable, 0);
    }
    closes(&c)
}

/// T9: a term and a half, so the floor, bound by B alone, passes C's hole
/// but stays inside C's window `{r, r + 1}`. C's NAK below the floor is
/// answered RANGE_UNAVAILABLE and C's image closes as unrecoverable
/// (`on_unrecoverable = close`); B's own hole above the floor is repaired.
#[cfg(target_os = "linux")]
#[test]
fn an_optional_receivers_hole_below_the_floor_is_unrecoverable() {
    if let Some(closes) =
        optional_receiver_closes(MIN_TERM_LENGTH * 3 / 2 / 1000, true, true, false)
    {
        assert_eq!(closes, (1, 0), "C closed as unrecoverable");
    }
}

/// Plan item 6 (contract-traceability-phase-2.md, "Retention floor";
/// SPEC.md §15's scenario with no required participant): as above, with no
/// receiver required. The sender follows its fastest member, B, so C, an
/// optional reader lagging at its hole, falls below the floor: its NAK is
/// answered RANGE_UNAVAILABLE and its image closes as unrecoverable, while
/// B's hole above the floor is repaired, and the live range never spans
/// more than two terms.
#[cfg(target_os = "linux")]
#[test]
fn a_lagging_optional_receivers_hole_below_the_floor_with_none_required_is_unrecoverable() {
    if let Some(closes) =
        optional_receiver_closes(MIN_TERM_LENGTH * 3 / 2 / 1000, true, false, false)
    {
        assert_eq!(closes, (1, 0), "C closed as unrecoverable");
    }
}

/// T9, the expected other outcome (GU-6): three terms, so the floor is
/// beyond C's window when its NAK flows. There is no far-window catch-up,
/// so C's image closes as GapCannotResume, not as unrecoverable.
#[cfg(target_os = "linux")]
#[test]
fn an_optional_receivers_hole_past_its_window_cannot_resume() {
    if let Some(closes) =
        optional_receiver_closes(3 * (MIN_TERM_LENGTH / 1000) + 8, false, true, false)
    {
        assert_eq!(closes, (0, 1), "C closed as GapCannotResume");
    }
}

/// Docs#336 (a'), DESIGN's gap 3: the `max` case of a reset with an
/// uncounted optional receiver, C, lagging below the hold and no receiver
/// required. The reset reads again from the restart position, at the
/// hold; C's hole below the floor is still answered RANGE_UNAVAILABLE and
/// its image closes as unrecoverable, a reported loss, never a silent one;
/// B reads every message once and its own later hole is repaired.
#[cfg(target_os = "linux")]
#[test]
fn a_reset_under_max_leaves_a_lagging_optional_receivers_loss_reported() {
    if let Some(closes) =
        optional_receiver_closes(MIN_TERM_LENGTH * 3 / 2 / 1000, true, false, true)
    {
        assert_eq!(closes, (1, 0), "C closed as unrecoverable");
    }
}

/// Posts an endpoint reset of `publication`'s route on A.
fn force_reset<T: StreamTerms>(a: &EmbeddedDriver<T>, publication: &AggregateHandle) {
    let (endpoint, alias) = a
        .net
        .as_ref()
        .unwrap()
        .publication_route(publication.registration())
        .unwrap();
    a.net
        .as_ref()
        .unwrap()
        .links()
        .sender
        .post(|_reply| crate::agents::AgentCommand::ForceReset { endpoint, alias })
        .unwrap();
}

/// Docs#336's first gate (quantstratum-docs:
/// karyos/design/retention-floor-optional-receivers.md): a lone unicast
/// receiver, optional by default, keeps its delivery through the flow
/// limit. While the sender holds NAKs back, B loses its third DATA
/// datagram and the sender runs to B's window above the hole, past
/// `retransmit_window` (half a term) from its start; then NAKs flow and
/// the hole, at or above the held floor `sent - retransmit_window`, is
/// repaired. B reads every message once, in order, and the live range
/// stays within two terms. Against the limit's rule alone (a floor at the
/// registered position) the NAK is answered RANGE_UNAVAILABLE.
#[test]
fn a_lone_optional_unicast_receivers_hole_is_repaired() {
    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let (publication, image) = connected(&mut a, &mut b, true, 10);
    let mut reader = b.subscribe_aggregate(&image, Role::Required).unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    let total = MIN_TERM_LENGTH * 3 / 2 / 1000;
    a.net.as_mut().unwrap().sender_ignores_naks(true);
    b.net.as_mut().unwrap().drop_receiver_data(&[2]);
    let (mut sent, mut seen) = (0u32, 0u32);
    let half = u64::from(MIN_TERM_LENGTH / 2);
    let mut past_window = false;
    for _ in 0..4_000 {
        offer_and_read(
            [&mut a, &mut b],
            &mut lane,
            &mut reader,
            (&mut sent, &mut seen),
            total,
        );
        let live = live_range(&a);
        assert!(
            live <= 2 * u64::from(MIN_TERM_LENGTH),
            "a live range of {live} bytes"
        );
        past_window |= u64::from(sent) * 1056 > half + 3 * 1056;
        std::thread::sleep(Duration::from_micros(100));
    }
    assert!(past_window, "sent {sent} past half a term");
    assert_eq!(seen, 2, "B holds at its hole");
    assert!(sent < total, "flow control bounds the sender at B's window");
    a.net.as_mut().unwrap().sender_ignores_naks(false);
    for _ in 0..40_000 {
        offer_and_read(
            [&mut a, &mut b],
            &mut lane,
            &mut reader,
            (&mut sent, &mut seen),
            total,
        );
        let live = live_range(&a);
        assert!(
            live <= 2 * u64::from(MIN_TERM_LENGTH),
            "a live range of {live} bytes"
        );
        if seen == total {
            break;
        }
        std::thread::sleep(Duration::from_micros(100));
    }
    assert_eq!(seen, total, "B's hole was repaired");
    let receiver = b.net.as_ref().unwrap().receiver_counters().unwrap();
    assert!(receiver.naks >= 1, "{receiver:?}");
    assert_eq!(
        (
            receiver.images_closed_unrecoverable,
            receiver.images_closed_cannot_resume
        ),
        (0, 0)
    );
}

/// Docs#336's second gate: a slow optional receiver under `min` (the
/// multicast default), C, is bounded by flow control and its hole is
/// repaired. While the sender holds NAKs back, C loses its third DATA
/// datagram; the sender runs to C's window above it, past
/// `retransmit_window` from its start, and B, the fast one, reads what is
/// sent. Then NAKs flow: C's hole, at or above the held floor, is
/// repaired, both read every message once, in order, and the live range
/// stays within two terms.
#[cfg(target_os = "linux")]
#[test]
fn a_slow_optional_receiver_under_min_is_bounded_and_repaired() {
    use std::io::Write as _;

    use crate::membership::{PublicationRoles, Strategy};

    if let Err(why) = multicast_probe() {
        let _ = writeln!(std::io::stderr(), "SKIPPED docs#336 min gate: {why}");
        return;
    }
    let port = free_port();
    let group = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 255, 0, 5)), port);
    let channel = UdpConfig {
        destination: Destination::Multicast { group, ttl: None },
        interface: None,
        paths: Vec::new(),
        reliable: true,
        flow_control: None,
        security: Security::Trusted,
    };
    let (mut a, mut b, mut c) = (
        driver(ThreadingMode::Shared),
        driver(ThreadingMode::Shared),
        driver(ThreadingMode::Shared),
    );
    let _ = b.add_network_subscription(10, &channel).unwrap();
    let _ = c.add_network_subscription(10, &channel).unwrap();
    let publication = a
        .add_network_publication_with_roles(
            aggregate(10, 3, 1),
            &channel,
            PublicationRoles {
                strategy: Strategy::Min,
                required: Vec::new(),
                tags: Vec::new(),
            },
        )
        .unwrap();
    let mut images = (None, None);
    pump(&mut [&mut a, &mut b, &mut c], |drivers| {
        images = (
            drivers[1].network_image(10, 3),
            drivers[2].network_image(10, 3),
        );
        images.0.is_some() && images.1.is_some()
    });
    let (Some(on_b), Some(on_c)) = images else {
        unreachable!("pumped until both exist");
    };
    let mut reader = b.subscribe_aggregate(&on_b, Role::Required).unwrap();
    let mut slow = c.subscribe_aggregate(&on_c, Role::Required).unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    let total = MIN_TERM_LENGTH * 3 / 2 / 1000;
    a.net.as_mut().unwrap().sender_ignores_naks(true);
    c.net.as_mut().unwrap().drop_receiver_data(&[2]);
    let (mut sent, mut seen, mut seen_c) = (0u32, 0u32, 0u32);
    let mut read_c = |c: &mut EmbeddedDriver, seen_c: &mut u32| {
        let _ = c.do_work().unwrap();
        let _ = slow.poll(
            |bytes, _, _| {
                let index = u32::from_le_bytes(bytes[..4].try_into().unwrap());
                assert_eq!(index, *seen_c, "C in order, exactly once");
                *seen_c += 1;
            },
            BUDGET,
        );
    };
    let half = u64::from(MIN_TERM_LENGTH / 2);
    let mut past_window = false;
    for _ in 0..4_000 {
        offer_and_read(
            [&mut a, &mut b],
            &mut lane,
            &mut reader,
            (&mut sent, &mut seen),
            total,
        );
        read_c(&mut c, &mut seen_c);
        let live = live_range(&a);
        assert!(
            live <= 2 * u64::from(MIN_TERM_LENGTH),
            "a live range of {live} bytes"
        );
        past_window |= u64::from(sent) * 1056 > half + 3 * 1056;
        std::thread::sleep(Duration::from_micros(100));
    }
    assert!(past_window, "sent {sent} past half a term");
    assert_eq!(seen_c, 2, "C holds at its hole");
    assert!(sent < total, "flow control bounds the sender at C's window");
    a.net.as_mut().unwrap().sender_ignores_naks(false);
    for _ in 0..40_000 {
        offer_and_read(
            [&mut a, &mut b],
            &mut lane,
            &mut reader,
            (&mut sent, &mut seen),
            total,
        );
        read_c(&mut c, &mut seen_c);
        let live = live_range(&a);
        assert!(
            live <= 2 * u64::from(MIN_TERM_LENGTH),
            "a live range of {live} bytes"
        );
        if seen == total && seen_c == total {
            break;
        }
        std::thread::sleep(Duration::from_micros(100));
    }
    assert_eq!((seen, seen_c), (total, total), "C's hole was repaired");
    let on_c = c.net.as_ref().unwrap().receiver_counters().unwrap();
    assert!(on_c.naks >= 1, "{on_c:?}");
    assert_eq!(
        (
            on_c.images_closed_unrecoverable,
            on_c.images_closed_cannot_resume
        ),
        (0, 0)
    );
}

/// Docs#336 (a'), DESIGN's gap 2: a reset drops the tail and the publisher
/// then offers nothing. B, a lone optional unicast receiver, loses the
/// last three DATA datagrams; the endpoint resets with nothing more
/// offered. The lane reads again from its restart position, at most B's
/// consumption, and the idle heartbeat tells B the sent position, so B
/// reads the tail once, in order, with no loss reported; traffic after it
/// flows.
#[test]
fn a_tail_lost_at_a_reset_with_an_idle_publisher_is_recovered() {
    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let (publication, image) = connected(&mut a, &mut b, true, 10);
    let mut reader = b.subscribe_aggregate(&image, Role::Required).unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    exchange_on(&mut a, &mut b, &mut lane, &mut reader, 0..64);
    let sender = |driver: &EmbeddedDriver| driver.net.as_ref().unwrap().sender_counters().unwrap();
    let before = sender(&a).sent;
    b.net.as_mut().unwrap().drop_receiver_data(&[0, 1, 2]);
    let mut sent = 64u32;
    pump(&mut [&mut a, &mut b], |drivers| {
        while sent < 67 {
            let mut payload = [0u8; 1000];
            payload[..4].copy_from_slice(&sent.to_le_bytes());
            match lane.offer(&payload).unwrap() {
                OfferOutcome::Accepted { .. } => sent += 1,
                _ => break,
            }
        }
        sender(drivers[0]).sent >= before + 3
    });
    force_reset(&a, &publication);
    // Idle: nothing more is offered until B has read the tail.
    let mut seen = 64u32;
    pump(&mut [&mut a, &mut b], |drivers| {
        let _ = reader.poll(
            |bytes, _, _| {
                let index = u32::from_le_bytes(bytes[..4].try_into().unwrap());
                assert_eq!(index, seen, "in order, exactly once");
                seen += 1;
            },
            BUDGET,
        );
        drivers[0].net.as_ref().unwrap().reopened() >= 1 && seen == 67
    });
    let receiver = b.net.as_ref().unwrap().receiver_counters().unwrap();
    assert_eq!(
        (
            receiver.images_closed_unrecoverable,
            receiver.images_closed_cannot_resume
        ),
        (0, 0)
    );
    exchange_from(&mut a, &mut b, &mut lane, &mut reader, 67, 67..128);
}

/// A fragmented message straddling an endpoint reset (karyos#594: a reset
/// re-reads from the restart position, a block start at or below the
/// receivers' consumption): B, a lone optional unicast receiver, gets the
/// first of a 3000-byte message's three DATA datagrams and loses the other
/// two; the endpoint resets with nothing more offered. The sender holds
/// NAKs back throughout, so only the reset's resend at once can deliver the
/// message: the restart never lands inside it, and B reads it once and
/// whole, then the messages after it, in order.
#[test]
fn a_fragmented_message_straddling_a_reset_is_read_once_and_whole() {
    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let (publication, image) = connected(&mut a, &mut b, true, 10);
    let mut reader = b.subscribe_aggregate(&image, Role::Required).unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    exchange_on(&mut a, &mut b, &mut lane, &mut reader, 0..8);
    let sender = |driver: &EmbeddedDriver| driver.net.as_ref().unwrap().sender_counters().unwrap();
    let before = sender(&a).sent;
    // The message's second and third DATA datagrams never reach B, and no
    // NAK repairs them.
    a.net.as_mut().unwrap().sender_ignores_naks(true);
    b.net.as_mut().unwrap().drop_receiver_data(&[1, 2]);
    let mut large = vec![0u8; 3000];
    large[..4].copy_from_slice(&8u32.to_le_bytes());
    for (index, byte) in large.iter_mut().enumerate().skip(4) {
        *byte = u8::try_from(index % 251).unwrap();
    }
    let mut offered = false;
    pump(&mut [&mut a, &mut b], |drivers| {
        if !offered {
            offered = matches!(lane.offer(&large).unwrap(), OfferOutcome::Accepted { .. });
        }
        offered && sender(drivers[0]).sent >= before + 3
    });
    let mut copies = 0u32;
    // B holds at the message: a part of it only.
    for _ in 0..200 {
        let _ = a.do_work().unwrap();
        let _ = b.do_work().unwrap();
        let _ = reader.poll(|_, _, _| copies += 1, BUDGET);
    }
    assert_eq!(copies, 0, "B read a message it does not hold whole");
    force_reset(&a, &publication);
    pump(&mut [&mut a, &mut b], |drivers| {
        let _ = reader.poll(
            |bytes, _, _| {
                assert_eq!(bytes, &large[..], "the message whole");
                copies += 1;
            },
            BUDGET,
        );
        drivers[0].net.as_ref().unwrap().reopened() >= 1 && copies >= 1
    });
    assert_eq!(copies, 1, "read once");
    a.net.as_mut().unwrap().sender_ignores_naks(false);
    let receiver = b.net.as_ref().unwrap().receiver_counters().unwrap();
    assert_eq!(
        (
            receiver.images_closed_unrecoverable,
            receiver.images_closed_cannot_resume
        ),
        (0, 0)
    );
    exchange_from(&mut a, &mut b, &mut lane, &mut reader, 9, 9..64);
}

/// Two drivers on a two-path multicast channel of `reliable` delivery, the
/// isolated-paths switch assumed (as in
/// `a_two_path_publication_reaches_a_two_path_subscription`), connected:
/// the publication and B's image. `None` when the host cannot carry
/// multicast, said on stderr.
#[cfg(target_os = "linux")]
fn two_paths(
    label: &str,
    reliable: bool,
) -> Option<(
    EmbeddedDriver,
    EmbeddedDriver,
    crate::embedded::AggregateHandle,
    crate::embedded::AggregateHandle,
)> {
    use std::io::Write as _;

    if let Err(why) = multicast_probe() {
        let _ = writeln!(std::io::stderr(), "SKIPPED {label}: {why}");
        return None;
    }
    let group = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 255, 0, 4)), free_port());
    let channel = UdpConfig {
        destination: Destination::Multicast { group, ttl: None },
        interface: None,
        paths: vec![
            Interface::Address(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            Interface::Address(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        ],
        reliable,
        flow_control: None,
        security: Security::Trusted,
    };
    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    for side in [&mut a, &mut b] {
        side.net.as_mut().unwrap().assume_isolated_paths();
    }
    let _ = b.add_network_subscription(10, &channel).unwrap();
    let publication = a
        .add_network_publication(aggregate(10, 4, 1), &channel)
        .unwrap();
    let mut image = None;
    pump(&mut [&mut a, &mut b], |drivers| {
        image = drivers[1].network_image(10, 4);
        image.is_some()
    });
    let image = image?;
    Some((a, b, publication, image))
}

/// Offers messages `0..3` on `a`'s lane 0, the tail from message 1 lost at
/// B by `one_source`, and pumps until `done` holds of what B delivered and
/// the local gaps it reported.
#[cfg(target_os = "linux")]
fn lose_the_tail(
    a: &mut EmbeddedDriver,
    b: &mut EmbeddedDriver,
    publication: &crate::embedded::AggregateHandle,
    image: &crate::embedded::AggregateHandle,
    one_source: bool,
    mut done: impl FnMut(&[u32], &[(u64, u64)]) -> bool,
) -> (Vec<u32>, Vec<(u64, u64)>) {
    use karyos_sys::log_buffer::SkipReason;

    let mut reader = b.subscribe_aggregate(image, Role::Required).unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    let offer = |lane: &mut karyos_client::ClientPublication<_>, index: u32| {
        let mut payload = [0u8; 1000];
        payload[..4].copy_from_slice(&index.to_le_bytes());
        assert!(matches!(
            lane.offer(&payload).unwrap(),
            OfferOutcome::Accepted { .. }
        ));
    };
    let (mut delivered, mut gaps) = (Vec::new(), Vec::new());
    // Message 0 arrives first, on its own.
    offer(&mut lane, 0);
    pump(&mut [&mut *a, &mut *b], |_| {
        let _ = reader.poll(
            |bytes, _, _| delivered.push(u32::from_le_bytes(bytes[..4].try_into().unwrap())),
            BUDGET,
        );
        !delivered.is_empty()
    });
    // A 1000-byte message takes 1056 bytes of the log: the tail starts at
    // 1056.
    b.net.as_mut().unwrap().drop_receiver_tail(1056, one_source);
    offer(&mut lane, 1);
    offer(&mut lane, 2);
    pump(&mut [a, b], |_| {
        let poll = reader.poll(
            |bytes, _, _| delivered.push(u32::from_le_bytes(bytes[..4].try_into().unwrap())),
            BUDGET,
        );
        if let Some(skipped) = poll.lanes[0].skipped
            && matches!(skipped.reason, SkipReason::LocalGap(_))
        {
            gaps.push((
                skipped.position,
                skipped.position + u64::from(skipped.extent),
            ));
        }
        done(&delivered, &gaps)
    });
    (delivered, gaps)
}

/// karyos#834 (SPEC §6, G1, over redundant paths): an unreliable two-path
/// lane whose tail is lost on every path goes idle; its idle DATA
/// heartbeat on each path shows the tail, which B seals as one local gap
/// of its exact range at the reorder deadline. The heartbeats keep coming
/// on both paths, and the gap is neither sealed again nor moved.
#[cfg(target_os = "linux")]
#[test]
fn a_tail_lost_on_every_path_is_one_local_gap() {
    let label = "a_tail_lost_on_every_path_is_one_local_gap";
    let Some((mut a, mut b, publication, image)) = two_paths(label, false) else {
        return;
    };
    let (delivered, gaps) =
        lose_the_tail(&mut a, &mut b, &publication, &image, false, |_, gaps| {
            !gaps.is_empty()
        });
    assert_eq!(delivered, [0]);
    assert_eq!(gaps, [(1056, 3 * 1056)], "the exact tail");
    // More heartbeats on both paths: still one seal.
    for _ in 0..2_000 {
        for driver in [&mut a, &mut b] {
            let _ = driver.do_work().unwrap();
        }
        std::thread::sleep(std::time::Duration::from_micros(100));
    }
    let receiver = b.net.as_ref().unwrap().receiver_counters().unwrap();
    assert_eq!(receiver.gaps_sealed, 1, "{receiver:?}");
    // Each path's heartbeat past the tail reached B (G3, #842 review).
    if b.network_path_counters().1 > 0 {
        use std::io::Write as _;

        let _ = writeln!(
            std::io::stderr(),
            "SKIPPED {label} (both paths' heartbeats): path 2's join failed on this host"
        );
        return;
    }
    assert_eq!(
        b.net.as_ref().unwrap().receiver_tail_heartbeat_sources(),
        2,
        "a heartbeat on both paths"
    );
}

/// karyos#834: the same tail on a reliable two-path lane is NAKed and
/// repaired: every message arrives once and in order.
#[cfg(target_os = "linux")]
#[test]
fn a_tail_lost_on_every_reliable_path_is_repaired() {
    let label = "a_tail_lost_on_every_reliable_path_is_repaired";
    let Some((mut a, mut b, publication, image)) = two_paths(label, true) else {
        return;
    };
    let (delivered, gaps) = lose_the_tail(
        &mut a,
        &mut b,
        &publication,
        &image,
        false,
        |delivered, _| delivered.len() == 3,
    );
    assert_eq!(delivered, [0, 1, 2], "in order, exactly once");
    assert!(gaps.is_empty());
    assert!(b.net.as_ref().unwrap().receiver_counters().unwrap().naks >= 1);
}

/// karyos#834: a tail lost on one path only arrives by the other, and
/// nothing is sealed.
#[cfg(target_os = "linux")]
#[test]
fn a_tail_lost_on_one_path_arrives_by_the_other() {
    use std::io::Write as _;

    let label = "a_tail_lost_on_one_path_arrives_by_the_other";
    let Some((mut a, mut b, publication, image)) = two_paths(label, false) else {
        return;
    };
    if b.network_path_counters().1 > 0 {
        let _ = writeln!(
            std::io::stderr(),
            "SKIPPED {label}: path 2's join failed on this host"
        );
        return;
    }
    let (delivered, gaps) = lose_the_tail(
        &mut a,
        &mut b,
        &publication,
        &image,
        true,
        |delivered, _| delivered.len() == 3,
    );
    assert_eq!(delivered, [0, 1, 2]);
    assert!(gaps.is_empty());
    assert_eq!(
        b.net
            .as_ref()
            .unwrap()
            .receiver_counters()
            .unwrap()
            .gaps_sealed,
        0
    );
}

/// rp-w4b2c: a publication over two paths reaches a subscription over the
/// same two paths, with the isolated-paths switch assumed on both drivers
/// (owner item 12 keeps it off on real sockets): every message once, in
/// order, though each path carries a copy. The second path is loopback,
/// which some hosts cannot carry multicast on; the founding path alone
/// then delivers, and the test still checks exactly-once order. Linux,
/// after the multicast probe.
#[cfg(target_os = "linux")]
#[test]
fn a_two_path_publication_reaches_a_two_path_subscription() {
    use std::io::Write as _;

    if let Err(why) = multicast_probe() {
        let _ = writeln!(
            std::io::stderr(),
            "SKIPPED a_two_path_publication_reaches_a_two_path_subscription: {why}"
        );
        return;
    }
    let port = free_port();
    let group = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 255, 0, 3)), port);
    let channel = UdpConfig {
        destination: Destination::Multicast { group, ttl: None },
        interface: None,
        paths: vec![
            Interface::Address(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            Interface::Address(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        ],
        reliable: true,
        flow_control: None,
        security: Security::Trusted,
    };
    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    for side in [&mut a, &mut b] {
        side.net.as_mut().unwrap().assume_isolated_paths();
    }
    let _ = b.add_network_subscription(10, &channel).unwrap();
    let publication = a
        .add_network_publication(aggregate(10, 4, 1), &channel)
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
        while sent < 128 {
            let mut payload = [0u8; 1000];
            payload[..4].copy_from_slice(&sent.to_le_bytes());
            match lane.offer(&payload).unwrap() {
                OfferOutcome::Accepted { .. } => sent += 1,
                _ => break,
            }
        }
        let _ = reader.poll(
            |bytes, _, _| {
                let index = u32::from_le_bytes(bytes[..4].try_into().unwrap());
                assert_eq!(index, seen, "in order, exactly once");
                seen += 1;
            },
            BUDGET,
        );
        seen == 128
    });
    // Path 2 carries the stream too (#343 review): the receiver's SMs reach
    // the sender on path 2's endpoint, so path 2 is bound, published and
    // live end to end. A host whose loopback cannot join the group on path 2
    // exercises the founding path only, and says so.
    if b.network_path_counters().1 > 0 {
        let _ = writeln!(
            std::io::stderr(),
            "SKIPPED path 2 of a_two_path_publication_reaches_a_two_path_subscription: its join failed on this host"
        );
        return;
    }
    let registration = publication.registration();
    pump(&mut [&mut a, &mut b], |drivers| {
        let bound = drivers[0]
            .net
            .as_ref()
            .unwrap()
            .publication_path_bindings(registration);
        bound.len() == 2 && bound.iter().all(|bound| *bound > 0)
    });
}

/// SPEC.md §15 "Guarded session abort", the trusted half
/// (guards-and-abort.md "Trusted sockets in Phase 2", O-11 and GC-6): a
/// guard close on a trusted socket channel is local. Messages written but
/// not sent before it never leave and are recorded `Aborted`; the sender
/// then sends nothing, no
/// DATA, repair, control, `SESSION_ABORT` or EOS; the close
/// acknowledgement names the last position submitted under the old epoch;
/// and the remote image ends at its liveness timeout with the messages
/// submitted before the close, and nothing after. A single-path sender
/// has no idle DATA heartbeat yet (gap G1), so none is checked here. The
/// reconnection half waits for a reopened network publication to bind a
/// fresh incarnation.
#[test]
fn a_guard_close_on_a_trusted_channel_ends_the_remote_image_at_liveness() {
    use karyos_sys::guard::Closed;
    use karyos_sys::outcome_ring::Kind;

    use crate::guard_ack::SenderAck;
    use crate::net::NetworkGuard;

    let (mut a, mut b) = (
        fast_driver(ThreadingMode::Shared),
        fast_driver(ThreadingMode::Shared),
    );
    let guard = a.add_guard("trusted").unwrap();
    assert_eq!(a.reopen_guard(guard, 1, 1).unwrap(), 2);
    let _ = b
        .add_network_subscription(10, &channel(ANY_PORT, true))
        .unwrap();
    let address = bound(&b, 10);
    let mut config = aggregate(10, 3, 1);
    // The sender's reservation and the guard's walker.
    config.stream.buffer.spare_slots = 4;
    let publication = a
        .add_guarded_network_publication(
            config,
            &channel(address, true),
            NetworkGuard {
                guard,
                messages: 4,
                rate: None,
            },
        )
        .unwrap();
    let mut image = None;
    pump(&mut [&mut a, &mut b], |drivers| {
        image = drivers[1].network_image(10, 3);
        image.is_some()
    });
    let mut reader = b
        .subscribe_aggregate(&image.unwrap(), Role::Optional)
        .unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    let message = |index: u32| {
        let mut payload = [0u8; 100];
        payload[..4].copy_from_slice(&index.to_le_bytes());
        payload
    };
    // Ten messages submitted and delivered under the open guard, each a
    // 160-byte frame.
    let mut kinds = Vec::new();
    let (mut sent, mut seen) = (0u32, 0u32);
    pump(&mut [&mut a, &mut b], |_| {
        let _ = lane
            .poll_outcomes(64, |_, record| kinds.push(record.kind))
            .unwrap();
        if sent < 10
            && matches!(
                lane.offer(&message(sent)).unwrap(),
                OfferOutcome::Accepted { .. }
            )
        {
            sent += 1;
        }
        let _ = reader.poll(
            |bytes, _, _| {
                assert_eq!(u32::from_le_bytes(bytes[..4].try_into().unwrap()), seen);
                seen += 1;
            },
            BUDGET,
        );
        seen == 10 && kinds.len() == 10
    });
    assert!(
        kinds.iter().all(|kind| *kind == Kind::Submitted),
        "{kinds:?}"
    );
    // Three more written, then the close before any cycle runs: no gate
    // ever sees them open.
    for index in 10..13 {
        assert!(matches!(
            lane.offer(&message(index)).unwrap(),
            OfferOutcome::Accepted { .. }
        ));
    }
    let Closed::Now { epoch } = a.close_guard(guard, 2).unwrap() else {
        panic!("not closed");
    };
    assert_eq!(lane.offer(&message(13)).unwrap(), OfferOutcome::Gated);
    let mut ended = Vec::new();
    pump(&mut [&mut a, &mut b], |drivers| {
        let _ = lane
            .poll_outcomes(64, |_, record| ended.push((record.kind, record.reason)))
            .unwrap();
        drivers[0]
            .close_guard_ack(guard, epoch)
            .unwrap()
            .effective()
            == Some(true)
            && ended.last().is_some_and(|(kind, _)| *kind == Kind::Ended)
    });
    // The three never left: each is `Aborted` by the close, then `Ended`
    // (records from the sender gate's submissions, not at commit).
    let closed = (Kind::Aborted, crate::guard_streams::REASON_GUARD_CLOSED);
    assert_eq!(
        ended,
        [
            closed,
            closed,
            closed,
            (Kind::Ended, crate::guard_streams::REASON_GUARD_CLOSED)
        ]
    );
    let ack = a.close_guard_ack(guard, epoch).unwrap();
    let [(_, SenderAck::Applied { positions, .. })] = ack.senders[..] else {
        panic!("{ack:?}");
    };
    assert_eq!(positions[0], 10 * 160, "the last position submitted");
    // From here the sender is silent.
    let quiet = (
        shared(&mut a).sender.outbound_counters(0).unwrap(),
        shared(&mut a).sender.counters(),
    );
    let mut end = None;
    pump(&mut [&mut a, &mut b], |_| {
        let poll = reader.poll(|_, _, _| panic!("a message after the close"), BUDGET);
        end = poll.lanes.first().and_then(|lane| lane.end);
        end.is_some()
    });
    assert_eq!(
        end,
        Some(LaneEnd::Closed {
            position: 10 * 160,
            reason: SealReason::ImageRetired,
        })
    );
    drop(reader);
    pump(&mut [&mut a, &mut b], |drivers| {
        drivers[1].net.as_ref().unwrap().image_count() == 0
    });
    let (outbound, sender) = (
        shared(&mut a).sender.outbound_counters(0).unwrap(),
        shared(&mut a).sender.counters(),
    );
    assert_eq!(
        (outbound.staged, outbound.submitted, outbound.records),
        (quiet.0.staged, quiet.0.submitted, quiet.0.records),
        "no DATA after the close"
    );
    assert_eq!(sender.sent, quiet.1.sent, "no control after the close");
    assert_eq!((sender.eos_sent, sender.repairs), (0, 0));
    let received = b.net.as_ref().unwrap().receiver_counters().unwrap();
    assert_eq!(received.data_committed, 10);
    assert_eq!(
        (received.images_retired, received.images_closed_eos),
        (1, 0),
        "ended at liveness, not by an EOS"
    );
}

/// SPEC.md §13 "Same position, different lanes", the outcomes half on a
/// trusted channel: two lanes of one guarded network publication reach
/// identical positions, then the guard closes. Every outcome record, on
/// both lanes, names its own lane and its lane's positions: ten
/// `Submitted` each at the same positions, then the three written before
/// the close `Aborted` each, then `Ended`. The close acknowledgement names
/// the same last position for both lanes, and the receiver gets each
/// lane's own messages on that lane. `SESSION_ABORT_ACK`, the other half,
/// is gated until a reviewed security profile exists (owner decision 5,
/// ADR-0035).
///
/// Each lane's `Ended` comes only once its handle has seen the close: a
/// lane's seal is positioned when its publication releases at the guard's
/// seal, which its next offer (`Gated`) does. This is the local-stream
/// design (guards-and-abort.md, Local streams), so the test offers once on
/// each lane after the close.
#[test]
fn two_lanes_at_the_same_position_keep_their_own_outcomes_through_a_close() {
    use karyos_sys::guard::Closed;
    use karyos_sys::outcome_ring::Kind;

    use crate::guard_ack::SenderAck;
    use crate::guard_streams::REASON_GUARD_CLOSED;
    use crate::net::NetworkGuard;

    const LANES: u8 = 2;
    const FRAME: u64 = 160;
    let (mut a, mut b) = (
        fast_driver(ThreadingMode::Shared),
        fast_driver(ThreadingMode::Shared),
    );
    let guard = a.add_guard("same-position").unwrap();
    assert_eq!(a.reopen_guard(guard, 1, 1).unwrap(), 2);
    let _ = b
        .add_network_subscription(10, &channel(ANY_PORT, true))
        .unwrap();
    let address = bound(&b, 10);
    let mut config = aggregate(10, 3, usize::from(LANES));
    // The sender's reservation and the guard's walker.
    config.stream.buffer.spare_slots = 4;
    let publication = a
        .add_guarded_network_publication(
            config,
            &channel(address, true),
            NetworkGuard {
                guard,
                messages: 4,
                rate: None,
            },
        )
        .unwrap();
    let mut image = None;
    pump(&mut [&mut a, &mut b], |drivers| {
        image = drivers[1].network_image(10, 3);
        image.is_some()
    });
    let mut reader = b
        .subscribe_aggregate(&image.unwrap(), Role::Optional)
        .unwrap();
    let mut lanes: Vec<_> = (0..LANES)
        .map(|lane| {
            a.publication(publication.lane(Lane::try_new(lane).unwrap()).unwrap())
                .unwrap()
        })
        .collect();
    // The same 100-byte payload size on both lanes, so the same positions;
    // each payload names its lane and its index.
    let message = |lane: u8, index: u32| {
        let mut payload = [0u8; 100];
        payload[..4].copy_from_slice(&index.to_le_bytes());
        payload[4] = lane;
        payload
    };
    let mut records: [Vec<karyos_sys::outcome_ring::Record>; 2] = [Vec::new(), Vec::new()];
    let mut sent = [0u32; 2];
    let mut seen = [0u32; 2];
    pump(&mut [&mut a, &mut b], |_| {
        for (index, lane) in lanes.iter_mut().enumerate() {
            let _ = lane
                .poll_outcomes(64, |_, record| records[index].push(record))
                .unwrap();
            let number = u8::try_from(index).unwrap();
            if sent[index] < 10
                && matches!(
                    lane.offer(&message(number, sent[index])).unwrap(),
                    OfferOutcome::Accepted { .. }
                )
            {
                sent[index] += 1;
            }
        }
        let _ = reader.poll(
            |bytes, lane, _| {
                let lane = usize::from(lane.get());
                assert_eq!(usize::from(bytes[4]), lane, "a message on another lane");
                let index = u32::from_le_bytes(bytes[..4].try_into().unwrap());
                assert_eq!(index, seen[lane], "lane {lane} in order");
                seen[lane] += 1;
            },
            BUDGET,
        );
        seen == [10, 10] && records.iter().all(|lane| lane.len() == 10)
    });
    for (index, lane) in records.iter().enumerate() {
        for (number, record) in (0u64..).zip(lane) {
            assert_eq!(
                (record.kind, usize::from(record.lane)),
                (Kind::Submitted, index),
                "{record:?}"
            );
            assert_eq!(
                (record.start, record.end),
                (number * FRAME, (number + 1) * FRAME)
            );
        }
    }
    // Three more on each lane, at the same positions, then the close
    // before any cycle runs.
    for (index, lane) in lanes.iter_mut().enumerate() {
        let number = u8::try_from(index).unwrap();
        for at in 10..13 {
            assert!(matches!(
                lane.offer(&message(number, at)).unwrap(),
                OfferOutcome::Accepted { .. }
            ));
        }
    }
    let Closed::Now { epoch } = a.close_guard(guard, 2).unwrap() else {
        panic!("not closed");
    };
    // Each handle sees the close at its next offer and releases at the
    // guard's seal, which the walker then reaches.
    for (index, lane) in lanes.iter_mut().enumerate() {
        let number = u8::try_from(index).unwrap();
        assert_eq!(
            lane.offer(&message(number, 13)).unwrap(),
            OfferOutcome::Gated
        );
    }
    let mut ended: [Vec<karyos_sys::outcome_ring::Record>; 2] = [Vec::new(), Vec::new()];
    pump(&mut [&mut a, &mut b], |drivers| {
        for (index, lane) in lanes.iter_mut().enumerate() {
            let _ = lane
                .poll_outcomes(64, |_, record| ended[index].push(record))
                .unwrap();
        }
        drivers[0]
            .close_guard_ack(guard, epoch)
            .unwrap()
            .effective()
            == Some(true)
            && ended
                .iter()
                .all(|lane| lane.last().is_some_and(|record| record.kind == Kind::Ended))
    });
    for (index, lane) in ended.iter().enumerate() {
        assert_eq!(lane.len(), 4, "lane {index}: {lane:?}");
        for record in lane {
            assert_eq!(usize::from(record.lane), index, "{record:?}");
            assert_eq!(record.reason, REASON_GUARD_CLOSED, "{record:?}");
        }
        let aborted: Vec<_> = lane[..3]
            .iter()
            .map(|record| (record.kind, record.start, record.end))
            .collect();
        assert_eq!(
            aborted,
            (10..13)
                .map(|at| (Kind::Aborted, at * FRAME, (at + 1) * FRAME))
                .collect::<Vec<_>>(),
            "lane {index}"
        );
        assert_eq!(lane[3].kind, Kind::Ended);
    }
    let ack = a.close_guard_ack(guard, epoch).unwrap();
    let [(_, SenderAck::Applied { positions, .. })] = ack.senders[..] else {
        panic!("{ack:?}");
    };
    assert_eq!(
        positions[..usize::from(LANES)],
        [10 * FRAME, 10 * FRAME],
        "each lane's last position submitted"
    );
    let _ = reader.poll(|_, _, _| panic!("a message after the close"), BUDGET);
    assert_eq!(seen, [10, 10]);
}

/// #381 review P1: on a dedicated runner a receiver failure leaves the
/// sender's thread, and its gates, running. The driver must not end their
/// lanes: a message the sender submits after the failure is recorded
/// `Submitted`, never `Aborted`.
#[test]
fn a_receiver_failure_on_a_dedicated_runner_leaves_the_gates_deciding() {
    use karyos_sys::outcome_ring::Kind;

    use crate::net::NetworkGuard;

    let (mut a, mut b) = (
        driver(ThreadingMode::Dedicated),
        driver(ThreadingMode::Shared),
    );
    let guard = a.add_guard("dedicated").unwrap();
    assert_eq!(a.reopen_guard(guard, 1, 1).unwrap(), 2);
    let _ = b
        .add_network_subscription(10, &channel(ANY_PORT, true))
        .unwrap();
    let address = bound(&b, 10);
    let mut config = aggregate(10, 3, 1);
    // The sender's reservation and the guard's walker.
    config.stream.buffer.spare_slots = 4;
    let publication = a
        .add_guarded_network_publication(
            config,
            &channel(address, true),
            NetworkGuard {
                guard,
                messages: 4,
                rate: None,
            },
        )
        .unwrap();
    let mut image = None;
    pump(&mut [&mut a, &mut b], |drivers| {
        image = drivers[1].network_image(10, 3);
        image.is_some()
    });
    let mut reader = b
        .subscribe_aggregate(&image.unwrap(), Role::Optional)
        .unwrap();
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    // Connected: two messages delivered and recorded.
    let (mut sent, mut seen, mut kinds) = (0u8, 0u32, Vec::new());
    pump(&mut [&mut a, &mut b], |_| {
        if sent < 2
            && matches!(
                lane.offer(&[sent; 100]).unwrap(),
                OfferOutcome::Accepted { .. }
            )
        {
            sent += 1;
        }
        let _ = lane
            .poll_outcomes(8, |_, record| kinds.push(record.kind))
            .unwrap();
        let _ = reader.poll(|_, _, _| seen += 1, BUDGET);
        seen == 2 && kinds.len() == 2
    });
    a.net
        .as_ref()
        .unwrap()
        .links()
        .receiver
        .post(|_reply| crate::agents::AgentCommand::Panic)
        .unwrap();
    let mut failed = false;
    for _ in 0..40_000 {
        if a.do_work().is_err() {
            failed = true;
            break;
        }
        std::thread::sleep(Duration::from_micros(100));
    }
    assert!(failed, "the receiver failed");
    // Two more, after the failure: the sender's gate submits them.
    for _ in 0..40_000 {
        if sent < 4
            && matches!(
                lane.offer(&[sent; 100]).unwrap(),
                OfferOutcome::Accepted { .. }
            )
        {
            sent += 1;
        }
        let _ = a.do_work();
        let _ = b.do_work().unwrap();
        let _ = lane
            .poll_outcomes(8, |_, record| kinds.push(record.kind))
            .unwrap();
        let _ = reader.poll(|_, _, _| seen += 1, BUDGET);
        if kinds.len() == 4 && seen == 4 {
            break;
        }
        std::thread::sleep(Duration::from_micros(100));
    }
    assert_eq!((sent, seen), (4, 4), "sent after the failure");
    assert_eq!(kinds, [Kind::Submitted; 4]);
}

/// SPEC §6 (G1): a tail lost on the wire is revealed only by the idle
/// sender's heartbeat. The last three DATA datagrams of a reliable lane
/// are dropped at B's intake and the publisher goes idle: nothing else
/// shows the hole, so the heartbeat at the lane's next position raises
/// the image's mark, B NAKs the tail, the repair arrives, and every
/// message is delivered, in order, with the image still live.
#[test]
fn an_idle_heartbeat_reveals_a_lost_tail() {
    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let (publication, image) = connected(&mut a, &mut b, true, 10);
    let mut reader = b.subscribe_aggregate(&image, Role::Required).unwrap();
    // The next three DATA datagrams, the whole tail, are lost.
    b.net.as_mut().unwrap().drop_receiver_data(&[0, 1, 2]);
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    for index in 0..3u32 {
        let mut payload = [0u8; 1000];
        payload[..4].copy_from_slice(&index.to_le_bytes());
        assert!(matches!(
            lane.offer(&payload).unwrap(),
            OfferOutcome::Accepted { .. }
        ));
    }
    let mut seen = 0u32;
    pump(&mut [&mut a, &mut b], |_| {
        let _ = reader.poll(
            |bytes, _, _| {
                let index = u32::from_le_bytes(bytes[..4].try_into().unwrap());
                assert_eq!(index, seen, "in order, exactly once");
                seen += 1;
            },
            BUDGET,
        );
        seen == 3
    });
    let sender = a.net.as_ref().unwrap().sender_counters().unwrap();
    let receiver = b.net.as_ref().unwrap().receiver_counters().unwrap();
    assert!(sender.heartbeats_sent >= 1, "{sender:?}");
    assert!(receiver.naks >= 1, "{receiver:?}");
    assert!(b.network_image(10, 3).is_some(), "the image is still live");
}

/// SPEC §6 (G1) on an unreliable lane (karyos#806): the last two DATA
/// datagrams are dropped at B's intake and the publisher goes idle.
/// Nothing but the heartbeat at the lane's next position shows the tail,
/// so at the reorder deadline B seals it as one local gap of its exact
/// range, after the one message delivered, and the image stays live.
#[test]
fn an_idle_heartbeat_reveals_a_lost_unreliable_tail_as_a_gap() {
    use karyos_sys::log_buffer::SkipReason;

    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let (publication, image) = connected(&mut a, &mut b, false, 10);
    let mut reader = b.subscribe_aggregate(&image, Role::Required).unwrap();
    b.net.as_mut().unwrap().drop_receiver_data(&[1, 2]);
    let mut lane = a
        .publication(publication.lane(Lane::ZERO).unwrap())
        .unwrap();
    for index in 0..3u32 {
        let mut payload = [0u8; 1000];
        payload[..4].copy_from_slice(&index.to_le_bytes());
        assert!(matches!(
            lane.offer(&payload).unwrap(),
            OfferOutcome::Accepted { .. }
        ));
    }
    // A 1000-byte message takes 1056 bytes of the log.
    let frame = 1056u64;
    let mut delivered = Vec::new();
    let mut gaps = Vec::new();
    pump(&mut [&mut a, &mut b], |_| {
        let poll = reader.poll(
            |bytes, _, _| delivered.push(u32::from_le_bytes(bytes[..4].try_into().unwrap())),
            BUDGET,
        );
        if let Some(skipped) = poll.lanes[0].skipped
            && matches!(skipped.reason, SkipReason::LocalGap(_))
        {
            gaps.push((
                skipped.position,
                skipped.position + u64::from(skipped.extent),
            ));
        }
        !gaps.is_empty()
    });
    assert_eq!(delivered, [0]);
    assert_eq!(gaps, [(frame, 3 * frame)], "the exact tail");
    let sender = a.net.as_ref().unwrap().sender_counters().unwrap();
    let receiver = b.net.as_ref().unwrap().receiver_counters().unwrap();
    assert!(sender.heartbeats_sent >= 1, "{sender:?}");
    assert_eq!(receiver.gaps_sealed, 1, "{receiver:?}");
    assert_eq!(receiver.naks, 0, "no NAK on an unreliable lane");
    assert!(b.network_image(10, 3).is_some(), "the image is still live");
}

/// G2: a publication whose `initial_term_id` is just below `u32::MAX`
/// (the test override) crosses the term id wrap: its messages arrive in
/// order across it.
#[test]
fn a_publication_crosses_the_term_id_wrap() {
    let mut network = NetworkConfig {
        threading: ThreadingMode::Shared,
        ..NetworkConfig::default()
    };
    network.stream_defaults.initial_term_id = Some(u32::MAX - 1);
    let mut a = EmbeddedDriver::with_config(DriverConfig {
        network: Some(network),
        ..DriverConfig::default()
    })
    .unwrap();
    let mut b = driver(ThreadingMode::Shared);
    let (publication, image) = connected(&mut a, &mut b, true, 10);
    let lane = a.stream_ref(publication.lane(Lane::ZERO).unwrap()).unwrap();
    assert_eq!(lane.config.initial_term_id.get(), u32::MAX - 1);
    let mut reader = b.subscribe_aggregate(&image, Role::Required).unwrap();
    // About four 64 KiB terms: term ids MAX - 1, MAX, 0 and 1.
    exchange(&mut a, &mut b, &publication, &mut reader, 256);
}

mod destinations;

/// karyos#859: the driver's accounting of what publications hold of a
/// send endpoint matches what the endpoint has open, through adds,
/// removals and a reset: at the end the endpoint's routes, queues and
/// committed slots are exactly the publications' demand plus its control
/// routes, with no drift.
#[test]
fn the_endpoint_accounting_matches_its_use_through_adds_removals_and_a_reset() {
    let (mut a, mut b) = (driver(ThreadingMode::Shared), driver(ThreadingMode::Shared));
    let mut publications = Vec::new();
    let add = |a: &mut EmbeddedDriver, b: &mut EmbeddedDriver, stream: i32| {
        let _ = b
            .add_network_subscription(stream, &channel(ANY_PORT, true))
            .unwrap();
        let address = bound(b, stream);
        a.add_network_publication(aggregate(stream, 1, 1), &channel(address, true))
            .unwrap()
    };
    for stream in 10..18 {
        publications.push((stream, add(&mut a, &mut b, stream)));
    }
    let images = |drivers: &mut [&mut EmbeddedDriver], streams: &[i32]| {
        streams
            .iter()
            .all(|stream| drivers[1].network_image(*stream, 1).is_some())
    };
    let streams: Vec<i32> = (10..18).collect();
    pump(&mut [&mut a, &mut b], |drivers| images(drivers, &streams));
    // Three removals, to their end.
    for (_, handle) in publications.drain(..3) {
        a.remove_aggregate(&handle).unwrap();
    }
    pump(&mut [&mut a, &mut b], |drivers| {
        drivers[0]
            .net
            .as_ref()
            .unwrap()
            .reserved()
            .iter()
            .all(|(_, held)| held.routes == 5)
    });
    // A reset of the endpoint, then two more adds.
    let endpoint = a.net.as_ref().unwrap().reserved()[0].0;
    {
        let net = a.net.as_mut().unwrap();
        let (endpoints, links) = net.endpoints_mut();
        endpoints.reset(links, endpoint).unwrap();
    }
    for stream in [20, 21] {
        publications.push((stream, add(&mut a, &mut b, stream)));
    }
    let streams: Vec<i32> = (13..18).chain([20, 21]).collect();
    pump(&mut [&mut a, &mut b], |drivers| images(drivers, &streams));
    let expected = |a: &mut EmbeddedDriver| {
        let reserved = a
            .net
            .as_ref()
            .unwrap()
            .reserved()
            .into_iter()
            .find(|(held, _)| *held == endpoint)
            .unwrap()
            .1;
        let control = u32::try_from(shared(a).sender.control_entries(endpoint)).unwrap();
        (
            reserved.routes + control,
            reserved.queues + control,
            reserved.slots + control * u32::from(crate::agents::control::CONTROL_QUEUE_DEPTH),
        )
    };
    let used = |a: &mut EmbeddedDriver| {
        let used = shared(a).sender.tx_commitment(endpoint).unwrap();
        (used.routes, used.queues, used.slots)
    };
    // Every publication opens; then the two agree.
    for _ in 0..20_000 {
        let _ = a.do_work().unwrap();
        let _ = b.do_work().unwrap();
        if used(&mut a) == expected(&mut a) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_micros(100));
    }
    let (routes, queues, slots) = used(&mut a);
    assert_eq!((routes, queues, slots), expected(&mut a));
    assert!(
        routes >= 7 && queues >= 7 && slots >= 7 * 8,
        "{routes} {queues} {slots}"
    );
}
