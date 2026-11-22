// SPDX-License-Identifier: Apache-2.0

//! The agent against an embedded IPC driver (Linux; quantstratum-docs:
//! karyos/design/management-agent-gap-analysis.md, M6a): it attaches as a
//! tool and reports the driver's counters and positions; a driver that
//! exits is reported closed and its tool slot is free again; a ring that
//! laps the agent's cursor is reported as overwritten records.
//!
//! The tests share one lock: each runs a driver and serves it on this
//! thread while the agent attaches on another.

#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use karyos_agent::api::{API_VERSION, DriverState};
use karyos_agent::{Agent, AgentConfig};
use karyos_driver::{DriverConfig, EmbeddedDriver, IpcConfig, SystemClock};
use karyos_sys::term_bytes::SharedTerms;

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

type IpcDriver = EmbeddedDriver<SharedTerms>;

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("karyos-agent-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn driver(dir: &Path, config: DriverConfig, max_tools: usize) -> IpcDriver {
    EmbeddedDriver::with_ipc(
        config,
        IpcConfig {
            dir: dir.to_path_buf(),
            max_pending_hellos: 4,
            hello_timeout: 5_000_000_000,
            max_outbound_per_client: 8,
            fetch_deadline: 5_000_000_000,
            max_exports_per_client: 16,
            max_fetches_per_client: 4,
            max_regions_per_fetch: 4,
            max_fetch_bytes: 1 << 30,
            max_tools,
        },
        Box::new(SystemClock::new()),
    )
    .unwrap()
}

fn agent(dirs: &[&Path]) -> Agent {
    Agent::new(
        AgentConfig::new(dirs.iter().map(|dir| dir.to_path_buf()).collect())
            .with_attach_timeout(Duration::from_secs(5))
            .with_history(8),
    )
}

/// Refreshes `agent` on another thread while serving `driver` here.
fn refresh_serving(driver: &mut IpcDriver, agent: &mut Agent) {
    std::thread::scope(|scope| {
        let handle = scope.spawn(|| agent.refresh());
        let start = Instant::now();
        while !handle.is_finished() {
            assert!(start.elapsed() < Duration::from_secs(30), "stuck");
            let _ = driver.do_work().unwrap();
            std::thread::sleep(Duration::from_micros(200));
        }
        handle.join().unwrap();
    });
}

/// Duty cycles until the driver completed a sampling pass.
fn sampled(driver: &mut IpcDriver) {
    for _ in 0..200 {
        let _ = driver.do_work().unwrap();
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn the_agent_attaches_and_reports_the_driver() {
    let _serial = serial();
    let dir = dir("attach");
    let mut driver = driver(&dir, DriverConfig::default(), 4);
    sampled(&mut driver);
    let mut agent = agent(&[&dir]);
    refresh_serving(&mut driver, &mut agent);
    let view = agent.view();
    assert_eq!(view.version, API_VERSION);
    let seen = &view.drivers[0];
    assert_eq!(seen.state, DriverState::Attached);
    assert_eq!(seen.instance, driver.instance());
    // A quiet driver raises no alert (M9).
    assert!(seen.alerts.is_empty());
    let sample = seen.sample.as_ref().unwrap();
    // The driver's own cells, among them its pid (M1).
    let pid = sample
        .counters
        .iter()
        .find(|counter| counter.label == "driver pid" && counter.stream == 0)
        .unwrap();
    assert_eq!(pid.value, u64::from(std::process::id()));
    // A second refresh reads again without attaching again.
    refresh_serving(&mut driver, &mut agent);
    assert_eq!(agent.view().drivers[0].state, DriverState::Attached);
}

#[test]
fn a_driver_that_exits_is_reported_closed_and_frees_its_slot() {
    let _serial = serial();
    let dir = dir("closed");
    let mut driver = driver(&dir, DriverConfig::default(), 1);
    let mut agent = agent(&[&dir]);
    refresh_serving(&mut driver, &mut agent);
    let instance = agent.view().drivers[0].instance;
    assert_eq!(agent.view().drivers[0].state, DriverState::Attached);
    // The only tool slot is the agent's: another tool is refused.
    let mut other = self::agent(&[&dir]);
    refresh_serving(&mut driver, &mut other);
    assert!(matches!(
        other.view().drivers[0].state,
        DriverState::Unavailable { .. }
    ));
    drop(driver);
    agent.refresh();
    let view = agent.view();
    assert_eq!(view.drivers[0].state, DriverState::Closed);
    // The last values and the instance stay in the view.
    assert_eq!(view.drivers[0].instance, instance);
    assert!(view.drivers[0].sample.is_some());
    // While the driver is down it stays reported closed.
    agent.refresh();
    assert_eq!(agent.view().drivers[0].state, DriverState::Closed);
    // A new driver in the same directory: the agent attaches again, to the
    // new instance, in the slot it released.
    let mut driver = self::driver(&dir, DriverConfig::default(), 1);
    refresh_serving(&mut driver, &mut agent);
    let view = agent.view();
    assert_eq!(view.drivers[0].state, DriverState::Attached);
    assert_eq!(view.drivers[0].instance, driver.instance());
    assert_ne!(view.drivers[0].instance, instance);
}

/// R-CORE-24: the view states each driver's attachment (since when, how
/// many, how the previous one ended) and the agent's own identity, apart
/// from the driver instance it watches.
#[test]
fn the_view_states_the_attachment_and_the_agent_identity() {
    use karyos_agent::api::AttachEndReason;

    let _serial = serial();
    let dir = dir("attachment");
    let mut driver = driver(&dir, DriverConfig::default(), 1);
    let mut agent = Agent::new(
        AgentConfig::new(vec![dir.clone()])
            .with_attach_timeout(Duration::from_secs(5))
            .with_agent_id("ns/pod-0".to_owned()),
    );
    let identity = agent.view().agent;
    assert_eq!(identity.id.as_deref(), Some("ns/pod-0"));
    assert_eq!(identity.pid, std::process::id());
    assert!(identity.started_ns > 0);
    let before = agent.view().drivers[0].attachment;
    assert_eq!(
        (before.since_ns, before.attaches, before.previous),
        (None, 0, None)
    );
    refresh_serving(&mut driver, &mut agent);
    let first = agent.view().drivers[0].clone();
    assert!(first.attachment.since_ns.is_some());
    assert_eq!(first.attachment.attaches, 1);
    assert_eq!(first.attachment.previous, None);
    // The driver goes: the attach ends, with the instance it named.
    drop(driver);
    agent.refresh();
    let ended = agent.view().drivers[0].attachment;
    assert_eq!(ended.since_ns, None);
    let previous = ended.previous.unwrap();
    assert_eq!(Some(previous.instance), first.instance);
    assert_eq!(previous.reason, AttachEndReason::DriverGone);
    assert!(previous.ended_ns >= first.attachment.since_ns.unwrap());
    // A new driver: a second attach, the previous end kept.
    let mut driver = self::driver(&dir, DriverConfig::default(), 1);
    refresh_serving(&mut driver, &mut agent);
    let second = agent.view().drivers[0].attachment;
    assert_eq!(second.attaches, 2);
    assert!(second.since_ns.unwrap() >= previous.ended_ns);
    assert_eq!(second.previous, Some(previous));
    // The agent's identity is its own: the same across the driver change.
    assert_eq!(agent.view().agent, identity);
}

#[test]
fn a_lapped_cursor_reports_what_it_lost() {
    let _serial = serial();
    let dir = dir("lapped");
    let config = DriverConfig {
        guard_audit_records: 4,
        ..DriverConfig::default()
    };
    let mut driver = driver(&dir, config, 4);
    let guard = driver.add_guard("orders").unwrap();
    let mut agent = agent(&[&dir]);
    refresh_serving(&mut driver, &mut agent);
    assert_eq!(agent.view().drivers[0].guards.delivered, 0);
    // Ten audited calls into a ring of four, between two refreshes: a
    // close, then nine closes of a closed guard, each audited.
    for operation in 1..=10 {
        let _ = driver.close_guard(guard, operation).unwrap();
    }
    refresh_serving(&mut driver, &mut agent);
    let guards = &agent.view().drivers[0].guards;
    assert_eq!(guards.delivered, 4);
    assert_eq!(guards.overwritten, 6);
    // The newest four, in order, with their operations.
    let operations: Vec<u64> = guards.records.iter().map(|entry| entry.operation).collect();
    assert_eq!(operations, [7, 8, 9, 10]);
}

/// The guard acknowledgement alert end to end (M4b): a close whose
/// registered sender has not applied it past `guard_ack_timeout` fires,
/// keyed by the guard; once the sender applies it, it clears.
#[test]
fn a_close_not_applied_in_time_raises_a_guard_alert() {
    use karyos_agent::api::AlertKind;
    use karyos_sys::applied_epoch::Applied;
    let _serial = serial();
    let dir = dir("guard-ack");
    let config = DriverConfig {
        guard_ack_timeout: 1,
        ..DriverConfig::default()
    };
    let mut driver = driver(&dir, config, 4);
    // A guard is created closed; open, then closed by a close.
    let guard = driver.add_guard("orders").unwrap();
    let _ = driver.reopen_guard(guard, 1, 1).unwrap();
    let (_sender, cell) = driver.register_guard_sender(guard).unwrap();
    let mut agent = agent(&[&dir]);
    refresh_serving(&mut driver, &mut agent);
    assert!(agent.view().drivers[0].alerts.is_empty());
    let epoch = match driver.close_guard(guard, 2).unwrap() {
        karyos_sys::guard::Closed::Now { epoch } => epoch,
        other => panic!("{other:?}"),
    };
    sampled(&mut driver);
    refresh_serving(&mut driver, &mut agent);
    let alerts = &agent.view().drivers[0].alerts;
    assert_eq!(alerts.len(), 1);
    assert_eq!(
        (alerts[0].kind, alerts[0].participant, alerts[0].value),
        (AlertKind::GuardAck, guard.id(), 1)
    );
    cell.publish(Applied {
        epoch,
        positions: [0; 4],
        in_flight: 0,
    });
    sampled(&mut driver);
    refresh_serving(&mut driver, &mut agent);
    assert!(agent.view().drivers[0].alerts.is_empty());
}

/// REVIEWER-02's F1 on #473: a repeated error updates its record in place,
/// and the agent shows the driver's count, not the one it first read.
#[test]
fn a_repeated_error_is_shown_with_its_current_count() {
    use karyos_driver::{LossPolicy, StreamConfig};
    use karyos_sys::frame::Lane;
    use karyos_sys::log_buffer::{LogBufferConfig, PublicationMode};
    use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
    use karyos_sys::term::TermId;

    let config = || StreamConfig {
        buffer: LogBufferConfig {
            term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
            spare_slots: 3,
            max_subscribers: 4,
            mtu: DEFAULT_MTU,
            max_reserved: MIN_TERM_LENGTH / 8,
            initial_term_id: TermId::new(7),
            lane: Lane::ZERO,
            session_id: 1,
            stream_id: 2,
            claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
            publication: PublicationMode::Exclusive,
            schedule_capacity: 0,
        },
        allow_unconnected: true,
        on_required_loss: LossPolicy::Hold,
        conflation: None,
    };
    let _serial = serial();
    let dir = dir("repeated");
    let mut driver = driver(&dir, DriverConfig::default(), 4);
    let _ = driver.add_stream(config()).unwrap();
    assert!(driver.add_stream(config()).is_err());
    let mut agent = agent(&[&dir]);
    refresh_serving(&mut driver, &mut agent);
    let errors = &agent.view().drivers[0].errors;
    assert_eq!(errors.records.len(), 1);
    assert_eq!(errors.records[0].occurrences, 1);
    for _ in 0..2 {
        assert!(driver.add_stream(config()).is_err());
    }
    refresh_serving(&mut driver, &mut agent);
    let errors = &agent.view().drivers[0].errors;
    assert_eq!(errors.records.len(), 1, "{errors:?}");
    assert_eq!(errors.records[0].occurrences, 3);
    // One record, delivered once, nothing lost.
    assert_eq!((errors.delivered, errors.overwritten), (1, 0));
}

/// M8: the exporter renders an attached driver's view, its own pid cell
/// among the driver counters as a gauge, and the attach as a gauge of 1.
#[test]
fn the_exporter_renders_an_attached_driver() {
    let _serial = serial();
    let dir = dir("exporter");
    let mut driver = driver(&dir, DriverConfig::default(), 4);
    sampled(&mut driver);
    let mut agent = agent(&[&dir]);
    refresh_serving(&mut driver, &mut agent);
    let text = karyos_agent::exporter::render(&agent.view());
    let driver_label = format!("driver=\"{}\"", dir.display());
    assert!(
        text.contains(&format!("karyos_driver_attached{{{driver_label}}} 1\n")),
        "{text}"
    );
    assert!(text.contains("# TYPE karyos_events_total counter\n"));
    let pid = format!(
        "karyos_gauge{{{driver_label},source=\"driver\",name=\"driver pid\",stream=\"0\",lane=\"0\",kind=\"0\",participant=\"0\"}} {}\n",
        std::process::id()
    );
    assert!(text.contains(&pid), "{text}");
}

/// M11 end to end: the agent lists the Archive catalog of a driver given
/// one, over its control streams: it connects as an IPC client, takes a
/// concurrent handle on the request stream the host configured concurrent
/// and reads the response stream. A fake Archive on this thread refuses
/// the first page, then answers each page from a catalog of three
/// recordings, two per page; the refusal is counted and the agent lists
/// again on the same connection.
#[test]
fn the_agent_lists_the_archive_catalog_of_a_driver() {
    use karyos_agent::catalog::{ArchiveStreams, CatalogConfig};
    use karyos_archive::catalog::{SourceIncarnation, Stop, StopReason};
    use karyos_archive::control::{
        ControlMessage, ControlResponse, RecordingDescriptor, RecordingState, ResponseCode,
    };
    use karyos_archive::segment::Geometry;
    use karyos_archive::server::MAX_ANSWER;
    use karyos_client::{MessageLimit, OfferOutcome};
    use karyos_driver::{LossPolicy, StreamConfig};
    use karyos_sys::frame::Lane;
    use karyos_sys::log_buffer::{LogBufferConfig, PublicationMode, Role};
    use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
    use karyos_sys::term::TermId;

    const REQUESTS: i32 = 100;
    const RESPONSES: i32 = 101;
    let stream = |stream_id, publication| StreamConfig {
        buffer: LogBufferConfig {
            term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
            // Two concurrent publishers and a reader take their credits.
            spare_slots: 6,
            max_subscribers: 4,
            mtu: DEFAULT_MTU,
            max_reserved: MIN_TERM_LENGTH / 8,
            initial_term_id: TermId::new(7),
            lane: Lane::ZERO,
            session_id: 1,
            stream_id,
            claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
            publication,
            schedule_capacity: 0,
        },
        allow_unconnected: true,
        on_required_loss: LossPolicy::Hold,
        conflation: None,
    };
    let _serial = serial();
    let dir = dir("catalog");
    let mut driver = driver(&dir, DriverConfig::default(), 4);
    // The host's control streams: the request stream shared (§7a).
    let requests = driver
        .add_stream(stream(
            REQUESTS,
            PublicationMode::Concurrent {
                publishers: 2,
                allow_non_lse: true,
            },
        ))
        .unwrap();
    let responses = driver
        .add_stream(stream(RESPONSES, PublicationMode::Exclusive))
        .unwrap();
    let mut reading = driver.subscribe(requests, Role::Optional).unwrap();
    let mut answering = driver.publication(responses).unwrap();
    let agent = Agent::new(AgentConfig::new(vec![dir.clone()]).with_archive(
        dir.clone(),
        CatalogConfig::new(ArchiveStreams::new(REQUESTS, RESPONSES)).with_timing(
            Duration::from_secs(2),
            Duration::from_secs(5),
            Duration::from_millis(50),
        ),
    ));
    let descriptor = |correlation_id, recording_id| RecordingDescriptor {
        correlation_id,
        recording_id,
        start: 0,
        start_time_ns: recording_id,
        state: if recording_id == 3 {
            RecordingState::Recording {
                written: 4096,
                incomplete: false,
            }
        } else {
            RecordingState::Stopped(Stop {
                position: 100,
                time_ns: 2,
                reason: StopReason::Stopped,
                incomplete: false,
                closed_utc_ns: None,
            })
        },
        geometry: Geometry::new(MIN_TERM_LENGTH, 4 * u64::from(MIN_TERM_LENGTH)).unwrap(),
        source: SourceIncarnation {
            driver: [1, 2],
            registration: recording_id,
            incarnation: 1,
        },
        stream_id: 42,
        session_id: 1,
        channel: "karyos:ipc",
    };
    let mut out = vec![0u8; MAX_ANSWER];
    let mut answer = |message: &ControlMessage<'_>, driver: &mut IpcDriver| {
        let length = message.encode(&mut out).unwrap();
        while !matches!(
            answering.offer(&out[..length]),
            Ok(OfferOutcome::Accepted { .. })
        ) {
            let _ = driver.do_work().unwrap();
        }
    };
    let mut refused = false;
    let mut seen_refusal = false;
    let mut after_refusal = None;
    let start = Instant::now();
    let catalog = loop {
        assert!(start.elapsed() < Duration::from_secs(30), "no listing");
        let _ = driver.do_work().unwrap();
        let mut pages = Vec::new();
        let _ = reading.poll(
            |bytes, _| {
                if let Ok(ControlMessage::ListRecordings(list)) = ControlMessage::decode(bytes) {
                    pages.push((list.correlation_id, list.from_id, list.max_count));
                }
            },
            MessageLimit::new(8),
        );
        for (correlation_id, from_id, max_count) in pages {
            // REVIEWER-02's P3-1 on #488: the first page is refused.
            if !refused {
                refused = true;
                answer(
                    &ControlMessage::ControlResponse(ControlResponse {
                        correlation_id,
                        id: 0,
                        code: ResponseCode::Error,
                        message: "catalog busy",
                    }),
                    &mut driver,
                );
                continue;
            }
            after_refusal.get_or_insert(correlation_id);
            // Two per page at most, as an Archive may answer fewer.
            let ids: Vec<u64> = (from_id.max(1)..=3)
                .take(max_count.min(2) as usize)
                .collect();
            for &id in &ids {
                answer(
                    &ControlMessage::RecordingDescriptor(descriptor(correlation_id, id)),
                    &mut driver,
                );
            }
            answer(
                &ControlMessage::ControlResponse(ControlResponse {
                    correlation_id,
                    id: ids.len() as u64,
                    code: ResponseCode::Ok,
                    message: "",
                }),
                &mut driver,
            );
        }
        let catalog = agent.view().drivers[0].catalog.clone().unwrap();
        seen_refusal |= catalog
            .last_error
            .as_deref()
            .is_some_and(|error| error.starts_with("refused"));
        if catalog.listings > 0 {
            break catalog;
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    let ids: Vec<u64> = catalog.recordings.iter().map(|r| r.recording_id).collect();
    assert_eq!(ids, [1, 2, 3], "{catalog:?}");
    assert_eq!(catalog.left_out, 0);
    assert!(catalog.listed_at.is_some());
    // The refusal was counted, and the listing that followed cleared it.
    assert!(seen_refusal);
    assert_eq!(catalog.failures, 1);
    // On the same connection: its lister's next correlation id (a new
    // connection's would start at 1 again).
    assert_eq!(after_refusal.unwrap() & 0xFFFF_FFFF, 2);
    assert_eq!(catalog.last_error, None);
    let (stopped, live) = (&catalog.recordings[0], &catalog.recordings[2]);
    assert!(!stopped.recording);
    assert_eq!(
        (stopped.position, stopped.stop_reason.as_deref()),
        (100, Some("stopped"))
    );
    assert!(live.recording);
    assert_eq!((live.position, live.stopped_ns), (4096, None));
    assert_eq!(live.channel, "karyos:ipc");
    // A driver without `--archive` has no catalog.
    assert!(
        agent_without_archive(&dir).view().drivers[0]
            .catalog
            .is_none()
    );
    drop(agent);
    // Streams the host does not have: each attempt fails, is counted and
    // retried; nothing was listed.
    let missing = Agent::new(AgentConfig::new(vec![dir.clone()]).with_archive(
        dir.clone(),
        CatalogConfig::new(ArchiveStreams::new(200, 201)).with_timing(
            Duration::from_secs(2),
            Duration::from_secs(5),
            Duration::from_millis(20),
        ),
    ));
    let start = Instant::now();
    let catalog = loop {
        assert!(start.elapsed() < Duration::from_secs(30), "no failure");
        let _ = driver.do_work().unwrap();
        let catalog = missing.view().drivers[0].catalog.clone().unwrap();
        if catalog.failures >= 2 {
            break catalog;
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    assert_eq!(catalog.listings, 0);
    assert!(catalog.recordings.is_empty());
    let error = catalog.last_error.unwrap();
    assert!(error.starts_with("request stream:"), "{error}");
}

fn agent_without_archive(dir: &Path) -> Agent {
    Agent::new(AgentConfig::new(vec![dir.to_path_buf()]))
}

/// REVIEWER-02's P3-2 on #488: when the agent's refresh finds the driver
/// gone, the catalog's session ends at once and is counted, rather than
/// at its listing deadline (here a minute).
#[test]
fn a_driver_that_closes_ends_its_catalog_session_at_once() {
    use karyos_agent::catalog::{ArchiveStreams, CatalogConfig};
    use karyos_client::MessageLimit;
    use karyos_driver::{LossPolicy, StreamConfig};
    use karyos_sys::frame::Lane;
    use karyos_sys::log_buffer::{LogBufferConfig, PublicationMode, Role};
    use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
    use karyos_sys::term::TermId;

    let stream = |stream_id, publication| StreamConfig {
        buffer: LogBufferConfig {
            term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
            spare_slots: 6,
            max_subscribers: 4,
            mtu: DEFAULT_MTU,
            max_reserved: MIN_TERM_LENGTH / 8,
            initial_term_id: TermId::new(7),
            lane: Lane::ZERO,
            session_id: 1,
            stream_id,
            claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
            publication,
            schedule_capacity: 0,
        },
        allow_unconnected: true,
        on_required_loss: LossPolicy::Hold,
        conflation: None,
    };
    let _serial = serial();
    let dir = dir("catalog-gone");
    let mut driver = driver(&dir, DriverConfig::default(), 4);
    let requests = driver
        .add_stream(stream(
            100,
            PublicationMode::Concurrent {
                publishers: 2,
                allow_non_lse: true,
            },
        ))
        .unwrap();
    let _ = driver
        .add_stream(stream(101, PublicationMode::Exclusive))
        .unwrap();
    let mut reading = driver.subscribe(requests, Role::Optional).unwrap();
    let mut agent = Agent::new(
        AgentConfig::new(vec![dir.clone()])
            .with_attach_timeout(Duration::from_secs(5))
            .with_archive(
                dir.clone(),
                CatalogConfig::new(ArchiveStreams::new(100, 101)).with_timing(
                    Duration::from_secs(2),
                    Duration::from_secs(60),
                    Duration::from_secs(60),
                ),
            ),
    );
    refresh_serving(&mut driver, &mut agent);
    // The session is up once its first page is asked for; nobody answers.
    let start = Instant::now();
    let mut asked = 0;
    while asked == 0 {
        assert!(start.elapsed() < Duration::from_secs(30), "no request");
        let _ = driver.do_work().unwrap();
        let _ = reading.poll(|_, _| asked += 1, MessageLimit::new(8));
        std::thread::sleep(Duration::from_millis(1));
    }
    drop(reading);
    drop(driver);
    agent.refresh();
    assert_eq!(agent.view().drivers[0].state, DriverState::Closed);
    let start = Instant::now();
    loop {
        // Well within the minute the listing deadline would take.
        assert!(start.elapsed() < Duration::from_secs(10), "not ended");
        let catalog = agent.view().drivers[0].catalog.clone().unwrap();
        if catalog.failures > 0 {
            assert_eq!(catalog.last_error.as_deref(), Some("the driver closed"));
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// R-CORE-17 (karyos#737): a new driver instance restarts every datum's
/// series, the driver counters' and the client counters', so nothing the
/// old instance changed carries a `changed_ns` into the new one.
#[test]
fn test_agent_a_new_instance_restarts_every_series() {
    let _serial = serial();
    let dir = dir("series");
    let mut driver = driver(&dir, DriverConfig::default(), 1);
    let mut agent = agent(&[&dir]);
    for _ in 0..4 {
        refresh_serving(&mut driver, &mut agent);
    }
    let view = agent.view();
    let counters = &view.drivers[0].sample.as_ref().unwrap().counters;
    assert!(
        counters.iter().all(|counter| counter.read_ns > 0),
        "every counter carries its read time"
    );
    drop(driver);
    agent.refresh();
    let mut driver = self::driver(&dir, DriverConfig::default(), 1);
    refresh_serving(&mut driver, &mut agent);
    let view = agent.view();
    assert_eq!(view.drivers[0].instance, driver.instance());
    let sample = view.drivers[0].sample.as_ref().unwrap();
    assert!(
        sample
            .counters
            .iter()
            .all(|counter| counter.changed_ns.is_none()),
        "a counter of the new instance joined an old series: {:?}",
        sample
            .counters
            .iter()
            .filter(|c| c.changed_ns.is_some())
            .collect::<Vec<_>>()
    );
    assert!(
        view.drivers[0]
            .client_counters
            .iter()
            .all(|counter| counter.changed_ns.is_none())
    );
}

/// R-CORE-13: the export's epoch is the driver instance, so a cursor
/// survives the agent's restart (the agent keeps none) and is refused,
/// with the new instance, after the driver's.
#[test]
fn an_export_cursor_survives_the_agent_and_not_the_driver() {
    use karyos_agent::api::ExportRefusal;

    let _serial = serial();
    let dir = dir("export");
    let mut driver = driver(&dir, DriverConfig::default(), 2);
    let mut agent = agent(&[&dir]);
    refresh_serving(&mut driver, &mut agent);
    let page = agent.trace_export(&dir, 0, 16, None).unwrap().unwrap();
    assert_eq!(Some(page.epoch), agent.view().drivers[0].instance);
    assert_eq!(Some(page.epoch), driver.instance());
    assert!(page.lost.is_empty());
    let cursor = (page.epoch, page.next);
    // A new agent: the same cursor is served, from where it was.
    drop(agent);
    let mut agent = self::agent(&[&dir]);
    refresh_serving(&mut driver, &mut agent);
    let page = agent
        .trace_export(&dir, cursor.1, 16, Some(cursor.0))
        .unwrap()
        .unwrap();
    assert_eq!((page.epoch, page.from), cursor);
    assert!(page.lost.is_empty());
    // A new driver: the cursor is refused, with the new instance.
    drop(driver);
    agent.refresh();
    let mut driver = self::driver(&dir, DriverConfig::default(), 2);
    refresh_serving(&mut driver, &mut agent);
    assert_eq!(
        agent
            .trace_export(&dir, cursor.1, 16, Some(cursor.0))
            .unwrap(),
        Err(ExportRefusal::EpochChanged {
            epoch: driver.instance().unwrap()
        })
    );
}

/// karyos#967 (ADR-0088, Proposed) end to end: the agent's Archive
/// retention backend reaches an Archive over a driver's control streams.
/// A fake Archive on this thread answers a hold as applied without
/// evidence (code 6), refuses a purge under a hold with `legal_hold`
/// (code 8), and answers a verification with two ranges; each comes back
/// verbatim. A purge for uid 0 is refused by the backend and never sent.
#[test]
fn the_retention_backend_reaches_an_archive_over_its_control_streams() {
    use karyos_agent::archive_retention::ArchiveRetention;
    use karyos_agent::catalog::ArchiveStreams;
    use karyos_agent::retention::{RangeOutcome, RetentionBackend, RetentionReply};
    use karyos_archive::control::{
        ControlMessage, ControlResponse, IntegrityOutcome, NO_INCONSISTENT,
        RangeOutcome as WireRange, ResponseCode,
    };
    use karyos_archive::server::MAX_ANSWER;
    use karyos_client::{MessageLimit, OfferOutcome};
    use karyos_driver::{LossPolicy, StreamConfig};
    use karyos_sys::frame::Lane;
    use karyos_sys::log_buffer::{LogBufferConfig, PublicationMode, Role};
    use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
    use karyos_sys::term::TermId;

    const REQUESTS: i32 = 100;
    const RESPONSES: i32 = 101;
    let stream = |stream_id, publication| StreamConfig {
        buffer: LogBufferConfig {
            term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
            spare_slots: 6,
            max_subscribers: 4,
            mtu: DEFAULT_MTU,
            max_reserved: MIN_TERM_LENGTH / 8,
            initial_term_id: TermId::new(7),
            lane: Lane::ZERO,
            session_id: 1,
            stream_id,
            claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
            publication,
            schedule_capacity: 0,
        },
        allow_unconnected: true,
        on_required_loss: LossPolicy::Hold,
        conflation: None,
    };
    let _serial = serial();
    let dir = dir("retention");
    let mut driver = driver(&dir, DriverConfig::default(), 4);
    let requests = driver
        .add_stream(stream(
            REQUESTS,
            PublicationMode::Concurrent {
                publishers: 2,
                allow_non_lse: true,
            },
        ))
        .unwrap();
    let responses = driver
        .add_stream(stream(RESPONSES, PublicationMode::Exclusive))
        .unwrap();
    let mut reading = driver.subscribe(requests, Role::Optional).unwrap();
    let mut answering = driver.publication(responses).unwrap();
    let mut out = vec![0u8; MAX_ANSWER];
    // Runs `call` on a thread of its own while this thread serves the
    // driver and answers as the fake Archive.
    let mut serve = |call: Box<dyn FnOnce() -> String + Send>, driver: &mut IpcDriver| {
        let worker = std::thread::spawn(call);
        let start = Instant::now();
        while !worker.is_finished() {
            assert!(start.elapsed() < Duration::from_secs(30), "no answer");
            let _ = driver.do_work().unwrap();
            let mut asked = Vec::new();
            let _ = reading.poll(
                |bytes, _| {
                    if let Ok(message) = ControlMessage::decode(bytes) {
                        let mut copy = vec![0u8; MAX_ANSWER];
                        let length = message.encode(&mut copy).unwrap();
                        copy.truncate(length);
                        asked.push(copy);
                    }
                },
                MessageLimit::new(8),
            );
            for bytes in asked {
                let answers: Vec<ControlMessage<'_>> = match ControlMessage::decode(&bytes).unwrap()
                {
                    ControlMessage::HoldRecording(hold) => {
                        vec![ControlMessage::ControlResponse(ControlResponse {
                            correlation_id: hold.correlation_id,
                            id: 0,
                            code: ResponseCode::HeldWithoutEvidence,
                            message: "",
                        })]
                    }
                    ControlMessage::PurgeRecording(purge) => {
                        assert_eq!(
                            (purge.before, purge.request_id, purge.operator),
                            (4096, 9, 1000)
                        );
                        vec![ControlMessage::ControlResponse(ControlResponse {
                            correlation_id: purge.correlation_id,
                            id: 0,
                            code: ResponseCode::Refused,
                            message: "legal_hold",
                        })]
                    }
                    ControlMessage::VerifyRecording(verify) => {
                        let range = |start, end, reasons, outcome| {
                            ControlMessage::RangeOutcome(WireRange {
                                correlation_id: verify.correlation_id,
                                recording_id: verify.recording_id,
                                start,
                                end,
                                first_inconsistent: NO_INCONSISTENT,
                                reasons,
                                outcome,
                            })
                        };
                        vec![
                            range(0, 4096, 0, IntegrityOutcome::Verified),
                            range(4096, 8192, 1 << 9, IntegrityOutcome::BeyondAnchor),
                            ControlMessage::ControlResponse(ControlResponse {
                                correlation_id: verify.correlation_id,
                                id: 2,
                                code: ResponseCode::Ok,
                                message: "",
                            }),
                        ]
                    }
                    other => panic!("{other:?}"),
                };
                for message in answers {
                    let length = message.encode(&mut out).unwrap();
                    while !matches!(
                        answering.offer(&out[..length]),
                        Ok(OfferOutcome::Accepted { .. })
                    ) {
                        let _ = driver.do_work().unwrap();
                    }
                }
            }
            std::thread::sleep(Duration::from_micros(200));
        }
        worker.join().unwrap()
    };
    let backend = ArchiveRetention::new(dir.clone(), ArchiveStreams::new(REQUESTS, RESPONSES))
        .with_deadline(Duration::from_secs(10));
    let mut hold = backend.clone();
    let answer = serve(
        Box::new(move || format!("{:?}", hold.hold(42, 1, 1000))),
        &mut driver,
    );
    assert_eq!(
        answer,
        format!("{:?}", RetentionReply::Done { evidenced: false })
    );
    let mut purge = backend.clone();
    let answer = serve(
        Box::new(move || format!("{:?}", purge.purge(42, 4096, 9, 1000))),
        &mut driver,
    );
    assert_eq!(
        answer,
        format!(
            "{:?}",
            RetentionReply::Refused {
                code: 8,
                reason: "legal_hold".to_owned()
            }
        )
    );
    let mut verify = backend.clone();
    let answer = serve(
        Box::new(move || format!("{:?}", verify.verify(42))),
        &mut driver,
    );
    let expected = vec![
        RangeOutcome {
            start: 0,
            end: 4096,
            outcome: "verified".to_owned(),
            reasons: Vec::new(),
        },
        RangeOutcome {
            start: 4096,
            end: 8192,
            outcome: "beyond_anchor".to_owned(),
            reasons: vec!["no_anchor".to_owned()],
        },
    ];
    assert_eq!(answer, format!("{:?}", Some(expected)));
    let mut root = backend;
    assert!(matches!(
        root.purge(42, 4096, 9, 0),
        RetentionReply::Refused { code: 4, .. }
    ));
}
