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
