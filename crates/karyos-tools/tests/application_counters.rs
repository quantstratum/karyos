// SPDX-License-Identifier: Apache-2.0

//! R-CORE-3 end to end (Linux): a remote application registers a counter
//! and a gauge with `Client::add_counter`, updates them, and `karyos-stat`
//! and the management agent's Prometheus exposition both show them with
//! their labels and values.

#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use karyos_agent::{Agent, AgentConfig};
use karyos_client::{Client, Context, CounterKind, IdleStrategy};
use karyos_driver::{DriverConfig, EmbeddedDriver, IpcConfig, SystemClock};
use karyos_sys::term_bytes::SharedTerms;

type IpcDriver = EmbeddedDriver<SharedTerms>;

fn dir(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("karyos-appcounters-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn driver(dir: &Path) -> IpcDriver {
    EmbeddedDriver::with_ipc(
        DriverConfig::default(),
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
            max_tools: 4,
            client_send_buffer: None,
        },
        Box::new(SystemClock::new()),
    )
    .unwrap()
}

/// Runs `work` on another thread while serving `driver` on this one.
fn serving<R: Send>(driver: &mut IpcDriver, work: impl FnOnce() -> R + Send) -> R {
    std::thread::scope(|scope| {
        let handle = scope.spawn(work);
        let start = Instant::now();
        while !handle.is_finished() {
            assert!(start.elapsed() < Duration::from_secs(30), "stuck");
            let _ = driver.do_work().unwrap();
            std::thread::sleep(Duration::from_micros(200));
        }
        handle.join().unwrap()
    })
}

#[test]
fn an_application_counter_reaches_karyos_stat_and_the_exporter() {
    let dir = dir("e2e");
    let mut driver = driver(&dir);
    let context = Context::builder()
        .dir(&dir)
        .idle_strategy(IdleStrategy::Sleep(Duration::from_micros(100)))
        .build()
        .unwrap();
    let (client, orders, depth) = serving(&mut driver, || {
        let mut client = Client::connect(context).unwrap();
        let orders = client
            .add_counter("orders \"filled\"", CounterKind::Event)
            .unwrap();
        let depth = client
            .add_counter("queue depth", CounterKind::Gauge)
            .unwrap();
        (client, orders, depth)
    });
    assert_eq!(orders.increment(40), Ok(40));
    assert_eq!(orders.increment(2), Ok(42));
    depth.set(7);

    // karyos-stat: under the application counters, with their values.
    let now = karyos_sys::host_clock::host_monotonic_ns();
    let text = karyos_tools::stat::report(&driver.counters(), &driver.client_counters(), now);
    let (_, applications) = text.split_once("application counters:\n").unwrap();
    assert!(applications.contains("  client "), "{text}");
    for (label, value) in [("orders \"filled\"", 42), ("queue depth", 7)] {
        assert!(
            applications.contains(&format!("    {label:<40} {value}\n")),
            "{label}: {text}"
        );
    }

    // The agent's exposition: each in its family, the name escaped.
    let mut agent =
        Agent::new(AgentConfig::new(vec![dir.clone()]).with_attach_timeout(Duration::from_secs(5)));
    serving(&mut driver, || agent.refresh());
    let text = karyos_agent::exporter::render(&agent.view());
    let driver_label = format!("driver=\"{}\"", dir.display());
    let events = text
        .lines()
        .find(|line| line.starts_with("karyos_application_events_total{"))
        .unwrap_or_else(|| panic!("{text}"));
    assert!(events.starts_with(&format!("karyos_application_events_total{{{driver_label},name=\"orders \\\"filled\\\"\",client=\"")), "{events}");
    assert!(events.ends_with("} 42"), "{events}");
    let gauge = text
        .lines()
        .find(|line| line.starts_with("karyos_application_gauge{"))
        .unwrap_or_else(|| panic!("{text}"));
    assert!(gauge.contains("name=\"queue depth\""), "{gauge}");
    assert!(gauge.ends_with("} 7"), "{gauge}");
    drop((orders, depth, client));
}
