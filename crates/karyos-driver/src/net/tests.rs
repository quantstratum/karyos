// SPDX-License-Identifier: Apache-2.0

//! The conductor's network: start, duty, failure and shutdown.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "tests, as ADR-0007 allows"
)]

use std::net::SocketAddr;
use std::time::Duration;

use karyos_io::sockets::OsSocket;
use karyos_io::sockets::endpoint::SocketsConfig;

use super::NetworkConfig;
use crate::agents::{AgentCommand, AgentKind, ThreadingMode};
use crate::embedded::{DriverConfig, EmbeddedDriver};
use crate::error::DriverError;

fn driver(threading: ThreadingMode) -> EmbeddedDriver {
    EmbeddedDriver::with_config(DriverConfig {
        network: Some(NetworkConfig {
            threading,
            ..NetworkConfig::default()
        }),
        ..DriverConfig::default()
    })
    .unwrap()
}

/// Opens a loopback endpoint through the conductor's table and runs duty
/// cycles until both agents hold its halves.
fn open_endpoint(driver: &mut EmbeddedDriver) {
    let net = driver.net.as_mut().unwrap();
    let (endpoints, links) = net.endpoints_mut();
    let loopback = SocketsConfig::new(SocketAddr::from(([127, 0, 0, 1], 0)));
    let endpoint = endpoints.open(links, loopback, OsSocket::new()).unwrap();
    for _ in 0..2000 {
        let _ = driver.do_work().unwrap();
        let net = driver.net.as_mut().unwrap();
        if net.endpoints_mut().0.is_active(endpoint) {
            return;
        }
        std::thread::sleep(Duration::from_micros(200));
    }
    panic!("the endpoint never became active");
}

/// Without a network configuration nothing starts and there is nothing to
/// close.
#[test]
fn a_driver_without_network_starts_no_agent() {
    let mut driver = EmbeddedDriver::new().unwrap();
    assert!(driver.net.is_none());
    let _ = driver.do_work().unwrap();
    assert!(driver.close_network().is_none());
}

/// In every threading mode the agents serve the conductor's commands
/// through the duty cycle, and closing reclaims the endpoint cleanly.
#[test]
fn the_duty_cycle_serves_the_agents_in_every_mode() {
    for mode in [
        ThreadingMode::Shared,
        ThreadingMode::SharedNetwork,
        ThreadingMode::Dedicated,
    ] {
        let mut driver = driver(mode);
        assert!(driver.net.as_ref().unwrap().is_running());
        open_endpoint(&mut driver);
        let shutdown = driver.close_network().unwrap();
        assert!(shutdown.agents_stopped, "{mode:?}");
        assert_eq!(shutdown.endpoints_retired, 1, "{mode:?}");
        assert!(shutdown.failures.is_empty(), "{mode:?}: {shutdown:?}");
        assert!(shutdown.late.is_empty(), "{mode:?}");
        assert!(driver.close_network().is_none(), "closed once");
        // The driver keeps working without its network.
        let _ = driver.do_work().unwrap();
    }
}

/// DN-9: an agent thread that panics is fatal for the driver; the duty
/// cycle reports which agent failed, and closing still reclaims it.
#[test]
fn a_failed_agent_fails_the_duty_cycle() {
    let mut driver = driver(ThreadingMode::Dedicated);
    driver
        .net
        .as_ref()
        .unwrap()
        .links()
        .receiver
        .post(|_reply| AgentCommand::Panic)
        .unwrap();
    let mut failed = None;
    for _ in 0..2000 {
        if let Err(error) = driver.do_work() {
            failed = Some(error);
            break;
        }
        std::thread::sleep(Duration::from_micros(200));
    }
    assert_eq!(
        failed,
        Some(DriverError::NetworkAgent {
            agent: AgentKind::Receiver
        })
    );
    let shutdown = driver.close_network().unwrap();
    assert!(!shutdown.failures.is_empty());
    assert!(shutdown.late.is_empty());
}

/// DN-9 in `Shared` mode: an agent that panics on the conductor's thread
/// is caught as on a runner thread, the error is latched, the failed agent
/// never runs again, and closing and dropping the driver do not panic.
#[test]
fn a_shared_agent_panic_is_a_driver_error() {
    let mut driver = driver(ThreadingMode::Shared);
    driver
        .net
        .as_ref()
        .unwrap()
        .links()
        .sender
        .post(|_reply| AgentCommand::Panic)
        .unwrap();
    let failed = Err(DriverError::NetworkAgent {
        agent: AgentKind::Sender,
    });
    assert_eq!(driver.do_work(), failed);
    assert_eq!(driver.do_work(), failed, "latched");
    let shutdown = driver.close_network().unwrap();
    assert!(shutdown.late.is_empty());
    drop(driver);
}

/// Dropping a driver whose agent thread does not stop in time joins it
/// instead of detaching it (wiring note W-g).
#[test]
fn dropping_the_driver_joins_a_late_agent() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
    use std::time::Instant;

    let mut network = NetworkConfig {
        threading: ThreadingMode::Dedicated,
        ..NetworkConfig::default()
    };
    network.agents.stop_timeout = Duration::from_millis(1);
    let driver = EmbeddedDriver::with_config(DriverConfig {
        network: Some(network),
        ..DriverConfig::default()
    })
    .unwrap();
    let gate = Arc::new(AtomicU8::new(crate::agents::BLOCK_ARMED));
    let command = Arc::clone(&gate);
    driver
        .net
        .as_ref()
        .unwrap()
        .links()
        .sender
        .post(|_reply| AgentCommand::Block(command))
        .unwrap();
    // The sender is blocked for certain before the drop (karyos#1067,
    // #1268 review): its gate says so, no fixed wait.
    let deadline = Instant::now() + Duration::from_secs(30);
    while gate.load(Ordering::Acquire) != crate::agents::BLOCK_ENTERED {
        assert!(Instant::now() < deadline, "the sender never blocked");
        std::thread::yield_now();
    }
    // Released only once the drop started and its 1 ms stop timeout has
    // long passed, so the stop has classified the sender late; the instant
    // of the release is recorded.
    let dropping = Arc::new(AtomicBool::new(false));
    let released = Arc::new(std::sync::Mutex::new(None::<Instant>));
    let releaser = {
        let (gate, dropping, released) = (
            Arc::clone(&gate),
            Arc::clone(&dropping),
            Arc::clone(&released),
        );
        std::thread::spawn(move || {
            while !dropping.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            std::thread::sleep(Duration::from_millis(100));
            *released.lock().unwrap() = Some(Instant::now());
            gate.store(crate::agents::BLOCK_RELEASED, Ordering::Release);
        })
    };
    dropping.store(true, Ordering::Release);
    drop(driver);
    let returned = Instant::now();
    // The drop returned only after the release: a driver that detached the
    // late sender would have returned at once, before it. (The releaser
    // drops its own handle on the gate when it ends, so a count taken here
    // would race; the count below is checked once it is joined.)
    releaser.join().unwrap();
    let released = released.lock().unwrap().expect("never released");
    assert!(returned >= released, "the drop returned before the release");
    assert_eq!(Arc::strong_count(&gate), 1);
}

/// Dropping a driver with running agent threads stops them.
#[test]
fn dropping_the_driver_stops_its_agents() {
    let mut driver = driver(ThreadingMode::Dedicated);
    open_endpoint(&mut driver);
    drop(driver);
}

/// An agent configuration the agents refuse fails the driver's start.
#[test]
fn an_invalid_agent_configuration_is_refused() {
    let mut network = NetworkConfig::default();
    network.agents.command_capacity = 0;
    let built = EmbeddedDriver::with_config(DriverConfig {
        network: Some(network),
        ..DriverConfig::default()
    });
    assert!(matches!(built, Err(DriverError::InvalidConfig)));
}
