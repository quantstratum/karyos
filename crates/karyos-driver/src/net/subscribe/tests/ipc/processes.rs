// SPDX-License-Identifier: Apache-2.0

//! Image grants held by remote subscriber processes (network-shared-terms
//! n5, cases 3 and 4; the other cases are in
//! `tests/network_processes.rs`). Each child is this lib test binary run
//! again with `--ignored --exact` on [`child`]; it attaches to the IPC
//! driver, takes the image's grant and holds it, reporting on stdout. The
//! parent reads the image table's counters, which only the crate's tests
//! see.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};

use super::*;
use crate::agents::AgentConfig;
use crate::agents::images::ImageCounters;
use crate::embedded::StreamState;

const SCENARIO: &str = "KARYOS_N5_IMAGE_CHILD";
const DIR: &str = "KARYOS_N5_IMAGE_DIR";

/// A one-lane image of 64 KiB terms: `64 KiB * (3 + 5 spare slots)`.
const IMAGE_CHARGE: u64 = 8 * 65_536;

/// A child process, killed when the test ends however it ends.
struct Guard(Child);

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A child running `scenario` against the IPC driver in `dir`, its stdout
/// lines delivered on a channel.
fn spawn(scenario: &str, dir: &Path) -> (Guard, Receiver<String>) {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "net::subscribe::tests::ipc::processes::child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(SCENARIO, scenario)
        .env(DIR, dir)
        .stdout(Stdio::piped())
        // A child's panic shows in the test's log.
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if let Some(at) = line.find("child: ") {
                let _ = sender.send(line[at + "child: ".len()..].to_string());
            }
        }
    });
    (Guard(child), receiver)
}

/// Sends a signal by name with the system `kill` tool (no libc).
fn signal(child: &Child, name: &str) {
    let status = Command::new("kill")
        .args([format!("-{name}"), child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
}

fn image_table(b: &IpcDriver) -> (ImageCounters, u64) {
    let net = b.net.as_ref().unwrap();
    (net.image_counters(), net.image_charge())
}

/// The receiver's retired images whose `StorageReclaimed` it handled.
fn reclaimed_tombstones(b: &IpcDriver) -> usize {
    b.net
        .as_ref()
        .unwrap()
        .receiver_reclaimed_tombstones()
        .unwrap()
}

fn grants_ended(b: &IpcDriver) -> u64 {
    b.counters.value(crate::counters::Event::GrantsEnded)
}

/// Runs both drivers until the child reports `expected`.
fn pump_until_report<P: StreamTerms>(
    a: &mut EmbeddedDriver<P>,
    b: &mut IpcDriver,
    reports: &Receiver<String>,
    expected: &str,
) {
    let mut found = false;
    pump(a, b, |_| {
        if let Ok(report) = reports.try_recv() {
            assert_eq!(report, expected);
            found = true;
        }
        found
    });
}

/// A publisher whose SETUP repeats every 2 s, so one refusal of its image
/// is counted once before the test acts on it.
fn slow_setup_driver() -> EmbeddedDriver {
    EmbeddedDriver::with_config(DriverConfig {
        network: Some(NetworkConfig {
            threading: ThreadingMode::Shared,
            agents: AgentConfig {
                setup_interval: 2_000_000_000,
                ..AgentConfig::default()
            },
            ..NetworkConfig::default()
        }),
        ..DriverConfig::default()
    })
    .unwrap()
}

/// Case 3: a remote subscriber process killed while it holds the grant of
/// a retired image. The grant keeps the image's stream, so its storage
/// stays charged; the exit proof ends the grant, the stream frees, the
/// image is reclaimed (`StorageReclaimed` posted) and the charge returns
/// to its value before the image.
#[test]
fn a_killed_remote_subscriber_of_an_image_is_reclaimed_at_its_exit_proof() {
    let dir = dir("p-killed");
    let (mut a, mut b) = (driver(ThreadingMode::Shared), ipc_driver(&dir));
    let (_, charge_before) = image_table(&b);
    let (publication, image, _subscription) = exposed(&mut a, &mut b, 1);
    let stream = image.lane(Lane::ZERO).unwrap();
    let (counters, charged) = image_table(&b);
    assert_eq!(charged, charge_before + IMAGE_CHARGE);
    let (mut child, reports) = spawn("hold-image", &dir);
    pump_until_report(&mut a, &mut b, &reports, "holding");
    // The image retires at the publication's EOS; the grant keeps it.
    a.remove_aggregate(&publication).unwrap();
    pump(&mut a, &mut b, |b| {
        image_table(b).0.retired == counters.retired + 1
    });
    for _ in 0..2_000 {
        let _ = a.do_work().unwrap();
        let _ = b.do_work().unwrap();
    }
    let (held, held_charge) = image_table(&b);
    assert_eq!(held.reclaimed, counters.reclaimed);
    // Nothing reached the receiver: its tombstone is not reclaimed, and
    // no other image retired before it.
    let tombstones = reclaimed_tombstones(&b);
    assert_eq!(tombstones, 0);
    assert_eq!(held_charge, charged);
    assert_eq!(b.stream_state(stream).unwrap(), StreamState::Retiring);
    let ended = grants_ended(&b);
    child.0.kill().unwrap();
    let _ = child.0.wait();
    pump(&mut a, &mut b, |b| b.clients() == 0);
    // The post itself: the receiver handled `StorageReclaimed` for the
    // retired image (its tombstone waits out the alias quarantine, 10 s).
    pump(&mut a, &mut b, |b| {
        reclaimed_tombstones(b) == tombstones + 1
    });
    assert_eq!(image_table(&b).0.reclaimed, counters.reclaimed + 1);
    assert_eq!(grants_ended(&b), ended + 1);
    let (reclaimed, charge_after) = image_table(&b);
    assert_eq!(reclaimed.reclaimed, counters.reclaimed + 1);
    assert_eq!(charge_after, charge_before);
    assert_eq!(b.stream_state(stream).unwrap(), StreamState::Freed);
    let _ = (a.close_network(), b.close_network());
}

/// Case 4: a remote subscriber process stopped (`SIGSTOP`) while it holds
/// an image's grant, when the image retires. The storage stays charged
/// while it is stopped, so a new image over the remaining budget (one
/// image) is refused for budget. The stopped client outlives its liveness
/// timeout (1 s here): it is timed out, but its sent grant stays charged
/// (only the exit proof ends a sent grant), so the image is still
/// refused. After the exit proof of the killed process, that image is
/// admitted.
#[test]
fn a_stopped_remote_subscriber_keeps_an_image_charged_past_its_liveness() {
    let dir = dir("p-stopped");
    let mut network = NetworkConfig {
        threading: ThreadingMode::Shared,
        ..NetworkConfig::default()
    };
    network.images.storage_budget = IMAGE_CHARGE;
    // Liveness at its least, ten heartbeats: crossed in a second.
    let config = DriverConfig {
        network: Some(network),
        heartbeat_interval: 100_000_000,
        client_liveness_timeout: 1_000_000_000,
        ..DriverConfig::default()
    };
    let (mut a, mut b) = (slow_setup_driver(), ipc_driver_configured(&dir, config));
    let (publication, _image, subscription) = exposed(&mut a, &mut b, 1);
    let (counters, charged) = image_table(&b);
    assert_eq!(charged, IMAGE_CHARGE);
    let (mut child, reports) = spawn("hold-image", &dir);
    pump_until_report(&mut a, &mut b, &reports, "holding");
    let timed_out = b.counters.value(crate::counters::Event::ClientsTimedOut);
    signal(&child.0, "STOP");
    a.remove_aggregate(&publication).unwrap();
    pump(&mut a, &mut b, |b| {
        image_table(b).0.retired == counters.retired + 1
    });
    assert_eq!(image_table(&b).1, IMAGE_CHARGE, "charged while stopped");
    // A new image of another session: over the remaining budget.
    let address = b
        .network_subscription_address(subscription.stream_id())
        .unwrap();
    let _second = a
        .add_network_publication(aggregate(10, 4, 1), &channel(address))
        .unwrap();
    pump(&mut a, &mut b, |b| {
        image_table(b).0.refused_budget > counters.refused_budget
    });
    // Past the liveness timeout and the publisher's next SETUP (2 s): the
    // client is timed out, and the grant still keeps the storage.
    pump(&mut a, &mut b, |b| {
        b.counters.value(crate::counters::Event::ClientsTimedOut) == timed_out + 1
    });
    let start = Instant::now();
    pump(&mut a, &mut b, |_| {
        start.elapsed() > Duration::from_millis(2_500)
    });
    let (stopped, charge) = image_table(&b);
    assert_eq!(charge, IMAGE_CHARGE, "still charged past liveness");
    assert_eq!(stopped.reclaimed, counters.reclaimed, "not reclaimed");
    assert!(stopped.refused_budget > counters.refused_budget);
    assert!(b.exposed_network_image(10, 4).is_none());
    // The exit proof: killed while stopped.
    child.0.kill().unwrap();
    let _ = child.0.wait();
    pump(&mut a, &mut b, |b| b.clients() == 0);
    pump(&mut a, &mut b, |b| b.exposed_network_image(10, 4).is_some());
    let (after, charge) = image_table(&b);
    assert_eq!(after.reclaimed, counters.reclaimed + 1);
    assert_eq!(charge, IMAGE_CHARGE, "the new image's charge only");
    let _ = (a.close_network(), b.close_network());
}

fn report(line: &str) {
    // A newline first: libtest may have started a line without ending it.
    let mut stdout = std::io::stdout();
    writeln!(stdout, "\nchild: {line}").unwrap();
    stdout.flush().unwrap();
}

/// The child of the tests above; a no-op outside them.
#[test]
#[ignore = "run by the image process tests above"]
fn child() {
    let (Some(scenario), Some(dir)) = (std::env::var_os(SCENARIO), std::env::var_os(DIR)) else {
        return;
    };
    let dir = PathBuf::from(dir);
    match scenario.to_str().unwrap() {
        "hold-image" => {
            let mut client = attach(&dir, Duration::from_secs(5), 16).unwrap();
            let key = StreamKey {
                stream_id: 10,
                session_id: 3,
            };
            let _ = client
                .add_subscription(key, SubscriberRole::Required)
                .unwrap();
            let mut grant = None;
            let start = Instant::now();
            while grant.is_none() {
                assert!(start.elapsed() < Duration::from_secs(10), "no grant");
                let _ = client.poll(usize::MAX, |completion| match completion.outcome {
                    Outcome::Fetchable(fetchable) => grant = Some(fetchable),
                    other => panic!("expected a grant, got {other:?}"),
                });
                std::thread::yield_now();
            }
            let subscription = client.take_subscription(&grant.unwrap()).unwrap();
            report("holding");
            // Held until killed; bounded, so a failed parent never leaves
            // this process behind.
            std::mem::forget(subscription);
            std::mem::forget(client);
            std::thread::sleep(Duration::from_secs(30));
            std::process::exit(1);
        }
        other => panic!("unknown scenario {other}"),
    }
}
