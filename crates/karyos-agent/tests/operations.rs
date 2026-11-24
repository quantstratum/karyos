// SPDX-License-Identifier: Apache-2.0

//! Audited guard operations through the agent's socket (Linux;
//! quantstratum-docs: karyos/design/management-agent-gap-analysis.md,
//! M10b): a request of a role that may make it reaches the driver for the
//! peer's uid, journalled before and after; a role that may not is
//! refused; a reopen without a journal is refused and never sent; an
//! unknown interval is acknowledged by an administrator only. The local
//! rest of SPEC §13's Audited operations row: a close while the journal
//! is down goes ahead and leaves an unknown interval, and so does an agent
//! host that fails during a close.

#![cfg(target_os = "linux")]
// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use karyos_agent::journal::{Journal, JournalRecord, Kind};
use karyos_agent::server::{ApiConfig, Principal, Role, Served, Server};
use karyos_agent::{Agent, AgentConfig};
use karyos_driver::guards::Requester;
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
    let dir = std::env::temp_dir().join(format!("karyos-ops-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
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

fn own() -> u32 {
    karyos_sys::ipc::own_uid()
}

/// Sends `request` from one thread and serves it from another, while this
/// thread serves `driver`; the answer and how it was served.
fn ask(
    driver: &mut IpcDriver,
    server: &mut Server,
    agent: &mut Agent,
    request: &str,
) -> (String, Vec<Served>) {
    let path = server.path().to_path_buf();
    std::thread::scope(|scope| {
        let client = scope.spawn(move || {
            let mut stream = UnixStream::connect(path).unwrap();
            stream.write_all(request.as_bytes()).unwrap();
            let mut answer = String::new();
            let _ = stream.read_to_string(&mut answer).unwrap();
            answer
        });
        let serving = scope.spawn(|| {
            let start = Instant::now();
            loop {
                let served = server.poll(agent).unwrap();
                if !served.is_empty() {
                    return served;
                }
                assert!(start.elapsed() < Duration::from_secs(10), "never served");
                std::thread::sleep(Duration::from_millis(1));
            }
        });
        let start = Instant::now();
        while !serving.is_finished() || !client.is_finished() {
            assert!(start.elapsed() < Duration::from_secs(30), "stuck");
            let _ = driver.do_work().unwrap();
            std::thread::sleep(Duration::from_micros(200));
        }
        (client.join().unwrap(), serving.join().unwrap())
    })
}

fn agent(dir: &Path, journal: bool) -> Agent {
    let mut config =
        AgentConfig::new(vec![dir.join("driver")]).with_attach_timeout(Duration::from_secs(5));
    if journal {
        config = config.with_journal(dir.join("journal"));
    }
    Agent::new(config)
}

/// A risk officer reopens and closes a guard: each reaches the driver for
/// the peer's uid and answers with the guard's state, and the journal holds
/// a request and an outcome record for each, with no unknown interval.
#[test]
fn a_risk_officer_reopens_and_closes_a_guard_journalled() {
    let _serial = serial();
    let dir = dir("operate");
    let mut driver = driver(&dir.join("driver"));
    let guard = driver.add_guard("orders").unwrap().id();
    let mut agent = agent(&dir, true);
    let mut server = Server::bind(ApiConfig::new(
        dir.join("api"),
        vec![(own(), Role::RiskOfficer)],
    ))
    .unwrap();
    let driver_dir = dir.join("driver");
    let request = format!(
        "KARYOS-AGENT 1 guard-reopen {} {guard} 1 start of day\n",
        driver_dir.display()
    );
    let (answer, served) = ask(&mut driver, &mut server, &mut agent, &request);
    assert_eq!(served, [Served::Operated]);
    assert!(
        answer.ends_with(&format!(
            "\"guard\":{guard},\"state\":{{\"epoch\":2,\"open\":true}}}}\n"
        )),
        "{answer}"
    );
    let request = format!(
        "KARYOS-AGENT 1 guard-close {} {guard}\n",
        driver_dir.display()
    );
    let (answer, _) = ask(&mut driver, &mut server, &mut agent, &request);
    assert!(
        answer.contains(r#""state":{"epoch":3,"open":false}"#),
        "{answer}"
    );
    // The driver audited both for this uid, through the agent's client.
    let audit = driver.guard_audit();
    let operators: Vec<_> = audit
        .records
        .iter()
        .map(|record| match record.requester {
            Requester::Operator { uid, .. } => uid,
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(operators, [u64::from(own()), u64::from(own())]);
    let view = agent.view();
    let journal = view.journal.unwrap();
    assert_eq!((journal.failed_appends, journal.gap), (0, None));
    assert!(!journal.unavailable && journal.unsealed);
    // A clean stop (kind 7): the next start records no unknown interval.
    agent.stop().unwrap();
    drop(agent);
    // Four records, each request answered: no unknown interval at start.
    let reopened = Journal::open(&dir.join("journal"), 1).unwrap();
    assert_eq!(reopened.gap(), None);
}

/// A role that may not make an operation is refused before anything is
/// sent; a reopen with no journal is refused and never reaches the driver.
#[test]
fn operations_beyond_the_role_or_without_a_journal_are_refused() {
    let _serial = serial();
    let dir = dir("refused");
    let mut driver = driver(&dir.join("driver"));
    let guard = driver.add_guard("orders").unwrap().id();
    let driver_dir = dir.join("driver");
    let mut agent = agent(&dir, false);
    let close = format!(
        "KARYOS-AGENT 1 guard-close {} {guard}\n",
        driver_dir.display()
    );
    let reopen = format!(
        "KARYOS-AGENT 1 guard-reopen {} {guard} 1\n",
        driver_dir.display()
    );
    for (role, request, expected) in [
        (Role::Viewer, close.as_str(), r#"{"error":"forbidden"}"#),
        (
            Role::Administrator,
            close.as_str(),
            r#"{"error":"forbidden"}"#,
        ),
        (Role::Operator, reopen.as_str(), r#"{"error":"forbidden"}"#),
        (
            Role::RiskOfficer,
            reopen.as_str(),
            r#"{"error":"journal unavailable"}"#,
        ),
        (
            Role::RiskOfficer,
            "KARYOS-AGENT 1 gap-ack 0\n",
            r#"{"error":"forbidden"}"#,
        ),
        (
            Role::Administrator,
            "KARYOS-AGENT 1 gap-ack 0\n",
            r#"{"error":"no such unknown interval"}"#,
        ),
        (
            Role::Operator,
            "KARYOS-AGENT 1 guard-close /nowhere 1\n",
            r#"{"error":"unknown driver"}"#,
        ),
    ] {
        let mut server =
            Server::bind(ApiConfig::new(dir.join("api"), vec![(own(), role)])).unwrap();
        let (answer, _) = ask(&mut driver, &mut server, &mut agent, request);
        assert_eq!(answer, format!("{expected}\n"), "{role:?} {request}");
    }
    // Nothing reached the driver.
    assert!(driver.guard_audit().records.is_empty());
}

/// An unknown interval left by an unanswered request is an alert in the
/// view until an administrator acknowledges it, by its position, through
/// the socket.
#[test]
fn an_administrator_acknowledges_the_unknown_interval() {
    let _serial = serial();
    let dir = dir("gap");
    let mut driver = driver(&dir.join("driver"));
    let mut journal = Journal::open(&dir.join("journal"), 1).unwrap();
    let _ = journal
        .append_durable(&JournalRecord::new(Kind::CloseRequest, 2), 2)
        .unwrap();
    drop(journal);
    let mut agent = agent(&dir, true);
    let gap = agent.view().journal.unwrap().gap.unwrap();
    let alerts = agent.view().journal.unwrap().alerts;
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].participant, gap.position);
    let mut server = Server::bind(ApiConfig::new(
        dir.join("api"),
        vec![(own(), Role::Administrator)],
    ))
    .unwrap();
    let request = format!("KARYOS-AGENT 1 gap-ack {}\n", gap.position);
    let (answer, served) = ask(&mut driver, &mut server, &mut agent, &request);
    assert_eq!(served, [Served::Operated]);
    assert_eq!(answer, format!("{{\"acknowledged\":{}}}\n", gap.position));
    let journal = agent.view().journal.unwrap();
    assert_eq!((journal.gap, journal.alerts.len()), (None, 0));
}

/// A reason longer than the journal keeps is cut once, before the digest:
/// the driver audits the digest of the 128 bytes the journal holds, so the
/// record can be verified against the audit (DESIGN's P2 on #487).
#[test]
fn a_long_reason_is_cut_before_its_digest() {
    let _serial = serial();
    let dir = dir("reason");
    let mut driver = driver(&dir.join("driver"));
    let guard = driver.add_guard("orders").unwrap().id();
    let mut agent = agent(&dir, true);
    let mut server = Server::bind(ApiConfig::new(
        dir.join("api"),
        vec![(own(), Role::Operator)],
    ))
    .unwrap();
    let reason = "r".repeat(129);
    let request = format!(
        "KARYOS-AGENT 1 guard-close {} {guard} {reason}\n",
        dir.join("driver").display()
    );
    let (answer, _) = ask(&mut driver, &mut server, &mut agent, &request);
    assert!(answer.contains(r#""open":false"#), "{answer}");
    let audit = driver.guard_audit();
    let record = audit.records.last().unwrap();
    let cut = karyos_protocol::cnc::guard_parameters(
        guard,
        0,
        record.operation,
        u64::from(own()),
        &reason.as_bytes()[..128],
    );
    assert_eq!(record.parameters, cut);
}

/// The driver's `clients connected` gauge.
fn clients_connected(driver: &IpcDriver) -> u64 {
    use karyos_sys::counters::CellRead;
    let reader = driver.counters();
    (0..reader.capacity())
        .find_map(|index| match reader.read(index) {
            CellRead::Allocated {
                metadata, value, ..
            } if metadata.label() == b"clients connected" => Some(value),
            _ => None,
        })
        .unwrap()
}

/// A close while the journal is down goes ahead (No A2): an agent whose
/// journal cannot be opened closes a guard for a risk officer through the
/// socket, refuses the reopen unsent, and shows the unknown interval and
/// its alert until an administrator acknowledges it.
#[test]
fn a_close_with_the_journal_down_goes_ahead_into_an_unknown_interval() {
    let _serial = serial();
    let dir = dir("journal-down");
    let mut driver = driver(&dir.join("driver"));
    let guard = driver.add_guard("orders").unwrap();
    let _ = driver.reopen_guard(guard, 1, 1).unwrap();
    // A file where the journal directory should be: it cannot open.
    std::fs::write(dir.join("journal"), b"not a journal").unwrap();
    let mut agent = agent(&dir, true);
    let journal = agent.view().journal.unwrap();
    assert!(journal.unavailable && journal.error.is_some());
    let gap = journal.gap.unwrap();
    assert_eq!(gap.reason, "journal_unavailable_at_start");
    assert_eq!(journal.alerts.len(), 1);
    let driver_dir = dir.join("driver");
    let mut server = Server::bind(ApiConfig::new(
        dir.join("api"),
        vec![(own(), Role::RiskOfficer)],
    ))
    .unwrap();
    let close = format!(
        "KARYOS-AGENT 1 guard-close {} {}\n",
        driver_dir.display(),
        guard.id()
    );
    let (answer, served) = ask(&mut driver, &mut server, &mut agent, &close);
    assert_eq!(served, [Served::Operated]);
    assert!(
        answer.contains(r#""state":{"epoch":3,"open":false}"#),
        "{answer}"
    );
    assert!(
        !driver.guard_state(guard).unwrap().open,
        "the close took effect"
    );
    let audited = driver.guard_audit().records.len();
    let reopen = format!(
        "KARYOS-AGENT 1 guard-reopen {} {} 3\n",
        driver_dir.display(),
        guard.id()
    );
    let (answer, _) = ask(&mut driver, &mut server, &mut agent, &reopen);
    assert_eq!(answer, "{\"error\":\"journal unavailable\"}\n");
    assert_eq!(driver.guard_audit().records.len(), audited, "never sent");
    assert!(!driver.guard_state(guard).unwrap().open);
    // The interval stands, for the close made unrecorded, until an
    // administrator acknowledges it.
    let journal = agent.view().journal.unwrap();
    assert_eq!((journal.gap, journal.alerts.len()), (Some(gap), 1));
    drop(server);
    let mut server = Server::bind(ApiConfig::new(
        dir.join("api"),
        vec![(own(), Role::Administrator)],
    ))
    .unwrap();
    let ack = format!("KARYOS-AGENT 1 gap-ack {}\n", gap.position);
    let (answer, served) = ask(&mut driver, &mut server, &mut agent, &ack);
    assert_eq!(served, [Served::Operated]);
    assert_eq!(answer, format!("{{\"acknowledged\":{}}}\n", gap.position));
    let journal = agent.view().journal.unwrap();
    assert_eq!((journal.gap, journal.alerts.len()), (None, 0));
}

/// The `karyos-agent` binary serving `dir`'s driver and journal, with this
/// uid as a risk officer.
fn spawn_agent(dir: &Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_karyos-agent"))
        .arg("--api-dir")
        .arg(dir.join("api"))
        .arg("--driver")
        .arg(dir.join("driver"))
        .arg("--journal")
        .arg(dir.join("journal"))
        .arg("--role")
        .arg(format!("{}=risk-officer", own()))
        .arg("--refresh-ms")
        .arg("10")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

/// An agent host that fails during a close leaves an unknown interval. The
/// agent binary journals the close's request, then attaches to the driver
/// as a one-command client: once the driver counts that client, the
/// request record is written, and with the driver no longer served no
/// answer can come, so no outcome. The agent is killed there. The next
/// agent on that journal shows a request without an outcome, whatever the
/// driver made of the close, until an administrator acknowledges it.
///
/// The cycle that admits the client may also serve a close written in
/// time (admission is served before commands), most often under load. The
/// driver then answers, and the live agent may journal the outcome before
/// it is killed, so that attempt cannot show the failure: it is set aside
/// and the scenario starts again on a fresh driver and directory, up to
/// five times.
///
/// So is an attempt whose attach the driver did not admit within the
/// agent's guard timeout (`DEFAULT_ATTACH_TIMEOUT`, 1 s), which a loaded
/// host can exceed: the agent then journals the close as not sent and
/// answers `driver unavailable`, never attaching (karyos#1067). That is the
/// agent's right answer to a driver that does not admit it in time, so the
/// attempt is set aside rather than failed.
#[test]
fn an_agent_killed_during_a_close_leaves_a_request_without_outcome() {
    const ATTEMPTS: u32 = 5;

    let _serial = serial();
    let mut attempt = 0;
    let (dir, mut driver, mut stream, audited) = loop {
        attempt += 1;
        assert!(
            attempt <= ATTEMPTS,
            "every attempt was served or not admitted in time"
        );
        let dir = dir(&format!("killed-{attempt}"));
        let mut driver = driver(&dir.join("driver"));
        let guard = driver.add_guard("orders").unwrap();
        let _ = driver.reopen_guard(guard, 1, 1).unwrap();
        let audited = driver.guard_audit().records.len();
        let mut child = spawn_agent(&dir);
        let socket = dir.join("api").join(karyos_agent::server::SOCKET_NAME);
        let start = Instant::now();
        let mut stream = loop {
            let _ = driver.do_work().unwrap();
            if let Ok(stream) = UnixStream::connect(&socket) {
                break stream;
            }
            assert!(start.elapsed() < Duration::from_secs(10), "no agent socket");
            std::thread::sleep(Duration::from_millis(1));
        };
        // The agent reads the CnC as a tool: not a client.
        assert_eq!(clients_connected(&driver), 0);
        let close = format!(
            "KARYOS-AGENT 1 guard-close {} {}\n",
            dir.join("driver").display(),
            guard.id()
        );
        stream.write_all(close.as_bytes()).unwrap();
        // Waits for the attach, or for the agent's answer that its attach
        // timed out: the stream reads nothing before an answer.
        stream.set_nonblocking(true).unwrap();
        let (start, mut answered) = (Instant::now(), Vec::new());
        while clients_connected(&driver) == 0 {
            assert!(start.elapsed() < Duration::from_secs(30), "never attached");
            let _ = driver.do_work().unwrap();
            let mut chunk = [0u8; 256];
            if let Ok(read) = stream.read(&mut chunk) {
                answered.extend_from_slice(&chunk[..read]);
            }
            if answered.ends_with(b"\n") {
                break;
            }
            std::thread::sleep(Duration::from_micros(200));
        }
        stream.set_nonblocking(false).unwrap();
        if !answered.is_empty() {
            // A close served in the cycle that admitted the client can be
            // answered before this read: set aside like any served attempt
            // (Codex review of #1252). Otherwise the only answer before an
            // attach is the guard timeout's.
            if driver.guard_audit().records.len() == audited {
                let answered = String::from_utf8_lossy(&answered);
                assert_eq!(
                    answered, "{\"error\":\"driver unavailable\"}\n",
                    "an answer before the attach"
                );
            }
            let _ = child.kill();
            let _ = child.wait().unwrap();
            continue;
        }
        // Attached, so its request record is written. An unchanged audit
        // proves no answer exists, and with the driver no longer served
        // none can come, so no outcome. The agent's own child, by its pid.
        let served = driver.guard_audit().records.len() != audited;
        child.kill().unwrap();
        let _ = child.wait().unwrap();
        if served {
            continue;
        }
        break (dir, driver, stream, audited);
    };
    let mut answer = String::new();
    let _ = stream.read_to_string(&mut answer);
    assert_eq!(answer, "", "the killed agent answered");
    // Serve the driver past the dead client, whatever it makes of a close
    // it may have taken.
    let start = Instant::now();
    while clients_connected(&driver) != 0 {
        assert!(start.elapsed() < Duration::from_secs(30), "client kept");
        let _ = driver.do_work().unwrap();
        std::thread::sleep(Duration::from_millis(1));
    }
    let closes = driver.guard_audit().records.len() - audited;
    assert!(closes <= 1, "{closes} closes audited");
    let mut agent = agent(&dir, true);
    let journal = agent.view().journal.unwrap();
    let gap = journal.gap.unwrap();
    assert_eq!(gap.reason, "request_without_outcome");
    assert_eq!(journal.alerts.len(), 1);
    let mut server = Server::bind(ApiConfig::new(
        dir.join("api"),
        vec![(own(), Role::Administrator)],
    ))
    .unwrap();
    let ack = format!("KARYOS-AGENT 1 gap-ack {}\n", gap.position);
    let (answer, served) = ask(&mut driver, &mut server, &mut agent, &ack);
    assert_eq!(served, [Served::Operated]);
    assert_eq!(answer, format!("{{\"acknowledged\":{}}}\n", gap.position));
    let journal = agent.view().journal.unwrap();
    assert_eq!((journal.gap, journal.alerts.len()), (None, 0));
}

/// A driver that does not admit the agent within its guard timeout (1 s):
/// the agent answers `driver unavailable` and journals the close as not
/// sent, so the next agent on that journal shows only the kill's unclean
/// stop, never a request without an outcome. This is the answer `an_agent_killed_during_a_close_leaves_a_request_without_outcome`
/// sets aside when a loaded host admits too late (karyos#1067).
#[test]
fn a_close_the_driver_does_not_admit_in_time_is_journalled_as_not_sent() {
    let _serial = serial();
    let dir = dir("unadmitted");
    let mut driver = driver(&dir.join("driver"));
    let guard = driver.add_guard("orders").unwrap();
    let _ = driver.reopen_guard(guard, 1, 1).unwrap();
    let audited = driver.guard_audit().records.len();
    let mut child = spawn_agent(&dir);
    let socket = dir.join("api").join(karyos_agent::server::SOCKET_NAME);
    let start = Instant::now();
    let mut stream = loop {
        let _ = driver.do_work().unwrap();
        if let Ok(stream) = UnixStream::connect(&socket) {
            break stream;
        }
        assert!(start.elapsed() < Duration::from_secs(10), "no agent socket");
        std::thread::sleep(Duration::from_millis(1));
    };
    let close = format!(
        "KARYOS-AGENT 1 guard-close {} {}\n",
        dir.join("driver").display(),
        guard.id()
    );
    let sent = karyos_sys::host_clock::host_monotonic_ns();
    stream.write_all(close.as_bytes()).unwrap();
    // The driver is not served: the agent's attach cannot be admitted. The
    // read is bounded, so an agent that never answers fails the test
    // rather than hanging it (Codex review of #1252).
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let mut answer = String::new();
    let read = stream.read_to_string(&mut answer);
    child.kill().unwrap();
    let _ = child.wait().unwrap();
    read.expect("the agent answered within 30 s");
    assert_eq!(answer, "{\"error\":\"driver unavailable\"}\n");
    // Served now, the driver closes nothing: the close was never sent.
    for _ in 0..100 {
        let _ = driver.do_work().unwrap();
    }
    assert_eq!(driver.guard_audit().records.len(), audited);
    // The kill is itself an unclean stop, which the next agent shows; the
    // close is not an open request: its outcome was journalled. The
    // interval runs from the last record read, so an interval from after
    // the close was sent shows a record of the close, and as the reason is
    // not `request_without_outcome`, that record is its outcome (Codex
    // review of #1252): a close journalled not at all would leave the
    // agent's start as the last record, before `sent`.
    let agent = agent(&dir, true);
    let journal = agent.view().journal.unwrap();
    let gap = journal.gap.unwrap();
    assert_eq!(gap.reason, "unclean_stop");
    assert!(
        gap.from >= sent,
        "{} < {sent}: the close left no record",
        gap.from
    );
    assert_eq!(journal.alerts.len(), 1, "one interval, the stop's");
}

/// R-CORE-19 (karyos#726): a relayed `gap-ack`. A relayed operator is
/// refused and the interval stays open; a position that is no open
/// interval is refused with a typed refusal; a relayed administrator's
/// acknowledgement answers with the interval and that its events remain
/// unknown, and closes it; the local answer stays the bare position.
#[test]
fn a_relayed_administrator_acknowledges_the_interval_and_no_more() {
    let _serial = serial();
    let dir = dir("relayed-gap");
    let mut driver = driver(&dir.join("driver"));
    let mut journal = Journal::open(&dir.join("journal"), 1).unwrap();
    let _ = journal
        .append_durable(&JournalRecord::new(Kind::CloseRequest, 2), 2)
        .unwrap();
    drop(journal);
    let mut agent = agent(&dir, true);
    let gap = agent.view().journal.unwrap().gap.unwrap();
    let principals = vec![
        Principal::new("alice@example", 50_001, Role::Administrator).unwrap(),
        Principal::new("bob@example", 50_002, Role::Operator).unwrap(),
    ];
    let mut server = Server::bind(
        ApiConfig::new(dir.join("api"), vec![(own(), Role::Viewer)])
            .with_relays(vec![(own(), 7)], principals),
    )
    .unwrap();
    let operator = format!(
        "KARYOS-AGENT 1 relay bob@example gap-ack {}\n",
        gap.position
    );
    let (answer, served) = ask(&mut driver, &mut server, &mut agent, &operator);
    assert_eq!(served, [Served::Refused]);
    assert_eq!(answer, "{\"error\":\"forbidden\"}\n");
    // The relay's own role is no administrator's either.
    let local = format!("KARYOS-AGENT 1 gap-ack {}\n", gap.position);
    let (answer, _) = ask(&mut driver, &mut server, &mut agent, &local);
    assert_eq!(answer, "{\"error\":\"forbidden\"}\n");
    assert_eq!(agent.view().journal.unwrap().gap, Some(gap));
    let wrong = format!(
        "KARYOS-AGENT 1 relay alice@example gap-ack {}\n",
        gap.position + 1
    );
    let (answer, served) = ask(&mut driver, &mut server, &mut agent, &wrong);
    assert_eq!(served, [Served::Operated]);
    assert_eq!(
        answer,
        format!(
            "{{\"error\":\"no such unknown interval\",\"refusal\":\"not_an_unknown_interval\",\"position\":{}}}\n",
            gap.position + 1
        )
    );
    let ack = format!(
        "KARYOS-AGENT 1 relay alice@example gap-ack {}\n",
        gap.position
    );
    let (answer, served) = ask(&mut driver, &mut server, &mut agent, &ack);
    assert_eq!(served, [Served::Operated]);
    assert_eq!(
        answer,
        format!(
            "{{\"acknowledged\":{{\"position\":{},\"reason\":\"{}\",\"from\":{},\"to\":{}}},\"events\":\"unknown\"}}\n",
            gap.position, gap.reason, gap.from, gap.to
        )
    );
    assert!(!answer.contains("resolved") && !answer.contains("repaired"));
    let journal = agent.view().journal.unwrap();
    assert_eq!((journal.gap, journal.alerts.len()), (None, 0));
    // Acknowledged once: a second is the typed refusal.
    let (answer, _) = ask(&mut driver, &mut server, &mut agent, &ack);
    assert!(answer.contains("not_an_unknown_interval"), "{answer}");
}

/// R-CORE-21 (karyos#740): a rate change through the agent's socket. An
/// operator's safety path tightening reaches the driver and answers with
/// the new version, kept in the view; an operator may not take the
/// administrator's path; an administrator's loosening without a journal is
/// refused unsent; with one it is made, journalled before and after, and
/// a stale version is refused with the current one.
#[test]
fn rate_changes_are_made_by_authority_and_journalled() {
    use karyos_driver::GuardRate;
    use karyos_sys::rate_limit::{Rate, RatePolicy};
    let _serial = serial();
    let dir = dir("rate");
    let driver_dir = dir.join("driver");
    let mut driver = driver(&driver_dir);
    let stream = driver.add_stream(stream_config()).unwrap();
    let guard = driver.add_guard("orders").unwrap();
    driver
        .guard_stream(
            stream,
            guard,
            4,
            Some(GuardRate::publication(RatePolicy {
                messages: Rate {
                    per_second: 100,
                    burst: 10,
                },
                bytes: None,
            })),
        )
        .unwrap();
    let change = |expected: u64, authority: &str, rate: u64| {
        format!(
            "KARYOS-AGENT 1 rate-change {} 2 1 {expected} {authority} {rate} 10 0 0 incident\n",
            driver_dir.display()
        )
    };
    let bind =
        |role: Role| Server::bind(ApiConfig::new(dir.join("api"), vec![(own(), role)])).unwrap();

    // No journal: the safety path goes ahead, the administrator's does not.
    let mut unjournalled = agent(&dir, false);
    let mut server = bind(Role::Operator);
    let (answer, served) = ask(
        &mut driver,
        &mut server,
        &mut unjournalled,
        &change(1, "safety", 50),
    );
    assert_eq!(served, [Served::Operated]);
    assert!(
        answer.ends_with("\"stream_id\":2,\"session_id\":1,\"version\":2}\n"),
        "{answer}"
    );
    let view = unjournalled.view();
    assert_eq!(view.rates.len(), 1);
    assert_eq!(
        (
            view.rates[0].stream_id,
            view.rates[0].session_id,
            view.rates[0].version
        ),
        (2, 1, 2)
    );
    let (answer, _) = ask(
        &mut driver,
        &mut server,
        &mut unjournalled,
        &change(2, "administrator", 200),
    );
    assert_eq!(answer, "{\"error\":\"forbidden\"}\n");
    drop(server);
    let mut server = bind(Role::Administrator);
    let (answer, _) = ask(
        &mut driver,
        &mut server,
        &mut unjournalled,
        &change(2, "administrator", 200),
    );
    assert_eq!(answer, "{\"error\":\"journal unavailable\"}\n");
    drop(server);
    drop(unjournalled);

    // With a journal: the administrator's loosening is made; a stale
    // version is refused with the current one.
    let mut journalled = agent(&dir, true);
    let mut server = bind(Role::Administrator);
    let (answer, _) = ask(
        &mut driver,
        &mut server,
        &mut journalled,
        &change(2, "administrator", 200),
    );
    assert!(answer.ends_with("\"version\":3}\n"), "{answer}");
    let (answer, _) = ask(
        &mut driver,
        &mut server,
        &mut journalled,
        &change(2, "safety", 20),
    );
    assert!(answer.starts_with("{\"error\":\"refused\""), "{answer}");
    assert!(answer.ends_with("\"detail\":3}\n"), "{answer}");
    assert_eq!(journalled.view().rates[0].version, 3);
    // The driver audited every change sent for this uid: three of them.
    assert_eq!(driver.guard_audit().records.len(), 3);
    let journal = journalled.view().journal.unwrap();
    assert_eq!((journal.failed_appends, journal.gap), (0, None));
    journalled.stop().unwrap();
    drop(journalled);
    // Every request answered by its outcome: no unknown interval.
    let reopened = Journal::open(&dir.join("journal"), 1).unwrap();
    assert_eq!(reopened.gap(), None);
}

/// Stream 2, session 1: the stream the rate test guards.
fn stream_config() -> karyos_driver::StreamConfig {
    use karyos_driver::{LossPolicy, StreamConfig};
    use karyos_sys::frame::Lane;
    use karyos_sys::log_buffer::{LogBufferConfig, PublicationMode};
    use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
    use karyos_sys::term::TermId;
    StreamConfig {
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
    }
}
