// SPDX-License-Identifier: Apache-2.0

//! Audited guard operations through the agent's socket (Linux;
//! quantstratum-docs: karyos/design/management-agent-gap-analysis.md,
//! M10b): a request of a role that may make it reaches the driver for the
//! peer's uid, journalled before and after; a role that may not is
//! refused; a reopen without a journal is refused and never sent; an
//! unknown interval is acknowledged by an administrator only.

#![cfg(target_os = "linux")]
// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use karyos_agent::journal::{Journal, JournalRecord, Kind};
use karyos_agent::server::{ApiConfig, Role, Served, Server};
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
