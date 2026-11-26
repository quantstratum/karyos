// SPDX-License-Identifier: Apache-2.0

//! The named contract test of SPEC §13's "Audited operations" row
//! (ADR-0055; karyos#719), its unauthenticated half, which needs no
//! security profile: a purge by unauthorised and authorised operators
//! through the agent, each request and its outcome journalled; the
//! journal asymmetry of owner item 51 for the retention operations (a
//! hold goes ahead and still inhibits a purge with the journal down; a
//! release and a purge fail closed); a relayed operator and the relay
//! recorded apart; every request ending in an outcome or inside an
//! unknown interval. The guard close and reopen clauses are in
//! `tests/operations.rs`; the standby promotion and the replicated close
//! wait on karyos#714 and karyos#703.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::collections::HashSet;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use karyos_agent::journal::retention::{REFUSED, refusal_word};
use karyos_agent::journal::{HISTORY_MAX, Journal, JournalRecord, Kind};
use karyos_agent::retention::{RangeOutcome, RetentionBackend, RetentionReply};
use karyos_agent::server::{ApiConfig, Principal, Role, Served, Server};
use karyos_agent::{Agent, AgentConfig};

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("karyos-audited-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn own() -> u32 {
    karyos_sys::ipc::own_uid()
}

/// An Archive that keeps its holds across agents, refuses a purge of a
/// held recording, and records what reached it.
#[derive(Debug, Default, Clone)]
struct Archive {
    sent: Arc<Mutex<Vec<String>>>,
    holds: Arc<Mutex<HashSet<u64>>>,
}

impl RetentionBackend for Archive {
    fn hold(&mut self, recording: u64, _: u64, _: u32) -> RetentionReply {
        self.sent.lock().unwrap().push(format!("hold {recording}"));
        let _ = self.holds.lock().unwrap().insert(recording);
        RetentionReply::Done { evidenced: true }
    }

    fn release(&mut self, recording: u64, _: u64, _: u32) -> RetentionReply {
        self.sent
            .lock()
            .unwrap()
            .push(format!("release {recording}"));
        let _ = self.holds.lock().unwrap().remove(&recording);
        RetentionReply::Done { evidenced: true }
    }

    fn purge(&mut self, recording: u64, before: u64, _: u64, _: u32) -> RetentionReply {
        self.sent
            .lock()
            .unwrap()
            .push(format!("purge {recording} {before}"));
        if self.holds.lock().unwrap().contains(&recording) {
            return RetentionReply::Refused {
                code: 2,
                reason: "legal_hold".to_owned(),
            };
        }
        RetentionReply::Done { evidenced: true }
    }

    fn verify(&mut self, recording: u64) -> Option<Vec<RangeOutcome>> {
        self.sent
            .lock()
            .unwrap()
            .push(format!("verify {recording}"));
        Some(Vec::new())
    }
}

/// An agent journalling in `journal`, over `archive`.
fn agent(journal: &Path, archive: &Archive) -> Agent {
    let mut agent = Agent::new(AgentConfig::new(Vec::new()).with_journal(journal.to_path_buf()));
    agent.set_retention(Box::new(archive.clone()));
    agent
}

/// Sends `request` to `server` and serves it.
fn ask(server: &mut Server, agent: &mut Agent, request: &str) -> String {
    let path = server.path().to_path_buf();
    let line = format!("KARYOS-AGENT 1 {request}\n");
    std::thread::scope(|scope| {
        let client = scope.spawn(move || {
            let mut stream = UnixStream::connect(path).unwrap();
            // Bounded, so a serve that fails ends the test instead of
            // leaving this read waiting.
            stream
                .set_read_timeout(Some(Duration::from_secs(15)))
                .unwrap();
            stream.write_all(line.as_bytes()).unwrap();
            let mut answer = String::new();
            let _ = stream.read_to_string(&mut answer).unwrap();
            answer
        });
        let mut served: Vec<Served> = Vec::new();
        let start = Instant::now();
        while served.is_empty() {
            assert!(start.elapsed() < Duration::from_secs(10), "never served");
            served = server.poll(agent).unwrap();
            std::thread::sleep(Duration::from_millis(1));
        }
        client.join().unwrap().trim_end().to_owned()
    })
}

/// A server where this uid has `role`, in its own directory.
fn server(dir: &Path, role: Role) -> Server {
    Server::bind(ApiConfig::new(
        dir.join(format!("api-{role:?}")),
        vec![(own(), role)],
    ))
    .unwrap()
}

/// The journal's records, every one written made durable first, as
/// before a view.
fn records(agent: &mut Agent) -> Vec<JournalRecord> {
    agent.settle_journal();
    agent
        .journal_history(None, HISTORY_MAX)
        .unwrap()
        .records
        .into_iter()
        .filter_map(|record| record.record)
        .collect()
}

/// The outcome kind of a retention request kind.
fn outcome_of(kind: Kind) -> Option<Kind> {
    Some(match kind {
        Kind::HoldRequest => Kind::HoldOutcome,
        Kind::ReleaseRequest => Kind::ReleaseOutcome,
        Kind::PurgeRequest => Kind::PurgeOutcome,
        Kind::VerifyRequest => Kind::VerifyOutcome,
        _ => return None,
    })
}

/// The records of `kind`.
fn of(records: &[JournalRecord], kind: Kind) -> Vec<&JournalRecord> {
    records
        .iter()
        .filter(|record| record.kind == kind)
        .collect()
}

/// A purge requested by every unauthorised role and then by an
/// administrator: only the administrator's reaches the Archive; each of
/// the four is journalled, request then outcome under one operation id
/// with its requester, the refusals as `not_authorised`.
#[test]
fn test_agent_audited_operations_a_purge_by_unauthorised_and_authorised_operators_is_journalled() {
    let dir = dir("purge");
    let archive = Archive::default();
    let mut agent = agent(&dir.join("journal"), &archive);
    for role in [Role::Viewer, Role::Operator, Role::RiskOfficer] {
        let answer = ask(&mut server(&dir, role), &mut agent, "purge 7 4096 expired");
        assert_eq!(answer, r#"{"error":"forbidden"}"#, "{role:?}");
    }
    assert!(archive.sent.lock().unwrap().is_empty(), "nothing sent");
    let answer = ask(
        &mut server(&dir, Role::Administrator),
        &mut agent,
        "purge 7 4096 expired",
    );
    assert!(answer.contains(r#""evidenced":true"#), "{answer}");
    assert_eq!(*archive.sent.lock().unwrap(), ["purge 7 4096"]);

    let records = records(&mut agent);
    let requests = of(&records, Kind::PurgeRequest);
    let outcomes = of(&records, Kind::PurgeOutcome);
    assert_eq!((requests.len(), outcomes.len()), (4, 4));
    for (request, outcome) in requests.iter().zip(&outcomes) {
        assert_eq!(request.operation, outcome.operation);
        assert_eq!(
            (request.operator, outcome.operator),
            (u64::from(own()), u64::from(own()))
        );
        assert_eq!(request.reason, b"expired");
    }
    for refused in &outcomes[..3] {
        assert_eq!(
            (refused.code, refused.word),
            (REFUSED, refusal_word("not_authorised"))
        );
    }
    assert_eq!((outcomes[3].code, outcomes[3].word), (0, 1));
    let ids: HashSet<u64> = requests.iter().map(|request| request.operation).collect();
    assert_eq!(ids.len(), 4, "one operation id each");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Owner item 51's asymmetry for the retention operations, one clause
/// each, with the journal down (it could not be opened): a hold goes
/// ahead; a release and a purge fail closed, unsent. Back up, the hold
/// taken while it was down inhibits the purge, and the outage is the
/// recorded unknown interval the hold falls inside.
#[test]
fn test_agent_audited_operations_with_the_journal_down_a_hold_inhibits_and_a_release_and_a_purge_fail_closed()
 {
    let dir = dir("asymmetry");
    let journal = dir.join("journal");
    let archive = Archive::default();
    // A file stands where the journal's directory goes: it cannot open.
    std::fs::write(&journal, b"not a directory").unwrap();
    let mut down = agent(&journal, &archive);
    assert!(down.view().journal.unwrap().unavailable);
    let mut admin = server(&dir, Role::Administrator);
    let answer = ask(&mut admin, &mut down, "legal-hold 7 case 12");
    assert!(
        answer.contains(r#""evidenced":true"#),
        "the hold goes ahead: {answer}"
    );
    for request in ["hold-release 7 closed", "purge 7 4096"] {
        assert_eq!(
            ask(&mut admin, &mut down, request),
            r#"{"error":"journal unavailable"}"#,
            "{request} fails closed"
        );
    }
    assert_eq!(
        *archive.sent.lock().unwrap(),
        ["hold 7"],
        "only the hold was sent"
    );
    drop(admin);
    drop(down);

    std::fs::remove_file(&journal).unwrap();
    let mut up = agent(&journal, &archive);
    let gap = up.view().journal.unwrap().gap.unwrap();
    assert_eq!(gap.reason, "journal_unavailable_at_start");
    let answer = ask(
        &mut server(&dir, Role::Administrator),
        &mut up,
        "purge 7 4096",
    );
    assert!(
        answer.contains(r#""reason":"legal_hold""#),
        "the hold inhibits the purge: {answer}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A relayed principal's purge: the journal records the principal's
/// operator id and the relay's id as separate fields, for the
/// administrator's purge and for an operator's refused one alike.
#[test]
fn test_agent_audited_operations_a_relayed_purge_records_the_operator_and_the_relay_apart() {
    let dir = dir("relayed");
    let archive = Archive::default();
    let mut agent = agent(&dir.join("journal"), &archive);
    let principals = vec![
        Principal::new("alice@example", 50_001, Role::Administrator).unwrap(),
        Principal::new("bob@example", 50_002, Role::Operator).unwrap(),
    ];
    let mut server = Server::bind(
        ApiConfig::new(dir.join("api"), vec![(own(), Role::Viewer)])
            .with_relays(vec![(own(), 7)], principals),
    )
    .unwrap();
    assert_eq!(
        ask(&mut server, &mut agent, "relay bob@example purge 7 4096"),
        r#"{"error":"forbidden"}"#
    );
    let answer = ask(&mut server, &mut agent, "relay alice@example purge 7 4096");
    assert!(answer.contains(r#""evidenced":true"#), "{answer}");
    let records = records(&mut agent);
    let requests = of(&records, Kind::PurgeRequest);
    assert_eq!(
        requests
            .iter()
            .map(|request| (request.operator, request.relay))
            .collect::<Vec<_>>(),
        [(50_002, 7), (50_001, 7)]
    );
    assert!(
        of(&records, Kind::PurgeOutcome)
            .iter()
            .all(|outcome| outcome.relay == 7)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Every retention request, authorised or not, ends in its outcome under
/// its operation id; one whose outcome a stop cut off falls inside the
/// unknown interval the next start records. There is no third case.
#[test]
fn test_agent_audited_operations_every_request_ends_in_an_outcome_or_an_unknown_interval() {
    let dir = dir("outcomes");
    let journal = dir.join("journal");
    let archive = Archive::default();
    let mut agent = agent(&journal, &archive);
    let mut viewer = server(&dir, Role::Viewer);
    let mut admin = server(&dir, Role::Administrator);
    for (role, request) in [
        (Role::Viewer, "legal-hold 7"),
        (Role::Viewer, "hold-release 7"),
        (Role::Viewer, "purge 7 64"),
        (Role::Viewer, "seal-verify 7"),
        (Role::Administrator, "legal-hold 7"),
        (Role::Administrator, "purge 7 64"),
        (Role::Administrator, "hold-release 7"),
        (Role::Administrator, "purge 7 64"),
    ] {
        let server = if role == Role::Viewer {
            &mut viewer
        } else {
            &mut admin
        };
        let _ = ask(server, &mut agent, request);
    }
    let records = records(&mut agent);
    let mut requests = 0;
    for (at, request) in records.iter().enumerate() {
        let Some(outcome) = outcome_of(request.kind) else {
            continue;
        };
        requests += 1;
        assert!(
            records[at + 1..]
                .iter()
                .any(|later| later.kind == outcome && later.operation == request.operation),
            "{request:?} has no outcome"
        );
    }
    assert_eq!(requests, 8);
    drop(viewer);
    drop(admin);
    drop(agent);

    // A purge's request durable and its outcome never written, as a stop
    // between them leaves it: the next start's unknown interval.
    let mut cut = Journal::open(&journal, 1).unwrap();
    let mut request = JournalRecord::new(Kind::PurgeRequest, 2);
    request.operation = 99;
    let _ = cut.append_durable(&request, 2).unwrap();
    drop(cut);
    let mut agent = self::agent(&journal, &archive);
    let gap = agent.view().journal.unwrap().gap.unwrap();
    assert_eq!(gap.reason, "request_without_outcome");
    let records = self::records(&mut agent);
    let at = records
        .iter()
        .position(|record| record.operation == 99)
        .unwrap();
    assert!(
        !records[at + 1..]
            .iter()
            .any(|record| record.kind == Kind::PurgeOutcome && record.operation == 99)
    );
    assert_eq!(records[at + 1].kind, Kind::UnknownInterval);
    let _ = std::fs::remove_dir_all(&dir);
}
