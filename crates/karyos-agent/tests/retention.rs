// SPDX-License-Identifier: Apache-2.0

//! The Archive's retention operations through the agent's socket, by role
//! (M12; karyos#701).

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use karyos_agent::retention::{RangeOutcome, RetentionBackend, RetentionReply};
use karyos_agent::server::{ApiConfig, Role, Served, Server};
use karyos_agent::{Agent, AgentConfig};

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "karyos-retention-api-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// An Archive that records what reached it.
#[derive(Debug, Default)]
struct Archive {
    sent: Arc<Mutex<Vec<String>>>,
}

impl Archive {
    fn log(&self, what: String) {
        self.sent.lock().unwrap().push(what);
    }
}

impl RetentionBackend for Archive {
    fn hold(&mut self, recording: u64, _: u64, operator: u32) -> RetentionReply {
        self.log(format!("hold {recording} by {operator}"));
        RetentionReply::Done { evidenced: true }
    }

    fn release(&mut self, recording: u64, _: u64, _: u32) -> RetentionReply {
        self.log(format!("release {recording}"));
        RetentionReply::Done { evidenced: true }
    }

    fn purge(&mut self, recording: u64, before: u64, _: u64, _: u32) -> RetentionReply {
        self.log(format!("purge {recording} {before}"));
        if recording == 9 {
            return RetentionReply::Refused {
                code: 2,
                reason: "legal_hold".to_owned(),
            };
        }
        RetentionReply::Done { evidenced: true }
    }

    fn verify(&mut self, recording: u64) -> Option<Vec<RangeOutcome>> {
        self.log(format!("verify {recording}"));
        Some(vec![RangeOutcome {
            start: 0,
            end: 128,
            outcome: "verified".to_owned(),
            reasons: Vec::new(),
        }])
    }
}

fn agent(dir: &std::path::Path, journal: bool) -> (Agent, Arc<Mutex<Vec<String>>>) {
    let mut config = AgentConfig::new(Vec::new());
    if journal {
        config = config.with_journal(dir.join("journal"));
    }
    let mut agent = Agent::new(config);
    let archive = Archive::default();
    let sent = Arc::clone(&archive.sent);
    agent.set_retention(Box::new(archive));
    (agent, sent)
}

fn ask(dir: &std::path::Path, role: Role, agent: &mut Agent, request: &str) -> String {
    let path = dir.join(format!("api-{role:?}"));
    let mut server = Server::bind(ApiConfig::new(
        path,
        vec![(karyos_sys::ipc::own_uid(), role)],
    ))
    .unwrap();
    let path = server.path().to_path_buf();
    let line = format!("KARYOS-AGENT 1 {request}\n");
    std::thread::scope(|scope| {
        let client = scope.spawn(move || {
            let mut stream = UnixStream::connect(path).unwrap();
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
        client.join().unwrap()
    })
}

#[test]
fn an_administrator_purges_and_an_operator_may_not() {
    let dir = dir("purge-roles");
    let (mut agent, sent) = agent(&dir, true);
    for role in [Role::Viewer, Role::Operator, Role::RiskOfficer] {
        let answer = ask(&dir, role, &mut agent, "purge 7 4096 expired");
        assert_eq!(answer, r#"{"error":"forbidden"}"#, "{role:?}");
    }
    assert!(sent.lock().unwrap().is_empty());
    let answer = ask(
        &dir,
        Role::Administrator,
        &mut agent,
        "purge 7 4096 expired",
    );
    assert!(answer.contains(r#""evidenced":true"#), "{answer}");
    assert_eq!(*sent.lock().unwrap(), vec!["purge 7 4096".to_owned()]);
}

#[test]
fn a_purge_under_a_hold_is_refused_with_the_archives_reason() {
    let dir = dir("purge-held");
    let (mut agent, _) = agent(&dir, true);
    let answer = ask(&dir, Role::Administrator, &mut agent, "purge 9 64");
    assert!(answer.starts_with(r#"{"error":"refused","#), "{answer}");
    assert!(
        answer.contains(r#""code":2,"reason":"legal_hold""#),
        "{answer}"
    );
}

#[test]
fn a_hold_by_role_and_a_release_by_an_administrator_only() {
    let dir = dir("hold-roles");
    let (mut agent, sent) = agent(&dir, true);
    assert_eq!(
        ask(&dir, Role::Viewer, &mut agent, "legal-hold 7 case 12"),
        r#"{"error":"forbidden"}"#
    );
    for role in [Role::Operator, Role::RiskOfficer, Role::Administrator] {
        let answer = ask(&dir, role, &mut agent, "legal-hold 7 case 12");
        assert!(answer.contains(r#""evidenced":true"#), "{role:?} {answer}");
    }
    for role in [Role::Viewer, Role::Operator, Role::RiskOfficer] {
        assert_eq!(
            ask(&dir, role, &mut agent, "hold-release 7"),
            r#"{"error":"forbidden"}"#,
            "{role:?}"
        );
    }
    let answer = ask(
        &dir,
        Role::Administrator,
        &mut agent,
        "hold-release 7 closed",
    );
    assert!(answer.contains(r#""evidenced":true"#), "{answer}");
    assert_eq!(sent.lock().unwrap().last().unwrap(), "release 7");
}

#[test]
fn without_a_journal_a_hold_applies_and_a_release_and_a_purge_refuse() {
    let dir = dir("no-journal");
    let (mut agent, sent) = agent(&dir, false);
    let answer = ask(&dir, Role::Administrator, &mut agent, "legal-hold 7");
    assert!(answer.contains(r#""evidenced":true"#), "{answer}");
    for request in ["hold-release 7", "purge 7 64"] {
        assert_eq!(
            ask(&dir, Role::Administrator, &mut agent, request),
            r#"{"error":"journal unavailable"}"#,
            "{request}"
        );
    }
    assert_eq!(sent.lock().unwrap().len(), 1, "only the hold was sent");
}

#[test]
fn every_role_verifies_and_gets_the_archives_outcomes() {
    let dir = dir("verify");
    let (mut agent, _) = agent(&dir, true);
    let answer = ask(&dir, Role::Viewer, &mut agent, "seal-verify 7");
    assert!(
        answer.ends_with(r#""ranges":[{"start":0,"end":128,"outcome":"verified","reasons":[]}]}"#),
        "{answer}"
    );
}
