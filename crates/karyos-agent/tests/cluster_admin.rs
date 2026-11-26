// SPDX-License-Identifier: Apache-2.0

//! R-CORE-41's contract (karyos#772; `karyos_agent::cluster_admin`)
//! against a fixture product Cluster: a sequencer-like `ClusteredService`
//! in C10's service container (`karyos_cluster::service`), reached through
//! the `ClusterGateway` the product attaches. The fixture's commands, their
//! encoding and its evidence are the product's; the agent reads none of
//! them.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use karyos_agent::cluster_admin::{
    AdminCommand, Authority, Clearance, ClusterAnswer, ClusterGateway, ClusterReply, Clusters,
    Command, Evidence, ProductCode, RefusalCode, Submission, cluster_command,
};
use karyos_agent::journal::Journal;
use karyos_cluster::dedup::Outcome;
use karyos_cluster::log::Entry;
use karyos_cluster::service::{
    Applied, ClusteredService, ContainerConfig, Context, Envelope, NotLeader, Propose,
    ServiceContainer,
};

fn dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "karyos-cluster-admin-it-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The product's state machine: killed or not, and the active upgrade.
/// Its command encoding is its own: a name's length byte, the name, the
/// parameters. Its reply: 0 then the evidence digest for done, 1 then a
/// code byte for refused.
#[derive(Debug, Default)]
struct Sequencer {
    killed: bool,
    upgrade: u64,
    runs: u64,
}

fn write(reply: &mut [u8], bytes: &[u8]) -> Option<usize> {
    reply.get_mut(..bytes.len())?.copy_from_slice(bytes);
    Some(bytes.len())
}

impl ClusteredService for Sequencer {
    fn on_command(
        &mut self,
        _: &mut Context<'_>,
        _: u64,
        command: &[u8],
        reply: &mut [u8],
    ) -> Option<usize> {
        self.runs += 1;
        let (&length, rest) = command.split_first()?;
        let (name, parameters) = rest.split_at_checked(usize::from(length))?;
        match name {
            b"kill" if self.killed => write(reply, &[1, 1]),
            b"kill" => {
                self.killed = true;
                write(reply, &[0])
            }
            b"reopen" if !self.killed => write(reply, &[1, 2]),
            b"reopen" => {
                self.killed = false;
                write(reply, &[0])
            }
            // The version, then the replay evidence's digest it checked.
            b"activate-upgrade" => {
                let (version, digest) = parameters.split_first_chunk::<8>()?;
                self.upgrade = u64::from_le_bytes(*version);
                let mut out = vec![0];
                out.extend_from_slice(digest);
                write(reply, &out)
            }
            _ => write(reply, &[1, 3]),
        }
    }

    fn on_timer(&mut self, _: &mut Context<'_>, _: u64) {}

    fn on_configuration(&mut self, _: &mut Context<'_>, _: &[u8]) {}
}

/// A single-node core: what it is asked to propose commits at once.
#[derive(Debug, Default)]
struct Core {
    pending: Vec<Vec<u8>>,
}

impl Propose for Core {
    fn propose(&mut self, payload: Vec<u8>) -> Result<(), NotLeader> {
        self.pending.push(payload);
        Ok(())
    }
}

/// The fixture Cluster: C10's container over the single-node core.
#[derive(Debug)]
struct Cluster {
    container: ServiceContainer<Sequencer>,
    core: Core,
    last: u64,
    session: Option<u64>,
    sequence: u64,
}

/// What the last applied request answered, with its entry.
struct Answered {
    index: u64,
    term: u64,
    reply: Option<Vec<u8>>,
}

const TERM: u64 = 1;
const CLIENT: u64 = 7;

impl Cluster {
    fn new() -> Self {
        Self {
            container: ServiceContainer::new(Sequencer::default(), ContainerConfig::default())
                .unwrap(),
            core: Core::default(),
            last: 0,
            session: None,
            sequence: 0,
        }
    }

    /// Applies every pending entry; the last request's answer.
    fn commit(&mut self) -> Option<Answered> {
        let mut answered = None;
        for payload in std::mem::take(&mut self.core.pending) {
            self.last += 1;
            let entry = Entry {
                index: self.last,
                term: TERM,
                event_time: self.last,
                payload,
            };
            match self.container.apply(&entry).unwrap() {
                Applied::Registered(Ok(registered)) => self.session = Some(registered.epoch),
                Applied::Answered { outcome, .. } => {
                    let reply = match outcome {
                        Outcome::Applied(reply) | Outcome::Retained(reply) => Some(reply.to_vec()),
                        _ => None,
                    };
                    answered = Some(Answered {
                        index: entry.index,
                        term: entry.term,
                        reply,
                    });
                }
                _ => {}
            }
        }
        answered
    }

    /// Proposes `command` as the product's client and applies it.
    fn run(&mut self, command: &[u8]) -> Option<Answered> {
        if self.session.is_none() {
            let _ = self.container.propose_bounds(&mut self.core).unwrap();
            let _ = self.commit();
            self.container
                .propose(&Envelope::Register { client: CLIENT }, &mut self.core)
                .unwrap();
            let _ = self.commit();
        }
        // A session's first sequence is 0.
        let sequence = self.sequence;
        self.sequence += 1;
        let request = karyos_cluster::Request::new(CLIENT, self.session?, sequence, sequence);
        self.container
            .propose(&Envelope::Request { request, command }, &mut self.core)
            .unwrap();
        self.commit()
    }
}

/// The product's gateway: it encodes a registered command its own way,
/// proposes it through C10 and reads the answer the entry applied with.
#[derive(Debug, Clone)]
struct Gateway {
    cluster: Arc<Mutex<Cluster>>,
    /// The answer is lost after the command applied.
    lose: Arc<AtomicBool>,
}

impl Gateway {
    fn new() -> Self {
        Self {
            cluster: Arc::new(Mutex::new(Cluster::new())),
            lose: Arc::default(),
        }
    }

    fn state(&self) -> (bool, u64, u64) {
        let cluster = self.cluster.lock().unwrap();
        let service = cluster.container.service();
        (service.killed, service.upgrade, service.runs)
    }
}

impl ClusterGateway for Gateway {
    fn commands(&self) -> Vec<AdminCommand> {
        vec![
            AdminCommand::new("kill", Authority::Operator).unwrap(),
            AdminCommand::new("reopen", Authority::Operator).unwrap(),
            AdminCommand::new("activate-upgrade", Authority::Administrator).unwrap(),
        ]
    }

    fn submit(&mut self, submission: &Submission<'_>) -> ClusterReply {
        let mut command = vec![u8::try_from(submission.command.len()).unwrap()];
        command.extend_from_slice(submission.command.as_bytes());
        command.extend_from_slice(submission.parameters);
        let answered = self.cluster.lock().unwrap().run(&command);
        if self.lose.load(Ordering::Relaxed) {
            return ClusterReply::NoAnswer;
        }
        let Some(Answered {
            index,
            term,
            reply: Some(reply),
        }) = answered
        else {
            return ClusterReply::NoAnswer;
        };
        match reply.split_first() {
            Some((0, digest)) => ClusterReply::sequenced(
                index,
                term,
                &reply,
                (!digest.is_empty()).then(|| Evidence::new("sha256", digest).unwrap()),
            )
            .unwrap(),
            Some((1, code)) => ClusterReply::refused(
                ProductCode::new(u64::from(code[0])).unwrap(),
                "refused by the product",
            ),
            _ => ClusterReply::NoAnswer,
        }
    }
}

fn submit(
    journal: &mut Journal,
    clusters: &Clusters,
    (name, parameters): (&str, &[u8]),
    operation: u64,
    clearance: Clearance,
) -> ClusterAnswer {
    let used = Mutex::new(std::collections::HashSet::new());
    cluster_command(
        Some(journal),
        clusters,
        &Command {
            cluster: "sequencer",
            command: name,
            parameters,
            operation,
            operator: 1000,
            relay: 0,
            clearance,
            reason: b"sq2 drill",
        },
        (Duration::from_secs(5), |id, take| {
            let mut used = used.lock().unwrap();
            if take {
                !used.insert(id)
            } else {
                used.contains(&id)
            }
        }),
        || 1,
    )
}

#[test]
fn an_authorised_operator_gets_the_sequenced_outcome_of_a_registered_command() {
    let dir = dir("sequenced");
    let gateway = Gateway::new();
    let mut clusters = Clusters::default();
    clusters
        .attach("sequencer", Box::new(gateway.clone()))
        .unwrap();
    let mut journal = Journal::open(&dir, 1).unwrap();
    let answer = submit(
        &mut journal,
        &clusters,
        ("kill", &[]),
        1,
        Clearance::Operator,
    );
    // Index 1 holds the bounds, 2 the registration, 3 the command.
    assert_eq!(
        answer,
        ClusterAnswer::Sequenced {
            operation: 1,
            index: 3,
            term: TERM,
            reply: vec![0],
            evidence: None,
            journalled: true,
        }
    );
    assert_eq!(gateway.state(), (true, 0, 1));
    // The product refuses a second kill: its code, verbatim.
    let answer = submit(
        &mut journal,
        &clusters,
        ("kill", &[]),
        2,
        Clearance::Operator,
    );
    assert!(
        matches!(
            answer,
            ClusterAnswer::Refused {
                operation: 2,
                code: 1,
                ..
            }
        ),
        "{answer:?}"
    );
    let answer = submit(
        &mut journal,
        &clusters,
        ("reopen", &[]),
        3,
        Clearance::Operator,
    );
    assert!(
        matches!(answer, ClusterAnswer::Sequenced { index: 5, .. }),
        "{answer:?}"
    );
    assert_eq!(gateway.state(), (false, 0, 3));
}

#[test]
fn an_upgrade_activation_shows_the_evidence_digest_the_product_attached() {
    let dir = dir("evidence");
    let gateway = Gateway::new();
    let mut clusters = Clusters::default();
    clusters
        .attach("sequencer", Box::new(gateway.clone()))
        .unwrap();
    let mut journal = Journal::open(&dir, 1).unwrap();
    let mut parameters = 42u64.to_le_bytes().to_vec();
    parameters.extend_from_slice(&[0x5a; 32]);
    // An operator may not activate an upgrade: refused, never run.
    let answer = submit(
        &mut journal,
        &clusters,
        ("activate-upgrade", &parameters),
        1,
        Clearance::Operator,
    );
    assert_eq!(
        answer,
        ClusterAnswer::Rejected {
            code: RefusalCode::Forbidden,
            journalled: true
        }
    );
    assert_eq!(gateway.state(), (false, 0, 0));
    let answer = submit(
        &mut journal,
        &clusters,
        ("activate-upgrade", &parameters),
        2,
        Clearance::Administrator,
    );
    let ClusterAnswer::Sequenced { evidence, .. } = answer else {
        panic!("sequenced: {answer:?}");
    };
    assert_eq!(evidence, Evidence::new("sha256", &[0x5a; 32]));
    assert_eq!(gateway.state(), (false, 42, 1));
    let shown = karyos_agent::json::cluster_answer(&ClusterAnswer::Sequenced {
        operation: 2,
        index: 3,
        term: 1,
        reply: vec![0],
        evidence,
        journalled: true,
    });
    assert!(
        shown.ends_with(&format!(
            r#""evidence":{{"algorithm":"sha256","digest":"{}"}}}}"#,
            "5a".repeat(32)
        )),
        "{shown}"
    );
}

#[test]
fn a_command_the_cluster_applied_but_whose_answer_was_lost_is_unknown() {
    let dir = dir("lost");
    let gateway = Gateway::new();
    gateway.lose.store(true, Ordering::Relaxed);
    let mut clusters = Clusters::default();
    clusters
        .attach("sequencer", Box::new(gateway.clone()))
        .unwrap();
    let mut journal = Journal::open(&dir, 1).unwrap();
    let answer = submit(
        &mut journal,
        &clusters,
        ("kill", &[]),
        1,
        Clearance::Operator,
    );
    // The Cluster did kill: the agent cannot know it, and never says so.
    assert_eq!(
        answer,
        ClusterAnswer::NoAnswer {
            operation: 1,
            journalled: true
        }
    );
    assert_eq!(gateway.state(), (true, 0, 1));
    assert_eq!(
        karyos_agent::json::cluster_answer(&answer),
        r#"{"error":"no answer","operation":1,"outcome":"unknown"}"#
    );
}

#[test]
fn an_unregistered_command_never_reaches_the_cluster() {
    let dir = dir("unregistered");
    let gateway = Gateway::new();
    let mut clusters = Clusters::default();
    clusters
        .attach("sequencer", Box::new(gateway.clone()))
        .unwrap();
    let mut journal = Journal::open(&dir, 1).unwrap();
    let answer = submit(
        &mut journal,
        &clusters,
        ("promote", &[]),
        1,
        Clearance::Administrator,
    );
    assert_eq!(
        answer,
        ClusterAnswer::Rejected {
            code: RefusalCode::UnregisteredCommand,
            journalled: true
        }
    );
    assert_eq!(gateway.state(), (false, 0, 0));
}

/// The operation through the agent's socket, by role and by relay.
#[cfg(target_os = "linux")]
mod socket {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Instant;

    use karyos_agent::server::{ApiConfig, Principal, Role, Served, Server};
    use karyos_agent::{Agent, AgentConfig};

    use super::*;

    fn ask(config: ApiConfig, agent: &mut Agent, line: &str) -> String {
        let mut server = Server::bind(config).unwrap();
        let path = server.path().to_path_buf();
        let line = format!("{line}\n");
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
            client.join().unwrap().trim_end().to_owned()
        })
    }

    fn local(dir: &std::path::Path, role: Role) -> ApiConfig {
        ApiConfig::new(
            dir.join(format!("api-{role:?}")),
            vec![(karyos_sys::ipc::own_uid(), role)],
        )
    }

    #[test]
    fn roles_bound_the_commands_through_the_socket_and_a_relay_carries_its_principal() {
        let dir = dir("socket");
        let gateway = Gateway::new();
        let mut agent = Agent::new(AgentConfig::new(Vec::new()).with_journal(dir.join("journal")));
        let caps =
            karyos_agent::json::capabilities(&agent.capabilities(true, false, false, false, false));
        assert!(
            caps.contains(
                r#"{"name":"cluster-command","state":"unavailable","reason":"not_configured"}"#
            ),
            "{caps}"
        );
        agent
            .attach_cluster("sequencer", Box::new(gateway.clone()))
            .unwrap();
        for role in [Role::Viewer, Role::Registrar] {
            let answer = ask(
                local(&dir, role),
                &mut agent,
                "KARYOS-AGENT 1 cluster-command 10 sequencer kill - drill",
            );
            assert_eq!(
                answer, r#"{"error":"forbidden","journalled":true}"#,
                "{role:?}"
            );
        }
        assert_eq!(gateway.state(), (false, 0, 0));
        let answer = ask(
            local(&dir, Role::Operator),
            &mut agent,
            "KARYOS-AGENT 1 cluster-command 10 sequencer kill - drill",
        );
        assert_eq!(
            answer,
            r#"{"operation":10,"outcome":"sequenced","index":3,"term":1,"reply":"00","evidence":null}"#
        );
        // The id is used up.
        let answer = ask(
            local(&dir, Role::Administrator),
            &mut agent,
            "KARYOS-AGENT 1 cluster-command 10 sequencer reopen -",
        );
        assert_eq!(
            answer,
            r#"{"error":"operation id conflict","journalled":true}"#
        );
        let answer = ask(
            local(&dir, Role::Operator),
            &mut agent,
            "KARYOS-AGENT 1 cluster-command 11 sequencer kill zz",
        );
        assert_eq!(
            answer,
            r#"{"error":"bad arguments","request":"cluster-command"}"#
        );
        // A relay carries a principal's request with the principal's role.
        let relayed = ApiConfig::new(dir.join("api-relay"), Vec::new()).with_relays(
            vec![(karyos_sys::ipc::own_uid(), 9)],
            vec![Principal::new("alice", 4242, Role::RiskOfficer).unwrap()],
        );
        let answer = ask(
            relayed,
            &mut agent,
            "KARYOS-AGENT 1 relay alice cluster-command 12 sequencer reopen - sq2",
        );
        assert!(answer.contains(r#""outcome":"sequenced""#), "{answer}");
        assert_eq!(gateway.state(), (false, 0, 2));
        let caps = karyos_agent::json::capabilities(
            &agent.capabilities(false, false, false, false, false),
        );
        assert!(
            caps.contains(r#"{"name":"cluster-command","state":"forbidden","reason":"role"}"#),
            "{caps}"
        );
        // A restart keeps the ids used.
        agent.stop().unwrap();
        drop(agent);
        let mut agent = Agent::new(AgentConfig::new(Vec::new()).with_journal(dir.join("journal")));
        agent
            .attach_cluster("sequencer", Box::new(gateway.clone()))
            .unwrap();
        let answer = ask(
            local(&dir, Role::Administrator),
            &mut agent,
            "KARYOS-AGENT 1 cluster-command 12 sequencer kill -",
        );
        assert_eq!(
            answer,
            r#"{"error":"operation id conflict","journalled":true}"#
        );
    }
}
