// SPDX-License-Identifier: Apache-2.0

//! C7a's session table (karyos-cluster `dedup`) under retries, checked
//! with C3's linearizability checker (quantstratum-docs:
//! karyos/design/cluster-dedup-and-snapshots.md §2 and §4, W5).
//!
//! A counter service runs on three replicas, each with its own session
//! table, all applying one log in order (the core is not needed: C7a is
//! driven only by applied entries). Clients add to the counter over a
//! lossy path: a request may be lost before the log, appended twice, or
//! its reply lost, and a client retries the same sequence until it gets a
//! reply. A reply may come from any replica, as after a leader change.
//! Each client keeps up to two requests in flight. With a short TTL some
//! sessions expire mid-request: the client then gives its open requests
//! up as pending (it cannot know whether they ran) and registers again
//! under a new epoch.
//!
//! Every seed's history must be linearizable as a counter, and every
//! replica must answer each entry alike and end with the same table and
//! counter. The negative control applies every entry without the table:
//! some seed must then fail the checker, so the workload does exercise
//! duplicates.
//!
//! The table is in memory, so C2's simulated disk does not apply here; it
//! comes with snapshots (C8).

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use karyos_cluster::dedup::{DedupConfig, Outcome, Request, SessionTable};
use karyos_sim::Rng;
use karyos_sim::lin::{self, History, Limit, Model, Verdict};

const CLIENTS: u64 = 4;
const REPLICAS: usize = 3;
const STEPS: u32 = 400;
const IN_FLIGHT: u64 = 2;

/// A counter: `Add(n)` returns the new value.
struct Counter;

impl Model for Counter {
    type State = u64;
    type Op = u64;
    type Ret = u64;

    fn init(&self) -> u64 {
        0
    }

    fn step(&self, state: &u64, op: &u64) -> (u64, u64) {
        let next = state + op;
        (next, next)
    }
}

/// One replica: its table (unless it is the control) and its counter.
struct Replica {
    table: Option<SessionTable>,
    counter: u64,
}

/// What one replica answered an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    Value(u64),
    Duplicate,
    Expired,
    Refused,
}

impl Replica {
    fn new(config: Option<DedupConfig>) -> Self {
        Self {
            table: config.map(|config| SessionTable::new(config).unwrap()),
            counter: 0,
        }
    }

    fn register(&mut self, client: u64, epoch: u64, time: u64) {
        if let Some(table) = &mut self.table {
            table.register(client, epoch, time).unwrap();
        }
    }

    fn apply(&mut self, request: Request, add: u64, time: u64) -> Answer {
        let counter = &mut self.counter;
        let Some(table) = &mut self.table else {
            *counter += add;
            return Answer::Value(*counter);
        };
        let outcome = table.request(request, time, |buffer| {
            *counter += add;
            buffer.get_mut(..8)?.copy_from_slice(&counter.to_le_bytes());
            Some(8)
        });
        match outcome {
            Outcome::Applied(bytes) | Outcome::Retained(bytes) => {
                Answer::Value(u64::from_le_bytes(bytes.try_into().unwrap()))
            }
            Outcome::Duplicate => Answer::Duplicate,
            Outcome::SessionExpired => Answer::Expired,
            _ => Answer::Refused,
        }
    }
}

/// One request a client has in flight.
#[derive(Clone, Copy)]
struct Open {
    sequence: u64,
    add: u64,
    /// The history's client the request was invoked under.
    history: u32,
}

struct Client {
    epoch: u64,
    next: u64,
    open: Vec<Open>,
    /// History ids of this client's in-flight slots, renewed at each epoch
    /// so a given-up request stays pending.
    slots: [u32; 2],
}

struct Run {
    history: History<u64, u64>,
    replicas: Vec<Replica>,
    expiries: u32,
    duplicates: u32,
}

fn run(seed: u64, config: Option<DedupConfig>) -> Run {
    let mut rng = Rng::new(seed);
    let mut replicas: Vec<Replica> = (0..REPLICAS).map(|_| Replica::new(config)).collect();
    let mut history = History::new();
    let mut ids = 0u32;
    let mut fresh = || {
        ids += 1;
        ids
    };
    let mut time = 0u64;
    let mut clients: Vec<Client> = (0..CLIENTS)
        .map(|client| {
            for replica in &mut replicas {
                replica.register(client, 1, time);
            }
            Client {
                epoch: 1,
                next: 0,
                open: Vec::new(),
                slots: [fresh(), fresh()],
            }
        })
        .collect();
    let (mut expiries, mut duplicates) = (0, 0);
    for _ in 0..STEPS {
        time += rng.below(6);
        let id = rng.below(CLIENTS);
        let client = &mut clients[usize::try_from(id).unwrap()];
        // Start a request when there is room, else retry an open one.
        let open = if u64::try_from(client.open.len()).unwrap() < IN_FLIGHT && rng.chance(1, 2) {
            let used: Vec<u32> = client.open.iter().map(|open| open.history).collect();
            let slot = *client
                .slots
                .iter()
                .find(|slot| !used.contains(slot))
                .unwrap();
            let open = Open {
                sequence: client.next,
                add: rng.between(1, 9),
                history: slot,
            };
            client.next += 1;
            client.open.push(open);
            history.invoke(slot, open.add);
            open
        } else if let Some(open) = client.open.first() {
            *open
        } else {
            continue;
        };
        // Lost before the log.
        if rng.chance(1, 5) {
            continue;
        }
        let lowest = client.open.iter().map(|open| open.sequence).min().unwrap();
        let request = Request::new(id, client.epoch, open.sequence, lowest);
        let copies = if rng.chance(1, 4) { 2 } else { 1 };
        let mut answer = None;
        for _ in 0..copies {
            let answers: Vec<Answer> = replicas
                .iter_mut()
                .map(|replica| replica.apply(request, open.add, time))
                .collect();
            assert!(
                answers.windows(2).all(|pair| pair[0] == pair[1]),
                "seed {seed}"
            );
            // Any replica answers, as after a leader change.
            answer = Some(answers[usize::try_from(rng.below(3)).unwrap()]);
        }
        duplicates += copies - 1;
        // The reply is lost.
        if rng.chance(1, 4) {
            continue;
        }
        match answer.unwrap() {
            Answer::Value(value) => {
                history.ret(open.history, value);
                client.open.retain(|held| held.sequence != open.sequence);
            }
            Answer::Expired => {
                // Its open requests stay pending; register afresh.
                expiries += 1;
                client.epoch += 1;
                client.next = 0;
                client.open.clear();
                client.slots = [fresh(), fresh()];
                for replica in &mut replicas {
                    replica.register(id, client.epoch, time);
                }
            }
            // A retry of an acknowledged reply, or a refused window or
            // order: the client retries later.
            Answer::Duplicate | Answer::Refused => {}
        }
    }
    Run {
        history,
        replicas,
        expiries,
        duplicates,
    }
}

fn limit() -> Limit {
    Limit {
        max_configurations: 1 << 22,
    }
}

fn small(ttl: u64) -> DedupConfig {
    DedupConfig::default()
        .with_sessions(8)
        .with_window(4)
        .with_response_bytes(8)
        .with_ttl(ttl)
}

#[test]
fn retried_requests_are_linearizable_and_replicas_agree() {
    let (mut expiries, mut duplicates) = (0, 0);
    for seed in 0..40 {
        // Half the seeds expire sessions mid-request.
        let ttl = if seed % 2 == 0 { 1 << 40 } else { 60 };
        let run = run(seed, Some(small(ttl)));
        let verdict = lin::check(&Counter, &run.history, limit()).unwrap();
        assert!(
            matches!(verdict, Verdict::Linearizable(_)),
            "seed {seed}: {verdict:?}"
        );
        let first = &run.replicas[0];
        for replica in &run.replicas[1..] {
            assert_eq!(replica.table, first.table, "seed {seed}");
            assert_eq!(replica.counter, first.counter, "seed {seed}");
        }
        expiries += run.expiries;
        duplicates += run.duplicates;
    }
    // The workload did retry, duplicate and expire.
    assert!(duplicates > 100, "{duplicates}");
    assert!(expiries > 10, "{expiries}");
}

#[test]
fn without_the_table_retries_break_linearizability() {
    let broken = (0..40)
        .filter(|seed| {
            let run = run(*seed, None);
            matches!(
                lin::check(&Counter, &run.history, limit()).unwrap(),
                Verdict::NotLinearizable(_)
            )
        })
        .count();
    assert!(broken > 0);
}
