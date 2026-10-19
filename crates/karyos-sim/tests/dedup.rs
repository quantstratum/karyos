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
//! Any earlier entry, a registration or a request, may also be appended
//! again much later, past its session's expiry: nobody waits for that
//! late duplicate's answer, and it must not run a command again or revive
//! a session (REVIEWER-02's F1 and F2 on #458). A registration goes
//! through the log too; its session's epoch is its log index, and a lost
//! reply makes the client register again.
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

use std::collections::HashMap;

use karyos_cluster::dedup::{DedupConfig, Outcome, RegisterError, Request, SessionTable};
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

    /// Applies a registration at log index `index`: the session's epoch,
    /// or `None` for a full table.
    fn register(&mut self, client: u64, index: u64, time: u64) -> Option<u64> {
        let Some(table) = &mut self.table else {
            return Some(index);
        };
        match table.register(client, index, time) {
            Ok(registered) => Some(registered.epoch),
            Err(RegisterError::SessionsExhausted) => None,
            Err(error) => panic!("{error}"),
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
    /// Its session's epoch, `None` until a registration is applied.
    epoch: Option<u64>,
    next: u64,
    open: Vec<Open>,
    /// History ids of this client's in-flight slots, renewed at each epoch
    /// so a given-up request stays pending.
    slots: [u32; 2],
}

/// An entry as the log carries it.
#[derive(Clone, Copy)]
enum Entry {
    Register { client: u64 },
    Request { request: Request, add: u64 },
}

/// The log: every replica applies each entry in order, at the next index.
struct Log {
    replicas: Vec<Replica>,
    index: u64,
    /// Every entry appended, for late duplicates.
    past: Vec<Entry>,
    /// The first value each request answered, by client, epoch and
    /// sequence: every later answer of that request, a late duplicate's
    /// included, must be the same value or none.
    answered: HashMap<(u64, u64, u64), u64>,
    seed: u64,
    /// The replicas keep session tables (not the control).
    table: bool,
}

/// What the replicas answered an entry, alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Applied {
    Registered(Option<u64>),
    Answered(Answer),
}

impl Log {
    fn append(&mut self, entry: Entry, time: u64) -> Applied {
        self.index += 1;
        self.past.push(entry);
        let index = self.index;
        let answers: Vec<Applied> = self
            .replicas
            .iter_mut()
            .map(|replica| match entry {
                Entry::Register { client } => {
                    Applied::Registered(replica.register(client, index, time))
                }
                Entry::Request { request, add } => {
                    Applied::Answered(replica.apply(request, add, time))
                }
            })
            .collect();
        assert!(
            answers.windows(2).all(|pair| pair[0] == pair[1]),
            "seed {}",
            self.seed
        );
        if let (Entry::Request { request, .. }, Applied::Answered(Answer::Value(value))) =
            (entry, answers[0])
            && self.table
        {
            let key = (request.client, request.epoch, request.sequence);
            let first = *self.answered.entry(key).or_insert(value);
            assert_eq!(
                first, value,
                "seed {}: request {key:?} answered twice",
                self.seed
            );
        }
        answers[0]
    }
}

struct Run {
    history: History<u64, u64>,
    replicas: Vec<Replica>,
    expiries: u32,
    duplicates: u32,
    late: u32,
}

fn run(seed: u64, config: Option<DedupConfig>) -> Run {
    let mut rng = Rng::new(seed);
    let mut log = Log {
        replicas: (0..REPLICAS).map(|_| Replica::new(config)).collect(),
        index: 0,
        past: Vec::new(),
        answered: HashMap::new(),
        seed,
        table: config.is_some(),
    };
    let mut history = History::new();
    let mut ids = 0u32;
    let mut fresh = || {
        ids += 1;
        ids
    };
    let mut time = 0u64;
    let mut clients: Vec<Client> = (0..CLIENTS)
        .map(|_| Client {
            epoch: None,
            next: 0,
            open: Vec::new(),
            slots: [fresh(), fresh()],
        })
        .collect();
    let (mut expiries, mut duplicates, mut late) = (0, 0, 0);
    for _ in 0..STEPS {
        time += rng.below(6);
        // A late duplicate of any earlier entry, registrations included:
        // nobody waits for its answer.
        if rng.chance(1, 6) {
            let at =
                usize::try_from(rng.below(u64::try_from(log.past.len()).unwrap().max(1))).unwrap();
            if let Some(entry) = log.past.get(at).copied() {
                let _ = log.append(entry, time);
                late += 1;
            }
        }
        let id = rng.below(CLIENTS);
        let client = &mut clients[usize::try_from(id).unwrap()];
        let Some(epoch) = client.epoch else {
            // Register; the reply may be lost, and the client asks again.
            let Applied::Registered(epoch) = log.append(Entry::Register { client: id }, time)
            else {
                unreachable!()
            };
            if !rng.chance(1, 4) {
                client.epoch = epoch;
            }
            continue;
        };
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
        let entry = Entry::Request {
            request: Request::new(id, epoch, open.sequence, lowest),
            add: open.add,
        };
        let copies = if rng.chance(1, 4) { 2 } else { 1 };
        let mut answer = None;
        for _ in 0..copies {
            let Applied::Answered(answered) = log.append(entry, time) else {
                unreachable!()
            };
            answer = Some(answered);
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
                client.epoch = None;
                client.next = 0;
                client.open.clear();
                client.slots = [fresh(), fresh()];
            }
            // A retry of an acknowledged reply, or a refused window or
            // order: the client retries later.
            Answer::Duplicate | Answer::Refused => {}
        }
    }
    Run {
        history,
        replicas: log.replicas,
        expiries,
        duplicates,
        late,
    }
}

fn limit() -> Limit {
    Limit {
        max_configurations: 1 << 22,
    }
}

fn small(ttl: u64) -> DedupConfig {
    DedupConfig::default()
        .with_sessions(16)
        .with_window(4)
        .with_response_bytes(8)
        .with_ttl(ttl)
}

#[test]
fn retried_requests_are_linearizable_and_replicas_agree() {
    let (mut expiries, mut duplicates, mut late) = (0, 0, 0);
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
        late += run.late;
    }
    // The workload did retry, duplicate and expire.
    assert!(duplicates > 100, "{duplicates}");
    assert!(expiries > 10, "{expiries}");
    assert!(late > 500, "{late}");
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
