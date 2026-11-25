// SPDX-License-Identifier: Apache-2.0

//! One client of a real-process run (C5 v2, "Processes"; karyos#691):
//! `raft-eval-client <case> <client> <id>=<address>...`, `<case>` the index
//! of a case in `process::cases()` and the addresses the servers'.
//!
//! The client runs its window of sessions (`Case::window`, W2's bursts:
//! each session one request open at once): sessions `client * window` to
//! `client * window + window - 1` of the case. Each session is the
//! harness's own client, `harness::node::ClientNode`, with the case's
//! script for that session (`workloads::script`), its id as
//! `workloads::run` numbers it, its first server the first one, and the
//! case's `retry_after`. All of them share one connection per server, each
//! frame naming its session. Each sends its requests to the server it is told,
//! follows a redirect, sends again after a refusal or its retry delay, and
//! records its history and observations, each stamped from the host's
//! monotonic clock when it is recorded (`karyos_raft_eval::record`): an
//! invocation before its request leaves, a return after its answer
//! arrived. One tick of it is `process::TICK_MS` of its process's clock,
//! so it runs for at most the case's `steps` ticks.
//!
//! It prints every stamped line, then `client <id> <done>` for each
//! session, `done` 1 when its script completed, and exits 0; a malformed argument prints the
//! usage and exits 2.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::Write as _;
use std::net::{SocketAddr, TcpStream};
use std::process::ExitCode;
use std::rc::Rc;
use std::time::{Duration, Instant};

use karyos_raft_eval::process::{Connection, cases, client_id, frame, ticks_since};
use karyos_raft_eval::record::{self, Item};
use karyos_sim::cluster::{Node as _, Outbox};
use karyos_sim::harness::node::{ClientNode, Recorder, Shared, Wire};
use karyos_sim::harness::workloads::{self, Case};
use karyos_sim::net::NodeId;

/// How long one connection attempt waits.
const CONNECT: Duration = Duration::from_millis(20);

/// A server's connection, opened when first needed and again after it
/// closed; frames for it wait until it is open.
#[derive(Default)]
struct Link {
    connection: Option<Connection>,
    waiting: Vec<Vec<u8>>,
}

/// The servers, by id and address.
type Servers = Vec<(NodeId, SocketAddr)>;

/// What a client reports: each session's id and whether its script
/// completed, and its stamped lines.
type Report = (Vec<(NodeId, bool)>, Vec<(u64, Item)>);

fn parsed() -> Option<(Case, usize, Servers)> {
    let mut args = std::env::args_os().skip(1);
    let index: usize = args.next()?.into_string().ok()?.parse().ok()?;
    let case = cases().into_iter().nth(index)?;
    let client: usize = args.next()?.into_string().ok()?.parse().ok()?;
    let servers = args
        .map(|server| {
            let server = server.into_string().ok()?;
            let (id, address) = server.split_once('=')?;
            Some((id.parse().ok()?, address.parse::<SocketAddr>().ok()?))
        })
        .collect::<Option<Vec<_>>>()?;
    if client >= case.clients || servers.is_empty() {
        return None;
    }
    if servers
        .iter()
        .any(|(_, address)| !address.ip().is_loopback())
    {
        return None;
    }
    Some((case, client, servers))
}

/// Moves what the client recorded since the last call into `items`, each
/// stamped now.
fn stamp(recorder: &Shared, items: &mut Vec<(u64, Item)>) {
    let mut recorded = recorder.borrow_mut();
    let stamp = record::now();
    for event in std::mem::take(&mut recorded.history).events() {
        let item = match event {
            karyos_sim::lin::Event::Invoke { client, op } => Item::Invoke {
                client: *client,
                op: op.clone(),
            },
            karyos_sim::lin::Event::Return { client, ret } => Item::Return {
                client: *client,
                ret: ret.clone(),
            },
        };
        items.push((stamp, item));
    }
    for observation in recorded.observations.drain(..) {
        items.push((stamp, Item::Observation(observation)));
    }
}

fn run(case: &Case, client: usize, servers: &[(NodeId, SocketAddr)]) -> Option<Report> {
    let first = servers.first().map(|(server, _)| *server)?;
    let window = case.window.max(1);
    // As `workloads::run` builds its clients: a retry after silence goes
    // to the next of the case's servers.
    let servers_count = NodeId::try_from(case.servers).ok()?;
    let recorder: Shared = Rc::new(RefCell::new(Recorder::default()));
    let mut sessions: BTreeMap<NodeId, ClientNode> = BTreeMap::new();
    for slot in 0..window {
        let session = client.checked_mul(window)?.checked_add(slot)?;
        let id = client_id(case, session)?;
        let node = ClientNode::new(
            id,
            first,
            workloads::script(case, session),
            Rc::clone(&recorder),
        )
        .with_retry_after(case.retry_after)
        .with_servers(servers_count);
        let _ = sessions.insert(id, node);
    }
    let mut links: BTreeMap<NodeId, Link> = BTreeMap::new();
    // Frames for servers, as the sessions send them, before their links.
    let mut pending: Vec<(NodeId, Vec<u8>)> = Vec::new();
    let mut items = Vec::new();
    let mut scratch = vec![0u8; 1 << 16];
    let mut out: Outbox<Wire<()>> = Vec::new();
    let mut ticked: Option<u64> = None;
    let start = Instant::now();
    loop {
        let now = ticks_since(start);
        if sessions.values().all(ClientNode::done) || now >= case.steps {
            break;
        }
        let mut quiet = true;
        for (server, link) in &mut links {
            let Some(connection) = link.connection.as_mut() else {
                continue;
            };
            for (id, message) in connection.poll::<()>(&mut scratch) {
                quiet = false;
                if let Some(session) = sessions.get_mut(&id) {
                    session.deliver(*server, message, now, &mut out);
                    stamp(&recorder, &mut items);
                    for (to, message) in out.drain(..) {
                        if let Some(framed) = frame(id, &message) {
                            pending.push((to, framed));
                        }
                    }
                }
            }
            if connection.closed() {
                link.connection = None;
            }
        }
        if ticked != Some(now) {
            ticked = Some(now);
            for (id, session) in &mut sessions {
                session.tick(now, &mut out);
                stamp(&recorder, &mut items);
                for (to, message) in out.drain(..) {
                    if let Some(framed) = frame(*id, &message) {
                        pending.push((to, framed));
                    }
                }
            }
        }
        for (to, framed) in pending.drain(..) {
            links.entry(to).or_default().waiting.push(framed);
        }
        for (server, link) in &mut links {
            if link.waiting.is_empty() {
                continue;
            }
            if link.connection.is_none() {
                let Some(address) = servers
                    .iter()
                    .find(|(id, _)| id == server)
                    .map(|(_, address)| *address)
                else {
                    link.waiting.clear();
                    continue;
                };
                // Not listening yet: the frames wait for the next loop.
                link.connection = TcpStream::connect_timeout(&address, CONNECT)
                    .ok()
                    .and_then(|stream| Connection::new(stream).ok());
            }
            if let Some(connection) = link.connection.as_mut() {
                for framed in link.waiting.drain(..) {
                    connection.queue(&framed);
                }
                connection.flush();
            }
        }
        if quiet {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    stamp(&recorder, &mut items);
    let done = sessions
        .iter()
        .map(|(id, session)| (*id, session.done()))
        .collect();
    Some((done, items))
}

fn main() -> ExitCode {
    let Some((case, client, servers)) = parsed() else {
        let _ = writeln!(
            std::io::stderr(),
            "usage: raft-eval-client <case> <client> <id>=<address>..."
        );
        return ExitCode::from(2);
    };
    let Some((done, items)) = run(&case, client, &servers) else {
        let _ = writeln!(std::io::stderr(), "raft-eval-client: no session id");
        return ExitCode::FAILURE;
    };
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    let written = items
        .iter()
        .filter_map(|(stamp, item)| record::encode(*stamp, item))
        .try_for_each(|line| writeln!(out, "{line}"))
        .and_then(|()| {
            done.iter()
                .try_for_each(|(id, done)| writeln!(out, "client {id} {}", u8::from(*done)))
        })
        .and_then(|()| out.flush());
    match written {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(std::io::stderr(), "raft-eval-client {client}: {error}");
            ExitCode::FAILURE
        }
    }
}
