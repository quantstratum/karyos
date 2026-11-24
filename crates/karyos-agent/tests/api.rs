// SPDX-License-Identifier: Apache-2.0

//! API v1 on its Unix socket (Linux; quantstratum-docs:
//! karyos/design/management-agent-gap-analysis.md, M7): a v1 client reads
//! the view; another version, a uid without a role and a malformed request
//! are refused with a JSON error; the socket's directory must be private,
//! a live agent's socket is never taken over and a stale one is.

#![cfg(target_os = "linux")]
// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use karyos_agent::server::{ApiConfig, Role, ServeError, Served, Server};
use karyos_agent::{Agent, AgentConfig};
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
    let dir = std::env::temp_dir().join(format!("karyos-api-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn driver(dir: &Path) -> IpcDriver {
    driver_with(dir, DriverConfig::default())
}

fn driver_with(dir: &Path, config: DriverConfig) -> IpcDriver {
    EmbeddedDriver::with_ipc(
        config,
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

/// An agent attached to a running driver in `name`'s directory.
fn attached(name: &str) -> (IpcDriver, Agent, PathBuf) {
    attached_with(name, DriverConfig::default())
}

/// As [`attached`], the driver configured with `config`.
fn attached_with(name: &str, config: DriverConfig) -> (IpcDriver, Agent, PathBuf) {
    let dir = dir(name);
    std::fs::create_dir_all(&dir).unwrap();
    let mut driver = driver_with(&dir.join("driver"), config);
    let mut agent = Agent::new(
        AgentConfig::new(vec![dir.join("driver")]).with_attach_timeout(Duration::from_secs(5)),
    );
    std::thread::scope(|scope| {
        let handle = scope.spawn(|| agent.refresh());
        let start = Instant::now();
        while !handle.is_finished() {
            assert!(start.elapsed() < Duration::from_secs(30), "stuck");
            let _ = driver.do_work().unwrap();
            std::thread::sleep(Duration::from_micros(200));
        }
        handle.join().unwrap();
    });
    (driver, agent, dir)
}

fn own() -> u32 {
    karyos_sys::ipc::own_uid()
}

/// Sends `request` from another thread and serves it; the answer, and how
/// the server says it served it.
fn ask(server: &mut Server, agent: &mut Agent, request: &str) -> (String, Vec<Served>) {
    let path = server.path().to_path_buf();
    std::thread::scope(|scope| {
        let client = scope.spawn(move || {
            let mut stream = UnixStream::connect(path).unwrap();
            stream.write_all(request.as_bytes()).unwrap();
            let mut answer = String::new();
            let _ = stream.read_to_string(&mut answer).unwrap();
            answer
        });
        let mut served = Vec::new();
        let start = Instant::now();
        while served.is_empty() {
            assert!(start.elapsed() < Duration::from_secs(10), "never served");
            served = server.poll(agent).unwrap();
            std::thread::sleep(Duration::from_millis(1));
        }
        (client.join().unwrap(), served)
    })
}

/// ADR-0055's compatibility test, over the socket: a client that speaks
/// v1 gets the view, whose fields are those of `json::tests::V1`.
#[test]
fn a_v1_client_reads_the_view() {
    let _serial = serial();
    let (driver, mut agent, dir) = attached("view");
    let mut server =
        Server::bind(ApiConfig::new(dir.join("api"), vec![(own(), Role::Viewer)])).unwrap();
    let (answer, served) = ask(&mut server, &mut agent, "KARYOS-AGENT 1 view\n");
    assert_eq!(served, [Served::View]);
    let instance = format!("{:032x}", driver.instance().unwrap());
    let expected = format!(
        r#"{{"version":1,"drivers":[{{"dir":"{}","state":{{"state":"attached"}},"instance":"{instance}","sample":{{"consistent":"#,
        dir.join("driver").display()
    );
    assert!(answer.starts_with(&expected), "{answer}");
    // No journal configured: `journal` is null (M10b). Then the agent's
    // identity, added after it (R-CORE-24): no id configured here.
    let agent_field = format!(
        r#"}}],"journal":null,"agent":{{"id":null,"pid":{},"started_ns":"#,
        std::process::id()
    );
    assert!(answer.contains(&agent_field), "{answer}");
    assert!(
        answer.contains(r#""catalog":null,"attachment":{"since_ns":"#),
        "{answer}"
    );
    assert!(answer.contains(r#""label":"driver pid""#));
}

/// R-CORE-24: capability discovery, answered per role. What the deployment
/// does not offer is `unavailable`, whatever the role; what it offers but
/// the role lacks is `forbidden`. A known request with stray arguments gets
/// its own typed error; a request this agent does not know is `bad
/// request`, which is what an agent without discovery answers.
#[test]
fn capabilities_tell_unavailable_from_forbidden() {
    let _serial = serial();
    let (_driver, mut agent, dir) = attached("capabilities");
    let answer = |role: Role, agent: &mut Agent| {
        let mut server =
            Server::bind(ApiConfig::new(dir.join("api"), vec![(own(), role)])).unwrap();
        let (answer, served) = ask(&mut server, agent, "KARYOS-AGENT 1 capabilities\n");
        assert_eq!(served, [Served::Capabilities]);
        answer
    };
    // No journal and no Archive configured.
    let viewer = answer(Role::Viewer, &mut agent);
    assert_eq!(
        viewer,
        concat!(
            r#"{"capabilities":[{"name":"view","state":"served","reason":null},"#,
            r#"{"name":"guard-close","state":"forbidden","reason":"role"},"#,
            r#"{"name":"guard-reopen","state":"unavailable","reason":"not_configured"},"#,
            r#"{"name":"gap-ack","state":"unavailable","reason":"not_configured"},"#,
            r#"{"name":"catalog","state":"unavailable","reason":"not_configured"},"#,
            r#"{"name":"trace-window","state":"served","reason":null},"#,
            r#"{"name":"limits","state":"served","reason":null},{"name":"trace-buckets","state":"served","reason":null},"#,
            r#"{"name":"trace-export","state":"served","reason":null},"#,
            r#"{"name":"join-registry","state":"served","reason":null},"#,
            r#"{"name":"join-put","state":"forbidden","reason":"role"},"#,
            r#"{"name":"rate-change","state":"forbidden","reason":"role"},"#,
            r#"{"name":"guard-preview","state":"forbidden","reason":"role"},"#,
            r#"{"name":"submit","state":"forbidden","reason":"role"}]}"#,
            "\n"
        )
    );
    // An operator may close: served. Reopening needs a journal this
    // deployment does not have: unavailable, not forbidden.
    let operator = answer(Role::Operator, &mut agent);
    assert!(operator.contains(r#"{"name":"guard-close","state":"served","reason":null}"#));
    assert!(
        operator
            .contains(r#"{"name":"guard-reopen","state":"unavailable","reason":"not_configured"}"#)
    );
    let mut server =
        Server::bind(ApiConfig::new(dir.join("api"), vec![(own(), Role::Viewer)])).unwrap();
    let (answer, served) = ask(&mut server, &mut agent, "KARYOS-AGENT 1 capabilities all\n");
    assert_eq!(served, [Served::Refused]);
    assert_eq!(
        answer,
        "{\"error\":\"bad arguments\",\"request\":\"capabilities\"}\n"
    );
    let (answer, _) = ask(&mut server, &mut agent, "KARYOS-AGENT 1 capabilities-v2\n");
    assert_eq!(answer, "{\"error\":\"bad request\"}\n");
}

/// R-CORE-24: a configured journal turns reopen and acknowledgement into
/// role questions, and a catalog configured for a driver is served.
#[test]
fn a_configured_journal_and_catalog_are_served_by_role() {
    let _serial = serial();
    let dir = dir("capabilities-configured");
    std::fs::create_dir_all(&dir).unwrap();
    // A regular file where the journal's directory should be: it cannot
    // open.
    std::fs::write(dir.join("not-a-journal"), b"x").unwrap();
    let _driver = driver(&dir.join("driver"));
    let agent = Agent::new(
        AgentConfig::new(vec![dir.join("driver")])
            .with_attach_timeout(Duration::from_secs(5))
            .with_journal(dir.join("not-a-journal"))
            .with_archive(
                dir.join("driver"),
                karyos_agent::catalog::CatalogConfig::new(
                    karyos_agent::catalog::ArchiveStreams::new(1, 2),
                ),
            ),
    );
    let caps = agent.capabilities(false, false, false, false);
    let state = |name: &str| {
        caps.iter()
            .find(|capability| capability.name == name)
            .map(|capability| capability.state)
            .unwrap()
    };
    use karyos_agent::api::CapabilityState;
    // A journal configured but not opened: reopens need it; the
    // acknowledgement of its unknown interval does not.
    assert_eq!(
        state("guard-reopen"),
        CapabilityState::Unavailable {
            reason: "journal_unavailable"
        }
    );
    assert_eq!(
        state("gap-ack"),
        CapabilityState::Forbidden { reason: "role" }
    );
    assert_eq!(state("catalog"), CapabilityState::Served);
}

#[test]
fn other_versions_uids_without_a_role_and_bad_requests_are_refused() {
    let _serial = serial();
    let (_driver, mut agent, dir) = attached("refused");
    let mut server = Server::bind(ApiConfig::new(
        dir.join("api"),
        vec![(own(), Role::Operator)],
    ))
    .unwrap();
    let (answer, served) = ask(&mut server, &mut agent, "KARYOS-AGENT 2 view\n");
    assert_eq!(served, [Served::Refused]);
    assert_eq!(
        answer,
        "{\"error\":\"unsupported version\",\"supported\":[1]}\n"
    );
    let (answer, _) = ask(&mut server, &mut agent, "GET / HTTP/1.1\r\n");
    assert_eq!(answer, "{\"error\":\"bad request\"}\n");
    drop(server);
    // This uid has no role here.
    let mut server = Server::bind(ApiConfig::new(
        dir.join("api"),
        vec![(own().wrapping_add(1), Role::Administrator)],
    ))
    .unwrap();
    let (answer, served) = ask(&mut server, &mut agent, "KARYOS-AGENT 1 view\n");
    assert_eq!(served, [Served::Refused]);
    assert_eq!(answer, "{\"error\":\"not authorized\"}\n");
}

/// R-CORE-38 over the socket: `limits` answers every dimension with one of
/// the three answers, a proposal within a fixed bound gets the bound, and
/// one above it is refused with the bound. No bound changed.
#[test]
fn a_client_negotiates_the_limits() {
    let _serial = serial();
    let (_driver, mut agent, dir) = attached("limits");
    let mut server =
        Server::bind(ApiConfig::new(dir.join("api"), vec![(own(), Role::Viewer)])).unwrap();
    let all = concat!(
        r#"{"limits":{"read.request_bytes":{"value":256,"negotiable":true},"#,
        r#""read.timeout_ms":{"value":100,"negotiable":false},"#,
        r#""read.deadline_ms":{"value":250,"negotiable":false},"#,
        r#""write.timeout_ms":{"value":100,"negotiable":false},"#,
        r#""write.deadline_ms":{"value":250,"negotiable":false},"#,
        r#""write.response_bytes":{"value":null},"#,
        r#""connection.accepts_per_poll":{"value":16,"negotiable":false},"#,
        r#""connection.requests":{"value":1,"negotiable":false},"#,
        r#""trace.point_ids":{"value":65535,"negotiable":false},"#,
        r#""trace.points_per_client":{"value":16,"negotiable":false},"#,
        r#""trace.point_registrations_per_client":{"value":256,"negotiable":false},"#,
        r#""join.request_bytes":{"value":1024,"negotiable":false},"#,
        r#""join.keys":{"value":1024,"negotiable":false},"#,
        r#""join.keys_per_driver":{"value":1024,"negotiable":false},"#,
        r#""join.versions_per_key":{"value":4,"negotiable":false},"#,
        r#""join.attributes_per_entry":{"value":16,"negotiable":false},"#,
        r#""join.name_bytes":{"value":32,"negotiable":false},"#,
        r#""join.value_bytes":{"value":64,"negotiable":false},"#,
        r#""join.key_bytes":{"value":64,"negotiable":false},"#,
        r#""join.list_page":{"value":64,"negotiable":false},"#,
        r#""join.memory_bytes":{"value":7241728,"negotiable":false}}}"#,
        "\n"
    );
    let (answer, served) = ask(&mut server, &mut agent, "KARYOS-AGENT 1 limits\n");
    assert_eq!(served, [Served::Limits]);
    assert_eq!(answer, all);
    let (answer, served) = ask(
        &mut server,
        &mut agent,
        "KARYOS-AGENT 1 limits read.timeout_ms=50 write.response_bytes=4096\n",
    );
    assert_eq!(served, [Served::Limits]);
    assert_eq!(answer, all);
    let (answer, served) = ask(
        &mut server,
        &mut agent,
        "KARYOS-AGENT 1 limits write.timeout_ms=1000\n",
    );
    assert_eq!(served, [Served::Refused]);
    assert_eq!(
        answer,
        "{\"error\":\"above bound\",\"dimension\":\"write.timeout_ms\",\"bound\":100}\n"
    );
    let (answer, _) = ask(
        &mut server,
        &mut agent,
        "KARYOS-AGENT 1 limits page.rows=10\n",
    );
    assert_eq!(
        answer,
        "{\"error\":\"unknown dimension\",\"dimension\":\"page.rows\"}\n"
    );
    // The one negotiable dimension, downwards only, applied to the request.
    let (answer, served) = ask(
        &mut server,
        &mut agent,
        "KARYOS-AGENT 1 limits read.request_bytes=200\n",
    );
    assert_eq!(served, [Served::Limits]);
    assert_eq!(
        answer,
        all.replace(
            r#""read.request_bytes":{"value":256,"#,
            r#""read.request_bytes":{"value":200,"#
        )
    );
    let (answer, _) = ask(
        &mut server,
        &mut agent,
        "KARYOS-AGENT 1 limits read.request_bytes=257\n",
    );
    assert_eq!(
        answer,
        "{\"error\":\"above bound\",\"dimension\":\"read.request_bytes\",\"bound\":256}\n"
    );
    let (answer, _) = ask(
        &mut server,
        &mut agent,
        "KARYOS-AGENT 1 limits read.request_bytes=20\n",
    );
    assert_eq!(
        answer,
        "{\"error\":\"above bound\",\"dimension\":\"read.request_bytes\",\"bound\":20}\n"
    );
    // `limits` without proposals is never `bad request` from an agent that
    // serves it, so that answer alone means "limits not supported".
    let (answer, _) = ask(&mut server, &mut agent, "KARYOS-AGENT 1 limits\n");
    assert!(answer.starts_with("{\"limits\":"), "{answer}");
    // A client that never negotiates is served as before.
    let (_, served) = ask(&mut server, &mut agent, "KARYOS-AGENT 1 view\n");
    assert_eq!(served, [Served::View]);
}

#[test]
fn the_socket_is_private_never_taken_over_and_cleaned_up() {
    use std::os::unix::fs::PermissionsExt;
    let _serial = serial();
    let dir = dir("bind");
    let config = || ApiConfig::new(dir.clone(), vec![(own(), Role::Viewer)]);
    // A directory others may read is refused.
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        Server::bind(config()),
        Err(ServeError::NotPrivate(_))
    ));
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let server = Server::bind(config()).unwrap();
    let mode = std::fs::metadata(server.path())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    // A live agent's socket is never taken over.
    assert!(matches!(Server::bind(config()), Err(ServeError::Live(_))));
    // Dropping the server removes its socket.
    let path = server.path().to_path_buf();
    drop(server);
    assert!(!path.exists());
    // A stale socket (nothing listening) is replaced.
    let stale = std::os::unix::net::UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    drop(stale);
    let _server = Server::bind(config()).unwrap();
}

/// karyos#708: an API directory left by a run without a relay group is
/// brought to the group's modes when the next run has one, and back when
/// it has none; a mode neither run uses is still refused.
#[test]
fn an_existing_directory_follows_the_relay_group_setting() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let _serial = serial();
    let dir = dir("regroup");
    let plain = || ApiConfig::new(dir.clone(), vec![(own(), Role::Viewer)]);
    // A group this process is in: the one its new directories get.
    let server = Server::bind(plain()).unwrap();
    let gid = std::fs::metadata(&dir).unwrap().gid();
    drop(server);
    let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&dir), 0o700);
    let server = Server::bind(plain().with_relay_group(gid)).unwrap();
    assert_eq!((mode(&dir), mode(server.path())), (0o710, 0o660));
    assert_eq!(std::fs::metadata(server.path()).unwrap().gid(), gid);
    drop(server);
    let server = Server::bind(plain()).unwrap();
    assert_eq!((mode(&dir), mode(server.path())), (0o700, 0o600));
    // A second agent that starts with the other setting while this one
    // serves fails, and changes nothing of the live agent's.
    assert!(matches!(
        Server::bind(plain().with_relay_group(gid)),
        Err(ServeError::Live(_))
    ));
    assert_eq!((mode(&dir), mode(server.path())), (0o700, 0o600));
    drop(server);
    let server = Server::bind(plain().with_relay_group(gid)).unwrap();
    assert!(matches!(Server::bind(plain()), Err(ServeError::Live(_))));
    assert_eq!((mode(&dir), mode(server.path())), (0o710, 0o660));
    drop(server);
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750)).unwrap();
    assert!(matches!(
        Server::bind(plain().with_relay_group(gid)),
        Err(ServeError::NotPrivate(_))
    ));
}

/// The binary: a bad command line exits 2; a good one serves the view of a
/// running driver until it is killed.
#[test]
fn the_binary_serves_the_view() {
    let _serial = serial();
    let binary = env!("CARGO_BIN_EXE_karyos-agent");
    let status = std::process::Command::new(binary)
        .arg("--api-dir")
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(2));

    let dir = dir("binary");
    std::fs::create_dir_all(&dir).unwrap();
    let mut driver = driver(&dir.join("driver"));
    let mut child = std::process::Command::new(binary)
        .args(["--api-dir", dir.join("api").to_str().unwrap()])
        .args(["--driver", dir.join("driver").to_str().unwrap()])
        .args(["--role", &format!("{}=viewer", own())])
        .args(["--refresh-ms", "20"])
        .spawn()
        .unwrap();
    let socket = dir.join("api").join("agent.sock");
    let start = Instant::now();
    let answer = loop {
        assert!(start.elapsed() < Duration::from_secs(30), "never attached");
        let _ = driver.do_work().unwrap();
        let answer = UnixStream::connect(&socket).ok().and_then(|mut stream| {
            stream.write_all(b"KARYOS-AGENT 1 view\n").ok()?;
            let mut answer = String::new();
            let _ = stream.read_to_string(&mut answer).ok()?;
            Some(answer)
        });
        if let Some(answer) = answer.filter(|answer| answer.contains(r#""state":"attached""#)) {
            break answer;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    child.kill().unwrap();
    let _ = child.wait().unwrap();
    assert!(
        answer.starts_with(r#"{"version":1,"drivers":[{"dir":"#),
        "{answer}"
    );
}

/// IMPLEMENT's F3 on #477: one poll serves at most `MAX_ACCEPTS`
/// connections; the rest wait for the next poll, and every one is answered.
#[test]
fn a_poll_serves_at_most_max_accepts() {
    use karyos_agent::server::MAX_ACCEPTS;
    let _serial = serial();
    let (_driver, mut agent, dir) = attached("accepts");
    let mut server =
        Server::bind(ApiConfig::new(dir.join("api"), vec![(own(), Role::Viewer)])).unwrap();
    let extra = 4;
    let mut clients: Vec<UnixStream> = (0..MAX_ACCEPTS + extra)
        .map(|_| {
            let mut stream = UnixStream::connect(server.path()).unwrap();
            stream.write_all(b"KARYOS-AGENT 1 view\n").unwrap();
            stream
        })
        .collect();
    assert_eq!(server.poll(&mut agent).unwrap().len(), MAX_ACCEPTS);
    assert_eq!(server.poll(&mut agent).unwrap().len(), extra);
    for client in &mut clients {
        let mut answer = String::new();
        let _ = client.read_to_string(&mut answer).unwrap();
        assert!(answer.starts_with(r#"{"version":1,"#), "{answer}");
    }
}

/// R-CORE-23: `trace-buckets` over the socket: the window's run as the
/// epoch and the buckets read; a cursor of another run gets the typed
/// refusal, served as a refusal; bad arguments their own error.
#[test]
fn trace_buckets_are_served_over_the_socket() {
    let _serial = serial();
    let (_driver, mut agent, dir) = attached("buckets");
    let mut server =
        Server::bind(ApiConfig::new(dir.join("api"), vec![(own(), Role::Viewer)])).unwrap();
    let driver_dir = dir.join("driver");
    // Number 0 is before this run's first slice: expired, with the oldest.
    let (answer, served) = ask(
        &mut server,
        &mut agent,
        &format!("KARYOS-AGENT 1 trace-buckets {} 0\n", driver_dir.display()),
    );
    assert_eq!(served, [Served::Refused]);
    let prefix = r#"{"error":"buckets expired","oldest":"#;
    assert!(answer.starts_with(prefix), "{answer}");
    let oldest: u64 = answer[prefix.len()..]
        .trim_end_matches("}\n")
        .parse()
        .unwrap();
    let (answer, served) = ask(
        &mut server,
        &mut agent,
        &format!(
            "KARYOS-AGENT 1 trace-buckets {} {oldest}\n",
            driver_dir.display()
        ),
    );
    assert_eq!(served, [Served::TraceBuckets]);
    assert!(answer.starts_with(r#"{"epoch":"#), "{answer}");
    assert!(answer.contains(r#","buckets":["#), "{answer}");
    let epoch: u64 = answer[r#"{"epoch":"#.len()..]
        .split(',')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let (answer, served) = ask(
        &mut server,
        &mut agent,
        &format!(
            "KARYOS-AGENT 1 trace-buckets {} {oldest} 6 {}\n",
            driver_dir.display(),
            epoch ^ 1
        ),
    );
    assert_eq!(served, [Served::Refused]);
    assert!(
        answer.starts_with(&format!(r#"{{"error":"epoch changed","epoch":{epoch},"#)),
        "{answer}"
    );
    let (answer, served) = ask(
        &mut server,
        &mut agent,
        &format!(
            "KARYOS-AGENT 1 trace-buckets {} 0 0\n",
            driver_dir.display()
        ),
    );
    assert_eq!(served, [Served::Refused]);
    assert_eq!(
        answer,
        "{\"error\":\"bad arguments\",\"request\":\"trace-buckets\"}\n"
    );
}

/// R-CORE-13: `trace-export` over the socket: a page of the attached
/// driver's mirror, with its instance as the epoch; a cursor of another
/// instance gets the typed refusal; an unknown directory, the guard
/// operations' answer.
#[test]
fn trace_export_is_served_over_the_socket() {
    let _serial = serial();
    let (driver, mut agent, dir) = attached("export");
    let mut server =
        Server::bind(ApiConfig::new(dir.join("api"), vec![(own(), Role::Viewer)])).unwrap();
    let epoch = format!("{:032x}", driver.instance().unwrap());
    let (answer, served) = ask(
        &mut server,
        &mut agent,
        &format!(
            "KARYOS-AGENT 1 trace-export {} 0 16 {epoch}\n",
            dir.join("driver").display()
        ),
    );
    assert_eq!(served, [Served::TraceExport]);
    assert!(
        answer.starts_with(&format!(
            r#"{{"epoch":"{epoch}","from":0,"lost":[],"records":["#
        )),
        "{answer}"
    );
    let other = format!("{:032x}", driver.instance().unwrap() ^ 1);
    let (answer, served) = ask(
        &mut server,
        &mut agent,
        &format!(
            "KARYOS-AGENT 1 trace-export {} 0 16 {other}\n",
            dir.join("driver").display()
        ),
    );
    assert_eq!(served, [Served::Refused]);
    assert_eq!(
        answer,
        format!("{{\"error\":\"epoch changed\",\"epoch\":\"{epoch}\"}}\n")
    );
    let (_, served) = ask(
        &mut server,
        &mut agent,
        "KARYOS-AGENT 1 trace-export /nowhere 0\n",
    );
    assert_eq!(served, [Served::Refused]);
}

/// QS-COORDINATOR, ACS 33663 (F2): a client that sends half a request
/// and stops is dropped, unanswered and counted, and the poll comes back
/// within the read deadline.
#[test]
fn a_half_request_is_dropped_within_the_read_deadline() {
    use karyos_agent::server::{IO_TIMEOUT, READ_DEADLINE};

    let _serial = serial();
    let (_driver, mut agent, dir) = attached("half");
    let mut server =
        Server::bind(ApiConfig::new(dir.join("api"), vec![(own(), Role::Viewer)])).unwrap();
    let mut client = UnixStream::connect(server.path()).unwrap();
    client.write_all(b"KARYOS-AGENT 1 vi").unwrap();
    let start = Instant::now();
    let mut served = Vec::new();
    while served.is_empty() {
        served = server.poll(&mut agent).unwrap();
        assert!(start.elapsed() < Duration::from_secs(5), "never served");
    }
    assert!(
        start.elapsed() < READ_DEADLINE + IO_TIMEOUT * 2,
        "{:?}",
        start.elapsed()
    );
    assert_eq!(served, [Served::Dropped]);
    let mut answer = Vec::new();
    client.read_to_end(&mut answer).unwrap();
    assert!(answer.is_empty());
}

/// karyos#708: a relay under a uid of its own, as `--relay UID=ID`
/// allows, reaches the socket through the relay group and only through
/// it: without the group the kernel refuses it before the agent sees it;
/// with it, it is served; a uid outside the group still cannot connect.
/// The agent runs as root and the relay as other uids, so it runs where
/// the tests are root (the Docker runs) and passes trivially elsewhere.
#[test]
fn a_relay_under_its_own_uid_reaches_the_socket_through_its_group() {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;

    use karyos_agent::server::Principal;

    const RELAY: u32 = 64_000;
    const GROUP: u32 = 64_000;
    const OTHER: u32 = 64_001;
    if own() != 0 {
        return;
    }
    let _serial = serial();
    let (_driver, mut agent, dir) = attached("relay-uid");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    for (group, uid, gid, served) in [
        (None, RELAY, GROUP, false),
        (Some(GROUP), RELAY, GROUP, true),
        (Some(GROUP), OTHER, OTHER, false),
    ] {
        let api = dir.join("api");
        let _ = std::fs::remove_dir_all(&api);
        let mut config = ApiConfig::new(api, vec![(own(), Role::Viewer)]).with_relays(
            vec![(RELAY, 7), (OTHER, 8)],
            vec![Principal::new("svc.ops", 50_001, Role::Viewer).unwrap()],
        );
        if let Some(gid) = group {
            config = config.with_relay_group(gid);
        }
        let mut server = Server::bind(config).unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "relay_child", "--ignored", "--nocapture"])
            .args(["--test-threads", "1"])
            .env("KARYOS_RELAY_CHILD_SOCKET", server.path())
            .uid(uid)
            .gid(gid)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        // Its output (a whole view) can fill a pipe: read it meanwhile.
        let mut stdout = child.stdout.take().unwrap();
        let reader = std::thread::spawn(move || {
            let mut out = String::new();
            let _ = stdout.read_to_string(&mut out).unwrap();
            out
        });
        let start = Instant::now();
        while child.try_wait().unwrap().is_none() {
            if start.elapsed() > Duration::from_secs(30) {
                let _ = child.kill();
                panic!("relay stuck: {group:?} {uid}");
            }
            let _ = server.poll(&mut agent).unwrap();
            std::thread::sleep(Duration::from_millis(1));
        }
        let out = reader.join().unwrap();
        if served {
            assert!(out.contains(r#"ANSWER {"version":1,"drivers""#), "{out}");
        } else {
            assert!(
                out.contains("ERR PermissionDenied"),
                "{group:?} {uid}: {out}"
            );
        }
    }
}

/// The relay of the test above, run as another uid; does nothing when run
/// on its own.
#[test]
#[ignore = "run by a_relay_under_its_own_uid_reaches_the_socket_through_its_group"]
fn relay_child() {
    let Ok(path) = std::env::var("KARYOS_RELAY_CHILD_SOCKET") else {
        return;
    };
    match UnixStream::connect(path) {
        Ok(mut stream) => {
            stream
                .write_all(b"KARYOS-AGENT 1 relay svc.ops view\n")
                .unwrap();
            let mut answer = String::new();
            let _ = stream.read_to_string(&mut answer).unwrap();
            let _ = write!(std::io::stdout(), "ANSWER {answer}");
        }
        Err(error) => {
            let _ = write!(std::io::stdout(), "ERR {:?}", error.kind());
        }
    }
}

/// karyos#868: `limits` answers the attached driver's configured trace
/// point bounds, which it publishes as gauges, not the driver's defaults.
#[test]
fn limits_report_the_drivers_configured_trace_bounds() {
    let _serial = serial();
    let config = DriverConfig {
        max_trace_points_per_client: 3,
        max_trace_point_registrations_per_client: 40,
        ..DriverConfig::default()
    };
    let (_driver, mut agent, dir) = attached_with("trace-bounds", config);
    let mut server =
        Server::bind(ApiConfig::new(dir.join("api"), vec![(own(), Role::Viewer)])).unwrap();
    let (answer, served) = ask(&mut server, &mut agent, "KARYOS-AGENT 1 limits\n");
    assert_eq!(served, vec![Served::Limits]);
    assert!(
        answer.contains(r#""trace.points_per_client":{"value":3,"negotiable":false}"#),
        "{answer}"
    );
    assert!(
        answer
            .contains(r#""trace.point_registrations_per_client":{"value":40,"negotiable":false}"#),
        "{answer}"
    );
    drop(server);
    let _ = std::fs::remove_dir_all(&dir);
}

/// karyos#738 review: a submit's token may be `-` (a retry needs none):
/// the request reaches the agent, and a fresh id without a token is
/// `token unknown`, not `bad arguments`; a malformed token still is.
#[test]
fn a_submit_without_a_token_reaches_the_agent() {
    let _serial = serial();
    let (_driver, mut agent, dir) = attached("tokenless");
    let mut server = Server::bind(ApiConfig::new(
        dir.join("api"),
        vec![(own(), Role::Operator)],
    ))
    .unwrap();
    let driver = dir.join("driver");
    let (answer, served) = ask(
        &mut server,
        &mut agent,
        &format!(
            "KARYOS-AGENT 1 submit 5 - guard-close {} 1\n",
            driver.display()
        ),
    );
    assert_eq!(served, [Served::Refused]);
    assert_eq!(answer, "{\"error\":\"token unknown\"}\n");
    let (answer, _) = ask(
        &mut server,
        &mut agent,
        &format!(
            "KARYOS-AGENT 1 submit 5 nothex guard-close {} 1\n",
            driver.display()
        ),
    );
    assert_eq!(
        answer,
        "{\"error\":\"bad arguments\",\"request\":\"submit\"}\n"
    );
}

/// Relay id 0 is the local socket's: a library configuration that names it
/// is refused at bind, as the CLI refuses it, so a relayed request is never
/// served the local answer (karyos#726).
#[test]
fn a_relay_id_of_zero_is_refused_at_bind() {
    let _serial = serial();
    let dir = dir("zero-relay");
    let api = dir.join("api");
    let zero = ApiConfig::new(api.clone(), vec![(own(), Role::Viewer)])
        .with_relays(vec![(own(), 0)], Vec::new());
    assert!(matches!(Server::bind(zero), Err(ServeError::ZeroRelay)));
    assert!(!api.exists(), "nothing is created");
    let one = ApiConfig::new(api, vec![(own(), Role::Viewer)])
        .with_relays(vec![(own(), 1)], Vec::new());
    Server::bind(one).unwrap();
}
