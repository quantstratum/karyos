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

/// An agent attached to a running driver in `name`'s directory.
fn attached(name: &str) -> (IpcDriver, Agent, PathBuf) {
    let dir = dir(name);
    std::fs::create_dir_all(&dir).unwrap();
    let mut driver = driver(&dir.join("driver"));
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
    // No journal configured: `journal` is null (M10b).
    assert!(answer.ends_with("}],\"journal\":null}\n"), "{answer}");
    assert!(answer.contains(r#""label":"driver pid""#));
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
