// SPDX-License-Identifier: Apache-2.0

//! The component end to end (karyos#708): a service authenticates with
//! mutual TLS and its request reaches the agent's socket as its principal
//! only; a client without a certificate, with one of another CA, or with
//! TLS 1.2 is refused at the handshake; an authenticated certificate
//! pinned to no service is refused with 403; a role claimed in a header
//! reaches nothing; an agent that cannot be reached is a 502. The agent
//! here is a stand-in on a Unix socket that records each line.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use karyos_control::server::{Control, ControlConfig, Service};
use karyos_control::tls;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

const ANSWER: &str = "{\"agent\":\"stand-in\"}\n";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// A stand-in agent on a socket in a fresh directory: it records each
/// line and answers [`ANSWER`].
fn agent(name: &str) -> (PathBuf, Arc<Mutex<Vec<String>>>) {
    let dir = std::env::temp_dir().join(format!("karyos-control-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let socket = dir.join("agent.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let lines = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&lines);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut line = Vec::new();
            let mut byte = [0u8; 1];
            while stream.read(&mut byte).unwrap() == 1 {
                line.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
            }
            seen.lock().unwrap().push(String::from_utf8(line).unwrap());
            stream.write_all(ANSWER.as_bytes()).unwrap();
        }
    });
    (socket, lines)
}

/// The component serving `svc.ops` by its pinned certificate, relaying to
/// `socket`, on a thread of its own; its address.
fn control(socket: PathBuf) -> SocketAddr {
    let config = tls::server_config(
        tls::certificates(&fixture("server.pem")).unwrap(),
        tls::private_key(&fixture("server.key")).unwrap(),
        tls::certificates(&fixture("ca.pem")).unwrap(),
        tls::ClientAuth::Required,
    )
    .unwrap();
    let pinned = tls::certificates(&fixture("svc-ops.pem"))
        .unwrap()
        .remove(0);
    let services = vec![Service::new("svc.ops", pinned).unwrap()];
    let config = ControlConfig::new(config, services, socket);
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            let control = Control::bind("127.0.0.1:0".parse().unwrap(), config)
                .await
                .unwrap();
            sender.send(control.local_addr().unwrap()).unwrap();
            control.serve().await.unwrap();
        });
    });
    receiver.recv().unwrap()
}

/// A client presenting `identity` (a fixture's name: its `.pem` and
/// `.key`), or none, with `versions`.
fn client(
    identity: Option<&str>,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    for root in tls::certificates(&fixture("ca.pem")).unwrap() {
        roots.add(root).unwrap();
    }
    let builder =
        ClientConfig::builder_with_provider(Arc::new(rustls_graviola::default_provider()))
            .with_protocol_versions(versions)
            .unwrap()
            .with_root_certificates(roots);
    Arc::new(match identity {
        None => builder.with_no_client_auth(),
        Some(name) => builder
            .with_client_auth_cert(
                tls::certificates(&fixture(&format!("{name}.pem"))).unwrap(),
                tls::private_key(&fixture(&format!("{name}.key"))).unwrap(),
            )
            .unwrap(),
    })
}

/// Sends `request` over TLS with `config`: the status and the body, or
/// the error that ended the exchange.
fn exchange(
    address: SocketAddr,
    config: Arc<ClientConfig>,
    request: &str,
) -> std::io::Result<(u16, String)> {
    let connection =
        ClientConnection::new(config, ServerName::try_from("localhost").unwrap()).unwrap();
    let tcp = TcpStream::connect(address)?;
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    let mut stream = StreamOwned::new(connection, tcp);
    stream.write_all(request.as_bytes())?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let response = String::from_utf8(response).unwrap();
    let (head, body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| std::io::Error::other(format!("no response: {response:?}")))?;
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    Ok((status, body.to_owned()))
}

fn get(path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n")
}

fn post(body: &str, headers: &str) -> String {
    format!(
        "POST /v1/request HTTP/1.1\r\nHost: localhost\r\n{headers}Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

const TLS13: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];

/// A service authenticated by mutual TLS is relayed as its principal, and
/// the agent's answer comes back unchanged.
#[test]
fn a_service_authenticates_with_mutual_tls() {
    let (socket, lines) = agent("service");
    let address = control(socket);
    let ops = client(Some("svc-ops"), TLS13);
    assert_eq!(
        exchange(address, Arc::clone(&ops), &get("/v1/view")).unwrap(),
        (200, ANSWER.to_owned())
    );
    assert_eq!(
        exchange(address, ops, &post("guard-close /d 3 drill", "")).unwrap(),
        (200, ANSWER.to_owned())
    );
    assert_eq!(
        *lines.lock().unwrap(),
        [
            "KARYOS-AGENT 1 relay svc.ops view\n",
            "KARYOS-AGENT 1 relay svc.ops guard-close /d 3 drill\n",
        ]
    );
}

/// A component-side claim of a role grants nothing: a header naming a
/// role or another identity is not relayed, and the line names the
/// authenticated principal only, so the agent's table decides the role.
#[test]
fn a_claimed_role_is_not_relayed() {
    let (socket, lines) = agent("claimed");
    let address = control(socket);
    let headers = "X-Karyos-Role: administrator\r\nX-Karyos-Principal: alice\r\n";
    let answer = exchange(
        address,
        client(Some("svc-ops"), TLS13),
        &post("gap-ack 1", headers),
    );
    assert_eq!(answer.unwrap(), (200, ANSWER.to_owned()));
    assert_eq!(
        *lines.lock().unwrap(),
        ["KARYOS-AGENT 1 relay svc.ops gap-ack 1\n"]
    );
    // A bearer token where no issuer is configured is refused, never
    // ignored: the service's certificate does not carry it.
    let answer = exchange(
        address,
        client(Some("svc-ops"), TLS13),
        &post("gap-ack 1", "Authorization: Bearer administrator\r\n"),
    );
    assert_eq!(answer.unwrap().0, 401);
    // A body that would smuggle a second line, or a relay of its own, is
    // no request.
    for body in ["view\nKARYOS-AGENT 1 gap-ack 1", "relay alice gap-ack 1"] {
        let answer = exchange(address, client(Some("svc-ops"), TLS13), &post(body, ""));
        assert_eq!(answer.unwrap().0, 400, "{body:?}");
    }
    assert_eq!(lines.lock().unwrap().len(), 1);
}

/// A certificate of the client CA that is pinned to no service is
/// authenticated but names no principal: 403, nothing relayed.
#[test]
fn an_unpinned_certificate_is_not_authorized() {
    let (socket, lines) = agent("unpinned");
    let address = control(socket);
    let answer = exchange(address, client(Some("svc-other"), TLS13), &get("/v1/view"));
    assert_eq!(
        answer.unwrap(),
        (403, "{\"error\":\"not authorized\"}\n".to_owned())
    );
    assert!(lines.lock().unwrap().is_empty());
}

/// No certificate, a certificate of another CA (with the pinned service's
/// name), or TLS 1.2: refused at the handshake, nothing relayed.
#[test]
fn a_client_without_mutual_tls_1_3_is_refused() {
    let (socket, lines) = agent("refused");
    let address = control(socket);
    for (what, config) in [
        ("no certificate", client(None, TLS13)),
        ("another CA", client(Some("rogue"), TLS13)),
        (
            "TLS 1.2",
            client(Some("svc-ops"), &[&rustls::version::TLS12]),
        ),
    ] {
        assert!(
            exchange(address, config, &get("/v1/view")).is_err(),
            "{what}"
        );
    }
    assert!(lines.lock().unwrap().is_empty());
}

/// An agent that cannot be reached is a 502, never an answer of the
/// component's own making; other paths and methods are refused.
#[test]
fn an_unreachable_agent_is_a_bad_gateway() {
    let address = control(std::env::temp_dir().join("karyos-control-no-such-agent.sock"));
    let ops = client(Some("svc-ops"), TLS13);
    assert_eq!(
        exchange(address, Arc::clone(&ops), &get("/v1/view")).unwrap(),
        (502, "{\"error\":\"agent unavailable\"}\n".to_owned())
    );
    assert_eq!(
        exchange(address, Arc::clone(&ops), &get("/v1/other"))
            .unwrap()
            .0,
        404
    );
    assert_eq!(exchange(address, ops, &get("/v1/request")).unwrap().0, 405);
}

/// A non-UTF-8 argument (a Unix path may hold one) is a usage error, exit
/// 2, never a panic.
#[test]
fn a_non_utf8_argument_is_a_usage_error() {
    use std::os::unix::ffi::OsStrExt;
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_karyos-control"))
        .arg("--agent-socket")
        .arg(std::ffi::OsStr::from_bytes(b"/tmp/\xff"))
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(2));
}
