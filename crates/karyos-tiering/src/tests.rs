// SPDX-License-Identifier: Apache-2.0

//! Tests of the S3 client against a TLS 1.3 stand-in on this host
//! (karyos#965). The stand-in uses `karyos-control`'s test certificates
//! (`localhost`, signed by its test CA).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests, as ADR-0007 allows"
)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use super::*;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../karyos-control/tests/fixtures")
        .join(name)
}

fn certificates(name: &str) -> Vec<CertificateDer<'static>> {
    CertificateDer::pem_file_iter(fixture(name))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

/// What the stand-in saw.
#[derive(Default)]
struct Seen {
    objects: HashMap<String, Vec<u8>>,
    lock_headers: Vec<String>,
}

/// An S3 stand-in: PUT stores, GET answers, over TLS 1.3. Returns its
/// port.
fn stand_in(seen: Arc<Mutex<Seen>>) -> u16 {
    let config =
        rustls::ServerConfig::builder_with_provider(Arc::new(rustls_graviola::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                certificates("server.pem"),
                PrivateKeyDer::from_pem_file(fixture("server.key")).unwrap(),
            )
            .unwrap();
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut tcp) = stream else { return };
            let mut tls = rustls::ServerConnection::new(Arc::clone(&config)).unwrap();
            let mut stream = rustls::Stream::new(&mut tls, &mut tcp);
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                if stream.read(&mut byte).unwrap_or(0) == 0 {
                    break;
                }
                request.push(byte[0]);
            }
            let head = String::from_utf8_lossy(&request).to_string();
            let mut lines = head.lines();
            let first = lines.next().unwrap_or_default().to_owned();
            let mut length = 0usize;
            let mut seen = seen.lock().unwrap();
            for line in lines {
                let lower = line.to_ascii_lowercase();
                if let Some(value) = lower.strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap_or(0);
                }
                if lower.starts_with("x-amz-object-lock") {
                    seen.lock_headers.push(lower);
                }
            }
            let mut body = vec![0u8; length];
            stream.read_exact(&mut body).unwrap();
            let mut parts = first.split(' ');
            let method = parts.next().unwrap_or_default();
            let path = parts.next().unwrap_or_default();
            let path = path.split('?').next().unwrap_or_default().to_owned();
            let (status, answer) = match method {
                "PUT" => {
                    seen.objects.insert(path, body);
                    ("200 OK", Vec::new())
                }
                "GET" => match seen.objects.get(&path) {
                    Some(object) => ("200 OK", object.clone()),
                    None => ("404 Not Found", Vec::new()),
                },
                _ => ("400 Bad Request", Vec::new()),
            };
            drop(seen);
            let reply = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                answer.len()
            );
            let _ = stream.write_all(reply.as_bytes());
            let _ = stream.write_all(&answer);
            let _ = stream.flush();
            tls.send_close_notify();
            let _ = tls.complete_io(&mut tcp);
        }
    });
    port
}

fn config(port: u16, object_lock: bool) -> S3Config {
    S3Config {
        endpoint: format!("https://localhost:{port}"),
        path_style: true,
        bucket: "archive".to_owned(),
        region: "test-1".to_owned(),
        access_key: "AKIDEXAMPLE".to_owned(),
        secret_key: "secret".to_owned(),
        roots: certificates("ca.pem"),
        object_lock,
        timeout: Duration::from_secs(10),
        max_object: 1 << 20,
    }
}

fn key(recording: u64) -> ObjectKey {
    ObjectKey {
        archive: [10; 32],
        recording,
        start: 0,
        end: 16,
    }
}

#[test]
fn an_object_is_put_under_object_lock_and_read_back() {
    let seen = Arc::new(Mutex::new(Seen::default()));
    let port = stand_in(Arc::clone(&seen));
    let mut store = S3Store::new(config(port, true)).unwrap();
    let enforcement = store
        .put(&key(3), b"sealed range....", 1_700_000_000_000_000_000)
        .unwrap();
    assert_eq!(enforcement, Enforcement::ObjectLock);
    assert_eq!(store.get(&key(3)).unwrap(), b"sealed range....");
    let seen = seen.lock().unwrap();
    assert!(
        seen.lock_headers
            .contains(&"x-amz-object-lock-mode: compliance".to_owned())
    );
    assert!(
        seen.lock_headers
            .contains(&"x-amz-object-lock-retain-until-date: 2023-11-14t22:13:20z".to_owned())
    );
    // Path style: the bucket, then the archive-scoped key.
    assert!(
        seen.objects
            .contains_key(&format!("/archive/{}", key(3).name()))
    );
}

#[test]
fn without_object_lock_the_copy_records_no_enforcement() {
    let port = stand_in(Arc::default());
    let mut store = S3Store::new(config(port, false)).unwrap();
    assert_eq!(
        store.put(&key(4), b"x", 0).unwrap(),
        Enforcement::Unsupported
    );
}

#[test]
fn a_missing_object_is_not_found() {
    let port = stand_in(Arc::default());
    let mut store = S3Store::new(config(port, false)).unwrap();
    assert_eq!(
        store.get(&key(9)).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
}

#[test]
fn a_server_the_roots_do_not_trust_is_refused() {
    let port = stand_in(Arc::default());
    let mut untrusting = config(port, false);
    untrusting.roots = certificates("rogue.pem");
    let mut store = S3Store::new(untrusting).unwrap();
    assert!(store.put(&key(5), b"x", 0).is_err());
}

#[test]
fn only_https_endpoints_are_accepted() {
    let mut plain = config(1, false);
    plain.endpoint = "http://localhost:1".to_owned();
    assert!(matches!(S3Store::new(plain), Err(S3Error::Endpoint(_))));
}

#[test]
fn retention_dates_are_rfc3339_rounded_up() {
    assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
    assert_eq!(rfc3339(1_700_000_000_000_000_000), "2023-11-14T22:13:20Z");
    assert_eq!(rfc3339(1), "1970-01-01T00:00:01Z");
    assert_eq!(rfc3339(951_782_400_000_000_000), "2000-02-29T00:00:00Z");
}
