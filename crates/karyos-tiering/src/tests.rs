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
    /// PUTs refused for a missing or wrong `x-amz-checksum-sha256`.
    bad_checksums: usize,
    /// The body of a 404, as S3's error document.
    not_found_body: Vec<u8>,
    /// Each object's version and the lock headers its PUT carried.
    versions: HashMap<String, (String, Vec<(String, String)>)>,
    /// PUTs answered, numbering the versions.
    puts: u64,
    /// The lock mode answered instead of the one put, if set.
    answer_mode: Option<String>,
    /// HEADs answered, with their version.
    heads: Vec<String>,
}

/// An S3 stand-in: PUT stores (only with the right SHA-256 checksum, as
/// S3 checks it and requires one under object lock), GET answers, over
/// TLS 1.3. Returns its port.
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
            let mut checksum = None;
            let mut locks: Vec<(String, String)> = Vec::new();
            let mut seen = seen.lock().unwrap();
            for line in lines {
                let lower = line.to_ascii_lowercase();
                if let Some(value) = lower.strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap_or(0);
                }
                if lower.starts_with("x-amz-checksum-sha256:") {
                    checksum = line
                        .split_once(':')
                        .map(|(_, value)| value.trim().to_owned());
                }
                if lower.starts_with("x-amz-object-lock") {
                    seen.lock_headers.push(lower.clone());
                    if let Some((name, value)) = line.split_once(':') {
                        locks.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
                    }
                }
            }
            let mut body = vec![0u8; length];
            stream.read_exact(&mut body).unwrap();
            let mut parts = first.split(' ');
            let method = parts.next().unwrap_or_default();
            let full = parts.next().unwrap_or_default();
            let path = full.split('?').next().unwrap_or_default().to_owned();
            let query = full
                .split_once('?')
                .map_or("", |(_, query)| query)
                .to_owned();
            let mut extra = String::new();
            let (status, answer) = match method {
                "PUT" if checksum.as_deref() != Some(checksum_sha256(&body).as_str()) => {
                    seen.bad_checksums += 1;
                    ("400 Bad Request", Vec::new())
                }
                "PUT" => {
                    seen.puts += 1;
                    let version = format!("v{}", seen.puts);
                    extra = format!("x-amz-version-id: {version}\r\n");
                    seen.versions.insert(path.clone(), (version, locks));
                    seen.objects.insert(path, body);
                    ("200 OK", Vec::new())
                }
                "HEAD" => {
                    let asked = query
                        .split('&')
                        .find_map(|pair| pair.strip_prefix("versionId="))
                        .unwrap_or_default()
                        .to_owned();
                    match seen.versions.get(&path).cloned() {
                        Some((version, locks)) if version == asked => {
                            seen.heads.push(version.clone());
                            extra = format!("x-amz-version-id: {version}\r\n");
                            for (name, value) in locks {
                                let value = match (&seen.answer_mode, name.as_str()) {
                                    (Some(mode), "x-amz-object-lock-mode") => mode.clone(),
                                    _ => value,
                                };
                                extra.push_str(&format!("{name}: {value}\r\n"));
                            }
                            ("200 OK", Vec::new())
                        }
                        _ => ("404 Not Found", Vec::new()),
                    }
                }
                "GET" => match seen.objects.get(&path) {
                    Some(object) => ("200 OK", object.clone()),
                    None => ("404 Not Found", seen.not_found_body.clone()),
                },
                _ => ("400 Bad Request", Vec::new()),
            };
            drop(seen);
            let reply = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n",
                answer.len()
            );
            let _ = stream.write_all(reply.as_bytes());
            if method != "HEAD" {
                let _ = stream.write_all(&answer);
            }
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
        kind: karyos_archive::integrity::tiering::ObjectKind::Range,
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

/// karyos#965 review P1: every PUT carries the SHA-256 checksum S3
/// requires under object lock, in standard base64.
#[test]
fn a_put_carries_its_sha256_checksum() {
    assert_eq!(
        checksum_sha256(b"abc"),
        "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
    );
    assert_eq!(base64(b""), "");
    assert_eq!(base64(b"f"), "Zg==");
    assert_eq!(base64(b"fo"), "Zm8=");
    assert_eq!(base64(b"foo"), "Zm9v");
    let seen = Arc::new(Mutex::new(Seen::default()));
    let port = stand_in(Arc::clone(&seen));
    let mut store = S3Store::new(config(port, true)).unwrap();
    store.put(&key(6), b"checked bytes", 0).unwrap();
    assert_eq!(seen.lock().unwrap().bad_checksums, 0);
}

/// karyos#965 review P2: the configuration's `Debug` output never shows
/// the credentials.
#[test]
fn the_configuration_debug_redacts_credentials() {
    let shown = format!("{:?}", config(1, false));
    assert!(!shown.contains("AKIDEXAMPLE"), "{shown}");
    assert!(!shown.contains("secret\""), "{shown}");
    assert!(shown.contains("<redacted>"), "{shown}");
}

/// karyos#965 review P2: called from inside a Tokio runtime, the
/// synchronous store returns an error instead of panicking.
#[test]
fn a_call_from_a_tokio_runtime_is_an_error() {
    let port = stand_in(Arc::default());
    let mut store = S3Store::new(config(port, false)).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let result = runtime.block_on(async { store.get(&key(1)) });
    assert!(result.is_err());
}

/// karyos#965 review P3: a 404 whose error document is larger than
/// `max_object` is still `NotFound`.
#[test]
fn a_large_not_found_document_is_still_not_found() {
    let seen = Arc::new(Mutex::new(Seen {
        not_found_body: vec![b'x'; 256],
        ..Seen::default()
    }));
    let port = stand_in(seen);
    let mut small = config(port, false);
    small.max_object = 8;
    let mut store = S3Store::new(small).unwrap();
    assert_eq!(
        store.get(&key(9)).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
}

#[test]
fn the_retention_of_the_exact_version_put_is_read_back() {
    let seen = Arc::new(Mutex::new(Seen::default()));
    let port = stand_in(Arc::clone(&seen));
    let mut store = S3Store::new(config(port, true)).unwrap();
    let until = 1_900_000_000_000_000_000;
    let _ = store.put(&key(1), b"first", until).unwrap();
    let _ = store.put(&key(1), b"second", until).unwrap();
    let retention = store.retention(&key(1)).unwrap().unwrap();
    assert_eq!(retention.mode, LockMode::Compliance);
    assert!(retention.retain_until_ns >= until);
    assert!(retention.enforces(until));
    assert!(!retention.enforces(until + 2_000_000_000));
    // The HEAD named the second PUT's version, never the first.
    assert_eq!(seen.lock().unwrap().heads, vec!["v2".to_owned()]);
    // A mode the store does not know is refused.
    seen.lock().unwrap().answer_mode = Some("LEGAL".to_owned());
    assert!(store.retention(&key(1)).is_err());
    // Without object lock, nothing is read back.
    let mut plain = S3Store::new(config(port, false)).unwrap();
    let _ = plain.put(&key(2), b"plain", 0).unwrap();
    assert_eq!(plain.retention(&key(3)).unwrap(), None);
    assert_eq!(plain.retention(&key(2)).unwrap(), None);
}

#[test]
fn rfc3339_dates_parse_back_to_their_nanoseconds() {
    for ns in [
        0,
        1_000_000_000,
        1_700_000_000_000_000_000,
        4_102_444_800_000_000_000,
    ] {
        assert_eq!(parse_rfc3339(&rfc3339(ns)), Some(ns));
    }
    assert_eq!(
        parse_rfc3339("2030-01-01T00:00:00.5Z"),
        Some(1_893_456_000_500_000_000)
    );
    for bad in [
        "",
        "2030-01-01",
        "2030-13-01T00:00:00Z",
        "2030-01-01T00:00:00+01:00",
        "1969-12-31T23:59:59Z",
    ] {
        assert_eq!(parse_rfc3339(bad), None, "{bad}");
    }
}
