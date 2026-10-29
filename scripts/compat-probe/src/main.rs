// SPDX-License-Identifier: Apache-2.0

//! The compatibility gate's client (scripts/compat-test.sh, R-CORE-36): one
//! source, built against each tree's `karyos` facade, so that a build of
//! one release attaches to, publishes to or subscribes from a driver of
//! another. It prints one line, `<mode> <outcome> <detail>`, and exits 0;
//! the script compares the outcome with the matrix.
//!
//! - `attach <dir>`: `ok`, or `refused <error>`.
//! - `pub <dir> <port> <count> <seconds>`: offers `count` messages of
//!   8 bytes (the index, little endian) on `karyos:udp`, then stays
//!   `seconds` so the receiver can read them.
//! - `sub <dir> <port> <count> <seconds>`: `received <n> in_order=<bool>`
//!   within `seconds`.

#![allow(clippy::unwrap_used, clippy::panic, reason = "a test-kit tool")]

use std::time::{Duration, Instant};

use karyos::{Client, Context, MessageLimit, StreamId};

const STREAM: i32 = 7;

fn context(dir: &str) -> Context {
    Context::builder()
        .dir(dir)
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let arg = |at: usize| args.get(at).map(String::as_str).unwrap_or_default();
    let number = |at: usize| arg(at).parse::<u64>().unwrap();
    match arg(0) {
        "attach" => match Client::connect(context(arg(1))) {
            Ok(_) => println!("attach ok"),
            Err(error) => println!("attach refused {error:?}"),
        },
        "pub" => {
            let mut client = match Client::connect(context(arg(1))) {
                Ok(client) => client,
                Err(error) => return println!("pub refused {error:?}"),
            };
            let uri = format!("karyos:udp?endpoint=127.0.0.1:{}|interface=127.0.0.1", arg(2));
            let mut publication = client
                .add_exclusive_publication(&uri, StreamId::new(STREAM))
                .unwrap();
            let (count, linger) = (number(3), Duration::from_secs(number(4)));
            let began = Instant::now();
            let mut sent = 0u64;
            while sent < count && began.elapsed() < linger {
                if publication.offer(&sent.to_le_bytes()).is_ok() {
                    sent += 1;
                } else {
                    std::thread::sleep(Duration::from_millis(1));
                }
                let _ = client.poll();
            }
            while began.elapsed() < linger {
                let _ = client.poll();
                std::thread::sleep(Duration::from_millis(10));
            }
            println!("pub offered {sent}");
        }
        "sub" => {
            let mut client = match Client::connect(context(arg(1))) {
                Ok(client) => client,
                Err(error) => return println!("sub refused {error:?}"),
            };
            let uri = format!("karyos:udp?endpoint=127.0.0.1:{}", arg(2));
            let mut reading = client
                .add_subscription(&uri, StreamId::new(STREAM))
                .unwrap();
            let (count, deadline) = (number(3), Duration::from_secs(number(4)));
            let began = Instant::now();
            let mut received = Vec::new();
            while (received.len() as u64) < count && began.elapsed() < deadline {
                let _ = reading.poll(
                    |payload, _| {
                        let mut index = [0u8; 8];
                        if let Some(bytes) = payload.get(..8) {
                            index.copy_from_slice(bytes);
                        }
                        received.push(u64::from_le_bytes(index));
                    },
                    MessageLimit::new(64),
                );
                let _ = client.poll();
                std::thread::sleep(Duration::from_millis(1));
            }
            // Joining where the image attaches: in order from its first.
            let in_order = received.windows(2).all(|pair| pair[1] == pair[0] + 1);
            println!(
                "sub received {} in_order={in_order} images={}",
                received.len(),
                reading.image_count()
            );
        }
        other => panic!("unknown mode {other:?}"),
    }
}
