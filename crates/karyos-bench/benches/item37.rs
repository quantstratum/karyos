// SPDX-License-Identifier: Apache-2.0

//! The three item 37 values the session table bench (`dedup.rs`) does not
//! exercise (karyos#932, part of karyos#685): one-shot measurements,
//! printed, of
//!
//! - **the 60 s TTL**: how many sessions crashed clients keep, and whether a
//!   registration finds a slot, under client churn at W1's and W2's 32
//!   live clients, in a table of each profile; and what a registration
//!   that has to find a free slot costs in a full table;
//! - **the 1 Mi-entry and 256 MiB snapshot triggers**: which fires first at
//!   W1's and W2's payloads, and a snapshot's write time and size there,
//!   with the sessions section of a full table of each profile;
//! - **the 1 GiB catch-up allowance**: the time to stream that many log
//!   bytes back from the log, as a leader reads them for a follower that
//!   lags by the whole allowance.
//!
//! Each case aborts on an error. The logs and snapshots are written under
//! `KARYOS_ITEM37_DIR` (default the system temporary directory), on the
//! machine's real file system, and removed after.
//!
//! These measure the mechanisms at item 37's values on one machine; they
//! are inputs to a keep-or-change recommendation, not timings inside a
//! cluster run.

use std::fmt::Debug;
use std::hint::black_box;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use karyos_archive::disk::StdDisk;
use karyos_archive::segment::Geometry;
use karyos_cluster::dedup::{DedupConfig, Outcome, Request, SessionTable};
use karyos_cluster::log::{Entry, RaftLog};
use karyos_cluster::snapshot::{
    DEFAULT_ALLOWANCE, DEFAULT_EVERY_BYTES, DEFAULT_EVERY_ENTRIES, Section, SectionKind,
    SnapshotConfig, SnapshotStore,
};

/// A second of log time, in nanoseconds.
const SECOND: u64 = 1_000_000_000;
/// W1's and W2's live clients.
const LIVE: u64 = 32;
/// W2's payload and W1's largest.
const PAYLOADS: [usize; 2] = [256, 8 * 1024];

/// `result`'s value, or a printed error and an abort.
fn ok<T, E: Debug>(result: Result<T, E>, what: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => {
            let _ = writeln!(std::io::stderr(), "item37: {what}: {error:?}");
            std::process::abort();
        }
    }
}

fn say(line: &str) {
    let _ = writeln!(std::io::stdout(), "{line}");
}

fn profiles() -> [(&'static str, DedupConfig); 2] {
    [
        ("default", DedupConfig::default()),
        ("large", DedupConfig::large()),
    ]
}

/// A fresh directory for one case, removed by [`Scratch`]'s drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let base =
            std::env::var_os("KARYOS_ITEM37_DIR").map_or_else(std::env::temp_dir, PathBuf::from);
        let dir = base.join(format!("karyos-item37-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        ok(std::fs::create_dir_all(&dir), "a scratch directory");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// TTL: under churn, `rate` clients a second register and then crash
/// without closing, while `LIVE` clients send a request a second each;
/// `seconds` of log time. Returns the registrations refused for no free
/// slot and the most sessions held at once.
fn churn(config: DedupConfig, rate: u64, seconds: u64) -> (u64, usize) {
    let mut table = ok(SessionTable::new(config), "a session table");
    let mut index = 0u64;
    let mut next = || {
        index = index.saturating_add(1);
        index
    };
    for client in 1..=LIVE {
        let _ = ok(table.register(client, next(), 0), "a live client");
    }
    let mut refused = 0u64;
    let mut most = 0usize;
    let mut sequence = 0u64;
    let mut crashed = LIVE;
    for second in 1..=seconds {
        let now = second.saturating_mul(SECOND);
        for client in 1..=LIVE {
            let outcome = table.request(
                Request::new(client, client, sequence, sequence),
                now,
                |_| Some(0),
            );
            if !matches!(outcome, Outcome::Applied(_)) {
                std::process::abort();
            }
        }
        sequence = sequence.saturating_add(1);
        for _ in 0..rate {
            crashed = crashed.saturating_add(1);
            if table.register(crashed, next(), now).is_err() {
                refused = refused.saturating_add(1);
            }
        }
        most = most.max(table.live_sessions());
    }
    (refused, most)
}

fn ttl() {
    say("## TTL (60 s) under churn: 32 live clients, `rate` crashed clients a second, 600 s");
    for (name, config) in profiles() {
        for rate in [0, 1, 2, 16] {
            for ttl in [config.ttl, config.ttl / 2] {
                let (refused, most) = churn(config.with_ttl(ttl), rate, 600);
                say(&format!(
                    "ttl {name} sessions {} ttl {} s rate {rate}/s: most held {most}, registrations refused {refused}",
                    config.sessions,
                    ttl / SECOND,
                ));
            }
        }
    }
    // What a registration costs when it has to find the free slot at the
    // end of a full table.
    for (name, config) in profiles() {
        let mut table = ok(SessionTable::new(config), "a session table");
        let sessions = u64::from(config.sessions);
        for client in 1..sessions {
            let _ = ok(table.register(client, client, 0), "a registration");
        }
        let started = Instant::now();
        let registered = table.register(sessions, sessions, 0);
        let took = started.elapsed();
        let _ = ok(registered, "the last slot");
        drop(black_box(table));
        say(&format!(
            "ttl {name}: a registration into the last free slot of {sessions}: {took:?}"
        ));
    }
}

/// The log bytes of `entries` entries of `payload` bytes.
fn log_bytes(entries: u64, payload: usize) -> u64 {
    let entry = Entry {
        index: 1,
        term: 1,
        event_time: 1,
        payload: vec![0u8; payload],
    };
    let frame = ok(entry.encoded_len().ok_or("too large"), "a frame length");
    frame.saturating_mul(entries)
}

fn snapshot() {
    say("## Snapshot triggers: every 1 Mi entries or 256 MiB of log");
    for payload in PAYLOADS {
        let bytes = log_bytes(DEFAULT_EVERY_ENTRIES, payload);
        let frame = log_bytes(1, payload);
        let entries_at_bytes = DEFAULT_EVERY_BYTES / frame.max(1);
        let first = if bytes >= DEFAULT_EVERY_BYTES {
            format!("256 MiB first, at {entries_at_bytes} entries")
        } else {
            "1 Mi entries first".to_owned()
        };
        say(&format!(
            "trigger payload {payload} B: frame {frame} B, 1 Mi entries are {} MiB: {first}",
            bytes >> 20
        ));
    }
    let geometry = ok(Geometry::new(64 * 1024, 1024 * 1024), "a geometry");
    for (name, config) in profiles() {
        let mut table = ok(SessionTable::new(config), "a session table");
        let length = usize::try_from(config.response_bytes).unwrap_or(usize::MAX);
        for client in 1..=u64::from(config.sessions) {
            let _ = ok(table.register(client, client, 0), "a registration");
            for sequence in 0..u64::from(config.window) {
                let _ = table.request(Request::new(client, client, sequence, 0), 0, |reply| {
                    reply.get_mut(..length)?.fill(0x5a);
                    Some(length)
                });
            }
        }
        let started = Instant::now();
        let sessions = table.encode();
        let encoded = started.elapsed();
        let consensus = [0u8; 64];
        let scratch = Scratch::new(&format!("snapshot-{name}"));
        let mut store = ok(
            SnapshotStore::open(StdDisk, scratch.path(), geometry, SnapshotConfig::default()),
            "a snapshot store",
        )
        .store;
        let started = Instant::now();
        let info = ok(
            store.write(
                DEFAULT_EVERY_ENTRIES,
                1,
                &[
                    Section::new(SectionKind::Consensus, 1, &consensus),
                    Section::new(SectionKind::Sessions, 1, &sessions),
                ],
            ),
            "a snapshot",
        );
        let written = started.elapsed();
        say(&format!(
            "snapshot {name}: sessions section {} MiB encoded in {encoded:?}; snapshot of {} MiB written and synced in {written:?}",
            sessions.len() >> 20,
            info.length >> 20
        ));
    }
}

fn catch_up() {
    say("## Catch-up allowance: 1 GiB of log read back as a leader reads it");
    let geometry = ok(Geometry::new(64 * 1024, 1024 * 1024), "a geometry");
    for payload in PAYLOADS {
        let scratch = Scratch::new(&format!("log-{payload}"));
        let mut log = ok(
            RaftLog::create(StdDisk, scratch.path(), geometry, 1),
            "a log",
        );
        let frame = log_bytes(1, payload);
        let entries = DEFAULT_ALLOWANCE / frame.max(1);
        let batch = 256u64;
        let started = Instant::now();
        let mut index = 1u64;
        while index <= entries {
            let last = index.saturating_add(batch - 1).min(entries);
            let block: Vec<Entry> = (index..=last)
                .map(|at| Entry {
                    index: at,
                    term: 1,
                    event_time: at,
                    payload: vec![0x5a; payload],
                })
                .collect();
            let _ = ok(log.append(&block), "an append");
            index = last.saturating_add(1);
        }
        let _ = ok(log.sync(), "a sync");
        let wrote = started.elapsed();
        // A leader reads a lagging follower's entries in appends of at
        // most 1 MiB.
        let started = Instant::now();
        let mut read = 0u64;
        let mut at = 1u64;
        while at <= entries {
            let got = ok(
                log.entries(at..entries.saturating_add(1), 1 << 20),
                "a read",
            );
            let Some(last) = got.last() else {
                std::process::abort();
            };
            read = read.saturating_add(
                got.iter()
                    .map(|entry| u64::try_from(entry.payload.len()).unwrap_or(u64::MAX))
                    .fold(0u64, u64::saturating_add),
            );
            at = last.index.saturating_add(1);
            drop(black_box(got));
        }
        let took = started.elapsed();
        let rate = gib_per_second(DEFAULT_ALLOWANCE, took);
        say(&format!(
            "catch-up payload {payload} B: {entries} entries in 1 GiB, written and synced in {wrote:?}; read back in {took:?} ({rate:.2} GiB/s, {} MiB of payload)",
            read >> 20
        ));
    }
}

fn gib_per_second(bytes: u64, took: Duration) -> f64 {
    #[allow(clippy::cast_precision_loss, reason = "a printed rate")]
    let gib = bytes as f64 / f64::from(1u32 << 30);
    gib / took.as_secs_f64().max(f64::MIN_POSITIVE)
}

fn main() {
    // `cargo bench` passes `--bench`; a filter names one part.
    let filter = std::env::args().skip(1).find(|arg| !arg.starts_with('-'));
    let run = |part: &str| filter.as_deref().is_none_or(|filter| part.contains(filter));
    if run("ttl") {
        ttl();
    }
    if run("snapshot") {
        snapshot();
    }
    if run("catch-up") {
        catch_up();
    }
}
