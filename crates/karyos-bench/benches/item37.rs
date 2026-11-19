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
//! An error ends the run with a diagnostic and a failure status, after
//! the scratch directories are removed. The logs and snapshots are written
//! under `KARYOS_ITEM37_DIR` (default the system temporary directory), on
//! the machine's real file system, each in a directory this run creates
//! (never one that already exists), and removed after.
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

/// A failed step: what failed, for the diagnostic.
type Failed = String;

/// `result`'s value, or what failed.
fn ok<T, E: Debug>(result: Result<T, E>, what: &str) -> Result<T, Failed> {
    result.map_err(|error| format!("{what}: {error:?}"))
}

/// `value`, or an overflow of `what`.
fn fits<T>(value: Option<T>, what: &str) -> Result<T, Failed> {
    value.ok_or_else(|| format!("{what} overflowed"))
}

/// Writes one result line; a failed write fails the run.
fn say(line: &str) -> Result<(), Failed> {
    ok(writeln!(std::io::stdout(), "{line}"), "writing a result")
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
    /// Creates the case's directory itself: one that already exists is an
    /// error, never removed, so nothing this run did not create is deleted.
    fn new(name: &str) -> Result<Self, Failed> {
        let base =
            std::env::var_os("KARYOS_ITEM37_DIR").map_or_else(std::env::temp_dir, PathBuf::from);
        ok(std::fs::create_dir_all(&base), "the scratch base")?;
        let dir = base.join(format!("karyos-item37-{}-{name}", std::process::id()));
        ok(std::fs::create_dir(&dir), "a new scratch directory")?;
        Ok(Self(dir))
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
fn churn(config: DedupConfig, rate: u64, seconds: u64) -> Result<(u64, usize), Failed> {
    let mut table = ok(SessionTable::new(config), "a session table")?;
    let mut index = 0u64;
    let mut next = || -> Result<u64, Failed> {
        index = fits(index.checked_add(1), "the log index")?;
        Ok(index)
    };
    for client in 1..=LIVE {
        let _ = ok(table.register(client, next()?, 0), "a live client")?;
    }
    let mut refused = 0u64;
    let mut most = 0usize;
    let mut sequence = 0u64;
    let mut crashed = LIVE;
    for second in 1..=seconds {
        let now = fits(second.checked_mul(SECOND), "the log time")?;
        for client in 1..=LIVE {
            let outcome = table.request(
                Request::new(client, client, sequence, sequence),
                now,
                |_| Some(0),
            );
            if !matches!(outcome, Outcome::Applied(_)) {
                return Err(format!(
                    "a live client's request was not applied: {outcome:?}"
                ));
            }
        }
        sequence = fits(sequence.checked_add(1), "the request sequence")?;
        for _ in 0..rate {
            crashed = fits(crashed.checked_add(1), "the client id")?;
            if table.register(crashed, next()?, now).is_err() {
                refused = fits(refused.checked_add(1), "the refused count")?;
            }
        }
        most = most.max(table.live_sessions());
    }
    Ok((refused, most))
}

fn ttl() -> Result<(), Failed> {
    say("## TTL (60 s) under churn: 32 live clients, `rate` crashed clients a second, 600 s")?;
    for (name, config) in profiles() {
        for rate in [0, 1, 2, 16] {
            for ttl in [config.ttl, config.ttl / 2] {
                let (refused, most) = churn(config.with_ttl(ttl), rate, 600)?;
                say(&format!(
                    "ttl {name} sessions {} ttl {} s rate {rate}/s: most held {most}, registrations refused {refused}",
                    config.sessions,
                    ttl / SECOND,
                ))?;
            }
        }
    }
    // What a registration costs when it has to find the free slot at the
    // end of a full table.
    for (name, config) in profiles() {
        let mut table = ok(SessionTable::new(config), "a session table")?;
        let sessions = u64::from(config.sessions);
        for client in 1..sessions {
            let _ = ok(table.register(client, client, 0), "a registration")?;
        }
        let started = Instant::now();
        let registered = table.register(sessions, sessions, 0);
        let took = started.elapsed();
        let _ = ok(registered, "the last slot")?;
        drop(black_box(table));
        say(&format!(
            "ttl {name}: a registration into the last free slot of {sessions}: {took:?}"
        ))?;
    }
    Ok(())
}

/// The log bytes of `entries` entries of `payload` bytes.
fn log_bytes(entries: u64, payload: usize) -> Result<u64, Failed> {
    let entry = Entry {
        index: 1,
        term: 1,
        event_time: 1,
        payload: vec![0u8; payload],
    };
    let frame = ok(entry.encoded_len().ok_or("too large"), "a frame length")?;
    fits(frame.checked_mul(entries), "the log bytes")
}

fn snapshot() -> Result<(), Failed> {
    say("## Snapshot triggers: every 1 Mi entries or 256 MiB of log")?;
    for payload in PAYLOADS {
        let bytes = log_bytes(DEFAULT_EVERY_ENTRIES, payload)?;
        let frame = log_bytes(1, payload)?;
        // The first entry at which the log reaches 256 MiB: a ceiling, so
        // the byte trigger is not reported one entry early.
        let entries_at_bytes = DEFAULT_EVERY_BYTES.div_ceil(frame.max(1));
        let first = match entries_at_bytes.cmp(&DEFAULT_EVERY_ENTRIES) {
            std::cmp::Ordering::Less => format!("256 MiB first, at {entries_at_bytes} entries"),
            std::cmp::Ordering::Equal => {
                format!("both at once, at {entries_at_bytes} entries")
            }
            std::cmp::Ordering::Greater => "1 Mi entries first".to_owned(),
        };
        say(&format!(
            "trigger payload {payload} B: frame {frame} B, 1 Mi entries are {} MiB: {first}",
            bytes >> 20
        ))?;
    }
    let geometry = ok(Geometry::new(64 * 1024, 1024 * 1024), "a geometry")?;
    for (name, config) in profiles() {
        let mut table = ok(SessionTable::new(config), "a session table")?;
        let length = ok(
            usize::try_from(config.response_bytes),
            "the response length",
        )?;
        for client in 1..=u64::from(config.sessions) {
            let _ = ok(table.register(client, client, 0), "a registration")?;
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
        let scratch = Scratch::new(&format!("snapshot-{name}"))?;
        let mut store = ok(
            SnapshotStore::open(StdDisk, scratch.path(), geometry, SnapshotConfig::default()),
            "a snapshot store",
        )?
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
        )?;
        let written = started.elapsed();
        say(&format!(
            "snapshot {name}: sessions section {} MiB encoded in {encoded:?}; snapshot of {} MiB written and synced in {written:?}",
            sessions.len() >> 20,
            info.length >> 20
        ))?;
    }
    Ok(())
}

fn catch_up() -> Result<(), Failed> {
    say("## Catch-up allowance: 1 GiB of log read back as a leader reads it")?;
    let geometry = ok(Geometry::new(64 * 1024, 1024 * 1024), "a geometry")?;
    for payload in PAYLOADS {
        let scratch = Scratch::new(&format!("log-{payload}"))?;
        let mut log = ok(
            RaftLog::create(StdDisk, scratch.path(), geometry, 1),
            "a log",
        )?;
        let frame = log_bytes(1, payload)?;
        let entries = DEFAULT_ALLOWANCE / frame.max(1);
        let batch = 256u64;
        let started = Instant::now();
        let mut index = 1u64;
        while index <= entries {
            let last = fits(index.checked_add(batch - 1), "the batch end")?.min(entries);
            let block: Vec<Entry> = (index..=last)
                .map(|at| Entry {
                    index: at,
                    term: 1,
                    event_time: at,
                    payload: vec![0x5a; payload],
                })
                .collect();
            let _ = ok(log.append(&block), "an append")?;
            index = fits(last.checked_add(1), "the log index")?;
        }
        let _ = ok(log.sync(), "a sync")?;
        let wrote = started.elapsed();
        // A leader reads a lagging follower's entries in appends of at
        // most 1 MiB.
        let started = Instant::now();
        let mut read = 0u64;
        let mut at = 1u64;
        while at <= entries {
            let end = fits(entries.checked_add(1), "the read end")?;
            let got = ok(log.entries(at..end, 1 << 20), "a read")?;
            let Some(last) = got.last() else {
                return Err(format!("a read from index {at} returned no entries"));
            };
            for entry in &got {
                let length = ok(u64::try_from(entry.payload.len()), "a payload length")?;
                read = fits(read.checked_add(length), "the bytes read")?;
            }
            at = fits(last.index.checked_add(1), "the read index")?;
            drop(black_box(got));
        }
        let took = started.elapsed();
        let rate = gib_per_second(DEFAULT_ALLOWANCE, took);
        say(&format!(
            "catch-up payload {payload} B: {entries} entries in 1 GiB, written and synced in {wrote:?}; read back in {took:?} ({rate:.2} GiB/s, {} MiB of payload)",
            read >> 20
        ))?;
    }
    Ok(())
}

fn gib_per_second(bytes: u64, took: Duration) -> f64 {
    #[allow(clippy::cast_precision_loss, reason = "a printed rate")]
    let gib = bytes as f64 / f64::from(1u32 << 30);
    gib / took.as_secs_f64().max(f64::MIN_POSITIVE)
}

/// The parts the arguments select; `cargo bench` passes `--bench`, and a
/// filter names one part. A filter that is not Unicode is an error.
fn run() -> Result<(), Failed> {
    let mut filter = None;
    for arg in std::env::args_os().skip(1) {
        let arg = arg
            .into_string()
            .map_err(|arg| format!("an argument that is not Unicode: {arg:?}"))?;
        if !arg.starts_with('-') && filter.is_none() {
            filter = Some(arg);
        }
    }
    let selected = |part: &str| filter.as_deref().is_none_or(|filter| part.contains(filter));
    if selected("ttl") {
        ttl()?;
    }
    if selected("snapshot") {
        snapshot()?;
    }
    if selected("catch-up") {
        catch_up()?;
    }
    Ok(())
}

fn main() -> std::process::ExitCode {
    // Errors return here, so every `Scratch` has been dropped (its
    // directory removed) before the failure status.
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(failed) => {
            let _ = writeln!(std::io::stderr(), "item37: {failed}");
            std::process::ExitCode::FAILURE
        }
    }
}
