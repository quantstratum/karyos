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
//!   lags by the whole allowance;
//! - **a lagging follower, from the log or from a snapshot** (karyos#1013):
//!   the whole 1 GiB allowance read from the leader's log, sent, and
//!   appended and synced by the follower, against a snapshot of each
//!   profile read, sent, written, installed and decoded by the follower.
//!   The transfer is a loopback TCP connection on this host, so it is the
//!   kernel's copy and not a wire; a link's own time is added apart.
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
use std::io::{BufReader, BufWriter, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
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

/// A table of `config`'s profile with every session registered and every
/// window slot holding a full response.
fn full_table(config: DedupConfig) -> Result<SessionTable, Failed> {
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
    Ok(table)
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
        let table = full_table(config)?;
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

/// A log in `scratch` holding the 1 GiB allowance of `payload` byte
/// entries, synced: the log, its entry count and the time to write it.
fn allowance_log(
    scratch: &Scratch,
    geometry: Geometry,
    payload: usize,
) -> Result<(RaftLog<StdDisk>, u64, Duration), Failed> {
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
    Ok((log, entries, started.elapsed()))
}

fn catch_up() -> Result<(), Failed> {
    say("## Catch-up allowance: 1 GiB of log read back as a leader reads it")?;
    let geometry = ok(Geometry::new(64 * 1024, 1024 * 1024), "a geometry")?;
    // W1's 32 B commands too: the most frames per GiB (karyos#1001).
    for payload in [32, 256, 8192] {
        let scratch = Scratch::new(&format!("log-{payload}"))?;
        let (mut log, entries, wrote) = allowance_log(&scratch, geometry, payload)?;
        // A cold read when asked (karyos#1001): `KARYOS_ITEM37_COLD` is a
        // shell command run after the sync, before the read, that empties
        // the page cache (for example `sync; sudo -n sh -c 'echo 3 >
        // /proc/sys/vm/drop_caches'` on Linux).
        let cache = match std::env::var("KARYOS_ITEM37_COLD") {
            Ok(command) => {
                let status = ok(
                    std::process::Command::new("sh")
                        .arg("-c")
                        .arg(&command)
                        .status(),
                    "the cold-cache command",
                )?;
                if !status.success() {
                    return Err(format!("the cold-cache command failed: {status}"));
                }
                "cold"
            }
            Err(_) => "warm",
        };
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
        #[allow(clippy::cast_precision_loss, reason = "a printed rate")]
        let per_entry = took.as_secs_f64() * 1e6 / (entries.max(1) as f64);
        say(&format!(
            "catch-up payload {payload} B: {entries} entries in 1 GiB, written and synced in {wrote:?}; read back {cache} in {took:?} ({rate:.2} GiB/s, {per_entry:.2} µs per entry, {} MiB of payload)",
            read >> 20
        ))?;
    }
    Ok(())
}

/// Writes `value` as 8 little-endian bytes.
fn put(output: &mut impl Write, value: u64) -> Result<(), Failed> {
    ok(output.write_all(&value.to_le_bytes()), "a send")
}

/// Reads 8 little-endian bytes.
fn word(input: &mut impl Read) -> Result<u64, Failed> {
    let mut bytes = [0u8; 8];
    ok(input.read_exact(&mut bytes), "a receive")?;
    Ok(u64::from_le_bytes(bytes))
}

/// `length` bytes from `input`.
fn bytes(input: &mut impl Read, length: u64) -> Result<Vec<u8>, Failed> {
    let mut read = vec![0u8; ok(usize::try_from(length), "a length")?];
    ok(input.read_exact(&mut read), "a receive")?;
    Ok(read)
}

/// A loopback listener, and the leader's connected end of it.
fn connection() -> Result<(TcpListener, TcpStream), Failed> {
    let listener = ok(TcpListener::bind((Ipv4Addr::LOCALHOST, 0)), "a listener")?;
    let address = ok(listener.local_addr(), "the listener's address")?;
    let stream = ok(TcpStream::connect(address), "a connection")?;
    Ok((listener, stream))
}

/// The follower's side of `handle`, or the failure that ended it.
fn joined<T>(handle: std::thread::JoinHandle<Result<T, Failed>>) -> Result<T, Failed> {
    handle
        .join()
        .map_err(|_| "the follower thread panicked".to_owned())?
}

/// Runs the leader's side `lead` against a follower thread `follow`, and
/// joins the follower on every path: the leader's connection is closed
/// first, so a follower blocked on a receive ends, and the follower's own
/// failure, when it has one, is the one reported (a leader's broken pipe
/// is usually its consequence). Nothing outlives the call, so the scratch
/// directories are never removed under a running follower.
fn exchange<T: Send + 'static, U>(
    follow: impl FnOnce(TcpListener) -> Result<T, Failed> + Send + 'static,
    lead: impl FnOnce(&mut BufReader<TcpStream>, &mut BufWriter<TcpStream>) -> Result<U, Failed>,
) -> Result<(T, U), Failed> {
    let (listener, stream) = connection()?;
    let handle = std::thread::spawn(move || follow(listener));
    let led = ok(stream.try_clone(), "a second handle of the connection").and_then(|reader| {
        let mut input = BufReader::new(reader);
        let mut output = BufWriter::with_capacity(1 << 20, stream);
        lead(&mut input, &mut output)
    });
    // `lead` owned both handles of the leader's end: they are closed here,
    // before the join, whatever it returned.
    let followed = joined(handle);
    match (followed, led) {
        (Err(follower), _) => Err(follower),
        (Ok(_), Err(leader)) => Err(leader),
        (Ok(followed), Ok(led)) => Ok((followed, led)),
    }
}

/// Signals one step to the other side: one byte.
fn signal(output: &mut impl Write) -> Result<(), Failed> {
    ok(output.write_all(&[1]), "a signal")?;
    ok(output.flush(), "a signal")
}

/// Waits for the other side's signal.
fn await_signal(input: &mut impl Read) -> Result<(), Failed> {
    let mut byte = [0u8; 1];
    ok(input.read_exact(&mut byte), "a signal")
}

/// The follower of the log route. Its log is created before it signals
/// that it is ready; it then appends each batch it receives (a count,
/// then each entry's index, term, event time, length and payload; a count
/// of 0 ends), syncs, and signals that it is durable. Returns the entries
/// applied.
fn follow_log(listener: &TcpListener, dir: &Path, geometry: Geometry) -> Result<u64, Failed> {
    let mut log = ok(RaftLog::create(StdDisk, dir, geometry, 1), "a follower log")?;
    let (stream, _) = ok(listener.accept(), "an accept")?;
    let mut reply = ok(stream.try_clone(), "a second handle of the connection")?;
    let mut input = BufReader::with_capacity(1 << 20, stream);
    signal(&mut reply)?;
    let mut applied = 0u64;
    let mut batch = Vec::new();
    loop {
        let count = word(&mut input)?;
        if count == 0 {
            break;
        }
        batch.clear();
        for _ in 0..count {
            let index = word(&mut input)?;
            let term = word(&mut input)?;
            let event_time = word(&mut input)?;
            let length = word(&mut input)?;
            batch.push(Entry {
                index,
                term,
                event_time,
                payload: bytes(&mut input, length)?,
            });
        }
        let _ = ok(log.append(&batch), "a follower append")?;
        applied = fits(applied.checked_add(count), "the entries applied")?;
    }
    let _ = ok(log.sync(), "a follower sync")?;
    signal(&mut reply)?;
    Ok(applied)
}

/// The follower of the snapshot route. Its snapshot store and its log are
/// opened before it signals that it is ready, the log holding one synced
/// entry so that the install cuts frames as it does on a lagging
/// follower. It then receives the consensus and sessions sections (each a
/// version, a length and its bytes), writes them as its own snapshot at
/// `base`, installs that snapshot into the log, decodes the session table
/// from the snapshot as stored (read back from its store, not from the
/// receive buffer), and signals that it is done. Returns the sessions the
/// decoded table holds.
fn follow_snapshot(
    listener: &TcpListener,
    dir: &Path,
    geometry: Geometry,
    base: (u64, u64),
) -> Result<usize, Failed> {
    let snapshots_dir = dir.join("snapshots");
    let log_dir = dir.join("log");
    ok(
        std::fs::create_dir(&snapshots_dir),
        "the follower's snapshot directory",
    )?;
    ok(
        std::fs::create_dir(&log_dir),
        "the follower's log directory",
    )?;
    let mut store = ok(
        SnapshotStore::open(StdDisk, &snapshots_dir, geometry, SnapshotConfig::default()),
        "a follower snapshot store",
    )?
    .store;
    let mut log = ok(
        RaftLog::create(StdDisk, &log_dir, geometry, 1),
        "a follower log",
    )?;
    let _ = ok(
        log.append(&[Entry {
            index: 1,
            term: 1,
            event_time: 1,
            payload: vec![0x5a; 32],
        }]),
        "the follower's lagging entry",
    )?;
    let _ = ok(log.sync(), "a follower sync")?;
    let (stream, _) = ok(listener.accept(), "an accept")?;
    let mut reply = ok(stream.try_clone(), "a second handle of the connection")?;
    let mut input = BufReader::with_capacity(1 << 20, stream);
    signal(&mut reply)?;
    let consensus_version = word(&mut input)?;
    let length = word(&mut input)?;
    let consensus = bytes(&mut input, length)?;
    let sessions_version = word(&mut input)?;
    let length = word(&mut input)?;
    let sessions = bytes(&mut input, length)?;
    let info = ok(
        store.write(
            base.0,
            base.1,
            &[
                Section::new(SectionKind::Consensus, consensus_version, &consensus),
                Section::new(SectionKind::Sessions, sessions_version, &sessions),
            ],
        ),
        "the follower's snapshot",
    )?;
    drop((consensus, sessions));
    ok(log.install(base.0, base.1, &store), "the install")?;
    let stored = ok(store.read(&info), "the follower's snapshot read")?;
    let Some(section) = stored
        .iter()
        .find(|section| section.kind == SectionKind::Sessions)
    else {
        return Err("the follower's snapshot has no sessions section".to_owned());
    };
    let table = ok(SessionTable::decode(&section.bytes), "the sessions section")?;
    let held = table.live_sessions();
    drop(black_box(table));
    signal(&mut reply)?;
    Ok(held)
}

/// A follower lagging by the whole allowance (karyos#1013): caught up
/// from the leader's log at each payload, and by a snapshot install of
/// each profile. The follower opens its log (and its snapshot store)
/// first; each route is then timed from the leader's first read to the
/// follower's signal that its end is durable, so neither the follower's
/// setup nor the thread's teardown is in it.
///
/// The snapshot is the leader's at its tip, so nothing is replayed after
/// the install: the route is the snapshot's read, transfer, write,
/// install (which cuts the follower's frames) and decode. The snapshot's
/// sections are whole buffers end to end, as the store's API writes and
/// reads them; the log route moves in batches of up to 1 MiB.
fn follower() -> Result<(), Failed> {
    say("## A follower lagging by the whole 1 GiB allowance: from the log or from a snapshot")?;
    let geometry = ok(Geometry::new(64 * 1024, 1024 * 1024), "a geometry")?;
    for payload in [32, 256, 8192] {
        let leader = Scratch::new(&format!("leader-{payload}"))?;
        let (mut log, entries, _) = allowance_log(&leader, geometry, payload)?;
        // What the log holds: whole entries, the allowance rounded down.
        let held = log_bytes(entries, payload)?;
        let follower = Scratch::new(&format!("follower-{payload}"))?;
        let dir = follower.path().to_path_buf();
        let (applied, (took, sent)) = exchange(
            move |listener| follow_log(&listener, &dir, geometry),
            |input, output| {
                await_signal(input)?;
                let started = Instant::now();
                let mut at = 1u64;
                let mut sent = 0u64;
                let end = fits(entries.checked_add(1), "the read end")?;
                while at <= entries {
                    let got = ok(log.entries(at..end, 1 << 20), "a read")?;
                    let Some(last) = got.last() else {
                        return Err(format!("a read from index {at} returned no entries"));
                    };
                    put(output, ok(u64::try_from(got.len()), "a batch length")?)?;
                    for entry in &got {
                        let length = ok(u64::try_from(entry.payload.len()), "a payload length")?;
                        put(output, entry.index)?;
                        put(output, entry.term)?;
                        put(output, entry.event_time)?;
                        put(output, length)?;
                        ok(output.write_all(&entry.payload), "a send")?;
                        sent = fits(
                            sent.checked_add(length.saturating_add(32)),
                            "the bytes sent",
                        )?;
                    }
                    at = fits(last.index.checked_add(1), "the read index")?;
                }
                put(output, 0)?;
                ok(output.flush(), "a send")?;
                await_signal(input)?;
                Ok((started.elapsed(), sent))
            },
        )?;
        if applied != entries {
            return Err(format!(
                "the follower applied {applied} of {entries} entries"
            ));
        }
        say(&format!(
            "follower log payload {payload} B: {entries} entries ({} MiB of log, {} MiB on the socket) read, sent over loopback, appended and synced in {took:?} ({:.2} GiB/s of log)",
            held >> 20,
            sent >> 20,
            gib_per_second(held, took)
        ))?;
    }
    for (name, config) in profiles() {
        let leader = Scratch::new(&format!("leader-snapshot-{name}"))?;
        let table = full_table(config)?;
        let sessions_held = table.live_sessions();
        let sessions = table.encode();
        drop(table);
        let consensus = [0u8; 64];
        let mut store = ok(
            SnapshotStore::open(StdDisk, leader.path(), geometry, SnapshotConfig::default()),
            "a snapshot store",
        )?
        .store;
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
        drop(sessions);
        let follower = Scratch::new(&format!("follower-snapshot-{name}"))?;
        let dir = follower.path().to_path_buf();
        let base = (info.index, info.term);
        let (decoded, (took, sent)) = exchange(
            move |listener| follow_snapshot(&listener, &dir, geometry, base),
            |input, output| {
                await_signal(input)?;
                let started = Instant::now();
                let sections = ok(store.read(&info), "a snapshot read")?;
                let mut sent = 0u64;
                for expected in [SectionKind::Consensus, SectionKind::Sessions] {
                    let Some(section) = sections.iter().find(|section| section.kind == expected)
                    else {
                        return Err(format!("the snapshot has no {expected:?} section"));
                    };
                    let length = ok(u64::try_from(section.bytes.len()), "a section length")?;
                    put(output, section.version)?;
                    put(output, length)?;
                    ok(output.write_all(&section.bytes), "a send")?;
                    sent = fits(
                        sent.checked_add(length.saturating_add(16)),
                        "the bytes sent",
                    )?;
                }
                ok(output.flush(), "a send")?;
                await_signal(input)?;
                Ok((started.elapsed(), sent))
            },
        )?;
        if decoded != sessions_held {
            return Err(format!(
                "the follower decoded {decoded} of {sessions_held} sessions"
            ));
        }
        say(&format!(
            "follower snapshot {name}: a {} MiB recording ({} MiB on the socket) read, sent over loopback, written, installed and decoded in {took:?}",
            info.length >> 20,
            sent >> 20
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
    if selected("follower") {
        follower()?;
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
