// SPDX-License-Identifier: Apache-2.0

//! `karyos-tools upgrade-evidence` (SPEC.md §9, the third rolling-upgrade
//! rule; ADR-0122; karyos#716): the evidence a node needs before it runs a
//! new binary ahead of an activation. The rule asks for two pieces, and
//! this module produces both as recording group journals that
//! `karyos-replay diff` (§8.3) compares:
//!
//! - **The replay.** A recorded Cluster log, replayed through the
//!   container of each binary from index 1, one event per entry: the
//!   entry's payload as the input, the typed outcome of applying it as the
//!   observation. The last event holds the composed snapshot after the
//!   last entry applied.
//! - **The differential test.** Generated command sequences ([`Generator`],
//!   one per seed), replayed the same way. They hold what both versions
//!   must handle identically, and what neither knows: unknown command
//!   types, unknown schemas, schema 2 and 5 versions no build writes,
//!   unknown templates, and bytes that are no message. Both binaries must
//!   accept the same entries with the same results and refuse the same
//!   entries with the same typed errors; a stop ([`ApplyError`]) is an
//!   outcome too, and the replay ends there.
//!
//! **The one command.** `scripts/upgrade-evidence.sh <old-rev> <new-rev>
//! <log-dir>` builds this subcommand at both revisions, writes both sets
//! of journals and compares each pair with `karyos-replay diff`; any
//! difference fails it. It records the evidence (the log, both revisions,
//! the seeds and every result) in `evidence.txt`.
//!
//! **What a clean diff does not say** (`quantstratum-docs:
//! karyos/testing/contract-traceability-phase-3.md`, the output diff row,
//! and plan issue 071): the diff compares records; a captured output is
//! compared by its length and CRC-32C, not byte by byte, so two outputs
//! that collide are not told apart. The outcomes here are recorded as
//! external observations, whose value is the text of the typed outcome
//! (its `Debug` form, the same code at both revisions only while that form
//! does not change: a change of the form alone shows as a difference, a
//! false alarm, never a missed one). The generated inputs cover what the
//! generator draws, not every input; the seeds name exactly which.
//!
//! **No normalisation.** Every field of every outcome is compared. An
//! apply-time [`CoreRefusal::VersionInactive`](karyos_cluster::service::CoreRefusal::VersionInactive) carries only the active
//! version, which the log fixes, so a command type only the new version
//! knows is refused identically by both binaries.
//!
//! **A declaration is not evidence** (SPEC.md:711): a service's statement
//! that a version is compatible, its `supported_version` or
//! `required_version` included, proves nothing. Only these journals,
//! compared clean, do.
//!
//! The service is the reference one, [`Reference`]: the container's own
//! behaviour across two Karyos revisions. A service author runs
//! [`replay`] over their own [`ClusteredService`] the same way, at both of
//! their revisions.

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};

use karyos_archive::disk::StdDisk;
use karyos_archive::group::journal::{GroupJournal, JournalConfig, MIN_SEGMENT_LENGTH};
use karyos_archive::group::record::{
    CONTRACT_VERSION, Capture, Clock, EndOutcome, EventEnd, ExternalEvent, ExternalObservation,
    GroupRecord, JournalHeader, MAX_INLINE, MAX_RECORD,
};
use karyos_archive::segment::{Geometry, SyncPolicy};
use karyos_cluster::log::{Entry, RaftLog};
use karyos_cluster::service::{
    Activation, ActiveVersion, Applied, ApplyError, ClusteredService, ContainerConfig, Context,
    CoordinatedStop, Envelope, ServiceContainer, ServiceSnapshot, SessionBounds, SnapshotFull,
};
use karyos_cluster::{DedupConfig, Request};

#[cfg(test)]
mod tests;

/// The exit status of an error.
pub const EXIT_ERROR: u8 = 2;

/// The event kind of an applied entry.
pub const KIND_ENTRY: u32 = 1;
/// The event kind of the closing snapshot.
pub const KIND_SNAPSHOT: u32 = 2;

/// The usage text.
pub const HELP: &str = "\
karyos-tools upgrade-evidence: the rolling-upgrade evidence of SPEC.md
section 9 (karyos#716), as recording group journals for karyos-replay diff.

Usage: karyos-tools upgrade-evidence replay --log <dir> --geometry <term>,<segment>
                                            --out <dir> --manifest <text>
       karyos-tools upgrade-evidence generate --seed <n> --count <n>
                                              [--max-service <n>]
                                              --out <dir> --manifest <text>
       karyos-tools upgrade-evidence record --seed <n> --count <n>
                                            [--max-service <n>] --log <dir>
                                            --geometry <term>,<segment>

  replay     replay a recorded Cluster log (from index 1; read from a copy:
             opening a log may cut a torn tail) into the journal of group 1
  generate   replay seed <n>'s generated sequence of <count> entries
  record     write seed <n>'s sequence as a Cluster log, to have one
  --max-service  the highest service version an Activation or a stop's
             resume names [1]: the old binary's, so that both run it
  --supported <n>  the reference service's supported version [1]
  --manifest the identity of what ran, recorded in the journal header

scripts/upgrade-evidence.sh runs both revisions and the diffs.
Exit status: 0 written; 2 error.
";

/// A splitmix64 generator: the same sequence from the same seed, on every
/// build and platform.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    /// The generator of `seed`.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// The next value.
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A value in `0..bound` (`bound` > 0).
    pub fn below(&mut self, bound: u64) -> u64 {
        self.next_u64() % bound.max(1)
    }

    fn byte(&mut self) -> u8 {
        self.next_u64().to_le_bytes()[0]
    }

    fn bytes(&mut self, length: u64) -> Vec<u8> {
        (0..length).map(|_| self.byte()).collect()
    }
}

/// A client the generator registered: its id, its epoch (the index of its
/// `Register`) and its next sequence.
#[derive(Debug, Clone, Copy)]
struct Client {
    id: u64,
    epoch: u64,
    next: u64,
}

/// The generated command sequence of one seed: Cluster log entries from
/// index 1, each payload one of the kinds below, drawn by weight. Known
/// inputs ([`Generator::entry`]): `SessionBounds` (first), `Register`,
/// `Request` (commands of the reference service's known types, and of
/// types no version knows), `Close`, `TimerFired`, `Configuration`,
/// `Activation`, `CoordinatedStop`, an empty entry. Unknown inputs
/// ([`Generator::probe`]), each a safety stop, so one ends a sequence: a
/// schema no build knows, schema 2 and schema 5 versions no build writes,
/// an unknown template of either schema, and random bytes.
#[derive(Debug, Clone)]
pub struct Generator {
    rng: Rng,
    index: u64,
    clients: Vec<Client>,
    max_service: u32,
}

impl Generator {
    /// Seed `seed`'s sequence. Activations and stops name service versions
    /// up to `max_service`: past the old binary's, its run ends at a stop
    /// the new binary does not take, which is the version change itself,
    /// not a difference in handling.
    #[must_use]
    pub fn new(seed: u64, max_service: u32) -> Self {
        Self {
            rng: Rng::new(seed),
            index: 0,
            clients: Vec::new(),
            max_service: max_service.max(1),
        }
    }

    /// The next entry.
    pub fn entry(&mut self) -> Entry {
        self.index += 1;
        let index = self.index;
        let payload = if index == 1 {
            SessionBounds::new(DedupConfig::default())
                .to_vec()
                .unwrap_or_default()
        } else {
            self.payload(index)
        };
        Entry {
            index,
            term: 1,
            event_time: index.saturating_mul(1_000),
            payload,
        }
    }

    fn payload(&mut self, index: u64) -> Vec<u8> {
        let draw = self.rng.below(73);
        match draw {
            0..=9 => self.register(index),
            10..=44 => self.request(index),
            45..=49 => self.close(index),
            50..=55 => {
                // The reference service schedules timer `key % 4` two
                // entries ahead: some of these match, most do not.
                let timer = self.rng.below(4);
                let deadline = index
                    .saturating_sub(self.rng.below(8))
                    .saturating_mul(1_000);
                encode(&Envelope::TimerFired { timer, deadline })
            }
            56..=59 => {
                let length = 1 + self.rng.below(16);
                encode(&Envelope::Configuration(&self.rng.bytes(length)))
            }
            60..=65 => {
                let service = 1 + self.version_below(self.max_service);
                let schema = u16::try_from(1 + self.rng.below(2)).unwrap_or(1);
                let offset = 1 + self.rng.below(6);
                let length = self.rng.below(4);
                let configuration = self.rng.bytes(length);
                Activation::new(ActiveVersion::new(service, schema), offset, &configuration)
                    .to_vec()
                    .unwrap_or_default()
            }
            66..=67 => {
                let offset = self.rng.below(7);
                let resume = 1 + self.version_below(self.max_service);
                CoordinatedStop::new(offset, resume)
                    .to_vec()
                    .unwrap_or_default()
            }
            _ => Vec::new(),
        }
    }

    /// The next entry, an unknown input: a schema no build knows, a
    /// schema 2 or schema 5 version no build writes, an unknown template,
    /// or bytes that are no message. Each is a safety stop
    /// ([`ApplyError::Envelope`]) on every binary, so a sequence ends with
    /// one: [`generate`]'s last entry.
    pub fn probe(&mut self) -> Entry {
        self.index += 1;
        let index = self.index;
        let payload = self.unknown(index);
        Entry {
            index,
            term: 1,
            event_time: index.saturating_mul(1_000),
            payload,
        }
    }

    fn unknown(&mut self, index: u64) -> Vec<u8> {
        match self.rng.below(4) {
            0 => {
                // A schema no build knows: anything but 2, 5 and 6.
                let schema = loop {
                    let schema = u16::try_from(self.rng.below(u64::from(u16::MAX))).unwrap_or(9);
                    if !matches!(schema, 2 | 5 | 6) {
                        break schema;
                    }
                };
                let length = self.rng.below(24);
                header(schema, 1, 1, &self.rng.bytes(length))
            }
            1 => {
                // A known message at a version no build writes.
                let (mut bytes, low) = if self.rng.below(2) == 0 {
                    (self.request(index), 2)
                } else {
                    (
                        Activation::new(ActiveVersion::new(1, 1), 1, &[])
                            .to_vec()
                            .unwrap_or_default(),
                        3,
                    )
                };
                let version = u16::try_from(low + self.rng.below(8)).unwrap_or(9);
                if let Some(field) = bytes.get_mut(4..6) {
                    field.copy_from_slice(&version.to_le_bytes());
                }
                bytes
            }
            2 => {
                let schema = if self.rng.below(2) == 0 { 2 } else { 5 };
                let template = u16::try_from(6 + self.rng.below(40)).unwrap_or(9);
                header(schema, template, if schema == 2 { 1 } else { 2 }, &[])
            }
            _ => {
                let length = 1 + self.rng.below(40);
                self.rng.bytes(length)
            }
        }
    }

    fn version_below(&mut self, max: u32) -> u32 {
        u32::try_from(self.rng.below(u64::from(max))).unwrap_or(0)
    }

    fn register(&mut self, index: u64) -> Vec<u8> {
        let id = if self.clients.len() < 6 && self.rng.below(4) != 0 {
            let id = u64::try_from(self.clients.len()).unwrap_or(0) + 1;
            self.clients.push(Client {
                id,
                epoch: index,
                next: 0,
            });
            id
        } else {
            // A client that registered already: a new epoch, or a refusal.
            let id = 1 + self.rng.below(7);
            if let Some(client) = self.clients.iter_mut().find(|client| client.id == id) {
                client.epoch = index;
                client.next = 0;
            }
            id
        };
        encode(&Envelope::Register { client: id })
    }

    fn close(&mut self, index: u64) -> Vec<u8> {
        if self.clients.is_empty() {
            return self.register(index);
        }
        let slot = usize::try_from(self.rng.below(self.clients.len() as u64)).unwrap_or(0);
        let stale = self.rng.below(4) == 0;
        let Some(client) = self.clients.get(slot).copied() else {
            return Vec::new();
        };
        // Mostly its epoch; sometimes an older one, refused.
        let epoch = if stale {
            client.epoch.saturating_sub(1).max(1)
        } else {
            client.epoch
        };
        encode(&Envelope::Close {
            client: client.id,
            epoch,
        })
    }

    fn request(&mut self, index: u64) -> Vec<u8> {
        if self.clients.is_empty() {
            return self.register(index);
        }
        let slot = usize::try_from(self.rng.below(self.clients.len() as u64)).unwrap_or(0);
        let skew = self.rng.below(10);
        let Some(client) = self.clients.get_mut(slot) else {
            return Vec::new();
        };
        // Mostly the next sequence; sometimes a retry or a gap.
        let sequence = match skew {
            0 => client.next.saturating_sub(1),
            1 => client.next + 2,
            _ => client.next,
        };
        client.next = client.next.max(sequence + 1);
        let request = Request::new(client.id, client.epoch, sequence, sequence);
        let command = match self.rng.below(8) {
            0..=2 => vec![1, self.rng.byte() % 8, self.rng.byte()],
            3..=4 => vec![2, self.rng.byte() % 8],
            5 => vec![3, self.rng.byte() % 8],
            6 => vec![0x7f, self.rng.byte()],
            _ => {
                let length = self.rng.below(6);
                self.rng.bytes(length)
            }
        };
        encode(&Envelope::Request {
            request,
            command: &command,
        })
    }
}

fn encode(envelope: &Envelope<'_>) -> Vec<u8> {
    envelope.to_vec().unwrap_or_default()
}

/// A message header over `block`, with no variable part.
fn header(schema: u16, template: u16, version: u16, block: &[u8]) -> Vec<u8> {
    let block_length = u16::try_from(block.len()).unwrap_or(0);
    let message_length = u32::from(block_length) + 12;
    let mut out = Vec::with_capacity(block.len() + 12);
    out.extend_from_slice(&schema.to_le_bytes());
    out.extend_from_slice(&template.to_le_bytes());
    out.extend_from_slice(&version.to_le_bytes());
    out.extend_from_slice(&block_length.to_le_bytes());
    out.extend_from_slice(&message_length.to_le_bytes());
    out.extend_from_slice(block);
    out
}

/// The reference service: counters by key. Command `[1, key, delta]` adds
/// (version 1), `[2, key]` reads (version 1), `[3, key]` resets (version
/// 2); every other type no version knows. An add schedules timer
/// `key % 4` two entries ahead. A version 2 binary runs `[3]`
/// once version 2 is active; a version 1 binary does not know it.
#[derive(Debug, Clone)]
pub struct Reference {
    counters: [u64; 8],
    supported: u32,
    timers: u64,
    configurations: u64,
}

impl Reference {
    /// A service running versions up to `supported`.
    #[must_use]
    pub const fn new(supported: u32) -> Self {
        Self {
            counters: [0; 8],
            supported,
            timers: 0,
            configurations: 0,
        }
    }

    fn counter(&mut self, key: u8) -> Option<&mut u64> {
        self.counters.get_mut(usize::from(key % 8))
    }
}

impl ClusteredService for Reference {
    fn on_command(
        &mut self,
        context: &mut Context<'_>,
        _client: u64,
        command: &[u8],
        reply: &mut [u8],
    ) -> Option<usize> {
        let key = command.get(1).copied().unwrap_or(0);
        let value = match command.first() {
            Some(1) => {
                let delta = u64::from(command.get(2).copied().unwrap_or(0));
                let deadline = context.log_time().saturating_add(2_000);
                let _ = context.schedule(u64::from(key % 4), deadline);
                let counter = self.counter(key)?;
                *counter = counter.wrapping_add(delta);
                *counter
            }
            Some(3) if context.active_version().service >= 2 => {
                let counter = self.counter(key)?;
                *counter = 0;
                0
            }
            _ => self.counter(key).map_or(0, |counter| *counter),
        };
        let out = reply.get_mut(..8)?;
        out.copy_from_slice(&value.to_le_bytes());
        Some(8)
    }

    fn on_timer(&mut self, _context: &mut Context<'_>, _timer: u64) {
        self.timers = self.timers.wrapping_add(1);
    }

    fn on_configuration(&mut self, _context: &mut Context<'_>, configuration: &[u8]) {
        self.configurations = self
            .configurations
            .wrapping_add(u64::try_from(configuration.len()).unwrap_or(0));
    }

    fn snapshot(&self, parts: &mut ServiceSnapshot) -> Result<(), SnapshotFull> {
        let mut bytes = Vec::with_capacity(80);
        for counter in self.counters {
            bytes.extend_from_slice(&counter.to_le_bytes());
        }
        bytes.extend_from_slice(&self.timers.to_le_bytes());
        bytes.extend_from_slice(&self.configurations.to_le_bytes());
        parts.part(1, 1, &bytes)
    }

    fn required_version(&self, command: &[u8]) -> Option<u32> {
        match command.first() {
            Some(1 | 2) => Some(1),
            Some(3) if self.supported >= 2 => Some(2),
            _ => None,
        }
    }

    fn supported_version(&self) -> u32 {
        self.supported
    }
}

/// The text of an entry's outcome, as recorded: its typed result's
/// `Debug` text, unnormalised.
#[must_use]
pub fn outcome_text(result: &Result<Applied<'_>, ApplyError>) -> String {
    format!("{result:?}")
}

/// One recorded step: the entry and the text of its outcome; the last
/// step's entry is `None` and its text the composed snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// The entry applied; `None` for the closing snapshot.
    pub entry: Option<Entry>,
    /// What it did.
    pub outcome: String,
}

/// Applies `entries` in order to `container` and returns each step, up to
/// and including the first stop, then the closing snapshot.
pub fn replay<S: ClusteredService>(
    container: &mut ServiceContainer<S>,
    entries: impl IntoIterator<Item = Entry>,
) -> Vec<Step> {
    let mut steps = Vec::new();
    for entry in entries {
        let result = container.apply(&entry);
        let outcome = outcome_text(&result);
        let stopped = result.is_err();
        steps.push(Step {
            entry: Some(entry),
            outcome,
        });
        if stopped {
            break;
        }
    }
    let mut parts = ServiceSnapshot::new(4096, 4);
    let snapshot = format!("{:?}", container.snapshot(&mut parts));
    steps.push(Step {
        entry: None,
        outcome: snapshot,
    });
    steps
}

/// The first step at which two replays differ: its position, and both
/// sides' steps (`None` past a side's end).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Divergence {
    /// The step's position, from 0.
    pub at: usize,
    /// The old binary's step.
    pub old: Option<Step>,
    /// The new binary's.
    pub new: Option<Step>,
}

/// The in-process differential test: seed `seed`'s `count` entries
/// replayed through `old` and `new`, compared step by step.
///
/// # Errors
///
/// The first [`Divergence`].
pub fn differential<A: ClusteredService, B: ClusteredService>(
    old: A,
    new: B,
    seed: u64,
    count: u64,
    max_service: u32,
) -> Result<usize, Box<Divergence>> {
    let entries = generate(seed, count, max_service);
    let mut old = ServiceContainer::new(old, ContainerConfig::default()).map_err(|_| {
        Box::new(Divergence {
            at: 0,
            old: None,
            new: None,
        })
    })?;
    let mut new = ServiceContainer::new(new, ContainerConfig::default()).map_err(|_| {
        Box::new(Divergence {
            at: 0,
            old: None,
            new: None,
        })
    })?;
    let left = replay(&mut old, entries.clone());
    let right = replay(&mut new, entries);
    compare(&left, &right)
}

/// Compares two replays step by step.
///
/// # Errors
///
/// The first [`Divergence`].
pub fn compare(old: &[Step], new: &[Step]) -> Result<usize, Box<Divergence>> {
    for at in 0..old.len().max(new.len()) {
        let (left, right) = (old.get(at), new.get(at));
        if left != right {
            return Err(Box::new(Divergence {
                at,
                old: left.cloned(),
                new: right.cloned(),
            }));
        }
    }
    Ok(old.len())
}

/// Seed `seed`'s sequence of `count` entries: `count - 1` known inputs,
/// then one unknown input ([`Generator::probe`]), which stops every
/// binary; a sequence that stops earlier ends there.
#[must_use]
pub fn generate(seed: u64, count: u64, max_service: u32) -> Vec<Entry> {
    let mut generator = Generator::new(seed, max_service);
    let mut entries: Vec<Entry> = (1..count).map(|_| generator.entry()).collect();
    if count > 0 {
        entries.push(generator.probe());
    }
    entries
}

/// Writes `steps` as the journal of group 1 in `dir`, under `manifest`.
///
/// # Errors
///
/// The journal's error, as text.
pub fn write_journal(dir: &Path, manifest: &str, steps: &[Step]) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    let manifest = if manifest.is_empty() { "-" } else { manifest };
    let header = JournalHeader {
        group_id: 1,
        first_group_seq: 1,
        inline_threshold: 4096,
        contract_version: CONTRACT_VERSION,
        clock: Clock::HostMonotonic,
        capture: Capture::Strict,
        reopen_hold: 0,
        manifest: manifest.as_bytes(),
    };
    let config = JournalConfig::new(MIN_SEGMENT_LENGTH, SyncPolicy::PerSegment);
    let mut journal =
        GroupJournal::create(StdDisk, dir, &header, config).map_err(|error| error.to_string())?;
    let mut out = vec![0u8; MAX_RECORD];
    for (seq, step) in (1u64..).zip(steps) {
        let (kind, value, time) = match &step.entry {
            Some(entry) => (KIND_ENTRY, entry.payload.as_slice(), entry.event_time),
            None => (KIND_SNAPSHOT, &[][..], 0),
        };
        let observed = step.outcome.as_bytes();
        let observed = observed.get(..MAX_INLINE).unwrap_or(observed);
        let value = value.get(..MAX_INLINE).unwrap_or(value);
        let records = [
            GroupRecord::External(ExternalEvent {
                group_seq: seq,
                logical_time: time,
                kind,
                value,
            }),
            GroupRecord::ExternalObservation(ExternalObservation {
                group_seq: seq,
                index: 0,
                kind,
                value: observed,
            }),
            GroupRecord::End(EventEnd {
                group_seq: seq,
                observations: 1,
                outcome: EndOutcome::Complete,
            }),
        ];
        let mut event = Vec::new();
        for record in records {
            let length = record.encode(&mut out).map_err(|error| error.to_string())?;
            event.extend_from_slice(out.get(..length).unwrap_or_default());
        }
        let _ = journal.append(&event).map_err(|error| error.to_string())?;
    }
    let _ = journal.close().map_err(|error| error.to_string())?;
    Ok(())
}

/// Every entry of the Cluster log in `dir`, from its first index.
///
/// # Errors
///
/// The log's error, as text.
pub fn read_log(dir: &Path, geometry: Geometry) -> Result<Vec<Entry>, String> {
    let mut log = RaftLog::open(StdDisk, dir, geometry)
        .map_err(|error| error.to_string())?
        .log;
    let Some(last) = log.last_index() else {
        return Ok(Vec::new());
    };
    let first = log.first_index();
    log.entries(first..last + 1, u64::MAX)
        .map_err(|error| error.to_string())
}

/// Writes `entries` as a Cluster log in `dir`.
///
/// # Errors
///
/// The log's error, as text.
pub fn write_log(dir: &Path, geometry: Geometry, entries: &[Entry]) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    let mut log = RaftLog::create(StdDisk, dir, geometry, 1).map_err(|error| error.to_string())?;
    let _ = log.append(entries).map_err(|error| error.to_string())?;
    let _ = log.sync().map_err(|error| error.to_string())?;
    log.close().map_err(|error| error.to_string())
}

#[derive(Debug, Default)]
struct Args {
    command: String,
    log: Option<PathBuf>,
    out: Option<PathBuf>,
    geometry: Option<Geometry>,
    manifest: String,
    seed: u64,
    count: u64,
    max_service: u32,
    supported: u32,
}

fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Option<Args>, String> {
    let mut args = args.into_iter();
    let command = match args.next() {
        None => return Ok(None),
        Some(command) => command
            .into_string()
            .map_err(|_| "an argument is not UTF-8")?,
    };
    if command == "-h" || command == "--help" {
        return Ok(None);
    }
    if !matches!(command.as_str(), "replay" | "generate" | "record") {
        return Err(format!("unknown command {command}"));
    }
    let mut parsed = Args {
        command,
        max_service: 1,
        supported: 1,
        ..Args::default()
    };
    while let Some(flag) = args.next() {
        let flag = flag.into_string().map_err(|_| "an argument is not UTF-8")?;
        let value = args
            .next()
            .ok_or_else(|| format!("{flag} needs a value"))?
            .into_string()
            .map_err(|_| "an argument is not UTF-8")?;
        let number = |value: &str| value.parse::<u64>().map_err(|_| format!("bad {flag}"));
        match flag.as_str() {
            "--log" => parsed.log = Some(PathBuf::from(value)),
            "--out" => parsed.out = Some(PathBuf::from(value)),
            "--manifest" => parsed.manifest = value,
            "--seed" => parsed.seed = number(&value)?,
            "--count" => parsed.count = number(&value)?,
            "--max-service" => {
                parsed.max_service =
                    u32::try_from(number(&value)?).map_err(|_| "bad --max-service")?;
            }
            "--supported" => {
                parsed.supported = u32::try_from(number(&value)?).map_err(|_| "bad --supported")?;
            }
            "--geometry" => {
                let (term, segment) = value
                    .split_once(',')
                    .ok_or("--geometry takes <term>,<segment>")?;
                let term = term.parse().map_err(|_| "bad term length")?;
                let segment = segment.parse().map_err(|_| "bad segment length")?;
                parsed.geometry =
                    Some(Geometry::new(term, segment).map_err(|error| error.to_string())?);
            }
            _ => return Err(format!("unknown flag {flag}")),
        }
    }
    Ok(Some(parsed))
}

fn execute(args: &Args) -> Result<(), String> {
    let need = |path: &Option<PathBuf>, flag: &str| {
        path.clone()
            .ok_or_else(|| format!("{} needs {flag}", args.command))
    };
    let geometry = || {
        args.geometry
            .ok_or_else(|| format!("{} needs --geometry", args.command))
    };
    let container = || {
        ServiceContainer::new(Reference::new(args.supported), ContainerConfig::default())
            .map_err(|error| error.to_string())
    };
    match args.command.as_str() {
        "record" => write_log(
            &need(&args.log, "--log")?,
            geometry()?,
            &generate(args.seed, args.count, args.max_service),
        ),
        "replay" => {
            let entries = read_log(&need(&args.log, "--log")?, geometry()?)?;
            let steps = replay(&mut container()?, entries);
            write_journal(&need(&args.out, "--out")?, &args.manifest, &steps)
        }
        _ => {
            let entries = generate(args.seed, args.count, args.max_service);
            let steps = replay(&mut container()?, entries);
            write_journal(&need(&args.out, "--out")?, &args.manifest, &steps)
        }
    }
}

/// Runs `karyos-tools upgrade-evidence` on `args` (after its name) and
/// returns the exit status.
pub fn run(
    args: impl IntoIterator<Item = OsString>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    match parse(args) {
        Ok(None) => {
            let _ = stdout.write_all(HELP.as_bytes());
            0
        }
        Ok(Some(args)) => match execute(&args) {
            Ok(()) => 0,
            Err(error) => {
                let _ = writeln!(stderr, "karyos-tools upgrade-evidence: {error}");
                EXIT_ERROR
            }
        },
        Err(error) => {
            let _ = writeln!(
                stderr,
                "karyos-tools upgrade-evidence: {error} (karyos-tools upgrade-evidence --help)"
            );
            EXIT_ERROR
        }
    }
}
