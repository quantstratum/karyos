// SPDX-License-Identifier: Apache-2.0

//! A guard owned by another driver, as one receiving driver follows it
//! (`quantstratum-docs:
//! karyos/adr/0086-wire-authentication-profile-v1.md` section 7,
//! `karyos/adr/0107-guard-recovery-and-renewal-on-the-wire.md` and
//! `karyos/design/authenticated-control-schemas.md` section 4; part of
//! quantstratum/karyos#648).
//!
//! A [`RemoteGuard`] starts closed and in recovery. Recovery and every
//! grant or extension of an `Open` are an accepted signed STATUS answering
//! the receiver's own unexpired, unconsumed nonce for its current boot id.
//! On it the floor becomes the STATUS epoch, persisted in [`GuardMarks`]
//! before anything opens; a STATUS below the durable mark latches the
//! guard closed for good, the latch persisted with the mark so a restart
//! keeps it (only another configured guard id starts afresh). After
//! recovery a STATE above the floor raises the floor at once, in memory
//! even when it cannot yet be persisted, and retires any outstanding
//! round: a `Closed` one closes, an `Open` one closes and only starts a
//! confirmation round. Nothing opens until the raised floor is durable
//! and a fresh STATUS meets it. An `Open` lapses one lifetime after its
//! last confirmation. The verified datagrams come from
//! [`crate::signed_control::SignedIntake`]; this module is its epoch check
//! and state change. Nothing here allocates after construction.

use karyos_protocol::network::authenticated::{GuardState, GuardStatus, StatusChallenge};
use karyos_protocol::network::{Identity, Receiver};

use crate::sessions::NonceSource;
use crate::wire_keys::store::{FileError, Files};

/// How long a challenge nonce lives (`setup_challenge_timeout`).
pub const CHALLENGE_TIMEOUT_NS: u64 = 1_000_000_000;
/// The lifetime of an `Open` recovery applies (`guard_lifetime_ms`).
pub const DEFAULT_LIFETIME_NS: u64 = 5_000_000_000;

/// The durable guard epoch marks: one small file per guard, replaced
/// atomically and durably, its epoch only ever raised and its rollback
/// latch only ever set.
pub trait MarkStore: core::fmt::Debug {
    /// The durable mark of `guard_id`: 0 when none was ever stored.
    ///
    /// # Errors
    ///
    /// [`MarkError`] when it exists and cannot be read; the guard then
    /// stays closed.
    fn load(&self, guard_id: u64) -> Result<u64, MarkError>;
    /// Whether `guard_id`'s durable rollback latch is set: false when no
    /// mark was ever stored.
    ///
    /// # Errors
    ///
    /// [`MarkError`] when the mark exists and cannot be read; the guard
    /// then stays latched closed.
    fn latched(&self, guard_id: u64) -> Result<bool, MarkError>;
    /// Persists `epoch` as `guard_id`'s mark before it is acted on,
    /// keeping its latch.
    ///
    /// # Errors
    ///
    /// [`MarkError`] when the mark cannot be read or the commit fails;
    /// nothing may then open.
    fn persist(&mut self, guard_id: u64, epoch: u64) -> Result<(), MarkError>;
    /// Sets `guard_id`'s rollback latch durably, keeping its epoch. Never
    /// cleared: only a different guard id has a mark of its own.
    ///
    /// # Errors
    ///
    /// [`MarkError`] when the mark cannot be read or the commit fails; the
    /// guard is latched in memory regardless.
    fn latch(&mut self, guard_id: u64) -> Result<(), MarkError>;
}

/// Why a mark cannot be read or stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkError {
    /// The file is refused or does not parse.
    Unreadable,
    /// The commit failed.
    Commit,
}

/// The epoch-only format, read as unlatched; never written.
const MARK_FORMAT_V1: &str = "karyos-guard-mark-v1";
/// The epoch and the rollback latch.
const MARK_FORMAT: &str = "karyos-guard-mark-v2";

/// A small text built on the stack: a mark file and its name allocate
/// nothing.
struct StackText {
    buf: [u8; 96],
    len: usize,
}

impl StackText {
    fn new() -> Self {
        Self {
            buf: [0; 96],
            len: 0,
        }
    }

    fn as_str(&self) -> &str {
        self.buf
            .get(..self.len)
            .and_then(|bytes| core::str::from_utf8(bytes).ok())
            .unwrap_or("")
    }
}

impl core::fmt::Write for StackText {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        let end = self.len.checked_add(text.len()).ok_or(core::fmt::Error)?;
        self.buf
            .get_mut(self.len..end)
            .ok_or(core::fmt::Error)?
            .copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// [`MarkStore`] over a state directory ([`Files`]: on Linux a
/// `karyos_sys::secure_dir::SecureDir`), with the commit discipline of
/// the key state: an atomic, durable replace. A followed guard's marks
/// ([`GuardMarks::new`]) and an authority's committed epochs
/// ([`GuardMarks::authority`]) are named apart.
pub struct GuardMarks<F: Files> {
    files: F,
    prefix: &'static str,
}

impl<F: Files> core::fmt::Debug for GuardMarks<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GuardMarks").finish_non_exhaustive()
    }
}

impl<F: Files> GuardMarks<F> {
    /// The marks of the guards this driver follows, in `files`.
    pub fn new(files: F) -> Self {
        Self {
            files,
            prefix: "guard-",
        }
    }

    /// The committed epochs of the guards this driver is the authority
    /// of, in `files` ([`crate::guard_authority::GuardAuthority`]).
    pub fn authority(files: F) -> Self {
        Self {
            files,
            prefix: "authority-guard-",
        }
    }

    fn name(&self, guard_id: u64) -> StackText {
        let mut name = StackText::new();
        // At most 16 + 20 bytes: it fits.
        let _ = core::fmt::Write::write_fmt(&mut name, format_args!("{}{guard_id}", self.prefix));
        name
    }

    /// The epoch and latch of `guard_id`: `(0, false)` when none was
    /// stored. Any other format, or a malformed one, is unreadable.
    fn read(&self, guard_id: u64) -> Result<(u64, bool), MarkError> {
        let mut buf = [0u8; 96];
        let len = match self.files.read(self.name(guard_id).as_str(), &mut buf) {
            Ok(len) => len,
            Err(FileError::NotFound) => return Ok((0, false)),
            Err(FileError::Refused) => return Err(MarkError::Unreadable),
        };
        let text = buf
            .get(..len)
            .and_then(|bytes| core::str::from_utf8(bytes).ok())
            .ok_or(MarkError::Unreadable)?;
        let mut lines = text.split('\n');
        let v2 = match lines.next() {
            Some(MARK_FORMAT) => true,
            Some(MARK_FORMAT_V1) => false,
            _ => return Err(MarkError::Unreadable),
        };
        let epoch = lines
            .next()
            .and_then(|line| line.strip_prefix("epoch="))
            .filter(|value| value.bytes().all(|byte| byte.is_ascii_digit()))
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or(MarkError::Unreadable)?;
        let latched = if v2 {
            match lines.next() {
                Some("latched=0") => false,
                Some("latched=1") => true,
                _ => return Err(MarkError::Unreadable),
            }
        } else {
            false
        };
        if lines.next() != Some("") || lines.next().is_some() {
            return Err(MarkError::Unreadable);
        }
        Ok((epoch, latched))
    }

    fn write(&self, guard_id: u64, epoch: u64, latched: bool) -> Result<(), MarkError> {
        let mut text = StackText::new();
        core::fmt::Write::write_fmt(
            &mut text,
            format_args!(
                "{MARK_FORMAT}\nepoch={epoch}\nlatched={}\n",
                u8::from(latched)
            ),
        )
        .map_err(|_| MarkError::Commit)?;
        self.files
            .write_atomic(self.name(guard_id).as_str(), text.as_str().as_bytes())
            .map_err(|_| MarkError::Commit)
    }
}

impl<F: Files> MarkStore for GuardMarks<F> {
    fn load(&self, guard_id: u64) -> Result<u64, MarkError> {
        self.read(guard_id).map(|(epoch, _)| epoch)
    }

    fn latched(&self, guard_id: u64) -> Result<bool, MarkError> {
        self.read(guard_id).map(|(_, latched)| latched)
    }

    fn persist(&mut self, guard_id: u64, epoch: u64) -> Result<(), MarkError> {
        // Only ever raised, and never over a mark it cannot read.
        let (held, latched) = self.read(guard_id)?;
        if held >= epoch {
            return Ok(());
        }
        self.write(guard_id, epoch, latched)
    }

    fn latch(&mut self, guard_id: u64) -> Result<(), MarkError> {
        let (held, latched) = self.read(guard_id)?;
        if latched {
            return Ok(());
        }
        self.write(guard_id, held, true)
    }
}

/// The durable record of the publication incarnations whose remote
/// SESSION_ABORT this receiver applied (H8 RCV-4): one stays terminal
/// across a receiver-only restart, even when its ACK never reached the
/// sender, so its SETUP never establishes it again.
pub trait AbortRecord: core::fmt::Debug {
    /// Whether `identity` is terminal here. Fail closed: true for every
    /// identity once the record is full or unreadable.
    fn terminal(&self, identity: &Identity) -> bool;
    /// Records `identity` durably before the abort is acknowledged. `Ok`
    /// only once it is committed: a repeated call after a failed commit
    /// retries it, never reports the in-memory entry as durable.
    ///
    /// # Errors
    ///
    /// [`MarkError`] when the record is full or unreadable, or the commit
    /// failed; the identity is terminal in memory regardless, and the
    /// abort must not be acknowledged.
    fn record(&mut self, identity: Identity) -> Result<(), MarkError>;
    /// Admits `identity` for an image install (H8 R5-02): records its
    /// publisher's incarnation high-water durably first, so a restart
    /// after an unclean stop knows which incarnations were live here.
    ///
    /// # Errors
    ///
    /// [`MarkError`] when `identity` is terminal or the high-water could
    /// not be committed: the install is refused (fail closed).
    fn admit(&mut self, identity: Identity) -> Result<(), MarkError> {
        if self.terminal(&identity) {
            return Err(MarkError::Unreadable);
        }
        Ok(())
    }
}

/// The most incarnations [`AbortedIncarnations`] holds; past it every
/// identity is terminal (fail closed, as a full key state disables the
/// store, KSF-4).
pub const MAX_ABORTED: usize = 256;
/// The record's file in the driver's durable state directory.
pub const ABORTED_FILE: &str = "aborted-incarnations";
/// Its replica, written first at each commit: a commit holds once either
/// file holds it, and a load takes the union of both.
pub const ABORTED_REPLICA: &str = "aborted-incarnations-replica";
const ABORTED_FORMAT: &str = "karyos-aborted-incarnations-v2";
/// The format before the incarnation high-water (no `h` lines), still read.
const ABORTED_FORMAT_V1: &str = "karyos-aborted-incarnations-v1";
/// The most publishers whose incarnation high-water the record keeps; a
/// new publisher past it is refused its install (fail closed).
pub const MAX_PUBLISHERS: usize = 256;
/// The longest line: a prefix (`h ` or `f `), four `u64` of 20 digits,
/// three dashes and the newline.
const ABORTED_LINE_MAX: usize = 2 + 4 * 20 + 3 + 1;
/// The largest record file: the header and flag, every terminal identity,
/// and both publisher tables, the high-water and the floor (H8 round 7,
/// R7-01).
pub const ABORTED_MAX_LEN: usize = 64 + (MAX_ABORTED + 2 * MAX_PUBLISHERS) * ABORTED_LINE_MAX;
/// The marker armed at every start and disarmed at a clean stop with
/// nothing left uncommitted (H8 R5-02): found armed, the last run may have
/// lost an abort it never committed.
pub const ABORTED_MARKER: &str = "aborted-incarnations-armed";
const MARKER_ARMED: &str = "karyos-aborted-marker-v1\narmed=1\n";
const MARKER_CLEAN: &str = "karyos-aborted-marker-v1\narmed=0\n";

/// [`AbortRecord`] in two files of a [`Files`] directory, each a header, a
/// `full` flag and one `<driver0>-<driver1>-<registration>-<incarnation>`
/// line per terminal identity, each replaced atomically at each record:
/// the replica first, then the record. The record is created with the
/// state directory ([`initialise_aborted`]), so a missing record is a lost
/// one and fails closed, never an empty one.
pub struct AbortedIncarnations<F: Files> {
    files: F,
    held: Vec<Identity>,
    /// A commit of `held` failed: the next record retries it.
    dirty: bool,
    /// The capacity was exceeded once: every identity is terminal.
    full: bool,
    /// The file could not be read at start: every identity is terminal.
    unreadable: bool,
    /// Per publisher (driver id, registration), the highest incarnation an
    /// image was installed for here, durably (H8 R5-02).
    high: Vec<([u64; 2], u64, u64)>,
    /// Per publisher, the terminal floor, durably: every incarnation at or
    /// below it is terminal. A start that finds the marker armed (the last
    /// run stopped uncleanly, so an abort it applied may never have been
    /// committed) raises it to the high-water and commits it before
    /// anything else, so a later clean stop cannot forget it (#1288
    /// review). It is separate from `high`, which keeps rising with this
    /// run's installs without making them terminal.
    floor: Vec<([u64; 2], u64, u64)>,
}

impl<F: Files> core::fmt::Debug for AbortedIncarnations<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AbortedIncarnations")
            .field("held", &self.held.len())
            .field("full", &self.full)
            .field("unreadable", &self.unreadable)
            .field("floor", &self.floor.len())
            .finish_non_exhaustive()
    }
}

impl<F: Files> AbortedIncarnations<F> {
    /// The record in `files`, loaded now; allocates only here.
    pub fn new(files: F) -> Self {
        let mut record = Self {
            files,
            held: Vec::with_capacity(MAX_ABORTED),
            dirty: false,
            full: false,
            unreadable: false,
            high: Vec::with_capacity(MAX_PUBLISHERS),
            floor: Vec::with_capacity(MAX_PUBLISHERS),
        };
        let loaded = record
            .load(ABORTED_FILE, false)
            .and_then(|()| record.load(ABORTED_REPLICA, true));
        if loaded.is_err() {
            record.held.clear();
            record.high.clear();
            record.floor.clear();
            record.unreadable = true;
        }
        // The marker (H8 R5-02): armed, or unreadable, the last run did not
        // stop cleanly. It is armed again now, while the disk works; a
        // record that cannot arm it fails closed.
        let mut buf = [0u8; 64];
        let uncertain = match record.files.read(ABORTED_MARKER, &mut buf) {
            Ok(len) => buf.get(..len) != Some(MARKER_CLEAN.as_bytes()),
            Err(FileError::NotFound) => false,
            Err(FileError::Refused) => true,
        };
        if uncertain && !record.unreadable {
            // Every incarnation that was live becomes terminal, durably,
            // before the marker is armed again; not committed, the record
            // fails closed.
            let mut raised = false;
            for (driver, registration, incarnation) in record.high.clone() {
                raised |=
                    raise(&mut record.floor, (driver, registration), incarnation).unwrap_or(true);
            }
            if raised && (record.write().is_err() || record.dirty) {
                record.unreadable = true;
            }
        }
        if record
            .files
            .write_atomic(ABORTED_MARKER, MARKER_ARMED.as_bytes())
            .is_err()
        {
            record.unreadable = true;
        }
        record
    }

    /// Disarms the marker at a clean stop, only when nothing is left
    /// uncommitted (H8 R5-02); `Drop` calls it.
    pub fn close(&mut self) {
        if !self.dirty && !self.unreadable {
            let _ = self
                .files
                .write_atomic(ABORTED_MARKER, MARKER_CLEAN.as_bytes());
        }
    }

    /// Whether `identity` is at or below its publisher's terminal floor.
    fn below_floor(&self, identity: &Identity) -> bool {
        self.floor
            .iter()
            .any(|&(driver, registration, incarnation)| {
                driver == identity.driver_id
                    && registration == identity.registration_id
                    && identity.incarnation <= incarnation
            })
    }

    /// Adds what `name` holds. A missing record was lost (it is created
    /// with the state directory); a missing replica was never written.
    fn load(&mut self, name: &str, optional: bool) -> Result<(), MarkError> {
        let mut buf = vec![0u8; ABORTED_MAX_LEN + 1];
        let len = match self.files.read(name, &mut buf) {
            Ok(len) => len,
            Err(FileError::NotFound) if optional => return Ok(()),
            Err(FileError::NotFound) => return Err(MarkError::Unreadable),
            Err(FileError::Refused) => return Err(MarkError::Unreadable),
        };
        let text = buf
            .get(..len)
            .and_then(|bytes| core::str::from_utf8(bytes).ok())
            .ok_or(MarkError::Unreadable)?;
        let mut lines = text.split('\n');
        let v2 = match lines.next() {
            Some(ABORTED_FORMAT) => true,
            Some(ABORTED_FORMAT_V1) => false,
            _ => return Err(MarkError::Unreadable),
        };
        self.full |= match lines.next() {
            Some("full=0") => false,
            Some("full=1") => true,
            _ => return Err(MarkError::Unreadable),
        };
        for line in lines {
            if line.is_empty() {
                continue;
            }
            let (table, line) = match (line.strip_prefix("h "), line.strip_prefix("f ")) {
                (Some(rest), _) if v2 => (Some(false), rest),
                (_, Some(rest)) if v2 => (Some(true), rest),
                (Some(_), _) | (_, Some(_)) => return Err(MarkError::Unreadable),
                (None, None) => (None, line),
            };
            let mut parts = line.split('-').map(|part| {
                part.bytes()
                    .all(|byte| byte.is_ascii_digit())
                    .then(|| part.parse::<u64>().ok())
                    .flatten()
            });
            let (Some(Some(d0)), Some(Some(d1)), Some(Some(registration)), Some(Some(inc)), None) = (
                parts.next(),
                parts.next(),
                parts.next(),
                parts.next(),
                parts.next(),
            ) else {
                return Err(MarkError::Unreadable);
            };
            let identity = Identity {
                driver_id: [d0, d1],
                registration_id: registration,
                incarnation: inc,
            };
            if let Some(is_floor) = table {
                // The union of both copies: the higher value.
                let table = if is_floor {
                    &mut self.floor
                } else {
                    &mut self.high
                };
                if raise(table, ([d0, d1], registration), inc).is_err() {
                    return Err(MarkError::Unreadable);
                }
                continue;
            }
            if self.held.contains(&identity) {
                continue;
            }
            if self.held.len() >= MAX_ABORTED {
                return Err(MarkError::Unreadable);
            }
            self.held.push(identity);
        }
        Ok(())
    }

    /// Commits `held` to the replica, then the record: it holds once
    /// either write does, since a load takes the union. It stays dirty
    /// until the record itself is written.
    fn write(&mut self) -> Result<(), MarkError> {
        let text = encode_aborted(self.full, &self.held, &self.high, &self.floor);
        let replica = self.files.write_atomic(ABORTED_REPLICA, text.as_bytes());
        let record = self.files.write_atomic(ABORTED_FILE, text.as_bytes());
        self.dirty = record.is_err();
        if replica.is_err() && record.is_err() {
            return Err(MarkError::Commit);
        }
        Ok(())
    }
}

/// Raises `key`'s entry of `table` to `incarnation`: whether it rose, or
/// `Err` when a new publisher does not fit.
fn raise(
    table: &mut Vec<([u64; 2], u64, u64)>,
    key: ([u64; 2], u64),
    incarnation: u64,
) -> Result<bool, ()> {
    let at = table
        .iter()
        .position(|(driver, registration, _)| (*driver, *registration) == key);
    let full = table.len() >= MAX_PUBLISHERS;
    match at.and_then(|at| table.get_mut(at)) {
        Some(entry) if entry.2 >= incarnation => Ok(false),
        Some(entry) => {
            entry.2 = incarnation;
            Ok(true)
        }
        None if !full => {
            table.push((key.0, key.1, incarnation));
            Ok(true)
        }
        None => Err(()),
    }
}

fn encode_aborted(
    full: bool,
    held: &[Identity],
    high: &[([u64; 2], u64, u64)],
    floor: &[([u64; 2], u64, u64)],
) -> String {
    use core::fmt::Write as _;

    let mut text = String::with_capacity(ABORTED_MAX_LEN);
    let _ = writeln!(text, "{ABORTED_FORMAT}\nfull={}", u8::from(full));
    for identity in held {
        let _ = writeln!(
            text,
            "{}-{}-{}-{}",
            identity.driver_id[0],
            identity.driver_id[1],
            identity.registration_id,
            identity.incarnation
        );
    }
    for (prefix, table) in [("h", high), ("f", floor)] {
        for (driver, registration, incarnation) in table {
            let _ = writeln!(
                text,
                "{prefix} {}-{}-{registration}-{incarnation}",
                driver[0], driver[1]
            );
        }
    }
    text
}

impl<F: Files> Drop for AbortedIncarnations<F> {
    fn drop(&mut self) {
        self.close();
    }
}

/// Creates the empty abort record in a new state directory, with the key
/// state (design section 2.6): from then on a missing record is a lost one.
///
/// # Errors
///
/// [`MarkError::Commit`] when the write fails.
pub fn initialise_aborted<F: Files + ?Sized>(files: &F) -> Result<(), MarkError> {
    files
        .write_atomic(
            ABORTED_FILE,
            encode_aborted(false, &[], &[], &[]).as_bytes(),
        )
        .map_err(|_| MarkError::Commit)
}

impl<F: Files> AbortRecord for AbortedIncarnations<F> {
    fn terminal(&self, identity: &Identity) -> bool {
        self.full || self.unreadable || self.held.contains(identity) || self.below_floor(identity)
    }

    fn admit(&mut self, identity: Identity) -> Result<(), MarkError> {
        if self.terminal(&identity) {
            return Err(MarkError::Unreadable);
        }
        let key = (identity.driver_id, identity.registration_id);
        let rose =
            raise(&mut self.high, key, identity.incarnation).map_err(|()| MarkError::Commit)?;
        // Already covered and durable: nothing to commit. Covered only in
        // memory (an earlier commit failed): the commit is retried, never
        // skipped (#1288 review).
        if !rose && !self.dirty {
            return Ok(());
        }
        // Raised in memory whatever the commit does: the install waits for
        // it, so an uncommitted high-water admits nothing here.
        match self.write() {
            Ok(()) if !self.dirty => Ok(()),
            _ => Err(MarkError::Commit),
        }
    }

    fn record(&mut self, identity: Identity) -> Result<(), MarkError> {
        if self.unreadable {
            return Err(MarkError::Unreadable);
        }
        if self.held.contains(&identity) {
            // Held in memory is not durable: retry a failed commit.
            return if self.dirty { self.write() } else { Ok(()) };
        }
        if self.held.len() >= MAX_ABORTED {
            // Fail closed: from here every identity is terminal, durably.
            self.full = true;
            self.write()?;
            return Err(MarkError::Commit);
        }
        self.held.push(identity);
        self.write()
    }
}

/// Where a followed guard is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Closed, waiting for a STATUS (the start).
    Recovering,
    /// Recovered and closed.
    Closed,
    /// Recovered and open at `epoch` until `until` (monotonic ns).
    Open {
        /// The open epoch.
        epoch: u64,
        /// When it lapses without a confirmation.
        until: u64,
    },
    /// A STATUS below the durable mark was seen during recovery: closed
    /// for good under this `guard_id`, durably (design section 4.4, step
    /// 3; ADR-0107 decision 6).
    Latched,
}

/// Why a STATUS or STATE changed nothing; one counter each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum GuardRefusal {
    /// No round is outstanding, or the nonce was never drawn.
    UnknownNonce = 0,
    /// The nonce expired, or was consumed or replaced.
    StaleNonce,
    /// Another receiver's boot id or id.
    WrongReceiver,
    /// Another guard or authority.
    WrongGuard,
    /// A STATE during recovery: discarded, the floor unchanged.
    Recovering,
    /// At or below the floor.
    Stale,
    /// Latched closed.
    Latched,
    /// The mark could not be persisted: nothing opens.
    Persist,
}

/// Refusal reasons.
pub const GUARD_REFUSALS: usize = GuardRefusal::Persist as usize + 1;

/// What an accepted STATUS or STATE did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardChange {
    /// Recovery completed, or a transition applied; the new phase.
    Applied(Phase),
    /// An `Open` STATE above the floor: the floor rose, and a confirmation
    /// round must start; nothing opened.
    ConfirmationDue,
}

/// One followed guard.
#[derive(Debug)]
pub struct RemoteGuard {
    authority_id: u64,
    guard_id: u64,
    floor: u64,
    phase: Phase,
    /// The outstanding round: its nonce and when it was drawn.
    round: Option<([u64; 2], u64)>,
    /// The last nonce consumed or replaced, for its own reason.
    retired: Option<[u64; 2]>,
    /// The lifetime of the `Open` STATE awaiting confirmation, by epoch.
    pending: Option<(u64, u64)>,
    /// The lifetime of the last confirmed `Open` STATE (the default until
    /// one is): each confirmation extends the `Open` by it, and its
    /// renewal round falls due from half of it before the `Open` lapses.
    lifetime_ns: u64,
    refusals: [u64; GUARD_REFUSALS],
}

impl RemoteGuard {
    /// A guard of `authority_id` starting closed and recovering, its floor
    /// the durable mark `mark`.
    #[must_use]
    pub fn new(authority_id: u64, guard_id: u64, mark: u64) -> Self {
        Self {
            authority_id,
            guard_id,
            floor: mark,
            phase: Phase::Recovering,
            round: None,
            retired: None,
            pending: None,
            lifetime_ns: DEFAULT_LIFETIME_NS,
            refusals: [0; GUARD_REFUSALS],
        }
    }

    /// The guard, its marks read from `marks`: a durable latch, or
    /// unreadable marks, leave it latched closed (fail closed).
    pub fn load(authority_id: u64, guard_id: u64, marks: &dyn MarkStore) -> Self {
        match (marks.load(guard_id), marks.latched(guard_id)) {
            (Ok(mark), Ok(false)) => Self::new(authority_id, guard_id, mark),
            (Ok(mark), Ok(true)) => Self {
                phase: Phase::Latched,
                ..Self::new(authority_id, guard_id, mark)
            },
            _ => Self {
                phase: Phase::Latched,
                ..Self::new(authority_id, guard_id, u64::MAX)
            },
        }
    }

    /// The guard id.
    #[must_use]
    pub fn guard_id(&self) -> u64 {
        self.guard_id
    }

    /// The floor.
    #[must_use]
    pub fn floor(&self) -> u64 {
        self.floor
    }

    /// The phase at `now`, an `Open` past its lifetime closed.
    #[must_use]
    pub fn phase(&self, now: u64) -> Phase {
        match self.phase {
            Phase::Open { until, .. } if now >= until => Phase::Closed,
            phase => phase,
        }
    }

    /// The guard word a local sender gate reads for this guard at `now`
    /// (`karyos_sys::guard` encoding): `(epoch, Open)` only while open and
    /// confirmed; otherwise a closed word at the floor, or just above an
    /// open floor that lapsed or awaits confirmation, so no gate admits.
    /// A publication it guards is admitted only once this word first
    /// reads `(e, Open)` ([`crate::agents::data::Outbound::guard_remote`]);
    /// its gate then aborts the incarnation for good on any other word,
    /// as for a local guard (guards-and-abort.md, "The sender gate and
    /// applied epoch", step 3).
    #[must_use]
    pub fn word(&self, now: u64) -> u64 {
        let closed = |epoch: u64| {
            let epoch = epoch.max(1);
            let epoch = if epoch.is_multiple_of(2) {
                epoch.saturating_add(1).min(karyos_sys::guard::MAX_EPOCH)
            } else {
                epoch
            };
            karyos_sys::guard::encode(karyos_sys::guard::GuardState { epoch, open: false })
                .unwrap_or(karyos_sys::guard::created())
        };
        match self.phase(now) {
            Phase::Open { epoch, .. } => {
                karyos_sys::guard::encode(karyos_sys::guard::GuardState { epoch, open: true })
                    .unwrap_or_else(|| closed(epoch))
            }
            Phase::Recovering | Phase::Closed | Phase::Latched => closed(self.floor),
        }
    }

    /// Whether the guard is open at `now`.
    #[must_use]
    pub fn is_open(&self, now: u64) -> bool {
        matches!(self.phase(now), Phase::Open { .. })
    }

    /// The refusals for `reason`.
    #[must_use]
    pub fn refusals(&self, reason: GuardRefusal) -> u64 {
        self.refusals.get(reason as usize).copied().unwrap_or(0)
    }

    fn refuse(&mut self, reason: GuardRefusal) -> GuardRefusal {
        if let Some(count) = self.refusals.get_mut(reason as usize) {
            *count = count.saturating_add(1);
        }
        reason
    }

    fn round_live(&self, now: u64) -> bool {
        self.round
            .is_some_and(|(_, at)| now.saturating_sub(at) < CHALLENGE_TIMEOUT_NS)
    }

    /// Whether a new round is due at `now`: while recovering, while an
    /// `Open` STATE awaits confirmation, and from half an `Open`'s lifetime
    /// on; never once latched, and not while a round is live.
    #[must_use]
    pub fn round_due(&self, now: u64) -> bool {
        if self.round_live(now) {
            return false;
        }
        match self.phase(now) {
            Phase::Recovering => true,
            Phase::Closed => self.pending.is_some(),
            Phase::Open { until, .. } => now >= until.saturating_sub(self.lifetime_ns / 2),
            Phase::Latched => false,
        }
    }

    /// Starts a round for `receiver` at `now`: a fresh nonce, which
    /// replaces the previous one. `None` when latched or the nonce source
    /// failed.
    pub fn challenge(
        &mut self,
        receiver: Receiver,
        now: u64,
        nonces: &mut dyn NonceSource,
    ) -> Option<StatusChallenge> {
        if self.phase == Phase::Latched {
            return None;
        }
        let nonce = nonces.nonce()?;
        if let Some((old, _)) = self.round.replace((nonce, now)) {
            self.retired = Some(old);
        }
        Some(StatusChallenge {
            authority_id: self.authority_id,
            guard_id: self.guard_id,
            receiver,
            nonce,
        })
    }

    /// A verified STATUS, for this receiver's current `receiver` block, at
    /// `now`: accepted only for the outstanding, unexpired nonce, which it
    /// consumes. During recovery an epoch at or above the floor completes
    /// it (the floor persisted first); one below latches. After recovery a
    /// higher epoch is a transition, the same open epoch extends the
    /// `Open`, a lower one changes nothing.
    ///
    /// # Errors
    ///
    /// The [`GuardRefusal`], counted.
    pub fn on_status(
        &mut self,
        status: &GuardStatus,
        receiver: Receiver,
        now: u64,
        marks: &mut dyn MarkStore,
    ) -> Result<GuardChange, GuardRefusal> {
        if (status.authority_id, status.guard_id) != (self.authority_id, self.guard_id) {
            return Err(self.refuse(GuardRefusal::WrongGuard));
        }
        if status.receiver != receiver {
            return Err(self.refuse(GuardRefusal::WrongReceiver));
        }
        match self.round {
            Some((nonce, _)) if nonce == status.nonce => {}
            _ if self.retired == Some(status.nonce) => {
                return Err(self.refuse(GuardRefusal::StaleNonce));
            }
            _ => return Err(self.refuse(GuardRefusal::UnknownNonce)),
        }
        let live = self.round_live(now);
        // Consumed either way: a nonce answers once.
        self.retired = self.round.take().map(|(nonce, _)| nonce);
        if !live {
            return Err(self.refuse(GuardRefusal::StaleNonce));
        }
        if self.phase == Phase::Latched {
            return Err(self.refuse(GuardRefusal::Latched));
        }
        let epoch = status.word.epoch();
        let recovering = self.phase == Phase::Recovering;
        if epoch < self.floor {
            if recovering {
                // The authority is behind this receiver: latched closed,
                // durably, so a restart keeps it (closed in memory even
                // if the latch cannot be stored).
                self.phase = Phase::Latched;
                if marks.latch(self.guard_id).is_err() {
                    self.refuse(GuardRefusal::Persist);
                }
                return Err(self.refuse(GuardRefusal::Latched));
            }
            return Err(self.refuse(GuardRefusal::Stale));
        }
        if marks.persist(self.guard_id, epoch).is_err() {
            // The verified epoch is still the safety floor: nothing below
            // it opens, and nothing opens until a fresh STATUS at or above
            // it is persisted.
            self.floor = epoch;
            self.phase = if recovering {
                Phase::Recovering
            } else {
                Phase::Closed
            };
            return Err(self.refuse(GuardRefusal::Persist));
        }
        self.floor = epoch;
        self.phase = if status.word.is_open() {
            // The confirmed STATE's lifetime stays the lifetime of every
            // later confirmation and of the renewal schedule.
            if let Some((pending, lifetime)) = self.pending
                && pending == epoch
            {
                self.lifetime_ns = lifetime;
            }
            let lifetime = self.lifetime_ns;
            Phase::Open {
                epoch,
                until: now.saturating_add(lifetime),
            }
        } else {
            Phase::Closed
        };
        if self.pending.is_some_and(|(pending, _)| pending <= epoch) {
            self.pending = None;
        }
        Ok(GuardChange::Applied(self.phase))
    }

    /// A verified STATE at `now`: discarded during recovery or once
    /// latched; refused at or below the floor. Above it the guard closes,
    /// the floor rises in memory at once and the outstanding round is
    /// retired, before the floor is persisted: a failed commit never
    /// leaves the old floor or an old nonce able to reopen it. `Closed`
    /// stops there; `Open` only makes a confirmation round due, which
    /// opens once a fresh STATUS meets the floor and persists it.
    ///
    /// # Errors
    ///
    /// The [`GuardRefusal`], counted.
    pub fn on_state(
        &mut self,
        state: &GuardState,
        now: u64,
        marks: &mut dyn MarkStore,
    ) -> Result<GuardChange, GuardRefusal> {
        if (state.authority_id, state.guard_id) != (self.authority_id, self.guard_id) {
            return Err(self.refuse(GuardRefusal::WrongGuard));
        }
        match self.phase(now) {
            Phase::Recovering => return Err(self.refuse(GuardRefusal::Recovering)),
            Phase::Latched => return Err(self.refuse(GuardRefusal::Latched)),
            Phase::Closed | Phase::Open { .. } => {}
        }
        let epoch = state.word.epoch();
        if epoch <= self.floor {
            return Err(self.refuse(GuardRefusal::Stale));
        }
        // A transition: whatever was open or being confirmed is over.
        // Closing, raising the floor and retiring the round are always
        // safe, so they happen even if the mark cannot be stored.
        self.phase = Phase::Closed;
        self.floor = epoch;
        if let Some((nonce, _)) = self.round.take() {
            self.retired = Some(nonce);
        }
        let open = state.word.is_open();
        // An `Open` needs a fresh confirmation: until then it is closed.
        self.pending = open.then(|| {
            (
                epoch,
                u64::from(state.lifetime_ms).saturating_mul(1_000_000),
            )
        });
        if marks.persist(self.guard_id, epoch).is_err() {
            return Err(self.refuse(GuardRefusal::Persist));
        }
        Ok(if open {
            GuardChange::ConfirmationDue
        } else {
            GuardChange::Applied(Phase::Closed)
        })
    }
}

#[cfg(test)]
pub(crate) mod tests;
