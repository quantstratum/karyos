// SPDX-License-Identifier: Apache-2.0

//! The key directory, loaded and reloaded against the durable key state
//! (`quantstratum-docs: karyos/design/wire-key-files.md` sections 2.1,
//! 2.3, 2.4 and 2.6).
//!
//! [`KeyStore`] reads the key directory and the state directory through
//! [`Files`], which on Linux is `karyos_sys::secure_dir::SecureDir`: each
//! opened once by descriptor and every file checked by `fstat` on its own
//! descriptor. It fails closed on every path: a refused file is absent, a
//! `revoked` list that does not validate disables every key, and a failed
//! commit disables every key until one succeeds. Nothing here enables a
//! channel; the driver calls [`KeyStore::reload`] every
//! [`RELOAD_INTERVAL_S`] seconds once a channel uses these keys.

use std::collections::BTreeMap;

use zeroize::{Zeroize, Zeroizing};

use super::state::{
    FingerprintKey, Fingerprints, KeyRef, KeyState, Lineage, MAX_ENTRIES, MAX_STATE_LEN,
    StateError, decode_fingerprint_key, encode_fingerprint_key, fingerprint,
};
use super::{KeyFile, KeyFileError, MAX_FILE_LEN, Material, parse, parse_name};

/// A heap buffer erased on drop: `zeroize` is built without `alloc`.
struct Erased(Vec<u8>);

impl Erased {
    fn new(len: usize) -> Self {
        Self(vec![0; len])
    }
}

impl core::ops::Deref for Erased {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl core::ops::DerefMut for Erased {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Drop for Erased {
    fn drop(&mut self) {
        self.0.as_mut_slice().zeroize();
    }
}

/// How often the driver reloads the key directory, in seconds (design
/// section 2.4).
pub const RELOAD_INTERVAL_S: i64 = 10;
/// The clock skew a verify window allows, in seconds (design section 2.3).
pub const SKEW_S: i64 = 60;
/// How long a predecessor epoch keeps verifying after its successor's
/// `not_before`, in seconds, before the skew (design section 2.3).
pub const OVERLAP_S: i64 = 86_400;
/// The revocation list in the key directory.
pub const REVOKED: &str = "revoked";
/// The durable key state in the state directory.
pub const STATE: &str = "key-state";
/// The fingerprint key in the state directory.
pub const FINGERPRINT_KEY: &str = "fingerprint-key";

/// Why a file could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileError {
    /// It does not exist.
    NotFound,
    /// It exists and was refused: owner, mode, type, size, a symbolic link
    /// or a failed read.
    Refused,
}

/// A directory opened once and checked, holding small files.
pub trait Files {
    /// The names in the directory.
    ///
    /// # Errors
    ///
    /// [`FileError::Refused`] when it cannot be listed.
    fn names(&self) -> Result<Vec<String>, FileError>;
    /// Reads `name` into `buf`, refusing anything over `buf.len() - 1`
    /// bytes, and returns its length.
    ///
    /// # Errors
    ///
    /// As [`FileError`].
    fn read(&self, name: &str, buf: &mut [u8]) -> Result<usize, FileError>;
    /// Replaces `name` with `bytes` durably and atomically.
    ///
    /// # Errors
    ///
    /// [`FileError::Refused`] when the commit fails.
    fn write_atomic(&self, name: &str, bytes: &[u8]) -> Result<(), FileError>;
    /// Takes the directory's exclusive lock without waiting, held for as
    /// long as this handle lives.
    ///
    /// # Errors
    ///
    /// [`FileError::Refused`] when another handle holds it or it cannot be
    /// taken.
    fn lock(&self) -> Result<(), FileError>;
}

#[cfg(target_os = "linux")]
impl Files for karyos_sys::secure_dir::SecureDir {
    fn names(&self) -> Result<Vec<String>, FileError> {
        Self::names(self).map_err(|_| FileError::Refused)
    }

    fn read(&self, name: &str, buf: &mut [u8]) -> Result<usize, FileError> {
        Self::read(self, name, buf).map_err(|error| match error {
            karyos_sys::secure_dir::SecureDirError::NotFound => FileError::NotFound,
            _ => FileError::Refused,
        })
    }

    fn write_atomic(&self, name: &str, bytes: &[u8]) -> Result<(), FileError> {
        Self::write_atomic(self, name, bytes).map_err(|_| FileError::Refused)
    }

    fn lock(&self) -> Result<(), FileError> {
        Self::lock_exclusive(self).map_err(|_| FileError::Refused)
    }
}

/// Why a key, or every key, is not in use. Diagnostics carry this,
/// `key_id` and `file_epoch` only (design section 2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// The file was refused by the directory checks.
    Refused,
    /// The file does not parse.
    Malformed(KeyFileError),
    /// An admitted file changed: the key is disabled for good.
    Changed,
    /// A never-admitted epoch below the highest admitted one.
    EpochBackward,
    /// A never-admitted key already past its verify window.
    Expired,
    /// A never-admitted key whose secret is another admitted key's
    /// (design section 2.2, "Independent secrets").
    ReusedSecret,
    /// The `revoked` list was refused or malformed: every key is disabled.
    RevokedList,
    /// The key directory could not be listed: every key is disabled.
    Directory,
    /// The state would exceed [`MAX_ENTRIES`]: every key is disabled.
    StateFull,
    /// A state commit failed: every key is disabled.
    Commit,
}

/// One diagnostic. `key_id` and `file_epoch` are 0 for the whole store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Event {
    /// The key identifier, or 0.
    pub key_id: u32,
    /// The file epoch, or 0.
    pub file_epoch: u32,
    /// Why.
    pub reason: Reason,
}

/// What one load or reload did. Every event raises the alarm and is
/// counted.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// The refusals and disablements, in the order they happened.
    pub events: Vec<Event>,
}

impl Report {
    /// Whether the alarm is raised.
    #[must_use]
    pub fn alarm(&self) -> bool {
        !self.events.is_empty()
    }

    fn push(&mut self, (key_id, file_epoch): KeyRef, reason: Reason) {
        self.events.push(Event {
            key_id,
            file_epoch,
            reason,
        });
    }
}

/// Why a store cannot start or be initialised.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// The state file or the fingerprint key is missing.
    #[error("the key state is not initialised")]
    NotInitialised,
    /// The state or the fingerprint key was refused by the directory checks.
    #[error("the key state cannot be read")]
    Unreadable,
    /// The state file does not decode.
    #[error("the key state is refused: {0}")]
    State(StateError),
    /// [`KeyStore::initialise`] found an existing state.
    #[error("a key state already exists")]
    AlreadyInitialised,
    /// Writing the initial state failed.
    #[error("the key state could not be written")]
    Commit,
    /// Another store holds the state directory's lock.
    #[error("the key state is in use by another store")]
    Locked,
}

/// The admitted keys, reloaded against the durable state.
pub struct KeyStore<K: Files, S: Files> {
    keys: K,
    state_dir: S,
    fingerprint_key: FingerprintKey,
    state: KeyState,
    /// The in-memory state holds changes not yet committed.
    dirty: bool,
    /// Every key is disabled until a reload validates and commits.
    disabled: bool,
    loaded: BTreeMap<KeyRef, KeyFile>,
}

impl<K: Files, S: Files> core::fmt::Debug for KeyStore<K, S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyStore")
            .field("loaded", &self.loaded.keys().collect::<Vec<_>>())
            .field("disabled", &self.disabled)
            .finish_non_exhaustive()
    }
}

impl<K: Files, S: Files> KeyStore<K, S> {
    /// Initialises an empty state in `state_dir`: the explicit operator
    /// command of design section 2.6, for a deployment that has never
    /// admitted a key. `random` is 32 bytes from a CSPRNG.
    ///
    /// # Errors
    ///
    /// [`StoreError::AlreadyInitialised`] when either file exists or cannot
    /// be read, [`StoreError::Locked`] when another store holds the state
    /// directory, and [`StoreError::Commit`] when a write fails.
    pub fn initialise(state_dir: &S, random: FingerprintKey) -> Result<(), StoreError> {
        state_dir.lock().map_err(|_| StoreError::Locked)?;
        let mut probe = Zeroizing::new([0_u8; 2]);
        for name in [STATE, FINGERPRINT_KEY] {
            if state_dir.read(name, probe.as_mut_slice()) != Err(FileError::NotFound) {
                return Err(StoreError::AlreadyInitialised);
            }
        }
        state_dir
            .write_atomic(FINGERPRINT_KEY, encode_fingerprint_key(&random).as_slice())
            .map_err(|_| StoreError::Commit)?;
        let empty = KeyState::default().encode().map_err(StoreError::State)?;
        state_dir
            .write_atomic(STATE, empty.as_bytes())
            .map_err(|_| StoreError::Commit)?;
        // The abort record is created with the state, so that a later
        // absence fails closed (H8 RCV-4).
        crate::remote_guard::initialise_aborted(state_dir).map_err(|_| StoreError::Commit)
    }

    /// Starts the store: it takes the state directory's exclusive lock and
    /// holds it for its lifetime, so no second store works from the same
    /// state; then the state and the fingerprint key must load, and the
    /// key directory is loaded as by [`KeyStore::reload`].
    ///
    /// # Errors
    ///
    /// The first [`StoreError`] that applies; no key loads.
    pub fn start(keys: K, state_dir: S, now: i64) -> Result<(Self, Report), StoreError> {
        state_dir.lock().map_err(|_| StoreError::Locked)?;
        let read = |name: &str, buf: &mut [u8]| match state_dir.read(name, buf) {
            Ok(len) => Ok(len),
            Err(FileError::NotFound) => Err(StoreError::NotInitialised),
            Err(FileError::Refused) => Err(StoreError::Unreadable),
        };
        let mut buf = Erased::new(MAX_FILE_LEN + 1);
        let len = read(FINGERPRINT_KEY, &mut buf)?;
        let fingerprint_key = decode_fingerprint_key(buf.get(..len).unwrap_or_default())
            .map_err(StoreError::State)?;
        let mut buf = Erased::new(MAX_STATE_LEN + 1);
        let len = read(STATE, &mut buf)?;
        let state =
            KeyState::decode(buf.get(..len).unwrap_or_default()).map_err(StoreError::State)?;
        let mut store = Self {
            keys,
            state_dir,
            fingerprint_key,
            state,
            dirty: false,
            disabled: true,
            loaded: BTreeMap::new(),
        };
        let report = store.reload(now);
        Ok((store, report))
    }

    /// The durable state as it stands in memory.
    #[must_use]
    pub fn state(&self) -> &KeyState {
        &self.state
    }

    /// Whether every key is disabled.
    #[must_use]
    pub fn is_disabled(&self) -> bool {
        self.disabled
    }

    /// The loaded keys.
    pub fn loaded(&self) -> impl Iterator<Item = &KeyFile> {
        self.loaded.values()
    }

    /// The key that signs and sends for `key_id` at `now`: the highest
    /// loaded epoch whose validity has started and not ended. A
    /// predecessor signs only until its successor's `not_before`, taken
    /// from the durable lineage, so whether the successor is still loaded
    /// does not matter (design section 2.3).
    #[must_use]
    pub fn signing_key(&self, key_id: u32, now: i64) -> Option<&KeyFile> {
        if self.disabled {
            return None;
        }
        let lineage = self.state.lineages.get(&key_id).copied();
        self.loaded
            .range((key_id, 0)..=(key_id, u32::MAX))
            .rev()
            .map(|(_, file)| file)
            .find(|file| {
                let cutover = match lineage {
                    Some(lineage) if file.file_epoch == lineage.highest => i64::MAX,
                    Some(Lineage {
                        predecessor: Some((epoch, deadline)),
                        ..
                    }) if epoch == file.file_epoch => successor_not_before(deadline),
                    // Below the predecessor: never signs.
                    Some(_) => i64::MIN,
                    None => i64::MAX,
                };
                file.not_before <= now && now <= file.not_after && now < cutover
            })
    }

    /// The keys that verify for `key_id` at `now`, at most two: each loaded
    /// epoch within its validity widened by [`SKEW_S`], and a predecessor
    /// only until its retirement deadline (design section 2.3).
    pub fn verify_keys(&self, key_id: u32, now: i64) -> impl Iterator<Item = &KeyFile> {
        let predecessor = self
            .state
            .lineages
            .get(&key_id)
            .and_then(|lineage| lineage.predecessor);
        self.loaded
            .range((key_id, 0)..=(key_id, u32::MAX))
            .filter(move |_| !self.disabled)
            .map(|(_, file)| file)
            .filter(move |file| {
                let deadline = match predecessor {
                    Some((epoch, deadline)) if epoch == file.file_epoch => deadline,
                    _ => i64::MAX,
                };
                file.not_before.saturating_sub(SKEW_S) <= now
                    && now <= file.not_after.saturating_add(SKEW_S)
                    && now < deadline
            })
    }

    fn disable_all(&mut self, report: &mut Report, reason: Reason) {
        self.disabled = true;
        // Dropping each key erases its secret.
        self.loaded.clear();
        report.push((0, 0), reason);
    }

    fn commit(&mut self, report: &mut Report) -> bool {
        if self.state.entries() > MAX_ENTRIES {
            self.dirty = true;
            self.disable_all(report, Reason::StateFull);
            return false;
        }
        let committed = self
            .state
            .encode()
            .ok()
            .is_some_and(|bytes| self.state_dir.write_atomic(STATE, bytes.as_bytes()).is_ok());
        self.dirty = !committed;
        if !committed {
            self.disable_all(report, Reason::Commit);
        }
        committed
    }

    /// Reopens and revalidates the `revoked` list and every key file, then
    /// swaps the result in at once (design section 2.4). Revocations,
    /// disable markers and retirements take effect in memory first and are
    /// then committed; a new admission is used only once committed.
    pub fn reload(&mut self, now: i64) -> Report {
        let mut report = Report::default();

        // 1. Revocation first.
        let Some(revoked) = self.read_revoked() else {
            self.disable_all(&mut report, Reason::RevokedList);
            return report;
        };
        for key in revoked {
            if self.state.tombstones.insert(key) {
                self.loaded.remove(&key);
                self.dirty = true;
            }
        }
        if self.dirty && !self.commit(&mut report) {
            return report;
        }

        // 2. Retirement by the wall clock, one way.
        let due: Vec<KeyRef> = self
            .state
            .lineages
            .iter()
            .filter_map(|(key_id, lineage)| {
                let (epoch, deadline) = lineage.predecessor?;
                (now >= deadline).then_some((*key_id, epoch))
            })
            .filter(|key| !self.state.retired.contains(key))
            .collect();
        for key in due {
            self.retire(key);
        }

        // 3. Every key file, reopened and revalidated.
        let Ok(names) = self.keys.names() else {
            self.disable_all(&mut report, Reason::Directory);
            return report;
        };
        let mut found: Vec<(KeyRef, String)> = names
            .into_iter()
            .filter_map(|name| parse_name(&name).ok().map(|key| (key, name)))
            .collect();
        found.sort_unstable();
        let mut next: BTreeMap<KeyRef, KeyFile> = BTreeMap::new();
        let mut admissions: Vec<(KeyFile, Fingerprints)> = Vec::new();
        let mut secrets: Vec<[u8; super::KEY_LEN]> = self
            .state
            .admitted
            .values()
            .filter_map(|prints| prints.secret)
            .collect();
        let mut buf = Erased::new(MAX_FILE_LEN + 1);
        for (key, name) in found {
            if self.state.is_dead(key) {
                continue;
            }
            let outcome = self.read_key(&name, &mut buf);
            buf.fill(0);
            let admitted = self.state.admitted.get(&key).copied();
            let (file, prints) = match outcome {
                Ok(parsed) => parsed,
                Err(reason) => {
                    report.push(key, reason);
                    if admitted.is_some() {
                        self.disable(key);
                    }
                    continue;
                }
            };
            let expired = now > file.not_after.saturating_add(SKEW_S);
            match admitted {
                Some(before) if before.file != prints.file => {
                    report.push(key, Reason::Changed);
                    self.disable(key);
                }
                Some(_) if expired => {}
                Some(_) => {
                    next.insert(key, file);
                }
                None if self
                    .state
                    .lineages
                    .get(&key.0)
                    .is_some_and(|lineage| key.1 < lineage.highest) =>
                {
                    report.push(key, Reason::EpochBackward);
                }
                None if expired => report.push(key, Reason::Expired),
                None if prints
                    .secret
                    .is_some_and(|secret| secrets.contains(&secret)) =>
                {
                    report.push(key, Reason::ReusedSecret);
                }
                None => {
                    secrets.extend(prints.secret);
                    admissions.push((file, prints));
                }
            }
        }
        // Deleted, expired, changed or refused keys leave at once.
        self.loaded.retain(|key, _| next.contains_key(key));

        // 4. New admissions: recorded, committed, and only then used.
        for (file, prints) in admissions {
            let key = (file.key_id, file.file_epoch);
            self.admit(key, &file, prints, now);
            next.insert(key, file);
        }
        next.retain(|key, _| !self.state.is_dead(*key));
        if self.dirty && !self.commit(&mut report) {
            return report;
        }
        self.loaded = next;
        self.disabled = false;
        report
    }

    /// Reads and parses the `revoked` list: `None` when it exists and does
    /// not validate.
    fn read_revoked(&self) -> Option<Vec<KeyRef>> {
        let mut buf = Erased::new(MAX_FILE_LEN + 1);
        let len = match self.keys.read(REVOKED, &mut buf) {
            Ok(len) => len,
            Err(FileError::NotFound) => return Some(Vec::new()),
            Err(FileError::Refused) => return None,
        };
        parse_revoked(buf.get(..len)?)
    }

    fn read_key(&self, name: &str, buf: &mut [u8]) -> Result<(KeyFile, Fingerprints), Reason> {
        let len = self.keys.read(name, buf).map_err(|_| Reason::Refused)?;
        let bytes = buf.get(..len).unwrap_or_default();
        let file = parse(name, bytes).map_err(Reason::Malformed)?;
        let secret = match &file.material {
            Material::Secret(secret) => Some(fingerprint(
                &self.fingerprint_key,
                b"secret",
                secret.as_slice(),
            )),
            Material::Public(_) => None,
        };
        let prints = Fingerprints {
            file: fingerprint(&self.fingerprint_key, b"file", bytes),
            secret,
        };
        Ok((file, prints))
    }

    /// A changed file: absent for good, in memory first.
    fn disable(&mut self, key: KeyRef) {
        self.loaded.remove(&key);
        self.state.disabled.insert(key);
        self.dirty = true;
    }

    fn retire(&mut self, key: KeyRef) {
        self.loaded.remove(&key);
        self.state.retired.insert(key);
        self.dirty = true;
    }

    /// Records an admission and moves the lineage forward: the previous
    /// highest epoch becomes the predecessor, with its retirement deadline,
    /// and an older predecessor still verifying retires at once. A
    /// predecessor whose deadline has already passed retires at once too,
    /// in the same commit as the admission.
    fn admit(&mut self, key: KeyRef, file: &KeyFile, prints: Fingerprints, now: i64) {
        let (key_id, epoch) = key;
        self.state.admitted.insert(key, prints);
        self.dirty = true;
        let previous = self.state.lineages.get(&key_id).copied();
        let lineage = match previous {
            None => Lineage {
                highest: epoch,
                predecessor: None,
            },
            Some(previous) => {
                if let Some((old, _)) = previous.predecessor
                    && !self.state.retired.contains(&(key_id, old))
                {
                    self.retire((key_id, old));
                }
                let deadline = file
                    .not_before
                    .saturating_add(OVERLAP_S)
                    .saturating_sub(SKEW_S);
                if now >= deadline && !self.state.retired.contains(&(key_id, previous.highest)) {
                    self.retire((key_id, previous.highest));
                }
                Lineage {
                    highest: epoch,
                    predecessor: Some((previous.highest, deadline)),
                }
            }
        };
        self.state.lineages.insert(key_id, lineage);
    }
}

/// The successor's `not_before`, from its predecessor's retirement
/// deadline `not_before + OVERLAP_S - SKEW_S`.
fn successor_not_before(deadline: i64) -> i64 {
    deadline.saturating_add(SKEW_S).saturating_sub(OVERLAP_S)
}

/// Parses a `revoked` list (design section 2.4): one canonical
/// `<key_id>-<file_epoch>` per line, strictly increasing, LF-terminated.
/// `None` when malformed.
#[must_use]
pub fn parse_revoked(bytes: &[u8]) -> Option<Vec<KeyRef>> {
    if bytes.is_empty() {
        return Some(Vec::new());
    }
    let body = bytes.strip_suffix(b"\n")?;
    let mut keys: Vec<KeyRef> = Vec::new();
    for line in body.split(|b| *b == b'\n') {
        let text = core::str::from_utf8(line).ok()?;
        let key = parse_name(&format!("{text}.key")).ok()?;
        if keys.last().is_some_and(|last| *last >= key) {
            return None;
        }
        keys.push(key);
    }
    Some(keys)
}

#[cfg(test)]
mod tests;
