// SPDX-License-Identifier: Apache-2.0

//! The durable key state (`quantstratum-docs:
//! karyos/design/wire-key-files.md` section 2.6): tombstones, disable
//! markers, retirement marks, the per-`key_id` epoch lineage, and a keyed
//! fingerprint of every admitted key file and secret.
//!
//! The design fixes the header, the entry count and the trailing SHA-256;
//! the entry lines below follow the key file rules of section 2.2: one
//! canonical line each, printable ASCII, LF only, and a fixed order, so that
//! a decoded state re-encodes to the same bytes.
//!
//! ```text
//! karyos-wire-key-state-v1
//! entries=<n>
//! tombstone=<key_id>-<file_epoch>
//! disabled=<key_id>-<file_epoch>
//! retired=<key_id>-<file_epoch>
//! lineage=<key_id> highest=<epoch> predecessor=<epoch or 0> deadline=<s>
//! admitted=<key_id>-<file_epoch> file=<hex> secret=<hex or ->
//! checksum=<SHA-256 of every byte before this line, hex>
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{KEY_LEN, decimal_u64, hex32};

/// The first line of a state file.
pub const HEADER: &str = "karyos-wire-key-state-v1";
/// The most entries a state holds; a state that would hold more disables
/// every key (design section 2.6).
pub const MAX_ENTRIES: usize = 4096;
/// The longest entry line: an `admitted` line with both fingerprints and
/// the largest identifiers is 173 bytes.
const MAX_LINE: usize = 192;
/// The largest state file, in bytes: the header, the count, the entries
/// and the checksum.
pub const MAX_STATE_LEN: usize = MAX_ENTRIES * MAX_LINE + 256;
/// The domain of the keyed fingerprints.
const FINGERPRINT_DOMAIN: &[u8] = b"karyos-key-fp-v1";

/// One key file, `(key_id, file_epoch)`.
pub type KeyRef = (u32, u32);

/// The epochs of one `key_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lineage {
    /// The highest file epoch ever admitted.
    pub highest: u32,
    /// The epoch admitted before `highest`, and its retirement deadline in
    /// seconds since the Unix epoch.
    pub predecessor: Option<(u32, i64)>,
}

/// The keyed fingerprints of one admitted key file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fingerprints {
    /// Of the file's bytes.
    pub file: [u8; KEY_LEN],
    /// Of its secret; `None` for an `authority-public` file.
    pub secret: Option<[u8; KEY_LEN]>,
}

/// The durable key state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyState {
    /// Revoked keys; never removed.
    pub tombstones: BTreeSet<KeyRef>,
    /// Keys whose file changed after admission; never removed.
    pub disabled: BTreeSet<KeyRef>,
    /// Retired predecessors; never removed.
    pub retired: BTreeSet<KeyRef>,
    /// Per `key_id`.
    pub lineages: BTreeMap<u32, Lineage>,
    /// Per admitted key.
    pub admitted: BTreeMap<KeyRef, Fingerprints>,
}

/// Why a state file is refused. Carries no content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StateError {
    /// Larger than [`MAX_STATE_LEN`] or more than [`MAX_ENTRIES`] entries.
    #[error("key state too large")]
    TooLarge,
    /// The checksum line is missing or does not match.
    #[error("key state checksum mismatch")]
    Checksum,
    /// Anything else: not canonical.
    #[error("malformed key state on line {line}")]
    Malformed {
        /// The 1-based line.
        line: usize,
    },
}

/// The fingerprint key: 32 bytes from a CSPRNG, in its own file.
pub type FingerprintKey = Zeroizing<[u8; KEY_LEN]>;

/// The SHA-256 block length, which HMAC pads its key to.
const BLOCK_LEN: usize = 64;

/// `HMAC-SHA-256(key, "karyos-key-fp-v1" || kind || bytes)`.
///
/// Written out (RFC 2104) rather than through `hmac`, whose key setup
/// keeps a padded copy of the key in a block it does not erase. Here the
/// padded key lives in one [`Zeroizing`] block, and both hash states are
/// erased on drop by `sha2`'s `zeroize` feature; `zeroize` stays without
/// `alloc`.
#[must_use]
pub fn fingerprint(key: &FingerprintKey, kind: &[u8], bytes: &[u8]) -> [u8; KEY_LEN] {
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5c;
    let mut pad = Zeroizing::new([IPAD; BLOCK_LEN]);
    for (byte, key_byte) in pad.iter_mut().zip(key.iter()) {
        *byte ^= key_byte;
    }
    let mut inner = Sha256::new();
    inner.update(pad.as_slice());
    inner.update(FINGERPRINT_DOMAIN);
    inner.update(kind);
    inner.update(bytes);
    let inner = inner.finalize();
    for byte in pad.iter_mut() {
        *byte ^= IPAD ^ OPAD;
    }
    let mut outer = Sha256::new();
    outer.update(pad.as_slice());
    outer.update(inner);
    let mut out = [0_u8; KEY_LEN];
    out.copy_from_slice(&outer.finalize());
    out
}

/// The length of a fingerprint key file.
pub const FINGERPRINT_KEY_LEN: usize = 2 * KEY_LEN + 1;

/// Encodes a fingerprint key file: 64 lowercase hex digits and a LF.
#[must_use]
pub fn encode_fingerprint_key(key: &FingerprintKey) -> Zeroizing<[u8; FINGERPRINT_KEY_LEN]> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = Zeroizing::new([b'\n'; FINGERPRINT_KEY_LEN]);
    for ([high, low], byte) in text.as_chunks_mut::<2>().0.iter_mut().zip(key.iter()) {
        *high = HEX.get(usize::from(byte >> 4)).copied().unwrap_or_default();
        *low = HEX
            .get(usize::from(byte & 0xf))
            .copied()
            .unwrap_or_default();
    }
    text
}

/// Decodes a fingerprint key file.
///
/// # Errors
///
/// [`StateError::Malformed`] unless it is 64 lowercase hex digits and a LF.
pub fn decode_fingerprint_key(bytes: &[u8]) -> Result<FingerprintKey, StateError> {
    let mut key = Zeroizing::new([0_u8; KEY_LEN]);
    bytes
        .strip_suffix(b"\n")
        .and_then(|hex| hex32(hex, &mut key))
        .ok_or(StateError::Malformed { line: 1 })?;
    Ok(key)
}

fn hex_into(out: &mut String, bytes: &[u8]) {
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
}

impl KeyState {
    /// The number of entries: every mark, lineage and admission.
    #[must_use]
    pub fn entries(&self) -> usize {
        self.tombstones.len()
            + self.disabled.len()
            + self.retired.len()
            + self.lineages.len()
            + self.admitted.len()
    }

    /// Whether a key is tombstoned, disabled or retired: it never loads
    /// again.
    #[must_use]
    pub fn is_dead(&self, key: KeyRef) -> bool {
        self.tombstones.contains(&key)
            || self.disabled.contains(&key)
            || self.retired.contains(&key)
    }

    /// The canonical bytes, checksum included.
    ///
    /// # Errors
    ///
    /// [`StateError::TooLarge`] beyond [`MAX_ENTRIES`].
    pub fn encode(&self) -> Result<String, StateError> {
        if self.entries() > MAX_ENTRIES {
            return Err(StateError::TooLarge);
        }
        let mut text = String::with_capacity(64 + self.entries() * 96);
        let _ = writeln!(text, "{HEADER}\nentries={}", self.entries());
        for (set, name) in [
            (&self.tombstones, "tombstone"),
            (&self.disabled, "disabled"),
            (&self.retired, "retired"),
        ] {
            for (key_id, epoch) in set {
                let _ = writeln!(text, "{name}={key_id}-{epoch}");
            }
        }
        for (key_id, lineage) in &self.lineages {
            let (predecessor, deadline) = lineage.predecessor.unwrap_or((0, 0));
            let _ = writeln!(
                text,
                "lineage={key_id} highest={} predecessor={predecessor} deadline={deadline}",
                lineage.highest
            );
        }
        for ((key_id, epoch), prints) in &self.admitted {
            let _ = write!(text, "admitted={key_id}-{epoch} file=");
            hex_into(&mut text, &prints.file);
            text.push_str(" secret=");
            match &prints.secret {
                Some(secret) => hex_into(&mut text, secret),
                None => text.push('-'),
            }
            text.push('\n');
        }
        let digest = Sha256::digest(text.as_bytes());
        text.push_str("checksum=");
        hex_into(&mut text, &digest);
        text.push('\n');
        Ok(text)
    }

    /// Decodes a state file. It must be canonical: it re-encodes to the
    /// same bytes.
    ///
    /// # Errors
    ///
    /// The first [`StateError`] that applies.
    pub fn decode(bytes: &[u8]) -> Result<Self, StateError> {
        if bytes.len() > MAX_STATE_LEN {
            return Err(StateError::TooLarge);
        }
        let body_end = bytes
            .strip_suffix(b"\n")
            .and_then(|b| b.iter().rposition(|c| *c == b'\n'))
            .map(|at| at + 1)
            .ok_or(StateError::Checksum)?;
        let (body, tail) = bytes.split_at(body_end);
        let mut expected = [0_u8; KEY_LEN];
        tail.strip_prefix(b"checksum=")
            .and_then(|t| t.strip_suffix(b"\n"))
            .and_then(|hex| hex32(hex, &mut expected))
            .ok_or(StateError::Checksum)?;
        if Sha256::digest(body).as_slice() != expected {
            return Err(StateError::Checksum);
        }
        let text = core::str::from_utf8(body).map_err(|_| StateError::Malformed { line: 1 })?;
        let mut lines = text.lines();
        if lines.next() != Some(HEADER) {
            return Err(StateError::Malformed { line: 1 });
        }
        let count = lines
            .next()
            .and_then(|l| l.strip_prefix("entries="))
            .and_then(|n| decimal_u64(n.as_bytes()))
            .and_then(|n| usize::try_from(n).ok())
            .ok_or(StateError::Malformed { line: 2 })?;
        if count > MAX_ENTRIES {
            return Err(StateError::TooLarge);
        }
        let mut state = Self::default();
        for (index, line) in lines.enumerate() {
            let number = index + 3;
            let bad = StateError::Malformed { line: number };
            state.decode_line(line).ok_or(bad)?;
        }
        // Order, duplicates, count and number forms: canonical or refused.
        if state.encode().ok().as_deref().map(str::as_bytes) != Some(bytes) {
            return Err(StateError::Malformed { line: 2 });
        }
        Ok(state)
    }

    fn decode_line(&mut self, line: &str) -> Option<()> {
        let (name, value) = line.split_once('=')?;
        match name {
            "tombstone" => insert_new(&mut self.tombstones, key_ref(value)?),
            "disabled" => insert_new(&mut self.disabled, key_ref(value)?),
            "retired" => insert_new(&mut self.retired, key_ref(value)?),
            "lineage" => {
                let mut parts = value.split(' ');
                let key_id = positive_u32(parts.next()?)?;
                let highest = positive_u32(parts.next()?.strip_prefix("highest=")?)?;
                let predecessor = u32::try_from(decimal_u64(
                    parts.next()?.strip_prefix("predecessor=")?.as_bytes(),
                )?)
                .ok()?;
                let deadline = decimal_i64(parts.next()?.strip_prefix("deadline=")?)?;
                if parts.next().is_some() || predecessor >= highest {
                    return None;
                }
                let predecessor = match (predecessor, deadline) {
                    (0, 0) => None,
                    (0, _) => return None,
                    (epoch, deadline) => Some((epoch, deadline)),
                };
                self.lineages
                    .insert(
                        key_id,
                        Lineage {
                            highest,
                            predecessor,
                        },
                    )
                    .is_none()
                    .then_some(())
            }
            "admitted" => {
                let mut parts = value.split(' ');
                let key = key_ref(parts.next()?)?;
                let mut file = [0_u8; KEY_LEN];
                hex32(parts.next()?.strip_prefix("file=")?.as_bytes(), &mut file)?;
                let secret = match parts.next()?.strip_prefix("secret=")? {
                    "-" => None,
                    hex => {
                        let mut secret = [0_u8; KEY_LEN];
                        hex32(hex.as_bytes(), &mut secret)?;
                        Some(secret)
                    }
                };
                if parts.next().is_some() {
                    return None;
                }
                self.admitted
                    .insert(key, Fingerprints { file, secret })
                    .is_none()
                    .then_some(())
            }
            _ => None,
        }
    }
}

fn insert_new(set: &mut BTreeSet<KeyRef>, key: KeyRef) -> Option<()> {
    set.insert(key).then_some(())
}

fn positive_u32(text: &str) -> Option<u32> {
    u32::try_from(decimal_u64(text.as_bytes())?)
        .ok()
        .filter(|v| *v >= 1)
}

fn key_ref(text: &str) -> Option<KeyRef> {
    let (key_id, epoch) = text.split_once('-')?;
    Some((positive_u32(key_id)?, positive_u32(epoch)?))
}

fn decimal_i64(text: &str) -> Option<i64> {
    match text.strip_prefix('-') {
        Some(rest) => {
            let magnitude = decimal_u64(rest.as_bytes()).filter(|m| *m != 0)?;
            0_i64.checked_sub_unsigned(magnitude)
        }
        None => i64::try_from(decimal_u64(text.as_bytes())?).ok(),
    }
}

#[cfg(test)]
mod tests;
