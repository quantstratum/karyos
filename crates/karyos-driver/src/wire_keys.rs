// SPDX-License-Identifier: Apache-2.0

//! Wire authentication key files and KDF contexts
//! (`quantstratum-docs: karyos/design/wire-key-files.md` sections 2.1 to 2.6
//! and 3; ADR-0086 sections 4 and 8).
//!
//! This module parses one key file's bytes into a [`KeyFile`] and derives
//! the per-purpose MAC keys with HKDF-SHA-256 (RFC 5869), written over
//! [`HmacKey`] so that the PRK, every padded key and every MAC output are
//! erased. [`store`] loads
//! and reloads the key directory against the durable key state of
//! [`state`] (design sections 2.1, 2.4 and 2.6).
//! Parsing allocates nothing, reads no clock and touches no file. Secrets
//! live in [`zeroize::Zeroizing`] buffers and are erased on drop, and the
//! caller's input buffer is never kept.

pub mod state;
pub mod store;

use karyos_protocol::network::Identity;
use karyos_protocol::protection::hmac_sha256::LABEL;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::authority::{AuthorityKeyError, Ed25519Verifier};

/// The largest key file, in bytes.
pub const MAX_FILE_LEN: usize = 4096;
/// Bytes of a secret, an Ed25519 seed or public key, and a derived key.
pub const KEY_LEN: usize = 32;
/// The largest validity of a `channel` or `pairwise` key: 90 days.
pub const MAX_SYMMETRIC_VALIDITY_S: i64 = 7_776_000;
/// The largest validity of an authority key: 180 days.
pub const MAX_AUTHORITY_VALIDITY_S: i64 = 15_552_000;
/// The largest number of guards an authority key names.
pub const MAX_GUARDS: usize = 16;

/// What a key is for (design section 2.2, `purpose`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// DATA and the SETUP proof of one channel.
    Channel,
    /// Receiver to publisher controls and RSP_SETUP of one pair.
    Pairwise,
    /// The authority's own Ed25519 signing seed.
    AuthoritySigning,
    /// An authority's Ed25519 public key, on receivers.
    AuthorityPublic,
}

/// The fields that name a key's peers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// A channel key.
    Channel {
        /// The channel's operator-assigned identity.
        channel_id: u64,
        /// Its stream.
        stream_id: i32,
    },
    /// A pairwise key.
    Pairwise {
        /// The receiver of the pair.
        receiver_id: u64,
        /// The publishing driver of the pair.
        publisher_id: u64,
    },
    /// An authority key.
    Authority {
        /// The authority.
        authority_id: u64,
        /// The guards it serves, strictly increasing.
        guards: [u64; MAX_GUARDS],
        /// How many entries of `guards` are used, 1 to [`MAX_GUARDS`].
        guard_count: usize,
        /// Whether it may sign SESSION_ABORT.
        abort: bool,
    },
}

/// The key material of a file.
pub enum Material {
    /// A 32-byte secret: a symmetric `IKM` or an Ed25519 seed. Erased on
    /// drop.
    Secret(Zeroizing<[u8; KEY_LEN]>),
    /// A checked Ed25519 public key.
    Public(Ed25519Verifier),
}

impl core::fmt::Debug for Material {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Secret(_) => f.write_str("Secret(..)"),
            Self::Public(_) => f.write_str("Public(..)"),
        }
    }
}

/// One parsed, validated key file.
#[derive(Debug)]
pub struct KeyFile {
    /// The key identifier.
    pub key_id: u32,
    /// The file epoch.
    pub file_epoch: u32,
    /// The purpose.
    pub purpose: Purpose,
    /// 1 (`authenticated`) or 16 (`encrypted`) for the symmetric purposes,
    /// 4 for the authority purposes.
    pub profile_id: u8,
    /// Start of validity, seconds since the Unix epoch, UTC.
    pub not_before: i64,
    /// End of validity, seconds since the Unix epoch, UTC.
    pub not_after: i64,
    /// The key material.
    pub material: Material,
    /// The peers it names.
    pub scope: Scope,
}

/// Why a key file is refused. Carries no secret and no file content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum KeyFileError {
    /// The file name is not `<key_id>-<file_epoch>.key` in canonical
    /// decimal.
    #[error("bad key file name")]
    Name,
    /// Larger than [`MAX_FILE_LEN`].
    #[error("key file too large")]
    TooLarge,
    /// A byte outside printable ASCII and LF, a CR, a missing final LF, an
    /// empty line, or a space.
    #[error("bad key file encoding")]
    Encoding,
    /// A line without `=`, or a name out of the canonical order, unknown,
    /// repeated, missing, or not allowed for the purpose.
    #[error("bad key file field {line}")]
    Field {
        /// The 1-based line.
        line: usize,
    },
    /// A value that does not parse or is out of range.
    #[error("bad key file value on line {line}")]
    Value {
        /// The 1-based line.
        line: usize,
    },
    /// `key_id` or `file_epoch` differs from the file name.
    #[error("key file name and contents differ")]
    NameMismatch,
    /// `profile_id` does not match the purpose.
    #[error("profile does not match the purpose")]
    ProfileMismatch,
    /// `not_before` is not before `not_after`, or the validity exceeds its
    /// bound.
    #[error("bad key validity")]
    Validity,
    /// The authority public key is refused.
    #[error("refused authority public key")]
    PublicKey(AuthorityKeyError),
}

/// The protection class a `channel` or `pairwise` file serves, by its
/// `profile_id` (design section 2.2, "One class per file"; ADR-0114
/// section 4a).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// `profile_id=1`: `authenticated` channels only (ADR-0086).
    Authenticated,
    /// `profile_id=16`: `encrypted` channels only (ADR-0114).
    Encrypted,
}

impl Class {
    /// The `profile_id` of the class.
    #[must_use]
    pub const fn profile_id(self) -> u8 {
        match self {
            Self::Authenticated => 1,
            Self::Encrypted => 16,
        }
    }
}

impl KeyFile {
    /// The class a symmetric file serves; `None` for the authority
    /// purposes, which serve no channel class.
    #[must_use]
    pub fn class(&self) -> Option<Class> {
        match (self.purpose, self.profile_id) {
            (Purpose::Channel | Purpose::Pairwise, 1) => Some(Class::Authenticated),
            (Purpose::Channel | Purpose::Pairwise, 16) => Some(Class::Encrypted),
            _ => None,
        }
    }

    /// Checks that a channel configuration of `class` may name this file
    /// as its `purpose` key.
    ///
    /// # Errors
    ///
    /// [`KeyFileError::ProfileMismatch`] for a file of the other class or
    /// another purpose: a wrong-class configuration is refused, never
    /// served.
    pub fn serves(&self, class: Class, purpose: Purpose) -> Result<(), KeyFileError> {
        if self.purpose == purpose && self.class() == Some(class) {
            Ok(())
        } else {
            Err(KeyFileError::ProfileMismatch)
        }
    }
}

/// Parses a key file name, `<key_id>-<file_epoch>.key`.
///
/// # Errors
///
/// [`KeyFileError::Name`] for anything else.
pub fn parse_name(name: &str) -> Result<(u32, u32), KeyFileError> {
    let stem = name.strip_suffix(".key").ok_or(KeyFileError::Name)?;
    let (key_id, epoch) = stem.split_once('-').ok_or(KeyFileError::Name)?;
    let key_id = decimal_u64(key_id.as_bytes())
        .and_then(|v| u32::try_from(v).ok())
        .filter(|v| *v >= 1)
        .ok_or(KeyFileError::Name)?;
    let epoch = decimal_u64(epoch.as_bytes())
        .and_then(|v| u32::try_from(v).ok())
        .filter(|v| *v >= 1)
        .ok_or(KeyFileError::Name)?;
    Ok((key_id, epoch))
}

/// The canonical field order; each purpose keeps the rows it lists.
const ORDER: [&str; 16] = [
    "format",
    "key_id",
    "file_epoch",
    "purpose",
    "profile_id",
    "not_before",
    "not_after",
    "secret",
    "public",
    "channel_id",
    "stream_id",
    "receiver_id",
    "publisher_id",
    "authority_id",
    "guards",
    "abort",
];

/// The fields a purpose uses, as indices into [`ORDER`].
fn fields_of(purpose: Purpose) -> &'static [usize] {
    match purpose {
        Purpose::Channel => &[0, 1, 2, 3, 4, 5, 6, 7, 9, 10],
        Purpose::Pairwise => &[0, 1, 2, 3, 4, 5, 6, 7, 11, 12],
        Purpose::AuthoritySigning => &[0, 1, 2, 3, 4, 5, 6, 7, 13, 14, 15],
        Purpose::AuthorityPublic => &[0, 1, 2, 3, 4, 5, 6, 8, 13, 14, 15],
    }
}

/// Parses and validates one key file named `name`. Allocates nothing; the
/// caller erases `bytes` afterwards.
///
/// # Errors
///
/// The first [`KeyFileError`] that applies.
pub fn parse(name: &str, bytes: &[u8]) -> Result<KeyFile, KeyFileError> {
    let (name_key, name_epoch) = parse_name(name)?;
    if bytes.len() > MAX_FILE_LEN {
        return Err(KeyFileError::TooLarge);
    }
    if bytes.last() != Some(&b'\n')
        || bytes
            .iter()
            .any(|b| !(*b == b'\n' || (0x21..=0x7e).contains(b)))
    {
        return Err(KeyFileError::Encoding);
    }
    let body = bytes
        .get(..bytes.len().saturating_sub(1))
        .unwrap_or_default();
    let mut lines = body.split(|b| *b == b'\n');
    let mut values: [&[u8]; 16] = [&[]; 16];
    // The first four lines are fixed for every purpose.
    for (index, slot) in values.iter_mut().enumerate().take(4) {
        *slot = field(lines.next(), index, index + 1)?;
    }
    if values[0] != b"karyos-wire-key-v1" {
        return Err(KeyFileError::Value { line: 1 });
    }
    let purpose = match values[3] {
        b"channel" => Purpose::Channel,
        b"pairwise" => Purpose::Pairwise,
        b"authority-signing" => Purpose::AuthoritySigning,
        b"authority-public" => Purpose::AuthorityPublic,
        _ => return Err(KeyFileError::Value { line: 4 }),
    };
    let wanted = fields_of(purpose);
    for (position, index) in wanted.iter().enumerate().skip(4) {
        if let Some(slot) = values.get_mut(*index) {
            *slot = field(lines.next(), *index, position + 1)?;
        }
    }
    if lines.next().is_some() {
        return Err(KeyFileError::Field {
            line: wanted.len() + 1,
        });
    }
    let line_of = |index: usize| wanted.iter().position(|i| *i == index).map_or(0, |p| p + 1);
    let value = |index: usize| values.get(index).copied().unwrap_or_default();
    let number = |index: usize| {
        decimal_u64(value(index)).ok_or(KeyFileError::Value {
            line: line_of(index),
        })
    };
    let key_id = u32::try_from(number(1)?)
        .ok()
        .filter(|v| *v >= 1)
        .ok_or(KeyFileError::Value { line: 2 })?;
    let file_epoch = u32::try_from(number(2)?)
        .ok()
        .filter(|v| *v >= 1)
        .ok_or(KeyFileError::Value { line: 3 })?;
    let profile = number(4)?;
    // Compared before any narrowing, so `256` is a mismatch, not a range
    // error (design section 2.2). A symmetric file serves one class: 1
    // `authenticated` or 16 `encrypted` (ADR-0114 section 4a).
    let profile_id = match (purpose, profile) {
        (Purpose::Channel | Purpose::Pairwise, 1) => Class::Authenticated.profile_id(),
        (Purpose::Channel | Purpose::Pairwise, 16) => Class::Encrypted.profile_id(),
        (Purpose::AuthoritySigning | Purpose::AuthorityPublic, 4) => 4,
        _ => return Err(KeyFileError::ProfileMismatch),
    };
    let not_before = timestamp(value(5)).ok_or(KeyFileError::Value { line: 6 })?;
    let not_after = timestamp(value(6)).ok_or(KeyFileError::Value { line: 7 })?;
    let bound = match purpose {
        Purpose::Channel | Purpose::Pairwise => MAX_SYMMETRIC_VALIDITY_S,
        Purpose::AuthoritySigning | Purpose::AuthorityPublic => MAX_AUTHORITY_VALIDITY_S,
    };
    match not_after.checked_sub(not_before) {
        Some(span) if span > 0 && span <= bound => {}
        _ => return Err(KeyFileError::Validity),
    }
    let material = if purpose == Purpose::AuthorityPublic {
        let mut public = [0_u8; KEY_LEN];
        hex32(value(8), &mut public).ok_or(KeyFileError::Value { line: 8 })?;
        Material::Public(Ed25519Verifier::from_bytes(&public).map_err(KeyFileError::PublicKey)?)
    } else {
        let mut secret = Zeroizing::new([0_u8; KEY_LEN]);
        hex32(value(7), &mut secret).ok_or(KeyFileError::Value { line: 8 })?;
        Material::Secret(secret)
    };
    let id = |index: usize| {
        Some(number(index)?)
            .filter(|v| *v >= 1)
            .ok_or(KeyFileError::Value {
                line: line_of(index),
            })
    };
    let scope = match purpose {
        Purpose::Channel => Scope::Channel {
            channel_id: id(9)?,
            stream_id: decimal_i32(value(10)).ok_or(KeyFileError::Value { line: line_of(10) })?,
        },
        Purpose::Pairwise => Scope::Pairwise {
            receiver_id: id(11)?,
            publisher_id: id(12)?,
        },
        Purpose::AuthoritySigning | Purpose::AuthorityPublic => {
            let mut guards = [0_u64; MAX_GUARDS];
            let mut guard_count = 0_usize;
            for part in value(14).split(|b| *b == b',') {
                let guard = decimal_u64(part)
                    .filter(|v| *v >= 1)
                    .ok_or(KeyFileError::Value { line: line_of(14) })?;
                let previous = guard_count
                    .checked_sub(1)
                    .and_then(|i| guards.get(i).copied());
                if previous.is_some_and(|p| p >= guard) {
                    return Err(KeyFileError::Value { line: line_of(14) });
                }
                *guards
                    .get_mut(guard_count)
                    .ok_or(KeyFileError::Value { line: line_of(14) })? = guard;
                guard_count += 1;
            }
            let abort = match value(15) {
                b"true" => true,
                b"false" => false,
                _ => return Err(KeyFileError::Value { line: line_of(15) }),
            };
            Scope::Authority {
                authority_id: id(13)?,
                guards,
                guard_count,
                abort,
            }
        }
    };
    if key_id != name_key || file_epoch != name_epoch {
        return Err(KeyFileError::NameMismatch);
    }
    Ok(KeyFile {
        key_id,
        file_epoch,
        purpose,
        profile_id,
        not_before,
        not_after,
        material,
        scope,
    })
}

/// One `name=value` line whose name is `ORDER[index]`.
fn field(line: Option<&[u8]>, index: usize, number: usize) -> Result<&[u8], KeyFileError> {
    let line = line.ok_or(KeyFileError::Field { line: number })?;
    let name = ORDER
        .get(index)
        .ok_or(KeyFileError::Field { line: number })?;
    let rest = line
        .strip_prefix(name.as_bytes())
        .and_then(|rest| rest.strip_prefix(b"="))
        .ok_or(KeyFileError::Field { line: number })?;
    if rest.is_empty() {
        return Err(KeyFileError::Value { line: number });
    }
    Ok(rest)
}

/// Canonical decimal: no leading zero except `0`, no sign.
fn decimal_u64(text: &[u8]) -> Option<u64> {
    match text {
        [] => None,
        [b'0'] => Some(0),
        [b'0', ..] => None,
        _ => text.iter().try_fold(0_u64, |acc, b| {
            let digit = u64::from(b.checked_sub(b'0').filter(|d| *d <= 9)?);
            acc.checked_mul(10)?.checked_add(digit)
        }),
    }
}

/// Canonical decimal i32: `-` only before a non-zero value.
fn decimal_i32(text: &[u8]) -> Option<i32> {
    match text.strip_prefix(b"-") {
        Some(rest) => {
            let magnitude = i64::try_from(decimal_u64(rest)?).ok()?;
            if magnitude == 0 {
                return None;
            }
            i32::try_from(magnitude.checked_neg()?).ok()
        }
        None => i32::try_from(decimal_u64(text)?).ok(),
    }
}

/// 64 lowercase hex digits into `out`.
fn hex32(text: &[u8], out: &mut [u8; KEY_LEN]) -> Option<()> {
    if text.len() != 2 * KEY_LEN {
        return None;
    }
    for (slot, pair) in out.iter_mut().zip(text.as_chunks::<2>().0) {
        let nibble = |b: u8| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        };
        let [hi, lo] = *pair;
        let (hi, lo) = (nibble(hi)?, nibble(lo)?);
        *slot = (hi << 4) | lo;
    }
    Some(())
}

/// `YYYY-MM-DDTHH:MM:SSZ`, UTC, no leap second, as Unix seconds.
fn timestamp(text: &[u8]) -> Option<i64> {
    let [
        y0,
        y1,
        y2,
        y3,
        b'-',
        m0,
        m1,
        b'-',
        d0,
        d1,
        b'T',
        h0,
        h1,
        b':',
        i0,
        i1,
        b':',
        s0,
        s1,
        b'Z',
    ] = *text
    else {
        return None;
    };
    let digits = |parts: &[u8]| -> Option<i64> {
        parts.iter().try_fold(0_i64, |acc, b| {
            let digit = i64::from(b.checked_sub(b'0').filter(|d| *d <= 9)?);
            acc.checked_mul(10)?.checked_add(digit)
        })
    };
    let year = digits(&[y0, y1, y2, y3])?;
    let month = digits(&[m0, m1])?;
    let day = digits(&[d0, d1])?;
    let hour = digits(&[h0, h1])?;
    let minute = digits(&[i0, i1])?;
    let second = digits(&[s0, s1])?;
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if !(1..=days_in_month).contains(&day) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    // Days from civil (Howard Hinnant's algorithm), proleptic Gregorian.
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    days.checked_mul(86_400)?
        .checked_add(hour * 3600 + minute * 60 + second)
}

/// The inputs of one derived MAC key (design section 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Context {
    /// Sender keys, domain 1 (`data`).
    Data {
        /// The file epoch.
        file_epoch: u32,
        /// The sender's in-band key epoch.
        party_epoch: u8,
        /// The full publication identity.
        identity: Identity,
        /// Lanes 0 to `lane_count - 1`.
        lane_count: u8,
        /// The key file.
        key_id: u32,
        /// The profile.
        profile_id: u8,
        /// Unicast: `receiver_boot_id` and `nonce` of the completed
        /// establishment. Multicast: `None`.
        unicast: Option<([u64; 2], [u64; 2])>,
    },
    /// Receiver keys, domain 4 (`rcv`).
    Receiver {
        /// The file epoch.
        file_epoch: u32,
        /// The receiver's in-band key epoch.
        party_epoch: u8,
        /// The receiver's boot id.
        receiver_boot_id: [u64; 2],
        /// The receiver.
        receiver_id: u64,
        /// The full publication identity.
        identity: Identity,
        /// The key file.
        key_id: u32,
        /// The profile.
        profile_id: u8,
    },
    /// The SETUP proof key, domain 5 (`setup`).
    Setup {
        /// The file epoch.
        file_epoch: u32,
        /// The key file.
        key_id: u32,
        /// The profile.
        profile_id: u8,
    },
    /// The RSP_SETUP key, domain 6 (`rsp`).
    RspSetup {
        /// The file epoch.
        file_epoch: u32,
        /// The receiver.
        receiver_id: u64,
        /// The key file.
        key_id: u32,
        /// The profile.
        profile_id: u8,
    },
}

/// The largest `info`: the `rcv` context, 89 bytes.
const MAX_INFO: usize = 96;

/// A context's `info` bytes and salt.
struct Info {
    buf: [u8; MAX_INFO],
    len: usize,
    salt: Option<[u8; 32]>,
}

impl Info {
    fn new(tag: &[u8]) -> Self {
        let mut info = Self {
            buf: [0; MAX_INFO],
            len: 0,
            salt: None,
        };
        info.put(LABEL);
        info.put(tag);
        info
    }

    fn put(&mut self, bytes: &[u8]) {
        let end = self.len.saturating_add(bytes.len());
        if let Some(slot) = self.buf.get_mut(self.len..end) {
            slot.copy_from_slice(bytes);
            self.len = end;
        }
    }

    fn id128(&mut self, [w0, w1]: [u64; 2]) {
        self.put(&w0.to_le_bytes());
        self.put(&w1.to_le_bytes());
    }

    fn identity(&mut self, identity: &Identity) {
        self.id128(identity.driver_id);
        self.put(&identity.registration_id.to_le_bytes());
        self.put(&identity.incarnation.to_le_bytes());
    }

    fn bytes(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or_default()
    }
}

impl Context {
    fn info(&self) -> Info {
        match self {
            Self::Data {
                file_epoch,
                party_epoch,
                identity,
                lane_count,
                key_id,
                profile_id,
                unicast,
            } => {
                let mut info = Info::new(b"data");
                info.put(&file_epoch.to_le_bytes());
                info.put(&[*party_epoch]);
                info.identity(identity);
                info.put(&[*lane_count]);
                info.put(&key_id.to_le_bytes());
                info.put(&[*profile_id]);
                if let Some((boot, nonce)) = unicast {
                    let mut salt = [0_u8; 32];
                    for (slot, word) in salt
                        .as_chunks_mut::<8>()
                        .0
                        .iter_mut()
                        .zip([boot[0], boot[1], nonce[0], nonce[1]])
                    {
                        *slot = word.to_le_bytes();
                    }
                    info.salt = Some(salt);
                }
                info
            }
            Self::Receiver {
                file_epoch,
                party_epoch,
                receiver_boot_id,
                receiver_id,
                identity,
                key_id,
                profile_id,
            } => {
                let mut info = Info::new(b"rcv");
                info.put(&file_epoch.to_le_bytes());
                info.put(&[*party_epoch]);
                info.id128(*receiver_boot_id);
                info.put(&receiver_id.to_le_bytes());
                info.identity(identity);
                info.put(&key_id.to_le_bytes());
                info.put(&[*profile_id]);
                info
            }
            Self::Setup {
                file_epoch,
                key_id,
                profile_id,
            } => {
                let mut info = Info::new(b"setup");
                info.put(&file_epoch.to_le_bytes());
                info.put(&key_id.to_le_bytes());
                info.put(&[*profile_id]);
                info
            }
            Self::RspSetup {
                file_epoch,
                receiver_id,
                key_id,
                profile_id,
            } => {
                let mut info = Info::new(b"rsp");
                info.put(&file_epoch.to_le_bytes());
                info.put(&receiver_id.to_le_bytes());
                info.put(&key_id.to_le_bytes());
                info.put(&[*profile_id]);
                info
            }
        }
    }

    /// The context's `info` bytes, for tests and diagnostics of the
    /// vectors.
    #[must_use]
    pub fn info_bytes(&self) -> ([u8; MAX_INFO], usize) {
        let info = self.info();
        (info.buf, info.len)
    }

    /// Derives the 32-byte MAC key from `secret` (the `IKM`). Allocates
    /// nothing; the result is erased on drop.
    #[must_use]
    pub fn derive(&self, secret: &[u8; KEY_LEN]) -> Zeroizing<[u8; KEY_LEN]> {
        // HKDF-SHA-256 (RFC 5869) for one 32-byte block, through the
        // workspace's one erasing HKDF over `HmacKey`
        // (`karyos_protocol::protection::hkdf`): every intermediate is
        // erased. A context without a salt uses 32 zero bytes, the RFC's
        // default for SHA-256.
        let info = self.info();
        karyos_protocol::protection::hkdf::hkdf_sha256::<KEY_LEN>(
            info.salt.as_ref().map(|salt| salt.as_slice()),
            secret,
            &[info.bytes()],
        )
    }
}

#[cfg(test)]
mod tests;
