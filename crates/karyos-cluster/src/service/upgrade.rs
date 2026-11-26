// SPDX-License-Identifier: Apache-2.0

//! Rolling upgrades (quantstratum-docs: karyos/adr/0122; design note
//! cluster-service-container.md §4.1, karyos#715): the active version is
//! log state, changed by schema 5's `Activation` (template 3) at a log
//! index ahead of its entry, with `CoordinatedStop` (template 4) as the
//! fallback.
//!
//! | Template | Id | Block | Then | Maximum |
//! | --- | --- | --- | --- | --- |
//! | `Activation` | 3 | service version 4, schema version 2, activation offset 8 | configuration, 0 to 4096 bytes | 4124 |
//! | `CoordinatedStop` | 4 | stop offset 8, resume version 4 | | 24 |
//!
//! Both are written and read at schema 5 version 2 only: no build wrote
//! them at version 1.

use karyos_codec::{CodecError, Decoder, ENVELOPE_LENGTH, Encoder, Template, VAR_HEADER_LENGTH};

use super::{CORE_SCHEMA_ID, CORE_VERSION, MAX_CONFIGURATION};

/// `Activation`, template 3 of schema 5: a 14-byte block, then the
/// configuration.
pub const ACTIVATION: Template = Template {
    schema_id: CORE_SCHEMA_ID,
    template_id: 3,
    version: CORE_VERSION,
    block_length: 14,
    max_length: (ENVELOPE_LENGTH + 14 + VAR_HEADER_LENGTH + MAX_CONFIGURATION) as u32,
};

/// `CoordinatedStop`, template 4 of schema 5: a 12-byte block.
pub const COORDINATED_STOP: Template = Template {
    schema_id: CORE_SCHEMA_ID,
    template_id: 4,
    version: CORE_VERSION,
    block_length: 12,
    max_length: ENVELOPE_LENGTH as u32 + 12,
};

/// The version a log runs under: the service version and the highest
/// schema 2 version of the commands it admits. A log before any
/// `Activation` runs [`ActiveVersion::INITIAL`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub struct ActiveVersion {
    /// The service version.
    pub service: u32,
    /// The highest schema 2 version admitted.
    pub schema: u16,
}

impl ActiveVersion {
    /// Service version 1, schema version 1: a log's state before any
    /// `Activation` (ADR-0122 decision 2).
    pub const INITIAL: Self = Self {
        service: 1,
        schema: 1,
    };

    /// Service `service`, schema `schema`.
    #[must_use]
    pub const fn new(service: u32, schema: u16) -> Self {
        Self { service, schema }
    }
}

impl Default for ActiveVersion {
    fn default() -> Self {
        Self::INITIAL
    }
}

fn nonzero_field<T: PartialEq + Default>(field: &'static str, value: T) -> Result<T, CodecError> {
    if value == T::default() {
        Err(CodecError::ValueOutOfRange { field })
    } else {
        Ok(value)
    }
}

/// An `Activation` entry: a change to `version`, and to the service's
/// configuration when `configuration` is not empty, at the entry's own
/// index plus `offset`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Activation<'a> {
    /// The version it activates.
    pub version: ActiveVersion,
    /// The distance from the entry's index to the activation index,
    /// nonzero.
    pub offset: u64,
    /// The configuration delivered at activation; empty for none.
    pub configuration: &'a [u8],
}

impl<'a> Activation<'a> {
    /// A change to `version` at `offset` entries past its own, with
    /// `configuration`.
    #[must_use]
    pub const fn new(version: ActiveVersion, offset: u64, configuration: &'a [u8]) -> Self {
        Self {
            version,
            offset,
            configuration,
        }
    }

    /// Encodes into `out`; returns the message's length.
    ///
    /// # Errors
    ///
    /// [`CodecError::ValueOutOfRange`] for a field of 0,
    /// [`CodecError::LengthOutOfRange`] for a configuration past 4096
    /// bytes, [`CodecError::Truncated`] for a short `out`.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut encoder = Encoder::new(out, &ACTIVATION)?;
        encoder.u32(0, nonzero_field("service_version", self.version.service)?)?;
        encoder.u16(4, nonzero_field("schema_version", self.version.schema)?)?;
        encoder.u64(6, nonzero_field("activation_offset", self.offset)?)?;
        encoder.bytes("configuration", 0, MAX_CONFIGURATION, self.configuration)?;
        encoder.finish()
    }

    /// The message's bytes.
    ///
    /// # Errors
    ///
    /// As [`Activation::encode`], but never `Truncated`.
    pub fn to_vec(&self) -> Result<Vec<u8>, CodecError> {
        let mut out = vec![0; ACTIVATION.max_length as usize];
        let length = self.encode(&mut out)?;
        out.truncate(length);
        Ok(out)
    }

    /// Decodes exactly one `Activation` message from `bytes`.
    ///
    /// # Errors
    ///
    /// [`CodecError::UnsupportedSchema`] for any tuple but schema 5,
    /// template 3, version 2 with a 14-byte block,
    /// [`CodecError::ValueOutOfRange`] naming a field of 0,
    /// [`CodecError::LengthOutOfRange`] for a configuration past 4096
    /// bytes, and every other [`CodecError`] the envelope can raise.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, CodecError> {
        // The message's length is bounded by the configuration's: a
        // configuration past 4096 bytes is `LengthOutOfRange` (vector A-7),
        // not a message past the template's maximum.
        let template = Template {
            max_length: u32::MAX,
            ..ACTIVATION
        };
        let (block, mut decoder) = Decoder::new(bytes, &template)?;
        let service = nonzero_field("service_version", block.u32(0)?)?;
        let schema = nonzero_field("schema_version", block.u16(4)?)?;
        let offset = nonzero_field("activation_offset", block.u64(6)?)?;
        let configuration = decoder.bytes("configuration", 0, MAX_CONFIGURATION)?;
        decoder.finish()?;
        Ok(Self {
            version: ActiveVersion::new(service, schema),
            offset,
            configuration,
        })
    }
}

/// A `CoordinatedStop` entry: every replica stops after the entry at its
/// own index plus `offset`, until a binary supporting `resume_version`
/// resumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct CoordinatedStop {
    /// The distance from the entry's index to the stop index; 0 stops at
    /// the entry itself.
    pub offset: u64,
    /// The service version the cluster resumes at, nonzero.
    pub resume_version: u32,
}

impl CoordinatedStop {
    /// A stop `offset` entries past its own, resuming at `resume_version`.
    #[must_use]
    pub const fn new(offset: u64, resume_version: u32) -> Self {
        Self {
            offset,
            resume_version,
        }
    }

    /// Encodes into `out`; returns the message's length.
    ///
    /// # Errors
    ///
    /// [`CodecError::ValueOutOfRange`] for a `resume_version` of 0,
    /// [`CodecError::Truncated`] for a short `out`.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CodecError> {
        let mut encoder = Encoder::new(out, &COORDINATED_STOP)?;
        encoder.u64(0, self.offset)?;
        encoder.u32(8, nonzero_field("resume_version", self.resume_version)?)?;
        encoder.finish()
    }

    /// The message's bytes.
    ///
    /// # Errors
    ///
    /// As [`CoordinatedStop::encode`], but never `Truncated`.
    pub fn to_vec(&self) -> Result<Vec<u8>, CodecError> {
        let mut out = vec![0; COORDINATED_STOP.max_length as usize];
        let length = self.encode(&mut out)?;
        out.truncate(length);
        Ok(out)
    }

    /// Decodes exactly one `CoordinatedStop` message from `bytes`.
    ///
    /// # Errors
    ///
    /// [`CodecError::UnsupportedSchema`] for any tuple but schema 5,
    /// template 4, version 2 with a 12-byte block,
    /// [`CodecError::ValueOutOfRange`] for a `resume_version` of 0, and
    /// every other [`CodecError`] the envelope can raise.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let (block, decoder) = Decoder::new(bytes, &COORDINATED_STOP)?;
        let offset = block.u64(0)?;
        let resume_version = nonzero_field("resume_version", block.u32(8)?)?;
        decoder.finish()?;
        Ok(Self {
            offset,
            resume_version,
        })
    }
}

/// Whether `bytes` carry template `template` of schema 5, by the envelope.
pub(super) fn is_core_template(bytes: &[u8], template: u16) -> bool {
    karyos_codec::Envelope::read(bytes).is_ok_and(|envelope| {
        envelope.schema_id == CORE_SCHEMA_ID && envelope.template_id == template
    })
}

/// Why the container applied a core entry or a command as nothing: the
/// same on every replica (ADR-0122 decisions 2, 3 and 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CoreRefusal {
    /// A command the active version cannot run. It carries only the
    /// active version, which the log fixes: the version the command needs
    /// is the binary's own reading (an older binary does not know a
    /// command type a newer one adds), so it would differ between
    /// replicas while versions are mixed.
    #[error("the active version {active:?} cannot run the command")]
    VersionInactive {
        /// The active version.
        active: ActiveVersion,
    },
    /// A version below the active one.
    #[error("the version falls below the active one")]
    Falls,
    /// Equal versions and no configuration.
    #[error("the entry changes nothing")]
    NoChange,
    /// Another `Activation` is pending, or another stop is logged.
    #[error("another change is pending")]
    Pending,
    /// The activation or stop index is past `u64::MAX`.
    #[error("the index overflows")]
    Overflow,
    /// A schema 2 entry past a coordinated stop, before the resuming
    /// `Activation` applies.
    #[error("the entry is past a coordinated stop")]
    PastStop,
}

/// A pending `Activation`: the version, the configuration and the index
/// it activates at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Pending {
    pub(super) version: ActiveVersion,
    pub(super) at: u64,
    pub(super) configuration: Vec<u8>,
}

/// A logged `CoordinatedStop`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Stop {
    pub(super) at: u64,
    pub(super) resume: u32,
}

/// The container's version state: log state, in the sessions section of
/// version 2.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Versions {
    pub(super) active: ActiveVersion,
    /// An `Activation` with a configuration has activated.
    pub(super) configured: bool,
    pub(super) pending: Option<Pending>,
    pub(super) stop: Option<Stop>,
}

const CONFIGURED: u8 = 1;
const PENDING: u8 = 2;
const STOPPED: u8 = 4;

impl Versions {
    /// Applies an `Activation` at `index`: pending, or why not.
    pub(super) fn activation(
        &mut self,
        index: u64,
        activation: &Activation<'_>,
    ) -> Result<(), CoreRefusal> {
        if self.pending.is_some() {
            return Err(CoreRefusal::Pending);
        }
        let at = index
            .checked_add(activation.offset)
            .ok_or(CoreRefusal::Overflow)?;
        let version = activation.version;
        if version.service < self.active.service || version.schema < self.active.schema {
            return Err(CoreRefusal::Falls);
        }
        if version == self.active && activation.configuration.is_empty() {
            return Err(CoreRefusal::NoChange);
        }
        self.pending = Some(Pending {
            version,
            at,
            configuration: activation.configuration.to_vec(),
        });
        // The resuming `Activation` (ADR-0122 decision 6): schema 2
        // entries apply again once it has applied.
        if self.stop.is_some_and(|stop| version.service >= stop.resume) {
            self.stop = None;
        }
        Ok(())
    }

    /// Applies a `CoordinatedStop` at `index`: logged, or why not.
    pub(super) fn stop(&mut self, index: u64, stop: CoordinatedStop) -> Result<(), CoreRefusal> {
        if self.stop.is_some() {
            return Err(CoreRefusal::Pending);
        }
        let at = index
            .checked_add(stop.offset)
            .ok_or(CoreRefusal::Overflow)?;
        match stop.resume_version.cmp(&self.active.service) {
            core::cmp::Ordering::Less => Err(CoreRefusal::Falls),
            core::cmp::Ordering::Equal => Err(CoreRefusal::NoChange),
            core::cmp::Ordering::Greater => {
                self.stop = Some(Stop {
                    at,
                    resume: stop.resume_version,
                });
                Ok(())
            }
        }
    }

    /// The version state's bytes, ahead of the session table's in the
    /// sessions section of version 2: active service u32, schema u16,
    /// flags u8; then, when pending, its service u32, schema u16, index
    /// u64, configuration length u16 and bytes; then, when stopped, its
    /// index u64 and resume version u32. Little endian.
    pub(super) fn encode(&self, out: &mut Vec<u8>) {
        let mut flags = 0;
        if self.configured {
            flags |= CONFIGURED;
        }
        if self.pending.is_some() {
            flags |= PENDING;
        }
        if self.stop.is_some() {
            flags |= STOPPED;
        }
        out.extend_from_slice(&self.active.service.to_le_bytes());
        out.extend_from_slice(&self.active.schema.to_le_bytes());
        out.push(flags);
        if let Some(pending) = &self.pending {
            out.extend_from_slice(&pending.version.service.to_le_bytes());
            out.extend_from_slice(&pending.version.schema.to_le_bytes());
            out.extend_from_slice(&pending.at.to_le_bytes());
            // At most MAX_CONFIGURATION bytes, as decoded.
            let length = u16::try_from(pending.configuration.len()).unwrap_or(u16::MAX);
            out.extend_from_slice(&length.to_le_bytes());
            out.extend_from_slice(&pending.configuration);
        }
        if let Some(stop) = self.stop {
            out.extend_from_slice(&stop.at.to_le_bytes());
            out.extend_from_slice(&stop.resume.to_le_bytes());
        }
    }

    /// The version state at the start of `bytes`, for a snapshot at
    /// `index`, and the rest; `None` for bytes [`Versions::encode`] does
    /// not write, or a pending activation at or before `index`.
    pub(super) fn decode(bytes: &[u8], index: u64) -> Option<(Self, &[u8])> {
        let (service, rest) = bytes.split_first_chunk::<4>()?;
        let (schema, rest) = rest.split_first_chunk::<2>()?;
        let (&flags, mut rest) = rest.split_first()?;
        if flags & !(CONFIGURED | PENDING | STOPPED) != 0 {
            return None;
        }
        let active = ActiveVersion::new(u32::from_le_bytes(*service), u16::from_le_bytes(*schema));
        if active.service == 0 || active.schema == 0 {
            return None;
        }
        let pending = if flags & PENDING == 0 {
            None
        } else {
            let (service, after) = rest.split_first_chunk::<4>()?;
            let (schema, after) = after.split_first_chunk::<2>()?;
            let (at, after) = after.split_first_chunk::<8>()?;
            let (length, after) = after.split_first_chunk::<2>()?;
            let length = usize::from(u16::from_le_bytes(*length));
            if length > MAX_CONFIGURATION {
                return None;
            }
            let (configuration, after) = after.split_at_checked(length)?;
            rest = after;
            let pending = Pending {
                version: ActiveVersion::new(
                    u32::from_le_bytes(*service),
                    u16::from_le_bytes(*schema),
                ),
                at: u64::from_le_bytes(*at),
                configuration: configuration.to_vec(),
            };
            if pending.at <= index
                || pending.version.service < active.service
                || pending.version.schema < active.schema
            {
                return None;
            }
            Some(pending)
        };
        let stop = if flags & STOPPED == 0 {
            None
        } else {
            let (at, after) = rest.split_first_chunk::<8>()?;
            let (resume, after) = after.split_first_chunk::<4>()?;
            rest = after;
            let resume = u32::from_le_bytes(*resume);
            if resume == 0 {
                return None;
            }
            Some(Stop {
                at: u64::from_le_bytes(*at),
                resume,
            })
        };
        Some((
            Self {
                active,
                configured: flags & CONFIGURED != 0,
                pending,
                stop,
            },
            rest,
        ))
    }
}

#[cfg(test)]
mod tests;
