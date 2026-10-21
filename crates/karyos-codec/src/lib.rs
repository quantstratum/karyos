// SPDX-License-Identifier: Apache-2.0

//! The runtime of the minimum v1 message schema of ADR-0036
//! (`quantstratum-docs: karyos/design/archive-control-codec.md`): checked
//! little-endian reads and writes at fixed offsets, the 12-byte envelope,
//! top-level groups of fixed entries, bounded variable fields and validated
//! UTF-8, with typed errors.
//!
//! - **Decoding.** [`Decoder::new`] checks the envelope against one
//!   supported [`Template`] and the input's length, then hands out the
//!   fixed block, the groups and the variable fields in schema order;
//!   [`Decoder::finish`] checks that nothing is left. Every value borrows
//!   the input; nothing allocates.
//! - **Encoding.** [`Encoder::new`] writes the envelope with a zero
//!   `message_length` into the caller's buffer, then the block, groups and
//!   variable fields; [`Encoder::finish`] writes the length last. An
//!   encoding that fails or stops early leaves the length zero, which no
//!   decoder accepts.
//!
//! The messages themselves (their templates, fields and limits) live with
//! their protocol, such as `karyos_archive::control`. A derive macro is to
//! generate them later from schema definitions.

#![forbid(unsafe_code)]

use core::fmt;

#[cfg(test)]
mod tests;

/// The envelope's length.
pub const ENVELOPE_LENGTH: usize = 12;
/// A group's header length: entry length and count.
pub const GROUP_HEADER_LENGTH: usize = 4;
/// A variable field's length prefix.
pub const VAR_HEADER_LENGTH: usize = 2;

/// One supported message format: the tuple a decoder accepts and the
/// limits of its version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Template {
    /// The schema.
    pub schema_id: u16,
    /// The template within the schema.
    pub template_id: u16,
    /// The schema version.
    pub version: u16,
    /// The fixed block's length in this version.
    pub block_length: u16,
    /// The longest message, envelope included.
    pub max_length: u32,
}

/// A decoding or encoding error, bounded and typed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CodecError {
    /// The input or the capacity is shorter than the next read or write.
    Truncated {
        /// Bytes needed, counted from the start of the region read or
        /// written: the message, or the fixed block (or group entry) for
        /// [`Block`] reads and [`Encoder`] block writes.
        needed: usize,
        /// Bytes available in that region.
        available: usize,
    },
    /// An unsupported schema, template or version, or a block or entry
    /// length other than the version's.
    UnsupportedSchema {
        /// The schema found.
        schema: u16,
        /// The template found.
        template: u16,
        /// The version found.
        version: u16,
    },
    /// `message_length` is not the input's length, or above the template's
    /// maximum.
    MessageLength {
        /// The length declared.
        declared: u32,
        /// The input's length.
        actual: usize,
    },
    /// An enum value not listed.
    InvalidEnum {
        /// The field.
        field: &'static str,
        /// The value found.
        value: u64,
    },
    /// A boolean other than 0 or 1.
    InvalidBool {
        /// The field.
        field: &'static str,
        /// The value found.
        value: u8,
    },
    /// A UTF-8 field that is not.
    InvalidUtf8 {
        /// The field.
        field: &'static str,
    },
    /// A variable field outside its bounds.
    LengthOutOfRange {
        /// The field.
        field: &'static str,
        /// Its length.
        length: usize,
        /// The least allowed.
        min: usize,
        /// The most allowed.
        max: usize,
    },
    /// A group count above its maximum.
    CountOverLimit {
        /// The group.
        group: &'static str,
        /// The count found.
        count: usize,
        /// The most allowed.
        max: usize,
    },
    /// A numeric field outside its listed values.
    ValueOutOfRange {
        /// The field.
        field: &'static str,
    },
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { needed, available } => {
                write!(f, "needs {needed} bytes, {available} available")
            }
            Self::UnsupportedSchema {
                schema,
                template,
                version,
            } => write!(
                f,
                "unsupported schema {schema}, template {template}, version {version}"
            ),
            Self::MessageLength { declared, actual } => {
                write!(f, "message length {declared}, input of {actual} bytes")
            }
            Self::InvalidEnum { field, value } => write!(f, "{field}: invalid value {value}"),
            Self::InvalidBool { field, value } => write!(f, "{field}: invalid boolean {value}"),
            Self::InvalidUtf8 { field } => write!(f, "{field}: invalid UTF-8"),
            Self::LengthOutOfRange {
                field,
                length,
                min,
                max,
            } => write!(f, "{field}: length {length} outside {min} to {max}"),
            Self::CountOverLimit { group, count, max } => {
                write!(f, "{group}: count {count} above {max}")
            }
            Self::ValueOutOfRange { field } => write!(f, "{field}: value out of range"),
        }
    }
}

impl std::error::Error for CodecError {}

fn truncated(needed: usize, available: usize) -> CodecError {
    CodecError::Truncated { needed, available }
}

/// `at + len`, or `Truncated` against `available` on overflow.
fn end(at: usize, len: usize, available: usize) -> Result<usize, CodecError> {
    at.checked_add(len)
        .ok_or_else(|| truncated(usize::MAX, available))
}

/// The bytes `[at, at + len)` of `buf`, or `Truncated`.
fn range(buf: &[u8], at: usize, len: usize) -> Result<&[u8], CodecError> {
    let end = end(at, len, buf.len())?;
    buf.get(at..end).ok_or_else(|| truncated(end, buf.len()))
}

/// The mutable bytes `[at, at + len)` of `buf`, or `Truncated`.
fn range_mut(buf: &mut [u8], at: usize, len: usize) -> Result<&mut [u8], CodecError> {
    let available = buf.len();
    let end = end(at, len, available)?;
    buf.get_mut(at..end)
        .ok_or_else(|| truncated(end, available))
}

fn array<const N: usize>(buf: &[u8], at: usize) -> Result<[u8; N], CodecError> {
    let bytes = range(buf, at, N)?;
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    Ok(out)
}

/// A validated fixed block (or group entry): checked little-endian reads
/// at fixed offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Block<'a>(&'a [u8]);

impl<'a> Block<'a> {
    /// The block's bytes.
    #[must_use]
    pub const fn bytes(&self) -> &'a [u8] {
        self.0
    }

    /// The u8 at `at`.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`] past the block.
    pub fn u8(&self, at: usize) -> Result<u8, CodecError> {
        Ok(u8::from_le_bytes(array(self.0, at)?))
    }

    /// The u16 at `at`.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`] past the block.
    pub fn u16(&self, at: usize) -> Result<u16, CodecError> {
        Ok(u16::from_le_bytes(array(self.0, at)?))
    }

    /// The u32 at `at`.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`] past the block.
    pub fn u32(&self, at: usize) -> Result<u32, CodecError> {
        Ok(u32::from_le_bytes(array(self.0, at)?))
    }

    /// The u64 at `at`.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`] past the block.
    pub fn u64(&self, at: usize) -> Result<u64, CodecError> {
        Ok(u64::from_le_bytes(array(self.0, at)?))
    }

    /// The i32 at `at`.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`] past the block.
    pub fn i32(&self, at: usize) -> Result<i32, CodecError> {
        Ok(i32::from_le_bytes(array(self.0, at)?))
    }

    /// The boolean at `at`: 0 or 1.
    ///
    /// # Errors
    ///
    /// [`CodecError::InvalidBool`] for any other byte, and
    /// [`CodecError::Truncated`].
    pub fn bool(&self, field: &'static str, at: usize) -> Result<bool, CodecError> {
        match self.u8(at)? {
            0 => Ok(false),
            1 => Ok(true),
            value => Err(CodecError::InvalidBool { field, value }),
        }
    }
}

/// A validated group: `count` fixed entries of the version's length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Group<'a> {
    entries: &'a [u8],
    entry_length: usize,
    count: usize,
}

impl<'a> Group<'a> {
    /// The number of entries.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Entry `index`, or `None` past the count.
    #[must_use]
    pub fn entry(&self, index: usize) -> Option<Block<'a>> {
        if index >= self.count {
            return None;
        }
        let at = index.checked_mul(self.entry_length)?;
        range(self.entries, at, self.entry_length).ok().map(Block)
    }

    /// The entries in order.
    pub fn iter(&self) -> impl Iterator<Item = Block<'a>> + 'a {
        let group = *self;
        (0..group.count).filter_map(move |index| group.entry(index))
    }
}

/// The envelope's fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Envelope {
    /// The schema.
    pub schema_id: u16,
    /// The template.
    pub template_id: u16,
    /// The version.
    pub version: u16,
    /// The fixed block's length.
    pub block_length: u16,
    /// The whole message's length.
    pub message_length: u32,
}

impl Envelope {
    /// The envelope at the start of `buf`.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`] when `buf` is shorter than the envelope.
    pub fn read(buf: &[u8]) -> Result<Self, CodecError> {
        let block = Block(range(buf, 0, ENVELOPE_LENGTH)?);
        Ok(Self {
            schema_id: block.u16(0)?,
            template_id: block.u16(2)?,
            version: block.u16(4)?,
            block_length: block.u16(6)?,
            message_length: block.u32(8)?,
        })
    }
}

/// A decoder of one message of one template: the fixed block, then the
/// groups, then the variable fields, in schema order.
#[derive(Debug)]
pub struct Decoder<'a> {
    buf: &'a [u8],
    declared: u32,
    cursor: usize,
}

impl<'a> Decoder<'a> {
    /// Checks `buf` holds exactly one message of `template`, and returns
    /// its fixed block and a decoder positioned after it.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`], [`CodecError::UnsupportedSchema`] for
    /// another tuple or block length, and [`CodecError::MessageLength`].
    pub fn new(buf: &'a [u8], template: &Template) -> Result<(Block<'a>, Self), CodecError> {
        let envelope = Envelope::read(buf)?;
        if (
            envelope.schema_id,
            envelope.template_id,
            envelope.version,
            envelope.block_length,
        ) != (
            template.schema_id,
            template.template_id,
            template.version,
            template.block_length,
        ) {
            return Err(CodecError::UnsupportedSchema {
                schema: envelope.schema_id,
                template: envelope.template_id,
                version: envelope.version,
            });
        }
        let declared =
            usize::try_from(envelope.message_length).map_err(|_| CodecError::MessageLength {
                declared: envelope.message_length,
                actual: buf.len(),
            })?;
        if declared != buf.len() || envelope.message_length > template.max_length {
            return Err(CodecError::MessageLength {
                declared: envelope.message_length,
                actual: buf.len(),
            });
        }
        let block = Block(range(
            buf,
            ENVELOPE_LENGTH,
            usize::from(template.block_length),
        )?);
        let cursor = end(ENVELOPE_LENGTH, block.0.len(), buf.len())?;
        Ok((
            block,
            Self {
                buf,
                declared: envelope.message_length,
                cursor,
            },
        ))
    }

    /// The next group, whose entries are `entry_length` bytes, at most
    /// `max` of them.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`], [`CodecError::UnsupportedSchema`] for
    /// another entry length, and [`CodecError::CountOverLimit`].
    pub fn group(
        &mut self,
        name: &'static str,
        entry_length: u16,
        max: usize,
    ) -> Result<Group<'a>, CodecError> {
        let header = Block(range(self.buf, self.cursor, GROUP_HEADER_LENGTH)?);
        let found = header.u16(0)?;
        if found != entry_length {
            let envelope = Envelope::read(self.buf)?;
            return Err(CodecError::UnsupportedSchema {
                schema: envelope.schema_id,
                template: envelope.template_id,
                version: envelope.version,
            });
        }
        let count = usize::from(header.u16(2)?);
        if count > max {
            return Err(CodecError::CountOverLimit {
                group: name,
                count,
                max,
            });
        }
        let start = end(self.cursor, GROUP_HEADER_LENGTH, self.buf.len())?;
        let length = count
            .checked_mul(usize::from(entry_length))
            .ok_or_else(|| truncated(usize::MAX, self.buf.len()))?;
        let entries = range(self.buf, start, length)?;
        self.cursor = end(start, length, self.buf.len())?;
        Ok(Group {
            entries,
            entry_length: usize::from(entry_length),
            count,
        })
    }

    /// The next variable field, `min` to `max` bytes.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`] and [`CodecError::LengthOutOfRange`].
    pub fn bytes(
        &mut self,
        field: &'static str,
        min: usize,
        max: usize,
    ) -> Result<&'a [u8], CodecError> {
        let header = Block(range(self.buf, self.cursor, VAR_HEADER_LENGTH)?);
        let length = usize::from(header.u16(0)?);
        if length < min || length > max {
            return Err(CodecError::LengthOutOfRange {
                field,
                length,
                min,
                max,
            });
        }
        let start = end(self.cursor, VAR_HEADER_LENGTH, self.buf.len())?;
        let value = range(self.buf, start, length)?;
        self.cursor = end(start, length, self.buf.len())?;
        Ok(value)
    }

    /// The next variable field as UTF-8, `min` to `max` bytes.
    ///
    /// # Errors
    ///
    /// As [`Decoder::bytes`], and [`CodecError::InvalidUtf8`].
    pub fn str(
        &mut self,
        field: &'static str,
        min: usize,
        max: usize,
    ) -> Result<&'a str, CodecError> {
        let bytes = self.bytes(field, min, max)?;
        core::str::from_utf8(bytes).map_err(|_| CodecError::InvalidUtf8 { field })
    }

    /// Checks the message ends where its last field does.
    ///
    /// # Errors
    ///
    /// [`CodecError::MessageLength`] when bytes are left over.
    pub fn finish(self) -> Result<(), CodecError> {
        if self.cursor == self.buf.len() {
            Ok(())
        } else {
            Err(CodecError::MessageLength {
                declared: self.declared,
                actual: self.cursor,
            })
        }
    }
}

/// An encoder of one message of one template into the caller's buffer.
#[derive(Debug)]
pub struct Encoder<'a> {
    buf: &'a mut [u8],
    block_length: usize,
    max_length: u32,
    cursor: usize,
}

impl<'a> Encoder<'a> {
    /// Writes the envelope of `template`, with a zero `message_length`, and
    /// a zeroed fixed block into `buf`.
    ///
    /// Whatever happens next, `buf` no longer holds a message: the length
    /// of any earlier one is zeroed first, even when `buf` is too short for
    /// this one.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`] when `buf` cannot hold them.
    pub fn new(buf: &'a mut [u8], template: &Template) -> Result<Self, CodecError> {
        if let Some(length) = buf.get_mut(8..ENVELOPE_LENGTH) {
            length.fill(0);
        }
        let block_length = usize::from(template.block_length);
        let head_length = end(ENVELOPE_LENGTH, block_length, buf.len())?;
        range_mut(buf, 0, head_length)?.fill(0);
        let mut encoder = Self {
            buf,
            block_length,
            max_length: template.max_length,
            cursor: head_length,
        };
        encoder.put(0, &template.schema_id.to_le_bytes())?;
        encoder.put(2, &template.template_id.to_le_bytes())?;
        encoder.put(4, &template.version.to_le_bytes())?;
        encoder.put(6, &template.block_length.to_le_bytes())?;
        Ok(encoder)
    }

    fn put(&mut self, at: usize, bytes: &[u8]) -> Result<(), CodecError> {
        range_mut(self.buf, at, bytes.len())?.copy_from_slice(bytes);
        Ok(())
    }

    fn put_block(&mut self, at: usize, bytes: &[u8]) -> Result<(), CodecError> {
        let last = end(at, bytes.len(), self.block_length)?;
        if last > self.block_length {
            return Err(truncated(last, self.block_length));
        }
        self.put(end(ENVELOPE_LENGTH, at, self.buf.len())?, bytes)
    }

    /// Writes the u8 at block offset `at`.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`] past the block.
    pub fn u8(&mut self, at: usize, value: u8) -> Result<(), CodecError> {
        self.put_block(at, &value.to_le_bytes())
    }

    /// Writes the u16 at block offset `at`.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`] past the block.
    pub fn u16(&mut self, at: usize, value: u16) -> Result<(), CodecError> {
        self.put_block(at, &value.to_le_bytes())
    }

    /// Writes the u32 at block offset `at`.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`] past the block.
    pub fn u32(&mut self, at: usize, value: u32) -> Result<(), CodecError> {
        self.put_block(at, &value.to_le_bytes())
    }

    /// Writes the u64 at block offset `at`.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`] past the block.
    pub fn u64(&mut self, at: usize, value: u64) -> Result<(), CodecError> {
        self.put_block(at, &value.to_le_bytes())
    }

    /// Writes the i32 at block offset `at`.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`] past the block.
    pub fn i32(&mut self, at: usize, value: i32) -> Result<(), CodecError> {
        self.put_block(at, &value.to_le_bytes())
    }

    /// Writes the boolean at block offset `at`.
    ///
    /// # Errors
    ///
    /// [`CodecError::Truncated`] past the block.
    pub fn bool(&mut self, at: usize, value: bool) -> Result<(), CodecError> {
        self.u8(at, u8::from(value))
    }

    /// Writes a group of `entries`, each `entry_length` bytes, at most `max`.
    ///
    /// # Errors
    ///
    /// [`CodecError::CountOverLimit`], [`CodecError::LengthOutOfRange`] for
    /// an entry of another length, and [`CodecError::Truncated`].
    pub fn group<'e>(
        &mut self,
        name: &'static str,
        entry_length: u16,
        max: usize,
        entries: impl ExactSizeIterator<Item = &'e [u8]>,
    ) -> Result<(), CodecError> {
        let count = entries.len();
        if count > max {
            return Err(CodecError::CountOverLimit {
                group: name,
                count,
                max,
            });
        }
        let count16 = u16::try_from(count).map_err(|_| CodecError::CountOverLimit {
            group: name,
            count,
            max: usize::from(u16::MAX),
        })?;
        let available = self.buf.len();
        let mut at = self.cursor;
        self.put(at, &entry_length.to_le_bytes())?;
        self.put(end(at, 2, available)?, &count16.to_le_bytes())?;
        at = end(at, GROUP_HEADER_LENGTH, available)?;
        for entry in entries {
            if entry.len() != usize::from(entry_length) {
                return Err(CodecError::LengthOutOfRange {
                    field: name,
                    length: entry.len(),
                    min: usize::from(entry_length),
                    max: usize::from(entry_length),
                });
            }
            self.put(at, entry)?;
            at = end(at, entry.len(), available)?;
        }
        self.cursor = at;
        Ok(())
    }

    /// Writes the next variable field, `min` to `max` bytes.
    ///
    /// # Errors
    ///
    /// [`CodecError::LengthOutOfRange`] and [`CodecError::Truncated`].
    pub fn bytes(
        &mut self,
        field: &'static str,
        min: usize,
        max: usize,
        value: &[u8],
    ) -> Result<(), CodecError> {
        let length = value.len();
        let length16 = u16::try_from(length)
            .ok()
            .filter(|_| length >= min && length <= max);
        let Some(length16) = length16 else {
            return Err(CodecError::LengthOutOfRange {
                field,
                length,
                min,
                max,
            });
        };
        let available = self.buf.len();
        let start = end(self.cursor, VAR_HEADER_LENGTH, available)?;
        self.put(self.cursor, &length16.to_le_bytes())?;
        self.put(start, value)?;
        self.cursor = end(start, length, available)?;
        Ok(())
    }

    /// Writes `message_length`, last, and returns it.
    ///
    /// # Errors
    ///
    /// [`CodecError::MessageLength`] above the template's maximum.
    pub fn finish(mut self) -> Result<usize, CodecError> {
        let length = u32::try_from(self.cursor)
            .ok()
            .filter(|length| *length <= self.max_length)
            .ok_or(CodecError::MessageLength {
                declared: self.max_length,
                actual: self.cursor,
            })?;
        self.put(8, &length.to_le_bytes())?;
        Ok(self.cursor)
    }
}
