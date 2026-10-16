// SPDX-License-Identifier: Apache-2.0

//! Raw per-message samples of one run and stage, and their file format
//! (`quantstratum-docs: karyos/design/measurement-harness.md` 2.3).
//!
//! The decision path keeps raw samples: the 2% tie of manifest 8.5 applies
//! to the added latency, finer than a 3-digit histogram resolves, and the
//! bootstrap of manifest 8.3 needs the run strata.
//!
//! A sample is a `u32` count of nanoseconds per message. [`MISSING`]
//! (`u32::MAX`) marks a dropped or orphaned message: it ranks above every
//! measured value of its run, as +∞ (coordinator, ACS 14828). A measured
//! value that does not fit below [`SATURATED`] is stored as [`SATURATED`]
//! and counted; a run with any saturated sample is not valid.
//!
//! # File format (version 1, little endian)
//!
//! | Bytes | Field |
//! | --- | --- |
//! | 8 | magic `KYBSMPL\0` |
//! | 2 | format version, 1 |
//! | 1, 1 | shape code, shape parameter |
//! | 1, 1, 4 | load code, invalid percent (R4), rate |
//! | 1, 1 | fan-out code, receivers |
//! | 1, 2 | stage code, receiver index |
//! | 4 | run index |
//! | 8 | seed |
//! | 4 | clock resolution, ns |
//! | 8 | warmup messages discarded |
//! | 8 | saturated samples |
//! | 1, n | profile name length and ASCII bytes |
//! | 8 | sample count `c` |
//! | 4 × c | samples |
//!
//! A file must be exactly this long: a short file is [`SamplesError::Truncated`]
//! and extra bytes are [`SamplesError::TrailingBytes`].

use std::fmt;
use std::io::{Read, Write};
use std::path::Path;

use crate::manifest::{ExtBase, Fanout, Load, Point, Shape};

/// A dropped or orphaned message: +∞.
pub const MISSING: u32 = u32::MAX;

/// The largest stored measured value; larger values saturate to it.
pub const SATURATED: u32 = u32::MAX - 1;

/// The file magic.
pub const MAGIC: [u8; 8] = *b"KYBSMPL\0";

/// The file format version.
pub const FORMAT_VERSION: u16 = 1;

/// The longest profile name.
pub const MAX_PROFILE_LEN: usize = 64;

/// Errors reading or writing a sample file.
#[derive(Debug)]
pub enum SamplesError {
    /// The file does not start with [`MAGIC`].
    BadMagic,
    /// The format version is not [`FORMAT_VERSION`].
    UnsupportedVersion(u16),
    /// The input ended before the header or the samples it announces.
    Truncated,
    /// Bytes follow the announced samples.
    TrailingBytes,
    /// A header field is out of range.
    InvalidField(&'static str),
    /// An I/O error.
    Io(std::io::Error),
}

impl fmt::Display for SamplesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadMagic => f.write_str("not a sample file (bad magic)"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported sample format version {version}")
            }
            Self::Truncated => f.write_str("sample file truncated"),
            Self::TrailingBytes => f.write_str("trailing bytes after the samples"),
            Self::InvalidField(field) => write!(f, "invalid header field: {field}"),
            Self::Io(cause) => write!(f, "sample file I/O: {cause}"),
        }
    }
}

impl std::error::Error for SamplesError {}

impl From<std::io::Error> for SamplesError {
    fn from(cause: std::io::Error) -> Self {
        Self::Io(cause)
    }
}

/// Which stage a file holds (manifest 6.2; design 2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stage {
    /// The send stage.
    Send,
    /// The receive stage of one receiver.
    Receive {
        /// The receiver index, 0 under F1.
        receiver: u16,
    },
    /// The per-message decision sample: send plus receive (coordinator
    /// M-5a), with the per-message maximum over receivers under F2 (H-3).
    Combined,
}

/// The header of one run's samples.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// The operating point.
    pub point: Point,
    /// The profile name, such as `trusted`.
    pub profile: String,
    /// The stage.
    pub stage: Stage,
    /// The run index at the point, from 0.
    pub run: u32,
    /// The seed recorded for the run.
    pub seed: u64,
    /// The clock resolution in nanoseconds.
    pub clock_resolution_ns: u32,
    /// Warmup messages measured and discarded (manifest 8.1).
    pub warmup: u64,
    /// Samples that saturated at [`SATURATED`].
    pub saturated: u64,
}

/// One run's samples with their header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunSamples {
    /// The header.
    pub header: Header,
    /// Nanoseconds per message, [`MISSING`] for a dropped message.
    pub samples: Vec<u32>,
}

impl RunSamples {
    /// Messages missing from the run.
    #[must_use]
    pub fn missing(&self) -> u64 {
        missing(&self.samples)
    }
}

/// The count of [`MISSING`] samples.
#[must_use]
pub fn missing(samples: &[u32]) -> u64 {
    samples
        .iter()
        .filter(|&&value| value == MISSING)
        .fold(0u64, |count, _| count.saturating_add(1))
}

/// Converts a measured duration to a sample, saturating at [`SATURATED`].
/// Returns the sample and whether it saturated.
#[must_use]
pub fn sample_from_ns(ns: u64) -> (u32, bool) {
    match u32::try_from(ns) {
        Ok(value) if value < SATURATED => (value, false),
        _ => (SATURATED, true),
    }
}

/// The per-message decision samples of one run: send plus the slowest
/// receive over the receivers (coordinator M-5a; H-3, ACS 14817). A
/// message missing at the sender or at any receiver is [`MISSING`]. A sum
/// that does not fit saturates at [`SATURATED`].
///
/// Returns the samples and the count of saturated sums.
///
/// # Errors
///
/// [`SamplesError::InvalidField`] when there is no receiver or the
/// lengths differ (send and receive are joined on the message sequence).
pub fn combine(send: &[u32], receives: &[&[u32]]) -> Result<(Vec<u32>, u64), SamplesError> {
    if receives.is_empty() {
        return Err(SamplesError::InvalidField("no receiver"));
    }
    if receives.iter().any(|receive| receive.len() != send.len()) {
        return Err(SamplesError::InvalidField("stage lengths differ"));
    }
    let mut saturated = 0u64;
    let mut out = Vec::with_capacity(send.len());
    for (index, &sent) in send.iter().enumerate() {
        let mut slowest = 0u32;
        for receive in receives {
            let value = receive.get(index).copied().unwrap_or(MISSING);
            slowest = slowest.max(value);
        }
        let value = if sent == MISSING || slowest == MISSING {
            MISSING
        } else {
            let (value, clipped) = sample_from_ns(u64::from(sent) + u64::from(slowest));
            if clipped {
                saturated = saturated.saturating_add(1);
            }
            value
        };
        out.push(value);
    }
    Ok((out, saturated))
}

fn shape_code(shape: Shape) -> (u8, u8) {
    match shape {
        Shape::W1 => (1, 0),
        Shape::W2 => (2, 0),
        Shape::W3 => (3, 0),
        Shape::W4 => (4, 0),
        Shape::W5 => (5, 0),
        Shape::W6 => (6, 0),
        Shape::W7 => (7, 0),
        Shape::W8(index) => (8, index),
        Shape::W9(ExtBase::W1) => (9, 1),
        Shape::W9(ExtBase::W4) => (9, 4),
    }
}

fn shape_from(code: u8, param: u8) -> Result<Shape, SamplesError> {
    let shape = match (code, param) {
        (1, 0) => Shape::W1,
        (2, 0) => Shape::W2,
        (3, 0) => Shape::W3,
        (4, 0) => Shape::W4,
        (5, 0) => Shape::W5,
        (6, 0) => Shape::W6,
        (7, 0) => Shape::W7,
        (8, index) => Shape::W8(index),
        (9, 1) => Shape::W9(ExtBase::W1),
        (9, 4) => Shape::W9(ExtBase::W4),
        _ => return Err(SamplesError::InvalidField("shape")),
    };
    Ok(shape)
}

fn load_code(load: Load) -> (u8, u8, u32) {
    match load {
        Load::R1 => (1, 0, 0),
        Load::R2 { rate } => (2, 0, rate),
        Load::R3 => (3, 0, 0),
        Load::R4 {
            rate,
            invalid_percent,
        } => (4, invalid_percent, rate),
        Load::R5 { rate } => (5, 0, rate),
    }
}

fn load_from(code: u8, percent: u8, rate: u32) -> Result<Load, SamplesError> {
    let load = match (code, percent, rate) {
        (1, 0, 0) => Load::R1,
        (2, 0, rate) if rate > 0 => Load::R2 { rate },
        (3, 0, 0) => Load::R3,
        (4, invalid_percent, rate) if rate > 0 && invalid_percent > 0 => Load::R4 {
            rate,
            invalid_percent,
        },
        (5, 0, rate) if rate > 0 => Load::R5 { rate },
        _ => return Err(SamplesError::InvalidField("load")),
    };
    Ok(load)
}

fn fanout_code(fanout: Fanout) -> (u8, u8) {
    match fanout {
        Fanout::F1 => (1, 1),
        Fanout::F2 { receivers } => (2, receivers),
    }
}

fn fanout_from(code: u8, receivers: u8) -> Result<Fanout, SamplesError> {
    match (code, receivers) {
        (1, 1) => Ok(Fanout::F1),
        (2, receivers) if receivers > 0 => Ok(Fanout::F2 { receivers }),
        _ => Err(SamplesError::InvalidField("fan-out")),
    }
}

fn stage_code(stage: Stage) -> (u8, u16) {
    match stage {
        Stage::Send => (1, 0),
        Stage::Receive { receiver } => (2, receiver),
        Stage::Combined => (3, 0),
    }
}

fn stage_from(code: u8, receiver: u16) -> Result<Stage, SamplesError> {
    match (code, receiver) {
        (1, 0) => Ok(Stage::Send),
        (2, receiver) => Ok(Stage::Receive { receiver }),
        (3, 0) => Ok(Stage::Combined),
        _ => Err(SamplesError::InvalidField("stage")),
    }
}

fn valid_profile(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_PROFILE_LEN
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

/// Encodes one run's samples.
///
/// # Errors
///
/// [`SamplesError::InvalidField`] for a profile name that is empty, longer
/// than [`MAX_PROFILE_LEN`] or not made of ASCII letters, digits, `-`, `_`
/// and `.`.
pub fn encode(run: &RunSamples) -> Result<Vec<u8>, SamplesError> {
    let header = &run.header;
    if !valid_profile(&header.profile) {
        return Err(SamplesError::InvalidField("profile"));
    }
    let profile_len =
        u8::try_from(header.profile.len()).map_err(|_| SamplesError::InvalidField("profile"))?;
    let count =
        u64::try_from(run.samples.len()).map_err(|_| SamplesError::InvalidField("count"))?;
    let mut out = Vec::with_capacity(run.samples.len().saturating_mul(4).saturating_add(128));
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    let (shape, shape_param) = shape_code(header.point.shape);
    out.extend_from_slice(&[shape, shape_param]);
    let (load, percent, rate) = load_code(header.point.load);
    out.extend_from_slice(&[load, percent]);
    out.extend_from_slice(&rate.to_le_bytes());
    let (fanout, receivers) = fanout_code(header.point.fanout);
    out.extend_from_slice(&[fanout, receivers]);
    let (stage, receiver) = stage_code(header.stage);
    out.push(stage);
    out.extend_from_slice(&receiver.to_le_bytes());
    out.extend_from_slice(&header.run.to_le_bytes());
    out.extend_from_slice(&header.seed.to_le_bytes());
    out.extend_from_slice(&header.clock_resolution_ns.to_le_bytes());
    out.extend_from_slice(&header.warmup.to_le_bytes());
    out.extend_from_slice(&header.saturated.to_le_bytes());
    out.push(profile_len);
    out.extend_from_slice(header.profile.as_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    for sample in &run.samples {
        out.extend_from_slice(&sample.to_le_bytes());
    }
    Ok(out)
}

struct Cursor<'a> {
    rest: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], SamplesError> {
        if self.rest.len() < n {
            return Err(SamplesError::Truncated);
        }
        let (head, rest) = self.rest.split_at(n);
        self.rest = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], SamplesError> {
        let bytes = self.take(N)?;
        <[u8; N]>::try_from(bytes).map_err(|_| SamplesError::Truncated)
    }

    fn u8(&mut self) -> Result<u8, SamplesError> {
        Ok(u8::from_le_bytes(self.array()?))
    }

    fn u16(&mut self) -> Result<u16, SamplesError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, SamplesError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, SamplesError> {
        Ok(u64::from_le_bytes(self.array()?))
    }
}

/// Decodes and validates one run's samples.
///
/// # Errors
///
/// [`SamplesError::BadMagic`], [`SamplesError::UnsupportedVersion`],
/// [`SamplesError::Truncated`] when the input is shorter than the header or
/// the samples it announces, [`SamplesError::TrailingBytes`] when it is
/// longer, and [`SamplesError::InvalidField`] for an out-of-range field
/// (including a saturated count above the sample count).
pub fn decode(bytes: &[u8]) -> Result<RunSamples, SamplesError> {
    let mut cursor = Cursor { rest: bytes };
    if cursor
        .take(MAGIC.len())
        .map_err(|_| SamplesError::BadMagic)?
        != MAGIC
    {
        return Err(SamplesError::BadMagic);
    }
    let version = cursor.u16()?;
    if version != FORMAT_VERSION {
        return Err(SamplesError::UnsupportedVersion(version));
    }
    let shape = {
        let code = cursor.u8()?;
        let param = cursor.u8()?;
        shape_from(code, param)?
    };
    let load = {
        let code = cursor.u8()?;
        let percent = cursor.u8()?;
        let rate = cursor.u32()?;
        load_from(code, percent, rate)?
    };
    let fanout = {
        let code = cursor.u8()?;
        let receivers = cursor.u8()?;
        fanout_from(code, receivers)?
    };
    let stage = {
        let code = cursor.u8()?;
        let receiver = cursor.u16()?;
        stage_from(code, receiver)?
    };
    let run = cursor.u32()?;
    let seed = cursor.u64()?;
    let clock_resolution_ns = cursor.u32()?;
    let warmup = cursor.u64()?;
    let saturated = cursor.u64()?;
    let profile_len = usize::from(cursor.u8()?);
    let profile = std::str::from_utf8(cursor.take(profile_len)?)
        .map_err(|_| SamplesError::InvalidField("profile"))?
        .to_string();
    if !valid_profile(&profile) {
        return Err(SamplesError::InvalidField("profile"));
    }
    let count = cursor.u64()?;
    let byte_len = count
        .checked_mul(4)
        .and_then(|len| usize::try_from(len).ok())
        .ok_or(SamplesError::Truncated)?;
    if cursor.rest.len() < byte_len {
        return Err(SamplesError::Truncated);
    }
    if cursor.rest.len() > byte_len {
        return Err(SamplesError::TrailingBytes);
    }
    if saturated > count {
        return Err(SamplesError::InvalidField("saturated"));
    }
    let (words, rest) = cursor.rest.as_chunks::<4>();
    if !rest.is_empty() {
        return Err(SamplesError::Truncated);
    }
    let samples: Vec<u32> = words.iter().map(|word| u32::from_le_bytes(*word)).collect();
    Ok(RunSamples {
        header: Header {
            point: Point {
                shape,
                load,
                fanout,
            },
            profile,
            stage,
            run,
            seed,
            clock_resolution_ns,
            warmup,
            saturated,
        },
        samples,
    })
}

/// Writes one run's samples to `writer`.
///
/// # Errors
///
/// As [`encode`], and [`SamplesError::Io`].
pub fn write(writer: &mut impl Write, run: &RunSamples) -> Result<(), SamplesError> {
    writer.write_all(&encode(run)?)?;
    Ok(())
}

/// Reads one run's samples from `reader`, to its end.
///
/// # Errors
///
/// As [`decode`], and [`SamplesError::Io`].
pub fn read(reader: &mut impl Read) -> Result<RunSamples, SamplesError> {
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    decode(&bytes)
}

/// Writes one run's samples to the file at `path`.
///
/// # Errors
///
/// As [`write()`].
pub fn write_file(path: &Path, run: &RunSamples) -> Result<(), SamplesError> {
    std::fs::write(path, encode(run)?)?;
    Ok(())
}

/// Reads one run's samples from the file at `path`.
///
/// # Errors
///
/// As [`read()`].
pub fn read_file(path: &Path) -> Result<RunSamples, SamplesError> {
    decode(&std::fs::read(path)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{RATE_100K, primary};

    fn example() -> RunSamples {
        RunSamples {
            header: Header {
                point: Point {
                    shape: Shape::W5,
                    load: Load::R2 { rate: RATE_100K },
                    fanout: Fanout::F2 { receivers: 4 },
                },
                profile: "trusted".into(),
                stage: Stage::Receive { receiver: 3 },
                run: 4,
                seed: 0xDEAD_BEEF_0123_4567,
                clock_resolution_ns: 41,
                warmup: 100_000,
                saturated: 1,
            },
            samples: vec![1, 2, 3, SATURATED, MISSING, 700],
        }
    }

    #[test]
    fn round_trip() {
        let run = example();
        let bytes = encode(&run).unwrap();
        assert_eq!(decode(&bytes).unwrap(), run);
        assert_eq!(run.missing(), 1);
        let mut buffer = Vec::new();
        write(&mut buffer, &run).unwrap();
        assert_eq!(read(&mut buffer.as_slice()).unwrap(), run);
        for point in primary() {
            for stage in [Stage::Send, Stage::Combined, Stage::Receive { receiver: 0 }] {
                let mut run = example();
                run.header.point = point;
                run.header.stage = stage;
                assert_eq!(decode(&encode(&run).unwrap()).unwrap(), run);
            }
        }
    }

    #[test]
    fn file_round_trip() {
        let dir = std::env::temp_dir().join(format!("karyos-bench-samples-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("run.bin");
        let run = example();
        write_file(&path, &run).unwrap();
        assert_eq!(read_file(&path).unwrap(), run);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn corrupted_input_is_rejected() {
        let bytes = encode(&example()).unwrap();
        // Every strict prefix is truncated or has a bad magic.
        for len in 0..bytes.len() {
            let result = decode(&bytes[..len]);
            assert!(
                matches!(
                    result,
                    Err(SamplesError::Truncated | SamplesError::BadMagic)
                ),
                "prefix {len}: {result:?}"
            );
        }
        let mut long = bytes.clone();
        long.push(0);
        assert!(matches!(decode(&long), Err(SamplesError::TrailingBytes)));
        let mut magic = bytes.clone();
        magic[0] ^= 1;
        assert!(matches!(decode(&magic), Err(SamplesError::BadMagic)));
        let mut version = bytes.clone();
        version[8] = 2;
        assert!(matches!(
            decode(&version),
            Err(SamplesError::UnsupportedVersion(2))
        ));
        let mut shape = bytes.clone();
        shape[10] = 0;
        assert!(matches!(
            decode(&shape),
            Err(SamplesError::InvalidField("shape"))
        ));
        let mut count = bytes;
        let at = count.len() - 6 * 4 - 8;
        count[at] = 7;
        assert!(matches!(decode(&count), Err(SamplesError::Truncated)));
    }

    #[test]
    fn bad_profiles_are_refused() {
        for name in ["", "with space", &"x".repeat(65)] {
            let mut run = example();
            run.header.profile = name.to_string();
            assert!(matches!(
                encode(&run),
                Err(SamplesError::InvalidField("profile"))
            ));
        }
    }

    #[test]
    fn combine_takes_the_slowest_receiver_and_keeps_drops() {
        let send = [10, 10, MISSING, 10, u32::MAX - 5];
        let first = [5, 50, 5, MISSING, 10];
        let second = [7, 1, 5, 5, 10];
        let (combined, saturated) = combine(&send, &[&first, &second]).unwrap();
        assert_eq!(combined, vec![17, 60, MISSING, MISSING, SATURATED]);
        assert_eq!(saturated, 1);
        assert!(combine(&send, &[]).is_err());
        assert!(combine(&send, &[&first[..2]]).is_err());
    }

    #[test]
    fn saturation() {
        assert_eq!(sample_from_ns(5), (5, false));
        assert_eq!(sample_from_ns(u64::from(SATURATED)), (SATURATED, true));
        assert_eq!(sample_from_ns(u64::MAX), (SATURATED, true));
    }
}
