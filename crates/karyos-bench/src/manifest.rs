// SPDX-License-Identifier: Apache-2.0

//! The wire threat model and comparison manifest, version `2.0`, as data
//! (`quantstratum-docs: karyos/design/wire-threat-model-manifest.md`).
//! Version 2.0 (owner approval, ACS 15075) keeps the operating points and
//! thresholds of 1.0 and makes the run-level Welch t interval the interval
//! method of §8.3 (see `decision::DECISION_METHOD`).
//!
//! The manifest is frozen (manifest 9). This module states its operating
//! points (6.1), its primary set (6.1) and the constants of its section 8.
//! It never reinterprets a frozen value. Where the manifest leaves a
//! choice open, the choice is named in the item's documentation together
//! with the coordinator decision or design choice that fixes it
//! (`quantstratum-docs: karyos/design/measurement-harness.md`).

use std::fmt;

use karyos_sys::frame::Flags;
use karyos_sys::sizing::{DEFAULT_MTU, FragmentPlan, TermLength};

/// The manifest version every result cites (manifest 9).
pub const VERSION: &str = "2.0";

/// The SHA-256 of the manifest file of [`VERSION`] (manifest 9). The file
/// cannot contain its own hash, so every result records it. This is the
/// 2.0 file as merged in quantstratum-docs #70 at 749ae98 (ACS note
/// `karyos/threat-model-manifest-v2-hash`). A value that is not 64 lowercase hex digits makes every result not
/// decision grade (`decision::GradeReason::ManifestHashPending`).
pub const MANIFEST_SHA256: &str =
    "67855e81f0ae526559f4dde470f6ab8b1dac7d5e939aa870a3e46a386a1c4dea";

/// The SHA-256 of manifest version 1.0 at its freeze (ACS note
/// `threat-model-manifest-v1-hash`), kept for results that cite 1.0.
pub const MANIFEST_1_0_SHA256: &str =
    "7e42ac9df17705a40e2987257e67b7462a187e7e313f983ac381f43ca06fbe90";

/// Whether [`MANIFEST_SHA256`] is a final hash: 64 lowercase hex digits.
#[must_use]
pub fn manifest_hash_is_final() -> bool {
    is_sha256_hex(MANIFEST_SHA256)
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The default MTU of the operating points (manifest 6.1; SPEC §4).
pub const MTU: u32 = DEFAULT_MTU;

/// The jumbo MTU of W7 (manifest 6.1, W7; SPEC §5).
pub const JUMBO_MTU: u32 = 8192;

/// The frame header length without the extension (SPEC §4).
pub const HEADER: u32 = 32;

/// The frame alignment (SPEC §4).
pub const ALIGNMENT: u32 = 32;

/// The largest `E_max` for which manifest 2.0 defines W6 (6.1, W6).
pub const W6_E_MAX_LIMIT: u32 = 176;

/// The W6 message length (manifest 6.1, W6).
pub const W6_LENGTH: u32 = 6000;

/// The W6 datagram count when `mtu` does not count the envelope, or the
/// envelope is at most 160 bytes; one more for 161 to 176 when it does
/// (manifest 2.0 6.1, W6).
pub const W6_DATAGRAMS: u32 = 5;

/// The illustrative `E_max` of the manifest examples (manifest 6.1).
pub const ILLUSTRATIVE_E_MAX: u32 = 64;

/// R2 and R4 at 100 000 messages per second (manifest 6.1, R2).
pub const RATE_100K: u32 = 100_000;

/// R2 and R5 at 1 000 000 messages per second (manifest 6.1, R2 and R5).
pub const RATE_1M: u32 = 1_000_000;

/// Constants of manifest section 8 (owner decision Q-8).
pub mod section8 {
    /// 8.1: measured messages per run, at least.
    pub const MIN_SAMPLES_PER_RUN: u64 = 1_000_000;
    /// 8.1: warmup messages per run, discarded.
    pub const WARMUP_PER_RUN: u64 = 100_000;
    /// 8.2: independent runs per point, at least.
    pub const MIN_RUNS: u32 = 5;
    /// 8.3: bootstrap resamples.
    pub const BOOTSTRAP_RESAMPLES: u32 = 10_000;
    /// 8.3: confidence level of the interval, in per mille (95%).
    pub const CONFIDENCE_PER_MILLE: u32 = 950;
    /// 8.4: the run-to-run coefficient of variation limit of p99.9, in
    /// percent. A value strictly above it invalidates the point.
    pub const CV_LIMIT_PERCENT: u32 = 10;
    /// 8.5: the tie threshold, in percent of the larger added latency.
    pub const TIE_PERCENT: u32 = 2;
    /// 6.2: the decision quantile p99.9, as numerator and denominator.
    pub const DECISION_QUANTILE: (u64, u64) = (999, 1000);
}

/// Errors of the manifest model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    /// `E_max` leaves no room for a frame at the MTU.
    EnvelopeTooLarge {
        /// The envelope budget.
        e_max: u32,
        /// The MTU it was applied to.
        mtu: u32,
    },
    /// W6 takes a count that manifest 2.0 6.1 does not state for this
    /// `E_max` and rule, with the fragment plan of SPEC §4 (see
    /// [`w6_datagrams`]); in practice an `E_max` above 176.
    W6DatagramCount {
        /// The envelope budget.
        e_max: u32,
        /// The `mtu` rule.
        rule: MtuRule,
        /// The datagram count found.
        datagrams: u32,
    },
    /// The shape has no size formula in this model (W8 sizes come from
    /// `network-control-schemas.md` 4.9, measured in a later batch).
    NoSizeFormula(Shape),
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EnvelopeTooLarge { e_max, mtu } => {
                write!(f, "E_max {e_max} leaves no frame room at MTU {mtu}")
            }
            Self::W6DatagramCount {
                e_max,
                rule,
                datagrams,
            } => write!(
                f,
                "W6 takes {datagrams} datagrams at E_max {e_max} ({rule}), outside manifest 2.0 6.1"
            ),
            Self::NoSizeFormula(shape) => write!(f, "{shape} has no size formula in this model"),
        }
    }
}

impl std::error::Error for ManifestError {}

/// The envelope budget `E_max` (manifest 6.1). Its value is fixed by
/// decision 5 of `network-control-schemas.md`; until then a run uses a
/// provisional value and no result is decision grade (coordinator M-7,
/// ACS 14786).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EMax {
    /// Not yet fixed by decision 5; labelled
    /// `provisional E_max (illustrative, manifest 6.1)`.
    Provisional(u32),
    /// Fixed by decision 5.
    Decided(u32),
}

impl EMax {
    /// The envelope bytes.
    #[must_use]
    pub const fn bytes(self) -> u32 {
        match self {
            Self::Provisional(bytes) | Self::Decided(bytes) => bytes,
        }
    }

    /// Whether decision 5 has fixed the value.
    #[must_use]
    pub const fn is_decided(self) -> bool {
        matches!(self, Self::Decided(_))
    }
}

impl fmt::Display for EMax {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provisional(bytes) => write!(
                f,
                "{bytes} (provisional E_max (illustrative, manifest 6.1))"
            ),
            Self::Decided(bytes) => write!(f, "{bytes}"),
        }
    }
}

/// Whether `mtu` counts the envelope (manifest 6.1, "Envelope budget";
/// ADR-0044 decision 2, fixed by decision 5). Both rules are modelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MtuRule {
    /// `mtu` counts the envelope: the inner frame budget is `1408 - E_max`.
    CountsEnvelope,
    /// `mtu` does not count it: the datagram grows by the envelope and the
    /// frame budget stays 1408.
    ExcludesEnvelope,
}

impl MtuRule {
    /// Both rules.
    pub const ALL: [Self; 2] = [Self::CountsEnvelope, Self::ExcludesEnvelope];

    /// The frame budget per datagram at `mtu` under this rule.
    ///
    /// # Errors
    ///
    /// [`ManifestError::EnvelopeTooLarge`] when the budget leaves no room
    /// for a header.
    pub fn frame_budget(self, mtu: u32, e_max: u32) -> Result<u32, ManifestError> {
        let budget = match self {
            Self::CountsEnvelope => mtu.checked_sub(e_max),
            Self::ExcludesEnvelope => Some(mtu),
        };
        match budget {
            Some(budget) if align_down(budget) > HEADER => Ok(budget),
            _ => Err(ManifestError::EnvelopeTooLarge { e_max, mtu }),
        }
    }
}

impl fmt::Display for MtuRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CountsEnvelope => "mtu counts the envelope",
            Self::ExcludesEnvelope => "mtu excludes the envelope",
        })
    }
}

/// `align_down(value, 32)`.
#[must_use]
pub const fn align_down(value: u32) -> u32 {
    value - value % ALIGNMENT
}

/// The base of a W9 point: W1 or W4 with the `EXT` extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ExtBase {
    /// W1 with `EXT`.
    W1,
    /// W4 with `EXT`.
    W4,
}

/// The workload shapes W1 to W9 (manifest 6.1, first table).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Shape {
    /// W1: `L` = 32, one per datagram.
    W1,
    /// W2: header-only DATA heartbeat.
    W2,
    /// W3: `L` = 256.
    W3,
    /// W4: full datagram, `L = align_down(1408 - E_max, 32) - 32`.
    W4,
    /// W5: `floor((1408 - E_max) / 64)` frames of `L` = 32 in one datagram.
    W5,
    /// W6: `L` = 6000 in 5 datagrams, or 6 for an envelope of 161 to 176
    /// bytes when `mtu` counts it (manifest 2.0 6.1).
    W6,
    /// W7: MTU 8192 and the largest single frame it holds.
    W7,
    /// W8: a control of `network-control-schemas.md` 4.9, by index there.
    W8(u8),
    /// W9: W1 or W4 with the `EXT` extension.
    W9(ExtBase),
}

/// The size of one message of a shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Size {
    /// Application payload `L` per message.
    pub payload: u32,
    /// Frames of that payload per datagram (W5 batches; 1 otherwise).
    pub frames_per_datagram: u32,
    /// Datagrams per message (W6 fragments; 1 otherwise).
    pub datagrams_per_message: u32,
    /// Whether the `EXT` extension is present (W9).
    pub ext: bool,
    /// The MTU of the point.
    pub mtu: u32,
}

impl Shape {
    /// The frame budget used by the W4 formula: `align_down(mtu - E_max, 32)`.
    /// The manifest fixes `L` for every profile under either rule (6.1:
    /// "the same `L` still applies"), so the formula always subtracts
    /// `E_max`.
    fn full_frame(mtu: u32, e_max: u32) -> Result<u32, ManifestError> {
        MtuRule::CountsEnvelope
            .frame_budget(mtu, e_max)
            .map(align_down)
    }

    /// The message size at `e_max` under `rule` (manifest 6.1).
    ///
    /// Resolutions where the manifest text is silent, each recorded in the
    /// B1 report:
    /// - W7 applies the W4 rule at MTU 8192:
    ///   `align_down(8192 - E_max, 32) - 32`.
    /// - W9 with base W4 keeps one full frame and gives the 64 extension
    ///   bytes back: `align_down(1408 - E_max, 32) - 96`.
    ///
    /// # Errors
    ///
    /// [`ManifestError::EnvelopeTooLarge`] when `e_max` leaves no frame
    /// room, [`ManifestError::W6DatagramCount`] when W6 takes a count other
    /// than manifest 2.0 6.1 states (5, or 6 for E from 161 to 176 when
    /// `mtu` counts the envelope), [`ManifestError::NoSizeFormula`] for W8.
    pub fn size(self, e_max: u32, rule: MtuRule) -> Result<Size, ManifestError> {
        let single = |payload: u32, ext: bool, mtu: u32| Size {
            payload,
            frames_per_datagram: 1,
            datagrams_per_message: 1,
            ext,
            mtu,
        };
        // Every size is checked against the budget of the rule.
        rule.frame_budget(MTU, e_max)?;
        match self {
            Self::W1 => Ok(single(32, false, MTU)),
            Self::W2 => Ok(single(0, false, MTU)),
            Self::W3 => Ok(single(256, false, MTU)),
            Self::W4 => Ok(single(w4_payload(e_max)?, false, MTU)),
            Self::W5 => Ok(Size {
                payload: 32,
                frames_per_datagram: w5_frames(e_max)?,
                datagrams_per_message: 1,
                ext: false,
                mtu: MTU,
            }),
            Self::W6 => {
                // Manifest 2.0 6.1: the fragment plan's count, 5 datagrams,
                // or 6 for E from 161 to 176 when `mtu` counts the envelope.
                let datagrams = w6_datagrams(e_max, rule)?;
                // W6 is defined only up to E_max 176, under either rule.
                if e_max <= W6_E_MAX_LIMIT
                    && (datagrams == W6_DATAGRAMS || datagrams == W6_DATAGRAMS + 1)
                {
                    Ok(Size {
                        payload: W6_LENGTH,
                        frames_per_datagram: 1,
                        datagrams_per_message: datagrams,
                        ext: false,
                        mtu: MTU,
                    })
                } else {
                    Err(ManifestError::W6DatagramCount {
                        e_max,
                        rule,
                        datagrams,
                    })
                }
            }
            Self::W7 => {
                let frame = Self::full_frame(JUMBO_MTU, e_max)?;
                Ok(single(frame - HEADER, false, JUMBO_MTU))
            }
            Self::W8(_) => Err(ManifestError::NoSizeFormula(self)),
            Self::W9(ExtBase::W1) => Ok(single(32, true, MTU)),
            Self::W9(ExtBase::W4) => {
                let frame = Self::full_frame(MTU, e_max)?;
                let header = Flags::new(false, false, false, true, karyos_sys::frame::Lane::ZERO)
                    .header_length();
                match frame.checked_sub(header) {
                    Some(payload) if payload > 0 => Ok(single(payload, true, MTU)),
                    _ => Err(ManifestError::EnvelopeTooLarge { e_max, mtu: MTU }),
                }
            }
        }
    }
}

impl fmt::Display for Shape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::W1 => f.write_str("W1"),
            Self::W2 => f.write_str("W2"),
            Self::W3 => f.write_str("W3"),
            Self::W4 => f.write_str("W4"),
            Self::W5 => f.write_str("W5"),
            Self::W6 => f.write_str("W6"),
            Self::W7 => f.write_str("W7"),
            Self::W8(index) => write!(f, "W8.{index}"),
            Self::W9(ExtBase::W1) => f.write_str("W9-W1"),
            Self::W9(ExtBase::W4) => f.write_str("W9-W4"),
        }
    }
}

/// W4: `L = align_down(1408 - E_max, 32) - 32` (manifest 6.1, W4).
///
/// # Errors
///
/// [`ManifestError::EnvelopeTooLarge`] when no frame fits.
pub fn w4_payload(e_max: u32) -> Result<u32, ManifestError> {
    Shape::full_frame(MTU, e_max).map(|frame| frame - HEADER)
}

/// W5: `floor((1408 - E_max) / 64)` frames of `L` = 32 (manifest 6.1, W5).
///
/// # Errors
///
/// [`ManifestError::EnvelopeTooLarge`] when no 64-byte frame fits.
pub fn w5_frames(e_max: u32) -> Result<u32, ManifestError> {
    match MTU.checked_sub(e_max).map(|budget| budget / 64) {
        Some(frames) if frames > 0 => Ok(frames),
        _ => Err(ManifestError::EnvelopeTooLarge { e_max, mtu: MTU }),
    }
}

/// The fragment payload `c` of W6 under `rule`, with the fragment plan of
/// SPEC §4 (`karyos_sys::sizing::FragmentPlan`): `c = align_down(budget,
/// 32) - 32`, where the budget is `1408 - E_max` when `mtu` counts the
/// envelope and 1408 otherwise.
///
/// # Errors
///
/// [`ManifestError::EnvelopeTooLarge`] when no frame fits.
pub fn w6_fragment_payload(e_max: u32, rule: MtuRule) -> Result<u32, ManifestError> {
    let budget = rule.frame_budget(MTU, e_max)?;
    FragmentPlan::new(budget, Flags::NONE)
        .map(FragmentPlan::payload_per_fragment)
        .map_err(|_| ManifestError::EnvelopeTooLarge { e_max, mtu: MTU })
}

/// The datagrams of one W6 message (`L` = 6000) under `rule`, with the
/// fragment plan of SPEC §4.
///
/// The fragment plan aligns the frame budget down to 32 bytes
/// (`FragmentPlan::new`), so under [`MtuRule::CountsEnvelope`] an envelope
/// of 161 to 176 bytes gives `c` = 1184 and 6 datagrams, and any smaller
/// one 5, as manifest 2.0 6.1 states; without the envelope in the MTU it
/// is always 5. [`Shape::size`] refuses W6 above `E_max` 176.
///
/// # Errors
///
/// [`ManifestError::EnvelopeTooLarge`] when no frame fits.
pub fn w6_datagrams(e_max: u32, rule: MtuRule) -> Result<u32, ManifestError> {
    let budget = rule.frame_budget(MTU, e_max)?;
    let plan = FragmentPlan::new(budget, Flags::NONE)
        .map_err(|_| ManifestError::EnvelopeTooLarge { e_max, mtu: MTU })?;
    Ok(plan.fragments(W6_LENGTH))
}

/// The W6 datagram count of the manifest's own arithmetic (6.1, W6):
/// `c = 1376 - E_max` under [`MtuRule::CountsEnvelope`], 1376 otherwise,
/// with no alignment of `c`.
#[must_use]
pub fn w6_datagrams_manifest_arithmetic(e_max: u32, rule: MtuRule) -> Option<u32> {
    let c = match rule {
        MtuRule::CountsEnvelope => (MTU - HEADER).checked_sub(e_max)?,
        MtuRule::ExcludesEnvelope => MTU - HEADER,
    };
    (c > 0).then(|| W6_LENGTH.div_ceil(c))
}

/// The bytes W6 reserves in a 64 KiB term under `rule`; the manifest
/// requires it under the 8192-byte limit (6.1, W6).
///
/// # Errors
///
/// [`ManifestError::EnvelopeTooLarge`] when no frame fits.
pub fn w6_reserved(e_max: u32, rule: MtuRule) -> Result<u32, ManifestError> {
    let budget = rule.frame_budget(MTU, e_max)?;
    let too_large = ManifestError::EnvelopeTooLarge { e_max, mtu: MTU };
    FragmentPlan::new(budget, Flags::NONE)
        .and_then(|plan| plan.reserved(W6_LENGTH))
        .map_err(|_| too_large)
}

/// `max_message_length` at 64 KiB terms under `rule`, one of the MTU
/// overhead figures reported by manifest 6.2.
///
/// # Errors
///
/// [`ManifestError::EnvelopeTooLarge`] when no frame fits.
pub fn max_message_length_64k(e_max: u32, rule: MtuRule) -> Result<u32, ManifestError> {
    let budget = rule.frame_budget(MTU, e_max)?;
    let too_large = ManifestError::EnvelopeTooLarge { e_max, mtu: MTU };
    let term = TermLength::try_new(64 * 1024).map_err(|_| too_large.clone())?;
    FragmentPlan::new(budget, Flags::NONE)
        .and_then(|plan| plan.max_message_length(term.max_reserved_limit(), term))
        .map_err(|_| too_large)
}

/// The loads R1 to R5 (manifest 6.1, second table).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Load {
    /// R1: closed loop, one message in flight.
    R1,
    /// R2: open loop at `rate` messages per second, scheduled.
    R2 {
        /// Messages per second: [`RATE_100K`] or [`RATE_1M`].
        rate: u32,
    },
    /// R3: saturation, reported only.
    R3,
    /// R4: R2 at `rate` plus invalid tags at `invalid_percent` of it.
    R4 {
        /// The valid rate.
        rate: u32,
        /// 10 or 100.
        invalid_percent: u8,
    },
    /// R5: R2 at `rate` across one in-band and one file epoch change.
    R5 {
        /// The rate.
        rate: u32,
    },
}

impl Load {
    /// Whether the parameters are values of manifest 6.1: R2, R4 and R5
    /// rates of the R2 table (100 000 or 1 000 000 per second) and R4
    /// invalid tags at 10% or 100%.
    #[must_use]
    pub const fn is_manifest(self) -> bool {
        const fn rate_ok(rate: u32) -> bool {
            rate == RATE_100K || rate == RATE_1M
        }
        match self {
            Self::R1 | Self::R3 => true,
            Self::R2 { rate } | Self::R5 { rate } => rate_ok(rate),
            Self::R4 {
                rate,
                invalid_percent,
            } => rate_ok(rate) && (invalid_percent == 10 || invalid_percent == 100),
        }
    }
}

impl fmt::Display for Load {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::R1 => f.write_str("R1"),
            Self::R2 { rate } => write!(f, "R2@{rate}"),
            Self::R3 => f.write_str("R3"),
            Self::R4 {
                rate,
                invalid_percent,
            } => write!(f, "R4@{rate}+{invalid_percent}%"),
            Self::R5 { rate } => write!(f, "R5@{rate}"),
        }
    }
}

/// The fan-outs F1 and F2 (manifest 6.1, third table).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Fanout {
    /// F1: unicast, one receiver.
    F1,
    /// F2: multicast with 1, 4 or 16 receivers.
    F2 {
        /// The receiver count.
        receivers: u8,
    },
}

impl Fanout {
    /// Whether the receiver count is a value of manifest 6.1 (F2: 1, 4 or
    /// 16).
    #[must_use]
    pub const fn is_manifest(self) -> bool {
        match self {
            Self::F1 => true,
            Self::F2 { receivers } => matches!(receivers, 1 | 4 | 16),
        }
    }

    /// The receiver count.
    #[must_use]
    pub const fn receivers(self) -> u8 {
        match self {
            Self::F1 => 1,
            Self::F2 { receivers } => receivers,
        }
    }
}

impl fmt::Display for Fanout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::F1 => f.write_str("F1"),
            Self::F2 { receivers } => write!(f, "F2x{receivers}"),
        }
    }
}

/// One operating point: a shape under a load on a fan-out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Point {
    /// The shape.
    pub shape: Shape,
    /// The load.
    pub load: Load,
    /// The fan-out.
    pub fanout: Fanout,
}

impl fmt::Display for Point {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}/{}", self.shape, self.load, self.fanout)
    }
}

impl Point {
    /// Whether this point is in the primary set (manifest 6.1).
    #[must_use]
    pub fn is_primary(&self) -> bool {
        primary().contains(self)
    }
}

/// The primary operating points (manifest 6.1, "Primary operating
/// points"): W1, W3, W4 and W5, each under R1 and R2 at 100 000 messages
/// per second, on F1 and on F2 with 4 receivers (16 points), plus R5 at W1
/// under R2 at 1 000 000 messages per second (17 in all).
///
/// The manifest does not name a fan-out for the R5 point; it is modelled
/// on F1, the unicast baseline (resolution recorded in the B1 report).
#[must_use]
pub fn primary() -> Vec<Point> {
    let mut points = Vec::with_capacity(17);
    for shape in [Shape::W1, Shape::W3, Shape::W4, Shape::W5] {
        for load in [Load::R1, Load::R2 { rate: RATE_100K }] {
            for fanout in [Fanout::F1, Fanout::F2 { receivers: 4 }] {
                points.push(Point {
                    shape,
                    load,
                    fanout,
                });
            }
        }
    }
    points.push(Point {
        shape: Shape::W1,
        load: Load::R5 { rate: RATE_1M },
        fanout: Fanout::F1,
    });
    points
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn w4_and_w5_match_the_manifest_example() {
        assert_eq!(w4_payload(64), Ok(1312));
        assert_eq!(w5_frames(64), Ok(21));
        for rule in MtuRule::ALL {
            let w4 = Shape::W4.size(64, rule).unwrap();
            assert_eq!(w4.payload, 1312);
            let w5 = Shape::W5.size(64, rule).unwrap();
            assert_eq!((w5.payload, w5.frames_per_datagram), (32, 21));
        }
        // The 32-byte variant fills the MTU exactly when mtu counts the
        // envelope: 1312 + 32 + 64 = 1408.
        assert_eq!(w4_payload(64).unwrap() + HEADER + 64, MTU);
        assert_eq!(w4_payload(0), Ok(1376));
    }

    #[test]
    fn w6_is_five_datagrams_under_the_manifest_arithmetic_for_every_e_max() {
        for e_max in 0..=W6_E_MAX_LIMIT {
            for rule in MtuRule::ALL {
                assert_eq!(
                    w6_datagrams_manifest_arithmetic(e_max, rule),
                    Some(5),
                    "E_max {e_max}, {rule}"
                );
            }
        }
    }

    #[test]
    fn w6_under_the_spec_fragment_plan() {
        // Exhaustive over 0..=176 and both rules. The aligned fragment
        // plan of SPEC §4 agrees with the manifest up to E_max = 160; under
        // CountsEnvelope, 161..=176 align the budget to 1216 and c to 1184,
        // so W6 takes 6 datagrams there, as manifest 2.0 6.1 states.
        for e_max in 0..=W6_E_MAX_LIMIT {
            for rule in MtuRule::ALL {
                let datagrams = w6_datagrams(e_max, rule).unwrap();
                let c = w6_fragment_payload(e_max, rule).unwrap();
                assert!(w6_reserved(e_max, rule).unwrap() < 8192);
                let expect_five = rule == MtuRule::ExcludesEnvelope || e_max <= 160;
                if expect_five {
                    assert_eq!(datagrams, 5, "E_max {e_max}, {rule}");
                    assert!((1200..=1376).contains(&c), "c {c}");
                    assert!(4 * c < W6_LENGTH && W6_LENGTH <= 5 * c);
                    let size = Shape::W6.size(e_max, rule).unwrap();
                    assert_eq!(size.datagrams_per_message, 5);
                } else {
                    assert_eq!((datagrams, c), (6, 1184), "E_max {e_max}");
                    // Manifest 2.0 6.1 states this count.
                    let size = Shape::W6.size(e_max, rule).unwrap();
                    assert_eq!(size.datagrams_per_message, 6);
                }
            }
        }
    }

    #[test]
    fn max_message_length_matches_the_manifest_example() {
        // Manifest 6.1: with mtu counting a 64-byte envelope, c = 1312 and
        // max_message_length at 64 KiB terms falls to 7968 bytes.
        assert_eq!(w6_fragment_payload(64, MtuRule::CountsEnvelope), Ok(1312));
        assert_eq!(
            max_message_length_64k(64, MtuRule::CountsEnvelope),
            Ok(7968)
        );
    }

    #[test]
    fn the_primary_set_has_seventeen_points() {
        let points = primary();
        assert_eq!(points.len(), 17);
        let mut unique = points.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), 17);
        assert_eq!(
            points
                .iter()
                .filter(|p| matches!(p.fanout, Fanout::F2 { .. }))
                .count(),
            8
        );
        assert!(points.iter().all(Point::is_primary));
        let r5 = Point {
            shape: Shape::W1,
            load: Load::R5 { rate: RATE_1M },
            fanout: Fanout::F1,
        };
        assert!(r5.is_primary());
        let reported = Point {
            shape: Shape::W2,
            load: Load::R1,
            fanout: Fanout::F1,
        };
        assert!(!reported.is_primary());
    }

    #[test]
    fn other_sizes() {
        let rule = MtuRule::CountsEnvelope;
        assert_eq!(Shape::W1.size(64, rule).unwrap().payload, 32);
        assert_eq!(Shape::W2.size(64, rule).unwrap().payload, 0);
        assert_eq!(Shape::W3.size(64, rule).unwrap().payload, 256);
        let w7 = Shape::W7.size(64, rule).unwrap();
        assert_eq!((w7.payload, w7.mtu), (8096, JUMBO_MTU));
        let w9 = Shape::W9(ExtBase::W4).size(64, rule).unwrap();
        assert_eq!((w9.payload, w9.ext), (1248, true));
        assert!(matches!(
            Shape::W8(0).size(64, rule),
            Err(ManifestError::NoSizeFormula(_))
        ));
        assert!(Shape::W1.size(1400, rule).is_err());
    }

    #[test]
    fn e_max_labels() {
        assert!(!EMax::Provisional(64).is_decided());
        assert!(EMax::Decided(64).is_decided());
        assert!(EMax::Provisional(64).to_string().contains("provisional"));
        assert_eq!(EMax::Decided(48).bytes(), 48);
    }

    #[test]
    fn version_and_hash() {
        assert_eq!(VERSION, "2.0");
        assert!(is_sha256_hex(MANIFEST_1_0_SHA256));
        assert_eq!(
            MANIFEST_SHA256,
            "67855e81f0ae526559f4dde470f6ab8b1dac7d5e939aa870a3e46a386a1c4dea"
        );
        assert!(manifest_hash_is_final());
        assert!(!is_sha256_hex("PENDING"));
        assert!(!is_sha256_hex(&"A".repeat(64)));
    }
}
