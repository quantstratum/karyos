// SPDX-License-Identifier: Apache-2.0

//! SBE 1.0 integration for Karyos (SPEC §10.1; ADR-0052; karyos#631).
//!
//! The SBE framing and the client feed adapters live here and only here:
//! the adapters plug into [`karyos_feed`]'s A/B arbitration, so this crate
//! depends on `karyos-feed` and never the reverse. IronSBE, admitted for
//! this crate alone (quantstratum-docs:
//! karyos/reviews/dependency-admission-ironsbe.md), enters through it with
//! its codec crates only: its transport, server and client never reach the
//! Karyos data plane, since Karyos is the transport (SPEC §18, X17).
//! `make sbe-graph-check` keeps both rules.
//!
//! The framing (karyos#646): [`car`] holds the codecs IronSBE's generator
//! writes at build time from public SBE 1.0 schemas, Real Logic's example
//! `Car` at schema version 0 and 1 (`schemas/`, SBE tag 1.42.0). Their
//! encoders write a message into a caller's buffer and their decoders read
//! it in place, borrowing the frame and allocating nothing. [`decode_car`]
//! frames a received message: it reads the SBE message header first and
//! refuses a schema, a schema version or a template this build does not
//! know with a typed [`FrameError`], never reading such a message as a
//! known one.
//!
//! The feed adapter (karyos#647): [`adapter::SbeFeed`] takes one SBE feed on
//! its two lines, frames each message by its SBE header against the feed's
//! [`adapter::SbeSchema`], reads its epoch and sequence through the feed's
//! [`adapter::SbeSequence`], and arbitrates the lines with
//! [`karyos_feed`]: each sequenced message once, in order, its header and
//! frame borrowed for the client to decode in place. Registering schemas
//! in Archive manifests is not here: it follows with the Archive in M03.
//!
//! Internal to the Karyos workspace and unstable in alpha, with no
//! compatibility promise. The supported API is the `karyos` facade,
//! `karyos-client` and `karyos-archive`, and the C ABI of `karyos-ffi`
//! under its own `0.y.z` rule.

#![forbid(unsafe_code)]

/// The feed arbitration the SBE adapters plug into (SPEC §7.2).
pub use karyos_feed as feed;

pub mod adapter;

use ironsbe_core::decoder::{DecodeError, SbeDecoder};
use ironsbe_core::header::MessageHeader;

/// The codecs of Real Logic's example `Car` schema, generated at build time
/// by IronSBE (`build.rs`) from `schemas/`.
pub mod car {
    /// Schema version 0 (`schemas/example-schema.xml`).
    pub mod v0 {
        include!(concat!(env!("OUT_DIR"), "/car_v0.rs"));
    }

    /// Schema version 1 (`schemas/example-extension-schema.xml`): version 0
    /// with `uuid` and `cupHolderCount` added to `Car`. Its decoders read a
    /// version 0 message too, with the added fields absent.
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/car_v1.rs"));
    }
}

/// The `Car` schema's identifier in the SBE message header.
pub const CAR_SCHEMA_ID: u16 = 1;

/// The highest `Car` schema version this build reads; versions 0 to it are
/// known.
pub const CAR_SCHEMA_VERSION: u16 = 1;

/// The `Car` message's template identifier.
pub const CAR_TEMPLATE_ID: u16 = 1;

/// Why a frame is not a message this build reads.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FrameError {
    /// Shorter than the SBE message header.
    #[error("a frame of {length} bytes is shorter than the SBE message header")]
    Truncated {
        /// The frame's length.
        length: usize,
    },
    /// The header names another schema.
    #[error("schema {schema_id} is not the Car schema ({CAR_SCHEMA_ID})")]
    UnknownSchema {
        /// The schema the header names.
        schema_id: u16,
    },
    /// The header names a version of the schema this build does not know:
    /// refused, never read as a known version (SPEC §13, "SBE
    /// interoperability").
    #[error(
        "Car schema version {version} is not known: this build reads 0 to {CAR_SCHEMA_VERSION}"
    )]
    UnknownVersion {
        /// The version the header names.
        version: u16,
    },
    /// The header names a template the schema does not define.
    #[error("template {template_id} is not a message of the Car schema")]
    UnknownTemplate {
        /// The template the header names.
        template_id: u16,
    },
    /// The frame ends inside the message: its repeating groups, nested
    /// groups and variable data reach past the frame.
    #[error("the Car message needs {needed} bytes, the frame has {length}")]
    Incomplete {
        /// The bytes the message's variable section reaches.
        needed: usize,
        /// The frame's length.
        length: usize,
    },
    /// The message does not decode.
    #[error("the Car message does not decode: {0:?}")]
    Decode(DecodeError),
}

/// Frames `frame` as a `Car` message and decodes it in place, borrowing
/// `frame` and allocating nothing. A message of version 0 is read with the
/// version 1 codecs, the fields version 1 added absent.
///
/// # Errors
///
/// [`FrameError::Truncated`] for a frame shorter than the message header,
/// [`FrameError::UnknownSchema`], [`FrameError::UnknownVersion`] and
/// [`FrameError::UnknownTemplate`] for a header this build does not know,
/// checked before the message is read, [`FrameError::Incomplete`] for a
/// frame that ends inside the message's variable section, and
/// [`FrameError::Decode`] for a message that does not decode, a bound of
/// its groups or variable data included.
pub fn decode_car(frame: &[u8]) -> Result<car::v1::CarDecoder<'_>, FrameError> {
    if frame.len() < MessageHeader::ENCODED_LENGTH {
        return Err(FrameError::Truncated {
            length: frame.len(),
        });
    }
    let header = MessageHeader::wrap(frame, 0);
    if header.schema_id != CAR_SCHEMA_ID {
        return Err(FrameError::UnknownSchema {
            schema_id: header.schema_id,
        });
    }
    if header.version > CAR_SCHEMA_VERSION {
        return Err(FrameError::UnknownVersion {
            version: header.version,
        });
    }
    if header.template_id != CAR_TEMPLATE_ID {
        return Err(FrameError::UnknownTemplate {
            template_id: header.template_id,
        });
    }
    let car = car::v1::CarDecoder::decode(frame).map_err(FrameError::Decode)?;
    // The whole variable section, every group, nested group and var data
    // field, is walked with checked bounds before the message is handed
    // out, so a frame cut anywhere inside it is refused, not read in part
    // (Codex review of #1197). The walk reads lengths in place and
    // allocates nothing.
    let needed = car.encoded_length().map_err(FrameError::Decode)?;
    if needed > frame.len() {
        return Err(FrameError::Incomplete {
            needed,
            length: frame.len(),
        });
    }
    Ok(car)
}
