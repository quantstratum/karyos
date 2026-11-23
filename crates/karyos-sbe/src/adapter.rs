// SPDX-License-Identifier: Apache-2.0

//! The SBE feed adapter (karyos#647): one SBE feed published on two lines,
//! framed by its SBE message header and arbitrated by [`karyos_feed`].
//!
//! The surface, confirmed against SPEC §7.2 and §10.1, ADR-0052 and
//! `quantstratum-docs: karyos/design/feed-arbitration.md` sections 1 and 2:
//!
//! - **The feed's extractor is the feed's.** The arbitration needs each
//!   message's epoch and sequence ("`karyos-feed` adapts external A/B feeds
//!   through a feed-specific sequence and epoch extractor", SPEC §7.2).
//!   Where a venue keeps them (a packet header, a field of every message, a
//!   session identifier mapped onto an increasing epoch) is the venue's, so
//!   the adapter takes them through [`SbeSequence`]. Venue mappings live in
//!   the feed handlers of the product layers, not in the core
//!   (`product-requirements-on-core.md`, "The kits' own work is not here").
//! - **The adapter frames; the client decodes.** A message is delivered
//!   only when its SBE message header names the feed's schema and a version
//!   this build reads ([`SbeSchema`]); any other frame is refused and
//!   counted, never handed to the sequence or the client (SPEC §13, "SBE
//!   interoperability": unknown versions are rejected, never reinterpreted).
//!   The delivered event carries the header and the frame, borrowed, so the
//!   client decodes it in place with its generated codecs (SPEC §10.1: SBE
//!   adds no copy).
//! - **The arbitration is unchanged.** Each sequenced message is delivered
//!   once, in order, from the line that brought it first; gaps, jumps and
//!   epoch changes are reported as [`karyos_feed`] reports them. The
//!   adapter is pure like the arbiter: no socket, no Karyos subscription, no
//!   clock. The client reads its two lines, from Karyos subscriptions or
//!   elsewhere, and pushes each message with its line and the current time.
//!   Recovery beyond the two lines (a retransmission request, a snapshot)
//!   stays the feed's (`feed-arbitration.md` section 1); the adapter offers
//!   the arbiter's position and resync.
//! - **Steady cycles allocate nothing.** The arbiter's buffer is allocated
//!   when the adapter is built, and framing reads the header in place.
//!
//! Registering a feed's schema in Archive manifests and recording groups
//! (SPEC §10.1, §8.3) is not here: it follows with the Archive in phase 3,
//! milestone M03 (SPEC §15, "manifest registration follows with the Archive
//! in phase 3"), and nothing in this module records a schema anywhere.

use std::num::NonZeroU64;

use ironsbe_core::header::MessageHeader;
use karyos_feed::{
    Arbiter, ArbiterConfig, ConfigError, Counters, Event, FeedSequencer, Identity, Line,
};

/// The SBE schema a feed's messages are framed by: its identifier and the
/// highest version this build reads. Versions `0..=max_version` are read;
/// a higher one is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SbeSchema {
    /// The schema's identifier in the SBE message header.
    pub schema_id: u16,
    /// The highest schema version this build reads.
    pub max_version: u16,
}

impl SbeSchema {
    /// The message header of `frame` when it names this schema and a
    /// version this build reads; `None` for a frame shorter than the
    /// header, another schema or an unknown version.
    #[must_use]
    pub fn frame(&self, frame: &[u8]) -> Option<MessageHeader> {
        if frame.len() < MessageHeader::ENCODED_LENGTH {
            return None;
        }
        let header = MessageHeader::wrap(frame, 0);
        (header.schema_id == self.schema_id && header.version <= self.max_version).then_some(header)
    }
}

/// Where a feed keeps each SBE message's epoch and sequence: the feed's
/// extractor (SPEC §7.2), given a frame the schema already accepted.
pub trait SbeSequence {
    /// The message's identity, or `None` for a message outside the
    /// sequence (a heartbeat, an administrative message), which is counted
    /// as `unsequenced` and not delivered.
    fn identity(&self, header: &MessageHeader, frame: &[u8]) -> Option<Identity>;

    /// The sequence space when the sequence wraps, at least 5; `None` when
    /// it never does.
    fn sequence_modulus(&self) -> Option<NonZeroU64> {
        None
    }

    /// The first sequence of `epoch` when the feed defines one.
    fn epoch_start(&self, epoch: u64) -> Option<u64> {
        let _ = epoch;
        None
    }
}

/// The [`FeedSequencer`] of an SBE feed: frames each message by `schema`,
/// then asks the feed's [`SbeSequence`].
#[derive(Debug, Clone)]
pub struct SbeSequencer<S> {
    schema: SbeSchema,
    sequence: S,
}

impl<S> SbeSequencer<S> {
    /// The sequencer of `schema`'s messages, sequenced by `sequence`.
    #[must_use]
    pub const fn new(schema: SbeSchema, sequence: S) -> Self {
        Self { schema, sequence }
    }
}

impl<S: SbeSequence> FeedSequencer for SbeSequencer<S> {
    fn identity(&self, message: &[u8]) -> Option<Identity> {
        let header = self.schema.frame(message)?;
        self.sequence.identity(&header, message)
    }

    fn sequence_modulus(&self) -> Option<NonZeroU64> {
        self.sequence.sequence_modulus()
    }

    fn epoch_start(&self, epoch: u64) -> Option<u64> {
        self.sequence.epoch_start(epoch)
    }
}

/// What the adapter reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbeEvent<'a> {
    /// A sequenced SBE message, once and in order, from the line that
    /// brought it first.
    Message {
        /// The line that brought it first.
        line: Line,
        /// Its identity.
        identity: Identity,
        /// Its SBE message header.
        header: MessageHeader,
        /// The whole frame, header included, borrowed for the callback
        /// only: decode it in place with the schema's codecs.
        frame: &'a [u8],
    },
    /// `count` sequences from `from` are declared lost: neither line
    /// brought them in time.
    Gap {
        /// The epoch.
        epoch: u64,
        /// The first lost sequence.
        from: u64,
        /// How many sequences are lost.
        count: u64,
    },
    /// A message at or beyond the window from the next sequence, dropped.
    Jump {
        /// The line that brought it.
        line: Line,
        /// Its identity.
        identity: Identity,
    },
    /// A larger epoch started.
    EpochChange {
        /// The epoch that ended.
        from: u64,
        /// The epoch that started.
        to: u64,
    },
}

/// The adapter's counters: the arbiter's, and the frames refused before
/// arbitration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SbeCounters {
    /// The arbiter's counters.
    pub feed: Counters,
    /// Frames shorter than the SBE message header, of another schema, or
    /// of a schema version this build does not read: never delivered.
    pub refused: u64,
}

/// One SBE feed on two lines, framed and arbitrated: each sequenced
/// message once, in order, with its SBE header.
#[derive(Debug)]
pub struct SbeFeed<S: SbeSequence> {
    arbiter: Arbiter<SbeSequencer<S>>,
    schema: SbeSchema,
    refused: u64,
}

impl<S: SbeSequence> SbeFeed<S> {
    /// The adapter of `schema`'s feed, sequenced by `sequence`, its
    /// arbiter's buffer allocated now.
    ///
    /// # Errors
    ///
    /// The arbiter's [`ConfigError`].
    pub fn new(schema: SbeSchema, sequence: S, config: ArbiterConfig) -> Result<Self, ConfigError> {
        Ok(Self {
            arbiter: Arbiter::new(SbeSequencer::new(schema, sequence), config)?,
            schema,
            refused: 0,
        })
    }

    /// Takes `frame` from `line` at the caller's time `now` and reports
    /// what it releases to `emit`. A frame the schema refuses is counted
    /// and goes no further.
    pub fn push<F: FnMut(SbeEvent<'_>)>(
        &mut self,
        line: Line,
        frame: &[u8],
        now: u64,
        mut emit: F,
    ) {
        if self.schema.frame(frame).is_none() {
            self.refused = self.refused.saturating_add(1);
            return;
        }
        let schema = self.schema;
        self.arbiter
            .push(line, frame, now, |event| forward(schema, event, &mut emit));
    }

    /// Declares the holes the skew window has passed at `now` and reports
    /// what that releases to `emit`.
    pub fn poll<F: FnMut(SbeEvent<'_>)>(&mut self, now: u64, mut emit: F) {
        let schema = self.schema;
        self.arbiter
            .poll(now, |event| forward(schema, event, &mut emit));
    }

    /// States that the client's state is current up to `position`, after a
    /// snapshot (`feed-arbitration.md` section 6), and reports what that
    /// releases to `emit`.
    pub fn resync<F: FnMut(SbeEvent<'_>)>(&mut self, position: Identity, now: u64, mut emit: F) {
        let schema = self.schema;
        self.arbiter
            .resync(position, now, |event| forward(schema, event, &mut emit));
    }

    /// The epoch and next sequence to deliver, once synchronised.
    #[must_use]
    pub fn position(&self) -> Option<Identity> {
        self.arbiter.position()
    }

    /// The counters so far.
    #[must_use]
    pub const fn counters(&self) -> SbeCounters {
        SbeCounters {
            feed: self.arbiter.counters(),
            refused: self.refused,
        }
    }
}

/// `event` as the adapter reports it. A delivered message passed the
/// schema when it was pushed, so its header is read again in place.
fn forward<F: FnMut(SbeEvent<'_>)>(schema: SbeSchema, event: Event<'_>, emit: &mut F) {
    match event {
        Event::Message {
            line,
            identity,
            bytes,
        } => {
            if let Some(header) = schema.frame(bytes) {
                emit(SbeEvent::Message {
                    line,
                    identity,
                    header,
                    frame: bytes,
                });
            }
        }
        Event::Gap { epoch, from, count } => emit(SbeEvent::Gap { epoch, from, count }),
        Event::Jump { line, identity } => emit(SbeEvent::Jump { line, identity }),
        Event::EpochChange { from, to } => emit(SbeEvent::EpochChange { from, to }),
    }
}
