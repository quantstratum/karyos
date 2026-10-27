// SPDX-License-Identifier: Apache-2.0

//! A/B arbitration for external exchange feeds (`quantstratum-docs:
//! karyos/design/feed-arbitration.md`; SPEC §7.2; karyos#659).
//!
//! An exchange publishes one feed on two lines, A and B. An [`Arbiter`]
//! turns them into one stream: each sequenced message once, in sequence
//! order, from whichever line brought it first. A message missing on one
//! line is repaired from the other; one missing on both is reported as a
//! [`Event::Gap`]. Each feed supplies its [`FeedSequencer`], which reads a
//! message's epoch (the feed's session) and sequence, so a session reset is
//! an epoch change the feed states, never inferred, and a sequence wrap is
//! ordinary serial arithmetic (RFC 1982).
//!
//! The arbiter is pure: no socket, no Karyos subscription, no clock. The
//! caller pushes each message with its line and the current time and
//! receives [`Event`]s through a callback. The reorder buffer is allocated
//! when the arbiter is built, so a steady cycle allocates nothing.
//!
//! Internal to the Karyos workspace and unstable in alpha, with no
//! compatibility promise. The supported API is the `karyos` facade,
//! `karyos-client` and `karyos-archive`, and the C ABI of `karyos-ffi`
//! under its own `0.y.z` rule.

use std::num::NonZeroU64;

/// One of the feed's two lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Line {
    /// Line A.
    A,
    /// Line B.
    B,
}

impl Line {
    const fn index(self) -> usize {
        match self {
            Self::A => 0,
            Self::B => 1,
        }
    }
}

/// Where a message sits in its feed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Identity {
    /// The feed's session: it changes at a session reset and only
    /// increases.
    pub epoch: u64,
    /// The message's sequence in its epoch.
    pub sequence: u64,
}

/// What the arbiter needs from a feed (design section 2).
pub trait FeedSequencer {
    /// The message's identity, or `None` for a message outside the
    /// sequence (a heartbeat, an administrative message), which is counted
    /// as `unsequenced` and not delivered.
    fn identity(&self, message: &[u8]) -> Option<Identity>;

    /// The sequence space when the sequence wraps, at least 5; `None` when
    /// it never does (a `u64` that only grows). A sequence at or above the
    /// modulus is a [`Event::Jump`].
    fn sequence_modulus(&self) -> Option<NonZeroU64>;

    /// The first sequence of `epoch` when the feed defines one; `None`
    /// makes the first message seen in a new epoch its start.
    fn epoch_start(&self, epoch: u64) -> Option<u64> {
        let _ = epoch;
        None
    }
}

/// What the arbiter reports (design section 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event<'a> {
    /// A sequenced message, once and in order, from the line that brought
    /// it first.
    Message {
        /// The line that brought it first.
        line: Line,
        /// Its identity.
        identity: Identity,
        /// Its bytes, borrowed for the callback only.
        bytes: &'a [u8],
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
    /// A message at or beyond the window from the next sequence: not an
    /// advance and never a reset; dropped.
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

/// How an arbiter joins its feed (design section 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Start {
    /// Synchronised on the first sequenced message it sees.
    #[default]
    AtFirst,
    /// Holds messages and delivers nothing until [`Arbiter::resync`], for
    /// a consumer that recovers through a snapshot. The buffer is anchored
    /// at the first sequenced message seen: later ones are held, the oldest
    /// discarded when it is full, and earlier ones arriving afterwards are
    /// late.
    AwaitingResync,
}

/// An arbiter's settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArbiterConfig {
    /// Messages the reorder buffer holds: a power of two, at least 1, and
    /// below the window.
    pub capacity: usize,
    /// The longest message the reorder buffer holds, in bytes. A longer
    /// one is delivered only when it is the next one.
    pub max_message_length: usize,
    /// How long, in the caller's nanoseconds, the first message held after
    /// a hole waits before the hole is declared a gap.
    pub skew_window: u64,
    /// How the arbiter joins its feed.
    pub start: Start,
}

/// Why an arbiter cannot be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigError {
    /// The capacity is 0 or not a power of two.
    Capacity,
    /// The capacity is not below the sequence window.
    CapacityAboveWindow,
    /// The modulus is below 5, whose window cannot hold a buffer of one.
    Modulus,
    /// The arena does not fit in memory.
    Arena,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Capacity => "the capacity must be a power of two",
            Self::CapacityAboveWindow => "the capacity must be below the sequence window",
            Self::Modulus => "the sequence modulus must be at least 5",
            Self::Arena => "capacity times max_message_length overflows",
        })
    }
}

impl std::error::Error for ConfigError {}

/// The arbiter's counters (design section 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Counters {
    /// Messages delivered.
    pub delivered: u64,
    /// Delivered messages line A brought first.
    pub wins_a: u64,
    /// Delivered messages line B brought first.
    pub wins_b: u64,
    /// Later copies on line A.
    pub duplicates_a: u64,
    /// Later copies on line B.
    pub duplicates_b: u64,
    /// Messages on line A behind the next sequence that were never
    /// delivered (declared lost, or too old to tell).
    pub late_a: u64,
    /// The same on line B.
    pub late_b: u64,
    /// Messages delivered from the reorder buffer.
    pub reordered: u64,
    /// Gaps declared.
    pub gaps: u64,
    /// Sequences the gaps cover.
    pub gap_messages: u64,
    /// Holes declared lost because the buffer was full.
    pub buffer_overflows: u64,
    /// Messages at or beyond the window.
    pub jumps: u64,
    /// Messages of an older epoch, dropped.
    pub stale_epoch: u64,
    /// Duplicates whose length differs from the first copy.
    pub length_conflicts: u64,
    /// Messages longer than a slot that could not be held.
    pub oversized: u64,
    /// Messages the extractor left outside the sequence.
    pub unsequenced: u64,
    /// Held messages a resync, or the wait for one, discarded.
    pub resync_discarded: u64,
}

/// A held message.
#[derive(Debug, Clone, Copy)]
struct Slot {
    held: bool,
    sequence: u64,
    line: Line,
    length: usize,
    arrived: u64,
}

/// A delivered sequence's length, for the conflict check.
#[derive(Debug, Clone, Copy)]
struct Delivered {
    valid: bool,
    /// Delivered, or declared lost.
    delivered: bool,
    sequence: u64,
    length: usize,
}

/// The sequence space: values `0..=max`, compared serially.
#[derive(Debug, Clone, Copy)]
struct Space {
    /// The modulus minus one, or `u64::MAX` without a modulus.
    max: u64,
}

impl Space {
    /// `to - from` in the space.
    const fn distance(self, from: u64, to: u64) -> u64 {
        if self.max == u64::MAX {
            to.wrapping_sub(from)
        } else if to >= from {
            to - from
        } else {
            // to + modulus - from, without overflow: max - (from - to) + 1.
            self.max - (from - to) + 1
        }
    }

    /// `from + by` in the space.
    const fn add(self, from: u64, by: u64) -> u64 {
        if self.max == u64::MAX {
            from.wrapping_add(by)
        } else {
            let room = self.max - from;
            if by <= room { from + by } else { by - room - 1 }
        }
    }

    /// The window: advances are below it, strictly less than half the
    /// space (design section 3).
    const fn window(self) -> u64 {
        self.max / 2
    }

    /// Whether `sequence` is inside the space.
    const fn contains(self, sequence: u64) -> bool {
        sequence <= self.max
    }
}

/// Where a message falls from the next sequence.
enum Place {
    Next,
    Ahead(u64),
    Behind(u64),
    Jump,
}

/// The arbiter's synchronised state.
#[derive(Debug, Clone, Copy)]
struct Running {
    epoch: u64,
    /// The next sequence to deliver.
    next: u64,
    /// The slot index of `next`, counted without wrapping the space.
    index: u64,
    /// Each line's highest sequence seen in the epoch.
    highest: [Option<u64>; 2],
    /// Holding for a resync: nothing is delivered and no gap declared.
    awaiting: bool,
}

/// The A/B arbiter of one feed.
#[derive(Debug)]
pub struct Arbiter<S> {
    sequencer: S,
    config: ArbiterConfig,
    space: Space,
    slots: Vec<Slot>,
    arena: Vec<u8>,
    history: Vec<Delivered>,
    held: usize,
    state: Option<Running>,
    /// A newer epoch that started on a line while the current one still
    /// had holes: its messages wait in the spare buffer, under their own
    /// base, until the current epoch closes (design section 6).
    pending: Option<Running>,
    spare_slots: Vec<Slot>,
    spare_arena: Vec<u8>,
    spare_history: Vec<Delivered>,
    spare_held: usize,
    counters: Counters,
}

impl<S: FeedSequencer> Arbiter<S> {
    /// An arbiter of `sequencer`'s feed, its buffer allocated now.
    ///
    /// # Errors
    ///
    /// A [`ConfigError`] for a capacity that is not a power of two or not
    /// below the window, a modulus below 4, or an arena that overflows.
    pub fn new(sequencer: S, config: ArbiterConfig) -> Result<Self, ConfigError> {
        let max = match sequencer.sequence_modulus() {
            Some(modulus) if modulus.get() < 5 => return Err(ConfigError::Modulus),
            Some(modulus) => modulus.get() - 1,
            None => u64::MAX,
        };
        let space = Space { max };
        if config.capacity == 0 || !config.capacity.is_power_of_two() {
            return Err(ConfigError::Capacity);
        }
        if u64::try_from(config.capacity).map_or(true, |capacity| capacity >= space.window()) {
            return Err(ConfigError::CapacityAboveWindow);
        }
        let bytes = config
            .capacity
            .checked_mul(config.max_message_length)
            .ok_or(ConfigError::Arena)?;
        let empty = Slot {
            held: false,
            sequence: 0,
            line: Line::A,
            length: 0,
            arrived: 0,
        };
        let none = Delivered {
            valid: false,
            delivered: false,
            sequence: 0,
            length: 0,
        };
        Ok(Self {
            sequencer,
            config,
            space,
            slots: vec![empty; config.capacity],
            arena: vec![0; bytes],
            history: vec![none; config.capacity],
            held: 0,
            state: None,
            pending: None,
            spare_slots: vec![empty; config.capacity],
            spare_arena: vec![0; bytes],
            spare_history: vec![none; config.capacity],
            spare_held: 0,
            counters: Counters::default(),
        })
    }

    /// The counters so far.
    #[must_use]
    pub const fn counters(&self) -> Counters {
        self.counters
    }

    /// The epoch and next sequence to deliver, once synchronised.
    #[must_use]
    pub fn position(&self) -> Option<Identity> {
        self.state.map(|state| Identity {
            epoch: state.epoch,
            sequence: state.next,
        })
    }

    /// Messages held, of the current epoch and of a newer one waiting.
    #[must_use]
    pub const fn held(&self) -> usize {
        self.held + self.spare_held
    }

    /// Takes `message` from `line` at the caller's time `now` and reports
    /// what it releases to `emit`.
    pub fn push<F: FnMut(Event<'_>)>(&mut self, line: Line, message: &[u8], now: u64, mut emit: F) {
        let Some(identity) = self.sequencer.identity(message) else {
            self.counters.unsequenced += 1;
            return;
        };
        if !self.space.contains(identity.sequence) {
            self.jump(line, identity, &mut emit);
            return;
        }
        let state = match self.state {
            None => {
                let state = Running {
                    epoch: identity.epoch,
                    next: identity.sequence,
                    index: 0,
                    highest: [None; 2],
                    awaiting: self.config.start == Start::AwaitingResync,
                };
                self.state = Some(state);
                state
            }
            Some(state) if identity.epoch < state.epoch => {
                self.counters.stale_epoch += 1;
                return;
            }
            Some(state) if identity.epoch > state.epoch => {
                if state.awaiting {
                    self.change_epoch(state, identity, &mut emit);
                    let Some(state) = self.state else { return };
                    state
                } else {
                    self.newer(line, identity, message, now, &mut emit);
                    self.advance(now, &mut emit);
                    return;
                }
            }
            Some(state) => state,
        };
        self.current(state, line, identity, message, now, &mut emit);
        self.advance(now, &mut emit);
    }

    /// A message of the current epoch.
    fn current<F: FnMut(Event<'_>)>(
        &mut self,
        state: Running,
        line: Line,
        identity: Identity,
        message: &[u8],
        now: u64,
        emit: &mut F,
    ) {
        match self.place(&state, identity.sequence) {
            Place::Jump => self.jump(line, identity, emit),
            Place::Behind(back) => {
                self.behind(&state, line, identity.sequence, back, message.len());
            }
            Place::Next => {
                self.see(line, identity.sequence);
                if state.awaiting {
                    self.hold(line, identity.sequence, message, now, 0);
                } else {
                    self.deliver_direct(line, identity, message, emit);
                }
            }
            Place::Ahead(ahead) => {
                self.see(line, identity.sequence);
                self.ahead(line, identity, message, now, ahead, emit);
            }
        }
    }

    /// A message of an epoch newer than the current one.
    fn newer<F: FnMut(Event<'_>)>(
        &mut self,
        line: Line,
        identity: Identity,
        message: &[u8],
        now: u64,
        emit: &mut F,
    ) {
        match self.pending {
            Some(pending) if identity.epoch > pending.epoch => {
                // A third epoch: the current one closes now, the waiting
                // one becomes current, and this message is newer again.
                self.close(emit);
                self.newer(line, identity, message, now, emit);
                return;
            }
            Some(_) => {}
            None => {
                let next = self
                    .sequencer
                    .epoch_start(identity.epoch)
                    .filter(|start| self.space.contains(*start))
                    .unwrap_or(identity.sequence);
                for entry in &mut self.spare_history {
                    entry.valid = false;
                }
                self.pending = Some(Running {
                    epoch: identity.epoch,
                    next,
                    index: 0,
                    highest: [None; 2],
                    awaiting: false,
                });
            }
        }
        let Some(pending) = self.pending else { return };
        let ahead = self.space.distance(pending.next, identity.sequence);
        let window = self.space.window();
        if ahead >= window {
            if self.space.distance(identity.sequence, pending.next) < window {
                // Behind the waiting epoch's start: never delivered.
                self.late(line);
            } else {
                self.jump(line, identity, emit);
            }
            return;
        }
        if ahead >= self.capacity() {
            // The spare buffer overflows: the current epoch closes as at an
            // overflow, and the message is handled in the new epoch.
            self.close(emit);
            if let Some(state) = self.state {
                self.current(state, line, identity, message, now, emit);
            }
            return;
        }
        let space = self.space;
        if let Some(highest) = self
            .pending
            .as_mut()
            .and_then(|pending| pending.highest.get_mut(line.index()))
        {
            let newer = highest.is_none_or(|seen| {
                let beyond = space.distance(seen, identity.sequence);
                beyond != 0 && beyond < window
            });
            if newer {
                *highest = Some(identity.sequence);
            }
        }
        let at = self.slot_of(pending.index.wrapping_add(ahead));
        let Some(slot) = self.spare_slots.get(at).copied() else {
            return;
        };
        if slot.held {
            match line {
                Line::A => self.counters.duplicates_a += 1,
                Line::B => self.counters.duplicates_b += 1,
            }
            if slot.length != message.len() {
                self.counters.length_conflicts += 1;
            }
            return;
        }
        if message.len() > self.config.max_message_length {
            self.counters.oversized += 1;
            return;
        }
        let start = at * self.config.max_message_length;
        if let Some(bytes) = self.spare_arena.get_mut(start..start + message.len()) {
            bytes.copy_from_slice(message);
        }
        if let Some(slot) = self.spare_slots.get_mut(at) {
            *slot = Slot {
                held: true,
                sequence: identity.sequence,
                line,
                length: message.len(),
                arrived: now,
            };
        }
        self.spare_held += 1;
    }

    /// Closes the current epoch at once: its held messages delivered, the
    /// holes between them declared lost; then a waiting epoch becomes
    /// current.
    fn close<F: FnMut(Event<'_>)>(&mut self, emit: &mut F) {
        while let Some(state) = self.state {
            let at = self.slot_of(state.index);
            let slot = self.slot(at);
            if slot.held && slot.sequence == state.next {
                self.deliver_held(at, emit);
                continue;
            }
            let Some((ahead, _)) = self.first_held(&state) else {
                break;
            };
            self.gap(ahead, emit);
        }
        self.promote(emit);
    }

    /// The waiting epoch becomes current; the current one has nothing held.
    fn promote<F: FnMut(Event<'_>)>(&mut self, emit: &mut F) {
        let (Some(state), Some(pending)) = (self.state, self.pending.take()) else {
            return;
        };
        emit(Event::EpochChange {
            from: state.epoch,
            to: pending.epoch,
        });
        std::mem::swap(&mut self.slots, &mut self.spare_slots);
        std::mem::swap(&mut self.arena, &mut self.spare_arena);
        std::mem::swap(&mut self.history, &mut self.spare_history);
        self.held = self.spare_held;
        self.spare_held = 0;
        self.state = Some(pending);
    }

    /// Ends holes whose skew window expired by `now`, for a caller with no
    /// message to push.
    pub fn poll<F: FnMut(Event<'_>)>(&mut self, now: u64, mut emit: F) {
        self.advance(now, &mut emit);
    }

    /// States that the consumer's state includes every message up to
    /// `position` (a snapshot's): deliveries resume after it. Held messages
    /// of another epoch, or at or before the position, are discarded and
    /// counted; held ones after it stay and are delivered in order once
    /// contiguous. An open hole is not declared a gap by the resync.
    pub fn resync<F: FnMut(Event<'_>)>(&mut self, position: Identity, now: u64, mut emit: F) {
        let next = self.space.add(position.sequence, 1);
        if self.pending.take().is_some() {
            for slot in &mut self.spare_slots {
                if slot.held {
                    slot.held = false;
                    self.counters.resync_discarded += 1;
                }
            }
            self.spare_held = 0;
        }
        match self.state {
            Some(state) if state.epoch == position.epoch => {
                // Keep the slot mapping: move the index with the sequence.
                let index = match self.place(&state, next) {
                    Place::Next => state.index,
                    Place::Ahead(ahead) => state.index.wrapping_add(ahead),
                    Place::Behind(back) => state.index.wrapping_sub(back),
                    Place::Jump => {
                        self.discard_all();
                        state.index
                    }
                };
                let moved = Running {
                    next,
                    index,
                    awaiting: false,
                    ..state
                };
                self.state = Some(moved);
                self.discard_outside(&moved);
            }
            _ => {
                self.discard_all();
                self.clear_history();
                self.state = Some(Running {
                    epoch: position.epoch,
                    next,
                    index: 0,
                    highest: [None; 2],
                    awaiting: false,
                });
            }
        }
        self.advance(now, &mut emit);
    }

    fn place(&self, state: &Running, sequence: u64) -> Place {
        let ahead = self.space.distance(state.next, sequence);
        let window = self.space.window();
        if ahead == 0 {
            Place::Next
        } else if ahead < window {
            Place::Ahead(ahead)
        } else {
            let back = self.space.distance(sequence, state.next);
            if back < window {
                Place::Behind(back)
            } else {
                Place::Jump
            }
        }
    }

    fn capacity(&self) -> u64 {
        // A `usize` power of two below the window always fits.
        u64::try_from(self.config.capacity).unwrap_or(u64::MAX)
    }

    fn slot_of(&self, index: u64) -> usize {
        // The capacity is a power of two, so wrapping indexes stay aligned.
        usize::try_from(index & (self.capacity() - 1)).unwrap_or(0)
    }

    /// The slot at `at`, a copy; an empty one past the end, which the
    /// power-of-two mask never reaches.
    fn slot(&self, at: usize) -> Slot {
        self.slots.get(at).copied().unwrap_or(Slot {
            held: false,
            sequence: 0,
            line: Line::A,
            length: 0,
            arrived: 0,
        })
    }

    fn unhold(&mut self, at: usize) {
        if let Some(slot) = self.slots.get_mut(at) {
            slot.held = false;
        }
    }

    fn jump<F: FnMut(Event<'_>)>(&mut self, line: Line, identity: Identity, emit: &mut F) {
        self.counters.jumps += 1;
        emit(Event::Jump { line, identity });
    }

    fn see(&mut self, line: Line, sequence: u64) {
        let Some(state) = self.state.as_mut() else {
            return;
        };
        let Some(highest) = state.highest.get_mut(line.index()) else {
            return;
        };
        let window = self.space.window();
        let newer = highest.is_none_or(|seen| {
            let ahead = self.space.distance(seen, sequence);
            ahead != 0 && ahead < window
        });
        if newer {
            *highest = Some(sequence);
        }
    }

    /// A message behind the next sequence: a duplicate when the history
    /// shows it delivered, late when it shows it lost or cannot tell.
    fn behind(&mut self, state: &Running, line: Line, sequence: u64, back: u64, length: usize) {
        let entry = (back <= self.capacity())
            .then(|| {
                self.history
                    .get(self.slot_of(state.index.wrapping_sub(back)))
            })
            .flatten()
            .copied()
            .filter(|entry| entry.valid && entry.sequence == sequence);
        match entry {
            Some(entry) if entry.delivered => {
                match line {
                    Line::A => self.counters.duplicates_a += 1,
                    Line::B => self.counters.duplicates_b += 1,
                }
                if entry.length != length {
                    self.counters.length_conflicts += 1;
                }
            }
            _ => self.late(line),
        }
    }

    fn late(&mut self, line: Line) {
        match line {
            Line::A => self.counters.late_a += 1,
            Line::B => self.counters.late_b += 1,
        }
    }

    fn ahead<F: FnMut(Event<'_>)>(
        &mut self,
        line: Line,
        identity: Identity,
        message: &[u8],
        now: u64,
        ahead: u64,
        emit: &mut F,
    ) {
        // Make room: the oldest holes go, or for a waiting arbiter the
        // oldest held messages.
        while self.state.is_some_and(|state| {
            self.space.distance(state.next, identity.sequence) >= self.capacity()
        }) {
            self.overflow(identity.sequence, emit);
        }
        let Some(state) = self.state else { return };
        let ahead = self
            .space
            .distance(state.next, identity.sequence)
            .min(ahead);
        if ahead == 0 {
            if state.awaiting {
                self.hold(line, identity.sequence, message, now, 0);
            } else {
                self.deliver_direct(line, identity, message, emit);
            }
            return;
        }
        let slot = self.slot(self.slot_of(state.index.wrapping_add(ahead)));
        if slot.held && slot.sequence == identity.sequence {
            match line {
                Line::A => self.counters.duplicates_a += 1,
                Line::B => self.counters.duplicates_b += 1,
            }
            if slot.length != message.len() {
                self.counters.length_conflicts += 1;
            }
            return;
        }
        if message.len() > self.config.max_message_length {
            self.counters.oversized += 1;
            return;
        }
        self.hold(line, identity.sequence, message, now, ahead);
    }

    /// One step of making room for `incoming` beyond the buffer.
    fn overflow<F: FnMut(Event<'_>)>(&mut self, incoming: u64, emit: &mut F) {
        let Some(state) = self.state else { return };
        let at = self.slot_of(state.index);
        if self.slot(at).held {
            if state.awaiting {
                self.unhold(at);
                self.held -= 1;
                self.counters.resync_discarded += 1;
                self.step();
            } else {
                self.deliver_held(at, emit);
            }
            return;
        }
        if state.awaiting {
            self.step();
            return;
        }
        // A hole: lost up to the first held message or to where `incoming`
        // fits, whichever is first.
        let fits = self.space.distance(state.next, incoming) - (self.capacity() - 1);
        let end = self
            .first_held(&state)
            .map_or(fits, |(ahead, _)| ahead.min(fits));
        self.counters.buffer_overflows += 1;
        self.gap(end, emit);
    }

    /// The first held message after `next`: its distance and slot.
    fn first_held(&self, state: &Running) -> Option<(u64, usize)> {
        if self.held == 0 {
            return None;
        }
        (1..self.capacity()).find_map(|ahead| {
            let at = self.slot_of(state.index.wrapping_add(ahead));
            let slot = self.slot(at);
            (slot.held && slot.sequence == self.space.add(state.next, ahead)).then_some((ahead, at))
        })
    }

    fn hold(&mut self, line: Line, sequence: u64, message: &[u8], now: u64, ahead: u64) {
        let Some(state) = self.state else { return };
        if message.len() > self.config.max_message_length {
            self.counters.oversized += 1;
            return;
        }
        let at = self.slot_of(state.index.wrapping_add(ahead));
        if self.slot(at).held {
            // Only a waiting arbiter holds at `next`; a second copy there
            // is a duplicate.
            match line {
                Line::A => self.counters.duplicates_a += 1,
                Line::B => self.counters.duplicates_b += 1,
            }
            if self.slot(at).length != message.len() {
                self.counters.length_conflicts += 1;
            }
            return;
        }
        let start = at * self.config.max_message_length;
        if let Some(bytes) = self.arena.get_mut(start..start + message.len()) {
            bytes.copy_from_slice(message);
        }
        let Some(entry) = self.slots.get_mut(at) else {
            return;
        };
        *entry = Slot {
            held: true,
            sequence,
            line,
            length: message.len(),
            arrived: now,
        };
        self.held += 1;
    }

    fn deliver_direct<F: FnMut(Event<'_>)>(
        &mut self,
        line: Line,
        identity: Identity,
        message: &[u8],
        emit: &mut F,
    ) {
        emit(Event::Message {
            line,
            identity,
            bytes: message,
        });
        self.delivered(line, identity.sequence, message.len());
    }

    fn deliver_held<F: FnMut(Event<'_>)>(&mut self, at: usize, emit: &mut F) {
        let Some(state) = self.state else { return };
        let slot = self.slot(at);
        let start = at * self.config.max_message_length;
        emit(Event::Message {
            line: slot.line,
            identity: Identity {
                epoch: state.epoch,
                sequence: slot.sequence,
            },
            bytes: self
                .arena
                .get(start..start + slot.length)
                .unwrap_or_default(),
        });
        self.unhold(at);
        self.held -= 1;
        self.counters.reordered += 1;
        self.delivered(slot.line, slot.sequence, slot.length);
    }

    /// Records a delivery of `next` and moves on.
    fn delivered(&mut self, line: Line, sequence: u64, length: usize) {
        let Some(state) = self.state else { return };
        let at = self.slot_of(state.index);
        if let Some(entry) = self.history.get_mut(at) {
            *entry = Delivered {
                valid: true,
                delivered: true,
                sequence,
                length,
            };
        }
        self.counters.delivered += 1;
        match line {
            Line::A => self.counters.wins_a += 1,
            Line::B => self.counters.wins_b += 1,
        }
        self.step();
    }

    /// Moves `next` on by one.
    fn step(&mut self) {
        let space = self.space;
        if let Some(state) = self.state.as_mut() {
            state.next = space.add(state.next, 1);
            state.index = state.index.wrapping_add(1);
        }
    }

    /// Declares the `count` sequences from `next` lost.
    fn gap<F: FnMut(Event<'_>)>(&mut self, count: u64, emit: &mut F) {
        let space = self.space;
        let Some(state) = self.state.as_mut() else {
            return;
        };
        if count == 0 {
            return;
        }
        emit(Event::Gap {
            epoch: state.epoch,
            from: state.next,
            count,
        });
        // The history keeps the last `capacity` sequences, lost ones too,
        // so a copy arriving later reads as late, not as a duplicate.
        let capacity = u64::try_from(self.history.len()).unwrap_or(1);
        let kept = count.min(capacity);
        for skip in count - kept..count {
            let index =
                usize::try_from(state.index.wrapping_add(skip) & (capacity - 1)).unwrap_or(0);
            if let Some(entry) = self.history.get_mut(index) {
                *entry = Delivered {
                    valid: true,
                    delivered: false,
                    sequence: space.add(state.next, skip),
                    length: 0,
                };
            }
        }
        state.next = space.add(state.next, count);
        state.index = state.index.wrapping_add(count);
        self.counters.gaps += 1;
        self.counters.gap_messages += count;
    }

    /// Delivers what is contiguous and ends the holes that rule 1 or 2 of
    /// design section 4 closes.
    fn advance<F: FnMut(Event<'_>)>(&mut self, now: u64, emit: &mut F) {
        while let Some(state) = self.state {
            if state.awaiting {
                return;
            }
            if self.held == 0 {
                if self.pending.is_none() {
                    return;
                }
                // No hole is known in the current epoch: it closes.
                self.promote(emit);
                continue;
            }
            let at = self.slot_of(state.index);
            let slot = self.slot(at);
            if slot.held && slot.sequence == state.next {
                self.deliver_held(at, emit);
                continue;
            }
            let Some((ahead, first)) = self.first_held(&state) else {
                return;
            };
            // A line that moved to the waiting epoch has passed every hole.
            let moved = self.pending.map_or([false; 2], |pending| {
                pending.highest.map(|seen| seen.is_some())
            });
            let passed = state.highest.iter().zip(moved).all(|(highest, moved)| {
                moved
                    || highest.is_some_and(|seen| {
                        let beyond = self.space.distance(state.next, seen);
                        beyond != 0 && beyond < self.space.window()
                    })
            });
            let expired = now.saturating_sub(self.slot(first).arrived) >= self.config.skew_window;
            if !(passed || expired) {
                return;
            }
            self.gap(ahead, emit);
        }
    }

    /// The first message of a larger epoch: ends the current one.
    fn change_epoch<F: FnMut(Event<'_>)>(
        &mut self,
        state: Running,
        identity: Identity,
        emit: &mut F,
    ) {
        if state.awaiting {
            self.discard_all();
        } else {
            // Deliver what is held, the holes between declared lost.
            while let Some(state) = self.state {
                let at = self.slot_of(state.index);
                if self.slot(at).held && self.slot(at).sequence == state.next {
                    self.deliver_held(at, emit);
                    continue;
                }
                let Some((ahead, _)) = self.first_held(&state) else {
                    break;
                };
                self.gap(ahead, emit);
            }
            emit(Event::EpochChange {
                from: state.epoch,
                to: identity.epoch,
            });
        }
        self.discard_all();
        self.clear_history();
        let next = self
            .sequencer
            .epoch_start(identity.epoch)
            .filter(|start| self.space.contains(*start))
            .unwrap_or(identity.sequence);
        self.state = Some(Running {
            epoch: identity.epoch,
            next,
            index: 0,
            highest: [None; 2],
            awaiting: state.awaiting,
        });
    }

    fn discard_all(&mut self) {
        for slot in &mut self.slots {
            if slot.held {
                slot.held = false;
                self.counters.resync_discarded += 1;
            }
        }
        self.held = 0;
    }

    /// Discards held messages outside the buffer's span from `next`.
    fn discard_outside(&mut self, state: &Running) {
        for ahead in 0..self.capacity() {
            let at = self.slot_of(state.index.wrapping_add(ahead));
            let Some(slot) = self.slots.get_mut(at) else {
                continue;
            };
            if slot.held && slot.sequence != self.space.add(state.next, ahead) {
                slot.held = false;
                self.held -= 1;
                self.counters.resync_discarded += 1;
            }
        }
    }

    fn clear_history(&mut self) {
        for entry in &mut self.history {
            entry.valid = false;
        }
    }
}

#[cfg(test)]
mod tests;
