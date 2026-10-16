// SPDX-License-Identifier: Apache-2.0

//! A resumable frame-level subscriber service (`quantstratum-docs:
//! karyos/design/frame-level-service.md`, P2.4 L4).
//!
//! [`FrameReader`] owns a [`Subscription`] and serves at most one block per
//! call: one DATA fragment copied into a private assembly, or one PAD,
//! ABORTED, local gap or image skip stepped over. An incomplete message is
//! resumed at its first missing fragment instead of restarting at BEGIN,
//! the documented exception to `receive-publication.md`'s restart rule;
//! nothing is delivered before END, and every fragment is checked
//! contiguous with the assembly. [`FrameReader::take`] delivers the complete
//! message once, with no loan held.
//!
//! Safety (ADR-0034): every region byte is read under a read loan taken and
//! released in the same call, whose target is the assembly's term; the
//! loan, not a lookup, proves the term, so no byte of a reused term joins
//! bytes copied earlier. In publication mode a block's interior fragments
//! are read only after this reader observed the block's first word 0 with
//! Acquire under the same loan target, in this call or an earlier one; in
//! image mode every fragment's word 0 is loaded with Acquire before its
//! bytes. Every outcome either ends the reader or moves past the copy, so
//! no fragment is copied, and charged, twice.

use super::{
    BufferOwner, FRAME_ALIGNMENT, Lookup, PollOutcome, SealReason, SealWord, SkipReason, Step,
    Subscription, SubscriptionContext, corrupt, decode_seal,
};
use crate::error::SysError;
use crate::frame::{EXTENSION_LENGTH, FrameType, HEADER_LENGTH, PROTOCOL_VERSION, Word0};
use crate::loan::{LoanOutcome, release_loan, take_loan};
use crate::publication::{load_interior, observe_block, seal_reason};
use crate::sizing::align_frame;
use crate::sync::Ordering;
use crate::term::TermCount;
use crate::term_bytes::TermBytes;

/// The charge of a stepped record: a PAD or ABORTED record's canonical 32
/// bytes (`aggregate-lanes.md`, the subscriber row of the charges table),
/// and, as proposed for L5 (GU-12), a local gap record or a skip step,
/// whatever it covers. An `Interrupted` skip is charged 0: the
/// interrupting frame is the next step, charged by its own kind.
pub const STEP_CHARGE: u32 = HEADER_LENGTH;

/// Frames a skip step walks at most over a run without BEGIN: a longer run
/// is several steps, so a step is bounded in work as in charge.
pub const SKIP_WALK_FRAMES: usize = 64;

/// A message the assembly completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageInfo {
    /// Stream position of the block.
    pub position: u64,
    /// Bytes of the message.
    pub length: u32,
    /// Whether the last fragment carries EOS.
    pub end_of_stream: bool,
    /// Reserved value of the first fragment.
    pub reserved_value: i64,
    /// The first fragment's trace extension (opaque).
    pub extension: Option<[u8; EXTENSION_LENGTH as usize]>,
}

/// A record stepped over without delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stepped {
    /// The PAD at the end of a term: the reader moved to the next term.
    Pad {
        /// Stream position of the PAD.
        position: u64,
    },
    /// An aborted block: only its word 0 was read.
    Aborted {
        /// Stream position of the block.
        position: u64,
        /// Bytes stepped over.
        extent: u32,
    },
    /// Only on an image: a range that delivers no message, as
    /// [`PollOutcome::Skipped`]. A partial assembly is discarded.
    Skipped {
        /// Stream position of the range.
        position: u64,
        /// Bytes skipped.
        extent: u32,
        /// Why the range delivers no message.
        reason: SkipReason,
    },
}

/// The end of service, or an optional reader's overrun.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameEnd {
    /// The subscriber was revoked. Terminal.
    Revoked {
        /// The reader's position.
        position: u64,
    },
    /// The buffer is sealed and the reader reached the seal position.
    /// Terminal.
    Closed {
        /// The seal position.
        position: u64,
        /// Why the buffer was sealed.
        reason: SealReason,
    },
    /// An optional or observer reader was lapped, as
    /// [`PollOutcome::Overrun`]: a partial assembly is discarded and
    /// reading resumes at `resume`.
    Overrun {
        /// First position not delivered.
        from: u64,
        /// End of the range known lost.
        lost_to: u64,
        /// Position the reader resumes from.
        resume: u64,
    },
}

/// What one [`FrameReader::serve_frame`] call did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameStep {
    /// A DATA fragment is in the assembly, charged its reserved length.
    Copied {
        /// The fragment's reserved frame length.
        charge: u32,
    },
    /// The END fragment is in the assembly, charged its reserved length: a
    /// message awaits [`FrameReader::take`].
    Complete {
        /// The END fragment's reserved frame length.
        charge: u32,
        /// The message.
        info: MessageInfo,
    },
    /// A complete message awaits [`FrameReader::take`]: nothing was read
    /// or charged.
    Ready,
    /// A record was stepped over, charged [`STEP_CHARGE`].
    Stepped {
        /// The step's charge.
        charge: u32,
        /// What was stepped over.
        kind: Stepped,
    },
    /// The next block or fragment is not committed: nothing was copied or
    /// charged, and a partial assembly is kept.
    Pending,
    /// The reader ended, or an optional reader was lapped.
    Ended(FrameEnd),
}

/// What [`FrameReader::peek`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Peek {
    /// `serve_frame` would serve one block, charged `charge`: a DATA
    /// fragment's reserved length, [`STEP_CHARGE`] for a stepped record,
    /// 0 for an `Interrupted` skip.
    Step {
        /// The block's charge.
        charge: u32,
    },
    /// A complete message awaits [`FrameReader::take`].
    Ready,
    /// Nothing to serve now.
    Pending,
    /// `serve_frame` would end the reader or report an overrun.
    Ended,
}

/// A message in progress.
#[derive(Debug, Clone, Copy)]
struct Assembly {
    /// Stream position of the block.
    position: u64,
    /// Term offset of the block's first fragment.
    start: u32,
    /// Term offset of the next fragment.
    next: u32,
    /// Payload bytes copied.
    written: u32,
    reserved_value: i64,
    extension: Option<[u8; EXTENSION_LENGTH as usize]>,
}

impl Assembly {
    /// Stream position of the next fragment.
    fn next_position(&self) -> u64 {
        self.position + u64::from(self.next - self.start)
    }
}

#[derive(Debug, Clone, Copy)]
enum State {
    Idle,
    Assembling(Assembly),
    /// A complete message and the position after its block.
    Ready(MessageInfo, u64),
    /// Revoked, closed or failed: every later call answers the same.
    Ended(Result<FrameEnd, SysError>),
}

/// A resumable frame-level reader over one subscription.
///
/// It owns the subscription exclusively, so no `poll` runs beside it, and
/// an assembly buffer of the buffer's `max_message_length` bytes,
/// allocated once when it is created (on the control path).
#[derive(Debug)]
pub struct FrameReader<O: BufferOwner> {
    subscription: Subscription<O>,
    assembly: Box<[u8]>,
    state: State,
}

impl<O: BufferOwner> FrameReader<O> {
    /// A reader over `subscription`. A message the subscription copied and
    /// did not acknowledge is served again from its first fragment.
    #[must_use]
    pub fn new(mut subscription: Subscription<O>) -> Self {
        if subscription.cursor.pending.take().is_some() {
            subscription.cursor.position = subscription.cursor.acknowledged;
        }
        let length = subscription.buffer.max_message_length as usize;
        Self {
            subscription,
            assembly: vec![0u8; length].into_boxed_slice(),
            state: State::Idle,
        }
    }

    /// The subscription it reads.
    #[must_use]
    pub fn subscription(&self) -> &Subscription<O> {
        &self.subscription
    }

    /// Whether a complete message awaits [`FrameReader::take`].
    #[must_use]
    pub fn ready(&self) -> bool {
        matches!(self.state, State::Ready(..))
    }

    /// Serves at most one block: copies one DATA fragment into the
    /// assembly or steps over one record. See [`FrameStep`].
    ///
    /// # Errors
    ///
    /// Returns [`SysError::RequiredSubscriberLapped`] when a required
    /// reader's data is gone, [`SysError::CorruptTerm`] for inconsistent
    /// published geometry, and the loan's errors such as
    /// [`SysError::GenerationMismatch`]. Every error ends the reader: its
    /// assembly is discarded and every later call returns the same error.
    pub fn serve_frame(&mut self) -> Result<FrameStep, SysError> {
        let assembly = match self.state {
            State::Idle => None,
            State::Assembling(assembly) => Some(assembly),
            State::Ready(..) => return Ok(FrameStep::Ready),
            State::Ended(Ok(end)) => return Ok(FrameStep::Ended(end)),
            State::Ended(Err(error)) => return Err(error),
        };
        let mut context = SubscriptionContext {
            buffer: &self.subscription.buffer,
            cursor: &mut self.subscription.cursor,
        };
        let served = context.serve(assembly, &mut self.assembly);
        let (state, step) = match served {
            // Closed is terminal like Revoked: later calls answer it again
            // without a loan, whatever happens to the slot after the seal.
            Ok((_, FrameStep::Ended(end @ FrameEnd::Closed { .. }))) => {
                (State::Ended(Ok(end)), Ok(FrameStep::Ended(end)))
            }
            Ok((state, step)) => (state, Ok(step)),
            Err(error) => (State::Ended(Err(error)), Err(error)),
        };
        self.state = state;
        step
    }

    /// What the next [`FrameReader::serve_frame`] would do, without doing
    /// it: no copy, no cursor or assembly change and no position
    /// publication. A hint for a scheduler's charge, never a reservation.
    ///
    /// # Errors
    ///
    /// The errors the next `serve_frame` would return, except that a
    /// required reader's lap answers `Ok(Peek::Ended)`: `serve_frame` then
    /// returns `RequiredSubscriberLapped`. A peek never ends the reader.
    pub fn peek(&mut self) -> Result<Peek, SysError> {
        let assembly = match self.state {
            State::Idle => None,
            State::Assembling(assembly) => Some(assembly),
            State::Ready(..) => return Ok(Peek::Ready),
            State::Ended(Ok(_)) => return Ok(Peek::Ended),
            State::Ended(Err(error)) => return Err(error),
        };
        SubscriptionContext {
            buffer: &self.subscription.buffer,
            cursor: &mut self.subscription.cursor,
        }
        .peek(assembly)
    }

    /// Delivers the complete message once to `deliver`, borrowing the
    /// assembly with no loan held, then moves the cursor past it and
    /// publishes the position (a required reader's acknowledgement, after
    /// `deliver` returned). Returns whether a message was delivered. If
    /// `deliver` panics the message stays complete and the next `take`
    /// delivers it again.
    ///
    /// It does not check for a revocation after the message completed: a
    /// message complete before the revocation is delivered, as `poll`
    /// delivers a message it copied before one.
    pub fn take(&mut self, deliver: impl FnOnce(&[u8], MessageInfo)) -> bool {
        let State::Ready(info, next) = self.state else {
            return false;
        };
        deliver(
            self.assembly.get(..info.length as usize).unwrap_or(&[]),
            info,
        );
        self.state = State::Idle;
        let mut context = SubscriptionContext {
            buffer: &self.subscription.buffer,
            cursor: &mut self.subscription.cursor,
        };
        context.cursor.position = next;
        context.publish(next);
        true
    }
}

/// One fragment read under the loan.
enum Fragment {
    Pending,
    Pad,
    Aborted {
        extent: u32,
    },
    /// A range from the block start, discarding a partial assembly.
    Skip {
        extent: u32,
        reason: SkipReason,
    },
    Copied {
        charge: u32,
        assembly: Assembly,
    },
    Complete {
        charge: u32,
        assembly: Assembly,
        end_of_stream: bool,
    },
}

impl<T: TermBytes> SubscriptionContext<'_, T> {
    /// One call of [`FrameReader::serve_frame`] from `assembly`: the next
    /// state and the step.
    fn serve(
        &mut self,
        assembly: Option<Assembly>,
        bytes: &mut [u8],
    ) -> Result<(State, FrameStep), SysError> {
        let buffer = self.buffer;
        // At most two iterations: the end of one term and the next term.
        for _ in 0..2 {
            let position = assembly.map_or(self.cursor.position, |a| a.next_position());
            let (count, offset) = buffer.split(position)?;
            if offset == buffer.term_length {
                // Only between messages: a block never ends a term without
                // END, so an assembly never stands at a term end.
                if assembly.is_some() {
                    return Err(corrupt(offset, "assembly at term end"));
                }
                self.advance_to(buffer.position(count.next()?, 0));
                continue;
            }
            return self.serve_in_term(count, offset, assembly, bytes);
        }
        Ok((State::Idle, self.pending()))
    }

    fn serve_in_term(
        &mut self,
        count: TermCount,
        offset: u32,
        assembly: Option<Assembly>,
        bytes: &mut [u8],
    ) -> Result<(State, FrameStep), SysError> {
        let buffer = self.buffer;
        let kept = assembly.map_or(State::Idle, State::Assembling);
        let slot = match buffer.lookup(count)? {
            Lookup::Slot(slot) => slot,
            Lookup::Missing => return Ok((kept, self.pending_with(assembly))),
            Lookup::Gone => return self.frame_overrun(),
        };
        let cell = buffer.cell(self.cursor.cell)?;
        // The loan's target is the assembly's term: a reclaimed or reused
        // slot is never granted, so no byte of another term is read.
        match take_loan(
            &cell.loan,
            &cell.revoked,
            buffer.descriptor(slot)?,
            buffer.target(slot, count)?,
        )? {
            LoanOutcome::Granted => {}
            LoanOutcome::Retry => return Ok((kept, self.pending_with(assembly))),
            LoanOutcome::Overrun => return self.frame_overrun(),
            LoanOutcome::Revoked => {
                let end = FrameEnd::Revoked {
                    position: self.cursor.position,
                };
                return Ok((State::Ended(Ok(end)), FrameStep::Ended(end)));
            }
        }
        // Retention admission point, as `poll_term`: a floor past the
        // assembly's start ends it as an overrun.
        let start = assembly.map_or(self.cursor.position, |a| a.position);
        if start < buffer.floor().load(Ordering::Acquire) {
            release_loan(&cell.loan);
            return self.frame_overrun();
        }
        let read = self.read_fragment(slot, start, offset, assembly, Some(bytes));
        release_loan(&cell.loan);
        let read = read?;
        self.cursor.note(match read {
            Fragment::Pending => super::Outcome::Pending,
            Fragment::Skip { extent, reason } => super::Outcome::Skip {
                position: start,
                extent,
                reason,
            },
            // The cursor reached a BEGIN, ABORTED or PAD frame.
            Fragment::Pad
            | Fragment::Aborted { .. }
            | Fragment::Copied { .. }
            | Fragment::Complete { .. } => super::Outcome::Boundary,
        });
        Ok(match read {
            Fragment::Pending => (kept, self.pending_with(assembly)),
            Fragment::Pad => {
                self.advance_to(buffer.position(count.next()?, 0));
                (
                    State::Idle,
                    FrameStep::Stepped {
                        charge: STEP_CHARGE,
                        kind: Stepped::Pad { position: start },
                    },
                )
            }
            Fragment::Aborted { extent } => {
                self.advance_to(start + u64::from(extent));
                (
                    State::Idle,
                    FrameStep::Stepped {
                        charge: STEP_CHARGE,
                        kind: Stepped::Aborted {
                            position: start,
                            extent,
                        },
                    },
                )
            }
            Fragment::Skip { extent, reason } => {
                self.advance_to(start + u64::from(extent));
                let charge = if reason == SkipReason::Interrupted {
                    0
                } else {
                    STEP_CHARGE
                };
                (
                    State::Idle,
                    FrameStep::Stepped {
                        charge,
                        kind: Stepped::Skipped {
                            position: start,
                            extent,
                            reason,
                        },
                    },
                )
            }
            Fragment::Copied { charge, assembly } => {
                (State::Assembling(assembly), FrameStep::Copied { charge })
            }
            Fragment::Complete {
                charge,
                assembly,
                end_of_stream,
            } => {
                let info = MessageInfo {
                    position: assembly.position,
                    length: assembly.written,
                    end_of_stream,
                    reserved_value: assembly.reserved_value,
                    extension: assembly.extension,
                };
                (
                    State::Ready(info, assembly.next_position()),
                    FrameStep::Complete { charge, info },
                )
            }
        })
    }

    /// What [`FrameReader::serve_frame`] would do from `assembly`, read
    /// under a loan of the same target and stopped before any copy, cursor
    /// or position change (`quantstratum-docs:
    /// karyos/design/aggregate-subscriber.md`, AS-1).
    fn peek(&self, assembly: Option<Assembly>) -> Result<Peek, SysError> {
        let buffer = self.buffer;
        let mut position = assembly.map_or(self.cursor.position, |a| a.next_position());
        // At most two iterations: the end of one term and the next term.
        for _ in 0..2 {
            let (count, offset) = buffer.split(position)?;
            if offset == buffer.term_length {
                if assembly.is_some() {
                    return Err(corrupt(offset, "assembly at term end"));
                }
                position = buffer.position(count.next()?, 0);
                continue;
            }
            let slot = match buffer.lookup(count)? {
                Lookup::Slot(slot) => slot,
                Lookup::Missing => return Ok(self.peek_pending(assembly, position)),
                Lookup::Gone => return Ok(Peek::Ended),
            };
            let cell = buffer.cell(self.cursor.cell)?;
            match take_loan(
                &cell.loan,
                &cell.revoked,
                buffer.descriptor(slot)?,
                buffer.target(slot, count)?,
            )? {
                LoanOutcome::Granted => {}
                LoanOutcome::Retry => return Ok(self.peek_pending(assembly, position)),
                LoanOutcome::Overrun | LoanOutcome::Revoked => return Ok(Peek::Ended),
            }
            let start = assembly.map_or(position, |a| a.position);
            if start < buffer.floor().load(Ordering::Acquire) {
                release_loan(&cell.loan);
                return Ok(Peek::Ended);
            }
            let read = self.read_fragment(slot, start, offset, assembly, None);
            release_loan(&cell.loan);
            return Ok(match read? {
                Fragment::Pending => self.peek_pending(assembly, position),
                Fragment::Pad | Fragment::Aborted { .. } => Peek::Step {
                    charge: STEP_CHARGE,
                },
                Fragment::Skip {
                    reason: SkipReason::Interrupted,
                    ..
                } => Peek::Step { charge: 0 },
                Fragment::Skip { .. } => Peek::Step {
                    charge: STEP_CHARGE,
                },
                Fragment::Copied { charge, .. } | Fragment::Complete { charge, .. } => {
                    Peek::Step { charge }
                }
            });
        }
        Ok(self.peek_pending(assembly, position))
    }

    /// `Pending`, or `Ended` for a reader between messages at the seal
    /// position, as [`Self::pending`] at `position`.
    fn peek_pending(&self, assembly: Option<Assembly>, position: u64) -> Peek {
        if assembly.is_some() {
            return Peek::Pending;
        }
        match decode_seal(self.buffer.seal().load(Ordering::Acquire)) {
            SealWord::Positioned(sealed) if position >= sealed => Peek::Ended,
            _ => Peek::Pending,
        }
    }

    /// Nothing to serve: `Pending`, or `Closed` once a reader between
    /// messages reached the seal position, as `Subscription::poll`.
    fn pending_with(&self, assembly: Option<Assembly>) -> FrameStep {
        if assembly.is_some() {
            FrameStep::Pending
        } else {
            self.pending()
        }
    }

    fn pending(&self) -> FrameStep {
        match decode_seal(self.buffer.seal().load(Ordering::Acquire)) {
            SealWord::Positioned(position) if self.cursor.position >= position => {
                // The Acquire load above observed the seal: the reason
                // stored before its swap is visible.
                let reason = SealReason::from_code(seal_reason(self.buffer.seal_reason_word()));
                FrameStep::Ended(FrameEnd::Closed { position, reason })
            }
            _ => FrameStep::Pending,
        }
    }

    /// The reader's data is gone: a partial assembly is discarded, and an
    /// optional reader rejoins as `overrun()` does.
    fn frame_overrun(&mut self) -> Result<(State, FrameStep), SysError> {
        match self.overrun()? {
            Step::Done(PollOutcome::Overrun {
                from,
                lost_to,
                resume,
            }) => Ok((
                State::Idle,
                FrameStep::Ended(FrameEnd::Overrun {
                    from,
                    lost_to,
                    resume,
                }),
            )),
            Step::Done(PollOutcome::Revoked { position }) => {
                let end = FrameEnd::Revoked { position };
                Ok((State::Ended(Ok(end)), FrameStep::Ended(end)))
            }
            // No consistent head yet: the assembly is dropped and the cursor
            // stays at its start. Every overrun trigger (a gone slot, a
            // refused loan, a floor past the start) persists, so the next
            // call overruns again and never copies a fragment twice.
            Step::Done(_) | Step::NextTerm => Ok((State::Idle, FrameStep::Pending)),
        }
    }

    /// Reads the fragment or record at `offset` of `slot` under the
    /// caller's read loan.
    fn read_fragment(
        &self,
        slot: u8,
        position: u64,
        offset: u32,
        assembly: Option<Assembly>,
        bytes: Option<&mut [u8]>,
    ) -> Result<Fragment, SysError> {
        match (self.buffer.image(), assembly) {
            (false, None) => self.publication_block(slot, position, offset, bytes),
            (false, Some(assembly)) => self.publication_fragment(slot, assembly, bytes),
            (true, None) => self.image_block(slot, position, offset, bytes),
            (true, Some(assembly)) => self.image_fragment(slot, assembly, bytes),
        }
    }

    /// The block at `start` of a publication: its first word 0 is loaded
    /// with Acquire, which orders the block's whole Release before every
    /// later read of it by this reader under the same loan target.
    fn publication_block(
        &self,
        slot: u8,
        position: u64,
        start: u32,
        bytes: Option<&mut [u8]>,
    ) -> Result<Fragment, SysError> {
        let buffer = self.buffer;
        let term_length = buffer.term_length;
        // SAFETY: read loan held for this slot's term; `start` is a block
        // boundary reached by the walk.
        let first = observe_block(unsafe { buffer.regions.word0(slot, start) });
        let signed = first as u32 as i32;
        if signed <= 0 {
            return Ok(Fragment::Pending);
        }
        let word0 = Word0::unpack(first).map_err(|_| corrupt(start, "reserved flags"))?;
        if word0.version() != PROTOCOL_VERSION {
            return Err(corrupt(start, "version"));
        }
        match FrameType::try_from_code(word0.frame_type_code()) {
            Ok(FrameType::Pad) => {
                if signed as u32 != term_length - start {
                    return Err(corrupt(start, "pad extent"));
                }
                Ok(Fragment::Pad)
            }
            Ok(FrameType::Aborted) => {
                // Only word 0 of an aborted block is read.
                let extent = signed as u32;
                if word0.flags().lane() != buffer.config.lane {
                    return Err(corrupt(start, "aborted lane"));
                }
                if !extent.is_multiple_of(FRAME_ALIGNMENT) || extent > term_length - start {
                    return Err(corrupt(start, "aborted extent"));
                }
                Ok(Fragment::Aborted { extent })
            }
            Ok(FrameType::Data) => {
                if !word0.flags().begin() {
                    return Err(corrupt(start, "BEGIN placement"));
                }
                let reserved = self.data_extent(word0, start)?;
                let assembly = self.first_header(slot, position, start, word0, bytes.is_some())?;
                self.copy(slot, assembly, word0, reserved, false, bytes)
            }
            _ => Err(corrupt(start, "frame type")),
        }
    }

    /// The next fragment of a publication block whose first word 0 this
    /// reader observed with Acquire: its word 0 is loaded Relaxed, and an
    /// uncommitted or non-DATA fragment inside a committed block is
    /// corrupt, never pending.
    fn publication_fragment(
        &self,
        slot: u8,
        assembly: Assembly,
        bytes: Option<&mut [u8]>,
    ) -> Result<Fragment, SysError> {
        let offset = assembly.next;
        // SAFETY: read loan held for this slot's term (the assembly's);
        // `offset` is the end of a fragment of the block, below the term
        // end.
        let raw = load_interior(unsafe { self.buffer.regions.word0(slot, offset) });
        let word = Word0::unpack(raw).map_err(|_| corrupt(offset, "reserved flags"))?;
        if word.frame_type_code() != FrameType::Data.code() {
            return Err(corrupt(offset, "interior frame type"));
        }
        if word.flags().begin() {
            return Err(corrupt(offset, "BEGIN placement"));
        }
        let reserved = self.data_extent(word, offset)?;
        self.copy(slot, assembly, word, reserved, false, bytes)
    }

    /// The frame at `start` of an image, between messages: as
    /// `validate_image_block`, one record at a time.
    fn image_block(
        &self,
        slot: u8,
        position: u64,
        start: u32,
        bytes: Option<&mut [u8]>,
    ) -> Result<Fragment, SysError> {
        let term_length = self.buffer.term_length;
        let Some(first) = self.frame(slot, start)? else {
            return Ok(Fragment::Pending);
        };
        let flags = first.word0.flags();
        let skipped = |validated| match validated {
            super::Validated::Skip { extent, reason } => Ok(Fragment::Skip { extent, reason }),
            _ => Err(corrupt(start, "image walk")),
        };
        match first.kind {
            super::image_read::Kind::LocalGap => {
                skipped(self.local_gap(slot, position, start, first.reserved)?)
            }
            super::image_read::Kind::Frame(FrameType::Pad) => {
                if first.reserved != term_length - start {
                    return Err(corrupt(start, "pad extent"));
                }
                Ok(Fragment::Pad)
            }
            super::image_read::Kind::Frame(FrameType::Aborted) => {
                if flags.lane() != self.buffer.config.lane {
                    return Err(corrupt(start, "aborted lane"));
                }
                Ok(Fragment::Aborted {
                    extent: first.reserved,
                })
            }
            _ if !flags.begin() => skipped(self.orphan_run(slot, start, SKIP_WALK_FRAMES)?),
            _ => {
                let assembly = Assembly {
                    position,
                    start,
                    next: start,
                    written: 0,
                    reserved_value: 0,
                    extension: None,
                };
                self.image_copy(slot, assembly, first, bytes)
            }
        }
    }

    /// The next fragment of an image message: its word 0 is loaded with
    /// Acquire (each fragment is its own publication).
    fn image_fragment(
        &self,
        slot: u8,
        assembly: Assembly,
        bytes: Option<&mut [u8]>,
    ) -> Result<Fragment, SysError> {
        let offset = assembly.next;
        let Some(frame) = self.frame(slot, offset)? else {
            // A fragment not yet received: the message is incomplete.
            return Ok(Fragment::Pending);
        };
        if !frame.data() || frame.word0.flags().begin() {
            return Ok(Fragment::Skip {
                extent: offset - assembly.start,
                reason: SkipReason::Interrupted,
            });
        }
        self.image_copy(slot, assembly, frame, bytes)
    }

    /// Applies an image's message bounds to the DATA fragment `frame` at
    /// `assembly.next`, then copies it.
    fn image_copy(
        &self,
        slot: u8,
        assembly: Assembly,
        frame: super::image_read::Frame,
        bytes: Option<&mut [u8]>,
    ) -> Result<Fragment, SysError> {
        let buffer = self.buffer;
        let offset = assembly.next;
        let flags = frame.word0.flags();
        let end = offset + frame.reserved;
        let payload = frame
            .word0
            .frame_length()
            .cast_unsigned()
            .saturating_sub(flags.header_length());
        if end - assembly.start > buffer.config.max_reserved
            || assembly.written.saturating_add(payload) > buffer.max_message_length
        {
            return Ok(Fragment::Skip {
                extent: end - assembly.start,
                reason: SkipReason::MessageTooLarge,
            });
        }
        if !flags.end() && end == buffer.term_length {
            return Ok(Fragment::Skip {
                extent: buffer.term_length - assembly.start,
                reason: SkipReason::MissingEnd,
            });
        }
        let assembly = if offset == assembly.start {
            self.first_header(
                slot,
                assembly.position,
                offset,
                frame.word0,
                bytes.is_some(),
            )?
        } else {
            assembly
        };
        self.copy(slot, assembly, frame.word0, frame.reserved, true, bytes)
    }

    /// The aligned extent of the DATA fragment `word` at `offset`, checked
    /// against its header and the term end.
    fn data_extent(&self, word: Word0, offset: u32) -> Result<u32, SysError> {
        let frame_length = u32::try_from(word.frame_length())
            .map_err(|_| corrupt(offset, "uncommitted fragment"))?;
        if frame_length < word.flags().header_length() {
            return Err(corrupt(offset, "frame shorter than header"));
        }
        let reserved = align_frame(frame_length).map_err(|_| corrupt(offset, "frame length"))?;
        if reserved > self.buffer.term_length - offset {
            return Err(corrupt(offset, "frame past term end"));
        }
        Ok(reserved)
    }

    /// A new assembly at the BEGIN fragment `word0` at `start`, with its
    /// reserved value and extension read under the loan.
    fn first_header(
        &self,
        slot: u8,
        position: u64,
        start: u32,
        word0: Word0,
        read: bool,
    ) -> Result<Assembly, SysError> {
        let buffer = self.buffer;
        let mut reserved_value = [0u8; 8];
        if !read {
            // A peek reads no header bytes.
            return Ok(Assembly {
                position,
                start,
                next: start,
                written: 0,
                reserved_value: 0,
                extension: None,
            });
        }
        // SAFETY: read loan held; header bytes 24..32 of a committed frame
        // whose length is at least its header (checked by the caller).
        unsafe {
            buffer
                .regions
                .read_bytes(slot, start + 24, &mut reserved_value)
        };
        let extension = if word0.flags().ext() {
            let mut bytes = [0u8; EXTENSION_LENGTH as usize];
            // SAFETY: read loan held; the extension follows the header
            // inside the committed frame, whose length includes it (its
            // header length with EXT was checked by the caller).
            unsafe {
                buffer
                    .regions
                    .read_bytes(slot, start + HEADER_LENGTH, &mut bytes)
            };
            Some(bytes)
        } else {
            None
        };
        Ok(Assembly {
            position,
            start,
            next: start,
            written: 0,
            reserved_value: i64::from_le_bytes(reserved_value),
            extension,
        })
    }

    /// Copies the payload of the DATA fragment `word` at `assembly.next`,
    /// of aligned extent `reserved`, into the assembly. A publication block
    /// that reaches the term end without END is corrupt; an image's was
    /// skipped before.
    fn copy(
        &self,
        slot: u8,
        assembly: Assembly,
        word: Word0,
        reserved: u32,
        image: bool,
        bytes: Option<&mut [u8]>,
    ) -> Result<Fragment, SysError> {
        let buffer = self.buffer;
        let offset = assembly.next;
        let flags = word.flags();
        let header_length = flags.header_length();
        let payload = word
            .frame_length()
            .cast_unsigned()
            .checked_sub(header_length)
            .ok_or_else(|| corrupt(offset, "frame shorter than header"))?;
        let next = offset + reserved;
        if next - assembly.start > buffer.config.max_reserved {
            return Err(corrupt(offset, "block longer than max_reserved"));
        }
        let written = assembly
            .written
            .checked_add(payload)
            .filter(|written| *written <= buffer.max_message_length)
            .ok_or_else(|| corrupt(offset, "message longer than max_message_length"))?;
        if !image && !flags.end() && next == buffer.term_length {
            return Err(corrupt(next, "block without END"));
        }
        if let Some(bytes) = bytes {
            let target = bytes
                .get_mut(assembly.written as usize..written as usize)
                .ok_or_else(|| corrupt(offset, "message longer than the assembly"))?;
            // SAFETY: read loan held for the assembly's term; the payload of
            // a committed DATA frame whose extent lies inside the term
            // (checked by `data_extent` or the image walk).
            unsafe {
                buffer
                    .regions
                    .read_bytes(slot, offset + header_length, target)
            };
        }
        let assembly = Assembly {
            next,
            written,
            ..assembly
        };
        Ok(if flags.end() {
            Fragment::Complete {
                charge: reserved,
                assembly,
                end_of_stream: flags.eos(),
            }
        } else {
            Fragment::Copied {
                charge: reserved,
                assembly,
            }
        })
    }
}
