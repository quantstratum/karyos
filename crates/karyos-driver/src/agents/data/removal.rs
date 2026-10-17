// SPDX-License-Identifier: Apache-2.0

//! A network publication's removal linger (`quantstratum-docs:
//! karyos/design/driver-network-agents.md` §7, "Removing a stream";
//! coordinator ACS 16954).
//!
//! At removal the publication admits no new receiver and announces no
//! SETUP, but keeps its incarnation: its lanes drain to their positioned
//! seals through the usual first sends, its repair serves NAKs and its
//! receivers' SMs are still read. Once a lane's first sends reached its
//! seal (its publishers released it and every frame below it was
//! submitted), the lane sends a header-only DATA frame with the EOS flag at
//! the seal, which names the lane's terminal bound to its receivers
//! (network-sessions.md, Liveness and terminal transitions), and repeats it
//! every `interval`. Once a receiver is established, the linger always
//! runs in full, whatever the receivers acknowledge (see "No established
//! receiver" below for the one early end).
//!
//! **Bound.** One timer, `linger` from the removal's start (its first duty),
//! bounds the drain: a lane may never drain (its receivers gone, so the
//! flow-control window never opens; a blocked socket; a stalled required
//! receiver), and the removal never waits for it. A lane not drained by
//! `start + max(linger, interval)` sends no EOS and is given up, counted
//! once per removal (`removals_undrained`); the bound is never below one
//! EOS interval, so a zero linger still lets the tail drain within one
//! cadence. The removal ends once every lane sent its EOS or was given up,
//! at the later of `start + linger` and the latest first EOS plus
//! `linger`: a lane that drained in time still has its full linger. With a
//! `linger` of 0 each drained lane's EOS goes once and the publication is
//! drained right after; a lost EOS then falls back to the receivers'
//! liveness timeout. Nothing in the removal waits for a TX half: without
//! one the bound still runs.
//!
//! A guarded lane whose guard closed sends no EOS: nothing more leaves the
//! sender (GC-6) and its receivers' images end at their liveness timeout.
//! Its linger runs as if it had sent one, and the removal is counted once
//! as guard closed (`removals_guard_closed`), not as undrained.
//!
//! **No established receiver.** A removal with no established receiver
//! ends at once, with no linger: it drains nothing and nobody would read
//! its EOS. It is counted once (`removals_unestablished`).

use std::num::NonZeroU16;

use karyos_io::backend::{
    Commit, Exposure, FlushRequest, GateDecision, SenderGate, SenderToken, TxBackend, TxFrame,
    TxItemOutcome, TxOptions,
};
use karyos_io::lanes::LaneGate;
use karyos_io::sockets::endpoint::SocketsTx;
use karyos_io::sockets::ops::SocketOps;
use karyos_protocol::frame::{Flags, FrameType, HEADER_LENGTH, Lane, Word0};

use super::Outbound;
use crate::embedded::StreamTerms;

/// One lane's EOS: its seal and when it was first and last sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LaneEos {
    seal: u64,
    first: u64,
    last: u64,
}

/// The removal state of a publication.
#[derive(Debug)]
pub(crate) struct Removal {
    /// The registration the removal named, echoed when it is drained.
    registration: u64,
    /// `publication_linger`, in the network's clock (ns).
    linger: u64,
    /// The EOS repeat cadence (ns).
    interval: u64,
    /// Per lane, its EOS once sent.
    eos: [Option<LaneEos>; 4],
    /// The removal's first duty, from which `linger` bounds the drain.
    start: Option<u64>,
    /// Per lane, given up undrained at the bound: it sends no EOS.
    abandoned: [bool; 4],
    /// Whether a lane was given up, so the removal counts once.
    undrained: bool,
    /// Whether a lane's closed guard withheld its EOS, so the removal
    /// counts once.
    guard_closed: bool,
    /// Whether the linger is over.
    drained: bool,
    /// Whether the drained publication was reported to the conductor.
    reported: bool,
}

/// What one removal step did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct RemovalStep {
    /// The linger is over.
    pub(crate) drained: bool,
    /// EOS frames submitted.
    pub(crate) sent: u32,
    /// A lane was given up undrained at the bound, for the first time in
    /// this removal.
    pub(crate) gave_up: bool,
    /// A lane's closed guard withheld its EOS (it drained, or was given up
    /// at the bound), for the first time in this removal.
    pub(crate) guard_closed: bool,
}

/// What sending a lane's EOS did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EosSent {
    /// Submitted.
    Submitted,
    /// Not taken now: tried again at the next cycle.
    NotSent,
    /// The lane's guard closed: no EOS leaves it, and its linger runs as
    /// if one did.
    Closed,
}

/// The gate of an EOS frame: one header-only frame, always permitted (a
/// closed guard's lane sends none, checked before the frame is claimed).
struct EosGate;

impl SenderGate for EosGate {
    fn check(&mut self, candidate: &Exposure<'_>) -> GateDecision {
        match u16::try_from(candidate.tokens.len())
            .ok()
            .and_then(NonZeroU16::new)
        {
            Some(count) => GateDecision::Permit { count },
            None => GateDecision::Deny,
        }
    }
}

impl<T: StreamTerms> Outbound<T> {
    /// Starts the removal: no new receiver, no SETUP; the lanes drain to
    /// their seals and then send EOS every `interval` for `linger`.
    pub(crate) fn begin_removal(&mut self, registration: u64, linger: u64, interval: u64) {
        if self.removal.is_none() {
            self.removal = Some(Box::new(Removal {
                registration,
                linger,
                interval,
                eos: [None; 4],
                start: None,
                abandoned: [false; 4],
                undrained: false,
                guard_closed: false,
                drained: false,
                reported: false,
            }));
        }
    }

    /// Whether the publication is being removed.
    #[must_use]
    pub(crate) fn removing(&self) -> bool {
        self.removal.is_some()
    }

    /// The EOS frames of a removing publication at `now`, on `tx` when the
    /// sender holds its TX half: each lane drained to its seal by the drain
    /// bound sends its EOS when it is due, and one not drained by then is
    /// given up. Returns what it did.
    pub(crate) fn serve_removal<O: SocketOps>(
        &mut self,
        mut tx: Option<&mut SocketsTx<O>>,
        now: u64,
    ) -> RemovalStep {
        let mut step = RemovalStep::default();
        let lanes = self.readers.len();
        let Some(removal) = self.removal.as_deref_mut() else {
            return step;
        };
        let start = *removal.start.get_or_insert(now);
        let (linger, interval) = (removal.linger, removal.interval);
        // The drain bound: `linger`, but never less than one EOS interval,
        // so a zero linger still gives the tail the conductor's seal
        // positioning (a later step of the same driver cycle) and one
        // cadence to drain.
        let bound = linger.max(interval);
        // The network clock is monotonic; a reading before the start (never)
        // waits for a later cycle.
        let Some(age) = now.checked_sub(start) else {
            return step;
        };
        for lane in 0..lanes {
            let Some(removal) = self.removal.as_deref() else {
                return step;
            };
            let eos = removal.eos.get(lane).copied().flatten();
            if removal.abandoned.get(lane).copied().unwrap_or(true) {
                continue;
            }
            let seal = self.drained_seal(lane);
            let due = match (seal, eos) {
                // A first EOS only within the drain bound.
                (Some(_), None) => age <= bound,
                (Some(_), Some(eos)) => {
                    linger > 0 && now.checked_sub(eos.last).is_none_or(|gap| gap >= interval)
                }
                (None, _) => false,
            };
            if eos.is_none() && !due && age >= bound {
                // Not drained by the bound: no EOS, ever. A lane its closed
                // guard stopped is counted as such, not as undrained.
                let closed = self.guard_closed(lane);
                if let Some(removal) = self.removal.as_deref_mut() {
                    if let Some(abandoned) = removal.abandoned.get_mut(lane) {
                        *abandoned = true;
                    }
                    if closed {
                        step.guard_closed |= !std::mem::replace(&mut removal.guard_closed, true);
                    } else if !removal.undrained {
                        removal.undrained = true;
                        step.gave_up = true;
                    }
                }
                continue;
            }
            let (Some(seal), true, Some(tx)) = (seal, due, tx.as_deref_mut()) else {
                continue;
            };
            match self.send_eos(tx, lane, seal) {
                EosSent::NotSent => continue,
                EosSent::Closed => {
                    if let Some(removal) = self.removal.as_deref_mut() {
                        step.guard_closed |= !std::mem::replace(&mut removal.guard_closed, true);
                    }
                }
                EosSent::Submitted => {
                    if let Some(next) = step.sent.checked_add(1) {
                        step.sent = next;
                    }
                }
            }
            if let Some(slot) = self
                .removal
                .as_deref_mut()
                .and_then(|removal| removal.eos.get_mut(lane))
            {
                *slot = Some(match *slot {
                    Some(eos) => LaneEos { last: now, ..eos },
                    None => LaneEos {
                        seal,
                        first: now,
                        last: now,
                    },
                });
            }
        }
        let Some(removal) = self.removal.as_deref_mut() else {
            return step;
        };
        // Every lane sent its EOS or was given up; the bound passed; and the
        // latest first EOS had its full linger.
        let resolved = (0..lanes).all(|lane| {
            removal.eos.get(lane).copied().flatten().is_some()
                || removal.abandoned.get(lane).copied().unwrap_or(true)
        });
        let latest = removal.eos.iter().flatten().map(|eos| eos.first).max();
        let lingered =
            latest.is_none_or(|first| now.checked_sub(first).is_some_and(|gap| gap >= linger));
        // A lane given up was resolved at the drain bound, past `linger`.
        removal.drained |= resolved && age >= linger && lingered;
        step.drained = removal.drained;
        step
    }

    /// The registration of a drained publication the conductor was not
    /// told of yet.
    #[must_use]
    pub(crate) fn drained_unreported(&self) -> Option<u64> {
        self.removal
            .as_deref()
            .filter(|removal| removal.drained && !removal.reported)
            .map(|removal| removal.registration)
    }

    /// Runs the linger from `now` with no EOS, as on every lane of a
    /// publication that cannot send one yet (a routed one).
    pub(crate) fn linger_without_eos(&mut self, now: u64) {
        let lanes = self.readers.len();
        let Some(removal) = self.removal.as_deref_mut() else {
            return;
        };
        for slot in removal.eos.iter_mut().take(lanes) {
            slot.get_or_insert(LaneEos {
                seal: 0,
                first: now,
                last: now,
            });
        }
        let first = removal.eos.iter().flatten().map(|eos| eos.first).max();
        let linger = removal.linger;
        removal.drained |=
            first.is_some_and(|first| now.checked_sub(first).is_some_and(|age| age >= linger));
    }

    /// Ends the linger at once: a removing publication with no established
    /// receiver drains nothing, and nobody would read its EOS. Returns
    /// whether this ended it (the first call).
    pub(crate) fn drain_now(&mut self) -> bool {
        self.removal
            .as_deref_mut()
            .is_some_and(|removal| !std::mem::replace(&mut removal.drained, true))
    }

    /// Records that the conductor was told the publication is drained.
    pub(crate) fn drained_reported(&mut self) {
        if let Some(removal) = self.removal.as_deref_mut() {
            removal.reported = true;
        }
    }

    /// The seal of `lane` once its first sends reached it: the seal is
    /// positioned, every frame below it was submitted and nothing is
    /// staged or pending.
    fn drained_seal(&self, lane: usize) -> Option<u64> {
        let seal = self.readers.get(lane)?.seal_position()?;
        let track = self.tracks.get(lane)?;
        let idle = track.staged.is_empty() && self.sender.pending(lane).unwrap_or(0) == 0;
        (idle && track.high >= seal && self.readers.get(lane)?.position() >= seal).then_some(seal)
    }

    /// Whether `lane`'s guard closed: the gate, asked, aborts the lane for
    /// good (GC-6). A lane held only by its rate is not closed.
    fn guard_closed(&mut self, lane: usize) -> bool {
        self.guard
            .as_deref_mut()
            .is_some_and(|guard| !LaneGate::admits(guard, lane) && LaneGate::aborting(guard, lane))
    }

    /// Sends `lane`'s EOS, a header-only DATA frame at `seal`, on the lane's
    /// queue. A lane whose guard closed sends none.
    fn send_eos<O: SocketOps>(&mut self, tx: &mut SocketsTx<O>, lane: usize, seal: u64) -> EosSent {
        if self
            .guard
            .as_deref_mut()
            .is_some_and(|guard| !LaneGate::admits(guard, lane))
        {
            return EosSent::Closed;
        }
        if self.write_eos(tx, lane, seal) {
            EosSent::Submitted
        } else {
            EosSent::NotSent
        }
    }

    /// Claims, writes and flushes `lane`'s EOS frame at `seal`; `true` when
    /// it was submitted.
    fn write_eos<O: SocketOps>(&mut self, tx: &mut SocketsTx<O>, lane: usize, seal: u64) -> bool {
        let (Some(reader), Some(queue)) = (self.readers.get(lane), self.queues.get(lane).copied())
        else {
            return false;
        };
        let config = reader.subscription().buffer().config();
        let term_length = u64::from(config.term_length.get());
        let Some((count, offset)) = seal
            .checked_div(term_length)
            .and_then(|count| u32::try_from(count).ok())
            .zip(seal.checked_rem(term_length))
            .and_then(|(count, offset)| Some((count, i32::try_from(offset).ok()?)))
        else {
            return false;
        };
        let Ok(lane_id) = u8::try_from(lane)
            .map_err(drop)
            .and_then(|lane| Lane::try_new(lane).map_err(drop))
        else {
            return false;
        };
        let header = HEADER_LENGTH as usize;
        let mut bytes = [0u8; HEADER_LENGTH as usize];
        let word0 = Word0::new(
            HEADER_LENGTH as i32,
            Flags::new(true, true, true, false, lane_id),
            FrameType::Data,
        );
        let term_id = config.initial_term_id.get().wrapping_add(count);
        for (at, field) in [
            (0, word0.pack().to_le_bytes().as_slice()),
            (8, offset.to_le_bytes().as_slice()),
            (12, config.session_id.to_le_bytes().as_slice()),
            (16, config.stream_id.to_le_bytes().as_slice()),
            (20, term_id.to_le_bytes().as_slice()),
        ] {
            if let Some(target) = bytes.get_mut(at..at + field.len()) {
                target.copy_from_slice(field);
            }
        }
        let Ok(mut frame) = tx.claim_tx(queue, header) else {
            return false;
        };
        let Some(target) = frame.bytes_mut().get_mut(..header) else {
            return false;
        };
        target.copy_from_slice(&bytes);
        if frame
            .commit(Commit {
                len: header,
                token: SenderToken::new(0),
                options: TxOptions::none(),
            })
            .is_err()
        {
            return false;
        }
        let _ = tx.flush(
            FlushRequest {
                queue,
                max_datagrams: NonZeroU16::MIN,
                max_bytes: u32::MAX,
            },
            &mut EosGate,
            &mut self.report,
        );
        let mut submitted = false;
        while let Some(entry) = self.report.pop_front() {
            submitted |= matches!(entry.outcome, TxItemOutcome::Submitted { .. });
        }
        if !submitted {
            // Not taken now: dropped, and sent again at the next cadence.
            let _ = tx.cancel_pending(queue, &mut self.report);
            while self.report.pop_front().is_some() {}
        }
        submitted
    }
}
