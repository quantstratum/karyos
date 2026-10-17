// SPDX-License-Identifier: Apache-2.0

//! A publication lane's header-only DATA frames (SPEC §6, item 4: idle
//! senders emit heartbeats; the frame table: a header-only DATA frame with
//! no payload is a heartbeat).
//!
//! An established single-path publication's lane that submitted no DATA
//! for `sender_heartbeat_interval` sends one at its next position, with
//! BEGIN and END and no EOS, and again every interval while it stays
//! idle; any DATA it submits restarts the wait. A receiver's image then
//! learns where the lane stands, so a lost tail shows as a hole it NAKs,
//! instead of waiting for liveness to retire the image. A removal's EOS
//! (`removal`) is the same frame with the EOS flag, and replaces the idle
//! heartbeat while the publication is removed. A lane whose guard does not
//! admit it sends neither (GC-6). Routed publications send PATH_HB instead
//! (redundant-paths.md RP-3).

use std::num::NonZeroU16;

use karyos_io::backend::{
    Commit, Exposure, FlushRequest, GateDecision, SenderGate, SenderToken, TxBackend, TxFrame,
    TxItemOutcome, TxOptions, TxQueueId,
};
use karyos_io::lanes::LaneGate;
use karyos_io::sockets::endpoint::SocketsTx;
use karyos_io::sockets::ops::SocketOps;
use karyos_protocol::frame::{Flags, FrameType, HEADER_LENGTH, Lane, Word0};

use super::Outbound;
use crate::embedded::StreamTerms;

/// The gate of a header-only frame: one frame, always permitted (a lane
/// whose guard does not admit it sends none, checked before the frame is
/// claimed).
struct HeaderGate;

impl SenderGate for HeaderGate {
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
    /// The idle heartbeats due at `now`: each lane idle for `interval`,
    /// with nothing staged or pending, sends one at its next position.
    /// None while the publication is removed (its EOS replaces them).
    /// Returns the heartbeats submitted.
    pub(crate) fn serve_heartbeats<O: SocketOps>(
        &mut self,
        tx: &mut SocketsTx<O>,
        now: u64,
        interval: u64,
    ) -> u32 {
        if self.removing() {
            return 0;
        }
        let mut sent = 0u32;
        for lane in 0..self.readers.len() {
            let busy = self
                .tracks
                .get(lane)
                .is_none_or(|track| !track.staged.is_empty())
                || self.sender.pending(lane).unwrap_or(0) > 0;
            let Some(since) = self.idle_since.get_mut(lane) else {
                continue;
            };
            if busy {
                *since = Some(now);
                continue;
            }
            let since = *since.get_or_insert(now);
            if now.checked_sub(since).is_none_or(|idle| idle < interval) {
                continue;
            }
            if self
                .guard
                .as_deref_mut()
                .is_some_and(|guard| !LaneGate::admits(guard, lane))
            {
                continue;
            }
            let Some(position) = self.readers.get(lane).map(|reader| reader.position()) else {
                continue;
            };
            if self.write_heartbeat(tx, lane, position, false) {
                if let Some(slot) = self.idle_since.get_mut(lane) {
                    *slot = Some(now);
                }
                sent = sent.checked_add(1).unwrap_or(sent);
            }
        }
        sent
    }

    /// Claims, writes and flushes a header-only DATA frame of `lane` at
    /// `position`, with the EOS flag when `eos` (a removal's EOS, §7) or
    /// without it (an idle heartbeat, SPEC §6); `true` when it was
    /// submitted. Not taken now, it is dropped: the caller sends it again
    /// at its next cadence. The caller checks the lane's guard first.
    pub(super) fn write_heartbeat<O: SocketOps>(
        &mut self,
        tx: &mut SocketsTx<O>,
        lane: usize,
        position: u64,
        eos: bool,
    ) -> bool {
        let Some(queue) = self.queues.get(lane).copied() else {
            return false;
        };
        self.write_heartbeat_on(tx, queue, lane, position, eos)
    }

    /// [`Outbound::write_heartbeat`] on `queue`, a queue of `tx`: the
    /// lane's own, or one route's queue of the lane on redundant paths.
    pub(super) fn write_heartbeat_on<O: SocketOps>(
        &mut self,
        tx: &mut SocketsTx<O>,
        queue: TxQueueId,
        lane: usize,
        position: u64,
        eos: bool,
    ) -> bool {
        let Some(reader) = self.readers.get(lane) else {
            return false;
        };
        let config = reader.subscription().buffer().config();
        let term_length = u64::from(config.term_length.get());
        let Some((count, offset)) = position
            .checked_div(term_length)
            .and_then(|count| u32::try_from(count).ok())
            .zip(position.checked_rem(term_length))
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
            Flags::new(true, true, eos, false, lane_id),
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
            &mut HeaderGate,
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
