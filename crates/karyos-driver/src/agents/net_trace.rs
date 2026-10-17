// SPDX-License-Identifier: Apache-2.0

//! The network trace points of the agents (`quantstratum-docs:
//! karyos/design/trace-network.md` §4 and §5, NT-1 to NT-4; P2.12 step 3,
//! coordinator ACS 15840 and 15847).
//!
//! - **Hook.** Each agent holds at most one [`NetworkTraceHook`], set by
//!   the conductor's `SetNetworkTrace` command. The data path pays one
//!   branch per staged datagram without it, and allocates nothing with it.
//! - **Journals.** The conductor creates a journal and hands it over with
//!   `OpenNetworkJournal`. The agent records the lane's start, its own
//!   next position when the journal arrives (the start fact of §5), and
//!   answers it to the conductor. `CloseNetworkJournal` answers the
//!   boundary the agent reached. A journal the agent cannot take comes
//!   back to the conductor, which closes it.
//! - **Frames.** A staged datagram is scanned for DATA frames that carry
//!   EXT; each records a `SenderPickup` once its datagram is committed to
//!   TX storage. An EXT that does not decode is counted and not traced.

use karyos_io::sockets::ops::SocketOps;
use karyos_protocol::frame::Lane;
use karyos_protocol::frame::{EXTENSION_LENGTH, FrameType, HEADER_LENGTH, TraceExtension, Word0};
use karyos_protocol::trace_hook::{NetSide, NetworkTraceHook, PublicationIdentity};
use karyos_sys::sizing::align_frame;

use super::data::Outbound;
use super::ring::Reservation;
use super::{AgentCommand, AgentEvent, AgentKind};

/// A network trace hook as the agents' rings carry it.
pub struct TraceHook(pub Box<dyn NetworkTraceHook>);

impl core::fmt::Debug for TraceHook {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TraceHook")
    }
}

/// One lane of a publication with an open network journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TracedLane {
    /// The publication the journal observes.
    pub(crate) publication: PublicationIdentity,
    /// The journal number.
    pub(crate) number: u64,
    /// The journal's start: the lane's next position when it arrived.
    pub(crate) start: u64,
    /// The end of the highest datagram picked up for a first send since
    /// the start; the start while nothing was picked up.
    pub(crate) boundary: u64,
    /// Positions read below the boundary whose datagram never reached TX
    /// storage (its commit failed): a reset's resend of them is their
    /// first pickup, so it is recorded (ACS 15882). One range per lane.
    pub(crate) unpicked: Option<(u64, u64)>,
}

impl TracedLane {
    /// Whether a frame at `position` was never picked up before.
    pub(crate) fn first_pickup(&self, position: u64) -> bool {
        position >= self.boundary
            || self
                .unpicked
                .is_some_and(|(low, high)| low <= position && position < high)
    }
}

/// How many sealed gaps a receiver journal's facts keep in process
/// (trace-network.md §5, `fact_gap_intervals`).
pub const FACT_GAP_INTERVALS: usize = 16;

/// A receiver journal's sealed local gaps (§5): the first
/// [`FACT_GAP_INTERVALS`], each `[start, end)`, and whether more were
/// sealed. A report expects the journal for frames after the last kept gap
/// when the list overflowed, so a missing commit there is never a false
/// `Complete`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GapIntervals {
    intervals: [(u64, u64); FACT_GAP_INTERVALS],
    len: u8,
    overflowed: bool,
}

impl GapIntervals {
    /// Keeps the gap of `extent` bytes at `position`. A full list, or a gap
    /// whose end does not fit, sets the overflow flag instead, so a report
    /// stays conservative.
    pub(crate) fn push(&mut self, position: u64, extent: u32) {
        let end = position.checked_add(u64::from(extent));
        let next = self.len.checked_add(1);
        match (self.intervals.get_mut(usize::from(self.len)), end, next) {
            (Some(slot), Some(end), Some(next)) => {
                *slot = (position, end);
                self.len = next;
            }
            _ => self.overflowed = true,
        }
    }

    /// The kept gaps, lowest first as sealed.
    #[must_use]
    pub fn intervals(&self) -> &[(u64, u64)] {
        self.intervals
            .get(..usize::from(self.len))
            .unwrap_or_default()
    }

    /// Whether gaps beyond the kept ones were sealed.
    #[must_use]
    pub fn overflowed(&self) -> bool {
        self.overflowed
    }
}

/// The facts of a journal the agent closed (§5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalFacts {
    /// The publication.
    pub publication: PublicationIdentity,
    /// The journal number.
    pub number: u64,
    /// The start the agent recorded when the journal arrived.
    pub start: u64,
    /// The sender's pickup boundary or the receiver's commit boundary.
    pub boundary: u64,
    /// A receiver's first sealed gap; `None` on the sender.
    pub first_gap: Option<u64>,
    /// A receiver's sealed gaps; `None` on the sender, and in a facts
    /// answer repeated after the conductor already has them. Boxed when the
    /// journal opens (control path), so the events stay small and a close
    /// allocates nothing.
    pub gaps: Option<Box<GapIntervals>>,
}

impl JournalFacts {
    /// These facts, their gaps moved out of `self` (nothing allocates).
    #[must_use]
    pub(crate) fn take(&mut self) -> Self {
        Self {
            publication: self.publication,
            number: self.number,
            start: self.start,
            boundary: self.boundary,
            first_gap: self.first_gap,
            gaps: self.gaps.take(),
        }
    }
}

/// The sender agent's hook and its journal commands.
#[derive(Debug, Default)]
pub(crate) struct SenderTrace {
    hook: Option<TraceHook>,
}

impl SenderTrace {
    /// The hook, for the data path.
    pub(crate) fn hook(&mut self) -> Option<&mut (dyn NetworkTraceHook + 'static)> {
        self.hook.as_mut().map(|hook| &mut *hook.0)
    }

    /// Serves a network trace command over `publications`; `None` for any
    /// other command.
    pub(crate) fn command<O: SocketOps, T: crate::embedded::StreamTerms>(
        &mut self,
        publications: &mut [Box<Outbound<T>>],
        command: AgentCommand<O, T>,
    ) -> Option<(Reservation, AgentEvent<O, T>)> {
        let agent = AgentKind::Sender;
        match command {
            AgentCommand::SetNetworkTrace { reply, hook } => {
                // The conductor closes the journals first; any still open
                // close here through the hook that holds them.
                let mut closed = Some(0u64);
                for outbound in publications.iter_mut() {
                    outbound.untrace_all(|lane, traced| {
                        if let (Some(previous), Some(lane)) = (self.hook.as_mut(), lane_of(lane)) {
                            previous
                                .0
                                .close_journal(NetSide::Sender, &traced.publication, lane);
                        }
                        closed = closed.and_then(|count| count.checked_add(1));
                    });
                }
                let previous = core::mem::replace(&mut self.hook, hook);
                Some((
                    reply,
                    AgentEvent::NetworkTraceSet {
                        agent,
                        previous,
                        closed,
                    },
                ))
            }
            AgentCommand::OpenNetworkJournal {
                reply,
                endpoint,
                alias,
                journal,
            } => {
                let (publication, lane) = (journal.publication, journal.lane);
                let start = match (&self.hook, journal.side) {
                    (Some(_), NetSide::Sender) => publications
                        .iter_mut()
                        .find(|outbound| {
                            outbound.endpoint() == endpoint && outbound.alias() == alias
                        })
                        .and_then(|outbound| {
                            outbound.trace(usize::from(lane.get()), publication, journal.number)
                        }),
                    _ => None,
                };
                let event = match (start, self.hook.as_mut()) {
                    (Some(start), Some(hook)) => {
                        let number = journal.number;
                        hook.0.open_journal(journal);
                        AgentEvent::NetworkJournalOpened {
                            agent,
                            publication,
                            lane,
                            number,
                            start,
                        }
                    }
                    _ => AgentEvent::NetworkJournalRefused { agent, journal },
                };
                Some((reply, event))
            }
            AgentCommand::CloseNetworkJournal {
                reply,
                publication,
                lane,
                number,
            } => {
                let traced = publications
                    .iter_mut()
                    .find_map(|outbound| outbound.untrace(usize::from(lane.get()), number));
                if traced.is_some()
                    && let Some(hook) = self.hook.as_mut()
                {
                    hook.0.close_journal(NetSide::Sender, &publication, lane);
                }
                let facts = traced.map(|traced| JournalFacts {
                    publication,
                    number,
                    start: traced.start,
                    boundary: traced.boundary,
                    first_gap: None,
                    gaps: None,
                });
                Some((
                    reply,
                    AgentEvent::NetworkJournalClosed {
                        agent,
                        publication,
                        lane,
                        number,
                        facts,
                    },
                ))
            }
            _ => None,
        }
    }
}

/// One lane of an installed image with an open network journal (§4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TracedImageLane {
    /// The image's installed slot.
    pub(crate) slot: crate::sessions::receive::SlotRef,
    /// The lane.
    pub(crate) lane: Lane,
    /// The publication the image receives.
    pub(crate) publication: PublicationIdentity,
    /// The journal number.
    pub(crate) number: u64,
    /// The journal's start: the lane's next commit position when it
    /// arrived (the image join fact of §5).
    pub(crate) start: u64,
    /// The gaps sealed on the lane since the journal opened, boxed when it
    /// opened.
    pub(crate) gaps: Box<GapIntervals>,
}

/// A journal its image's retirement closed: posted to the conductor
/// unsolicited, and answered again to a later `CloseNetworkJournal`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RetiredJournal {
    pub(crate) lane: Lane,
    pub(crate) facts: JournalFacts,
    /// Whether the unsolicited `NetworkJournalClosed` was posted.
    pub(crate) posted: bool,
}

/// The receiver agent's hook, its traced image lanes and the journals
/// retirement closed (P2.12 step 3, PR 2). Both tables are allocated at
/// start, so the data path allocates nothing.
#[derive(Debug)]
pub(crate) struct ReceiverTrace {
    hook: Option<TraceHook>,
    lanes: Vec<TracedImageLane>,
    retired: Vec<RetiredJournal>,
    capacity: usize,
}

impl ReceiverTrace {
    /// Room for `capacity` traced image lanes.
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            hook: None,
            lanes: Vec::with_capacity(capacity),
            retired: Vec::with_capacity(capacity),
            capacity,
        }
    }

    /// The hook, for the data path.
    pub(crate) fn hook(&mut self) -> Option<&mut (dyn NetworkTraceHook + 'static)> {
        self.hook.as_mut().map(|hook| &mut *hook.0)
    }

    /// The traced lane `lane` of the image at `slot`, if it has a journal.
    pub(crate) fn traced(
        &self,
        slot: crate::sessions::receive::SlotRef,
        lane: Lane,
    ) -> Option<&TracedImageLane> {
        self.lanes
            .iter()
            .find(|traced| traced.slot == slot && traced.lane == lane)
    }

    /// Whether any lane has a journal: the data path's one branch.
    pub(crate) fn any(&self) -> bool {
        !self.lanes.is_empty()
    }

    /// The gap `[position, position + extent)` was sealed on `lane` of the
    /// image at `slot`: its journal, if any, keeps it.
    pub(crate) fn sealed(
        &mut self,
        slot: crate::sessions::receive::SlotRef,
        lane: Lane,
        position: u64,
        extent: u32,
    ) {
        if let Some(traced) = self
            .lanes
            .iter_mut()
            .find(|traced| traced.slot == slot && traced.lane == lane)
        {
            traced.gaps.push(position, extent);
        }
    }

    /// Replaces the hook; every journal still open closes through the
    /// previous one, without facts. Returns the previous hook and how many
    /// closed (`None` if the count overflowed).
    pub(crate) fn set_hook(&mut self, hook: Option<TraceHook>) -> (Option<TraceHook>, Option<u64>) {
        let mut closed = Some(0u64);
        for traced in self.lanes.drain(..) {
            if let Some(previous) = self.hook.as_mut() {
                previous
                    .0
                    .close_journal(NetSide::Receiver, &traced.publication, traced.lane);
            }
            closed = closed.and_then(|count| count.checked_add(1));
        }
        (core::mem::replace(&mut self.hook, hook), closed)
    }

    /// Opens `journal` on `traced`: refused (`Err` with the journal) with
    /// no hook, the wrong side, a lane already traced or no room.
    pub(crate) fn open(
        &mut self,
        traced: TracedImageLane,
        journal: karyos_protocol::trace_hook::NetJournal,
    ) -> Result<(), karyos_protocol::trace_hook::NetJournal> {
        let lane_taken = self.lanes.iter().any(|open| {
            (open.publication, open.lane) == (traced.publication, traced.lane)
                || (open.slot, open.lane) == (traced.slot, traced.lane)
        });
        let Some(hook) = self.hook.as_mut() else {
            return Err(journal);
        };
        if journal.side != NetSide::Receiver || lane_taken || self.lanes.len() >= self.capacity {
            return Err(journal);
        }
        hook.0.open_journal(journal);
        self.lanes.push(traced);
        Ok(())
    }

    /// Closes journal `number` with the facts `facts` gives for its open
    /// lane. A journal its image's retirement closed answers its facts
    /// again (idempotent); `None` when there is no such journal.
    pub(crate) fn close(
        &mut self,
        number: u64,
        facts: impl FnOnce(TracedImageLane) -> JournalFacts,
    ) -> Option<JournalFacts> {
        if let Some(index) = self.lanes.iter().position(|traced| traced.number == number) {
            let traced = self.lanes.swap_remove(index);
            if let Some(hook) = self.hook.as_mut() {
                hook.0
                    .close_journal(NetSide::Receiver, &traced.publication, traced.lane);
            }
            return Some(facts(traced));
        }
        // Closed by its image's retirement: the same facts again, and the
        // unsolicited event is no longer needed.
        let index = self
            .retired
            .iter()
            .position(|retired| retired.facts.number == number)?;
        Some(self.retired.swap_remove(index).facts)
    }

    /// The image at `slot` retires: every journal of its lanes closes now,
    /// with the facts `facts` gives, and is queued for the conductor. A
    /// full queue drops its oldest posted entry first; with none posted,
    /// the newest close keeps no entry and `dropped` is called for it, so
    /// the caller counts each one.
    pub(crate) fn retire(
        &mut self,
        slot: crate::sessions::receive::SlotRef,
        mut facts: impl FnMut(TracedImageLane) -> JournalFacts,
        mut dropped: impl FnMut(),
    ) {
        while let Some(index) = self.lanes.iter().position(|traced| traced.slot == slot) {
            let traced = self.lanes.swap_remove(index);
            if let Some(hook) = self.hook.as_mut() {
                hook.0
                    .close_journal(NetSide::Receiver, &traced.publication, traced.lane);
            }
            if self.retired.len() >= self.capacity
                && let Some(oldest) = self.retired.iter().position(|retired| retired.posted)
            {
                self.retired.remove(oldest);
            }
            if self.retired.len() < self.capacity {
                let lane = traced.lane;
                self.retired.push(RetiredJournal {
                    lane,
                    facts: facts(traced),
                    posted: false,
                });
            } else {
                dropped();
            }
        }
    }

    /// Posts each retired journal not posted yet through `post`, which
    /// hands the facts back when its ring was full: they wait for the next
    /// cycle. A posted journal's gaps go with the event; a later close
    /// answers its facts without them. Nothing allocates.
    pub(crate) fn post_retired(
        &mut self,
        mut post: impl FnMut(Lane, JournalFacts) -> Result<(), JournalFacts>,
    ) {
        for retired in self.retired.iter_mut().filter(|retired| !retired.posted) {
            if let Err(back) = post(retired.lane, retired.facts.take()) {
                retired.facts = back;
                return;
            }
            retired.posted = true;
        }
    }
}

/// The trace extension of a committed DATA frame: `None` without EXT,
/// `Some(None)` for an EXT that does not decode (counted, not traced).
pub(crate) fn frame_extension(
    frame: &karyos_sys::receive::ValidatedFrame<'_>,
) -> Option<Option<TraceExtension>> {
    let word0 = frame.image_word0();
    if word0.frame_type_code() != FrameType::Data.code() || !word0.flags().ext() {
        return None;
    }
    // The extension follows the header, within the body.
    let start = usize::try_from(HEADER_LENGTH)
        .ok()?
        .checked_sub(BODY_OFFSET)?;
    let end = start.checked_add(usize::try_from(EXTENSION_LENGTH).ok()?)?;
    Some(
        frame
            .body()
            .get(start..end)
            .and_then(|ext| TraceExtension::decode(ext).ok()),
    )
}

/// The header byte where a validated frame's body starts, after word 0
/// (`ValidatedFrame::body`).
const BODY_OFFSET: usize = 8;

fn lane_of(lane: usize) -> Option<Lane> {
    u8::try_from(lane)
        .ok()
        .and_then(|lane| Lane::try_new(lane).ok())
}

/// The most traced frames one datagram of `mtu` bytes can hold: each is
/// at least a header and an extension. `None` if that does not fit.
pub(crate) fn traced_frames_per_datagram(mtu: usize) -> Option<usize> {
    let smallest = usize::try_from(HEADER_LENGTH.checked_add(EXTENSION_LENGTH)?).ok()?;
    mtu.checked_div(smallest)?.checked_add(1)
}

/// Collects into `out`, within its capacity, the extension and position of
/// each DATA frame with EXT in the datagram `bytes`, read at stream
/// position `from`. Returns how many extensions did not decode, did not
/// fit their frame or found no room; those frames are not traced. `None`
/// when that count overflows.
pub(crate) fn traced_frames(
    bytes: &[u8],
    from: u64,
    out: &mut Vec<(TraceExtension, u64)>,
) -> Option<u64> {
    out.clear();
    let header = usize::try_from(HEADER_LENGTH).ok()?;
    let extension = usize::try_from(EXTENSION_LENGTH).ok()?;
    let traced_length = header.checked_add(extension)?;
    let mut skipped = 0u64;
    let mut offset = 0usize;
    while let Some(word) = offset
        .checked_add(8)
        .and_then(|end| bytes.get(offset..end))
        .and_then(|word| <[u8; 8]>::try_from(word).ok())
    {
        let Ok(word0) = Word0::unpack(u64::from_le_bytes(word)) else {
            break;
        };
        let Some(extent) = u32::try_from(word0.frame_length())
            .ok()
            .filter(|length| *length > 0)
            .and_then(|length| align_frame(length).ok())
            .and_then(|extent| usize::try_from(extent).ok())
        else {
            break;
        };
        if word0.frame_type_code() == FrameType::Data.code() && word0.flags().ext() {
            // A frame too short for its extension has none to read.
            let fits =
                usize::try_from(word0.frame_length()).is_ok_and(|length| length >= traced_length);
            let ext = offset
                .checked_add(header)
                .filter(|_| fits)
                .and_then(|start| bytes.get(start..start.checked_add(extension)?))
                .and_then(|ext| TraceExtension::decode(ext).ok());
            let position = u64::try_from(offset)
                .ok()
                .and_then(|offset| from.checked_add(offset));
            match (ext, position) {
                (Some(ext), Some(position)) if out.len() < out.capacity() => {
                    out.push((ext, position));
                }
                _ => skipped = skipped.checked_add(1)?,
            }
        }
        let Some(next) = offset.checked_add(extent) else {
            break;
        };
        offset = next;
    }
    Some(skipped)
}

#[cfg(test)]
mod tests;
