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

/// The facts of a journal the agent closed (§5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalFacts {
    /// The publication.
    pub publication: PublicationIdentity,
    /// The start the agent recorded when the journal arrived.
    pub start: u64,
    /// The sender's pickup boundary or the receiver's commit boundary.
    pub boundary: u64,
    /// A receiver's first sealed gap; `None` on the sender.
    pub first_gap: Option<u64>,
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
    pub(crate) fn command<O: SocketOps>(
        &mut self,
        publications: &mut [Box<Outbound>],
        command: AgentCommand<O>,
    ) -> Option<(Reservation, AgentEvent<O>)> {
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
                        .and_then(|outbound| outbound.trace(usize::from(lane.get()), publication)),
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
            } => {
                let traced = publications
                    .iter_mut()
                    .find_map(|outbound| outbound.untrace(usize::from(lane.get()), &publication));
                if traced.is_some()
                    && let Some(hook) = self.hook.as_mut()
                {
                    hook.0.close_journal(NetSide::Sender, &publication, lane);
                }
                let facts = traced.map(|traced| JournalFacts {
                    publication,
                    start: traced.start,
                    boundary: traced.boundary,
                    first_gap: None,
                });
                Some((
                    reply,
                    AgentEvent::NetworkJournalClosed {
                        agent,
                        publication,
                        lane,
                        facts,
                    },
                ))
            }
            _ => None,
        }
    }
}

/// The receiver agent's hook until its trace points land (P2.12 step 3,
/// PR 2): it holds the hook and refuses every journal.
#[derive(Debug, Default)]
pub(crate) struct ReceiverTrace {
    hook: Option<TraceHook>,
}

impl ReceiverTrace {
    /// Serves a network trace command; `None` for any other command.
    pub(crate) fn command<O: SocketOps>(
        &mut self,
        command: AgentCommand<O>,
    ) -> Option<(Reservation, AgentEvent<O>)> {
        let agent = AgentKind::Receiver;
        let event = match command {
            AgentCommand::SetNetworkTrace { reply, hook } => (
                reply,
                AgentEvent::NetworkTraceSet {
                    agent,
                    previous: core::mem::replace(&mut self.hook, hook),
                    closed: Some(0),
                },
            ),
            AgentCommand::OpenNetworkJournal { reply, journal, .. } => {
                (reply, AgentEvent::NetworkJournalRefused { agent, journal })
            }
            AgentCommand::CloseNetworkJournal {
                reply,
                publication,
                lane,
            } => (
                reply,
                AgentEvent::NetworkJournalClosed {
                    agent,
                    publication,
                    lane,
                    facts: None,
                },
            ),
            _ => return None,
        };
        Some(event)
    }
}

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
