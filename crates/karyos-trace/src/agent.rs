// SPDX-License-Identifier: Apache-2.0

//! [`TraceAgent`], the [`TraceHook`] of `karyos-trace`
//! (`quantstratum-docs: karyos/design/trace-data-path.md`, batch p6a): a
//! [`Sampler`], an [`IdSource`], a [`TraceClock`] and a [`TraceWriter`].

use karyos_protocol::frame::TraceExtension;
use karyos_protocol::journal::{Append, Stamp};
use karyos_protocol::trace_hook::{
    Committed, Delivered, PublicationIdentity, PublishContext, SubscriberIdentity, TraceHook,
};

use crate::ids::{BufferedIds, OsRandom, RandomSource};
use crate::journal::TraceWriter;
use crate::record::{ObservedTime, Point, PublicationId, SubscriberId, TraceIds, TraceRecord};
use crate::sampling::{Decision, IdSource, Sampler, Sampling};
use crate::trace_clock::{MonotonicClock, TraceClock};

impl From<TraceExtension> for TraceIds {
    fn from(ext: TraceExtension) -> Self {
        Self {
            trace_id: ext.trace_id,
            span_id: ext.span_id,
            parent_span_id: ext.parent_span_id,
            message_id: ext.message_id,
        }
    }
}

impl From<TraceIds> for TraceExtension {
    fn from(ids: TraceIds) -> Self {
        Self {
            extension_flags: 0,
            trace_id: ids.trace_id,
            span_id: ids.span_id,
            parent_span_id: ids.parent_span_id,
            message_id: ids.message_id,
        }
    }
}

impl From<PublicationIdentity> for PublicationId {
    fn from(identity: PublicationIdentity) -> Self {
        Self {
            driver: identity.driver,
            registration: identity.registration,
            stream_id: identity.stream_id,
            session_id: identity.session_id,
            incarnation: identity.incarnation,
        }
    }
}

impl From<SubscriberIdentity> for SubscriberId {
    fn from(identity: SubscriberIdentity) -> Self {
        Self {
            driver: identity.driver,
            registration: identity.registration,
            incarnation: identity.incarnation,
        }
    }
}

/// One of the [`AgentCounts`] counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AgentCounter {
    /// [`AgentCounts::stored`].
    Stored,
    /// [`AgentCounts::dropped`].
    Dropped,
    /// [`AgentCounts::refused`].
    Refused,
}

/// What the agent's records did, for the report and for tests. Counters are
/// checked: a counter that would overflow keeps its value, never wraps or
/// saturates silently, and the first such counter is reported in
/// `overflowed` (SPEC.md §14, ADR-0007). An overflow never changes the
/// observation itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AgentCounts {
    /// Records stored in the journal.
    pub stored: u64,
    /// Records the full journal dropped (also counted in its drop ranges).
    pub dropped: u64,
    /// Records the journal refused (closed, exhausted, a collection clock
    /// other than the writer's).
    pub refused: u64,
    /// The first counter that would have overflowed; it stays set.
    pub overflowed: Option<AgentCounter>,
}

impl AgentCounts {
    fn count(&mut self, counter: AgentCounter) {
        let value = match counter {
            AgentCounter::Stored => &mut self.stored,
            AgentCounter::Dropped => &mut self.dropped,
            AgentCounter::Refused => &mut self.refused,
        };
        match value.checked_add(1) {
            Some(next) => *value = next,
            None => {
                self.overflowed.get_or_insert(counter);
            }
        }
    }
}

/// Fresh traces decided by [`TraceHook::on_publish`] whose `Publish` was
/// not recorded yet. A handle commits a message soon after deciding it, so
/// a few suffice; past this the oldest is forgotten and its `Publish`
/// records without the `root` flag, which only narrows a tool's scope.
const PENDING_ROOTS: usize = 16;

/// The trace hook of one client handle. It owns its journal's writer; its
/// clock's domain is the writer's collection clock.
///
/// It sets the `root` flag (`quantstratum-docs:
/// karyos/design/trace-records.md`, "Root flag") on the `Publish` record of
/// a message it decided as a fresh trace, one without incoming context,
/// never on a child or a parentless join.
#[derive(Debug)]
pub struct TraceAgent<R = OsRandom, C = MonotonicClock> {
    sampler: Sampler,
    ids: BufferedIds<R>,
    clock: C,
    writer: TraceWriter,
    counts: AgentCounts,
    /// `(trace_id, span_id)` of fresh traces awaiting their `Publish`.
    roots: Vec<([u64; 2], u64)>,
}

impl<R: RandomSource, C: TraceClock> TraceAgent<R, C> {
    /// An agent deciding with `policy`, taking ids from `ids`, stamping with
    /// `clock` and recording into `writer` (control path). The writer's
    /// collection clock must be `clock`'s domain: every stamp is taken from
    /// `clock`, so with another collection clock every record is refused
    /// and counted in [`AgentCounts::refused`].
    #[must_use]
    pub fn new(policy: Sampling, ids: BufferedIds<R>, clock: C, writer: TraceWriter) -> Self {
        Self {
            sampler: Sampler::new(policy),
            ids,
            clock,
            writer,
            counts: AgentCounts::default(),
            roots: Vec::with_capacity(PENDING_ROOTS),
        }
    }

    /// The sampler, to change the policy on the control path.
    pub fn sampler_mut(&mut self) -> &mut Sampler {
        &mut self.sampler
    }

    /// What the records did so far.
    #[must_use]
    pub fn counts(&self) -> AgentCounts {
        self.counts
    }

    /// The clock.
    #[must_use]
    pub fn clock(&self) -> &C {
        &self.clock
    }

    /// Closes the journal when the handle closes; the collector drains it.
    pub fn close(&mut self) {
        self.writer.close();
    }

    fn record(&mut self, record: TraceRecord, observed: ObservedTime) {
        let collected = Stamp {
            time: observed.time,
            clock: observed.clock,
            epoch: observed.epoch,
        };
        match self.writer.record(&record, collected) {
            Ok(Append::Stored { .. }) => self.counts.count(AgentCounter::Stored),
            Ok(Append::Dropped { .. }) => self.counts.count(AgentCounter::Dropped),
            Err(_) => self.counts.count(AgentCounter::Refused),
        }
    }
}

impl<R: RandomSource, C: TraceClock> TraceHook for TraceAgent<R, C>
where
    BufferedIds<R>: IdSource,
{
    fn on_publish(
        &mut self,
        incoming: Option<&TraceExtension>,
        _message: &PublishContext,
    ) -> Option<TraceExtension> {
        // No context, or one whose trace id is zero: a fresh trace.
        let fresh = incoming.is_none_or(|ext| ext.trace_id == [0, 0]);
        match self
            .sampler
            .decide(incoming.map(|ext| TraceIds::from(*ext)), &mut self.ids)
        {
            Decision::Traced(ids) => {
                if fresh {
                    if self.roots.len() == PENDING_ROOTS {
                        let _ = self.roots.remove(0);
                    }
                    self.roots.push((ids.trace_id, ids.span_id));
                }
                Some(TraceExtension::from(ids))
            }
            Decision::Untraced | Decision::IdsUnavailable | Decision::MessageIdsExhausted => None,
        }
    }

    fn on_committed(&mut self, ext: &TraceExtension, at: &Committed) {
        let observed = self.clock.now();
        let pending = self
            .roots
            .iter()
            .position(|root| *root == (ext.trace_id, ext.span_id));
        if let Some(index) = pending {
            let _ = self.roots.remove(index);
        }
        self.record(
            TraceRecord {
                point: Point::Publish,
                publication: at.publication.into(),
                lane: at.lane.get(),
                position: at.position,
                ids: TraceIds::from(*ext),
                observed,
                subscriber: None,
                packet: None,
                network: None,
                root: pending.is_some(),
            },
            observed,
        );
    }

    fn on_delivered(&mut self, ext: &TraceExtension, at: &Delivered) {
        let observed = self.clock.now();
        self.record(
            TraceRecord {
                point: Point::SubscriberPoll,
                publication: at.publication.into(),
                lane: at.lane.get(),
                position: at.position,
                ids: TraceIds::from(*ext),
                observed,
                subscriber: Some(at.subscriber.into()),
                packet: None,
                network: None,
                root: false,
            },
            observed,
        );
    }

    fn maintain(&mut self) {
        // A failed refill leaves the buffer as it was: later messages are
        // published untraced until a refill succeeds.
        let _ = self.ids.refill();
    }
}

#[cfg(test)]
mod tests;
