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

/// What the agent's records did, for the report and for tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AgentCounts {
    /// Records stored in the journal.
    pub stored: u64,
    /// Records the full journal dropped (also counted in its drop ranges).
    pub dropped: u64,
    /// Records the journal refused (closed, exhausted, clock regression).
    pub refused: u64,
}

/// The trace hook of one client handle. It owns its journal's writer; its
/// clock's domain is the writer's collection clock.
#[derive(Debug)]
pub struct TraceAgent<R = OsRandom, C = MonotonicClock> {
    sampler: Sampler,
    ids: BufferedIds<R>,
    clock: C,
    writer: TraceWriter,
    counts: AgentCounts,
}

impl<R: RandomSource, C: TraceClock> TraceAgent<R, C> {
    /// An agent deciding with `policy`, taking ids from `ids`, stamping with
    /// `clock` and recording into `writer`, whose collection clock must be
    /// `clock`'s domain (control path).
    #[must_use]
    pub fn new(policy: Sampling, ids: BufferedIds<R>, clock: C, writer: TraceWriter) -> Self {
        Self {
            sampler: Sampler::new(policy),
            ids,
            clock,
            writer,
            counts: AgentCounts::default(),
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
            Ok(Append::Stored { .. }) => self.counts.stored += 1,
            Ok(Append::Dropped { .. }) => self.counts.dropped += 1,
            Err(_) => self.counts.refused += 1,
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
        match self
            .sampler
            .decide(incoming.map(|ext| TraceIds::from(*ext)), &mut self.ids)
        {
            Decision::Traced(ids) => Some(TraceExtension::from(ids)),
            Decision::Untraced | Decision::IdsUnavailable | Decision::MessageIdsExhausted => None,
        }
    }

    fn on_committed(&mut self, ext: &TraceExtension, at: &Committed) {
        let observed = self.clock.now();
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
