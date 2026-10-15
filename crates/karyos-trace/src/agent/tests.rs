// SPDX-License-Identifier: Apache-2.0

// Tests of the trace agent (`quantstratum-docs:
// karyos/design/trace-data-path.md`, "Tests", the parts batch p6a can show
// without the client).

use std::io;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use karyos_protocol::frame::Lane;

use super::*;
use crate::journal::{Collected, ObserverId, TraceCollector, trace_journal};

/// A deterministic source that fails the test if it is asked to fill while
/// `armed`: only the control path may refill.
struct Words {
    next: u64,
    armed: Arc<AtomicBool>,
}

impl RandomSource for Words {
    fn fill(&mut self, words: &mut [u64]) -> io::Result<()> {
        assert!(
            !self.armed.load(Ordering::SeqCst),
            "the data path asked for a refill"
        );
        for word in words {
            self.next += 1;
            *word = self.next;
        }
        Ok(())
    }
}

const DOMAIN: u64 = 11;

const PUBLICATION: PublicationIdentity = PublicationIdentity {
    driver: [1, 2],
    registration: 3,
    stream_id: 10,
    session_id: -4,
    incarnation: 1,
};

fn context() -> PublishContext {
    PublishContext {
        publication: PUBLICATION,
        lane: Lane::ZERO,
    }
}

type Agent = TraceAgent<Words, MonotonicClock>;

fn new_agent(
    policy: Sampling,
    ids: usize,
    capacity: usize,
) -> (Agent, TraceCollector, Arc<AtomicBool>) {
    let armed = Arc::new(AtomicBool::new(false));
    let source = Words {
        next: 0,
        armed: Arc::clone(&armed),
    };
    let ids = BufferedIds::new(ids, source).unwrap();
    let observer = ObserverId {
        driver: [1, 2],
        journal: 5,
    };
    let (writer, collector) = trace_journal(capacity, 4, observer, DOMAIN).unwrap();
    let agent = TraceAgent::new(policy, ids, MonotonicClock::new(DOMAIN), writer);
    armed.store(true, Ordering::SeqCst);
    (agent, collector, armed)
}

fn records(collector: &mut TraceCollector) -> Vec<TraceRecord> {
    let mut out = Vec::new();
    loop {
        match collector.take() {
            Collected::Record { record, .. } => out.push(record),
            Collected::Empty | Collected::Closed => return out,
            Collected::Corrupt { error, .. } => panic!("corrupt record: {error:?}"),
        }
    }
}

#[test]
fn test_trace_off_writes_no_ext_and_no_record() {
    let (mut agent, mut collector, _) = new_agent(Sampling::Off, 64, 8);
    for _ in 0..10 {
        assert_eq!(agent.on_publish(None, &context()), None);
    }
    assert!(records(&mut collector).is_empty());
    assert_eq!(agent.counts(), AgentCounts::default());
}

#[test]
fn test_trace_sampled_n_traces_every_nth_root() {
    let n = NonZeroU32::new(3).unwrap();
    let (mut agent, _collector, _) = new_agent(Sampling::Sampled(n), 256, 8);
    let traced: Vec<bool> = (0..9)
        .map(|_| agent.on_publish(None, &context()).is_some())
        .collect();
    assert_eq!(
        traced,
        [true, false, false, true, false, false, true, false, false]
    );
}

#[test]
fn test_trace_child_inherits_trace_id() {
    let (mut agent, _collector, _) = new_agent(Sampling::All, 64, 8);
    let parent = agent.on_publish(None, &context()).unwrap();
    assert_ne!(parent.trace_id, [0, 0]);
    let child = agent.on_publish(Some(&parent), &context()).unwrap();
    assert_eq!(child.trace_id, parent.trace_id);
    assert_ne!(child.span_id, parent.span_id);
    assert_eq!(child.parent_span_id, parent.span_id);
    assert!(child.message_id > parent.message_id);
    // A child of a traced parent is traced even when roots are not.
    let (mut off_roots, _collector, _) =
        new_agent(Sampling::Sampled(NonZeroU32::new(1000).unwrap()), 64, 8);
    let _ = off_roots.on_publish(None, &context());
    assert!(off_roots.on_publish(None, &context()).is_none());
    assert!(off_roots.on_publish(Some(&parent), &context()).is_some());
}

#[test]
fn test_trace_publish_and_poll_records_match() {
    let (mut publisher, mut published, _) = new_agent(Sampling::All, 64, 8);
    let (mut subscriber, mut polled, _) = new_agent(Sampling::Off, 64, 8);
    let ext = publisher.on_publish(None, &context()).unwrap();
    let committed = Committed {
        publication: PUBLICATION,
        lane: Lane::try_new(2).unwrap(),
        position: 4096,
    };
    publisher.on_committed(&ext, &committed);
    let subscriber_id = SubscriberIdentity {
        driver: [1, 2],
        registration: 9,
        incarnation: 1,
    };
    subscriber.on_delivered(
        &ext,
        &Delivered {
            publication: PUBLICATION,
            subscriber: subscriber_id,
            lane: committed.lane,
            position: committed.position,
        },
    );
    let [publish] = records(&mut published)[..] else {
        panic!("one Publish record");
    };
    let [poll] = records(&mut polled)[..] else {
        panic!("one SubscriberPoll record");
    };
    assert_eq!(publish.point, Point::Publish);
    assert_eq!(poll.point, Point::SubscriberPoll);
    for record in [publish, poll] {
        assert_eq!(record.publication, PublicationId::from(PUBLICATION));
        assert_eq!(record.lane, 2);
        assert_eq!(record.position, 4096);
        assert_eq!(record.ids, TraceIds::from(ext));
        assert_eq!(record.observed.clock, DOMAIN);
        assert_eq!(record.observed.epoch, MonotonicClock::epoch());
    }
    assert_eq!(publish.subscriber, None);
    assert_eq!(poll.subscriber, Some(SubscriberId::from(subscriber_id)));
    assert!(publish.observed.time <= poll.observed.time);
}

#[test]
fn test_trace_full_journal_drops_never_blocks() {
    let (mut agent, mut collector, _) = new_agent(Sampling::All, 4096, 2);
    let ext = agent.on_publish(None, &context()).unwrap();
    for position in 0..50 {
        agent.on_committed(
            &ext,
            &Committed {
                publication: PUBLICATION,
                lane: Lane::ZERO,
                position: position * 64,
            },
        );
    }
    let counts = agent.counts();
    assert_eq!(counts.stored + counts.dropped, 50);
    assert!(counts.dropped > 0);
    assert_eq!(counts.refused, 0);
    let stored = records(&mut collector);
    assert_eq!(stored.len() as u64, counts.stored);
    assert!(!collector.losses().ranges.is_empty());
}

#[test]
fn test_trace_ids_run_out_and_maintenance_refills() {
    let (mut agent, _collector, armed) = new_agent(Sampling::All, 6, 8);
    // Three words per root: two roots, then untraced.
    assert!(agent.on_publish(None, &context()).is_some());
    assert!(agent.on_publish(None, &context()).is_some());
    assert!(agent.on_publish(None, &context()).is_none());
    // The control path refills; the data path never did (the source would
    // have failed the test).
    armed.store(false, Ordering::SeqCst);
    agent.maintain();
    armed.store(true, Ordering::SeqCst);
    assert!(agent.on_publish(None, &context()).is_some());
}

#[test]
fn test_trace_custom_clock_records_its_own_domain() {
    struct Fixed;
    impl TraceClock for Fixed {
        fn now(&mut self) -> ObservedTime {
            ObservedTime {
                time: 500,
                clock: DOMAIN,
                epoch: 3,
                uncertainty: 9,
            }
        }
    }
    let ids = BufferedIds::new(
        16,
        Words {
            next: 0,
            armed: Arc::new(AtomicBool::new(false)),
        },
    )
    .unwrap();
    let observer = ObserverId {
        driver: [1, 2],
        journal: 6,
    };
    let (writer, mut collector) = trace_journal(4, 2, observer, DOMAIN).unwrap();
    let mut agent = TraceAgent::new(Sampling::All, ids, Fixed, writer);
    assert_eq!(
        agent.clock().provenance(),
        crate::trace_clock::ClockProvenance::Opaque
    );
    let ext = agent.on_publish(None, &context()).unwrap();
    agent.on_committed(
        &ext,
        &Committed {
            publication: PUBLICATION,
            lane: Lane::ZERO,
            position: 0,
        },
    );
    let [record] = records(&mut collector)[..] else {
        panic!("one record");
    };
    assert_eq!(record.observed.time, 500);
    assert_eq!(record.observed.uncertainty, 9);
}

#[test]
fn test_trace_extension_and_ids_convert_both_ways() {
    let ids = TraceIds {
        trace_id: [1, 2],
        span_id: 3,
        parent_span_id: 4,
        message_id: 5,
    };
    let ext = TraceExtension::from(ids);
    assert_eq!(ext.extension_flags, 0);
    assert_eq!(TraceIds::from(ext), ids);
    let mut bytes = [0u8; 64];
    ext.encode(&mut bytes).unwrap();
    assert_eq!(TraceExtension::decode(&bytes).unwrap(), ext);
}

#[test]
fn counters_are_checked_and_report_the_first_overflow() {
    let (mut agent, _collector, _) = new_agent(Sampling::All, 64, 8);
    let ext = agent.on_publish(None, &context()).unwrap();
    let at = Committed {
        publication: PUBLICATION,
        lane: Lane::ZERO,
        position: 0,
    };
    agent.counts.stored = u64::MAX;
    agent.on_committed(&ext, &at);
    assert_eq!(agent.counts().stored, u64::MAX);
    assert_eq!(agent.counts().overflowed, Some(super::AgentCounter::Stored));
    // Refusals after close: the refused counter at its limit stays there,
    // and the first overflow stays reported.
    agent.close();
    agent.counts.refused = u64::MAX - 1;
    agent.on_committed(&ext, &at);
    assert_eq!(agent.counts().refused, u64::MAX);
    agent.on_committed(&ext, &at);
    assert_eq!(agent.counts().refused, u64::MAX);
    assert_eq!(agent.counts().overflowed, Some(super::AgentCounter::Stored));
}

#[test]
fn the_dropped_counter_is_checked() {
    let (mut agent, _collector, _) = new_agent(Sampling::All, 64, 1);
    let ext = agent.on_publish(None, &context()).unwrap();
    let at = Committed {
        publication: PUBLICATION,
        lane: Lane::ZERO,
        position: 0,
    };
    agent.on_committed(&ext, &at);
    agent.counts.dropped = u64::MAX;
    agent.on_committed(&ext, &at);
    assert_eq!(agent.counts().dropped, u64::MAX);
    assert_eq!(
        agent.counts().overflowed,
        Some(super::AgentCounter::Dropped)
    );
}
