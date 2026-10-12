// SPDX-License-Identifier: Apache-2.0

use std::collections::VecDeque;

use karyos_protocol::frame::TraceExtension;

use super::*;

/// A scripted source that counts its calls.
#[derive(Default)]
struct Script {
    traces: VecDeque<Option<[u64; 2]>>,
    spans: VecDeque<Option<u64>>,
    trace_calls: u32,
    span_calls: u32,
    counter: u64,
}

impl Script {
    /// A source that always has fresh, distinct ids.
    fn fresh() -> Self {
        Self::default()
    }
}

impl IdSource for Script {
    fn trace_id(&mut self) -> Option<[u64; 2]> {
        self.trace_calls += 1;
        self.counter += 1;
        self.traces
            .pop_front()
            .unwrap_or(Some([0xAB, self.counter]))
    }

    fn span_id(&mut self) -> Option<u64> {
        self.span_calls += 1;
        self.counter += 1;
        self.spans
            .pop_front()
            .unwrap_or(Some(0x1000 + self.counter))
    }
}

fn sampled(n: u32) -> Sampling {
    Sampling::Sampled(NonZeroU32::new(n).unwrap())
}

fn traced(decision: Decision) -> bool {
    matches!(decision, Decision::Traced(_))
}

#[test]
fn sampled_n_traces_the_first_root_then_one_in_n() {
    let mut sampler = Sampler::new(sampled(3));
    let mut ids = Script::fresh();
    let pattern: Vec<bool> = (0..9)
        .map(|_| traced(sampler.decide(None, &mut ids)))
        .collect();
    assert_eq!(
        pattern,
        vec![true, false, false, true, false, false, true, false, false]
    );
    // Unselected roots never call the source.
    assert_eq!((ids.trace_calls, ids.span_calls), (3, 3));
}

#[test]
fn sampled_one_is_all_and_off_traces_nothing() {
    let mut one = Sampler::new(sampled(1));
    let mut all = Sampler::new(Sampling::All);
    let mut ids = Script::fresh();
    for _ in 0..5 {
        assert!(traced(one.decide(None, &mut ids)));
        assert!(traced(all.decide(None, &mut ids)));
    }
    let mut off = Sampler::new(Sampling::Off);
    let mut quiet = Script::fresh();
    let parent = TraceIds {
        trace_id: [1, 2],
        span_id: 3,
        parent_span_id: 0,
        message_id: 4,
    };
    assert_eq!(off.decide(None, &mut quiet), Decision::Untraced);
    assert_eq!(off.decide(Some(parent), &mut quiet), Decision::Untraced);
    assert_eq!((quiet.trace_calls, quiet.span_calls), (0, 0));
}

#[test]
fn roots_and_children_take_the_right_identity() {
    let mut sampler = Sampler::new(Sampling::All);
    let mut ids = Script::fresh();
    let Decision::Traced(root) = sampler.decide(None, &mut ids) else {
        panic!("root not traced");
    };
    assert_ne!(root.trace_id, [0, 0]);
    assert_ne!(root.span_id, 0);
    assert_eq!(root.parent_span_id, 0);
    assert_eq!(root.message_id, 1);
    let Decision::Traced(child) = sampler.decide(Some(root), &mut ids) else {
        panic!("child not traced");
    };
    assert_eq!(child.trace_id, root.trace_id);
    assert_eq!(child.parent_span_id, root.span_id);
    assert_ne!(child.span_id, root.span_id);
    assert_eq!(child.message_id, 2);
    // A child takes only a span id from the source.
    assert_eq!((ids.trace_calls, ids.span_calls), (1, 2));
}

#[test]
fn contexts_with_zero_ids() {
    let mut sampler = Sampler::new(sampled(1000));
    let mut ids = Script::fresh();
    // Zero trace id: no context, so a root (the first root is selected).
    let none = TraceIds::default();
    let Decision::Traced(root) = sampler.decide(Some(none), &mut ids) else {
        panic!("not traced");
    };
    assert_eq!(root.parent_span_id, 0);
    // Nonzero trace id with span 0: joins the trace without a parent edge,
    // whatever the cadence.
    let parentless = TraceIds {
        trace_id: [9, 9],
        ..TraceIds::default()
    };
    let Decision::Traced(child) = sampler.decide(Some(parentless), &mut ids) else {
        panic!("not traced");
    };
    assert_eq!(child.trace_id, [9, 9]);
    assert_eq!(child.parent_span_id, 0);
}

#[test]
fn unavailable_ids_consume_the_root_slot_but_no_message_id() {
    let mut sampler = Sampler::new(sampled(2));
    let mut ids = Script::fresh();
    ids.traces.push_back(None);
    assert_eq!(sampler.decide(None, &mut ids), Decision::IdsUnavailable);
    // Never retried within the decision.
    assert_eq!((ids.trace_calls, ids.span_calls), (1, 0));
    // The slot was consumed: the next root is the unselected one.
    assert_eq!(sampler.decide(None, &mut ids), Decision::Untraced);
    let Decision::Traced(next) = sampler.decide(None, &mut ids) else {
        panic!("not traced");
    };
    assert_eq!(next.message_id, 1);

    // A zero trace id or span id is refused the same way.
    let mut zero = Script::fresh();
    zero.traces.push_back(Some([0, 0]));
    let mut all = Sampler::new(Sampling::All);
    assert_eq!(all.decide(None, &mut zero), Decision::IdsUnavailable);
    zero.spans.push_back(Some(0));
    assert_eq!(all.decide(None, &mut zero), Decision::IdsUnavailable);
    assert_eq!(all.next_message_id(), 1);
}

#[test]
fn a_child_failure_never_moves_the_cadence() {
    let mut sampler = Sampler::new(sampled(2));
    let mut ids = Script::fresh();
    let parent = TraceIds {
        trace_id: [5, 5],
        span_id: 77,
        parent_span_id: 0,
        message_id: 1,
    };
    // A child span equal to the known parent span is refused.
    ids.spans.push_back(Some(77));
    assert_eq!(
        sampler.decide(Some(parent), &mut ids),
        Decision::IdsUnavailable
    );
    ids.spans.push_back(None);
    assert_eq!(
        sampler.decide(Some(parent), &mut ids),
        Decision::IdsUnavailable
    );
    assert!(traced(sampler.decide(Some(parent), &mut ids)));
    // Roots still start at residue 0: traced, untraced, traced.
    assert!(traced(sampler.decide(None, &mut ids)));
    assert!(!traced(sampler.decide(None, &mut ids)));
    assert!(traced(sampler.decide(None, &mut ids)));
}

#[test]
fn a_policy_change_resets_the_cadence_and_keeps_message_ids() {
    let mut sampler = Sampler::new(sampled(4));
    let mut ids = Script::fresh();
    assert!(traced(sampler.decide(None, &mut ids)));
    assert!(!traced(sampler.decide(None, &mut ids)));
    sampler.set_policy(sampled(4));
    let Decision::Traced(after) = sampler.decide(None, &mut ids) else {
        panic!("first root after a policy change is traced");
    };
    assert_eq!(after.message_id, 2);
    sampler.set_policy(Sampling::Off);
    assert_eq!(sampler.decide(None, &mut ids), Decision::Untraced);
    assert_eq!(sampler.next_message_id(), 3);
}

#[test]
fn message_ids_stop_at_the_maximum() {
    let mut sampler = Sampler::resume(Sampling::All, u64::MAX - 1);
    let mut ids = Script::fresh();
    let Decision::Traced(last) = sampler.decide(None, &mut ids) else {
        panic!("not traced");
    };
    assert_eq!(last.message_id, u64::MAX - 1);
    let calls = (ids.trace_calls, ids.span_calls);
    assert_eq!(
        sampler.decide(None, &mut ids),
        Decision::MessageIdsExhausted
    );
    let parent = last;
    assert_eq!(
        sampler.decide(Some(parent), &mut ids),
        Decision::MessageIdsExhausted
    );
    // Exhaustion is decided before the source is called.
    assert_eq!((ids.trace_calls, ids.span_calls), calls);
    // A resumed sampler never starts below 1.
    assert_eq!(Sampler::resume(Sampling::All, 0).next_message_id(), 1);
}

#[test]
fn decided_ids_round_trip_through_ext() {
    let mut sampler = Sampler::new(Sampling::All);
    let mut ids = Script::fresh();
    let Decision::Traced(decided) = sampler.decide(None, &mut ids) else {
        panic!("not traced");
    };
    let extension = TraceExtension {
        extension_flags: 0,
        trace_id: decided.trace_id,
        span_id: decided.span_id,
        parent_span_id: decided.parent_span_id,
        message_id: decided.message_id,
    };
    let mut bytes = [0u8; 64];
    extension.encode(&mut bytes).unwrap();
    assert_eq!(TraceExtension::decode(&bytes), Ok(extension));
}
