// SPDX-License-Identifier: Apache-2.0

// Client tracing (`quantstratum-docs: karyos/design/trace-data-path.md`,
// "Tests", the client parts of batch p6b) over a heap log buffer, with a
// recording hook.

use std::sync::Arc;

use karyos_protocol::frame::{Lane, TraceExtension};
use karyos_protocol::trace_hook::{PublicationIdentity, SubscriberIdentity};
use karyos_sys::frame::Flags;
use karyos_sys::log_buffer::{LogBuffer, LogBufferConfig, PublicationMode, Role};
use karyos_sys::sizing::{DEFAULT_MTU, FragmentPlan, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

use super::test_hook::recording;
use super::*;
use crate::{
    ClaimOutcome, ClientConcurrentPublication, ClientPublication, ClientSubscription,
    CommitOutcome, ConcurrentClaimOutcome, ConcurrentOfferOutcome, MessageLimit, OfferOutcome,
};

const PUBLICATION: PublicationIdentity = PublicationIdentity {
    driver: [1, 2],
    registration: 3,
    stream_id: 2,
    session_id: 1,
    incarnation: 1,
};

const SUBSCRIBER: SubscriberIdentity = SubscriberIdentity {
    driver: [1, 2],
    registration: 9,
    incarnation: 1,
};

fn buffer(publication: PublicationMode) -> Arc<LogBuffer> {
    Arc::new(
        LogBuffer::new(LogBufferConfig {
            term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
            spare_slots: 3,
            max_subscribers: 3,
            mtu: DEFAULT_MTU,
            max_reserved: MIN_TERM_LENGTH / 8,
            initial_term_id: TermId::new(7),
            lane: Lane::ZERO,
            session_id: 1,
            stream_id: 2,
            claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
            publication,
        })
        .unwrap(),
    )
}

/// The end of a traced block of `length` payload bytes at `position`,
/// computed independently of the subscription: the EXT64 fragmentation of
/// SPEC.md §4.
fn traced_end(position: u64, length: u32) -> u64 {
    let flags = Flags::new(false, false, false, true, Lane::ZERO);
    let reserved = FragmentPlan::new(DEFAULT_MTU, flags)
        .unwrap()
        .reserved(length)
        .unwrap();
    position + u64::from(reserved)
}

/// Polls one message and returns its bytes and decoded trace context.
fn poll_one(subscription: &mut ClientSubscription) -> Option<(Vec<u8>, Option<TraceExtension>)> {
    let mut got = None;
    let _ = subscription
        .poll(
            |bytes, info| got = Some((bytes.to_vec(), info.trace())),
            MessageLimit::new(1),
        )
        .unwrap();
    got
}

#[test]
fn test_trace_off_writes_no_ext_and_no_record() {
    let buffer = buffer(PublicationMode::Exclusive);
    let mut conductor = buffer.conductor_owned().unwrap();
    let (sub_hook, delivered) = recording(false);
    let mut subscription = ClientSubscription::new(conductor.subscribe(Role::Required).unwrap())
        .with_trace(sub_hook, PUBLICATION, SUBSCRIBER);
    let (hook, seen) = recording(false);
    let mut publication =
        ClientPublication::new(buffer.publication_owned().unwrap().unwrap(), false)
            .with_trace(hook, PUBLICATION);
    let decision = publication.trace_message(None);
    assert!(!decision.is_traced());
    assert!(matches!(
        publication.offer_with_trace(b"plain", &decision).unwrap(),
        OfferOutcome::Accepted { .. }
    ));
    assert_eq!(poll_one(&mut subscription), Some((b"plain".to_vec(), None)));
    assert!(seen.lock().unwrap().committed.is_empty());
    assert!(delivered.lock().unwrap().delivered.is_empty());
}

#[test]
fn a_handle_without_a_hook_publishes_untraced() {
    let buffer = buffer(PublicationMode::Exclusive);
    let mut publication =
        ClientPublication::new(buffer.publication_owned().unwrap().unwrap(), true);
    assert!(!publication.is_traced());
    assert_eq!(publication.trace_message(None), TraceDecision::UNTRACED);
}

#[test]
fn test_trace_publish_and_poll_records_match() {
    let buffer = buffer(PublicationMode::Exclusive);
    let mut conductor = buffer.conductor_owned().unwrap();
    let (sub_hook, sub_seen) = recording(false);
    let mut subscription = ClientSubscription::new(conductor.subscribe(Role::Required).unwrap())
        .with_trace(sub_hook, PUBLICATION, SUBSCRIBER);
    let (hook, seen) = recording(true);
    let mut publication =
        ClientPublication::new(buffer.publication_owned().unwrap().unwrap(), false)
            .with_trace(hook, PUBLICATION);
    // A fragmented traced message: EXT is in every fragment, the reader
    // decodes the first.
    let payload = vec![7u8; 5000];
    let decision = publication.trace_message(None);
    let OfferOutcome::Accepted { lane, position } =
        publication.offer_with_trace(&payload, &decision).unwrap()
    else {
        panic!("not accepted");
    };
    let (bytes, trace) = poll_one(&mut subscription).unwrap();
    assert_eq!(bytes, payload);
    assert_eq!(trace, decision.extension());
    let seen = seen.lock().unwrap();
    let [(ext, committed)] = seen.committed[..] else {
        panic!("one Publish observation");
    };
    let sub_seen = sub_seen.lock().unwrap();
    let [(polled_ext, delivered)] = sub_seen.delivered[..] else {
        panic!("one SubscriberPoll observation");
    };
    assert_eq!(Some(ext), decision.extension());
    assert_eq!(polled_ext, ext);
    assert_eq!(
        (committed.publication, committed.lane, committed.position),
        (PUBLICATION, lane, position)
    );
    assert_eq!(
        (
            delivered.publication,
            delivered.subscriber,
            delivered.lane,
            delivered.position
        ),
        (PUBLICATION, SUBSCRIBER, lane, position)
    );
    // The boundary is the message's end: 3 x 1408 + align32(96 + 776) for
    // 5000 bytes with EXT64.
    assert_eq!(traced_end(0, 5000), 5408);
    assert_eq!(subscription.delivery_boundary(), traced_end(position, 5000));
}

#[test]
fn test_trace_child_inherits_trace_id() {
    let buffer = buffer(PublicationMode::Exclusive);
    let mut conductor = buffer.conductor_owned().unwrap();
    let mut subscription = ClientSubscription::new(conductor.subscribe(Role::Required).unwrap());
    let (hook, _seen) = recording(true);
    let mut publication =
        ClientPublication::new(buffer.publication_owned().unwrap().unwrap(), false)
            .with_trace(hook, PUBLICATION);
    let parent = publication.trace_message(None);
    let _ = publication.offer_with_trace(b"parent", &parent).unwrap();
    let (_, received) = poll_one(&mut subscription).unwrap();
    let received = received.unwrap();
    // The handler republishes with the received context as parent.
    let child = publication.trace_message(Some(&received));
    let child = child.extension().unwrap();
    assert_eq!(child.trace_id, received.trace_id);
    assert_ne!(child.span_id, received.span_id);
    assert_eq!(child.parent_span_id, received.span_id);
}

#[test]
fn test_trace_retry_reuses_the_decision() {
    let buffer = buffer(PublicationMode::Exclusive);
    let mut conductor = buffer.conductor_owned().unwrap();
    let (hook, seen) = recording(true);
    let mut publication =
        ClientPublication::new(buffer.publication_owned().unwrap().unwrap(), false)
            .with_trace(hook, PUBLICATION);
    let decision = publication.trace_message(None);
    // Not connected yet: nothing appended, nothing recorded.
    assert_eq!(
        publication.offer_with_trace(b"retry", &decision).unwrap(),
        OfferOutcome::NotConnected
    );
    assert!(seen.lock().unwrap().committed.is_empty());
    let mut subscription = ClientSubscription::new(conductor.subscribe(Role::Required).unwrap());
    // The retry carries the same decision: one sampling, one record.
    assert!(matches!(
        publication.offer_with_trace(b"retry", &decision).unwrap(),
        OfferOutcome::Accepted { .. }
    ));
    let (_, trace) = poll_one(&mut subscription).unwrap();
    assert_eq!(trace, decision.extension());
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.decisions, 1);
        assert_eq!(seen.committed.len(), 1);
    }
    // An abandoned decision consumed its sampling and records nothing.
    let _abandoned = publication.trace_message(None);
    let seen = seen.lock().unwrap();
    assert_eq!((seen.decisions, seen.committed.len()), (2, 1));
}

#[test]
fn test_trace_aborted_claim_records_nothing() {
    let buffer = buffer(PublicationMode::Exclusive);
    let mut conductor = buffer.conductor_owned().unwrap();
    let mut subscription = ClientSubscription::new(conductor.subscribe(Role::Required).unwrap());
    let (hook, seen) = recording(true);
    let mut publication =
        ClientPublication::new(buffer.publication_owned().unwrap().unwrap(), false)
            .with_trace(hook, PUBLICATION);
    let decision = publication.trace_message(None);
    let ClaimOutcome::Claimed(claim) = publication.try_claim_with_trace(8, &decision).unwrap()
    else {
        panic!("not claimed");
    };
    claim.abort();
    assert!(seen.lock().unwrap().committed.is_empty());
    // The same message, claimed again with its decision, commits once.
    let ClaimOutcome::Claimed(mut claim) = publication.try_claim_with_trace(8, &decision).unwrap()
    else {
        panic!("not claimed");
    };
    claim.payload().copy_from_slice(b"claimed!");
    let CommitOutcome::Accepted { position, .. } = claim.commit() else {
        panic!("not committed");
    };
    let seen = seen.lock().unwrap();
    assert_eq!(seen.decisions, 1);
    let [(ext, committed)] = seen.committed[..] else {
        panic!("one Publish observation");
    };
    assert_eq!(Some(ext), decision.extension());
    assert_eq!(committed.position, position);
    drop(seen);
    let _ = subscription.poll(|_, _| {}, MessageLimit::new(4));
}

#[test]
fn test_trace_redelivery_records_first_delivery_only() {
    let buffer = buffer(PublicationMode::Exclusive);
    let mut conductor = buffer.conductor_owned().unwrap();
    let (sub_hook, sub_seen) = recording(false);
    let mut subscription = ClientSubscription::new(conductor.subscribe(Role::Required).unwrap())
        .with_trace(sub_hook, PUBLICATION, SUBSCRIBER);
    let (hook, _seen) = recording(true);
    let mut publication =
        ClientPublication::new(buffer.publication_owned().unwrap().unwrap(), false)
            .with_trace(hook, PUBLICATION);
    let decision = publication.trace_message(None);
    let OfferOutcome::Accepted { position, .. } = publication
        .offer_with_trace(b"panics once", &decision)
        .unwrap()
    else {
        panic!("not accepted");
    };
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = subscription.poll(|_, _| panic!("handler failed"), MessageLimit::new(1));
    }));
    assert!(panicked.is_err());
    // Attempted, not acknowledged: the boundary passed the message.
    assert_eq!(
        subscription.delivery_boundary(),
        traced_end(position, b"panics once".len() as u32)
    );
    assert_eq!(subscription.position(), 0);
    let (bytes, _) = poll_one(&mut subscription).unwrap();
    assert_eq!(bytes, b"panics once");
    assert_eq!(sub_seen.lock().unwrap().delivered.len(), 1);
}

#[test]
fn test_trace_invalid_ext_delivered_untraced() {
    let buffer = buffer(PublicationMode::Exclusive);
    let mut conductor = buffer.conductor_owned().unwrap();
    let (sub_hook, sub_seen) = recording(false);
    let mut subscription = ClientSubscription::new(conductor.subscribe(Role::Required).unwrap())
        .with_trace(sub_hook, PUBLICATION, SUBSCRIBER);
    let mut publication =
        ClientPublication::new(buffer.publication_owned().unwrap().unwrap(), false);
    // Version 9: not a decodable extension.
    let mut bytes = [0u8; 64];
    bytes[0] = 9;
    let options = karyos_sys::log_buffer::AppendOptions {
        extension: Some(bytes),
        ..Default::default()
    };
    assert!(matches!(
        publication.offer_with(b"odd ext", options).unwrap(),
        OfferOutcome::Accepted { .. }
    ));
    assert_eq!(
        poll_one(&mut subscription),
        Some((b"odd ext".to_vec(), None))
    );
    assert_eq!(subscription.invalid_extensions().count, 1);
    assert!(!subscription.invalid_extensions().overflowed);
    assert!(sub_seen.lock().unwrap().delivered.is_empty());
}

#[test]
fn test_trace_maintenance_reaches_the_hook() {
    let buffer = buffer(PublicationMode::Exclusive);
    let (hook, seen) = recording(true);
    let mut publication =
        ClientPublication::new(buffer.publication_owned().unwrap().unwrap(), true)
            .with_trace(hook, PUBLICATION);
    assert!(publication.is_traced());
    publication.trace_maintenance();
    assert_eq!(seen.lock().unwrap().maintained, 1);
}

#[test]
fn test_trace_concurrent_offer_and_claim_record_their_commits() {
    let buffer = buffer(PublicationMode::Concurrent {
        publishers: 2,
        allow_non_lse: true,
    });
    let mut conductor = buffer.conductor_owned().unwrap();
    let mut subscription = ClientSubscription::new(conductor.subscribe(Role::Required).unwrap());
    let (hook, seen) = recording(true);
    let mut publication = ClientConcurrentPublication::new(
        conductor.concurrent_publication().unwrap().unwrap(),
        false,
    )
    .with_trace(hook, PUBLICATION);
    let first = publication.trace_message(None);
    let ConcurrentOfferOutcome::Accepted {
        position: offered, ..
    } = publication.offer_with_trace(b"offered", &first).unwrap()
    else {
        panic!("not accepted");
    };
    let second = publication.trace_message(None);
    let ConcurrentClaimOutcome::Claimed(mut claim) =
        publication.try_claim_with_trace(7, &second).unwrap()
    else {
        panic!("not claimed");
    };
    claim.payload().copy_from_slice(b"claimed");
    let CommitOutcome::Accepted {
        position: claimed, ..
    } = claim.commit()
    else {
        panic!("not committed");
    };
    let seen = seen.lock().unwrap();
    let positions: Vec<_> = seen.committed.iter().map(|(_, at)| at.position).collect();
    assert_eq!(positions, [offered, claimed]);
    assert_eq!(Some(seen.committed[1].0), second.extension());
    drop(seen);
    assert_eq!(poll_one(&mut subscription).unwrap().1, first.extension());
    assert_eq!(poll_one(&mut subscription).unwrap().1, second.extension());
}

#[test]
fn rebinding_a_hook_keeps_the_boundary_and_records_nothing_twice() {
    let buffer = buffer(PublicationMode::Exclusive);
    let mut conductor = buffer.conductor_owned().unwrap();
    let (first_hook, first_seen) = recording(false);
    let mut subscription = ClientSubscription::new(conductor.subscribe(Role::Required).unwrap())
        .with_trace(first_hook, PUBLICATION, SUBSCRIBER);
    let (hook, _seen) = recording(true);
    let mut publication =
        ClientPublication::new(buffer.publication_owned().unwrap().unwrap(), false)
            .with_trace(hook, PUBLICATION);
    let decision = publication.trace_message(None);
    let OfferOutcome::Accepted { position, .. } =
        publication.offer_with_trace(b"once", &decision).unwrap()
    else {
        panic!("not accepted");
    };
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = subscription.poll(|_, _| panic!("handler failed"), MessageLimit::new(1));
    }));
    assert!(panicked.is_err());
    let boundary = subscription.delivery_boundary();
    assert_eq!(boundary, traced_end(position, 4));
    // A new hook bound to the same subscription keeps its history.
    let (second_hook, second_seen) = recording(false);
    let mut subscription = subscription.with_trace(second_hook, PUBLICATION, SUBSCRIBER);
    assert_eq!(subscription.delivery_boundary(), boundary);
    let (bytes, _) = poll_one(&mut subscription).unwrap();
    assert_eq!(bytes, b"once");
    assert_eq!(first_seen.lock().unwrap().delivered.len(), 1);
    assert!(second_seen.lock().unwrap().delivered.is_empty());
}
