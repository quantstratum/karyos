// SPDX-License-Identifier: Apache-2.0

//! Client handles across a cutover (`quantstratum-docs: karyos/design/mapping-generations.md`,
//! g2), with the test standing in for the driver: it seals the predecessor,
//! marks links pending, creates the successor and offers capabilities.

// Test helpers outside #[test] functions are not covered by clippy.toml's
// test exemptions (ADR-0007 exempts tests from these lints).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::sync::Arc;

use karyos_client::{
    ClaimOutcome, ClientConcurrentPublication, ClientPublication, ClientSubscription,
    CommitOutcome, ConcurrentOfferOutcome, GenerationLink, LinkStatus, MessageLimit, OfferOutcome,
    Successor,
};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{
    Conductor, DEFAULT_CLAIM_DEADLINE, LogBuffer, LogBufferConfig, PublicationMode, Role, SealState,
};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::{Generation, TermId};

fn config(publication: PublicationMode) -> LogBufferConfig {
    LogBufferConfig {
        term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
        spare_slots: 6,
        max_subscribers: 3,
        mtu: DEFAULT_MTU,
        max_reserved: MIN_TERM_LENGTH / 8,
        initial_term_id: TermId::new(7),
        lane: Lane::ZERO,
        session_id: 1,
        stream_id: 2,
        claim_deadline: DEFAULT_CLAIM_DEADLINE,
        publication,
        schedule_capacity: 0,
    }
}

fn concurrent() -> PublicationMode {
    PublicationMode::Concurrent {
        publishers: 2,
        allow_non_lse: true,
    }
}

fn buffer(
    generation: u32,
    publication: PublicationMode,
) -> (Arc<LogBuffer>, Conductor<Arc<LogBuffer>>) {
    let buffer = Arc::new(
        LogBuffer::new_with_generation(
            config(publication),
            Generation::try_new(generation).unwrap(),
        )
        .unwrap(),
    );
    let conductor = buffer.conductor_owned().unwrap();
    (buffer, conductor)
}

/// A successor cell and its copy buffer, as the driver prepares them.
fn successor_cell(conductor: &mut Conductor<Arc<LogBuffer>>, role: Role) -> Successor {
    let inner = conductor.subscribe(role).unwrap();
    let scratch = vec![0u8; inner.buffer().max_message_length() as usize].into_boxed_slice();
    Successor::Subscription { inner, scratch }
}

fn read(subscription: &mut ClientSubscription, limit: u32) -> (Vec<(u64, Vec<u8>)>, Option<u64>) {
    let mut seen = Vec::new();
    let summary = subscription
        .poll(
            |bytes, info| seen.push((info.position, bytes.to_vec())),
            MessageLimit::new(limit),
        )
        .unwrap();
    (seen, summary.closed)
}

#[test]
fn an_exclusive_writer_and_its_reader_continue_on_the_successor() {
    let (a, mut a_conductor) = buffer(0, PublicationMode::Exclusive);
    let writer_link = GenerationLink::new();
    let reader_link = GenerationLink::new();
    let mut writer = ClientPublication::new(a.publication_owned().unwrap().unwrap(), false)
        .with_generation(Arc::clone(&writer_link), 0)
        .unwrap();
    let mut reader = ClientSubscription::new(a_conductor.subscribe(Role::Required).unwrap())
        .with_generation(Arc::clone(&reader_link), 0)
        .unwrap();
    let OfferOutcome::Accepted {
        position: first, ..
    } = writer.offer(b"one").unwrap()
    else {
        panic!("not accepted");
    };
    assert_eq!(first, 0);
    // The cutover starts: links pending, then the predecessor is sealed.
    assert!(writer_link.set_pending() && reader_link.set_pending());
    a_conductor.seal().unwrap();
    assert_eq!(writer.offer(b"two").unwrap(), OfferOutcome::AdminAction);
    assert_eq!(writer.offer(b"two").unwrap(), OfferOutcome::AdminAction);
    let _ = a_conductor.duty_cycle().unwrap();
    let SealState::Positioned { position: end } = a_conductor.seal_state() else {
        panic!("not positioned");
    };
    // The reader drains the predecessor and waits at its end.
    let (seen, closed) = read(&mut reader, 8);
    assert_eq!(seen, vec![(0, b"one".to_vec())]);
    assert_eq!(closed, None);
    // The cutover opens at `end`.
    let (b, mut b_conductor) = buffer(1, PublicationMode::Exclusive);
    let reader_cell = successor_cell(&mut b_conductor, Role::Required);
    assert!(reader_link.offer(end, reader_cell).is_ok());
    assert!(
        writer_link
            .offer(
                end,
                Successor::Publication(b.publication_owned().unwrap().unwrap())
            )
            .is_ok()
    );
    assert_eq!(writer.offer(b"two").unwrap(), OfferOutcome::AdminAction);
    assert_eq!(writer_link.status(), LinkStatus::Current);
    let OfferOutcome::Accepted { position, .. } = writer.offer(b"two").unwrap() else {
        panic!("not accepted on the successor");
    };
    assert_eq!(position, end);
    let ClaimOutcome::Claimed(mut claim) = writer.try_claim(5).unwrap() else {
        panic!("not claimed");
    };
    let claimed_at = claim.position();
    claim.payload().copy_from_slice(b"three");
    assert_eq!(
        claim.commit(),
        CommitOutcome::Accepted {
            lane: Lane::ZERO,
            position: claimed_at,
        }
    );
    // The reader moves inside one poll and continues at `end`.
    let (seen, closed) = read(&mut reader, 8);
    assert_eq!(
        seen,
        vec![(end, b"two".to_vec()), (claimed_at, b"three".to_vec())]
    );
    assert_eq!(closed, None);
    assert_eq!(reader_link.status(), LinkStatus::Current);
    assert!(reader.position() > end);
    // The predecessor's reader cell was detached by the move.
    assert_eq!(a.attached_subscribers(), 0);
}

#[test]
fn a_fenced_handle_reports_closed_and_its_reader_the_seal() {
    let (a, mut a_conductor) = buffer(0, concurrent());
    let writer_link = GenerationLink::new();
    let reader_link = GenerationLink::new();
    let mut writer = ClientConcurrentPublication::new(
        a_conductor.concurrent_publication().unwrap().unwrap(),
        false,
    )
    .with_generation(Arc::clone(&writer_link), 0)
    .unwrap();
    let mut reader = ClientSubscription::new(a_conductor.subscribe(Role::Optional).unwrap())
        .with_generation(Arc::clone(&reader_link), 0)
        .unwrap();
    assert!(matches!(
        writer.offer(b"one").unwrap(),
        ConcurrentOfferOutcome::Accepted { .. }
    ));
    assert!(writer_link.set_pending() && reader_link.set_pending());
    a_conductor.seal().unwrap();
    // Concurrent: positioned at once.
    let SealState::Positioned { position: end } = a_conductor.seal_state() else {
        panic!("not positioned");
    };
    let (b, mut b_conductor) = buffer(1, concurrent());
    assert!(
        writer_link
            .offer(
                end,
                Successor::Concurrent(b_conductor.concurrent_publication().unwrap().unwrap())
            )
            .is_ok()
    );
    assert!(
        reader_link
            .offer(end, successor_cell(&mut b_conductor, Role::Optional))
            .is_ok()
    );
    // The deadline passes: both are fenced, their reserved capabilities
    // come back to the driver.
    assert!(matches!(
        writer_link.fence(),
        Some(Successor::Concurrent(_))
    ));
    assert!(matches!(
        reader_link.fence(),
        Some(Successor::Subscription { .. })
    ));
    assert_eq!(b.attached_subscribers(), 0);
    for _ in 0..2 {
        assert_eq!(
            writer.offer(b"late").unwrap(),
            ConcurrentOfferOutcome::Closed
        );
    }
    let (seen, closed) = read(&mut reader, 8);
    assert_eq!(seen, vec![(0, b"one".to_vec())]);
    assert_eq!(closed, Some(end));
    assert_eq!(read(&mut reader, 8), (Vec::new(), Some(end)));
    let _ = a;
}

#[test]
fn positions_carry_the_base_and_a_link_without_cutover_ends() {
    let (a, mut a_conductor) = buffer(0, concurrent());
    let link = GenerationLink::new();
    let base = 1 << 40;
    let mut writer = ClientConcurrentPublication::new(
        a_conductor.concurrent_publication().unwrap().unwrap(),
        true,
    )
    .with_generation(Arc::clone(&link), base)
    .unwrap();
    let mut reader = ClientSubscription::new(a_conductor.subscribe(Role::Optional).unwrap())
        .with_generation(GenerationLink::new(), base)
        .unwrap();
    for payload in [&b"a"[..], b"b"] {
        let ConcurrentOfferOutcome::Accepted { position, .. } = writer.offer(payload).unwrap()
        else {
            panic!("not accepted");
        };
        assert!(position >= base);
    }
    let (seen, closed) = read(&mut reader, 1);
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, base);
    assert_eq!(closed, None);
    // A link with no cutover: the end of the mapping is the end.
    a_conductor.seal().unwrap();
    let (seen, closed) = read(&mut reader, 8);
    assert_eq!(seen.len(), 1);
    let SealState::Retired { position } = a_conductor.seal_state() else {
        panic!("not retired");
    };
    assert_eq!(closed, Some(base + position));
    assert_eq!(writer.offer(b"c").unwrap(), ConcurrentOfferOutcome::Closed);
    let _ = a;
}

#[test]
fn a_base_must_keep_every_position_of_its_mapping_below_2_pow_63() {
    use karyos_client::ClientError;
    use karyos_client::generation::{POSITION_LIMIT, representable};

    let (a, mut a_conductor) = buffer(0, concurrent());
    let span = (1u64 << 31) * u64::from(a.term_length());
    let highest = POSITION_LIMIT - span;
    assert!(representable(highest, &a));
    assert!(!representable(highest + 1, &a));
    assert!(!representable(u64::MAX - 1, &a));
    // The highest base is accepted, and its positions stay exact.
    let mut writer = ClientConcurrentPublication::new(
        a_conductor.concurrent_publication().unwrap().unwrap(),
        true,
    )
    .with_generation(GenerationLink::new(), highest)
    .unwrap();
    for _ in 0..2 {
        let ConcurrentOfferOutcome::Accepted { position, .. } = writer.offer(b"x").unwrap() else {
            panic!("not accepted");
        };
        assert!(position >= highest && position < POSITION_LIMIT);
    }
    // One more, or the probe's u64::MAX - 1, is refused before any use.
    for base in [highest + 1, u64::MAX - 1] {
        let handle = a_conductor.concurrent_publication().unwrap().unwrap();
        assert!(matches!(
            ClientConcurrentPublication::new(handle, true).with_generation(GenerationLink::new(), base),
            Err(ClientError::PositionsExhausted { base: refused }) if refused == base
        ));
    }
    // A driver offer past the range gives the successor back, and the link
    // stays pending.
    let link = GenerationLink::new();
    assert!(link.set_pending());
    let (_b, mut b_conductor) = buffer(1, concurrent());
    let successor = Successor::Concurrent(b_conductor.concurrent_publication().unwrap().unwrap());
    assert!(matches!(
        link.offer(highest + 1, successor),
        Err(Successor::Concurrent(_))
    ));
    assert_eq!(link.status(), LinkStatus::Pending);
}
