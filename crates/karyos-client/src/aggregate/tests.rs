// SPDX-License-Identifier: Apache-2.0

//! The aggregate subscriber over an image (`quantstratum-docs:
//! karyos/design/aggregate-subscriber.md`, "The probe in the lane
//! source"): a zero-charge `Interrupted` skip is applied by the probe,
//! outside DRR service, and the probe then reports the interrupting frame's
//! own charge. In-process aggregates are publication mode; this fixture
//! anticipates image lanes.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::sync::Arc;

use karyos_sys::frame::{Flags, FrameType, Word0};
use karyos_sys::log_buffer::{
    DEFAULT_CLAIM_DEADLINE, LogBufferConfig, PublicationMode, ReceiveOwner, Role, STEP_CHARGE,
};
use karyos_sys::receive::{ImageParams, Item, ValidatedDatagram};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

use super::*;

const SESSION: i32 = 3;
const STREAM: i32 = 4;
const INITIAL: u32 = 7;

fn params() -> ImageParams {
    ImageParams::new(
        SESSION,
        STREAM,
        1,
        TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
        DEFAULT_MTU,
    )
    .unwrap()
}

fn image() -> Arc<LogBuffer> {
    Arc::new(
        LogBuffer::new(LogBufferConfig {
            term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
            spare_slots: 5,
            max_subscribers: 2,
            mtu: DEFAULT_MTU,
            max_reserved: MIN_TERM_LENGTH / 8,
            initial_term_id: TermId::new(INITIAL),
            lane: Lane::ZERO,
            session_id: SESSION,
            stream_id: STREAM,
            claim_deadline: DEFAULT_CLAIM_DEADLINE,
            publication: PublicationMode::Image {
                join: 0,
                local_gaps: false,
            },
            schedule_capacity: 0,
        })
        .unwrap(),
    )
}

/// One frame of term 0 at `offset` on the wire.
fn wire(word0: Word0, offset: u32, reserved_value: i64, payload: usize) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&word0.pack().to_le_bytes());
    out.extend_from_slice(&offset.cast_signed().to_le_bytes());
    out.extend_from_slice(&SESSION.to_le_bytes());
    out.extend_from_slice(&STREAM.to_le_bytes());
    out.extend_from_slice(&INITIAL.to_le_bytes());
    out.extend_from_slice(&reserved_value.to_le_bytes());
    out.extend((0..payload).map(|i| u8::try_from(i % 251).unwrap()));
    out
}

fn fragment(offset: u32, begin: bool, end: bool) -> Vec<u8> {
    let flags = Flags::new(begin, end, false, false, Lane::ZERO);
    wire(Word0::new(64, flags, FrameType::Data), offset, 0, 32)
}

fn receive(owner: &mut ReceiveOwner, bytes: &[u8]) {
    let datagram = ValidatedDatagram::parse(bytes, &params()).unwrap();
    let Some(Item::Frame(frame)) = datagram.items().next() else {
        panic!("no frame");
    };
    let _ = owner.receive(&frame).unwrap();
}

#[test]
fn an_interrupted_skip_is_applied_by_the_probe() {
    let buffer = image();
    let mut conductor = buffer.conductor_owned().unwrap();
    let subscription = ClientSubscription::new(conductor.subscribe(Role::Optional).unwrap());
    let mut owner = ReceiveOwner::new(params(), vec![Arc::clone(&buffer)]).unwrap();
    // A BEGIN without its END, interrupted by an ABORTED record, then a
    // whole message.
    receive(&mut owner, &fragment(0, true, false));
    receive(
        &mut owner,
        &wire(Word0::new(32, Flags::NONE, FrameType::Aborted), 64, 64, 0),
    );
    receive(&mut owner, &fragment(128, true, true));
    let frame = 1408;
    let mut aggregate = AggregateSubscription::new(
        DrrConfig::new(&[frame], frame).unwrap(),
        vec![(Lane::ZERO, subscription)],
    )
    .unwrap();
    let mut delivered = Vec::new();
    let report = aggregate.poll(
        |bytes, lane, info| delivered.push((lane, info.position, bytes.len())),
        Budget {
            work: 16,
            bytes: 10 * frame,
        },
    );
    // The BEGIN was copied (64), the Interrupted skip applied by the probe
    // (no charge), the ABORTED record stepped (32) and the message served
    // (64).
    assert_eq!(
        report.drr.lanes[0].served_bytes,
        64 + u64::from(STEP_CHARGE) + 64
    );
    assert_eq!(delivered, [(Lane::ZERO, 128, 32)]);
    let lane = report.lanes[0];
    assert_eq!(
        lane.skipped.map(|skipped| skipped.reason),
        Some(SkipReason::Interrupted)
    );
    assert_eq!(lane.first_loss, Some(0));
    assert!(lane.end.is_none());
}

/// A publication-mode buffer of 3 spare slots for optional readers.
fn publication_buffer() -> Arc<LogBuffer> {
    Arc::new(
        LogBuffer::new(LogBufferConfig {
            term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
            spare_slots: 3,
            max_subscribers: 2,
            mtu: DEFAULT_MTU,
            max_reserved: MIN_TERM_LENGTH / 8,
            initial_term_id: TermId::new(INITIAL),
            lane: Lane::ZERO,
            session_id: SESSION,
            stream_id: STREAM,
            claim_deadline: DEFAULT_CLAIM_DEADLINE,
            publication: PublicationMode::Exclusive,
            schedule_capacity: 0,
        })
        .unwrap(),
    )
}

/// An overrun that `serve_frame` finds between the probe's peek and the
/// serve is consumed by it: the lane source applies it there, so the loss,
/// the rejoin policy and the first loss are not lost.
#[test]
fn an_overrun_between_peek_and_serve_is_applied() {
    use karyos_sys::log_buffer::{AppendOptions, AppendOutcome};
    let buffer = publication_buffer();
    let mut conductor = buffer.conductor_owned().unwrap();
    let subscription = ClientSubscription::new(conductor.subscribe(Role::Optional).unwrap());
    let mut publication = buffer.publication_owned().unwrap().unwrap();
    assert!(matches!(
        publication
            .append(&[7; 100], AppendOptions::default())
            .unwrap(),
        AppendOutcome::Appended { .. }
    ));
    let frame = 1408;
    let mut aggregate = AggregateSubscription::new(
        DrrConfig::new(&[frame], frame).unwrap(),
        vec![(Lane::ZERO, subscription)],
    )
    .unwrap();
    // Between the peek and the serve, the publisher laps the reader.
    aggregate.between = Some(Box::new(move || {
        for _ in 0..300 {
            // Back pressure or an admin action only delays the lap.
            let _ = publication.append(&[1; 3000], AppendOptions::default());
            let _ = conductor.duty_cycle().unwrap();
        }
    }));
    let mut delivered = 0;
    let report = aggregate.poll(
        |_, _, _| delivered += 1,
        Budget {
            work: 4,
            bytes: frame,
        },
    );
    assert_eq!(delivered, 0, "the lapped message is never delivered");
    let lane = report.lanes[0];
    let (overrun, _) = lane.overrun.expect("the overrun is reported");
    assert_eq!(overrun.from, 0);
    assert_eq!(lane.first_loss, Some(0));
    assert_eq!(report.drr.lanes[0].served_bytes, 0);
}

/// A peeked charge above every frame of the geometry (`F_max`) ends the
/// lane as a corrupt term, with nothing charged.
#[test]
fn a_charge_above_f_max_ends_the_lane() {
    use karyos_sys::log_buffer::{AppendOptions, AppendOutcome};
    let buffer = publication_buffer();
    let mut conductor = buffer.conductor_owned().unwrap();
    let subscription = ClientSubscription::new(conductor.subscribe(Role::Optional).unwrap());
    let mut publication = buffer.publication_owned().unwrap().unwrap();
    assert!(matches!(
        publication
            .append(&[7; 1000], AppendOptions::default())
            .unwrap(),
        AppendOutcome::Appended { .. }
    ));
    // A profile whose largest charge is below the frame just committed.
    let mut aggregate = AggregateSubscription::new(
        DrrConfig::new(&[256], 256).unwrap(),
        vec![(Lane::ZERO, subscription)],
    )
    .unwrap();
    let report = aggregate.poll(
        |_, _, _| panic!("nothing is delivered"),
        Budget {
            work: 8,
            bytes: 4096,
        },
    );
    assert!(matches!(
        report.lanes[0].end,
        Some(LaneEnd::Failed(ClientError::Sys(
            SysError::CorruptTerm { .. }
        )))
    ));
    assert_eq!(report.drr.lanes[0].served_bytes, 0);
    assert_eq!(report.terminal, Some(Terminal { clean: false }));
}

/// A subscription its rejoin policy already closed cannot become a lane.
#[test]
fn a_closed_subscription_is_refused() {
    let buffer = publication_buffer();
    let mut conductor = buffer.conductor_owned().unwrap();
    let mut subscription = ClientSubscription::new(conductor.subscribe(Role::Optional).unwrap())
        .with_rejoin(RejoinPolicy::Close);
    let mut publication = buffer.publication_owned().unwrap().unwrap();
    for _ in 0..300 {
        let _ = publication.append(&[1; 3000], karyos_sys::log_buffer::AppendOptions::default());
        let _ = conductor.duty_cycle().unwrap();
    }
    let _ = subscription.poll(|_, _| {}, crate::subscription::MessageLimit::new(1));
    assert!(subscription.is_closed_by_overrun());
    assert!(matches!(
        AggregateSubscription::new(
            DrrConfig::new(&[1408], 1408).unwrap(),
            vec![(Lane::ZERO, subscription)],
        ),
        Err(ClientError::ClosedByOverrun)
    ));
}

/// A 64-byte DATA frame of term `term` at `offset`, BEGIN and END.
fn whole(term: u32, offset: u32) -> Vec<u8> {
    let flags = Flags::new(true, true, false, false, Lane::ZERO);
    let mut out = wire(Word0::new(64, flags, FrameType::Data), offset, 0, 32);
    out[20..24].copy_from_slice(&INITIAL.wrapping_add(term).to_le_bytes());
    out
}

/// The PAD that fills term `term` from `offset`.
fn pad(term: u32, offset: u32) -> Vec<u8> {
    let extent = MIN_TERM_LENGTH - offset;
    let mut out = wire(
        Word0::new(32, Flags::NONE, FrameType::Pad),
        offset,
        i64::from(extent),
        0,
    );
    out[20..24].copy_from_slice(&INITIAL.wrapping_add(term).to_le_bytes());
    out
}

/// An overrun that the probe's zero-charge serve finds is consumed by
/// `serve_frame`: the probe applies it (rejoin policy, loss report, first
/// loss) instead of dropping it.
#[test]
fn an_overrun_at_the_probes_zero_charge_serve_is_applied() {
    let buffer = image();
    let mut conductor = buffer.conductor_owned().unwrap();
    let subscription = ClientSubscription::new(conductor.subscribe(Role::Optional).unwrap());
    let mut owner = ReceiveOwner::new(params(), vec![Arc::clone(&buffer)]).unwrap();
    // A BEGIN without its END, then an ABORTED record: the probe peeks an
    // Interrupted skip, a zero-charge step.
    receive(&mut owner, &fragment(0, true, false));
    receive(
        &mut owner,
        &wire(Word0::new(32, Flags::NONE, FrameType::Aborted), 64, 64, 0),
    );
    let frame = 1408;
    let mut aggregate = AggregateSubscription::new(
        DrrConfig::new(&[frame], frame).unwrap(),
        vec![(Lane::ZERO, subscription)],
    )
    .unwrap();
    // The first poll copies the BEGIN.
    let _ = aggregate.poll(
        |_, _, _| panic!("nothing complete"),
        Budget {
            work: 1,
            bytes: frame,
        },
    );
    // Before the zero-charge serve, the image moves on by whole terms and
    // its slot of term 0 is reclaimed: the serve finds an overrun.
    aggregate.before_zero_charge = Some(Box::new(move || {
        receive(&mut owner, &pad(0, 128));
        for term in 1..8u32 {
            receive(&mut owner, &whole(term, 0));
            receive(&mut owner, &pad(term, 64));
            let _ = conductor.duty_cycle().unwrap();
            while owner.duty() {}
        }
    }));
    let report = aggregate.poll(
        |_, _, _| {},
        Budget {
            work: 4,
            bytes: frame,
        },
    );
    let lane = report.lanes[0];
    let (overrun, _) = lane.overrun.expect("the probe applied the overrun");
    assert_eq!(overrun.from, 0);
    assert_eq!(lane.first_loss, Some(0));
    assert!(lane.end.is_none(), "rejoined at the head");
}
