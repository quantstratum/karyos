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
