// SPDX-License-Identifier: Apache-2.0

//! Which trace records are in session (ADR-0117 point 2, Validation), and
//! how a range folds.

use karyos_sys::frame::{Flags, HEADER_LENGTH, Lane};
use karyos_trace::stream::{MAX_MESSAGE_BYTES, StreamRecord};
use karyos_trace::{ObservedTime, Point, PublicationId, RECORD_WORDS, TraceIds, TraceRecord};

use super::*;

/// The declared clock of these tests: domain 5, epoch 77, 1 us.
pub(crate) const CLOCK: EventClock = EventClock {
    clock: [0, 0, 0, 5, 77],
    granularity: 1000,
};

pub(crate) const OWN: DriverSelf = DriverSelf {
    namespace: 1,
    namespace_inode: 4_026_531_834,
    clock: CLOCK.clock,
    granularity: 1000,
};

/// A whole unfragmented data frame carrying `message`, padded to the
/// frame alignment.
pub(crate) fn frame(message: &StreamMessage) -> Vec<u8> {
    let mut payload = [0u8; MAX_MESSAGE_BYTES];
    let length = message.encode(&mut payload).unwrap();
    data_frame(&payload[..length], true, true)
}

/// A data frame of `payload` with the begin and end flags given.
pub(crate) fn data_frame(payload: &[u8], begin: bool, end: bool) -> Vec<u8> {
    let length = HEADER_LENGTH as usize + payload.len();
    let flags = Flags::new(begin, end, false, false, Lane::default());
    let word0 = Word0::new(i32::try_from(length).unwrap(), flags, FrameType::Data);
    let mut bytes = vec![0u8; HEADER_LENGTH as usize];
    bytes[..8].copy_from_slice(&word0.pack().to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes.resize(length.next_multiple_of(FRAME_ALIGNMENT as usize), 0);
    bytes
}

/// A padding frame of `length` bytes.
pub(crate) fn pad(length: usize) -> Vec<u8> {
    let word0 = Word0::new(i32::try_from(length).unwrap(), Flags::NONE, FrameType::Pad);
    let mut bytes = vec![0u8; length];
    bytes[..8].copy_from_slice(&word0.pack().to_le_bytes());
    bytes
}

pub(crate) fn facts(
    journal: u64,
    generation: u64,
    namespace: u64,
    provenance: u64,
) -> StreamMessage {
    StreamMessage::Facts(JournalFacts {
        journal,
        generation,
        kind: 2,
        time_namespace: namespace,
        provenance,
    })
}

/// A `Publish` record of `journal` under facts `generation`, observed at
/// `time` with `uncertainty`.
pub(crate) fn record(journal: u64, generation: u64, time: u64, uncertainty: u64) -> StreamMessage {
    let observed = ObservedTime {
        time,
        clock: 1,
        epoch: 1,
        uncertainty,
    };
    let trace = TraceRecord {
        point: Point::Publish,
        publication: PublicationId {
            driver: [1, 2],
            registration: 3,
            stream_id: 4,
            session_id: 5,
            incarnation: 6,
        },
        lane: 0,
        position: time,
        ids: TraceIds {
            trace_id: [time, 1],
            span_id: 1,
            parent_span_id: 0,
            message_id: time,
        },
        observed,
        subscriber: None,
        packet: None,
        network: None,
        root: true,
    };
    // The observation, then the collection stamp (time, clock, epoch).
    let mut words = [0u64; RECORD_WORDS];
    for (word, value) in words
        .iter_mut()
        .zip(trace.encode().unwrap().into_iter().chain([time, 1, 1]))
    {
        *word = value;
    }
    StreamMessage::Record(StreamRecord {
        journal,
        generation,
        sequence: time,
        words,
    })
}

const HOST: u64 = 2;

fn session_with(messages: &[StreamMessage]) -> TraceSession {
    let mut session = TraceSession::new();
    for message in messages {
        let mut out = [0u8; MAX_MESSAGE_BYTES];
        let length = message.encode(&mut out).unwrap();
        let _ = session.observe(Some(&out[..length]), &CLOCK);
    }
    session
}

fn observe(session: &mut TraceSession, message: &StreamMessage) -> Observation {
    let mut out = [0u8; MAX_MESSAGE_BYTES];
    let length = message.encode(&mut out).unwrap();
    session.observe(Some(&out[..length]), &CLOCK)
}

fn in_session(observation: Observation) -> bool {
    match observation {
        Observation::Timed { in_session, .. } => in_session,
        other => panic!("not a record: {other:?}"),
    }
}

/// Point 2: a record is in session only with its generation's facts
/// before it, provenance `HostMonotonic`, the driver's own namespace, and
/// an uncertainty within the granularity.
#[test]
fn only_a_record_meeting_every_rule_is_in_session() {
    let own = StreamMessage::DriverSelf(OWN);
    let mut session = session_with(&[own, facts(7, 1, 1, HOST)]);
    assert_eq!(
        observe(&mut session, &record(7, 1, 5000, 1000)),
        Observation::Timed {
            time: 5000,
            in_session: true
        }
    );
    // Uncertainty past the granularity.
    assert!(!in_session(observe(
        &mut session,
        &record(7, 1, 6000, 1001)
    )));
    // Another provenance: standard monotonic, opaque.
    for provenance in [0, 1, 9] {
        let mut session = session_with(&[own, facts(7, 1, 1, provenance)]);
        assert!(!in_session(observe(&mut session, &record(7, 1, 5000, 0))));
    }
    // An unknown or a different namespace.
    for namespace in [0, 2] {
        let mut session = session_with(&[own, facts(7, 1, namespace, HOST)]);
        assert!(!in_session(observe(&mut session, &record(7, 1, 5000, 0))));
    }
    // No facts at all, or another journal's.
    let mut session = session_with(&[own, facts(8, 1, 1, HOST)]);
    assert!(!in_session(observe(&mut session, &record(7, 1, 5000, 0))));
    assert!(!in_session(observe(&mut session, &record(7, 0, 5000, 0))));
}

/// A lost facts change never lets earlier facts apply: generation 2's
/// message is missing, so generation 2's records are out of session even
/// though generation 1 was in session.
#[test]
fn a_lost_facts_change_never_lets_earlier_facts_apply() {
    let mut session = session_with(&[StreamMessage::DriverSelf(OWN), facts(7, 1, 1, HOST)]);
    assert!(in_session(observe(&mut session, &record(7, 1, 5000, 0))));
    assert!(!in_session(observe(&mut session, &record(7, 2, 6000, 0))));
    // Its facts arriving later puts the later records in session.
    let _ = observe(&mut session, &facts(7, 2, 1, HOST));
    assert!(in_session(observe(&mut session, &record(7, 2, 7000, 0))));
    // A change that leaves the namespace: out of session.
    let _ = observe(&mut session, &facts(7, 3, 2, HOST));
    assert!(!in_session(observe(&mut session, &record(7, 3, 8000, 0))));
}

/// The self message must come first and declare the recording's clock.
#[test]
fn the_self_message_must_come_first_and_declare_the_clock() {
    // Facts first, self later: never the self message.
    let mut session = session_with(&[facts(7, 1, 1, HOST), StreamMessage::DriverSelf(OWN)]);
    assert!(session.own().is_none());
    assert!(!in_session(observe(&mut session, &record(7, 1, 5000, 0))));
    // Another clock, another granularity, or a zero namespace word.
    for own in [
        DriverSelf {
            clock: [0, 0, 0, 5, 78],
            ..OWN
        },
        DriverSelf {
            granularity: 999,
            ..OWN
        },
        DriverSelf {
            namespace: 0,
            ..OWN
        },
    ] {
        let mut session = session_with(&[StreamMessage::DriverSelf(own), facts(7, 1, 1, HOST)]);
        assert!(!in_session(observe(&mut session, &record(7, 1, 5000, 0))));
    }
    // A record that does not decode has no time.
    let mut session = session_with(&[StreamMessage::DriverSelf(OWN), facts(7, 1, 1, HOST)]);
    let StreamMessage::Record(mut bad) = record(7, 1, 5000, 0) else {
        unreachable!()
    };
    bad.words[0] = u64::MAX;
    assert_eq!(
        observe(&mut session, &StreamMessage::Record(bad)),
        Observation::Unreadable
    );
}

/// The events tile the range: the self and facts frames belong to the
/// first record, padding and a loss to the record before; a partial frame
/// at the end is left for the next range.
#[test]
fn a_range_folds_into_tiling_events_and_its_losses() {
    let loss = StreamLoss {
        journal: 7,
        first: 3,
        last: 4,
    };
    let mut bytes = Vec::new();
    for message in [
        StreamMessage::DriverSelf(OWN),
        facts(7, 1, 1, HOST),
        record(7, 1, 5000, 10),
        StreamMessage::Loss(loss),
        record(7, 1, 6000, 2000),
    ] {
        bytes.extend(frame(&message));
    }
    bytes.extend(pad(64));
    let whole = bytes.len() as u64;
    // Half a frame more.
    bytes.extend(&frame(&record(7, 1, 7000, 0))[..64]);
    let base = 4096;
    let mut session = TraceSession::new();
    let folded = fold(&mut session, &CLOCK, &bytes, base);
    assert_eq!(folded.end, base + whole);
    assert_eq!(folded.events.len(), 2);
    let [first, second] = [folded.events[0], folded.events[1]];
    assert_eq!(
        (first.start, first.time, first.in_session),
        (base, 5000, true)
    );
    assert_eq!(first.end, second.start);
    assert_eq!((second.time, second.in_session), (6000, false));
    assert_eq!(second.end, base + whole);
    assert_eq!(folded.losses.len(), 1);
    assert_eq!(folded.losses[0].1, loss);
    // A fragment and a heartbeat carry no message.
    let mut seen = Vec::new();
    let mut odd = data_frame(&[1; 40], true, false);
    odd.extend(data_frame(&[], true, true));
    let end = frames(&odd, 0, |start, end, payload| {
        seen.push((start, end, payload.is_some()));
    });
    assert_eq!(seen, [(0, 96, false), (96, 128, false)]);
    assert_eq!(end, 128);
}
