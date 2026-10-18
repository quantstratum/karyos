// SPDX-License-Identifier: Apache-2.0

// The Archive's client against a fake Archive on in-memory control
// streams: it finds the recording of the right incarnation that covers a
// range, asks for exactly that range, and hands out the target's
// subscription; it says why when no replay comes, waits for a recording
// that is behind until its deadline, pages through long lists, skips
// others' answers, and stops the replays it hands out or abandons.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers, as ADR-0007 allows in tests"
)]

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use karyos_client::{PublicationIdentity, ReplayProvider};
use karyos_sys::frame::Lane;
use karyos_sys::log_buffer::{Conductor, LogBuffer, LogBufferConfig, Role};
use karyos_sys::sizing::{DEFAULT_MTU, MIN_TERM_LENGTH, TermLength};
use karyos_sys::term::TermId;

use super::*;
use crate::catalog::Stop;
use crate::catalog::StopReason;
use crate::segment::Geometry;

const TARGET: i32 = 77;
const CLIENT: u32 = 9;
const MS: u64 = 1_000_000;

fn source() -> PublicationIdentity {
    PublicationIdentity {
        driver: [1, 2],
        registration: 3,
        stream_id: 10,
        session_id: 4,
        incarnation: 5,
    }
}

fn request(from: u64, to: u64) -> ReplayRequest {
    ReplayRequest {
        source: source(),
        from,
        to,
    }
}

/// A recording the fake Archive lists.
#[derive(Debug, Clone, Copy)]
struct Listed {
    id: u64,
    start: u64,
    /// The stop, or the position written while it records.
    end: u64,
    recording: bool,
    stream_id: i32,
    session_id: i32,
    source: SourceIncarnation,
}

fn recording_of_source(id: u64, start: u64, end: u64, recording: bool) -> Listed {
    let source = source();
    Listed {
        id,
        start,
        end,
        recording,
        stream_id: source.stream_id,
        session_id: source.session_id,
        source: SourceIncarnation {
            driver: source.driver,
            registration: source.registration,
            incarnation: source.incarnation,
        },
    }
}

/// The fake Archive: it reads what the client sent and answers.
#[derive(Default)]
struct Archive {
    sent: Arc<Mutex<VecDeque<Vec<u8>>>>,
    answers: Arc<Mutex<VecDeque<Vec<u8>>>>,
    room: Arc<AtomicBool>,
    recordings: Vec<Listed>,
    /// The code a replay request is answered with.
    replay_code: Option<ResponseCode>,
    list_code: Option<ResponseCode>,
    next_replay: u64,
    /// The targets it opened: stream and session ids.
    opened: Arc<Mutex<Vec<(i32, i32)>>>,
    /// Every request it read, decoded to its kind and fields.
    seen: Vec<Seen>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Seen {
    List {
        from_id: u64,
        max_count: u32,
    },
    Replay {
        recording_id: u64,
        position: u64,
        length: u64,
        target_stream_id: i32,
        full: bool,
    },
    Stop {
        replay_id: u64,
    },
}

impl Archive {
    fn new(recordings: Vec<Listed>) -> Self {
        Self {
            room: Arc::new(AtomicBool::new(true)),
            recordings,
            next_replay: 0x1_0000_0041,
            ..Self::default()
        }
    }

    fn answer(&self, message: &ControlMessage<'_>) {
        let mut out = vec![0u8; MAX_ANSWER];
        let length = message.encode(&mut out).unwrap();
        out.truncate(length);
        self.answers.lock().unwrap().push_back(out);
    }

    fn respond(&self, correlation_id: u64, id: u64, code: ResponseCode) {
        self.answer(&ControlMessage::ControlResponse(ControlResponse {
            correlation_id,
            id: if code == ResponseCode::Ok { id } else { 0 },
            code,
            message: if code == ResponseCode::Ok {
                ""
            } else {
                "refused"
            },
        }));
    }

    /// Answers every request sent so far.
    fn serve(&mut self) {
        loop {
            let Some(bytes) = self.sent.lock().unwrap().pop_front() else {
                return;
            };
            match ControlMessage::decode(&bytes).unwrap() {
                ControlMessage::ListRecordings(list) => {
                    self.seen.push(Seen::List {
                        from_id: list.from_id,
                        max_count: list.max_count,
                    });
                    if let Some(code) = self.list_code {
                        self.respond(list.correlation_id, 0, code);
                        continue;
                    }
                    let listed: Vec<Listed> = self
                        .recordings
                        .iter()
                        .filter(|recording| recording.id >= list.from_id)
                        .take(usize::try_from(list.max_count).unwrap())
                        .copied()
                        .collect();
                    for recording in &listed {
                        self.answer(&ControlMessage::RecordingDescriptor(descriptor(
                            list.correlation_id,
                            recording,
                        )));
                    }
                    self.respond(
                        list.correlation_id,
                        u64::try_from(listed.len()).unwrap(),
                        ResponseCode::Ok,
                    );
                }
                ControlMessage::Replay(replay) => {
                    self.seen.push(Seen::Replay {
                        recording_id: replay.recording_id,
                        position: replay.position,
                        length: replay.length,
                        target_stream_id: replay.target_stream_id,
                        full: replay.rate == ReplayRate::Full,
                    });
                    let code = self.replay_code.unwrap_or(ResponseCode::Ok);
                    let id = self.next_replay;
                    self.next_replay += 1;
                    if code == ResponseCode::Ok {
                        self.opened
                            .lock()
                            .unwrap()
                            .push((replay.target_stream_id, replay_session_id(id)));
                    }
                    self.respond(replay.correlation_id, id, code);
                }
                ControlMessage::StopReplay(stop) => {
                    self.seen.push(Seen::Stop {
                        replay_id: stop.replay_id,
                    });
                    self.respond(stop.correlation_id, stop.replay_id, ResponseCode::Ok);
                }
                other => panic!("not a request: {other:?}"),
            }
        }
    }

    fn stops(&self) -> Vec<u64> {
        self.seen
            .iter()
            .filter_map(|seen| match seen {
                Seen::Stop { replay_id } => Some(*replay_id),
                _ => None,
            })
            .collect()
    }
}

fn descriptor<'a>(correlation_id: u64, recording: &Listed) -> RecordingDescriptor<'a> {
    RecordingDescriptor {
        correlation_id,
        recording_id: recording.id,
        start: recording.start,
        start_time_ns: 1,
        state: if recording.recording {
            RecordingState::Recording {
                written: recording.end,
                incomplete: false,
            }
        } else {
            RecordingState::Stopped(Stop {
                position: recording.end,
                time_ns: 2,
                reason: StopReason::Stopped,
                incomplete: false,
            })
        },
        geometry: Geometry::new(MIN_TERM_LENGTH, 4 * u64::from(MIN_TERM_LENGTH)).unwrap(),
        source: recording.source,
        stream_id: recording.stream_id,
        session_id: recording.session_id,
        channel: "karyos:ipc",
    }
}

/// The client's request stream: into the fake Archive, while it has room.
struct Requests {
    sent: Arc<Mutex<VecDeque<Vec<u8>>>>,
    room: Arc<AtomicBool>,
}

impl ControlRequests for Requests {
    fn send(&mut self, message: &[u8]) -> bool {
        if !self.room.load(Ordering::Acquire) {
            return false;
        }
        self.sent.lock().unwrap().push_back(message.to_vec());
        true
    }
}

/// The client's response stream: the fake Archive's answers.
struct Responses(Arc<Mutex<VecDeque<Vec<u8>>>>);

impl ControlResponses for Responses {
    fn next(&mut self, out: &mut [u8]) -> Option<usize> {
        let message = self.0.lock().unwrap().pop_front()?;
        out[..message.len()].copy_from_slice(&message);
        Some(message.len())
    }
}

/// The host's targets: a subscription to a log buffer for each target the
/// fake Archive opened.
struct Targets {
    opened: Arc<Mutex<Vec<(i32, i32)>>>,
    conductor: Conductor<Arc<LogBuffer>>,
    /// Hide the targets, as a host whose image is not exposed yet.
    hidden: Arc<AtomicBool>,
}

impl ReplayTargets for Targets {
    fn subscribe(&mut self, stream_id: i32, session_id: i32) -> Option<ClientSubscription> {
        if self.hidden.load(Ordering::Acquire)
            || !self
                .opened
                .lock()
                .unwrap()
                .contains(&(stream_id, session_id))
        {
            return None;
        }
        Some(ClientSubscription::new(
            self.conductor.subscribe(Role::Required).unwrap(),
        ))
    }
}

fn buffer() -> Arc<LogBuffer> {
    Arc::new(
        LogBuffer::new(LogBufferConfig {
            term_length: TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
            spare_slots: 2,
            max_subscribers: 8,
            mtu: DEFAULT_MTU,
            max_reserved: MIN_TERM_LENGTH / 8,
            initial_term_id: TermId::new(7),
            lane: Lane::ZERO,
            session_id: 1,
            stream_id: TARGET,
            claim_deadline: karyos_sys::log_buffer::DEFAULT_CLAIM_DEADLINE,
            publication: karyos_sys::log_buffer::PublicationMode::Exclusive,
            schedule_capacity: 0,
        })
        .unwrap(),
    )
}

type Client = ArchiveClient<Requests, Responses, Targets>;

/// A client of `archive` on a clock the test sets, and the clock and the
/// targets' hiding switch.
fn connect(archive: &Archive, config: ClientConfig) -> (Client, Arc<AtomicU64>, Arc<AtomicBool>) {
    let clock = Arc::new(AtomicU64::new(0));
    let hidden = Arc::new(AtomicBool::new(false));
    let now = Arc::clone(&clock);
    let client = ArchiveClient::with_clock(
        config,
        Requests {
            sent: Arc::clone(&archive.sent),
            room: Arc::clone(&archive.room),
        },
        Responses(Arc::clone(&archive.answers)),
        Targets {
            opened: Arc::clone(&archive.opened),
            conductor: buffer().conductor_owned().unwrap(),
            hidden: Arc::clone(&hidden),
        },
        Box::new(move || now.load(Ordering::Acquire)),
    );
    (client, clock, hidden)
}

fn config() -> ClientConfig {
    ClientConfig {
        deadline: Duration::from_millis(100),
        relist: Duration::from_millis(10),
        ..ClientConfig::new(CLIENT, TARGET)
    }
}

/// Calls the client and lets the Archive answer until the request is
/// answered, at most 100 rounds.
fn ask(client: &mut Client, archive: &mut Archive, request: &ReplayRequest) -> ReplayStatus {
    for _ in 0..100 {
        match client.replay(request) {
            ReplayStatus::Pending => archive.serve(),
            status => return status,
        }
    }
    panic!("no answer");
}

fn unavailable(status: ReplayStatus) -> ReplayUnavailable {
    match status {
        ReplayStatus::Unavailable(reason) => reason,
        other => panic!("{other:?}"),
    }
}

/// The recording of the source that covers the range is replayed, exactly
/// that range, onto the client's target stream; the target is found at the
/// replay id's low 32 bits; dropping the replay stops it.
#[test]
fn a_covering_recording_is_replayed_and_stopped() {
    let mut archive = Archive::new(vec![
        // Another incarnation, another session, then the covering one.
        Listed {
            source: SourceIncarnation {
                incarnation: 6,
                ..recording_of_source(1, 0, 9000, false).source
            },
            ..recording_of_source(1, 0, 9000, false)
        },
        Listed {
            session_id: 5,
            ..recording_of_source(2, 0, 9000, false)
        },
        // Its end exactly the range's.
        recording_of_source(3, 0, 5000, false),
    ]);
    let (mut client, _, _) = connect(&archive, config());
    let ReplayStatus::Ready(replay) = ask(&mut client, &mut archive, &request(1000, 5000)) else {
        panic!("no replay");
    };
    assert_eq!(*replay.source(), source());
    assert_eq!(
        archive.seen,
        [
            Seen::List {
                from_id: 0,
                max_count: MAX_LIST_COUNT
            },
            Seen::Replay {
                recording_id: 3,
                position: 1000,
                length: 4000,
                target_stream_id: TARGET,
                full: true,
            },
        ]
    );
    assert_eq!(
        *archive.opened.lock().unwrap(),
        [(TARGET, replay_session_id(0x1_0000_0041))]
    );
    drop(replay);
    archive.serve();
    assert_eq!(archive.stops(), [0x1_0000_0041]);
}

/// No replay comes, with the reason: no recording of the source, one of
/// another incarnation only, one that starts after the range, one that
/// stopped before its end, and the Archive's refusals.
#[test]
fn an_unavailable_replay_says_why() {
    let other = Listed {
        source: SourceIncarnation {
            incarnation: 6,
            ..recording_of_source(1, 0, 9000, false).source
        },
        ..recording_of_source(1, 0, 9000, false)
    };
    let cases = [
        (vec![], ReplayUnavailable::NoRecording),
        (vec![other], ReplayUnavailable::NoRecording),
        (
            vec![recording_of_source(1, 2000, 9000, false)],
            ReplayUnavailable::RetentionShort,
        ),
        (
            vec![recording_of_source(1, 0, 3000, false)],
            ReplayUnavailable::NoRecording,
        ),
    ];
    for (recordings, reason) in cases {
        let mut archive = Archive::new(recordings);
        let (mut client, _, _) = connect(&archive, config());
        assert_eq!(
            unavailable(ask(&mut client, &mut archive, &request(1000, 5000))),
            reason
        );
    }
    for (list_code, replay_code) in [
        (Some(ResponseCode::Error), None),
        (None, Some(ResponseCode::Error)),
        (None, Some(ResponseCode::InvalidRequest)),
    ] {
        let mut archive = Archive {
            list_code,
            replay_code,
            ..Archive::new(vec![recording_of_source(1, 0, 9000, false)])
        };
        let (mut client, _, _) = connect(&archive, config());
        assert_eq!(
            unavailable(ask(&mut client, &mut archive, &request(1000, 5000))),
            ReplayUnavailable::Refused
        );
    }
    // The recording went between the list and the replay.
    let mut archive = Archive {
        replay_code: Some(ResponseCode::UnknownRecording),
        ..Archive::new(vec![recording_of_source(1, 0, 9000, false)])
    };
    let (mut client, _, _) = connect(&archive, config());
    assert_eq!(
        unavailable(ask(&mut client, &mut archive, &request(1000, 5000))),
        ReplayUnavailable::NoRecording
    );
    // An empty range asks nothing.
    assert_eq!(
        unavailable(client.replay(&request(5000, 5000))),
        ReplayUnavailable::Refused
    );
}

/// A recording that still records and has not reached the range's end is
/// listed again after the relist interval, and replayed once it covers;
/// one that never catches up is behind at the deadline.
#[test]
fn a_recording_behind_is_awaited_until_the_deadline() {
    let mut archive = Archive::new(vec![recording_of_source(1, 0, 3000, true)]);
    let (mut client, clock, _) = connect(&archive, config());
    let range = request(1000, 5000);
    for _ in 0..4 {
        assert!(matches!(client.replay(&range), ReplayStatus::Pending));
        archive.serve();
    }
    // Before the relist interval: no second list.
    let lists = |archive: &Archive| {
        archive
            .seen
            .iter()
            .filter(|seen| matches!(seen, Seen::List { .. }))
            .count()
    };
    assert_eq!(lists(&archive), 1);
    archive.recordings[0].end = 6000;
    clock.store(11 * MS, Ordering::Release);
    let ReplayStatus::Ready(_replay) = ask(&mut client, &mut archive, &range) else {
        panic!("no replay");
    };
    assert_eq!(lists(&archive), 2);

    let mut archive = Archive::new(vec![recording_of_source(1, 0, 3000, true)]);
    let (mut client, clock, _) = connect(&archive, config());
    for step in 0..20 {
        clock.store(step * 10 * MS, Ordering::Release);
        match client.replay(&range) {
            ReplayStatus::Pending => archive.serve(),
            status => {
                assert_eq!(unavailable(status), ReplayUnavailable::RecordingBehind);
                assert!(step * 10 * MS > 100 * MS);
                return;
            }
        }
    }
    panic!("never behind");
}

/// A long list is read page by page, from after the last id listed.
#[test]
fn a_long_list_is_paged() {
    let mut archive = Archive::new(vec![
        recording_of_source(1, 2000, 9000, false),
        recording_of_source(2, 2000, 9000, false),
        recording_of_source(3, 2000, 9000, false),
        recording_of_source(4, 2000, 9000, false),
        recording_of_source(5, 0, 9000, false),
    ]);
    let (mut client, _, _) = connect(
        &archive,
        ClientConfig {
            page: 2,
            ..config()
        },
    );
    let ReplayStatus::Ready(_replay) = ask(&mut client, &mut archive, &request(1000, 5000)) else {
        panic!("no replay");
    };
    let lists: Vec<u64> = archive
        .seen
        .iter()
        .filter_map(|seen| match seen {
            Seen::List { from_id, max_count } => {
                assert_eq!(*max_count, 2);
                Some(*from_id)
            }
            _ => None,
        })
        .collect();
    assert_eq!(lists, [0, 3, 5]);
}

/// Others' answers and signals are skipped, and a request stream with no
/// room holds the request until it has.
#[test]
fn others_answers_are_skipped_and_a_full_stream_waits() {
    let mut archive = Archive::new(vec![recording_of_source(1, 0, 9000, false)]);
    let (mut client, _, _) = connect(&archive, config());
    archive.room.store(false, Ordering::Release);
    let range = request(1000, 5000);
    for _ in 0..3 {
        assert!(matches!(client.replay(&range), ReplayStatus::Pending));
    }
    assert!(archive.sent.lock().unwrap().is_empty());
    archive.room.store(true, Ordering::Release);
    // Another requester's answer and a signal for every reader.
    archive.respond(u64::from(CLIENT + 1) << 32 | 1, 3, ResponseCode::Ok);
    archive.answer(&ControlMessage::RecordingSignal(control::RecordingSignal {
        correlation_id: 0,
        recording_id: 1,
        position: 9000,
        signal: control::Signal::Stopped {
            reason: StopReason::Stopped,
            incomplete: false,
        },
    }));
    let ReplayStatus::Ready(_replay) = ask(&mut client, &mut archive, &range) else {
        panic!("no replay");
    };
}

/// A replay withdrawn before it is handed out is stopped: one whose target
/// is looked for at once, one asked for when its answer comes, and one
/// whose target never appears at the deadline. A stop that finds no room
/// goes out with the next call.
#[test]
fn an_abandoned_replay_is_stopped() {
    let mut archive = Archive::new(vec![recording_of_source(1, 0, 9000, false)]);
    let (mut client, clock, hidden) = connect(&archive, config());
    let range = request(1000, 5000);
    // Its target hidden: the replay runs, its target not found yet.
    hidden.store(true, Ordering::Release);
    for _ in 0..4 {
        assert!(matches!(client.replay(&range), ReplayStatus::Pending));
        archive.serve();
    }
    ReplayProvider::<HeapTerms>::cancel(&mut client);
    archive.serve();
    assert_eq!(archive.stops(), [0x1_0000_0041]);

    // Withdrawn while asked: stopped once the answer comes, on a later
    // call for another range.
    assert!(matches!(client.replay(&range), ReplayStatus::Pending));
    archive.serve();
    assert!(matches!(client.replay(&range), ReplayStatus::Pending));
    ReplayProvider::<HeapTerms>::cancel(&mut client);
    archive.serve();
    hidden.store(false, Ordering::Release);
    let ReplayStatus::Ready(_replay) = ask(&mut client, &mut archive, &request(2000, 6000)) else {
        panic!("no replay");
    };
    assert_eq!(archive.stops(), [0x1_0000_0041, 0x1_0000_0042]);

    // A target that never appears: stopped at the deadline.
    hidden.store(true, Ordering::Release);
    let range = request(3000, 7000);
    for _ in 0..4 {
        assert!(matches!(client.replay(&range), ReplayStatus::Pending));
        archive.serve();
    }
    clock.store(200 * MS, Ordering::Release);
    assert_eq!(
        unavailable(client.replay(&range)),
        ReplayUnavailable::Refused
    );
    archive.serve();
    assert_eq!(archive.stops().len(), 3);

    // A stop with no room waits for the next call.
    hidden.store(false, Ordering::Release);
    let ReplayStatus::Ready(replay) = ask(&mut client, &mut archive, &request(4000, 8000)) else {
        panic!("no replay");
    };
    archive.room.store(false, Ordering::Release);
    drop(replay);
    archive.serve();
    assert_eq!(archive.stops().len(), 3);
    archive.room.store(true, Ordering::Release);
    assert!(matches!(
        client.replay(&request(5000, 9000)),
        ReplayStatus::Pending
    ));
    archive.serve();
    assert_eq!(archive.stops().len(), 4);
}
