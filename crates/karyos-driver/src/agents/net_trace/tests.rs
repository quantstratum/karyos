// SPDX-License-Identifier: Apache-2.0

//! The agents' network trace points: the frame scan, the sender's pickups
//! and its journal commands.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests, as ADR-0007 allows"
)]

use super::*;
use karyos_protocol::frame::{Flags, FrameHeader};

fn frame(out: &mut Vec<u8>, payload: usize, ext: Option<TraceExtension>) {
    let header = usize::try_from(HEADER_LENGTH).unwrap();
    let extension = usize::try_from(EXTENSION_LENGTH).unwrap();
    let ext_len = if ext.is_some() { extension } else { 0 };
    let length = header + ext_len + payload;
    let flags = Flags::new(
        true,
        true,
        false,
        ext.is_some(),
        karyos_protocol::frame::Lane::ZERO,
    );
    let start = out.len();
    let extent = usize::try_from(align_frame(u32::try_from(length).unwrap()).unwrap()).unwrap();
    out.resize(start + extent, 0);
    FrameHeader {
        word0: Word0::new(i32::try_from(length).unwrap(), flags, FrameType::Data),
        term_offset: 0,
        session_id: 1,
        stream_id: 2,
        term_id: 0,
        reserved_value: 0,
    }
    .encode(&mut out[start..])
    .unwrap();
    if let Some(ext) = ext {
        ext.encode(&mut out[start + header..]).unwrap();
    }
}

fn ext(message_id: u64) -> TraceExtension {
    TraceExtension {
        extension_flags: 0,
        trace_id: [7, 9],
        span_id: 3,
        parent_span_id: 0,
        message_id,
    }
}

#[test]
fn finds_each_traced_frame_at_its_position() {
    let mut bytes = Vec::new();
    frame(&mut bytes, 10, Some(ext(1)));
    let second = u64::try_from(bytes.len()).unwrap();
    frame(&mut bytes, 40, None);
    let third = u64::try_from(bytes.len()).unwrap();
    frame(&mut bytes, 0, Some(ext(2)));
    let mut out = Vec::with_capacity(traced_frames_per_datagram(bytes.len()).unwrap());
    assert_eq!(traced_frames(&bytes, 4096, &mut out), Some(0));
    assert_eq!(out, vec![(ext(1), 4096), (ext(2), 4096 + third)]);
    assert!(second < third);
}

#[test]
fn an_extension_that_does_not_decode_is_counted_not_traced() {
    let mut bytes = Vec::new();
    frame(&mut bytes, 0, Some(ext(1)));
    let header = usize::try_from(HEADER_LENGTH).unwrap();
    // A wrong extension version.
    bytes[header] = 0xff;
    let mut out = Vec::with_capacity(4);
    assert_eq!(traced_frames(&bytes, 0, &mut out), Some(1));
    assert!(out.is_empty());
}

#[test]
fn never_grows_its_scratch() {
    let mut bytes = Vec::new();
    frame(&mut bytes, 0, Some(ext(1)));
    frame(&mut bytes, 0, Some(ext(2)));
    let mut out = Vec::with_capacity(1);
    let capacity = out.capacity();
    let skipped = traced_frames(&bytes, 0, &mut out).unwrap();
    assert_eq!(out.capacity(), capacity);
    assert_eq!(out.len() + usize::try_from(skipped).unwrap(), 2);
}

#[test]
fn a_canonical_record_or_garbage_ends_the_scan() {
    let mut out = Vec::with_capacity(4);
    assert_eq!(traced_frames(&[0u8; 32], 0, &mut out), Some(0));
    assert_eq!(traced_frames(&[], 0, &mut out), Some(0));
    assert!(out.is_empty());
}

mod sender {
    use std::net::SocketAddr;
    use std::num::NonZeroUsize;
    use std::sync::{Arc, Mutex};

    use karyos_io::backend::InstanceId;
    use karyos_io::sockets::endpoint::{SocketsConfig, SocketsEndpoint, SocketsTx};
    use karyos_io::sockets::ops::SendResult;
    use karyos_io::sockets::scripted::ScriptedSocket;
    use karyos_protocol::journal::record_journal;
    use karyos_protocol::lanes::drr::Budget;
    use karyos_protocol::network::{Alias, TermParams};
    use karyos_protocol::trace_hook::{NetCommit, NetJournal, NetPickup};
    use karyos_sys::alloc_count::count;
    use karyos_sys::log_buffer::{AppendOptions, AppendOutcome};

    use super::super::super::data::testing::{TestLog, outbound};
    use super::super::super::ring::ring;
    use super::super::super::{AgentCommand, AgentEvent, EndpointId};
    use super::super::*;
    use super::ext;

    #[derive(Default)]
    struct Seen {
        journals: Vec<NetJournal>,
        closed: Vec<(NetSide, PublicationIdentity, Lane)>,
        pickups: Vec<(TraceExtension, NetPickup)>,
    }

    /// Records every call; its storage is reserved up front so that
    /// recording allocates nothing.
    #[derive(Clone)]
    struct Recorder(Arc<Mutex<Seen>>);

    impl Recorder {
        fn new() -> Self {
            Self(Arc::new(Mutex::new(Seen {
                journals: Vec::with_capacity(8),
                closed: Vec::with_capacity(8),
                pickups: Vec::with_capacity(64),
            })))
        }

        fn pickups(&self) -> Vec<(TraceExtension, NetPickup)> {
            self.0.lock().unwrap().pickups.clone()
        }

        fn journals(&self) -> Vec<u64> {
            let seen = self.0.lock().unwrap();
            seen.journals.iter().map(|journal| journal.number).collect()
        }

        fn closed(&self) -> Vec<(NetSide, PublicationIdentity, Lane)> {
            self.0.lock().unwrap().closed.clone()
        }
    }

    impl NetworkTraceHook for Recorder {
        fn open_journal(&mut self, journal: NetJournal) {
            self.0.lock().unwrap().journals.push(journal);
        }

        fn close_journal(&mut self, side: NetSide, publication: &PublicationIdentity, lane: Lane) {
            self.0
                .lock()
                .unwrap()
                .closed
                .push((side, *publication, lane));
        }

        fn on_sender_pickup(&mut self, ext: &TraceExtension, at: &NetPickup) {
            self.0.lock().unwrap().pickups.push((*ext, *at));
        }

        fn on_receiver_commit(&mut self, _ext: &TraceExtension, _at: &NetCommit) {}
    }

    const ALIAS: Alias = Alias {
        session_id: 5,
        stream_id: 6,
    };

    fn identity() -> PublicationIdentity {
        PublicationIdentity {
            driver: [1, 2],
            registration: 3,
            stream_id: ALIAS.stream_id,
            session_id: ALIAS.session_id,
            incarnation: 1,
        }
    }

    const BUDGET: Budget = Budget {
        work: 64,
        bytes: 1 << 20,
    };

    /// A scripted endpoint that sends everything, and a one-lane
    /// unreliable publication with an MTU of 1408 bytes.
    fn sending() -> (SocketsTx<ScriptedSocket>, Box<Outbound>, TestLog) {
        let socket = ScriptedSocket::new();
        let observer = socket.observer();
        for _ in 0..64 {
            observer.push_send(SendResult::Sent {
                sent: 1,
                error: None,
            });
        }
        let local = SocketsConfig::new(SocketAddr::from(([127, 0, 0, 1], 0)));
        let endpoint = SocketsEndpoint::open(&local, InstanceId::FIRST, socket).unwrap();
        let (tx, _rx) = endpoint.split().unwrap();
        let term = TermParams {
            term_length: 65_536,
            initial_term_id: 9,
            mtu: 1408,
        };
        let destination = SocketAddr::from(([127, 0, 0, 1], 41_000));
        let (path, log) = outbound(EndpointId(1), ALIAS, destination, term, 1, false);
        (tx, path, log)
    }

    fn traced(message_id: u64) -> AppendOptions {
        let mut bytes = [0u8; 64];
        ext(message_id).encode(&mut bytes).unwrap();
        AppendOptions {
            extension: Some(bytes),
            ..AppendOptions::default()
        }
    }

    fn append(log: &mut TestLog, len: usize, options: AppendOptions) -> u64 {
        match log.publications[0]
            .append(&vec![7u8; len], options)
            .unwrap()
        {
            AppendOutcome::Appended { position } => position,
            other => panic!("not appended: {other:?}"),
        }
    }

    fn serve(
        tx: &mut SocketsTx<ScriptedSocket>,
        path: &mut Outbound,
        hook: Option<&mut Box<dyn NetworkTraceHook>>,
    ) {
        let mut hook = hook.map(|hook| &mut **hook);
        for _ in 0..4 {
            let _ = path
                .serve_traced(tx, BUDGET, None, 0, hook.as_deref_mut())
                .unwrap();
        }
    }

    /// NT-2: every fragment of a traced message is picked up once, at its
    /// own position, as a first send on path 0; an untraced message
    /// records nothing; the boundary is where the lane's reads reached.
    #[test]
    fn every_fragment_of_a_traced_message_is_picked_up_once() {
        let (mut tx, mut path, mut log) = sending();
        let recorder = Recorder::new();
        let mut hook: Box<dyn NetworkTraceHook> = Box::new(recorder.clone());
        assert_eq!(path.trace(0, identity()), Some(0));
        assert_eq!(path.trace(0, identity()), None, "already traced");
        assert_eq!(path.trace(1, identity()), None, "no such lane");
        let block = append(&mut log, 3000, traced(1));
        let _ = append(&mut log, 200, AppendOptions::default());
        serve(&mut tx, &mut path, Some(&mut hook));
        let pickups = recorder.pickups();
        assert_eq!(pickups.len(), 3, "{pickups:?}");
        assert_eq!(pickups[0].1.position, block);
        for window in pickups.windows(2) {
            assert!(window[0].1.position < window[1].1.position);
        }
        for (seen, at) in &pickups {
            assert_eq!(*seen, ext(1));
            assert_eq!(
                (at.publication, at.lane, at.path, at.attempt),
                (identity(), Lane::ZERO, 0, 0)
            );
        }
        let facts = path.untrace(0, &identity()).unwrap();
        assert_eq!(facts.start, 0);
        assert_eq!(facts.boundary, path.readers()[0].position());
        assert!(facts.boundary > pickups[2].1.position);
        assert_eq!(path.counters().trace_invalid, 0);
    }

    /// The start fact (trace-network.md §5, ACS 15840): a journal starts at
    /// the lane's next position when it arrives; what was sent before
    /// records nothing, what follows is recorded.
    #[test]
    fn a_journal_starts_at_the_next_position() {
        let (mut tx, mut path, mut log) = sending();
        let recorder = Recorder::new();
        let mut hook: Box<dyn NetworkTraceHook> = Box::new(recorder.clone());
        let _ = append(&mut log, 300, traced(1));
        serve(&mut tx, &mut path, Some(&mut hook));
        assert!(recorder.pickups().is_empty(), "the lane was not traced");
        let start = path.trace(0, identity()).unwrap();
        assert_eq!(start, path.readers()[0].position());
        assert!(start > 0);
        let block = append(&mut log, 300, traced(2));
        serve(&mut tx, &mut path, Some(&mut hook));
        let pickups = recorder.pickups();
        assert_eq!(pickups.len(), 1);
        assert_eq!((pickups[0].0, pickups[0].1.position), (ext(2), block));
        assert!(block >= start);
        let facts = path.untrace(0, &identity()).unwrap();
        assert_eq!(facts.start, start);
        assert_eq!(facts.boundary, path.readers()[0].position());
    }

    /// Picks up `bytes`, read at `from`, on lane 0 of `lanes`.
    fn pick(
        bytes: &[u8],
        from: u64,
        lanes: &mut [Option<TracedLane>; 4],
        hook: &mut Box<dyn NetworkTraceHook>,
    ) {
        let mut picked = Vec::with_capacity(8);
        assert_eq!(traced_frames(bytes, from, &mut picked), Some(0));
        let traced = lanes[0].unwrap();
        let next = from + u64::try_from(bytes.len()).unwrap();
        super::super::super::data::pick_up(&picked, lanes, 0, traced, from..next, &mut **hook);
    }

    fn traced_lane() -> TracedLane {
        TracedLane {
            publication: identity(),
            start: 0,
            boundary: 0,
            unpicked: None,
        }
    }

    /// NT-2: a resend after a reset rewind was picked up before and records
    /// nothing.
    #[test]
    fn a_rewound_resend_records_nothing() {
        let mut bytes = Vec::new();
        super::frame(&mut bytes, 100, Some(ext(1)));
        let recorder = Recorder::new();
        let mut hook: Box<dyn NetworkTraceHook> = Box::new(recorder.clone());
        let mut lanes = [Some(traced_lane()), None, None, None];
        pick(&bytes, 0, &mut lanes, &mut hook);
        assert_eq!(recorder.pickups().len(), 1);
        pick(&bytes, 0, &mut lanes, &mut hook);
        assert_eq!(recorder.pickups().len(), 1, "the resend is not recorded");
    }

    /// ACS 15882: a datagram whose commit failed never reached TX storage;
    /// after the reset rewinds, its resend is the frames' first pickup and
    /// is recorded once, even below the boundary; a datagram the failure
    /// did not touch is not.
    #[test]
    fn a_failed_commit_is_picked_up_on_its_resend() {
        use super::super::super::data::remember_unpicked;

        let mut first = Vec::new();
        super::frame(&mut first, 100, Some(ext(1)));
        let len = u64::try_from(first.len()).unwrap();
        let mut second = Vec::new();
        super::frame(&mut second, 100, Some(ext(2)));
        let recorder = Recorder::new();
        let mut hook: Box<dyn NetworkTraceHook> = Box::new(recorder.clone());
        let mut lanes = [Some(traced_lane()), None, None, None];
        // The first datagram's commit fails; the second is picked up.
        assert!(remember_unpicked(&mut lanes, 0, 0, len));
        pick(&second, len, &mut lanes, &mut hook);
        assert_eq!(recorder.pickups().len(), 1);
        // A range the lane cannot also hold is refused, so it is counted.
        assert!(!remember_unpicked(&mut lanes, 0, 4 * len, 5 * len));
        // The rewind resends both.
        pick(&first, 0, &mut lanes, &mut hook);
        pick(&second, len, &mut lanes, &mut hook);
        let pickups = recorder.pickups();
        assert_eq!(pickups.len(), 2, "{pickups:?}");
        assert_eq!((pickups[1].0, pickups[1].1.position), (ext(1), 0));
        assert_eq!(lanes[0].unwrap().unpicked, None);
        pick(&first, 0, &mut lanes, &mut hook);
        assert_eq!(recorder.pickups().len(), 2, "picked up once");
    }

    /// A frame with EXT set but too short for its extension is counted, and
    /// nothing is read past it.
    #[test]
    fn an_extension_past_its_frame_is_not_read() {
        let mut bytes = Vec::new();
        super::frame(&mut bytes, 100, Some(ext(1)));
        // Frame length 40: the header and 8 bytes, EXT still set.
        bytes[..4].copy_from_slice(&40i32.to_le_bytes());
        let mut out = Vec::with_capacity(4);
        assert_eq!(traced_frames(&bytes, 0, &mut out), Some(1));
        assert!(out.is_empty());
    }

    /// Without a hook nothing is recorded and the boundary stays at the
    /// start: nothing is expected of the journal.
    #[test]
    fn without_a_hook_the_boundary_holds() {
        let (mut tx, mut path, mut log) = sending();
        let start = path.trace(0, identity()).unwrap();
        let _ = append(&mut log, 300, traced(1));
        serve(&mut tx, &mut path, None);
        assert!(path.readers()[0].position() > start);
        let facts = path.untrace(0, &identity()).unwrap();
        assert_eq!((facts.start, facts.boundary), (start, start));
    }

    /// Recording a pickup allocates nothing: the scan uses the scratch
    /// reserved at construction (P2.12 step 3, data path).
    #[test]
    fn picking_up_allocates_nothing() {
        let ((), made) = count(|| drop(std::hint::black_box(vec![0_u8; 8])));
        assert!(made > 0, "the counting allocator counts in this binary");
        let mut bytes = Vec::new();
        super::frame(&mut bytes, 100, Some(ext(1)));
        super::frame(&mut bytes, 100, Some(ext(2)));
        let mut picked = Vec::with_capacity(traced_frames_per_datagram(1408).unwrap());
        let recorder = Recorder::new();
        let mut hook: Box<dyn NetworkTraceHook> = Box::new(recorder.clone());
        let traced_lane = TracedLane {
            publication: identity(),
            start: 0,
            boundary: 0,
            unpicked: None,
        };
        let mut lanes = [Some(traced_lane), None, None, None];
        // A first lock may allocate the mutex itself (macOS).
        assert!(recorder.pickups().is_empty());
        let next = u64::try_from(bytes.len()).unwrap();
        let ((), made) = count(|| {
            let skipped = traced_frames(&bytes, 0, &mut picked);
            assert_eq!(skipped, Some(0));
            super::super::super::data::pick_up(
                &picked,
                &mut lanes,
                0,
                traced_lane,
                0..next,
                &mut *hook,
            );
        });
        assert_eq!(made, 0);
        assert_eq!(recorder.pickups().len(), 2);
        assert_eq!(lanes[0].unwrap().boundary, next);
    }

    fn journal(side: NetSide, number: u64) -> NetJournal {
        let (writer, _consumer) = record_journal(4, 1, 1).unwrap();
        NetJournal {
            side,
            publication: identity(),
            lane: Lane::ZERO,
            number,
            writer,
        }
    }

    type Event = AgentEvent<karyos_io::sockets::OsSocket>;
    type Command = AgentCommand<karyos_io::sockets::OsSocket>;

    /// The journal commands: refused without a hook, for the wrong side,
    /// publication or a lane already traced (the journal comes back);
    /// opened with the start; closed with the facts, once; a hook replaced
    /// closes the journals it still held.
    #[test]
    fn the_sender_serves_its_journal_commands() {
        let (_tx, path, _log) = sending();
        let mut publications = vec![*path];
        let mut trace = SenderTrace::default();
        let (replies, _keep) = ring::<Event>(NonZeroUsize::new(16).unwrap());
        let mut serve = |trace: &mut SenderTrace, command: Command| {
            trace
                .command(&mut publications, command)
                .map(|(_, event)| event)
                .unwrap()
        };
        let open = |endpoint, journal| Command::OpenNetworkJournal {
            reply: replies.reserve().unwrap(),
            endpoint,
            alias: ALIAS,
            journal,
        };
        let refused = |event: Event, number: u64| {
            assert!(
                matches!(event, AgentEvent::NetworkJournalRefused { ref journal, .. }
                    if journal.number == number),
                "{event:?}"
            );
        };
        refused(
            serve(&mut trace, open(EndpointId(1), journal(NetSide::Sender, 1))),
            1,
        );
        let recorder = Recorder::new();
        let set = Command::SetNetworkTrace {
            reply: replies.reserve().unwrap(),
            hook: Some(TraceHook(Box::new(recorder.clone()))),
        };
        assert!(matches!(
            serve(&mut trace, set),
            AgentEvent::NetworkTraceSet {
                previous: None,
                closed: Some(0),
                ..
            }
        ));
        refused(
            serve(
                &mut trace,
                open(EndpointId(1), journal(NetSide::Receiver, 2)),
            ),
            2,
        );
        refused(
            serve(&mut trace, open(EndpointId(2), journal(NetSide::Sender, 3))),
            3,
        );
        assert!(matches!(
            serve(&mut trace, open(EndpointId(1), journal(NetSide::Sender, 4))),
            AgentEvent::NetworkJournalOpened {
                number: 4,
                start: 0,
                lane: Lane::ZERO,
                ..
            }
        ));
        refused(
            serve(&mut trace, open(EndpointId(1), journal(NetSide::Sender, 5))),
            5,
        );
        assert_eq!(recorder.journals(), [4]);
        let close = || Command::CloseNetworkJournal {
            reply: replies.reserve().unwrap(),
            publication: identity(),
            lane: Lane::ZERO,
        };
        let AgentEvent::NetworkJournalClosed {
            facts: Some(facts), ..
        } = serve(&mut trace, close())
        else {
            panic!("not closed");
        };
        assert_eq!(
            facts,
            JournalFacts {
                publication: identity(),
                start: 0,
                boundary: 0,
                first_gap: None,
            }
        );
        assert_eq!(
            recorder.closed(),
            [(NetSide::Sender, identity(), Lane::ZERO)]
        );
        assert!(matches!(
            serve(&mut trace, close()),
            AgentEvent::NetworkJournalClosed { facts: None, .. }
        ));
        assert!(matches!(
            serve(&mut trace, open(EndpointId(1), journal(NetSide::Sender, 6))),
            AgentEvent::NetworkJournalOpened { number: 6, .. }
        ));
        let remove = Command::SetNetworkTrace {
            reply: replies.reserve().unwrap(),
            hook: None,
        };
        assert!(matches!(
            serve(&mut trace, remove),
            AgentEvent::NetworkTraceSet {
                previous: Some(_),
                closed: Some(1),
                ..
            }
        ));
        assert_eq!(recorder.closed().len(), 2);
        assert!(trace.hook().is_none());
    }
}
