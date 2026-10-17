// SPDX-License-Identifier: Apache-2.0

// SenderRead tests (`quantstratum-docs:
// karyos/design/network-sessions-sender.md` S2 2.7, phase 5a), included
// once per term backing by `log_buffer.rs` after `common.rs`.

use crate::receive::{FrameKind, ImageParams, Item, ValidatedDatagram};
use std::collections::{BTreeMap, VecDeque};

use crate::term::TermCount;

/// A datagram buffer of the default MTU.
fn sr_out() -> Vec<u8> {
    vec![0u8; DEFAULT_MTU as usize]
}

/// The read capability over a new reserved required subscriber of
/// `conductor` (S2 2.1).
fn sr_reader<'a>(
    conductor: &mut Conductor<&'a LogBuffer<Terms>>,
) -> SenderRead<&'a LogBuffer<Terms>> {
    SenderRead::new(
        conductor.subscribe_as(Role::Required, true, 1).unwrap(),
        DEFAULT_CORRUPT_RETRIES,
    )
    .unwrap()
}

/// Whether the reader's loan word is empty: every return released it.
fn sr_loan_released(reader: &SenderRead<&LogBuffer<Terms>>) -> bool {
    let subscription = reader.subscription();
    subscription.buffer().cells()[subscription.cell()]
        .loan
        .load(Ordering::Acquire)
        == 0
}

/// Registers the highest block boundary read so far, as the sender does
/// on a submission reaching the cursor.
fn sr_sent(reader: &mut SenderRead<&LogBuffer<Terms>>) {
    if let Some(boundary) = reader.boundary_at_or_below(reader.position()) {
        reader.sent(boundary).unwrap();
    }
}

/// Reads at the cursor and checks that the loan was released.
fn sr_read(
    reader: &mut SenderRead<&LogBuffer<Terms>>,
    out: &mut [u8],
) -> Result<ReadOutcome, ReadError> {
    let result = reader.read_committed(reader.position(), ReadOrigin::Cursor, out);
    assert!(sr_loan_released(reader), "loan held after {result:?}");
    result
}

/// The receive side's parameters of the test buffers' stream.
fn sr_params() -> ImageParams {
    ImageParams::new(
        3,
        4,
        1,
        TermLength::try_new(MIN_TERM_LENGTH).unwrap(),
        DEFAULT_MTU,
    )
    .unwrap()
}

/// The payloads of the DATA frames of a datagram, and its record kinds,
/// as the receive side validates them.
fn sr_parse(bytes: &[u8]) -> (Vec<Vec<u8>>, Vec<FrameKind>) {
    let datagram = ValidatedDatagram::parse(bytes, &sr_params()).unwrap();
    let mut payloads = Vec::new();
    let mut kinds = Vec::new();
    for item in datagram.items() {
        let Item::Frame(frame) = item else {
            panic!("a heartbeat in a sender read");
        };
        kinds.push(frame.kind());
        if frame.kind() == FrameKind::Data {
            payloads.push(frame.body()[HEADER_LENGTH as usize - 8..].to_vec());
        }
    }
    (payloads, kinds)
}

/// Small messages are copied whole, several per datagram, at 32-byte
/// strides; the datagram passes the receive side's validation and carries
/// exactly the payloads; the cursor ends at the head.
#[test]
fn sender_read_copies_whole_frames_at_strides() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_reader(&mut conductor);
    let mut publication = buffer.publication().unwrap().unwrap();
    let messages: Vec<Vec<u8>> = (0..3).map(|i| sized_message(i, 100 + i as usize)).collect();
    for message in &messages {
        let _ = publication.append(message, AppendOptions::default()).unwrap();
    }
    let mut out = sr_out();
    let Ok(ReadOutcome::Copied { len, next }) = sr_read(&mut reader, &mut out) else {
        panic!("not copied");
    };
    let (payloads, kinds) = sr_parse(&out[..len]);
    assert_eq!(payloads, messages);
    assert_eq!(kinds, [FrameKind::Data; 3]);
    assert_eq!(next, buffer.reserved_head().load(Ordering::Acquire));
    assert_eq!(reader.position(), next);
    // Nothing more is committed.
    assert_eq!(sr_read(&mut reader, &mut out), Ok(ReadOutcome::Pending));
    // Reading never moves the registered position.
    assert_eq!(reader.sent_position(), 0);
    let counters = reader.counters();
    assert_eq!((counters.reads, counters.read_bytes), (1, len as u64));
}

/// A message of three fragments read into one-frame datagrams: each call
/// copies one frame and the next resumes inside the block; the frames carry
/// the message in order.
#[test]
fn sender_read_resumes_inside_a_block() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_reader(&mut conductor);
    let mut publication = buffer.publication().unwrap().unwrap();
    let message = sized_message(7, 3000);
    let _ = publication.append(&message, AppendOptions::default()).unwrap();
    let mut out = sr_out();
    let mut payload = Vec::new();
    let mut calls = 0;
    while let Ok(ReadOutcome::Copied { len, .. }) = sr_read(&mut reader, &mut out) {
        let (payloads, _) = sr_parse(&out[..len]);
        assert_eq!(payloads.len(), 1, "one fragment per datagram");
        payload.extend_from_slice(&payloads[0]);
        calls += 1;
    }
    assert_eq!(calls, 3);
    assert_eq!(payload, message);
    assert_eq!(reader.position(), buffer.reserved_head().load(Ordering::Acquire));
}

/// A copy that stops at a block boundary, because the next block's first
/// frame does not fit after the previous block's last, leaves the cursor at
/// that block's start: the next call reads its BEGIN frame as a block start
/// (a regression: it was taken for an interior frame).
#[test]
fn sender_read_stops_at_a_block_boundary() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_reader(&mut conductor);
    let mut publication = buffer.publication().unwrap().unwrap();
    // Three fragments each, the last of 280 bytes.
    let messages = [sized_message(1, 3000), sized_message(2, 3000)];
    for message in &messages {
        let _ = publication.append(message, AppendOptions::default()).unwrap();
    }
    let mut out = sr_out();
    let mut payload = Vec::new();
    while let Ok(ReadOutcome::Copied { len, .. }) = sr_read(&mut reader, &mut out) {
        for frame in sr_parse(&out[..len]).0 {
            payload.extend_from_slice(&frame);
        }
    }
    assert_eq!(payload, messages.concat());
    assert_eq!(reader.position(), buffer.reserved_head().load(Ordering::Acquire));
}

/// A frame larger than `out` returns `TooSmall` with the frame's length
/// and moves nothing; a shorter frame after copied ones ends the copy.
#[test]
fn sender_read_reports_a_small_buffer() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_reader(&mut conductor);
    let mut publication = buffer.publication().unwrap().unwrap();
    let _ = publication
        .append(&sized_message(1, 200), AppendOptions::default())
        .unwrap();
    let _ = publication
        .append(&sized_message(2, 200), AppendOptions::default())
        .unwrap();
    let mut small = vec![0u8; 100];
    assert_eq!(
        sr_read(&mut reader, &mut small),
        Err(ReadError::TooSmall { needed: 232 })
    );
    assert_eq!(reader.position(), 0);
    // Room for one frame (stride 256) but not two: one per call.
    let mut one = vec![0u8; 300];
    let Ok(ReadOutcome::Copied { len, next }) = sr_read(&mut reader, &mut one) else {
        panic!("not copied");
    };
    assert_eq!((len, next), (232, 256));
}

/// A PAD at the term end becomes its canonical 32-byte record, alone, and
/// the next read continues in the next term; with `out` under 32 bytes it
/// is `TooSmall`.
#[test]
fn sender_read_turns_padding_into_its_canonical_record() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_reader(&mut conductor);
    let mut publication = buffer.publication().unwrap().unwrap();
    // Each 7000-byte message reserves 7200 bytes: nine fill 64800 of the
    // 65536-byte term, and the tenth pads the last 736.
    let data = sized_message(1, 7000);
    let mut out = sr_out();
    let mut records = Vec::new();
    for _ in 0..10 {
        let _ = append_retrying(&mut publication, &mut conductor, &data, || {});
        // Read and submit everything appended so far.
        loop {
            match sr_read(&mut reader, &mut out) {
                Ok(ReadOutcome::Copied { .. }) => {}
                Ok(ReadOutcome::Canonical { record, next }) => {
                    records.push((record, next));
                    let (_, kinds) = sr_parse(&out[..32]);
                    assert_eq!(kinds, [FrameKind::Pad]);
                    assert_eq!(next, TERM, "the next term starts after the PAD");
                }
                Ok(ReadOutcome::Pending) => break,
                Err(error) => panic!("{error:?} at {}", reader.position()),
            }
        }
        sr_sent(&mut reader);
    }
    assert_eq!(records, [(CanonicalKind::Pad, TERM)]);
    assert_eq!(reader.counters().canonical_records, 1);
    // The tenth message was read in the next term.
    assert_eq!(reader.position(), TERM + 7200);
}

/// `out` shorter than 32 bytes cannot hold a canonical record.
#[test]
fn sender_read_needs_32_bytes_for_a_record() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_reader(&mut conductor);
    let mut publication = buffer.publication().unwrap().unwrap();
    let claim = claimed(publication.try_claim(100, AppendOptions::default()));
    claim.abort();
    let mut tiny = vec![0u8; 31];
    assert_eq!(
        sr_read(&mut reader, &mut tiny),
        Err(ReadError::TooSmall { needed: 32 })
    );
    assert_eq!(reader.position(), 0);
}

/// A claim still being written is `Pending` and nothing is read; once
/// aborted, its block becomes a canonical ABORTED record with its extent,
/// and no byte of the extent is copied.
#[test]
fn sender_read_never_reads_a_live_or_aborted_claim() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_reader(&mut conductor);
    let mut publication = buffer.publication().unwrap().unwrap();
    let mut claim = claimed(publication.try_claim(100, AppendOptions::default()));
    claim.payload().fill(0xAB);
    let mut out = vec![0x11u8; DEFAULT_MTU as usize];
    assert_eq!(sr_read(&mut reader, &mut out), Ok(ReadOutcome::Pending));
    assert!(out.iter().all(|byte| *byte == 0x11), "nothing was written");
    claim.abort();
    assert_eq!(
        sr_read(&mut reader, &mut out),
        Ok(ReadOutcome::Canonical {
            record: CanonicalKind::Aborted,
            next: 160,
        })
    );
    assert!(out[32..].iter().all(|byte| *byte == 0x11), "only the record");
    let datagram = ValidatedDatagram::parse(&out[..32], &sr_params()).unwrap();
    let Some(Item::Frame(frame)) = datagram.items().next() else {
        panic!("no record");
    };
    assert_eq!(
        (frame.kind(), frame.term_offset(), frame.extent()),
        (FrameKind::Aborted, 0, 160)
    );
}

/// Frames with the trace extension are copied whole, extension included.
#[test]
fn sender_read_copies_extensions_whole() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_reader(&mut conductor);
    let mut publication = buffer.publication().unwrap().unwrap();
    let extension = [0x5Au8; 64];
    let options = AppendOptions {
        extension: Some(extension),
        ..AppendOptions::default()
    };
    let message = sized_message(3, 100);
    let _ = publication.append(&message, options).unwrap();
    let mut out = sr_out();
    let Ok(ReadOutcome::Copied { len, .. }) = sr_read(&mut reader, &mut out) else {
        panic!("not copied");
    };
    assert_eq!(len, 96 + 100);
    let word = Word0::unpack(u64::from_le_bytes(out[..8].try_into().unwrap())).unwrap();
    assert!(word.flags().ext());
    assert_eq!(&out[32..96], &extension);
    assert_eq!(&out[96..len], message.as_slice());
}

/// The retention floor: below it is `Unavailable` with the floor, exactly
/// at it reads, and the floor is checked again after the loan.
#[test]
fn sender_read_respects_the_retention_floor() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_reader(&mut conductor);
    let mut publication = buffer.publication().unwrap().unwrap();
    let _ = publication
        .append(&sized_message(1, 100), AppendOptions::default())
        .unwrap();
    let mut out = sr_out();
    buffer.floor().store(32, Ordering::Release);
    assert_eq!(
        sr_read(&mut reader, &mut out),
        Err(ReadError::Unavailable { lowest: 32 })
    );
    buffer.floor().store(0, Ordering::Release);
    assert!(matches!(
        sr_read(&mut reader, &mut out),
        Ok(ReadOutcome::Copied { .. })
    ));
    assert_eq!(reader.counters().unavailable, 1);
}

/// A revoked participant gets `Revoked`, with no loan taken.
#[test]
fn sender_read_is_revoked() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let subscription = conductor.subscribe_as(Role::Required, true, 7).unwrap();
    let cell = subscription.cell();
    let mut reader = SenderRead::new(subscription, DEFAULT_CORRUPT_RETRIES).unwrap();
    let mut publication = buffer.publication().unwrap().unwrap();
    let _ = publication
        .append(&sized_message(1, 100), AppendOptions::default())
        .unwrap();
    assert_ne!(
        conductor
            .revoke_participant(cell, 7, LossPolicy::Continue)
            .unwrap(),
        Revocation::Stale
    );
    let mut out = sr_out();
    assert_eq!(sr_read(&mut reader, &mut out), Err(ReadError::Revoked));
}

/// A position other than the cursor is a sender bug: `Invariant`, nothing
/// read; so is a sent position past the cursor.
#[test]
fn sender_read_refuses_positions_other_than_its_cursor() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_reader(&mut conductor);
    let mut publication = buffer.publication().unwrap().unwrap();
    let _ = publication
        .append(&sized_message(1, 100), AppendOptions::default())
        .unwrap();
    let mut out = sr_out();
    assert_eq!(
        reader.read_committed(32, ReadOrigin::Cursor, &mut out),
        Err(ReadError::Invariant)
    );
    assert!(sr_loan_released(&reader));
    assert_eq!(reader.sent(32), Err(ReadError::Invariant));
    assert_eq!(reader.counters().invariant, 2);
}

/// C-9: a corrupt block at the cursor is retried `corrupt_retries` times,
/// then the reader is faulted for good; it never skips the block.
#[test]
fn sender_read_faults_after_corrupt_retries() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_reader(&mut conductor);
    let mut publication = buffer.publication().unwrap().unwrap();
    let _ = publication
        .append(&sized_message(1, 3000), AppendOptions::default())
        .unwrap();
    // The second fragment's word 0 loses its type: the block is corrupt.
    let frames = frames(&buffer);
    let (offset, word) = frames[1];
    word0_of_term0(&buffer, offset).store(
        Word0::new(word.frame_length(), word.flags(), FrameType::Pad)
            .pack()
            .to_le(),
        Ordering::Relaxed,
    );
    let mut out = sr_out();
    for failures in 1..=DEFAULT_CORRUPT_RETRIES {
        assert_eq!(
            sr_read(&mut reader, &mut out),
            Err(ReadError::CorruptTerm { failures })
        );
    }
    assert_eq!(
        sr_read(&mut reader, &mut out),
        Err(ReadError::Faulted { position: 0 })
    );
    // Faulted for good, even once the word is repaired.
    word0_of_term0(&buffer, offset).store(word.pack().to_le(), Ordering::Relaxed);
    assert_eq!(
        sr_read(&mut reader, &mut out),
        Err(ReadError::Faulted { position: 0 })
    );
    assert_eq!(reader.position(), 0);
}

/// The C-9 count resets once the cursor moves past the block.
#[test]
fn sender_read_corrupt_count_resets_when_the_cursor_advances() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_reader(&mut conductor);
    let mut publication = buffer.publication().unwrap().unwrap();
    let _ = publication
        .append(&sized_message(1, 3000), AppendOptions::default())
        .unwrap();
    let frames = frames(&buffer);
    let (offset, word) = frames[1];
    let corrupt = Word0::new(word.frame_length(), word.flags(), FrameType::Pad)
        .pack()
        .to_le();
    let mut out = sr_out();
    for _ in 0..DEFAULT_CORRUPT_RETRIES {
        word0_of_term0(&buffer, offset).store(corrupt, Ordering::Relaxed);
        assert!(matches!(
            sr_read(&mut reader, &mut out),
            Err(ReadError::CorruptTerm { .. })
        ));
    }
    // Repaired: the block is read and the cursor moves on.
    word0_of_term0(&buffer, offset).store(word.pack().to_le(), Ordering::Relaxed);
    while let Ok(ReadOutcome::Copied { .. }) = sr_read(&mut reader, &mut out) {}
    let _ = publication
        .append(&sized_message(2, 3000), AppendOptions::default())
        .unwrap();
    let start = reader.position();
    let second = start as u32 + 1408;
    let raw = word0_of_term0(&buffer, second).load(Ordering::Relaxed);
    let word = Word0::unpack(u64::from_le(raw)).unwrap();
    word0_of_term0(&buffer, second).store(
        Word0::new(word.frame_length(), word.flags(), FrameType::Pad)
            .pack()
            .to_le(),
        Ordering::Relaxed,
    );
    // A fresh count: the full retries again before the fault.
    for failures in 1..=DEFAULT_CORRUPT_RETRIES {
        assert_eq!(
            sr_read(&mut reader, &mut out),
            Err(ReadError::CorruptTerm { failures })
        );
    }
}

/// On a reliable channel the sender is a required participant: its sent
/// position, not its reads, bounds the publisher.
#[test]
fn sender_read_sent_position_bounds_the_publisher() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_reader(&mut conductor);
    let mut publication = buffer.publication().unwrap().unwrap();
    let data = sized_message(1, 992);
    let mut appended = 0u64;
    let mut out = sr_out();
    // Read everything as it is appended, but never report a send.
    loop {
        match publication.append(&data, AppendOptions::default()).unwrap() {
            AppendOutcome::Appended { .. } => appended += 1,
            AppendOutcome::BackPressured => break,
            AppendOutcome::AdminAction => {
                let _ = conductor.duty_cycle().unwrap();
            }
            other => panic!("{other:?}"),
        }
        while let Ok(ReadOutcome::Copied { .. }) = sr_read(&mut reader, &mut out) {}
        assert!(appended < 1000, "never back pressured");
    }
    // The submission moves the bound.
    sr_sent(&mut reader);
    let _ = conductor.duty_cycle().unwrap();
    assert!(matches!(
        publication.append(&data, AppendOptions::default()).unwrap(),
        AppendOutcome::Appended { .. }
    ));
    assert_eq!(reader.sent_position(), reader.subscription().acknowledged_position());
}

/// Only publication buffers, and only a required participant with its
/// `L_send` reservation: an optional, an observer or an unreserved
/// required cell is refused.
#[test]
fn sender_read_admission_is_checked() {
    for role in [Role::Optional, Role::Observer, Role::Required] {
        let buffer = new_buffer(config(3, 2)).unwrap();
        let mut conductor = buffer.conductor().unwrap();
        let subscription = conductor.subscribe(role).unwrap();
        assert!(matches!(
            SenderRead::new(subscription, DEFAULT_CORRUPT_RETRIES),
            Err(SysError::InvalidPublicationMode { .. })
        ));
    }
}

// Randomized and boundary probes of the coordinator's review of #244.

struct ProbeLcg(u64);
impl ProbeLcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next() % (hi - lo + 1)
    }
}

#[derive(Default)]
struct ProbeSink {
    messages: Vec<Vec<u8>>,
    partial: Option<Vec<u8>>,
    aborted: u32,
    pads: u32,
    datagrams: u32,
}

impl ProbeSink {
    fn datagram(&mut self, bytes: &[u8]) {
        if bytes.len() <= DEFAULT_MTU as usize {
            ValidatedDatagram::parse(bytes, &sr_params()).unwrap();
        }
        self.datagrams += 1;
        let mut offset = 0usize;
        while offset < bytes.len() {
            let raw = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
            let word = Word0::unpack(raw).unwrap();
            assert_eq!(word.frame_type_code(), FrameType::Data.code());
            let flags = word.flags();
            let length = word.frame_length() as usize;
            let payload = &bytes[offset + flags.header_length() as usize..offset + length];
            if flags.begin() {
                assert!(self.partial.is_none(), "BEGIN inside a message");
                self.partial = Some(Vec::new());
            }
            self.partial.as_mut().expect("fragment without BEGIN").extend_from_slice(payload);
            if flags.end() {
                self.messages.push(self.partial.take().unwrap());
            }
            offset += length.div_ceil(32) * 32;
        }
    }
}

fn probe_drain(
    reader: &mut SenderRead<&LogBuffer<Terms>>,
    rng: &mut ProbeLcg,
    sink: &mut ProbeSink,
) {
    loop {
        let size = match rng.range(0, 3) {
            0 => 32,
            1 => rng.range(32, 1500) as usize,
            2 => DEFAULT_MTU as usize,
            _ => rng.range(1400, 9000) as usize,
        };
        let mut out = vec![0u8; size];
        let before = reader.position();
        match sr_read(reader, &mut out) {
            Ok(ReadOutcome::Copied { len, next }) => {
                assert!(next > before);
                assert_eq!((next - 1) / TERM, before / TERM, "crossed a term: {before} -> {next}");
                sink.datagram(&out[..len]);
            }
            Ok(ReadOutcome::Canonical { record, next }) => {
                assert!(sink.partial.is_none(), "record inside a message");
                let (_, kinds) = sr_parse(&out[..32]);
                match record {
                    CanonicalKind::Pad => {
                        assert_eq!(kinds, [FrameKind::Pad]);
                        assert_eq!(next % TERM, 0);
                        sink.pads += 1;
                    }
                    CanonicalKind::Aborted => {
                        assert_eq!(kinds, [FrameKind::Aborted]);
                        sink.aborted += 1;
                    }
                }
            }
            Ok(ReadOutcome::Pending) => break,
            Err(ReadError::TooSmall { needed }) => {
                assert!(needed > size, "TooSmall {needed} with {size}");
            }
            Err(error) => panic!("{error:?} at {before}"),
        }
        sr_sent(reader);
    }
}

fn probe_run(seed: u64, steps: usize) {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_reader(&mut conductor);
    let mut publication = buffer.publication().unwrap().unwrap();
    let mut rng = ProbeLcg(seed);
    let mut sink = ProbeSink::default();
    let mut expected: Vec<Vec<u8>> = Vec::new();
    let mut aborts = 0u32;
    for step in 0..steps {
        let kind = rng.range(0, 9);
        if kind < 7 {
            let len = match rng.range(0, 2) {
                0 => rng.range(1, 200),
                1 => rng.range(1, 1400),
                _ => rng.range(1, 6000),
            } as usize;
            let data = sized_message(step as u32, len.max(4));
            loop {
                match publication.append(&data, AppendOptions::default()).unwrap() {
                    AppendOutcome::Appended { .. } => break,
                    AppendOutcome::BackPressured | AppendOutcome::AdminAction => {
                        probe_drain(&mut reader, &mut rng, &mut sink);
                        let _ = conductor.duty_cycle().unwrap();
                    }
                    other => panic!("{other:?}"),
                }
            }
            expected.push(data);
        } else {
            let len = rng.range(1, 1300) as u32;
            let commit = kind == 9;
            loop {
                match publication.try_claim(len, AppendOptions::default()).unwrap() {
                    ClaimOutcome::Claimed(mut claim) => {
                        let fill = step as u8;
                        claim.payload().fill(fill);
                        if commit {
                            assert!(matches!(claim.commit(), CommitOutcome::Committed { .. }));
                            expected.push(vec![fill; len as usize]);
                        } else {
                            claim.abort();
                            aborts += 1;
                        }
                        break;
                    }
                    ClaimOutcome::BackPressured | ClaimOutcome::AdminAction => {
                        probe_drain(&mut reader, &mut rng, &mut sink);
                        let _ = conductor.duty_cycle().unwrap();
                    }
                    _ => panic!("claim"),
                }
            }
        }
        if rng.range(0, 3) == 0 {
            probe_drain(&mut reader, &mut rng, &mut sink);
        }
        if rng.range(0, 5) == 0 {
            let _ = conductor.duty_cycle().unwrap();
        }
    }
    probe_drain(&mut reader, &mut rng, &mut sink);
    assert!(sink.partial.is_none());
    assert_eq!(sink.messages.len(), expected.len(), "seed {seed}");
    assert!(sink.messages == expected, "seed {seed}: payload mismatch");
    assert_eq!(sink.aborted, aborts, "seed {seed}");
    assert_eq!(reader.position(), buffer.reserved_head().load(Ordering::Acquire));
    assert!(sink.pads > 0 || steps < 50, "seed {seed}: no pad exercised");
}

#[test]
fn sender_read_probe_random_sequences() {
    let seeds: u64 = if cfg!(miri) { 1 } else { 40 };
    let steps = if cfg!(miri) { 30 } else { 400 };
    for seed in 1..=seeds {
        probe_run(seed, steps);
    }
}

/// Messages that fill a term exactly (no PAD): copies end exactly at the
/// term end, with partial copies and fragmented messages.
#[test]
fn sender_read_probe_exact_term_end() {
    for (size, out_len) in [(992usize, 4096usize), (992, 1100), (992, 32 * 40), (4000, 1408), (4000, 3000), (4000, 2816)] {
        let buffer = new_buffer(config(3, 2)).unwrap();
        let mut conductor = buffer.conductor().unwrap();
        let mut reader = sr_reader(&mut conductor);
        let mut publication = buffer.publication().unwrap().unwrap();
        let mut sink = ProbeSink::default();
        let mut expected = Vec::new();
        let mut i = 0u32;
        let mut ends = Vec::new();
        while buffer.reserved_head().load(Ordering::Acquire) < TERM + 4096 {
            let data = sized_message(i, size);
            i += 1;
            let _ = append_retrying(&mut publication, &mut conductor, &data, || {});
            expected.push(data);
            loop {
                let mut out = vec![0u8; out_len];
                match sr_read(&mut reader, &mut out) {
                    Ok(ReadOutcome::Copied { len, next }) => {
                        ends.push(next);
                        sink.datagram(&out[..len]);
                    }
                    Ok(ReadOutcome::Pending) => break,
                    other => panic!("{other:?} size {size}"),
                }
                sr_sent(&mut reader);
            }
        }
        assert!(ends.contains(&TERM), "size {size} out {out_len}: no copy ended at the term end");
        assert_eq!(sink.messages, expected);
    }
}

/// Concurrent publication: random offers, required sender read.
#[test]
fn sender_read_probe_concurrent() {
    let buffer = new_buffer(concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_reader(&mut conductor);
    let mut handles: Vec<_> = (0..2)
        .map(|_| conductor.concurrent_publication().unwrap().unwrap())
        .collect();
    let mut rng = ProbeLcg(77);
    let mut sink = ProbeSink::default();
    let mut expected = Vec::new();
    let total = if cfg!(miri) { 30 } else { 600 };
    for sequence in 0..total {
        let len = rng.range(4, 5000) as usize;
        let data = sized_message(sequence, len);
        let handle = &mut handles[(sequence % 2) as usize];
        let mut tries = 0;
        loop {
            tries += 1;
            assert!(tries < 1000);
            match handle.offer(&data, AppendOptions::default()).unwrap() {
                ConcurrentOfferOutcome::Appended { .. } => break,
                ConcurrentOfferOutcome::BackPressured | ConcurrentOfferOutcome::AdminAction => {
                    probe_drain(&mut reader, &mut rng, &mut sink);
                    let _ = conductor.duty_cycle().unwrap();
                }
                other => panic!("{other:?}"),
            }
        }
        expected.push(data);
        if rng.range(0, 2) == 0 {
            probe_drain(&mut reader, &mut rng, &mut sink);
        }
    }
    for _ in 0..10 {
        probe_drain(&mut reader, &mut rng, &mut sink);
        let _ = conductor.duty_cycle().unwrap();
    }
    assert_eq!(sink.messages.len(), expected.len());
    assert!(sink.messages == expected);
    assert!(sink.pads > 0);
}

/// A zero-payload DATA frame (written by a faulty peer) is `CorruptTerm`
/// under C-9: it would leave as a heartbeat.
#[test]
fn sender_read_refuses_a_zero_payload_frame() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_reader(&mut conductor);
    let mut publication = buffer.publication().unwrap().unwrap();
    let _ = publication
        .append(&sized_message(1, 100), AppendOptions::default())
        .unwrap();
    let frames = frames(&buffer);
    let (offset, word) = frames[0];
    word0_of_term0(&buffer, offset).store(
        Word0::new(32, word.flags(), FrameType::Data).pack().to_le(),
        Ordering::Relaxed,
    );
    let mut out = sr_out();
    assert_eq!(
        sr_read(&mut reader, &mut out),
        Err(ReadError::CorruptTerm { failures: 1 })
    );
    assert_eq!(reader.position(), 0);
}

/// An interior word 0 that changes between its two loads (a peer storing
/// while the frame is copied) is `CorruptTerm`: the copy is not sent.
#[test]
fn sender_read_rechecks_an_interior_word0_after_the_copy() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_reader(&mut conductor);
    let mut publication = buffer.publication().unwrap().unwrap();
    let _ = publication
        .append(&sized_message(1, 3000), AppendOptions::default())
        .unwrap();
    let frames = frames(&buffer);
    let mut out = sr_out();
    // The first fragment, alone in its datagram.
    assert!(matches!(
        sr_read(&mut reader, &mut out),
        Ok(ReadOutcome::Copied { .. })
    ));
    let (offset, word) = frames[1];
    let changed = Word0::new(word.frame_length() - 1, word.flags(), FrameType::Data).pack();
    reader.inject(super::sender_read::TestHook::Word0BetweenLoads {
        offset,
        raw: changed,
    });
    assert_eq!(
        sr_read(&mut reader, &mut out),
        Err(ReadError::CorruptTerm { failures: 1 })
    );
    assert_eq!(reader.position(), u64::from(offset));
}

/// The floor raised between the first check and the loan (a pause): the
/// check after the loan refuses, releasing the loan; one frame above the
/// floor reads.
#[test]
fn sender_read_rechecks_the_floor_after_the_loan() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_reader(&mut conductor);
    let mut publication = buffer.publication().unwrap().unwrap();
    for i in 0..2 {
        let _ = publication
            .append(&sized_message(i, 100), AppendOptions::default())
            .unwrap();
    }
    let mut out = vec![0u8; 200];
    reader.inject(super::sender_read::TestHook::FloorBeforeLoan(32));
    assert_eq!(
        sr_read(&mut reader, &mut out),
        Err(ReadError::Unavailable { lowest: 32 })
    );
    buffer.floor().store(0, Ordering::Release);
    let Ok(ReadOutcome::Copied { next, .. }) = sr_read(&mut reader, &mut out) else {
        panic!("not copied");
    };
    // One frame above the floor: the next read is served.
    buffer.floor().store(next - 32, Ordering::Release);
    assert!(matches!(
        sr_read(&mut reader, &mut out),
        Ok(ReadOutcome::Copied { .. })
    ));
}

/// The descriptor changing before the loan: a term not active yet is
/// `Retry`, a term reclaimed (`Overrun`) is `Unavailable`; both release the
/// loan word and move nothing.
#[test]
fn sender_read_retries_and_refuses_at_the_loan() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_reader(&mut conductor);
    let mut publication = buffer.publication().unwrap().unwrap();
    let _ = publication
        .append(&sized_message(1, 100), AppendOptions::default())
        .unwrap();
    let active = Descriptor::decode(buffer.descriptor(0).unwrap().load(Ordering::Acquire)).unwrap();
    let mut out = sr_out();
    reader.inject(super::sender_read::TestHook::DescriptorBeforeLoan(
        active.with_state(SlotState::Ready).encode(),
    ));
    assert_eq!(sr_read(&mut reader, &mut out), Err(ReadError::Retry));
    let later = Descriptor::new(
        active.term_id().advanced_by(TermCount::try_new(3).unwrap()),
        active.generation(),
        SlotState::Active,
    );
    reader.inject(super::sender_read::TestHook::DescriptorBeforeLoan(
        later.encode(),
    ));
    assert!(matches!(
        sr_read(&mut reader, &mut out),
        Err(ReadError::Unavailable { .. })
    ));
    buffer
        .descriptor(0)
        .unwrap()
        .store(active.encode(), Ordering::Release);
    assert!(matches!(
        sr_read(&mut reader, &mut out),
        Ok(ReadOutcome::Copied { .. })
    ));
    assert_eq!(reader.counters().retry, 1);
}

fn probe_to_end(reader: &mut SenderRead<&LogBuffer<Terms>>) -> Vec<Result<ReadOutcome, ReadError>> {
    let mut seen = Vec::new();
    for _ in 0..1000 {
        let mut out = sr_out();
        let r = sr_read(reader, &mut out);
        seen.push(r);
        if !matches!(r, Ok(ReadOutcome::Copied { .. } | ReadOutcome::Canonical { .. })) {
            break;
        }
        sr_sent(reader);
    }
    seen
}

#[test]
fn sender_read_probe_seal_exclusive_claim_in_hand() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_reader(&mut conductor);
    let mut publication = buffer.publication().unwrap().unwrap();
    let mut claim = claimed(publication.try_claim(64, AppendOptions::default()));
    claim.payload().fill(7);
    conductor.seal().unwrap();
    let _ = conductor.duty_cycle().unwrap();
    assert_eq!(probe_to_end(&mut reader).last(), Some(&Ok(ReadOutcome::Pending)));
    assert!(matches!(claim.commit(), CommitOutcome::Committed { .. }));
    let _ = conductor.duty_cycle().unwrap();
    let _ = publication.append(&message(1), AppendOptions::default()).unwrap();
    let _ = conductor.duty_cycle().unwrap();
    let seen = probe_to_end(&mut reader);
    assert_eq!(seen.last(), Some(&Ok(ReadOutcome::Pending)), "{seen:?}");
    assert_eq!(reader.seal_position(), Some(96));
    assert_eq!(reader.position(), 96);
}

#[test]
fn sender_read_probe_seal_concurrent_after_crossing() {
    let buffer = new_buffer(concurrent_config(2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_reader(&mut conductor);
    let mut handle = conductor.concurrent_publication().unwrap().unwrap();
    let data = sized_message(1, 3000);
    loop {
        match handle.offer(&data, AppendOptions::default()).unwrap() {
            ConcurrentOfferOutcome::Appended { .. } => {}
            ConcurrentOfferOutcome::AdminAction => break,
            ConcurrentOfferOutcome::BackPressured => {}
            other => panic!("unexpected {other:?}"),
        }
        let _ = probe_to_end(&mut reader);
        let _ = conductor.duty_cycle().unwrap();
    }
    conductor.seal().unwrap();
    let _ = conductor.duty_cycle().unwrap();
    let seen = probe_to_end(&mut reader);
    assert_eq!(seen.last(), Some(&Ok(ReadOutcome::Pending)), "{seen:?}");
    assert_eq!(reader.seal_position(), Some(TERM));
    assert_eq!(reader.position(), TERM);
}

/// S2 2.7 under threads: the real reader on one thread, the publisher and
/// its conductor (rotation, reclamation, floor) on another, every message
/// reassembled in order from the copied datagrams, with every read's loan
/// released. Under Miri, any read of a term the conductor recycles races.
#[test]
fn sender_read_runs_beside_a_publisher_and_its_conductor() {
    use core::sync::atomic::AtomicBool;

    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_reader(&mut conductor);
    let mut publication = buffer.publication().unwrap().unwrap();
    let total: u32 = if cfg!(miri) { 40 } else { 2000 };
    let expected: Vec<Vec<u8>> = (0..total)
        .map(|i| sized_message(i, 24 + (i as usize * 523) % 3000))
        .collect();
    let done = AtomicBool::new(false);
    let mut sink = ProbeSink::default();
    std::thread::scope(|scope| {
        let messages = &expected;
        let done = &done;
        scope.spawn(move || {
            for message in messages {
                loop {
                    match publication.append(message, AppendOptions::default()).unwrap() {
                        AppendOutcome::Appended { .. } => break,
                        AppendOutcome::BackPressured | AppendOutcome::AdminAction => {
                            let _ = conductor.duty_cycle().unwrap();
                            std::thread::yield_now();
                        }
                        other => panic!("{other:?}"),
                    }
                }
            }
            while !done.load(Ordering::Acquire) {
                let _ = conductor.duty_cycle().unwrap();
                std::thread::yield_now();
            }
        });
        let mut out = sr_out();
        let mut spins = 0u64;
        while sink.messages.len() < messages.len() {
            match sr_read(&mut reader, &mut out) {
                Ok(ReadOutcome::Copied { len, .. }) => sink.datagram(&out[..len]),
                Ok(ReadOutcome::Canonical { record, .. }) => {
                    assert_eq!(record, CanonicalKind::Pad);
                    sink.pads += 1;
                }
                Ok(ReadOutcome::Pending) | Err(ReadError::Retry) => {
                    spins += 1;
                    assert!(spins < 50_000_000, "no progress");
                    std::thread::yield_now();
                }
                Err(error) => panic!("{error:?} at {}", reader.position()),
            }
            sr_sent(&mut reader);
        }
        done.store(true, Ordering::Release);
    });
    assert_eq!(sink.messages, expected);
}

/// NAK reads under threads (S2 2.3): the reader registers with a lag, and
/// NAK-reads recent datagram starts while the publisher and its conductor
/// rotate, reclaim and move the floor. A NAK copy is byte-identical to the
/// cursor's copy from the same start, or refused only as `Unavailable`
/// (the floor passed it) or `Retry`; never a torn or foreign copy. Under
/// Miri, any read of a recycled term races.
#[test]
fn sender_read_nak_runs_beside_a_publisher_and_its_conductor() {
    use core::sync::atomic::AtomicBool;

    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_nak_reader(&mut conductor, MIN_NAK_CHECKPOINT_STRIDE);
    let mut publication = buffer.publication().unwrap().unwrap();
    let total: u32 = if cfg!(miri) { 40 } else { 2000 };
    let expected: Vec<Vec<u8>> = (0..total)
        .map(|i| sized_message(i, 24 + (i as usize * 523) % 3000))
        .collect();
    let done = AtomicBool::new(false);
    let mut sink = ProbeSink::default();
    let mut copies = 0u32;
    std::thread::scope(|scope| {
        let messages = &expected;
        let done = &done;
        scope.spawn(move || {
            for message in messages {
                loop {
                    match publication.append(message, AppendOptions::default()).unwrap() {
                        AppendOutcome::Appended { .. } => break,
                        AppendOutcome::BackPressured | AppendOutcome::AdminAction => {
                            // The reader stopped (a failed check): stop too.
                            if done.load(Ordering::Acquire) {
                                return;
                            }
                            let _ = conductor.duty_cycle().unwrap();
                            std::thread::yield_now();
                        }
                        other => panic!("{other:?}"),
                    }
                }
            }
            while !done.load(Ordering::Acquire) {
                let _ = conductor.duty_cycle().unwrap();
                std::thread::yield_now();
            }
        });
        // Ends the publisher's loop on a reader panic too.
        struct Done<'a>(&'a AtomicBool);
        impl Drop for Done<'_> {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let _done = Done(done);
        let mut out = sr_out();
        let mut nak_out = sr_out();
        let mut recent: VecDeque<(u64, Vec<u8>)> = VecDeque::new();
        let mut spins = 0u64;
        while sink.messages.len() < messages.len() {
            let from = reader.position();
            match sr_read(&mut reader, &mut out) {
                Ok(ReadOutcome::Copied { len, .. }) => {
                    sink.datagram(&out[..len]);
                    if recent.len() == 16 {
                        recent.pop_front();
                    }
                    recent.push_back((from, out[..len].to_vec()));
                }
                Ok(ReadOutcome::Canonical { .. }) => sink.pads += 1,
                Ok(ReadOutcome::Pending) | Err(ReadError::Retry) => {
                    spins += 1;
                    assert!(
                        spins < 200_000,
                        "no progress: position {} sent {} messages {}",
                        reader.position(),
                        reader.sent_position(),
                        sink.messages.len()
                    );
                    std::thread::yield_now();
                }
                Err(error) => panic!("{error:?} at {}", reader.position()),
            }
            // A NAK of a recent start.
            if let Some((start, bytes)) = recent.get(spins as usize % recent.len().max(1)) {
                let bound = reader.position();
                let (result, _) = sr_nak(&mut reader, *start, bound, u32::MAX, &mut nak_out);
                match result {
                    // The cursor copied what was committed then; a NAK
                    // later may copy more whole frames from the same start,
                    // never different bytes.
                    Ok(ReadOutcome::Copied { len, .. }) => {
                        assert!(len >= bytes.len(), "NAK copy at {start}: {len} < {}", bytes.len());
                        assert_eq!(&nak_out[..bytes.len()], &bytes[..], "NAK copy at {start}");
                        copies += 1;
                    }
                    Err(ReadError::Unavailable { .. } | ReadError::Retry) => {}
                    other => panic!("{other:?} for a NAK at {start}"),
                }
            }
            // Register with a lag, so recent starts stay retained.
            // Well inside the publisher's window (`max_reserved`, 8 KiB).
            let lagged = reader.position().saturating_sub(2 * 1024);
            if let Some(boundary) = reader.boundary_at_or_below(lagged) {
                reader.sent(boundary).unwrap();
            }
        }
        done.store(true, Ordering::Release);
    });
    assert_eq!(sink.messages, expected);
    assert!(copies > 0, "no NAK copy was checked");
}

/// `rewind` restarts at the registered position, a block boundary the
/// caller registered: what was read past it is read again, whole.
#[test]
fn sender_read_rewinds_to_the_registered_boundary() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_reader(&mut conductor);
    let mut publication = buffer.publication().unwrap().unwrap();
    let messages = [sized_message(1, 3000), sized_message(2, 3000)];
    for message in &messages {
        let _ = publication.append(message, AppendOptions::default()).unwrap();
    }
    let mut out = sr_out();
    // The first message, three one-frame datagrams: a boundary at its end.
    let mut first = ProbeSink::default();
    for _ in 0..3 {
        let Ok(ReadOutcome::Copied { len, .. }) = sr_read(&mut reader, &mut out) else {
            panic!("not copied");
        };
        first.datagram(&out[..len]);
    }
    assert!(reader.at_boundary());
    sr_sent(&mut reader);
    // Part of the second, inside its block, then a reset drops it.
    let _ = sr_read(&mut reader, &mut out).unwrap();
    assert!(!reader.at_boundary());
    reader.rewind().unwrap();
    assert_eq!(reader.position(), reader.sent_position());
    let mut second = ProbeSink::default();
    while let Ok(ReadOutcome::Copied { len, .. }) = sr_read(&mut reader, &mut out) {
        second.datagram(&out[..len]);
    }
    assert_eq!(first.messages, [messages[0].clone()]);
    assert_eq!(second.messages, [messages[1].clone()]);
}

/// The #263 review probe: a forged DATA word 0 inside a payload is never a
/// restart. `sent` refuses a position that is not a block boundary the
/// reader returned, so `rewind` restarts only at a real block start, and
/// the application bytes are never sent as a frame.
#[test]
fn sender_read_never_restarts_inside_a_payload() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_reader(&mut conductor);
    let mut publication = buffer.publication().unwrap().unwrap();
    // A 200-byte payload holding, at payload byte 32 (term offset 64), a
    // plausible DATA word 0 of BEGIN|END and length 64.
    let mut message = sized_message(1, 200);
    let forged = Word0::new(64, Flags::new(true, true, false, false, Lane::ZERO), FrameType::Data);
    message[32..40].copy_from_slice(&forged.pack().to_le_bytes());
    let _ = publication.append(&message, AppendOptions::default()).unwrap();
    let mut out = sr_out();
    let Ok(ReadOutcome::Copied { next, .. }) = sr_read(&mut reader, &mut out) else {
        panic!("not copied");
    };
    assert_eq!(next, 256);
    // 64 is on the 32-byte grid but no boundary: refused, nothing moves.
    assert_eq!(reader.sent(64), Err(ReadError::Invariant));
    assert_eq!(reader.sent_position(), 0);
    reader.rewind().unwrap();
    // The restart is the real block start: the whole message again.
    let mut sink = ProbeSink::default();
    let Ok(ReadOutcome::Copied { len, next }) = sr_read(&mut reader, &mut out) else {
        panic!("not copied");
    };
    sink.datagram(&out[..len]);
    assert_eq!((next, sink.messages), (256, vec![message]));
}

/// `rewind` keeps the C-9 count: rewinding onto a corrupt block does not
/// restore its retries, and a faulted reader refuses to rewind.
#[test]
fn sender_read_rewind_keeps_the_corrupt_count() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_reader(&mut conductor);
    let mut publication = buffer.publication().unwrap().unwrap();
    let _ = publication
        .append(&sized_message(1, 3000), AppendOptions::default())
        .unwrap();
    let (offset, word) = frames(&buffer)[1];
    word0_of_term0(&buffer, offset).store(
        Word0::new(word.frame_length(), word.flags(), FrameType::Pad)
            .pack()
            .to_le(),
        Ordering::Relaxed,
    );
    let mut out = sr_out();
    for failures in 1..=DEFAULT_CORRUPT_RETRIES {
        assert_eq!(
            sr_read(&mut reader, &mut out),
            Err(ReadError::CorruptTerm { failures })
        );
        reader.rewind().unwrap();
    }
    assert_eq!(
        sr_read(&mut reader, &mut out),
        Err(ReadError::Faulted { position: 0 })
    );
    assert_eq!(reader.rewind(), Err(ReadError::Faulted { position: 0 }));
}

/// A reliable lane read far ahead of its registered position (one window
/// of the smallest frames is more than the boundary ring holds): the ring
/// is thinned, never emptied below a position, so the registered position
/// keeps advancing in small steps as consumption advances, up to the
/// cursor.
#[test]
fn sender_read_keeps_registering_far_ahead() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_reader(&mut conductor);
    let mut publication = buffer.publication().unwrap().unwrap();
    // One-byte messages: 64-byte frames, until the window presses back.
    let mut appended = 0u32;
    while let AppendOutcome::Appended { .. } = publication
        .append(&[7u8], AppendOptions::default())
        .unwrap()
    {
        appended += 1;
    }
    assert!(appended > 300, "{appended} frames: fewer than the ring holds");
    // Read all of it in small datagrams, registering nothing.
    let mut out = vec![0u8; 64];
    while let Ok(ReadOutcome::Copied { .. }) = sr_read(&mut reader, &mut out) {}
    let cursor = reader.position();
    assert_eq!(cursor, u64::from(appended) * 64);
    // Consumption advances one frame at a time: the registered position
    // follows within a few frames and reaches the cursor.
    let mut lag_max = 0u64;
    for consumed in (64..=cursor).step_by(64) {
        if let Some(boundary) = reader.boundary_at_or_below(consumed) {
            reader.sent(boundary).unwrap();
        }
        lag_max = lag_max.max(consumed - reader.sent_position());
    }
    assert_eq!(reader.sent_position(), cursor);
    assert!(lag_max <= 4 * 64, "registered lag reached {lag_max} bytes");
}

// NAK reads (S2 2.3; ACS 15762, 15763).

/// A reader with NAK checkpoints every `stride` bytes.
fn sr_nak_reader<'a>(
    conductor: &mut Conductor<&'a LogBuffer<Terms>>,
    stride: u32,
) -> SenderRead<&'a LogBuffer<Terms>> {
    SenderRead::with_nak_stride(
        conductor.subscribe_as(Role::Required, true, 1).unwrap(),
        DEFAULT_CORRUPT_RETRIES,
        stride,
    )
    .unwrap()
}

/// A NAK read at `from`; checks that the loan was released and that
/// nothing of the cursor path moved.
fn sr_nak(
    reader: &mut SenderRead<&LogBuffer<Terms>>,
    from: u64,
    bound: u64,
    loads: u32,
    out: &mut [u8],
) -> (Result<ReadOutcome, ReadError>, u32) {
    let before = (
        reader.position(),
        reader.sent_position(),
        reader.at_boundary(),
        reader.boundary_at_or_below(u64::MAX),
    );
    let result = reader.read_nak(from, NakRead { bound, loads }, out);
    assert!(sr_loan_released(reader), "loan held after {result:?}");
    let after = (
        reader.position(),
        reader.sent_position(),
        reader.at_boundary(),
        reader.boundary_at_or_below(u64::MAX),
    );
    assert_eq!(before, after, "a NAK read moved the cursor path");
    result
}

/// Reads the whole log at the cursor, and returns every frame start
/// (fragments, PAD and ABORTED records included) with its bytes as sent.
fn sr_walk(reader: &mut SenderRead<&LogBuffer<Terms>>) -> BTreeMap<u64, Vec<u8>> {
    let mut frames = BTreeMap::new();
    let mut out = sr_out();
    loop {
        let from = reader.position();
        match sr_read(reader, &mut out) {
            Ok(ReadOutcome::Copied { len, .. }) => {
                let mut offset = 0usize;
                while offset < len {
                    let raw = u64::from_le_bytes(out[offset..offset + 8].try_into().unwrap());
                    let length = Word0::unpack(raw).unwrap().frame_length() as usize;
                    let reserved = length.div_ceil(32) * 32;
                    frames.insert(from + offset as u64, out[offset..offset + length].to_vec());
                    offset += reserved;
                }
            }
            Ok(ReadOutcome::Canonical { .. }) => {
                frames.insert(from, out[..32].to_vec());
            }
            Ok(ReadOutcome::Pending) => return frames,
            Err(error) => panic!("{error:?} at {from}"),
        }
    }
}

/// The reference check: every 32-byte position below the head is either a
/// frame start, which a NAK reads byte-identical to the cursor's copy,
/// or `BadRequest`.
fn sr_nak_matches_walker(sizes: &[usize], abort: Option<usize>, stride: u32) {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_nak_reader(&mut conductor, stride);
    let mut publication = buffer.publication().unwrap().unwrap();
    for (i, size) in sizes.iter().enumerate() {
        if abort == Some(i) {
            // An aborted claim of at most 1000 bytes; past the window
            // (back pressure) nothing is claimed, as appends there are
            // refused too: the walk reads whatever the log holds.
            let claim = (*size).min(1000) as u32;
            if let Ok(ClaimOutcome::Claimed(claim)) =
                publication.try_claim(claim, AppendOptions::default())
            {
                claim.abort();
            }
        } else {
            let _ = publication
                .append(&sized_message(i as u32, *size), AppendOptions::default())
                .unwrap();
        }
    }
    let frames = sr_walk(&mut reader);
    let head = reader.position();
    let mut out = sr_out();
    let mut position = 0;
    while position < head {
        let (result, loads) = sr_nak(&mut reader, position, head, u32::MAX, &mut out);
        match frames.get(&position) {
            Some(bytes) => {
                let len = match result {
                    Ok(ReadOutcome::Copied { len, .. }) => len,
                    Ok(ReadOutcome::Canonical { .. }) => 32,
                    other => panic!("{other:?} at the frame start {position}"),
                };
                assert!(len >= bytes.len());
                assert_eq!(&out[..bytes.len()], &bytes[..], "frame at {position}");
            }
            None => assert_eq!(result, Err(ReadError::BadRequest), "at {position}"),
        }
        // From the checkpoint of its own stride, recorded when a frame
        // starts in the stride or later in the term, a scan stays within
        // one stride.
        let stride_start = position - position % u64::from(stride);
        let term_end = (position / TERM + 1) * TERM;
        if frames.range(stride_start..term_end).next().is_some() {
            assert!(loads <= stride / 32 + 1, "{loads} loads at {position}");
        }
        position += 32;
    }
}

/// The reference check on a mix of one-frame, fragmented and aborted
/// messages, with checkpoints every 4 KiB (deterministic; Miri runs it).
#[test]
fn sender_read_nak_matches_the_walk() {
    let sizes = [100, 3000, 40, 9000, 64, 4, 2500, 700, 5000, 33];
    sr_nak_matches_walker(&sizes, Some(3), MIN_NAK_CHECKPOINT_STRIDE);
}

proptest::proptest! {
    // Under Miri: one case and no failure file (isolation forbids it).
    #![proptest_config(proptest::prelude::ProptestConfig {
        cases: if cfg!(miri) { 1 } else { 24 },
        ..crate::receive::tests_config()
    })]

    /// The reference check on random logs.
    #[test]
    fn sender_read_nak_matches_the_walk_on_random_logs(
        sizes in proptest::collection::vec(4usize..6000, 1..16),
        abort in proptest::option::of(0usize..16),
    ) {
        sr_nak_matches_walker(&sizes, abort, MIN_NAK_CHECKPOINT_STRIDE);
    }
}

/// At or above the bound, past the head, unaligned: `BadRequest`; below
/// the floor: `Unavailable` with the floor.
#[test]
fn sender_read_nak_refuses_out_of_range_positions() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_reader(&mut conductor);
    let mut publication = buffer.publication().unwrap().unwrap();
    for i in 0..4 {
        let _ = publication
            .append(&sized_message(i, 100), AppendOptions::default())
            .unwrap();
    }
    let frames = sr_walk(&mut reader);
    let head = reader.position();
    let mut out = sr_out();
    let second = *frames.keys().nth(1).unwrap();
    assert_eq!(sr_nak(&mut reader, second, second, 99, &mut out).0, Err(ReadError::BadRequest));
    assert_eq!(sr_nak(&mut reader, head, u64::MAX, 99, &mut out).0, Err(ReadError::BadRequest));
    assert_eq!(sr_nak(&mut reader, second + 8, head, 99, &mut out).0, Err(ReadError::BadRequest));
    buffer.floor().store(second, Ordering::Release);
    assert_eq!(
        sr_nak(&mut reader, 0, head, 99, &mut out).0,
        Err(ReadError::Unavailable { lowest: second })
    );
    let counters = reader.counters();
    assert_eq!((counters.nak_bad_request, counters.unavailable), (3, 1));
}

/// The NAK twin of the forged-header probe: a plausible word 0 inside a
/// payload is never landed on.
#[test]
fn sender_read_nak_never_lands_inside_a_payload() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_reader(&mut conductor);
    let mut publication = buffer.publication().unwrap().unwrap();
    let mut message = sized_message(1, 200);
    let forged = Word0::new(64, Flags::new(true, true, false, false, Lane::ZERO), FrameType::Data);
    message[32..40].copy_from_slice(&forged.pack().to_le_bytes());
    let _ = publication.append(&message, AppendOptions::default()).unwrap();
    let _ = sr_walk(&mut reader);
    let mut out = sr_out();
    assert_eq!(sr_nak(&mut reader, 64, 256, 99, &mut out).0, Err(ReadError::BadRequest));
    let (result, _) = sr_nak(&mut reader, 0, 256, 99, &mut out);
    let Ok(ReadOutcome::Copied { len, next }) = result else {
        panic!("{result:?}");
    };
    let mut sink = ProbeSink::default();
    sink.datagram(&out[..len]);
    assert_eq!((next, sink.messages), (256, vec![message]));
}

/// A checkpoint array tagged with another term count is never used, even
/// with an entry pointing inside a payload: the scan starts at the term
/// start and still refuses.
#[test]
fn sender_read_nak_ignores_another_terms_checkpoints() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_nak_reader(&mut conductor, MIN_NAK_CHECKPOINT_STRIDE);
    let mut publication = buffer.publication().unwrap().unwrap();
    // A message spanning the first stride, with a forged word 0 in its
    // payload just past the stride.
    let mut message = sized_message(1, 6000);
    let at = 4096 + 64 - 32;
    let forged = Word0::new(64, Flags::new(true, true, false, false, Lane::ZERO), FrameType::Data);
    message[at..at + 8].copy_from_slice(&forged.pack().to_le_bytes());
    let _ = publication.append(&message, AppendOptions::default()).unwrap();
    let frames = sr_walk(&mut reader);
    let head = reader.position();
    let zero = TermCount::try_new(0).unwrap();
    let foreign = TermCount::try_new(3).unwrap();
    // The array of count 0's slot, retagged for count 3, entry 1 aimed at
    // the forged word 0 (term offset 4096 + 64).
    reader.plant_checkpoint(zero, foreign, 1, (4096 + 64, 0, true));
    let mut out = sr_out();
    let (result, loads) = sr_nak(&mut reader, 4096 + 64, head, u32::MAX, &mut out);
    if frames.contains_key(&(4096 + 64)) {
        assert!(matches!(result, Ok(ReadOutcome::Copied { .. })));
    } else {
        assert_eq!(result, Err(ReadError::BadRequest));
    }
    assert!(loads > 1, "the walk started at the term start");
}

/// A scan beyond its load budget is `Budget`, counted, and spends no more
/// than the budget.
#[test]
fn sender_read_nak_keeps_to_its_budget() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_reader(&mut conductor);
    let mut publication = buffer.publication().unwrap().unwrap();
    for i in 0..40 {
        let _ = publication
            .append(&sized_message(i, 50), AppendOptions::default())
            .unwrap();
    }
    let frames = sr_walk(&mut reader);
    let head = reader.position();
    let last = *frames.keys().last().unwrap();
    let mut out = sr_out();
    let (result, loads) = sr_nak(&mut reader, last, head, 5, &mut out);
    assert_eq!(result, Err(ReadError::Budget));
    assert!(loads <= 5);
    assert_eq!(reader.counters().nak_budget, 1);
    let (result, _) = sr_nak(&mut reader, last, head, u32::MAX, &mut out);
    assert!(matches!(result, Ok(ReadOutcome::Copied { .. })));
}

/// A corrupt word 0 met by a NAK scan is counted as a NAK corruption and
/// never faults the reader (C-9 belongs to the cursor).
#[test]
fn sender_read_nak_corruption_never_faults() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_reader(&mut conductor);
    let mut publication = buffer.publication().unwrap().unwrap();
    for i in 0..3 {
        let _ = publication
            .append(&sized_message(i, 100), AppendOptions::default())
            .unwrap();
    }
    let frames = sr_walk(&mut reader);
    let head = reader.position();
    let second = *frames.keys().nth(1).unwrap();
    let third = *frames.keys().nth(2).unwrap();
    // Break the second frame's type after the cursor read it: the walk to
    // the third loads it (the first is passed by its recorded end).
    let bad = Word0::new(132, Flags::new(true, true, false, false, Lane::ZERO), FrameType::Pad);
    word0_of_term0(&buffer, second as u32).store(bad.pack().to_le(), Ordering::Relaxed);
    let mut out = sr_out();
    for _ in 0..(DEFAULT_CORRUPT_RETRIES + 2) {
        let (result, _) = sr_nak(&mut reader, third, head, 99, &mut out);
        assert!(matches!(result, Err(ReadError::CorruptTerm { .. })), "{result:?}");
    }
    assert_eq!(reader.counters().nak_corrupt, u64::from(DEFAULT_CORRUPT_RETRIES) + 2);
    // The cursor path is not faulted.
    assert_eq!(sr_read(&mut reader, &mut out), Ok(ReadOutcome::Pending));
}

/// An ABORTED block is read as its canonical record.
#[test]
fn sender_read_nak_reads_an_aborted_record() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_reader(&mut conductor);
    let mut publication = buffer.publication().unwrap().unwrap();
    claimed(publication.try_claim(100, AppendOptions::default())).abort();
    let _ = publication
        .append(&sized_message(1, 100), AppendOptions::default())
        .unwrap();
    let frames = sr_walk(&mut reader);
    let head = reader.position();
    let mut out = sr_out();
    assert_eq!(
        sr_nak(&mut reader, 0, head, u32::MAX, &mut out).0,
        Ok(ReadOutcome::Canonical {
            record: CanonicalKind::Aborted,
            next: 160,
        })
    );
    assert_eq!(&out[..32], &frames[&0][..]);
}

/// A PAD block is read as its canonical record, ending at the term end.
#[test]
fn sender_read_nak_reads_a_pad_record() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_reader(&mut conductor);
    let mut publication = buffer.publication().unwrap().unwrap();
    // Nine 7000-byte messages reserve 64800 bytes; the tenth pads the rest.
    let pad = 9 * 7200;
    let data = sized_message(1, 7000);
    let mut out = sr_out();
    for _ in 0..10 {
        let _ = append_retrying(&mut publication, &mut conductor, &data, || {});
        while let Ok(ReadOutcome::Copied { .. } | ReadOutcome::Canonical { .. }) =
            sr_read(&mut reader, &mut out)
        {}
        // Registered no further than the PAD: it stays retained.
        if let Some(boundary) = reader.boundary_at_or_below(reader.position().min(pad)) {
            reader.sent(boundary).unwrap();
        }
    }
    let head = reader.position();
    assert_eq!(
        sr_nak(&mut reader, pad, head, u32::MAX, &mut out).0,
        Ok(ReadOutcome::Canonical {
            record: CanonicalKind::Pad,
            next: TERM,
        })
    );
}

/// A NAK inside a large block that starts at its stride's checkpoint walks
/// only the fragments below it: one load for the second fragment, not one
/// per fragment of the block.
#[test]
fn sender_read_nak_walks_a_large_block_from_its_checkpoint() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_nak_reader(&mut conductor, MIN_NAK_CHECKPOINT_STRIDE);
    let mut publication = buffer.publication().unwrap().unwrap();
    let _ = publication
        .append(&sized_message(1, 7000), AppendOptions::default())
        .unwrap();
    let frames = sr_walk(&mut reader);
    let head = reader.position();
    let starts: Vec<u64> = frames.keys().copied().collect();
    assert_eq!(starts.len(), 6);
    let mut out = sr_out();
    let (result, loads) = sr_nak(&mut reader, starts[1], head, u32::MAX, &mut out);
    assert_eq!(
        result,
        Ok(ReadOutcome::Copied {
            len: frames[&starts[1]].len(),
            next: starts[2],
        })
    );
    assert_eq!(&out[..frames[&starts[1]].len()], &frames[&starts[1]][..]);
    assert_eq!(loads, 1);
    assert_eq!(reader.counters().nak_loads, 1);
}

/// A NAK inside a block that starts after its stride's checkpoint takes
/// the block's end from the next stride's checkpoint, its first fragment
/// there: the loads stop below it, never at the block's END.
#[test]
fn sender_read_nak_takes_a_blocks_end_from_the_next_checkpoint() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_nak_reader(&mut conductor, MIN_NAK_CHECKPOINT_STRIDE);
    let mut publication = buffer.publication().unwrap().unwrap();
    for (i, size) in [100, 7000].into_iter().enumerate() {
        let _ = publication
            .append(&sized_message(i as u32, size), AppendOptions::default())
            .unwrap();
    }
    let frames = sr_walk(&mut reader);
    let head = reader.position();
    // 0, then the large block's fragments from 160: 1568 and 2976 lie in
    // the first stride, 4384 is the next stride's first frame start.
    let starts: Vec<u64> = frames.keys().copied().collect();
    assert_eq!(&starts[..5], &[0, 160, 1568, 2976, 4384]);
    let mut out = sr_out();
    let (result, loads) = sr_nak(&mut reader, 1568, head, u32::MAX, &mut out);
    assert_eq!(
        result,
        Ok(ReadOutcome::Copied {
            len: frames[&1568].len(),
            next: 2976,
        })
    );
    assert_eq!(&out[..frames[&1568].len()], &frames[&1568][..]);
    // The block's first word 0 and the fragments at 1568 and 2976.
    assert_eq!(loads, 3);
}

/// A NAK inside the block the cursor stands in takes the block's end from
/// the cursor's open block when the walk reaches the cursor's fragment.
#[test]
fn sender_read_nak_takes_a_blocks_end_from_the_cursor() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_nak_reader(&mut conductor, MIN_NAK_CHECKPOINT_STRIDE);
    let mut publication = buffer.publication().unwrap().unwrap();
    for (i, size) in [100, 7000].into_iter().enumerate() {
        let _ = publication
            .append(&sized_message(i as u32, size), AppendOptions::default())
            .unwrap();
    }
    // One read of the first frame and the large block's first fragment:
    // the cursor stands inside the block, at 1568.
    let mut out = vec![0u8; 1568];
    assert_eq!(
        sr_read(&mut reader, &mut out),
        Ok(ReadOutcome::Copied {
            len: 1568,
            next: 1568,
        })
    );
    assert!(!reader.at_boundary());
    let head = buffer.conductor_head().unwrap();
    let mut nak_out = sr_out();
    let (result, loads) = sr_nak(&mut reader, 1568, head, u32::MAX, &mut nak_out);
    assert!(
        matches!(result, Ok(ReadOutcome::Copied { next: 2976, .. })),
        "{result:?}"
    );
    // Only the block's first word 0.
    assert_eq!(loads, 1);
    // The cursor's own read of the fragment is the same bytes.
    let Ok(ReadOutcome::Copied { len, .. }) = sr_read(&mut reader, &mut out) else {
        panic!("not copied");
    };
    assert_eq!(&nak_out[..len], &out[..len]);
}

/// A term slot reused by a later term starts with no checkpoints: the
/// cursor stopped before the second stride of term `slots` leaves that
/// entry empty, so a NAK at the offset term 0 recorded there walks from
/// term `slots`'s own entry and never validates the word 0 forged in a
/// payload at that offset.
#[test]
fn sender_read_nak_never_uses_a_reused_slots_checkpoints() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_nak_reader(&mut conductor, MIN_NAK_CHECKPOINT_STRIDE);
    let mut publication = buffer.publication().unwrap().unwrap();
    let slots = u64::from(buffer.slots);
    let mut out = sr_out();
    let mut append = |size: usize| {
        let _ = append_retrying(
            &mut publication,
            &mut conductor,
            &sized_message(1, size),
            || {},
        );
        while let Ok(ReadOutcome::Copied { .. } | ReadOutcome::Canonical { .. }) =
            sr_read(&mut reader, &mut out)
        {}
        sr_sent(&mut reader);
    };
    // Nine 7000-byte messages per term (7200 bytes each): in each term the
    // first frame start at or after 4096 is the fragment at 4224. The
    // last term ends with a 600-byte message, leaving 96 bytes.
    for _ in 0..slots {
        for _ in 0..9 {
            append(7000);
        }
    }
    append(600);
    assert_eq!(reader.position(), slots * TERM - 96);
    // Term `slots`, in term 0's slot: a frame at 0, then a block from 160
    // whose fragment at 2976 runs past 4224.
    let first = slots * TERM;
    for size in [100, 7000] {
        let _ = append_retrying(&mut publication, &mut conductor, &sized_message(2, size), || {});
    }
    let forged = Word0::new(64, Flags::new(false, false, false, false, Lane::ZERO), FrameType::Data);
    word0_of_term0(&buffer, 4224).store(forged.pack().to_le(), Ordering::Relaxed);
    // The PAD, then the frame at 0 alone: the cursor stops at 160.
    assert!(matches!(
        sr_read(&mut reader, &mut out),
        Ok(ReadOutcome::Canonical { record: CanonicalKind::Pad, .. })
    ));
    assert_eq!(
        sr_read(&mut reader, &mut out),
        Ok(ReadOutcome::Copied {
            len: 132,
            next: first + 160,
        })
    );
    let (result, _) = sr_nak(&mut reader, first + 4224, u64::MAX, u32::MAX, &mut out);
    assert_eq!(result, Err(ReadError::BadRequest));
}

/// Each floor check of a NAK read refuses on its own: a floor raised
/// after the loan is refused by the second; a floor the first saw is
/// refused there, even when a test lowers it before the loan.
#[test]
fn sender_read_nak_checks_the_floor_before_and_after_the_loan() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_reader(&mut conductor);
    let mut publication = buffer.publication().unwrap().unwrap();
    for i in 0..2 {
        let _ = publication
            .append(&sized_message(i, 100), AppendOptions::default())
            .unwrap();
    }
    let frames = sr_walk(&mut reader);
    let head = reader.position();
    let second = *frames.keys().nth(1).unwrap();
    let mut out = sr_out();
    reader.inject(super::sender_read::TestHook::FloorAfterLoan(second));
    assert_eq!(
        sr_nak(&mut reader, 0, head, 99, &mut out).0,
        Err(ReadError::Unavailable { lowest: second })
    );
    buffer.floor().store(second, Ordering::Release);
    reader.inject(super::sender_read::TestHook::FloorBeforeLoan(0));
    assert_eq!(
        sr_nak(&mut reader, 0, head, 99, &mut out).0,
        Err(ReadError::Unavailable { lowest: second })
    );
    // The hook is still pending: the next NAK read lowers the floor to 0
    // before its loan, and the first check passed already.
    buffer.floor().store(0, Ordering::Release);
    assert!(matches!(
        sr_nak(&mut reader, 0, head, 99, &mut out).0,
        Ok(ReadOutcome::Copied { .. })
    ));
}

/// A NAK at the start of an uncommitted block below the bound is
/// `BadRequest`, counted: the sender never sent it.
#[test]
fn sender_read_nak_refuses_an_uncommitted_block() {
    let buffer = new_buffer(config(3, 2)).unwrap();
    let mut conductor = buffer.conductor().unwrap();
    let mut reader = sr_reader(&mut conductor);
    let mut publication = buffer.publication().unwrap().unwrap();
    let _ = publication
        .append(&sized_message(1, 100), AppendOptions::default())
        .unwrap();
    let claim = claimed(publication.try_claim(100, AppendOptions::default()));
    let _ = sr_walk(&mut reader);
    let at = reader.position();
    assert_eq!(at, 160);
    let mut out = sr_out();
    assert_eq!(
        sr_nak(&mut reader, at, u64::MAX, 99, &mut out).0,
        Err(ReadError::BadRequest)
    );
    // Past it as well: the walk cannot cross it.
    assert_eq!(
        sr_nak(&mut reader, at + 160, u64::MAX, 99, &mut out).0,
        Err(ReadError::BadRequest)
    );
    assert_eq!(reader.counters().nak_bad_request, 2);
    claim.abort();
}
