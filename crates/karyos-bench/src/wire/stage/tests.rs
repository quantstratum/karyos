// SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::AtomicU32;

use super::*;
use crate::manifest::{ExtBase, ILLUSTRATIVE_E_MAX};
use crate::samples::SATURATED;
use karyos_protocol::protection::{Rejection, SealError, Trusted};

fn stage_run(shape: Shape, load: StageLoad, messages: u64, warmup: u64) -> StageRun {
    StageRun {
        shape,
        e_max: ILLUSTRATIVE_E_MAX,
        rule: MtuRule::CountsEnvelope,
        load,
        messages,
        warmup,
        receivers: 1,
    }
}

fn smoke(shape: Shape, load: StageLoad) -> StageSamples {
    run(stage_run(shape, load, 200, 20), &Trusted)
        .unwrap_or_else(|error| panic!("{shape} {load:?}: {error}"))
}

#[test]
fn every_shape_runs_closed_loop_over_loopback() {
    for shape in [
        Shape::W1,
        Shape::W2,
        Shape::W3,
        Shape::W4,
        Shape::W5,
        Shape::W6,
        Shape::W7,
        Shape::W9(ExtBase::W1),
        Shape::W9(ExtBase::W4),
    ] {
        let samples = smoke(shape, StageLoad::Closed);
        assert_eq!(samples.send.len(), 200);
        assert!(samples.send.iter().all(|s| *s != MISSING), "{shape}");
        let receiver = &samples.receivers[0];
        let lost = receiver.receive.iter().filter(|s| **s == MISSING).count();
        assert_eq!(lost, 0, "{shape}: {lost} lost in closed loop");
        // H-5: the batch's first callback is never after the message's own.
        assert!(
            receiver
                .receive
                .iter()
                .zip(&receiver.receive_callback)
                .all(|(batch, own)| batch >= own),
            "{shape}"
        );
        assert!(samples.functional_only);
        assert!(!samples.functional_reasons.is_empty());
        assert_eq!(samples.messages_per_sample == 1, shape != Shape::W5);
    }
}

#[test]
fn the_allocation_build_counts_and_both_stages_allocate_nothing() {
    // The counting allocator is this test binary's (lib.rs).
    assert!(BUILD.starts_with("alloc-count"), "{BUILD}");
    let (vector, allocations) = counted(|| vec![1_u8; 16]);
    assert_eq!(vector.len(), 16);
    assert!(allocations >= 1, "counting is off");
    for shape in [Shape::W1, Shape::W5, Shape::W6] {
        let samples = smoke(shape, StageLoad::Closed);
        assert_eq!(samples.send_allocations, 0, "{shape}");
        assert_eq!(samples.receivers[0].allocations, 0, "{shape}");
    }
}

/// A protection that allocates in one seal or one open, the third.
#[derive(Default)]
struct AllocatesOnce {
    seals: AtomicU32,
    opens: AtomicU32,
    in_open: bool,
}

impl Protection for AllocatesOnce {
    fn envelope_len(&self) -> usize {
        0
    }

    fn seal(&self, datagram: &mut [u8], frames: usize) -> Result<usize, SealError> {
        if !self.in_open && self.seals.fetch_add(1, Ordering::Relaxed) == 2 {
            std::hint::black_box(vec![0_u8; 8]);
        }
        Trusted.seal(datagram, frames)
    }

    fn open(&self, datagram: &[u8]) -> Verdict {
        if self.in_open && self.opens.fetch_add(1, Ordering::Relaxed) == 2 {
            std::hint::black_box(vec![0_u8; 8]);
        }
        Trusted.open(datagram)
    }
}

#[test]
fn one_allocating_stage_among_clean_ones_is_counted() {
    // The most of any stage is reported, not the last one's: the third
    // message allocates, the 19 after it do not.
    let samples = run(
        stage_run(Shape::W1, StageLoad::Closed, 20, 0),
        &AllocatesOnce::default(),
    )
    .unwrap();
    assert!(
        samples.send_allocations >= 1,
        "{}",
        samples.send_allocations
    );
    assert_eq!(samples.receivers[0].allocations, 0);
    // The receive count covers the whole poll, the decision included.
    let samples = run(
        stage_run(Shape::W1, StageLoad::Closed, 20, 0),
        &AllocatesOnce {
            in_open: true,
            ..AllocatesOnce::default()
        },
    )
    .unwrap();
    assert_eq!(samples.send_allocations, 0);
    assert!(samples.receivers[0].allocations >= 1);
}

#[test]
fn a_stop_after_the_last_ack_is_no_stop() {
    // The receiver acks message 0 and stops between the sender's two
    // reads (#236 flake): the count read after the stop has the ack.
    let count = std::cell::Cell::new(0_u64);
    let done = || {
        count.set(1);
        true
    };
    assert_eq!(wait_for_ack(|| count.get(), done, 0), Wait::Completed);
    // A receiver that stopped short of the message is a stop.
    assert_eq!(wait_for_ack(|| 1, || true, 1), Wait::Stopped);
    assert_eq!(wait_for_ack(|| 2, || true, 1), Wait::Completed);
}

#[test]
#[ignore = "stress: holds every core for seconds; run with --ignored"]
fn a_receiver_done_with_every_message_never_stops_the_sender() {
    // The receiver acks the last message and stops at once; under load the
    // sender may see the stop before the last ack. Stressors hold every
    // core so the threads are preempted between the two. The regression
    // gate is a_stop_after_the_last_ack_is_no_stop, which forces the
    // interleaving.
    let quit = AtomicBool::new(false);
    thread::scope(|scope| {
        let stressors = thread::available_parallelism().map_or(4, usize::from);
        for _ in 0..stressors {
            scope.spawn(|| {
                while !quit.load(Ordering::Relaxed) {
                    std::hint::spin_loop();
                }
            });
        }
        let _quit = SetOnDrop(&quit);
        for iteration in 0..200 {
            if let Err(error) = run(stage_run(Shape::W1, StageLoad::Closed, 20, 0), &Trusted) {
                panic!("iteration {iteration}: {error}");
            }
        }
    });
}

#[test]
fn the_synthetic_profile_adds_its_spin_to_each_stage() {
    use crate::wire::profile::Profile;
    // Load-tolerant (ACS 16456): the two profiles run interleaved, a few
    // rounds each, and each stage is compared by its fastest sample over
    // every round. Load only adds time, so a minimum is the least
    // disturbed figure; Synthetic spins at least 500 ns in seal and in
    // open, which the fastest path cannot skip, while a busy spin keeps
    // the core clocked up and makes the rest of the stage faster (ACS
    // 15453), so the bounds only show the spin is there and is not
    // runaway. Without the spin both minima are the same path.
    let fastest = |values: &[u32]| values.iter().copied().min().map_or(u64::MAX, u64::from);
    let stages = |configuration: &str| {
        let samples = run(
            stage_run(Shape::W1, StageLoad::Closed, 500, 50),
            &Profile::of(configuration).unwrap(),
        )
        .unwrap();
        (
            fastest(&samples.send),
            fastest(&samples.receivers[0].receive),
        )
    };
    let (mut trusted, mut synthetic) = ((u64::MAX, u64::MAX), (u64::MAX, u64::MAX));
    for _ in 0..4 {
        let round = stages("trusted");
        trusted = (trusted.0.min(round.0), trusted.1.min(round.1));
        let round = stages("synthetic-500");
        synthetic = (synthetic.0.min(round.0), synthetic.1.min(round.1));
    }
    for (stage, trusted, synthetic) in [
        ("send", trusted.0, synthetic.0),
        ("receive", trusted.1, synthetic.1),
    ] {
        // A synthetic minimum below the trusted one adds nothing.
        let added = synthetic.checked_sub(trusted);
        assert!(
            added.is_some_and(|added| (125..20_000).contains(&added)),
            "{stage}: trusted {trusted} ns, synthetic {synthetic} ns (fastest samples)"
        );
    }
}

#[test]
fn an_open_loop_run_records_every_message() {
    let samples = smoke(Shape::W1, StageLoad::Open { rate: 20_000 });
    assert_eq!(samples.receivers[0].receive.len(), 200);
    assert!(!samples.receivers[0].batches.is_empty());
}

#[test]
fn a_sample_at_or_above_saturated_saturates() {
    assert_eq!(ns(Duration::from_nanos(1_000)), Some(1_000));
    assert_eq!(
        ns(Duration::from_nanos(u64::from(SATURATED) - 1)),
        Some(SATURATED - 1)
    );
    assert_eq!(ns(Duration::from_nanos(u64::from(SATURATED))), None);
    assert_eq!(ns(Duration::from_nanos(u64::from(MISSING))), None);
    assert_eq!(ns(Duration::from_secs(5)), None);
}

/// Message `sequence` of `prepared`, datagram by datagram.
fn datagrams(prepared: &Prepared, sequence: u64) -> Vec<Vec<u8>> {
    let template = &prepared.template;
    let mut message = vec![0_u8; template.len()];
    template.stamp(sequence, &mut message).unwrap();
    (0..template.datagrams())
        .map(|index| template.datagram(&message, index).unwrap().to_vec())
        .collect()
}

fn ago(duration: Duration) -> Instant {
    Instant::now().checked_sub(duration).unwrap()
}

/// W6 under `trusted`: five datagrams per message; two warmup messages,
/// then three measured.
fn w6() -> (StageRun, Prepared) {
    let run = stage_run(Shape::W6, StageLoad::Closed, 3, 2);
    let prepared = Prepared::new(&run, &Trusted).unwrap();
    assert_eq!(prepared.template.datagrams(), 5);
    (run, prepared)
}

#[test]
fn a_message_completes_on_its_last_datagram_only() {
    let (run, prepared) = w6();
    let mut receiver = Receiver::new(&run, &prepared, &Trusted).unwrap();
    let now = Instant::now();
    // Warmup message 0: no acknowledgement before its fifth datagram.
    let warmup = datagrams(&prepared, 0);
    for (index, datagram) in warmup.iter().enumerate() {
        assert_eq!(receiver.completed, 0, "after {index} datagrams");
        assert!(receiver.accept(datagram, now, now).is_continue());
    }
    assert_eq!(receiver.completed, 1);
    // Measured message 2 (index 0): no sample before its last datagram,
    // even with the others received out of order.
    let measured = datagrams(&prepared, 2);
    for index in [4, 0, 3, 1] {
        assert!(receiver.accept(&measured[index], now, now).is_continue());
        assert_eq!(receiver.receive[0], MISSING);
        assert_eq!(receiver.completed, 1);
    }
    assert!(receiver.accept(&measured[2], now, now).is_continue());
    assert_ne!(receiver.receive[0], MISSING);
    assert_eq!(receiver.completed, 3);
    assert!(receiver.fault.is_none());
}

#[test]
fn the_receive_stage_starts_at_the_first_callback_of_the_batch() {
    let (run, prepared) = w6();
    let mut receiver = Receiver::new(&run, &prepared, &Trusted).unwrap();
    let measured = datagrams(&prepared, 2);
    // The first datagram arrives 1 ms ago, in a batch whose first callback
    // was 10 ms ago; later datagrams in later batches do not move either
    // start.
    let (batch, own) = (
        ago(Duration::from_millis(10)),
        ago(Duration::from_millis(1)),
    );
    assert!(receiver.accept(&measured[0], batch, own).is_continue());
    let now = Instant::now();
    for datagram in &measured[1..] {
        assert!(receiver.accept(datagram, now, now).is_continue());
    }
    let (from_batch, from_own) = (receiver.receive[0], receiver.receive_callback[0]);
    assert!(from_batch >= 10_000_000, "{from_batch}");
    assert!((1_000_000..10_000_000).contains(&from_own), "{from_own}");
}

fn fault_of(receiver: &mut Receiver<'_, impl Protection>, datagram: &[u8]) -> String {
    let now = Instant::now();
    assert!(receiver.accept(datagram, now, now).is_break());
    receiver
        .fault
        .take()
        .map(|fault| fault.0)
        .unwrap_or_default()
}

#[test]
fn a_duplicate_datagram_invalidates_the_run() {
    let (run, prepared) = w6();
    let mut receiver = Receiver::new(&run, &prepared, &Trusted).unwrap();
    let measured = datagrams(&prepared, 3);
    let now = Instant::now();
    assert!(receiver.accept(&measured[1], now, now).is_continue());
    let fault = fault_of(&mut receiver, &measured[1]);
    assert!(fault.contains("duplicate"), "{fault}");
    // Five datagrams with one repeated never complete the message.
    assert_eq!(receiver.receive[1], MISSING);
}

#[test]
fn a_duplicate_warmup_datagram_invalidates_the_run() {
    let (run, prepared) = w6();
    let mut receiver = Receiver::new(&run, &prepared, &Trusted).unwrap();
    let warmup = datagrams(&prepared, 1);
    let now = Instant::now();
    assert!(receiver.accept(&warmup[2], now, now).is_continue());
    let fault = fault_of(&mut receiver, &warmup[2]);
    assert!(fault.contains("sequence 1: duplicate"), "{fault}");
    assert_eq!(receiver.completed, 0);
}

#[test]
fn a_receiver_stop_ends_an_open_loop_wait() {
    // At one message per second, message 1 is due 1 s after message 0;
    // the receiver stops after 50 ms, inside that wait.
    let run = stage_run(Shape::W1, StageLoad::Open { rate: 1 }, 5, 0);
    let prepared = Prepared::new(&run, &Trusted).unwrap();
    let (mut tx, _tx_rx) = prepared
        .endpoint()
        .unwrap()
        .split()
        .map_err(|_| "split")
        .unwrap();
    let receiving = prepared.endpoint().unwrap();
    let peer = receiving.capabilities().local;
    let stop = AtomicBool::new(false);
    let started = Instant::now();
    let result = thread::scope(|scope| {
        scope.spawn(|| {
            thread::sleep(Duration::from_millis(50));
            stop.store(true, Ordering::Release);
        });
        send_role(
            &run,
            &prepared,
            &Trusted,
            &mut tx,
            peer,
            &SendControl {
                wait: &|_| Wait::Completed,
                stopped: &|| stop.load(Ordering::Acquire),
            },
        )
    });
    let error = result.err().map(|error| error.0).unwrap_or_default();
    assert!(error.contains("receiver stopped"), "{error}");
    assert!(
        started.elapsed() < Duration::from_millis(900),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn unacknowledged_messages_past_the_drop_budget_end_the_run() {
    // 1000 messages allow one timeout (M-11): the second ends the run.
    let run = stage_run(Shape::W1, StageLoad::Closed, 1_000, 0);
    let prepared = Prepared::new(&run, &Trusted).unwrap();
    let (mut tx, _tx_rx) = prepared
        .endpoint()
        .unwrap()
        .split()
        .map_err(|_| "split")
        .unwrap();
    let receiving = prepared.endpoint().unwrap();
    let waits = AtomicU32::new(0);
    let result = send_role(
        &run,
        &prepared,
        &Trusted,
        &mut tx,
        receiving.capabilities().local,
        &SendControl {
            wait: &|_| {
                waits.fetch_add(1, Ordering::Relaxed);
                Wait::TimedOut
            },
            stopped: &|| false,
        },
    );
    let error = result.err().map(|error| error.0).unwrap_or_default();
    assert!(error.contains("2 messages unacknowledged"), "{error}");
    assert_eq!(waits.load(Ordering::Relaxed), 2);
}

#[test]
fn a_sequence_never_sent_is_an_orphan() {
    let (run, prepared) = w6();
    let mut receiver = Receiver::new(&run, &prepared, &Trusted).unwrap();
    // Total is 5: sequence 5 was never sent (M-11).
    let fault = fault_of(&mut receiver, &datagrams(&prepared, 5)[0]);
    assert!(fault.contains("orphan sequence 5"), "{fault}");
}

/// A protection that rejects every datagram on open.
struct RejectAll;

impl Protection for RejectAll {
    fn envelope_len(&self) -> usize {
        0
    }

    fn seal(&self, datagram: &mut [u8], frames: usize) -> Result<usize, SealError> {
        Trusted.seal(datagram, frames)
    }

    fn open(&self, _datagram: &[u8]) -> Verdict {
        Verdict::Reject(Rejection::Short)
    }
}

#[test]
fn a_rejected_datagram_invalidates_the_run() {
    let (run, prepared) = w6();
    let mut receiver = Receiver::new(&run, &prepared, &RejectAll).unwrap();
    let fault = fault_of(&mut receiver, &datagrams(&prepared, 2)[0]);
    assert!(fault.contains("protection"), "{fault}");
    // A datagram the parser refuses: its first frame names another stream.
    let mut receiver = Receiver::new(&run, &prepared, &Trusted).unwrap();
    let mut datagram = datagrams(&prepared, 2)[0].clone();
    datagram[16] ^= 0xff;
    let fault = fault_of(&mut receiver, &datagram);
    assert!(fault.contains("parser"), "{fault}");
}

#[test]
fn a_saturated_receive_sample_invalidates_the_run() {
    let run = stage_run(Shape::W1, StageLoad::Closed, 1, 0);
    let prepared = Prepared::new(&run, &Trusted).unwrap();
    let mut receiver = Receiver::new(&run, &prepared, &Trusted).unwrap();
    let datagram = &datagrams(&prepared, 0)[0];
    let old = ago(Duration::from_secs(5));
    assert!(receiver.accept(datagram, old, old).is_break());
    let fault = receiver
        .fault
        .take()
        .map(|fault| fault.0)
        .unwrap_or_default();
    assert!(fault.contains("saturated"), "{fault}");
}

/// A protection whose first seal sleeps 20 ms.
#[derive(Default)]
struct SlowFirst(AtomicBool);

impl Protection for SlowFirst {
    fn envelope_len(&self) -> usize {
        0
    }

    fn seal(&self, datagram: &mut [u8], frames: usize) -> Result<usize, SealError> {
        if !self.0.swap(true, Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(20));
        }
        Trusted.seal(datagram, frames)
    }

    fn open(&self, datagram: &[u8]) -> Verdict {
        Trusted.open(datagram)
    }
}

#[test]
fn a_late_open_loop_send_keeps_its_delay() {
    // At 100 000 per second message 1 is due 10 µs after message 0, which
    // takes 20 ms: its send stage starts at its scheduled instant.
    let samples = run(
        stage_run(Shape::W1, StageLoad::Open { rate: 100_000 }, 3, 0),
        &SlowFirst::default(),
    )
    .unwrap();
    assert!(samples.send[0] >= 20_000_000, "{}", samples.send[0]);
    assert!(samples.send[1] >= 15_000_000, "{}", samples.send[1]);
}

/// A protection whose third seal panics.
#[derive(Default)]
struct PanicAtThird(AtomicU32);

impl Protection for PanicAtThird {
    fn envelope_len(&self) -> usize {
        0
    }

    fn seal(&self, datagram: &mut [u8], frames: usize) -> Result<usize, SealError> {
        assert_ne!(self.0.fetch_add(1, Ordering::Relaxed), 2, "seal panics");
        Trusted.seal(datagram, frames)
    }

    fn open(&self, datagram: &[u8]) -> Verdict {
        Trusted.open(datagram)
    }
}

#[test]
fn a_sender_panic_ends_the_run() {
    let started = Instant::now();
    let result = run(
        stage_run(Shape::W1, StageLoad::Closed, 10, 0),
        &PanicAtThird::default(),
    );
    let error = result.err().map(|error| error.0).unwrap_or_default();
    assert!(error.contains("sender thread panicked"), "{error}");
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn a_receiver_fault_stops_the_sender() {
    // Under R1 a sender that ignored the receiver would wait ACK_TIMEOUT
    // for each of the 50 messages.
    let started = Instant::now();
    let result = run(stage_run(Shape::W1, StageLoad::Closed, 50, 0), &RejectAll);
    let error = result.err().map(|error| error.0).unwrap_or_default();
    assert!(error.contains("protection"), "{error}");
    assert!(started.elapsed() < Duration::from_secs(3));
}
