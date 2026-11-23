// SPDX-License-Identifier: Apache-2.0

//! The `io_uring` completion model (SPEC.md §13, "Backend ring and frame
//! ownership"; karyos#641): seeded runs drive the `io_uring` TX and RX
//! state machines of `karyos-io` over its scripted rings, completing
//! operations in random order, with random results, cancels and resets,
//! and check the row's three failures: a frame touched while the kernel
//! owns it, a leaked frame or buffer, and a wrong recovery after a reset.
//!
//! A deliberate mutant (a TX half that releases each slot at submission,
//! as copied sockets do) must be caught, so the model is shown to fail
//! when ownership is broken.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests, as ADR-0007 allows"
)]

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::ops::ControlFlow;

use karyos_io::backend::CapabilityState;
use karyos_io::backend::{
    Authority, Budget, Commit, CompletionHandler, Exposure, FlushRequest, GateDecision, InstanceId,
    RxBackend, RxDatagram, RxDrop, RxHandler, SenderGate, SenderToken, SubmissionId, TxBackend,
    TxEvent, TxFrame, TxOptions, TxQueueConfig, TxReport,
};
use karyos_io::uring::rx::{UringRx, UringRxConfig};
use karyos_io::uring::scripted::{Pushed, ScriptedRing, ScriptedRxRing};
use karyos_io::uring::tx::{UringTx, UringTxConfig};
use karyos_sim::rng::Rng;
use karyos_sim::scenarios::seeds;

const SLOTS: u16 = 8;
const LEN: u16 = 32;
const STEPS: u32 = 400;

fn nz(value: u16) -> NonZeroU16 {
    NonZeroU16::new(value).unwrap()
}

struct Permit;

impl SenderGate for Permit {
    fn check(&mut self, candidate: &Exposure<'_>) -> GateDecision {
        match NonZeroU16::new(u16::try_from(candidate.tokens.len()).unwrap()) {
            Some(count) => GateDecision::Permit { count },
            None => GateDecision::Deny,
        }
    }
}

#[derive(Default)]
struct Releases(HashMap<SubmissionId, u32>);

impl CompletionHandler for Releases {
    fn event(&mut self, event: TxEvent) {
        if let TxEvent::Released { id, .. } = event {
            *self.0.entry(id).or_default() += 1;
        }
    }
}

/// What one TX run observed.
#[derive(Debug, Default)]
struct TxRun {
    touches_while_owned: u64,
    stale_completions: u64,
    double_releases: usize,
    retained_after_reset: u16,
    submitted_after_reset: usize,
    kernel_mismatches: u32,
}

fn tx_run(seed: u64, mutant: bool) -> TxRun {
    let mut rng = Rng::new(seed);
    let config = UringTxConfig {
        max_datagram: nz(LEN),
        tx_slots: nz(SLOTS),
        max_queues: nz(1),
        max_routes: nz(1),
        max_batch: nz(4),
        sqpoll: None,
    };
    let ring = ScriptedRing::new(SLOTS, LEN, 16);
    let instance = InstanceId::new(NonZeroU32::MIN);
    let mut tx = UringTx::open(config, instance, ring, CapabilityState::NotRequested).unwrap();
    if mutant {
        tx.inject_release_at_submission();
    }
    let route = tx
        .add_route(SocketAddr::from((Ipv4Addr::LOCALHOST, 9)))
        .unwrap();
    let queue = tx
        .open_queue(TxQueueConfig {
            authority: Authority::new(NonZeroU64::MIN),
            route,
            max_pending: nz(SLOTS),
        })
        .unwrap();
    let mut report = TxReport::new();
    let mut releases = Releases::default();
    // The bytes each kernel owned slot held when its send was pushed:
    // what the kernel reads, which must not change before the completion.
    let mut pushed_bytes: HashMap<u16, Vec<u8>> = HashMap::new();
    let mut run = TxRun::default();
    let mut seen_pushes = 0;
    let budget = Budget::new(64, u64::MAX, 8);
    for step in 0..STEPS {
        match rng.below(6) {
            0 | 1 => {
                let len = usize::try_from(rng.between(1, u64::from(LEN))).unwrap();
                if let Ok(mut frame) = tx.claim_tx(queue, len) {
                    let byte = u8::try_from(step % 251).unwrap();
                    frame.bytes_mut().fill(byte);
                    let _ = frame.commit(Commit {
                        len,
                        token: SenderToken::new(u64::from(step)),
                        options: TxOptions::none(),
                    });
                }
            }
            2 => {
                let request = FlushRequest {
                    queue,
                    max_datagrams: nz(4),
                    max_bytes: u32::MAX,
                };
                tx.flush(request, &mut Permit, &mut report);
                while report.pop_front().is_some() {}
            }
            3 | 4 => {
                // The kernel completes one owned operation, in any order.
                let owned: Vec<u16> = (0..SLOTS)
                    .filter(|&slot| tx.ring().owner(slot).is_some())
                    .collect();
                if !owned.is_empty() {
                    let slot = owned[usize::try_from(rng.below(owned.len() as u64)).unwrap()];
                    let len = tx
                        .ring()
                        .pushed()
                        .iter()
                        .rev()
                        .find_map(|pushed| match pushed {
                            Pushed::Send { slot: s, len, .. } if *s == slot => Some(*len),
                            _ => None,
                        })
                        .unwrap();
                    if let Some(expected) = pushed_bytes.get(&slot) {
                        let now = tx.ring().slot_bytes(slot).unwrap();
                        if now.get(..expected.len()) != Some(expected.as_slice()) {
                            run.kernel_mismatches += 1;
                        }
                    }
                    let result = match rng.below(4) {
                        0 => -11,
                        1 => -125,
                        _ => i32::from(len),
                    };
                    tx.ring_mut().complete_slot(slot, result);
                }
            }
            _ => {
                tx.poll_completions(budget, &mut releases);
                if rng.chance(1, 8) {
                    let _ = tx.cancel_submitted(queue);
                }
            }
        }
        // Record what each new push made the kernel read.
        let pushed = tx.ring().pushed();
        for event in &pushed[seen_pushes..] {
            if let Pushed::Send { slot, len, .. } = event {
                let bytes = tx.ring().slot_bytes(*slot).unwrap();
                pushed_bytes.insert(*slot, bytes[..usize::from(*len)].to_vec());
            }
        }
        seen_pushes = pushed.len();
    }
    // Reset: return pending items, cancel everything, then the kernel
    // completes what it owns; the reset completes only on terminal CQEs.
    let mut rounds = 0;
    loop {
        let reset = tx.reset(&mut report, budget, &mut releases);
        while report.pop_front().is_some() {}
        if !reset.more || rounds > 64 {
            break;
        }
        rounds += 1;
        for slot in 0..SLOTS {
            tx.ring_mut().complete_slot(slot, -125);
        }
        let cancels: Vec<_> = tx
            .ring()
            .pushed()
            .iter()
            .filter_map(|pushed| match pushed {
                Pushed::Cancel { user_data, .. } => Some(*user_data),
                Pushed::Send { .. } => None,
            })
            .collect();
        for cancel in cancels {
            tx.ring_mut().complete(cancel, 0, 0);
        }
    }
    run.touches_while_owned = tx.ring().touches_while_owned();
    run.stale_completions = tx.counters().stale_completions;
    run.double_releases = releases.0.values().filter(|&&count| count > 1).count();
    run.retained_after_reset = tx.retained().slots;
    run.submitted_after_reset = tx.submitted();
    run
}

#[test]
fn no_frame_is_touched_while_the_kernel_owns_it_and_none_leaks() {
    for seed in seeds() {
        let run = tx_run(seed, false);
        assert_eq!(run.touches_while_owned, 0, "seed {seed}: {run:?}");
        assert_eq!(run.kernel_mismatches, 0, "seed {seed}: {run:?}");
        assert_eq!(run.double_releases, 0, "seed {seed}: {run:?}");
        assert_eq!(run.retained_after_reset, 0, "seed {seed}: {run:?}");
        assert_eq!(run.submitted_after_reset, 0, "seed {seed}: {run:?}");
    }
}

#[test]
fn the_model_catches_a_backend_that_releases_at_submission() {
    let caught = seeds().into_iter().any(|seed| {
        let run = tx_run(seed, true);
        run.touches_while_owned > 0 || run.stale_completions > 0 || run.double_releases > 0
    });
    assert!(
        caught,
        "the mutant that frees a slot the kernel still owns must fail the model"
    );
}

#[derive(Default)]
struct Count(u32);

impl RxHandler for Count {
    fn datagram(&mut self, _: RxDatagram<'_>) -> ControlFlow<()> {
        self.0 += 1;
        ControlFlow::Continue(())
    }

    fn dropped(&mut self, _: RxDrop) {}
}

#[test]
fn rx_buffers_return_only_after_completion_and_survive_resets() {
    const BUFFERS: u16 = 8;
    for seed in seeds() {
        let mut rng = Rng::new(seed);
        let config = UringRxConfig {
            max_datagram: nz(32),
            rx_buffers: nz(BUFFERS),
            ..UringRxConfig::default()
        };
        let ring = ScriptedRxRing::new(BUFFERS, config.buffer_len());
        let mut rx = UringRx::open(config, InstanceId::new(NonZeroU32::MIN), ring).unwrap();
        let mut handler = Count::default();
        let source = SocketAddr::from((Ipv4Addr::LOCALHOST, 7));
        let mut delivered = 0_u32;
        for _ in 0..STEPS {
            match rng.below(5) {
                0 | 1 => {
                    for _ in 0..rng.between(1, 12) {
                        if rx.ring_mut().deliver(b"model", source, 0).is_some() {
                            delivered += 1;
                        }
                    }
                }
                2 if rng.chance(1, 6) => {
                    let mut rounds = 0;
                    loop {
                        let reset = rx.reset(Budget::new(64, u64::MAX, 4));
                        if !reset.more {
                            assert_eq!(
                                reset.posted, BUFFERS,
                                "seed {seed}: a reset leaks no buffer"
                            );
                            break;
                        }
                        rounds += 1;
                        assert!(rounds < 8, "seed {seed}: the reset completes");
                        rx.ring_mut().end_arm(-125);
                        let cancels: Vec<_> = rx
                            .ring()
                            .pushed()
                            .iter()
                            .filter_map(|pushed| match pushed {
                                Pushed::Cancel { user_data, .. } => Some(*user_data),
                                Pushed::Send { .. } => None,
                            })
                            .collect();
                        for cancel in cancels {
                            rx.ring_mut().complete(cancel, 0, 0);
                        }
                    }
                }
                _ => {
                    let budget =
                        Budget::new(u32::try_from(rng.between(1, 16)).unwrap(), u64::MAX, 4);
                    rx.poll_rx(budget, &mut handler);
                }
            }
            assert_eq!(
                rx.ring().lent_posted(),
                0,
                "seed {seed}: a Posted buffer was lent"
            );
            assert!(rx.posted() <= BUFFERS);
        }
        // Drain, then every buffer is posted again.
        for _ in 0..64 {
            rx.poll_rx(Budget::new(64, u64::MAX, 4), &mut handler);
        }
        assert_eq!(rx.posted(), BUFFERS, "seed {seed}: no buffer leaked");
        assert!(handler.0 <= delivered);
    }
}
