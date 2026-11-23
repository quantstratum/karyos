// SPDX-License-Identifier: Apache-2.0

//! The AF_XDP UMEM ring model (SPEC.md §13, "Backend ring and frame
//! ownership"; karyos#643): seeded runs drive the copy-mode endpoint of
//! `karyos-io` over its scripted socket. The "kernel" consumes TX
//! descriptors only inside a kick while `XDP_RING_NEED_WAKEUP` is set, and
//! on its own while it is clear, a few at a time and out of step with the
//! flushes; completions, received frames (some corrupted) and RX polls
//! interleave at random. The checks are the row's three failures: a frame
//! touched while the kernel owns it (or bytes the kernel reads changed), a
//! leaked frame, and a wrong recovery at teardown; plus `need_wakeup`
//! liveness: no descriptor stays unsent once the endpoint keeps polling.
//!
//! A deliberate mutant (an endpoint that frees each frame at submission)
//! must be caught by the same checks.

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

use karyos_io::backend::{
    Authority, Budget, Commit, CompletionHandler, Exposure, FlushRequest, GateDecision, InstanceId,
    PathId, RxBackend, RxDatagram, RxDrop, RxHandler, SenderGate, SenderToken, SubmissionId,
    TxBackend, TxEvent, TxFrame, TxOptions, TxQueueConfig, TxReport,
};
use karyos_io::xdp::endpoint::{Teardown, XdpEndpoint, XdpEndpointConfig};
use karyos_io::xdp::headers::{self, Addressing, Checked};
use karyos_io::xdp::ops::XskOps;
use karyos_io::xdp::scripted::ScriptedXsk;
use karyos_sim::rng::Rng;
use karyos_sim::scenarios::seeds;

const FRAME: u32 = 2048;
const TX: u16 = 8;
const RX: u32 = 8;
const STEPS: u32 = 400;
const MAC_LOCAL: [u8; 6] = [2, 0, 0, 0, 0, 1];
const MAC_PEER: [u8; 6] = [2, 0, 0, 0, 0, 2];

fn nz(value: u16) -> NonZeroU16 {
    NonZeroU16::new(value).unwrap()
}

fn local() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 5000))
}

fn peer() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 6000))
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

#[derive(Default)]
struct Count(u32);

impl RxHandler for Count {
    fn datagram(&mut self, _: RxDatagram<'_>) -> ControlFlow<()> {
        self.0 += 1;
        ControlFlow::Continue(())
    }

    fn dropped(&mut self, _: RxDrop) {}
}

fn inbound(payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0_u8; 128];
    let header = headers::header_len(&local());
    frame[header..header + payload.len()].copy_from_slice(payload);
    let addressing = Addressing {
        source_mac: MAC_PEER,
        destination_mac: MAC_LOCAL,
        source: peer(),
        destination: local(),
        hop_limit: 64,
    };
    let len = headers::write_headers(&mut frame, &addressing, payload.len()).unwrap();
    frame.truncate(len);
    frame
}

#[derive(Debug, Default)]
struct Run {
    touches_while_owned: u64,
    corrupted_sends: u32,
    double_releases: usize,
    stuck_after_polling: usize,
    rx_not_reposted: u32,
    unknown: u16,
    kernel_owned_at_teardown: u16,
    released: usize,
    committed: u32,
    returned: u16,
}

fn run(seed: u64, mutant: bool) -> Run {
    let mut rng = Rng::new(seed);
    let config = XdpEndpointConfig {
        local: local(),
        local_mac: MAC_LOCAL,
        mtu: 1500,
        max_datagram: nz(256),
        max_queues: nz(1),
        max_routes: nz(1),
        max_batch: nz(4),
        hop_limit: 64,
        path: PathId::new(0),
    };
    let xsk = ScriptedXsk::new(FRAME, TX, RX, usize::from(TX));
    let mut endpoint = XdpEndpoint::open(config, InstanceId::new(NonZeroU32::MIN), xsk).unwrap();
    if mutant {
        endpoint.inject_release_at_submission();
    }
    let route = endpoint.add_route(peer(), MAC_PEER).unwrap();
    let queue = endpoint
        .open_queue(TxQueueConfig {
            authority: Authority::new(NonZeroU64::MIN),
            route,
            max_pending: nz(TX),
        })
        .unwrap();
    let mut report = TxReport::new();
    let mut releases = Releases::default();
    let mut received = Count::default();
    let mut out = Run::default();
    let budget = Budget::new(16, u64::MAX, 4);
    let mut kicks_seen = 0;
    for step in 0..STEPS {
        match rng.below(7) {
            0 | 1 => {
                let len = usize::try_from(rng.between(1, 64)).unwrap();
                // Every byte of a payload is its token's low byte, so a
                // payload the kernel reads either matches or was touched.
                let byte = u8::try_from(step % 251).unwrap();
                if let Ok(mut frame) = endpoint.claim_tx(queue, len) {
                    frame.bytes_mut().fill(byte);
                    if frame
                        .commit(Commit {
                            len,
                            token: SenderToken::new(u64::from(byte)),
                            options: TxOptions::none(),
                        })
                        .is_ok()
                    {
                        out.committed += 1;
                    }
                }
            }
            2 => {
                let request = FlushRequest {
                    queue,
                    max_datagrams: nz(4),
                    max_bytes: u32::MAX,
                };
                endpoint.flush(request, &mut Permit, &mut report);
                while let Some(entry) = report.pop_front() {
                    if matches!(
                        entry.outcome,
                        karyos_io::backend::TxItemOutcome::Returned { .. }
                    ) {
                        out.returned += 1;
                    }
                }
            }
            3 => {
                let flag = rng.chance(1, 4);
                endpoint.xsk_mut().unwrap().set_need_wakeup(!flag);
            }
            4 => {
                let frame = if rng.chance(1, 5) {
                    let mut bad = inbound(b"corrupt");
                    let last = bad.len() - 1;
                    bad[last] ^= 0xff;
                    bad
                } else {
                    inbound(b"inbound")
                };
                endpoint.xsk_mut().unwrap().receive(&frame);
            }
            5 => {
                endpoint.poll_rx(budget, &mut received);
            }
            _ => {
                endpoint.poll_completions(budget, &mut releases);
            }
        }
        // The kernel: inside a kick while need_wakeup is set, on its own
        // otherwise, a few descriptors at a time.
        let xsk = endpoint.xsk_mut().unwrap();
        let kicked = xsk.kicks() > kicks_seen;
        kicks_seen = xsk.kicks();
        if kicked || (!xsk.tx_needs_wakeup() && rng.chance(1, 3)) {
            let some = usize::try_from(rng.between(1, 3)).unwrap();
            xsk.transmit_some(some);
        }
    }
    // need_wakeup liveness: with the flag set and the kernel sending only
    // inside kicks, polling alone drains every outstanding descriptor.
    endpoint.xsk_mut().unwrap().set_need_wakeup(true);
    for _ in 0..64 {
        endpoint.poll_completions(budget, &mut releases);
        let xsk = endpoint.xsk_mut().unwrap();
        if xsk.kicks() > kicks_seen {
            kicks_seen = xsk.kicks();
            xsk.transmit_some(2);
        }
    }
    endpoint.poll_completions(budget, &mut releases);
    out.stuck_after_polling = endpoint.xsk().unwrap().tx_outstanding();
    for _ in 0..8 {
        endpoint.poll_rx(budget, &mut received);
    }
    let xsk = endpoint.xsk().unwrap();
    out.rx_not_reposted = RX - xsk.rx_posted();
    out.touches_while_owned = xsk.touches_while_owned();
    for (_, bytes) in xsk.sent() {
        match headers::validate(bytes, peer(), MAC_PEER, 256) {
            Checked::Datagram { offset, len, .. } => {
                let payload = &bytes[offset..offset + len];
                if payload.iter().any(|byte| *byte != payload[0]) {
                    out.corrupted_sends += 1;
                }
            }
            Checked::Drop(..) => out.corrupted_sends += 1,
        }
    }
    out.double_releases = releases.0.values().filter(|&&count| count > 1).count();
    out.released = releases.0.len();
    loop {
        match endpoint.retire(&mut report) {
            Teardown::More { returned } => out.returned += returned,
            Teardown::Complete {
                returned,
                unknown,
                kernel_owned_frames,
            } => {
                out.returned += returned;
                out.unknown = unknown;
                out.kernel_owned_at_teardown = kernel_owned_frames;
                break;
            }
            Teardown::ReportNotEmpty => {}
        }
        while report.pop_front().is_some() {}
    }
    out
}

#[test]
fn no_frame_is_touched_while_the_kernel_owns_it_and_none_leaks() {
    for seed in seeds() {
        let run = run(seed, false);
        assert_eq!(run.touches_while_owned, 0, "seed {seed}: {run:?}");
        assert_eq!(run.corrupted_sends, 0, "seed {seed}: {run:?}");
        assert_eq!(run.double_releases, 0, "seed {seed}: {run:?}");
        assert_eq!(
            run.stuck_after_polling, 0,
            "seed {seed}: need_wakeup left descriptors unsent: {run:?}"
        );
        assert_eq!(run.rx_not_reposted, 0, "seed {seed}: {run:?}");
        // Teardown: every kernel owned frame is reported Unknown, and the
        // committed items all end released, returned or Unknown.
        assert_eq!(
            u32::from(run.kernel_owned_at_teardown),
            u32::from(run.unknown),
            "seed {seed}: {run:?}"
        );
        assert_eq!(
            run.committed,
            u32::try_from(run.released).unwrap() + u32::from(run.returned) + u32::from(run.unknown),
            "seed {seed}: a committed item leaked: {run:?}"
        );
    }
}

#[test]
fn the_model_catches_an_endpoint_that_frees_frames_at_submission() {
    let caught = seeds().into_iter().any(|seed| {
        let run = run(seed, true);
        run.touches_while_owned > 0 || run.corrupted_sends > 0 || run.double_releases > 0
    });
    assert!(
        caught,
        "the mutant that frees a frame the kernel still owns must fail the model"
    );
}
