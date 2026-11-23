// SPDX-License-Identifier: Apache-2.0

//! The RX state machine over [`ScriptedRxRing`], and over the real ring on
//! Linux with the `uring` feature.

use std::net::{Ipv4Addr, SocketAddr};
use std::num::{NonZeroU16, NonZeroU32};
use std::ops::ControlFlow;

use super::*;
use crate::backend::InstanceId;
use crate::uring::scripted::ScriptedRxRing;

const BUFFERS: u16 = 8;

fn config() -> UringRxConfig {
    UringRxConfig {
        max_datagram: NonZeroU16::new(64).unwrap_or(NonZeroU16::MIN),
        rx_buffers: NonZeroU16::new(BUFFERS).unwrap_or(NonZeroU16::MIN),
        path: PathId::new(3),
    }
}

fn source() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::new(10, 0, 0, 7), 4242))
}

fn rx() -> UringRx<ScriptedRxRing> {
    let ring = ScriptedRxRing::new(BUFFERS, config().buffer_len());
    let rx = UringRx::open(config(), InstanceId::new(NonZeroU32::MIN), ring);
    let Ok(rx) = rx else {
        panic!("open: {rx:?}");
    };
    rx
}

#[derive(Default)]
struct Sink {
    datagrams: Vec<(Vec<u8>, SocketAddr, PathId)>,
    drops: Vec<RxDrop>,
    stop_after: Option<usize>,
    panic_on_first: bool,
}

impl RxHandler for Sink {
    fn datagram(&mut self, datagram: RxDatagram<'_>) -> ControlFlow<()> {
        assert!(!self.panic_on_first, "handler failure while lent");
        self.datagrams.push((
            datagram.bytes().to_vec(),
            datagram.source(),
            datagram.path(),
        ));
        match self.stop_after {
            Some(limit) if self.datagrams.len() >= limit => ControlFlow::Break(()),
            _ => ControlFlow::Continue(()),
        }
    }

    fn dropped(&mut self, drop: RxDrop) {
        self.drops.push(drop);
    }
}

fn budget() -> Budget {
    Budget::new(64, u64::MAX, 4)
}

#[test]
fn a_datagram_is_lent_from_its_provided_buffer_and_the_buffer_reposted() {
    let mut rx = rx();
    let mut sink = Sink::default();
    // The first poll arms; nothing has arrived.
    let first = rx.poll_rx(budget(), &mut sink);
    assert_eq!(first.stop, RxStop::WouldBlock);
    assert_eq!(rx.ring().arms(), 1);
    assert_eq!(rx.posted(), BUFFERS);
    let id = rx.ring_mut().deliver(b"hello", source(), 0);
    assert!(id.is_some());
    assert_eq!(rx.posted(), BUFFERS - 1, "the kernel wrote one buffer");
    let outcome = rx.poll_rx(budget(), &mut sink);
    assert_eq!(outcome.delivered, 1);
    assert_eq!(outcome.spent.bytes, 5);
    assert_eq!(
        sink.datagrams,
        vec![(b"hello".to_vec(), source(), PathId::new(3))]
    );
    assert_eq!(rx.posted(), BUFFERS, "reposted after the lend");
    assert_eq!(rx.ring().arms(), 1, "the multishot arm stays armed");
}

#[test]
fn no_buffer_is_reused_while_the_kernel_owns_it() {
    let mut rx = rx();
    let mut sink = Sink::default();
    rx.poll_rx(budget(), &mut sink);
    // A completion naming a buffer the kernel still owns (Posted) is
    // refused by the ring and counted, never lent.
    let arm = rx.ring().arm_user_data();
    let Some(arm) = arm else {
        panic!("not armed");
    };
    rx.ring_mut().complete(
        arm,
        64,
        super::super::ops::CQE_F_BUFFER | CQE_F_MORE | (5 << 16),
    );
    rx.poll_rx(budget(), &mut sink);
    assert!(sink.datagrams.is_empty());
    assert_eq!(rx.ring().lent_posted(), 1);
    assert_eq!(rx.counters().invariants, 1);
    assert_eq!(rx.posted(), BUFFERS);
}

#[test]
fn a_handler_that_unwinds_still_gets_its_buffer_reposted() {
    let mut rx = rx();
    let mut sink = Sink::default();
    rx.poll_rx(budget(), &mut sink);
    rx.ring_mut().deliver(b"boom", source(), 0);
    sink.panic_on_first = true;
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rx.poll_rx(budget(), &mut sink)
    }));
    assert!(unwound.is_err());
    assert_eq!(rx.posted(), BUFFERS);
}

#[test]
fn a_handler_stop_leaves_the_rest_in_the_cq() {
    let mut rx = rx();
    let mut sink = Sink {
        stop_after: Some(1),
        ..Sink::default()
    };
    rx.poll_rx(budget(), &mut sink);
    rx.ring_mut().deliver(b"one", source(), 0);
    rx.ring_mut().deliver(b"two", source(), 0);
    let first = rx.poll_rx(budget(), &mut sink);
    assert_eq!(first.stop, RxStop::HandlerStopped);
    assert_eq!(first.delivered, 1);
    sink.stop_after = None;
    let second = rx.poll_rx(budget(), &mut sink);
    assert_eq!(second.delivered, 1);
    assert_eq!(sink.datagrams.len(), 2);
    assert_eq!(rx.posted(), BUFFERS);
}

#[test]
fn truncated_and_oversize_datagrams_are_dropped_with_the_buffer_reposted() {
    let mut rx = rx();
    let mut sink = Sink::default();
    rx.poll_rx(budget(), &mut sink);
    rx.ring_mut().deliver(&[1; 65], source(), 0);
    rx.ring_mut().deliver(b"cut", source(), MSG_TRUNC);
    let outcome = rx.poll_rx(budget(), &mut sink);
    assert_eq!(outcome.delivered, 0);
    assert_eq!(outcome.dropped, 2);
    assert_eq!(rx.counters().oversize, 2);
    assert!(
        sink.drops
            .iter()
            .all(|drop| matches!(drop.reason, RxDropReason::Oversize { limit: 64, .. }))
    );
    assert_eq!(rx.posted(), BUFFERS);
}

#[test]
fn buffer_exhaustion_is_counted_and_the_next_poll_rearms() {
    let mut rx = rx();
    let mut sink = Sink::default();
    rx.poll_rx(budget(), &mut sink);
    for byte in 0..BUFFERS {
        rx.ring_mut()
            .deliver(&[u8::try_from(byte).unwrap_or(0); 4], source(), 0);
    }
    assert_eq!(rx.posted(), 0);
    assert!(rx.ring_mut().deliver(b"none", source(), 0).is_none());
    let outcome = rx.poll_rx(budget(), &mut sink);
    assert_eq!(outcome.delivered, u32::from(BUFFERS));
    assert_eq!(outcome.stop, RxStop::NoBuffers);
    assert_eq!(rx.counters().no_buffers, 1);
    assert_eq!(rx.posted(), BUFFERS);
    rx.poll_rx(budget(), &mut sink);
    assert_eq!(rx.ring().arms(), 2, "re-armed after reposting");
}

#[test]
fn a_stale_arm_completion_is_counted_and_its_buffer_returned() {
    let mut rx = rx();
    let mut sink = Sink::default();
    rx.poll_rx(budget(), &mut sink);
    rx.ring_mut().complete(UserData::new(0, 99), -5, 0);
    rx.poll_rx(budget(), &mut sink);
    assert_eq!(rx.counters().stale_completions, 1);
    assert!(rx.failure().is_none());
}

#[test]
fn a_repeated_arm_failure_stops_the_half() {
    let mut rx = rx();
    let mut sink = Sink::default();
    rx.poll_rx(budget(), &mut sink);
    rx.ring_mut().end_arm(-22);
    rx.poll_rx(budget(), &mut sink);
    assert_eq!(rx.ring().arms(), 1);
    rx.poll_rx(budget(), &mut sink);
    assert_eq!(rx.ring().arms(), 2, "one re-arm");
    rx.ring_mut().end_arm(-22);
    let outcome = rx.poll_rx(budget(), &mut sink);
    assert_eq!(
        outcome.stop,
        RxStop::Failed(BackendFailure::Os {
            operation: "io_uring_recvmsg",
            errno: 22
        })
    );
}

#[test]
fn a_reset_reregisters_the_pool_without_leaking_a_buffer() {
    let mut rx = rx();
    let mut sink = Sink::default();
    rx.poll_rx(budget(), &mut sink);
    let before = rx.posted();
    rx.ring_mut().deliver(b"late", source(), 0);
    let first = rx.reset(budget());
    assert!(first.more, "the arm is cancelled, not yet ended");
    assert_eq!(
        rx.ring().registrations(),
        1,
        "nothing re-registered while armed"
    );
    let cancel = rx.ring().pushed().iter().find_map(|pushed| match pushed {
        crate::uring::scripted::Pushed::Cancel { user_data, .. } => Some(*user_data),
        crate::uring::scripted::Pushed::Send { .. } => None,
    });
    let Some(cancel) = cancel else {
        panic!("no cancel of the arm");
    };
    rx.ring_mut().end_arm(-125);
    rx.ring_mut().complete(cancel, 0, 0);
    let last = rx.reset(budget());
    assert!(!last.more);
    assert_eq!(last.posted, before, "count before and after");
    assert_eq!(last.buffers, BUFFERS);
    assert_eq!(rx.ring().registrations(), 2, "registered once more, once");
    assert_eq!(rx.counters().reregistrations, 1);
    assert!(sink.datagrams.is_empty(), "a reset delivers nothing");
    rx.poll_rx(budget(), &mut sink);
    assert_eq!(rx.ring().arms(), 2, "the next poll arms again");
}

#[test]
fn polls_do_not_allocate() {
    let mut rx = rx();
    let mut sink = Sink {
        datagrams: Vec::with_capacity(4),
        ..Sink::default()
    };
    rx.poll_rx(budget(), &mut sink);
    rx.ring_mut().deliver(b"x", source(), 0);
    let mut counted = CountingSink(0);
    let (outcome, allocations) =
        karyos_sys::alloc_count::count_allocations(|| rx.poll_rx(budget(), &mut counted));
    assert_eq!(outcome.delivered, 1);
    assert_eq!(allocations, 0);
}

struct CountingSink(u32);

impl RxHandler for CountingSink {
    fn datagram(&mut self, _: RxDatagram<'_>) -> ControlFlow<()> {
        self.0 = self.0.saturating_add(1);
        ControlFlow::Continue(())
    }

    fn dropped(&mut self, _: RxDrop) {}
}

#[test]
fn the_configuration_bounds_the_buffers() {
    let mut odd = config();
    odd.rx_buffers = NonZeroU16::new(12).unwrap_or(NonZeroU16::MIN);
    assert!(odd.validate().is_err());
    let mut few = config();
    few.rx_buffers = NonZeroU16::new(4).unwrap_or(NonZeroU16::MIN);
    assert!(few.validate().is_err());
    assert_eq!(UringRxConfig::default().buffer_len(), 1472);
    assert_eq!(UringRxConfig::default().cq_entries(), 512);
}

/// The real ring on this kernel; skipped where `io_uring` is denied unless
/// `KARYOS_URING_REQUIRED` is set.
#[cfg(all(feature = "uring", target_os = "linux"))]
#[expect(
    clippy::print_stderr,
    reason = "a skipped kernel test says why on the test output"
)]
mod kernel {
    use std::net::UdpSocket;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::uring::ring::OsRxRing;

    fn open(config: &UringRxConfig) -> Option<UringRx<OsRxRing>> {
        let local = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        match OsRxRing::open(local, config) {
            Ok(ring) => {
                let rx = UringRx::open(*config, InstanceId::new(NonZeroU32::MIN), ring);
                match rx {
                    Ok(rx) => Some(rx),
                    Err(error) => panic!("open: {error}"),
                }
            }
            Err(OpenError::Os {
                operation: "io_uring_setup",
                errno,
            }) if std::env::var_os("KARYOS_URING_REQUIRED").is_none() => {
                eprintln!("io_uring unavailable here (io_uring_setup errno {errno}); skipped");
                None
            }
            Err(error) => panic!("open: {error}"),
        }
    }

    fn poll_until<H: RxHandler>(
        rx: &mut UringRx<OsRxRing>,
        handler: &mut H,
        done: impl Fn(&H) -> bool,
    ) -> RxOutcome {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut last = rx.poll_rx(budget(), handler);
        while !done(handler) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
            last = rx.poll_rx(budget(), handler);
        }
        last
    }

    #[test]
    fn a_datagram_arrives_through_a_provided_buffer_and_a_reset_leaks_none() {
        let Some(mut rx) = open(&config()) else {
            return;
        };
        let Ok(to) = rx.ring().local_addr() else {
            panic!("local_addr");
        };
        let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0));
        let Ok(sender) = sender else {
            panic!("bind: {sender:?}");
        };
        let mut sink = Sink::default();
        rx.poll_rx(budget(), &mut sink);
        assert!(sender.send_to(b"karyos rx", to).is_ok());
        poll_until(&mut rx, &mut sink, |sink| !sink.datagrams.is_empty());
        let Ok(from) = sender.local_addr() else {
            panic!("local_addr");
        };
        assert_eq!(
            sink.datagrams,
            vec![(b"karyos rx".to_vec(), from, PathId::new(3))]
        );
        assert_eq!(rx.posted(), BUFFERS);

        let before = rx.posted();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut reset = rx.reset(budget());
        while reset.more && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
            reset = rx.reset(budget());
        }
        assert!(!reset.more, "the arm ended within the deadline");
        assert_eq!(reset.posted, before, "no buffer leaked by the reset");
        assert_eq!(rx.counters().reregistrations, 1);

        // The re-registered pool receives again.
        rx.poll_rx(budget(), &mut sink);
        assert!(sender.send_to(b"again", to).is_ok());
        poll_until(&mut rx, &mut sink, |sink| sink.datagrams.len() == 2);
        assert_eq!(
            sink.datagrams.get(1).map(|d| d.0.clone()),
            Some(b"again".to_vec())
        );
    }

    #[test]
    fn exhaustion_of_the_buffer_ring_is_counted() {
        let Some(mut rx) = open(&config()) else {
            return;
        };
        let Ok(to) = rx.ring().local_addr() else {
            panic!("local_addr");
        };
        let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0));
        let Ok(sender) = sender else {
            panic!("bind: {sender:?}");
        };
        let mut sink = CountingSink(0);
        rx.poll_rx(budget(), &mut sink);
        let datagrams = u32::from(BUFFERS) * 3;
        for _ in 0..datagrams {
            assert!(sender.send_to(b"flood", to).is_ok());
        }
        std::thread::sleep(Duration::from_millis(50));
        poll_until(&mut rx, &mut sink, |sink| sink.0 >= datagrams);
        assert!(
            rx.counters().no_buffers >= 1,
            "{BUFFERS} buffers for {datagrams} queued datagrams end the arm with -ENOBUFS"
        );
        assert_eq!(
            sink.0, datagrams,
            "re-arming recovers every queued datagram"
        );
        assert_eq!(rx.posted(), BUFFERS);
    }
}
