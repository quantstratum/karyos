// SPDX-License-Identifier: Apache-2.0

//! The AF_XDP endpoint over [`ScriptedXsk`], and over a real socket on the
//! loopback interface in generic mode with the `xdp` feature on Linux.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests and their helpers, as ADR-0007 allows"
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};

use super::*;
use crate::backend::{Authority, RxDropReason, TxOptions};
use crate::xdp::headers::{Addressing, write_headers};
use crate::xdp::scripted::ScriptedXsk;

const FRAME: u32 = 2048;
const TX: u16 = 8;
const RX: u32 = 8;
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

fn config(local: SocketAddr, local_mac: [u8; 6]) -> XdpEndpointConfig {
    XdpEndpointConfig {
        local,
        local_mac,
        mtu: 1500,
        max_datagram: nz(1408),
        max_queues: nz(2),
        max_routes: nz(2),
        max_batch: nz(16),
        hop_limit: 64,
        path: PathId::new(1),
    }
}

struct Fixture<O: XskOps> {
    endpoint: XdpEndpoint<O>,
    queue: TxQueueId,
}

fn fixture_over<O: XskOps>(
    xsk: O,
    local: SocketAddr,
    local_mac: [u8; 6],
    to: SocketAddr,
    next_hop: [u8; 6],
    max_pending: u16,
) -> Fixture<O> {
    let mut endpoint = XdpEndpoint::open(
        config(local, local_mac),
        InstanceId::new(NonZeroU32::MIN),
        xsk,
    )
    .unwrap();
    let route = endpoint.add_route(to, next_hop).unwrap();
    let queue = endpoint
        .open_queue(TxQueueConfig {
            authority: Authority::new(NonZeroU64::MIN),
            route,
            max_pending: nz(max_pending),
        })
        .unwrap();
    Fixture { endpoint, queue }
}

fn fixture() -> Fixture<ScriptedXsk> {
    fixture_over(
        ScriptedXsk::new(FRAME, TX, RX, 8),
        local(),
        MAC_LOCAL,
        peer(),
        MAC_PEER,
        TX,
    )
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

#[derive(Default, Debug)]
struct Events(Vec<TxEvent>);

impl CompletionHandler for Events {
    fn event(&mut self, event: TxEvent) {
        self.0.push(event);
    }
}

#[derive(Default)]
struct Sink {
    datagrams: Vec<(Vec<u8>, SocketAddr)>,
    drops: Vec<RxDrop>,
}

impl RxHandler for Sink {
    fn datagram(&mut self, datagram: RxDatagram<'_>) -> ControlFlow<()> {
        self.datagrams
            .push((datagram.bytes().to_vec(), datagram.source()));
        ControlFlow::Continue(())
    }

    fn dropped(&mut self, drop: RxDrop) {
        self.drops.push(drop);
    }
}

fn send<O: XskOps>(fixture: &mut Fixture<O>, payload: &[u8], token: u64) -> TxTicket {
    let mut frame = fixture
        .endpoint
        .claim_tx(fixture.queue, payload.len())
        .unwrap();
    frame.bytes_mut().copy_from_slice(payload);
    frame
        .commit(Commit {
            len: payload.len(),
            token: SenderToken::new(token),
            options: TxOptions::none(),
        })
        .map_err(|rejected| rejected.error)
        .unwrap()
}

fn request(queue: TxQueueId) -> FlushRequest {
    FlushRequest {
        queue,
        max_datagrams: nz(64),
        max_bytes: u32::MAX,
    }
}

fn budget() -> Budget {
    Budget::new(64, u64::MAX, 4)
}

fn drain(report: &mut TxReport) -> Vec<TxEntry> {
    std::iter::from_fn(|| report.pop_front()).collect()
}

#[test]
fn a_datagram_goes_out_with_its_headers_and_is_released_by_its_completion() {
    let mut f = fixture();
    let ticket = send(&mut f, b"karyos", 7);
    let mut report = TxReport::new();
    let outcome = f.endpoint.flush(request(f.queue), &mut Permit, &mut report);
    assert_eq!(outcome.stop, FlushStop::Exposed);
    assert_eq!(outcome.submitted, 1);
    assert_eq!(
        drain(&mut report)[0].outcome,
        TxItemOutcome::Submitted {
            release: Release::Deferred
        }
    );
    assert_eq!(
        f.endpoint.xsk().unwrap().kicks(),
        1,
        "need_wakeup is set: one kick"
    );
    let xsk = f.endpoint.xsk_mut().unwrap();
    xsk.transmit();
    let (_, bytes) = xsk.sent()[0].clone();
    // The kernel reads a valid frame: it validates back on the peer.
    match headers::validate(&bytes, peer(), MAC_PEER, 1408) {
        Checked::Datagram {
            offset,
            len,
            source,
        } => {
            assert_eq!(&bytes[offset..offset + len], b"karyos");
            assert_eq!(source, local());
        }
        other => panic!("{other:?}"),
    }
    let mut events = Events::default();
    f.endpoint.poll_completions(budget(), &mut events);
    assert_eq!(
        events.0,
        vec![TxEvent::Released {
            id: ticket.id(),
            token: SenderToken::new(7)
        }],
        "a release and no send result"
    );
    assert_eq!(f.endpoint.submitted(), 0);
}

#[test]
fn a_completion_that_is_not_a_release_is_not_treated_as_one() {
    let mut f = fixture();
    send(&mut f, b"one", 1);
    let mut report = TxReport::new();
    f.endpoint.flush(request(f.queue), &mut Permit, &mut report);
    drain(&mut report);
    // An address naming no Submitted frame: an RX frame's.
    let rx_frame = u64::from(TX) * u64::from(FRAME);
    f.endpoint.xsk_mut().unwrap().complete_addr(rx_frame);
    let mut events = Events::default();
    f.endpoint.poll_completions(budget(), &mut events);
    assert!(events.0.is_empty(), "nothing released");
    assert_eq!(f.endpoint.counters().invalid_completions, 1);
    assert_eq!(
        f.endpoint.xsk().unwrap().tx_kernel_owned(),
        1,
        "still the kernel's"
    );
    assert_eq!(
        f.endpoint.failure(),
        Some(BackendFailure::Invariant {
            operation: "xsk_completion"
        })
    );
    // The real completion of the quarantined frame infers no release.
    f.endpoint.xsk_mut().unwrap().transmit();
    f.endpoint.poll_completions(budget(), &mut events);
    assert!(events.0.is_empty());
    // A misaligned address is not a release either.
    let mut g = fixture();
    send(&mut g, b"two", 2);
    g.endpoint.flush(request(g.queue), &mut Permit, &mut report);
    drain(&mut report);
    g.endpoint.xsk_mut().unwrap().complete_addr(1);
    g.endpoint.poll_completions(budget(), &mut events);
    assert!(events.0.is_empty());
}

#[test]
fn a_kernel_owned_frame_is_never_claimed_or_written() {
    let mut f = fixture();
    let sent = send(&mut f, b"held", 1);
    let mut report = TxReport::new();
    f.endpoint.flush(request(f.queue), &mut Permit, &mut report);
    drain(&mut report);
    for token in 0..u64::from(TX - 1) {
        let ticket = send(&mut f, b"x", token);
        assert_ne!(ticket.id().slot(), sent.id().slot());
    }
    assert!(f.endpoint.claim_tx(f.queue, 1).is_err());
    assert_eq!(f.endpoint.xsk().unwrap().touches_while_owned(), 0);
}

fn frame_to_local(payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0_u8; 256];
    let header = headers::header_len(&local());
    frame[header..header + payload.len()].copy_from_slice(payload);
    let addressing = Addressing {
        source_mac: MAC_PEER,
        destination_mac: MAC_LOCAL,
        source: peer(),
        destination: local(),
        hop_limit: 64,
    };
    let len = write_headers(&mut frame, &addressing, payload.len()).unwrap();
    frame.truncate(len);
    frame
}

#[test]
fn a_received_frame_is_validated_lent_and_its_frame_reposted() {
    let mut f = fixture();
    let xsk = f.endpoint.xsk_mut().unwrap();
    assert!(xsk.receive(&frame_to_local(b"inbound")));
    let mut corrupt = frame_to_local(b"bad");
    let last = corrupt.len() - 1;
    corrupt[last] ^= 0xff;
    assert!(xsk.receive(&corrupt));
    xsk.push_rx_desc(RxDesc { addr: 0, len: 64 });
    let mut sink = Sink::default();
    let outcome = f.endpoint.poll_rx(budget(), &mut sink);
    assert_eq!(outcome.delivered, 1);
    assert_eq!(outcome.dropped, 1);
    assert_eq!(sink.datagrams, vec![(b"inbound".to_vec(), peer())]);
    assert_eq!(sink.drops[0].reason, RxDropReason::Checksum);
    assert_eq!(
        f.endpoint.counters().invalid_rx,
        1,
        "a TX frame address is never lent"
    );
    assert_eq!(
        f.endpoint.xsk().unwrap().rx_posted(),
        RX,
        "every frame back in the fill ring"
    );
}

#[test]
fn teardown_reports_unknown_and_leaves_no_owned_frame() {
    let mut f = fixture();
    send(&mut f, b"sent", 1);
    let mut report = TxReport::new();
    f.endpoint.flush(request(f.queue), &mut Permit, &mut report);
    drain(&mut report);
    send(&mut f, b"pending", 2);
    let teardown = f.endpoint.retire(&mut report);
    assert_eq!(
        teardown,
        Teardown::Complete {
            returned: 1,
            unknown: 1,
            kernel_owned_frames: 1
        }
    );
    let outcomes: Vec<_> = drain(&mut report)
        .into_iter()
        .map(|entry| entry.outcome)
        .collect();
    assert_eq!(
        outcomes,
        vec![
            TxItemOutcome::Returned {
                reason: ReturnReason::Reset
            },
            TxItemOutcome::Unknown
        ]
    );
    assert!(f.endpoint.xsk().is_none(), "the socket core is gone");
    assert!(matches!(
        f.endpoint.claim_tx(f.queue, 1),
        Err(ClaimError::NotActive)
    ));
}

#[test]
fn retire_reports_quarantined_items_unknown_and_refuses_new_work() {
    let mut f = fixture();
    send(&mut f, b"one", 1);
    let mut report = TxReport::new();
    f.endpoint.flush(request(f.queue), &mut Permit, &mut report);
    drain(&mut report);
    // An invalid completion quarantines the submitted item.
    f.endpoint.xsk_mut().unwrap().complete_addr(1);
    f.endpoint
        .poll_completions(budget(), &mut Events::default());
    // A full report keeps the retirement going: nothing new is accepted.
    let teardown = f.endpoint.retire(&mut report);
    assert_eq!(
        teardown,
        Teardown::Complete {
            returned: 0,
            unknown: 1,
            kernel_owned_frames: 1
        }
    );
    assert_eq!(drain(&mut report)[0].outcome, TxItemOutcome::Unknown);
}

#[test]
fn rx_admits_only_what_fits_the_byte_and_op_budget() {
    let mut f = fixture();
    let xsk = f.endpoint.xsk_mut().unwrap();
    for _ in 0..3 {
        assert!(xsk.receive(&frame_to_local(b"0123456789")));
    }
    let mut sink = Sink::default();
    let none = f.endpoint.poll_rx(Budget::new(64, u64::MAX, 0), &mut sink);
    assert_eq!(none.stop, RxStop::Budget);
    assert_eq!(none.delivered, 0);
    // Room for one largest payload (1408) but not two.
    let one = f.endpoint.poll_rx(Budget::new(64, 1417, 4), &mut sink);
    assert_eq!(one.delivered, 1);
    assert!(one.spent.bytes <= 1417);
}

#[test]
fn the_frame_bound_of_design_6_1_is_checked() {
    let mut big = config(local(), MAC_LOCAL);
    // 42 header bytes and the 256 byte RX headroom in a 2048 byte frame.
    big.max_datagram = nz(2048 - 256 - 42 + 1);
    big.mtu = 9000;
    assert!(
        XdpEndpoint::open(
            big,
            InstanceId::new(NonZeroU32::MIN),
            ScriptedXsk::new(FRAME, TX, RX, 8)
        )
        .is_err()
    );
    let mut mtu = config(local(), MAC_LOCAL);
    mtu.mtu = 1000;
    assert!(
        XdpEndpoint::open(
            mtu,
            InstanceId::new(NonZeroU32::MIN),
            ScriptedXsk::new(FRAME, TX, RX, 8)
        )
        .is_err()
    );
}

#[test]
fn flush_completions_and_rx_do_not_allocate() {
    let mut f = fixture();
    send(&mut f, b"a", 1);
    let mut report = TxReport::new();
    let (_, allocations) = karyos_sys::alloc_count::count_allocations(|| {
        f.endpoint.flush(request(f.queue), &mut Permit, &mut report)
    });
    assert_eq!(allocations, 0);
    drain(&mut report);
    f.endpoint.xsk_mut().unwrap().transmit();
    let mut events = Events(Vec::with_capacity(4));
    let (_, allocations) = karyos_sys::alloc_count::count_allocations(|| {
        f.endpoint.poll_completions(budget(), &mut events)
    });
    assert_eq!(allocations, 0);
    f.endpoint
        .xsk_mut()
        .unwrap()
        .receive(&frame_to_local(b"in"));
    let mut sink = Sink {
        datagrams: Vec::with_capacity(4),
        drops: Vec::with_capacity(4),
    };
    sink.datagrams.push((Vec::with_capacity(8), peer()));
    sink.datagrams.clear();
    let mut counting = Counting(0);
    let (_, allocations) =
        karyos_sys::alloc_count::count_allocations(|| f.endpoint.poll_rx(budget(), &mut counting));
    assert_eq!(allocations, 0);
    assert_eq!(counting.0, 1);
}

struct Counting(u32);

impl RxHandler for Counting {
    fn datagram(&mut self, _: RxDatagram<'_>) -> ControlFlow<()> {
        self.0 += 1;
        ControlFlow::Continue(())
    }

    fn dropped(&mut self, _: RxDrop) {}
}

/// The real socket on `lo`, generic XDP: a datagram the endpoint sends to
/// its own address leaves through the TX ring, loops back, is redirected
/// by the program to the socket and arrives through the RX ring. Needs `CAP_NET_RAW`, `CAP_NET_ADMIN`,
/// `CAP_BPF`; skipped where missing unless `KARYOS_XDP_REQUIRED` is set.
#[cfg(all(feature = "xdp", target_os = "linux"))]
#[expect(
    clippy::print_stderr,
    reason = "a skipped kernel test says why on the test output"
)]
mod kernel {
    use std::net::UdpSocket;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::xdp::attach::{AttachMode, XdpAttachment};
    use crate::xdp::ring::{OsXsk, XskSizes};

    /// The kernel tests that map a UMEM run one at a time: the UMEM byte
    /// count they check is process wide.
    static UMEM: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn umem_lock() -> std::sync::MutexGuard<'static, ()> {
        UMEM.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn required() -> bool {
        std::env::var_os("KARYOS_XDP_REQUIRED").is_some()
    }

    #[test]
    fn a_datagram_loops_through_the_copy_mode_backend_and_teardown_releases_the_umem() {
        let _umem = umem_lock();
        let ifindex = rustix::net::netdevice::name_to_index(
            rustix::net::socket(
                rustix::net::AddressFamily::INET,
                rustix::net::SocketType::DGRAM,
                None,
            )
            .unwrap(),
            "lo",
        )
        .unwrap();
        let local = SocketAddr::from((Ipv4Addr::LOCALHOST, 47_001));
        // The port reservation socket of design 7.6.
        let reservation = UdpSocket::bind(local).unwrap();
        let sizes = XskSizes {
            frame_len: FRAME,
            tx_frames: TX,
            rx_frames: RX,
        };
        let xsk = match OsXsk::open(ifindex, 0, sizes) {
            Ok(xsk) => xsk,
            Err(error) if !required() => {
                eprintln!("AF_XDP unavailable here ({error}); skipped");
                return;
            }
            Err(error) => panic!("open: {error}"),
        };
        let mut attachment = match XdpAttachment::attach(ifindex, AttachMode::Generic, &[local]) {
            Ok(attachment) => attachment,
            Err(error) if !required() => {
                eprintln!("XDP attach unavailable here ({error}); skipped");
                return;
            }
            Err(error) => panic!("attach: {error}"),
        };
        assert!(attachment.is_linked(), "a bpf_link, never a netlink attach");
        attachment.set_socket(0, xsk.socket()).unwrap();
        let umem = xsk.umem_len();
        assert!(umem > 0);
        // lo has the all zero MAC.
        let mut f = fixture_over(xsk, local, [0; 6], local, [0; 6], TX);
        // To ourselves: TX ring, lo, the program, the RX ring.
        let ticket = send(&mut f, b"through xdp", 1);
        let mut report = TxReport::new();
        let outcome = f.endpoint.flush(request(f.queue), &mut Permit, &mut report);
        assert_eq!(outcome.submitted, 1, "{outcome:?}");
        drain(&mut report);
        let mut events = Events::default();
        let mut sink = Sink::default();
        let deadline = Instant::now() + Duration::from_secs(5);
        while (events.0.is_empty() || sink.datagrams.is_empty()) && Instant::now() < deadline {
            f.endpoint.poll_completions(budget(), &mut events);
            f.endpoint.poll_rx(budget(), &mut sink);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(
            events.0,
            vec![TxEvent::Released {
                id: ticket.id(),
                token: SenderToken::new(1)
            }]
        );
        assert_eq!(
            sink.datagrams,
            vec![(b"through xdp".to_vec(), local)],
            "drops: {:?}",
            sink.drops
        );

        // A frame the backend sends on `lo` to an address the program
        // passes is transmitted and released, but in generic mode the
        // kernel does not deliver such a self-transmitted skb to an
        // ordinary socket (no IP or UDP error counter moves): the kernel
        // stack's acceptance of these headers is checked on a veth pair
        // with the release work of #643, not here.
        // Teardown: no frame owned, the UMEM unmapped.
        let before = karyos_sys::xsk_map::live_umem_bytes();
        assert!(before >= u64::try_from(umem).unwrap());
        attachment.unset_socket(0).unwrap();
        let teardown = f.endpoint.retire(&mut report);
        assert!(
            matches!(
                teardown,
                Teardown::Complete {
                    kernel_owned_frames: 0,
                    unknown: 0,
                    ..
                }
            ),
            "{teardown:?}"
        );
        assert_eq!(
            karyos_sys::xsk_map::live_umem_bytes(),
            before - u64::try_from(umem).unwrap(),
            "the UMEM is unmapped by teardown"
        );
        drop(attachment);
        drop(reservation);
    }

    /// Minimal rtnetlink writes for the test environment only: a veth pair,
    /// links up, IPv4 addresses. Never part of the backend, whose adapter
    /// is read-only (ADR-0038).
    mod veth {
        use rustix::net::netlink::SocketAddrNetlink;
        use rustix::net::{AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType};

        fn attr(kind: u16, payload: &[u8]) -> Vec<u8> {
            let mut out = Vec::new();
            out.extend_from_slice(&u16::try_from(4 + payload.len()).unwrap().to_ne_bytes());
            out.extend_from_slice(&kind.to_ne_bytes());
            out.extend_from_slice(payload);
            while out.len() % 4 != 0 {
                out.push(0);
            }
            out
        }

        fn ifinfo(index: i32, flags: u32, change: u32) -> Vec<u8> {
            let mut out = vec![0_u8; 16];
            out[4..8].copy_from_slice(&index.to_ne_bytes());
            out[8..12].copy_from_slice(&flags.to_ne_bytes());
            out[12..16].copy_from_slice(&change.to_ne_bytes());
            out
        }

        fn request(kind: u16, flags: u16, payload: &[u8]) -> Result<(), i32> {
            let socket = rustix::net::socket_with(
                AddressFamily::NETLINK,
                SocketType::RAW,
                SocketFlags::CLOEXEC,
                None,
            )
            .map_err(|errno| errno.raw_os_error())?;
            let mut message = Vec::new();
            message.extend_from_slice(&u32::try_from(16 + payload.len()).unwrap().to_ne_bytes());
            message.extend_from_slice(&kind.to_ne_bytes());
            message.extend_from_slice(&(flags | 0x1 | 0x4).to_ne_bytes());
            message.extend_from_slice(&1_u32.to_ne_bytes());
            message.extend_from_slice(&0_u32.to_ne_bytes());
            message.extend_from_slice(payload);
            rustix::net::sendto(
                &socket,
                &message,
                SendFlags::empty(),
                &SocketAddrNetlink::new(0, 0),
            )
            .map_err(|errno| errno.raw_os_error())?;
            let mut buffer = [0_u8; 4096];
            let (len, _) = rustix::net::recv(&socket, &mut buffer[..], RecvFlags::empty())
                .map_err(|errno| errno.raw_os_error())?;
            if len >= 20 && u16::from_ne_bytes([buffer[4], buffer[5]]) == 2 {
                let error = i32::from_ne_bytes(buffer[16..20].try_into().unwrap());
                if error != 0 {
                    return Err(-error);
                }
            }
            Ok(())
        }

        /// Creates `a` and `b`, brings both up and gives each an address
        /// of `10.77.0.0/24`.
        pub fn create(a: &str, b: &str, a_host: u8, b_host: u8) -> Result<(), i32> {
            let mut peer = ifinfo(0, 0, 0);
            peer.extend(attr(3, format!("{b}\0").as_bytes()));
            let info = [attr(1, b"veth"), attr(2 | 0x8000, &attr(1 | 0x8000, &peer))].concat();
            let mut link = ifinfo(0, 0, 0);
            link.extend(attr(3, format!("{a}\0").as_bytes()));
            link.extend(attr(18 | 0x8000, &info));
            request(16, 0x400 | 0x200, &link)?;
            for (name, host) in [(a, a_host), (b, b_host)] {
                let index = rustix::net::netdevice::name_to_index(
                    rustix::net::socket(AddressFamily::INET, SocketType::DGRAM, None)
                        .map_err(|e| e.raw_os_error())?,
                    name,
                )
                .map_err(|errno| errno.raw_os_error())?;
                request(16, 0, &ifinfo(i32::try_from(index).unwrap(), 1, 1))?;
                let mut address = vec![2_u8, 24, 0, 0];
                address.extend_from_slice(&index.to_ne_bytes());
                address.extend(attr(2, &[10, 77, 0, host]));
                address.extend(attr(1, &[10, 77, 0, host]));
                request(20, 0x400 | 0x200, &address)?;
            }
            Ok(())
        }
    }

    /// The kernel stack accepts the frames the backend writes: on a veth
    /// pair, a datagram leaves `kx0`'s TX ring and an ordinary UDP socket
    /// bound on `kx1` receives it (the check `lo` cannot make, karyos#642).
    #[test]
    fn the_kernel_stack_accepts_the_headers_the_backend_writes() {
        let _umem = umem_lock();
        if let Err(errno) = veth::create("kx0", "kx1", 1, 2) {
            if required() {
                panic!("veth setup failed with errno {errno}");
            }
            eprintln!("veth setup unavailable here (errno {errno}); skipped");
            return;
        }
        let kx0 = rustix::net::netdevice::name_to_index(
            rustix::net::socket(
                rustix::net::AddressFamily::INET,
                rustix::net::SocketType::DGRAM,
                None,
            )
            .unwrap(),
            "kx0",
        )
        .unwrap();
        let (Some(mac0), Some(mac1)) = (
            crate::xdp::netlink::link_mac("kx0"),
            crate::xdp::netlink::link_mac("kx1"),
        ) else {
            panic!("sysfs MACs");
        };
        let receiver = UdpSocket::bind((Ipv4Addr::new(10, 77, 0, 2), 47_002)).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let sizes = XskSizes {
            frame_len: FRAME,
            tx_frames: TX,
            rx_frames: RX,
        };
        let xsk = OsXsk::open(kx0, 0, sizes).unwrap();
        // A source outside the host's addresses: a frame arriving with a
        // local source address would be dropped as martian.
        let source = SocketAddr::from((Ipv4Addr::new(10, 77, 0, 9), 47_003));
        let to = receiver.local_addr().unwrap();
        let mut f = fixture_over(xsk, source, mac0, to, mac1, TX);
        let ticket = send(&mut f, b"kernel accepts", 1);
        let mut report = TxReport::new();
        f.endpoint.flush(request(f.queue), &mut Permit, &mut report);
        drain(&mut report);
        let mut events = Events::default();
        for _ in 0..200 {
            f.endpoint.poll_completions(budget(), &mut events);
            if !events.0.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(
            events.0,
            vec![TxEvent::Released {
                id: ticket.id(),
                token: SenderToken::new(1)
            }]
        );
        let mut buffer = [0_u8; 64];
        let (len, from) = receiver.recv_from(&mut buffer).unwrap();
        assert_eq!(&buffer[..len], b"kernel accepts");
        assert_eq!(from, source);
    }

    /// A real failed bind (an interface that does not exist) fails the
    /// configuration under either choice: the explicit copy-mode bind is
    /// never a fallback trigger (SPEC §16.3).
    #[test]
    fn a_real_failed_bind_fails_under_both_choices() {
        use crate::xdp::select::{XdpChoice, select};
        let _umem = umem_lock();
        let sizes = XskSizes {
            frame_len: FRAME,
            tx_frames: TX,
            rx_frames: RX,
        };
        let missing = 0x7fff_fff0;
        for choice in [XdpChoice::AfXdp, XdpChoice::AfXdpOrSockets] {
            let selected = select(choice, || OsXsk::open(missing, 0, sizes), || Ok(()));
            assert!(
                matches!(
                    selected,
                    Err(crate::backend::OpenError::Os {
                        operation: "xsk_bind",
                        ..
                    })
                ),
                "{choice:?}: {:?}",
                selected.map(|_| ())
            );
        }
    }

    /// Under Docker's default capabilities (no `CAP_BPF`, no
    /// `CAP_NET_ADMIN`; the default job of CI) loading the program is
    /// denied with `EPERM`, reported as a denial, never as absence.
    #[test]
    fn a_missing_privilege_is_reported_as_denied() {
        if std::env::var_os("KARYOS_XDP_EXPECT_DENIED").is_none() {
            return;
        }
        let attached = XdpAttachment::attach(1, AttachMode::Generic, &[]);
        let Err(error) = attached else {
            panic!("the program loaded without the BPF capabilities");
        };
        let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&error);
        let mut denied = false;
        while let Some(current) = source {
            if let Some(io) = current.downcast_ref::<std::io::Error>() {
                denied |= io.raw_os_error() == Some(1);
            }
            source = current.source();
        }
        assert!(
            denied || error.to_string().contains("Operation not permitted"),
            "{error}"
        );
    }
}
