// SPDX-License-Identifier: Apache-2.0

//! ADR-0127 at the shard set: each datagram received once across shards,
//! the shared open-rate counters under concurrent charges, key age across
//! queued work, per-lane order and cancellation, the in-flight cap, every
//! full queue, round-robin service, shutdown, withdrawal and allocations.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::cell::Cell;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Barrier;

use karyos_protocol::protection::aes_gcm_siv::{KeyContext, PublicationIdentity, Salt};
use karyos_sys::alloc_count::count_allocations;

use super::*;
use crate::wire_enc::{
    COMMITTED_OPENS_PER_S, ChannelKeys, EncOpener, EncSealer, KEY_AGE_NS, MAX_SEALED,
    SCRATCH_OPENS_PER_S, SECOND_NS, bootstrap_complete, scratch_erased,
};
use crate::wire_keys::{KEY_LEN, parse};

thread_local! {
    static NOW: Cell<u64> = const { Cell::new(1_000 * SECOND_NS) };
}

fn clock() -> u64 {
    NOW.with(Cell::get)
}

fn keys(fill: u8) -> ChannelKeys {
    let secret: String = (0..KEY_LEN).map(|_| format!("{fill:02x}")).collect();
    let text = format!(
        "format=karyos-wire-key-v1\nkey_id=3\nfile_epoch=1\npurpose=channel\nprofile_id=16\nnot_before=2026-11-01T00:00:00Z\nnot_after=2027-01-30T00:00:00Z\nsecret={secret}\nchannel_id=7\nstream_id=6\n"
    );
    ChannelKeys::new(&[&parse("3-1.key", text.as_bytes()).unwrap()]).unwrap()
}

fn context() -> KeyContext {
    KeyContext {
        domain: Domain::Sender,
        key_epoch: 1,
        party_epoch: 0,
        session_id: 9,
        stream_id: 6,
        publication: PublicationIdentity {
            driver_id: [1; 16],
            registration_id: 7,
            incarnation: 1,
        },
        receiver: None,
        salt: Salt::Challenge {
            receiver_boot_id: [2; 16],
            nonce: [3; 16],
        },
    }
}

/// The next epoch of [`context`]: its next `party_epoch`.
fn next_context() -> KeyContext {
    KeyContext {
        party_epoch: 1,
        ..context()
    }
}

/// The domain 5 context of [`context`]'s publication and alias.
fn setup_context() -> KeyContext {
    KeyContext {
        domain: Domain::Setup,
        salt: Salt::Empty,
        ..context()
    }
}

/// `count` datagrams of one DATA frame each, sealed under the channel key
/// of `fill`: genuine under 0x11, forged under any other.
fn sealed(fill: u8, count: usize) -> Vec<Vec<u8>> {
    sealed_in(fill, context(), 1, count)
}

/// `count` datagrams of one frame of `frame_type` each, sealed under the
/// channel key of `fill` in `context`.
fn sealed_in(fill: u8, context: KeyContext, frame_type: u16, count: usize) -> Vec<Vec<u8>> {
    let mut sealer = EncSealer::new(&keys(fill), None, context, clock).unwrap();
    (0..count)
        .map(|i| {
            let mut bytes = vec![0_u8; MAX_SEALED];
            let mut frame = [u8::try_from(i % 251).unwrap(); 32];
            frame[..4].copy_from_slice(&32_i32.to_le_bytes());
            frame[4] = 1;
            frame[5] = 0;
            frame[6..8].copy_from_slice(&frame_type.to_le_bytes());
            bytes[..32].copy_from_slice(&frame);
            let length = sealer.seal(&mut bytes, 32).unwrap();
            bytes.truncate(length);
            bytes
        })
        .collect()
}

fn opener() -> EncOpener {
    EncOpener::new(&keys(0x11), None, context(), clock()).unwrap()
}

fn source() -> SocketAddr {
    "127.0.0.1:4000".parse().unwrap()
}

fn alias() -> Alias {
    Alias {
        session_id: 9,
        stream_id: 6,
    }
}

/// A set of `lanes` lanes of `slots` with no thread: the test thread is
/// the shard, the verifier and the role.
fn detached(lanes: usize, slots: u16, ring: u16) -> ShardSet<u32> {
    ShardSet {
        shared: Arc::new(
            SetShared::new(
                lanes,
                (slots, ring),
                usize::from(karyos_io::sockets::endpoint::MAX_DATAGRAM),
                1,
                (4, 4, 4),
            )
            .unwrap(),
        ),
        shards: Vec::new(),
        verifiers: Vec::new(),
    }
}

/// Publishes `opener`'s keys for the stream and binding of [`context`],
/// with `rate` the channel's counters; returns the shared counts.
fn bind(set: &ShardSet<u32>, opener: &mut EncOpener, rate: &OpenRate) -> Arc<SharedRejections> {
    bind_share(set, opener, rate, &Arc::new(OpenerShare::default()))
}

/// [`bind`], the stream's domain 5 jobs leased under `share`.
fn bind_share(
    set: &ShardSet<u32>,
    opener: &mut EncOpener,
    rate: &OpenRate,
    share: &Arc<OpenerShare>,
) -> Arc<SharedRejections> {
    let counts = Arc::new(SharedRejections::default());
    let view = opener.shard_view(clock()).unwrap();
    set.publish(|snapshot| {
        snapshot.clear();
        snapshot.complete = true;
        snapshot.streams.push(StreamView {
            stream_id: 6,
            rate: rate.clone(),
            counts: Arc::clone(&counts),
            setup: keys(0x11).shard_setup(),
            setup_share: Arc::clone(share),
        });
        snapshot.bindings.push(BindingView {
            tag: 1,
            alias: alias(),
            source: source(),
            opener: view,
        });
    });
    set.set_clock(clock());
    counts
}

/// Runs the shard path on `bytes` in lane `lane`.
fn shard_take(set: &ShardSet<u32>, lane: usize, bytes: &[u8]) -> Step {
    shard_take_from(set, lane, bytes, source())
}

/// Runs the shard path on `bytes` from `from` in lane `lane`.
fn shard_take_from(set: &ShardSet<u32>, lane: usize, bytes: &[u8], from: SocketAddr) -> Step {
    let snapshot = set.shared.snapshot.read().unwrap();
    let now = set.shared.clock.0.load(Ordering::Acquire);
    set.shared.take(lane, &snapshot, bytes, from, now)
}

/// Whether lane `lane`'s slot `at` holds a derived scratch key, and
/// whether its key is at rest (erased).
fn slot_key(set: &ShardSet<u32>, lane: usize, at: u64) -> (bool, bool) {
    let job = set.shared.lanes[lane].cell(at).unwrap().lock();
    (job.derived, scratch_erased(&job.scratch))
}

fn counted(counts: &SharedRejections, reason: EncRejection) -> u64 {
    counts.merged(EncRejections::default()).get(reason)
}

/// A receive handle on a plain UDP socket, one `recv_from` per result,
/// that marks `closed` when dropped.
struct TestSocket {
    socket: UdpSocket,
    closed: Arc<AtomicBool>,
}

impl SharedRecv for TestSocket {
    fn recv_batch(&mut self, slab: &mut [u8], stride: usize, results: &mut [RecvResult]) -> usize {
        let mut written = 0;
        for (buffer, result) in slab.chunks_exact_mut(stride).zip(results.iter_mut()) {
            written += 1;
            match self.socket.recv_from(buffer) {
                Ok((len, from)) => {
                    *result = RecvResult::Datagram {
                        len,
                        truncated: None,
                        source: Some(from),
                    }
                }
                Err(_) => {
                    *result = RecvResult::Error(Errno::AGAIN);
                    break;
                }
            }
        }
        written
    }
}

impl Drop for TestSocket {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::SeqCst);
    }
}

/// `shards` handles on one bound nonblocking socket, and its address.
fn sockets(shards: usize) -> (Vec<Box<dyn SharedRecv>>, SocketAddr, Vec<Arc<AtomicBool>>) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_nonblocking(true).unwrap();
    let address = socket.local_addr().unwrap();
    let mut closed = Vec::new();
    let handles = (0..shards)
        .map(|_| {
            let flag = Arc::new(AtomicBool::new(false));
            closed.push(Arc::clone(&flag));
            Box::new(TestSocket {
                socket: socket.try_clone().unwrap(),
                closed: flag,
            }) as Box<dyn SharedRecv>
        })
        .collect();
    (handles, address, closed)
}

#[test]
fn a_shard_config_is_validated() {
    assert_eq!(EncShardConfig::default().shards, 0, "off by default");
    assert_eq!(EncShardConfig::default().validate(), Ok(()));
    let config = |shards, ring| EncShardConfig { shards, ring };
    assert_eq!(
        config(MAX_ENC_SHARDS, MAX_ENC_SHARD_RING).validate(),
        Ok(())
    );
    assert!(config(MAX_ENC_SHARDS + 1, 64).validate().is_err());
    assert!(config(2, 0).validate().is_err());
    assert!(config(2, MAX_ENC_SHARD_RING + 1).validate().is_err());
}

/// Decision 1: four shards read one socket concurrently; every datagram
/// sent reaches exactly one of them.
#[test]
fn each_datagram_is_received_exactly_once_across_shards() {
    const SENT: u32 = 20_000;
    const CHUNK: u32 = 100;
    let (handles, address, _closed) = sockets(4);
    let set = ShardSet::<u32>::new(
        EncShardConfig {
            shards: 4,
            ring: MAX_ENC_SHARD_RING,
        },
        EncVerifyConfig {
            verifiers: 1,
            slots: 16,
        },
        handles,
        1408,
        (4, 4, 4),
    )
    .unwrap();
    assert_eq!(set.shards(), 4);
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut seen = vec![0_u8; SENT as usize];
    let mut buffer = vec![0_u8; 1409];
    let mut got = 0_u32;
    let mut per_shard = [0_u32; 4];
    for chunk in 0..SENT / CHUNK {
        for index in chunk * CHUNK..(chunk + 1) * CHUNK {
            let mut datagram = [0_u8; 64];
            datagram[..4].copy_from_slice(&index.to_le_bytes());
            sender.send_to(&datagram, address).unwrap();
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while got < (chunk + 1) * CHUNK {
            assert!(Instant::now() < deadline, "only {got} received");
            for (lane, count) in per_shard.iter_mut().enumerate() {
                while let Some((len, _)) = set.pop_other(lane, &mut buffer) {
                    assert_eq!(len, 64);
                    let index = u32::from_le_bytes(buffer[..4].try_into().unwrap());
                    seen[index as usize] += 1;
                    *count += 1;
                    got += 1;
                }
            }
        }
    }
    assert!(seen.iter().all(|count| *count == 1), "each exactly once");
    let stats = set.stats();
    assert_eq!(stats.received, u64::from(SENT));
    assert_eq!(stats.forwarded, u64::from(SENT));
    assert_eq!(stats.ring_full, 0);
    assert_eq!(per_shard.iter().sum::<u32>(), SENT);
}

/// Decision 3: one shared counter per budget. Threads charging it
/// concurrently get exactly the budget's charges; when the interval moves
/// under them, the compare-and-swap starts it once and loses no charge;
/// committed and scratch charges mixed stay on their own budgets.
#[test]
fn the_shared_open_rate_holds_under_concurrent_rollover_and_mixed_charges() {
    let threads = 8;
    let second = 5_000 * SECOND_NS;
    // The last 1 000 committed charges of an interval, raced for.
    let rate = OpenRate::preset(KeyKind::Committed, second, COMMITTED_OPENS_PER_S - 1_000);
    let charge = |kind, at, each: u32| {
        let barrier = Barrier::new(threads);
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..threads)
                .map(|_| {
                    let (rate, barrier) = (rate.clone(), &barrier);
                    scope.spawn(move || {
                        barrier.wait();
                        (0..each).filter(|_| rate.charge(kind, at).is_ok()).count()
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .sum::<usize>()
        })
    };
    assert_eq!(charge(KeyKind::Committed, second, 500), 1_000);
    assert_eq!(rate.charged(KeyKind::Committed), COMMITTED_OPENS_PER_S);
    // The rollover, raced: every thread's first charge sees the old
    // interval; exactly one starts the new one and none is lost.
    assert_eq!(charge(KeyKind::Committed, second + SECOND_NS, 500), 4_000);
    assert_eq!(rate.charged(KeyKind::Committed), 4_000);
    // Mixed: the scratch budget fills on its own; the committed count is
    // untouched by it, and still charges.
    let scratch_each = SCRATCH_OPENS_PER_S / 4;
    let mixed = std::thread::scope(|scope| {
        let scratch: Vec<_> = (0..threads)
            .map(|_| {
                let rate = rate.clone();
                scope.spawn(move || {
                    (0..scratch_each)
                        .filter(|_| rate.charge(KeyKind::Scratch, second + SECOND_NS).is_ok())
                        .count()
                })
            })
            .collect();
        let committed: Vec<_> = (0..threads)
            .map(|_| {
                let rate = rate.clone();
                scope.spawn(move || {
                    (0..1_000)
                        .filter(|_| rate.charge(KeyKind::Committed, second + SECOND_NS).is_ok())
                        .count()
                })
            })
            .collect();
        let scratch: usize = scratch
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .sum();
        let committed: usize = committed
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .sum();
        (scratch, committed)
    });
    assert_eq!(mixed, (SCRATCH_OPENS_PER_S as usize, 8_000));
    assert_eq!(rate.charged(KeyKind::Scratch), SCRATCH_OPENS_PER_S);
    assert_eq!(rate.charged(KeyKind::Committed), 12_000);
}

/// Decisions 2 and 4: a shard refuses a key past its original deadline
/// before dispatch, and a verifier refuses a queued job whose key crossed
/// it, without an open, counted as key age.
#[test]
fn key_age_crossing_while_work_is_queued_is_refused_without_an_open() {
    let set = detached(1, 8, 4);
    let mut opener = opener();
    let rate = OpenRate::default();
    let counts = bind(&set, &mut opener, &rate);
    let genuine = sealed(0x11, 2);
    // Dispatched inside the age.
    assert!(matches!(shard_take(&set, 0, &genuine[0]), Step::Dispatched));
    // The clock crosses the deadline while the job is queued.
    let deadline = clock() + KEY_AGE_NS;
    set.set_clock(deadline + 1);
    assert!(set.shared.lanes[0].run_one(&set.shared.clock.0));
    let mut plain = [0xAA_u8; MAX_PLAINTEXT];
    let done = set.take(0, &mut plain).unwrap();
    assert_eq!(done.outcome, Outcome::Failed(EncRejection::KeyAge));
    assert!(plain.iter().all(|byte| *byte == 0xAA), "nothing opened");
    drop(done);
    // A shard past the deadline refuses before dispatch.
    assert!(matches!(shard_take(&set, 0, &genuine[1]), Step::Refused));
    assert_eq!(counted(&counts, EncRejection::KeyAge), 1);
    assert_eq!(set.in_flight(), 0);
    assert_eq!(opener.leases(), 0, "every lease back once");
}

/// Decision 5 and ADR-0126 decisions 4 and 5 across shards: a delayed job
/// holds back only its own lane's later results; another lane's are
/// consumed; cancellation ends the queued ones in every lane, and every
/// lease returns exactly once.
#[test]
fn delayed_completion_and_cancellation_hold_per_lane_across_shards() {
    let set = detached(2, 8, 4);
    let mut opener = opener();
    let rate = OpenRate::default();
    let _counts = bind(&set, &mut opener, &rate);
    let genuine = sealed(0x11, 5);
    for bytes in &genuine[..3] {
        assert!(matches!(shard_take(&set, 0, bytes), Step::Dispatched));
    }
    for bytes in &genuine[3..] {
        assert!(matches!(shard_take(&set, 1, bytes), Step::Dispatched));
    }
    assert_eq!(opener.leases(), 5);
    // Lane 0's second job and lane 1's first are verified; lane 0's first
    // is delayed.
    let clock_word = &set.shared.clock.0;
    assert!(run(set.shared.lanes[0].cell(1).unwrap(), clock_word));
    assert!(run(set.shared.lanes[1].cell(0).unwrap(), clock_word));
    let mut plain = [0_u8; MAX_PLAINTEXT];
    assert!(set.take(0, &mut plain).is_none(), "held back by its first");
    let other = set.take(1, &mut plain).unwrap();
    assert!(matches!(other.outcome, Outcome::Verified(_)));
    assert_eq!(other.context.ticket.seq, 3, "lane 1 in its own order");
    drop(other);
    // Cancellation: lane 0's first and third, lane 1's second.
    assert_eq!(set.cancel_all(), 3);
    let outcomes: Vec<_> = core::iter::from_fn(|| set.take(0, &mut plain))
        .map(|done| (done.context.ticket.seq, done.outcome))
        .collect();
    assert_eq!(outcomes.len(), 3);
    assert_eq!(outcomes[0], (0, Outcome::Cancelled));
    assert!(matches!(outcomes[1], (1, Outcome::Verified(_))));
    assert_eq!(outcomes[2], (2, Outcome::Cancelled));
    assert_eq!(
        set.take(1, &mut plain).map(|done| done.outcome),
        Some(Outcome::Cancelled)
    );
    assert_eq!(opener.leases(), 0, "each lease returned exactly once");
    assert_eq!(set.in_flight(), 0);
}

/// Decision 5: at most the replay window of jobs is in flight across the
/// lanes, so an older datagram in flight is never displaced from the
/// window by newer ones committed meanwhile; the next is dropped before
/// its open and counted.
#[test]
fn the_slot_cap_keeps_in_flight_work_within_the_replay_window() {
    let set = detached(2, 1_024, 4);
    let mut opener = opener();
    let rate = OpenRate::default();
    let counts = bind(&set, &mut opener, &rate);
    let genuine = sealed(0x11, 1_025);
    for (at, bytes) in genuine[..1_024].iter().enumerate() {
        assert!(matches!(shard_take(&set, at % 2, bytes), Step::Dispatched));
    }
    assert_eq!(set.in_flight(), ENC_SHARD_IN_FLIGHT as usize);
    assert!(matches!(
        shard_take(&set, 0, &genuine[1_024]),
        Step::Refused
    ));
    assert_eq!(counted(&counts, EncRejection::VerifyBusy), 1);
    // The oldest in flight is at most the window behind the newest.
    let (oldest, newest) = (0_u64, 1_023_u64);
    assert!(newest.saturating_sub(oldest) < karyos_protocol::protection::replay::WINDOW);
    let mut plain = [0_u8; MAX_PLAINTEXT];
    assert_eq!(set.cancel_all(), 1_024);
    for lane in 0..2 {
        while set.take(lane, &mut plain).is_some() {}
    }
    assert_eq!(opener.leases(), 0);
}

/// A full queue at each stage drops before work and counts it: a full
/// lane (its shard's slots), the set's in-flight cap (above), a full ring
/// for the role; and the rate budget before any of them.
#[test]
fn a_full_queue_at_each_stage_drops_before_work_and_counts_it() {
    let set = detached(2, 2, 2);
    let mut opener = opener();
    let rate = OpenRate::preset(KeyKind::Committed, clock(), COMMITTED_OPENS_PER_S - 3);
    let counts = bind(&set, &mut opener, &rate);
    let genuine = sealed(0x11, 4);
    // Lane 0 holds two.
    assert!(matches!(shard_take(&set, 0, &genuine[0]), Step::Dispatched));
    assert!(matches!(shard_take(&set, 0, &genuine[1]), Step::Dispatched));
    assert!(matches!(shard_take(&set, 0, &genuine[2]), Step::Refused));
    assert_eq!(counted(&counts, EncRejection::VerifyBusy), 1);
    // The rate budget is spent: refused before the lane, counted.
    assert!(matches!(shard_take(&set, 1, &genuine[3]), Step::Refused));
    assert_eq!(counted(&counts, EncRejection::OpenRate), 1);
    // A ring of two: the third datagram for the role is dropped and
    // counted, the first two wait in order.
    let other = |byte: u8| [byte; 40];
    let results = [RecvResult::Datagram {
        len: 40,
        truncated: None,
        source: Some(source()),
    }; 3];
    let mut slab = vec![0_u8; set.shared.stride * 3];
    for at in 0..3 {
        let start = at * set.shared.stride;
        slab[start..start + 40].copy_from_slice(&other(u8::try_from(at).unwrap()));
    }
    assert_eq!(set.shared.batch(1, &slab, &results), 3);
    let stats = set.stats();
    assert_eq!((stats.forwarded, stats.ring_full), (3, 1));
    let mut buffer = [0_u8; 64];
    assert_eq!(set.pop_other(1, &mut buffer), Some((40, source())));
    assert_eq!(buffer[0], 0);
    assert_eq!(set.pop_other(1, &mut buffer), Some((40, source())));
    assert_eq!(buffer[0], 1);
    assert_eq!(set.pop_other(1, &mut buffer), None);
    assert_eq!(set.cancel_all(), 2);
    let mut plain = [0_u8; MAX_PLAINTEXT];
    while set.take(0, &mut plain).is_some() {}
    assert_eq!(opener.leases(), 0);
}

/// Decision 6: the role's inputs are served round robin with a budget
/// each: sustained encrypted load does not starve pending control traffic,
/// and the reverse.
#[test]
fn sustained_load_on_one_input_never_starves_another() {
    for busy in [0_usize, 1] {
        let mut pending = [0_u32; 2];
        pending[1 - busy] = 3;
        let mut served = [0_u32; 2];
        let total = serve_round(2, 64, |input| {
            if input == busy {
                // Sustained: always one more.
                served[input] += 1;
                true
            } else if pending[input] > 0 {
                pending[input] -= 1;
                served[input] += 1;
                true
            } else {
                false
            }
        });
        assert_eq!(served[busy], 64, "the busy input gets its budget");
        assert_eq!(served[1 - busy], 3, "the other is served in the same poll");
        assert_eq!(total, 67);
    }
}

/// Decision 6 on a set: a lane full of verified results and a ring of
/// control datagrams are both served within one poll of the role.
#[test]
fn a_full_lane_and_pending_control_traffic_share_one_poll() {
    let set = detached(1, 128, 16);
    let mut opener = opener();
    let rate = OpenRate::default();
    let _counts = bind(&set, &mut opener, &rate);
    for bytes in &sealed(0x11, 100) {
        assert!(matches!(shard_take(&set, 0, bytes), Step::Dispatched));
    }
    while set.verify_one() {}
    let results = [RecvResult::Datagram {
        len: 40,
        truncated: None,
        source: Some(source()),
    }; 5];
    let slab = vec![0_u8; set.shared.stride * 5];
    assert_eq!(set.shared.batch(0, &slab, &results), 5);
    let (mut plain, mut buffer) = ([0_u8; MAX_PLAINTEXT], [0_u8; 64]);
    let mut kinds = [0_u32; 2];
    let served = serve_round(2, 32, |input| {
        let got = if input == 0 {
            set.take(0, &mut plain).is_some()
        } else {
            set.pop_other(0, &mut buffer).is_some()
        };
        kinds[input] += u32::from(got);
        got
    });
    assert_eq!(kinds, [32, 5]);
    assert_eq!(served, 37);
    assert_eq!(set.cancel_all(), 0);
    while set.take(0, &mut plain).is_some() {}
    assert_eq!(opener.leases(), 0);
}

/// Decision 7: a published withdrawal stops dispatch at once: a shard then
/// hands the binding's datagrams to the role, as it does for a withdrawn
/// opener or an earlier VM generation's.
#[test]
fn a_withdrawn_snapshot_stops_dispatch_before_the_change_applies() {
    let set = detached(1, 8, 8);
    let mut opener = opener();
    let rate = OpenRate::default();
    let _counts = bind(&set, &mut opener, &rate);
    let genuine = sealed(0x11, 3);
    assert!(matches!(shard_take(&set, 0, &genuine[0]), Step::Dispatched));
    // The opener withdrawn while the snapshot still names it.
    opener.withdraw();
    assert!(matches!(shard_take(&set, 0, &genuine[1]), Step::Forward));
    // The snapshot taken back.
    set.publish(Snapshot::clear);
    assert!(matches!(shard_take(&set, 0, &genuine[2]), Step::Forward));
    assert_eq!(set.cancel_all(), 1);
    let mut plain = [0_u8; MAX_PLAINTEXT];
    assert_eq!(
        set.take(0, &mut plain).map(|done| done.outcome),
        Some(Outcome::Cancelled)
    );
    assert_eq!(opener.leases(), 0);
}

/// Decision 7: stopping the shards joins them and closes their
/// descriptors, leaving their rings to the role; dropping the set joins
/// the verifiers and returns every lease still in a lane.
#[test]
fn shard_shutdown_joins_the_shards_before_their_descriptors_close() {
    let (handles, address, closed) = sockets(3);
    let mut set = ShardSet::<u32>::new(
        EncShardConfig {
            shards: 3,
            ring: 64,
        },
        EncVerifyConfig {
            verifiers: 2,
            slots: 16,
        },
        handles,
        1408,
        (4, 4, 4),
    )
    .unwrap();
    assert_eq!((set.shards(), set.verifiers()), (3, 2));
    let mut opener = opener();
    let rate = OpenRate::default();
    let _counts = bind(&set, &mut opener, &rate);
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    sender.send_to(&[7_u8; 40], address).unwrap();
    // Quiet once what was sent is received.
    assert!((0..10).any(|_| set.quiet(Duration::from_secs(1))));
    // A job in a lane, held there.
    set.shared.verifiers_stop.store(true, Ordering::SeqCst);
    assert!(matches!(
        shard_take(&set, 0, &sealed(0x11, 1)[0]),
        Step::Dispatched
    ));
    assert_eq!(opener.leases(), 1);
    set.stop_shards();
    assert!(
        closed.iter().all(|flag| flag.load(Ordering::SeqCst)),
        "closed"
    );
    assert_eq!(set.shards(), 0);
    let mut buffer = [0_u8; 64];
    let left: usize = (0..3)
        .map(|lane| core::iter::from_fn(|| set.pop_other(lane, &mut buffer)).count())
        .sum();
    assert_eq!(left, 1, "what they received stays for the role");
    drop(set);
    assert_eq!(opener.leases(), 0, "returned with the lanes");
}

/// Nothing a shard does per batch, nor the role's consumption, allocates:
/// valid and forged datagrams dispatched, others forwarded.
#[test]
fn a_shard_batch_and_its_consumption_allocate_nothing() {
    let set = detached(1, 64, 64);
    let mut opener = opener();
    let rate = OpenRate::default();
    let _counts = bind(&set, &mut opener, &rate);
    let mut datagrams = sealed(0x11, 8);
    datagrams.extend(sealed(0x99, 8));
    // Scratch derivations on the shard: the next epoch and domain 5.
    datagrams.extend(sealed_in(0x11, next_context(), 1, 2));
    datagrams.extend(sealed_in(0x11, setup_context(), 5, 2));
    datagrams.push(vec![5_u8; 40]);
    let stride = set.shared.stride;
    let mut slab = vec![0_u8; stride * datagrams.len()];
    let mut results = Vec::with_capacity(datagrams.len());
    for (at, bytes) in datagrams.iter().enumerate() {
        slab[at * stride..at * stride + bytes.len()].copy_from_slice(bytes);
        results.push(RecvResult::Datagram {
            len: bytes.len(),
            truncated: None,
            source: Some(source()),
        });
    }
    let mut plain = [0_u8; MAX_PLAINTEXT];
    let mut buffer = [0_u8; 64];
    let ((), allocations) = count_allocations(|| {
        assert_eq!(set.shared.batch(0, &slab, &results), datagrams.len());
        while set.verify_one() {}
        let (mut verified, mut forged) = (0, 0);
        while let Some(done) = set.take(0, &mut plain) {
            match done.outcome {
                Outcome::Verified(_) => verified += 1,
                Outcome::Failed(EncRejection::Tag) => forged += 1,
                other => panic!("{other:?}"),
            }
        }
        assert_eq!((verified, forged), (12, 8));
        assert!(set.pop_other(0, &mut buffer).is_some());
    });
    assert_eq!(allocations, 0);
    assert_eq!(set.stats().scratch, 4);
    assert_eq!(opener.leases(), 0);
}

/// Decision 2, step 4: a datagram of the next epoch is derived on the
/// shard, under a lease on its opener, into the lane slot's own key,
/// charged once to the scratch budget there; its key is erased after the
/// open; the role's re-check charges nothing and its commit promotes.
#[test]
fn a_next_epoch_is_derived_on_the_shard_charged_once_and_erased_after_its_open() {
    let set = detached(1, 8, 4);
    let mut opener = opener();
    let rate = OpenRate::default();
    let counts = bind(&set, &mut opener, &rate);
    let next = sealed_in(0x11, next_context(), 1, 1);
    assert!(matches!(shard_take(&set, 0, &next[0]), Step::Dispatched));
    assert_eq!(rate.charged(KeyKind::Scratch), 1, "charged on the shard");
    assert_eq!(rate.charged(KeyKind::Committed), 0);
    assert_eq!(opener.leases(), 1, "under a lease on the opener");
    assert_eq!(slot_key(&set, 0, 0), (true, false), "derived into the slot");
    assert_eq!(
        *set.shared.lanes[0]
            .cell(0)
            .unwrap()
            .lock()
            .scratch
            .context(),
        next_context()
    );
    assert!(set.verify_one());
    assert_eq!(slot_key(&set, 0, 0), (false, true), "erased after its open");
    let mut plain = [0_u8; MAX_PLAINTEXT];
    let done = set.take(0, &mut plain).unwrap();
    assert_eq!(done.context.kind, JobKind::Next);
    let Outcome::Verified(opened) = done.outcome else {
        panic!("{:?}", done.outcome);
    };
    let lease = done.lease.as_ref().unwrap();
    assert!(lease.key().is_none(), "no committed key is held");
    let pending = opener
        .complete(
            &done.context.ticket,
            lease,
            &opened,
            (&done.header, done.len),
            clock(),
        )
        .unwrap();
    drop(done);
    assert_eq!(opener.leases(), 0, "returned once consumed");
    let accepted = opener.commit(pending).unwrap();
    assert!(accepted.promoted, "the role's commit promotes");
    assert_eq!(opener.epochs(), (1, 1));
    assert_eq!(rate.charged(KeyKind::Scratch), 1, "never charged again");
    assert_eq!(counted(&counts, EncRejection::OpenRate), 0);
    assert_eq!(set.stats().scratch, 1);
}

/// Decision 2, step 4: a domain 5 SETUP is derived on the shard from its
/// header, under a lease on its stream, charged once to the scratch
/// budget; its key is erased after the open; the role's re-check
/// ([`bootstrap_complete`]) charges nothing. A queued SETUP of a
/// withdrawn stream is cancelled, its key erased, its lease returned.
#[test]
fn a_domain_5_setup_is_derived_on_the_shard_under_its_streams_lease() {
    let set = detached(1, 8, 4);
    let mut opener = opener();
    let rate = OpenRate::default();
    let share = Arc::new(OpenerShare::default());
    let _counts = bind_share(&set, &mut opener, &rate, &share);
    let setup = sealed_in(0x11, setup_context(), 5, 2);
    assert!(matches!(shard_take(&set, 0, &setup[0]), Step::Dispatched));
    assert_eq!(rate.charged(KeyKind::Scratch), 1);
    assert_eq!(share.leases(), 1, "under a lease on the stream");
    assert_eq!(opener.leases(), 0);
    assert_eq!(slot_key(&set, 0, 0), (true, false));
    assert!(set.verify_one());
    assert_eq!(slot_key(&set, 0, 0), (false, true), "erased after its open");
    let mut plain = [0_u8; MAX_PLAINTEXT];
    let done = set.take(0, &mut plain).unwrap();
    assert_eq!(done.context.kind, JobKind::Setup);
    assert!(done.context.tag.is_none());
    let Outcome::Verified(opened) = done.outcome else {
        panic!("{:?}", done.outcome);
    };
    let verified = bootstrap_complete(
        &keys(0x11),
        (&done.context.ticket, &done.context.head),
        &opened,
        (&done.header, done.len),
        &plain,
        |_, _| Ok(()),
    )
    .unwrap();
    assert_eq!(verified.header.publication, Some(context().publication));
    assert_eq!(rate.charged(KeyKind::Scratch), 1, "never charged again");
    // A forged header cannot pass as the job's.
    let mut other = done.header;
    other[28] ^= 1;
    assert_eq!(
        bootstrap_complete(
            &keys(0x11),
            (&done.context.ticket, &done.context.head),
            &opened,
            (&other, done.len),
            &plain,
            |_, _| Ok(()),
        )
        .map(|_| ()),
        Err(EncRejection::Binding)
    );
    drop(done);
    assert_eq!(share.leases(), 0);
    // Withdrawn while queued: cancelled, erased, returned.
    assert!(matches!(shard_take(&set, 0, &setup[1]), Step::Dispatched));
    share.withdraw();
    assert!(set.verify_one());
    assert_eq!(slot_key(&set, 0, 1), (false, true));
    assert_eq!(
        set.take(0, &mut plain).map(|done| done.outcome),
        Some(Outcome::Cancelled)
    );
    assert_eq!(share.leases(), 0);
}

/// Decisions 2 and 3: a key the snapshot does not hold is refused on the
/// shard before any derivation or charge (an epoch behind, a SETUP under
/// a file epoch the stream does not hold or a later `party_epoch`, an
/// unbound source no verified SETUP named), or left to the role where it
/// must act (an epoch ahead: its resynchronisation; an unbound source
/// naming a verified target: its SOLICIT). A spent scratch budget refuses
/// a next epoch before its derivation; a cancelled one is erased.
#[test]
fn a_key_the_snapshot_does_not_hold_is_refused_on_the_shard_or_left_to_the_role() {
    let set = detached(1, 8, 8);
    let mut opener = opener();
    let rate = OpenRate::default();
    let counts = bind(&set, &mut opener, &rate);
    let data = sealed(0x11, 1).remove(0);
    let setup = sealed_in(0x11, setup_context(), 5, 1).remove(0);
    let with = |bytes: &[u8], at: usize, value: &[u8]| {
        let mut changed = bytes.to_vec();
        changed[at..at + value.len()].copy_from_slice(value);
        changed
    };
    // An epoch behind: refused.
    let behind = with(&data, 12, &0_u32.to_le_bytes());
    assert!(matches!(shard_take(&set, 0, &behind), Step::Refused));
    // Two ahead: the role's resynchronisation.
    let ahead = with(&data, 16, &2_u16.to_le_bytes());
    assert!(matches!(shard_take(&set, 0, &ahead), Step::Forward));
    // A SETUP under an unheld file epoch, or a later party epoch.
    let unheld = with(&setup, 12, &2_u32.to_le_bytes());
    assert!(matches!(shard_take(&set, 0, &unheld), Step::Refused));
    let party = with(&setup, 16, &1_u16.to_le_bytes());
    assert!(matches!(shard_take(&set, 0, &party), Step::Refused));
    assert_eq!(counted(&counts, EncRejection::Epoch), 3);
    // An unbound source: refused, unless a verified SETUP named it.
    let stranger: SocketAddr = "127.0.0.1:4001".parse().unwrap();
    assert!(matches!(
        shard_take_from(&set, 0, &data, stranger),
        Step::Refused
    ));
    assert_eq!(counted(&counts, EncRejection::Binding), 1);
    set.publish(|snapshot| {
        snapshot.verified.push((alias(), context().publication));
    });
    assert!(matches!(
        shard_take_from(&set, 0, &data, stranger),
        Step::Forward
    ));
    assert_eq!(rate.charged(KeyKind::Scratch), 0, "nothing derived");
    assert_eq!(rate.charged(KeyKind::Committed), 0);
    assert_eq!(set.in_flight(), 0);
    // A retired identity inside its quarantine: refused before any
    // derivation.
    set.publish(|snapshot| {
        snapshot.retired.push((context().publication, clock() + 1));
    });
    assert!(matches!(shard_take(&set, 0, &setup), Step::Refused));
    assert_eq!(counted(&counts, EncRejection::RetiredParty), 1);
    assert_eq!(rate.charged(KeyKind::Scratch), 0);
    // A spent scratch budget: the next epoch is refused before its
    // derivation, the committed key still serves.
    let spent = detached(1, 8, 8);
    let rate = OpenRate::preset(KeyKind::Scratch, clock(), SCRATCH_OPENS_PER_S);
    let counts = bind(&spent, &mut opener, &rate);
    let next = sealed_in(0x11, next_context(), 1, 2);
    assert!(matches!(shard_take(&spent, 0, &next[0]), Step::Refused));
    assert_eq!(counted(&counts, EncRejection::OpenRate), 1);
    assert_eq!(slot_key(&spent, 0, 0), (false, true), "nothing derived");
    assert!(matches!(shard_take(&spent, 0, &data), Step::Dispatched));
    // A cancelled scratch job is erased.
    let fresh = detached(1, 8, 8);
    let rate = OpenRate::default();
    let _counts = bind(&fresh, &mut opener, &rate);
    assert!(matches!(shard_take(&fresh, 0, &next[1]), Step::Dispatched));
    assert_eq!(fresh.cancel_all(), 1);
    assert_eq!(slot_key(&fresh, 0, 0), (false, true), "erased on cancel");
    let mut plain = [0_u8; MAX_PLAINTEXT];
    for held in [&spent, &fresh] {
        let _ = held.cancel_all();
        while held.take(0, &mut plain).is_some() {}
    }
    assert_eq!(opener.leases(), 0);
}
